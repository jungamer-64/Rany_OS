use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
use kernel_api::abi::driver::DriverContext as AbiDriverContext;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::service::platform::PciDeviceInfo;

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
use crate::driver_domain::DriverDomainId;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
use crate::driver_domain::RestartPolicy;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
use crate::driver_domain::lifecycle::{self, DriverDomainConfig};
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
use crate::driver_registry::DriverHandle;
use crate::sync::PoisonLock;

use super::driver_pack::{self, DriverPackPciSelector};

#[derive(Clone)]
struct StagedPciDriverPack {
    manifest_name: String,
    artifact_name: String,
    artifact: Cow<'static, [u8]>,
    allow_unsafe: bool,
    selector: DriverPackPciSelector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageArtifactResult {
    NotStaged,
    Staged,
    Rejected(String),
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub enum StagedPciBindOutcome {
    NoMatch,
    AlreadyBound,
    Started {
        domain_id: DriverDomainId,
        handles: Vec<DriverHandle>,
    },
    Failed(String),
}

static STAGED_PCI_PACKS: PoisonLock<Vec<StagedPciDriverPack>> = PoisonLock::new(Vec::new());
static BOUND_PCI_LOCATORS: PoisonLock<Vec<PackedPciLocation>> = PoisonLock::new(Vec::new());

fn class_code_u32(dev: &PciDeviceInfo) -> u32 {
    ((dev.class_code.class as u32) << 16)
        | ((dev.class_code.subclass as u32) << 8)
        | dev.class_code.prog_if as u32
}

fn selector_rank(selector: DriverPackPciSelector) -> u8 {
    match selector {
        DriverPackPciSelector::ExactDevice { .. } => 3,
        DriverPackPciSelector::ClassCode {
            vendor_id: Some(_), ..
        } => 2,
        DriverPackPciSelector::ClassCode {
            vendor_id: None, ..
        } => 1,
    }
}

fn selector_matches(selector: DriverPackPciSelector, dev: &PciDeviceInfo) -> bool {
    match selector {
        DriverPackPciSelector::ExactDevice {
            vendor_id,
            device_id,
        } => dev.vendor_id.0 == vendor_id && dev.device_id.0 == device_id,
        DriverPackPciSelector::ClassCode {
            vendor_id,
            class,
            subclass,
            prog_if,
        } => {
            vendor_id.is_none_or(|expected| dev.vendor_id.0 == expected)
                && dev.class_code.class == class
                && dev.class_code.subclass == subclass
                && dev.class_code.prog_if == prog_if
        }
    }
}

fn duplicate_selector(entries: &[StagedPciDriverPack], selector: DriverPackPciSelector) -> bool {
    entries.iter().any(|entry| entry.selector == selector)
}

fn binding_name(entry: &StagedPciDriverPack, dev: &PciDeviceInfo) -> String {
    let mut name = entry.manifest_name.clone();
    name.push('@');
    name.push_str(&alloc::format!(
        "{:04x}:{:02x}:{:02x}.{}",
        dev.segment,
        dev.bdf.bus(),
        dev.bdf.device(),
        dev.bdf.function()
    ));
    name
}

fn best_match_for(dev: &PciDeviceInfo) -> Option<StagedPciDriverPack> {
    let entries = STAGED_PCI_PACKS.lock().unwrap_or_else(|e| e.into_inner());
    let mut best: Option<(u8, usize)> = None;
    for (index, entry) in entries.iter().enumerate() {
        if !selector_matches(entry.selector, dev) {
            continue;
        }

        let rank = selector_rank(entry.selector);
        if best.is_none_or(|(best_rank, _)| rank > best_rank) {
            best = Some((rank, index));
        }
    }

    best.map(|(_, index)| entries[index].clone())
}

fn mark_bound(locator: PackedPciLocation) {
    let mut bound = BOUND_PCI_LOCATORS.lock().unwrap_or_else(|e| e.into_inner());
    if !bound.contains(&locator) {
        bound.push(locator);
    }
}

pub fn is_device_bound(locator: PackedPciLocation) -> bool {
    BOUND_PCI_LOCATORS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&locator)
}

fn stage_driver_artifact_inner(
    artifact_name: &str,
    artifact: Cow<'static, [u8]>,
    allow_unsafe: bool,
) -> StageArtifactResult {
    if !driver_pack::is_driver_pack(artifact.as_ref()) {
        return StageArtifactResult::NotStaged;
    }

    let parsed = match driver_pack::parse_driver_pack(artifact.as_ref()) {
        Ok(parsed) => parsed,
        Err(err) => {
            return StageArtifactResult::Rejected(alloc::format!(
                "failed to parse driver pack {}: {}",
                artifact_name,
                err
            ));
        }
    };

    let selector = match parsed.manifest.pci_selector() {
        Ok(Some(selector)) => selector,
        Ok(None) => return StageArtifactResult::NotStaged,
        Err(reason) => {
            return StageArtifactResult::Rejected(alloc::format!(
                "invalid PCI selector in {}: {}",
                artifact_name,
                reason
            ));
        }
    };

    let mut entries = STAGED_PCI_PACKS.lock().unwrap_or_else(|e| e.into_inner());
    if duplicate_selector(&entries, selector) {
        return StageArtifactResult::Rejected(alloc::format!(
            "duplicate staged PCI selector in {}",
            artifact_name
        ));
    }

    let manifest_name = parsed.manifest.name_str();
    entries.push(StagedPciDriverPack {
        manifest_name: if manifest_name.is_empty() {
            artifact_name.to_string()
        } else {
            manifest_name.to_string()
        },
        artifact_name: artifact_name.to_string(),
        artifact,
        allow_unsafe,
        selector,
    });
    StageArtifactResult::Staged
}

pub fn stage_initramfs_driver_artifact(
    artifact_name: &str,
    artifact: &[u8],
    allow_unsafe: bool,
) -> StageArtifactResult {
    stage_driver_artifact_inner(artifact_name, Cow::Owned(artifact.to_vec()), allow_unsafe)
}

pub(crate) fn stage_initramfs_driver_artifact_static(
    artifact_name: &str,
    artifact: &'static [u8],
    allow_unsafe: bool,
) -> StageArtifactResult {
    stage_driver_artifact_inner(artifact_name, Cow::Borrowed(artifact), allow_unsafe)
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub fn try_start_for_device(
    dev: &PciDeviceInfo,
    mut ctx: AbiDriverContext,
) -> StagedPciBindOutcome {
    let locator = dev.packed_locator();
    if is_device_bound(locator) {
        return StagedPciBindOutcome::AlreadyBound;
    }

    let Some(entry) = best_match_for(dev) else {
        return StagedPciBindOutcome::NoMatch;
    };

    ctx.irq = dev.interrupt_line as u32;
    ctx.vendor_id = dev.vendor_id.0;
    ctx.device_id = dev.device_id.0;
    ctx.class_code = class_code_u32(dev);
    ctx.pci_locator = locator.raw();

    let mut config = DriverDomainConfig::new(binding_name(&entry, dev))
        .with_restart_policy(RestartPolicy::on_panic(3, 100))
        .with_capabilities(crate::security::CapabilitySet::empty())
        .with_abi_driver_context(ctx);
    if entry.allow_unsafe {
        config = config.with_unsafe_allowed();
    }

    match lifecycle::create_and_start(&config, entry.artifact.as_ref()) {
        Ok((domain_id, handles)) => {
            log::info!(
                target: "staged_pci",
                "Started staged PCI driver '{}' from '{}' for {:04x}:{:02x}:{:02x}.{}",
                entry.manifest_name,
                entry.artifact_name,
                dev.segment,
                dev.bdf.bus(),
                dev.bdf.device(),
                dev.bdf.function()
            );
            mark_bound(locator);
            StagedPciBindOutcome::Started { domain_id, handles }
        }
        Err(err) => StagedPciBindOutcome::Failed(alloc::format!(
            "staged PCI driver '{}' failed for {:04x}:{:02x}:{:02x}.{}: {}",
            entry.manifest_name,
            dev.segment,
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
            err
        )),
    }
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    STAGED_PCI_PACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    BOUND_PCI_LOCATORS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::driver_pack::{
        DriverPackPciSelector, build_unsigned_driver_pack_with_manifest,
    };
    use kernel_api::service::platform::{Bar, BdfAddress, ClassCode, DeviceId, VendorId};

    fn fake_device(
        vendor_id: u16,
        device_id: u16,
        class: u8,
        subclass: u8,
        prog_if: u8,
    ) -> PciDeviceInfo {
        PciDeviceInfo {
            segment: 0,
            bdf: BdfAddress::new(0, 1, 0),
            vendor_id: VendorId(vendor_id),
            device_id: DeviceId(device_id),
            revision_id: 0,
            class_code: ClassCode::new(class, subclass, prog_if),
            header_type: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            interrupt_line: 11,
            interrupt_pin: 1,
            bars: [
                Some(Bar::Memory32 {
                    base: 0x1000,
                    size: 0x1000,
                    prefetchable: false,
                }),
                None,
                None,
                None,
                None,
                None,
            ],
            capabilities: Vec::new(),
            msi_cap_offset: None,
            msix_cap_offset: None,
            pcie_cap_offset: None,
            iommu_domain_id: None,
        }
    }

    #[test_case]
    fn stage_skips_non_pci_driver_packs() {
        reset_for_tests();

        let pack = build_unsigned_driver_pack_with_manifest(
            "plain",
            &[1, 2, 3, 4],
            kernel_api::abi::driver::DRIVER_ABI_VERSION as u32,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
            None,
        );

        assert_eq!(
            stage_initramfs_driver_artifact("plain.cell", &pack, true),
            StageArtifactResult::NotStaged
        );
    }

    #[test_case]
    fn stage_rejects_duplicate_selectors() {
        reset_for_tests();

        let pack = build_unsigned_driver_pack_with_manifest(
            "dup",
            &[1, 2, 3, 4],
            kernel_api::abi::driver::DRIVER_ABI_VERSION as u32,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
            Some(DriverPackPciSelector::ExactDevice {
                vendor_id: 0x8086,
                device_id: 0x1234,
            }),
        );

        assert_eq!(
            stage_initramfs_driver_artifact("dup-a.cell", &pack, true),
            StageArtifactResult::Staged
        );
        assert!(matches!(
            stage_initramfs_driver_artifact("dup-b.cell", &pack, true),
            StageArtifactResult::Rejected(_)
        ));
    }

    #[test_case]
    fn best_match_prefers_exact_over_class() {
        reset_for_tests();

        let class_pack = build_unsigned_driver_pack_with_manifest(
            "class-match",
            &[1, 2, 3, 4],
            kernel_api::abi::driver::DRIVER_ABI_VERSION as u32,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
            Some(DriverPackPciSelector::ClassCode {
                vendor_id: None,
                class: 0x04,
                subclass: 0x03,
                prog_if: 0x00,
            }),
        );
        let exact_pack = build_unsigned_driver_pack_with_manifest(
            "exact-match",
            &[5, 6, 7, 8],
            kernel_api::abi::driver::DRIVER_ABI_VERSION as u32,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
            Some(DriverPackPciSelector::ExactDevice {
                vendor_id: 0x8086,
                device_id: 0x2668,
            }),
        );

        assert_eq!(
            stage_initramfs_driver_artifact("class.cell", &class_pack, true),
            StageArtifactResult::Staged
        );
        assert_eq!(
            stage_initramfs_driver_artifact("exact.cell", &exact_pack, true),
            StageArtifactResult::Staged
        );

        let device = fake_device(0x8086, 0x2668, 0x04, 0x03, 0x00);
        let matched = best_match_for(&device).expect("match");
        assert_eq!(matched.manifest_name, "exact-match");
    }

    #[test_case]
    fn best_match_prefers_vendor_qualified_class_over_plain_class() {
        reset_for_tests();

        let plain_class_pack = build_unsigned_driver_pack_with_manifest(
            "plain-class",
            &[1, 2, 3, 4],
            kernel_api::abi::driver::DRIVER_ABI_VERSION as u32,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
            Some(DriverPackPciSelector::ClassCode {
                vendor_id: None,
                class: 0x04,
                subclass: 0x03,
                prog_if: 0x00,
            }),
        );
        let vendor_class_pack = build_unsigned_driver_pack_with_manifest(
            "vendor-class",
            &[5, 6, 7, 8],
            kernel_api::abi::driver::DRIVER_ABI_VERSION as u32,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
            Some(DriverPackPciSelector::ClassCode {
                vendor_id: Some(0x8086),
                class: 0x04,
                subclass: 0x03,
                prog_if: 0x00,
            }),
        );

        assert_eq!(
            stage_initramfs_driver_artifact("plain-class.cell", &plain_class_pack, true),
            StageArtifactResult::Staged
        );
        assert_eq!(
            stage_initramfs_driver_artifact("vendor-class.cell", &vendor_class_pack, true),
            StageArtifactResult::Staged
        );

        let device = fake_device(0x8086, 0x2668, 0x04, 0x03, 0x00);
        let matched = best_match_for(&device).expect("match");
        assert_eq!(matched.manifest_name, "vendor-class");
    }

    #[test_case]
    fn staged_class_pack_is_reusable_for_multiple_devices() {
        reset_for_tests();

        let pack = build_unsigned_driver_pack_with_manifest(
            "shared-class",
            &[1, 2, 3, 4],
            kernel_api::abi::driver::DRIVER_ABI_VERSION as u32,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
            Some(DriverPackPciSelector::ClassCode {
                vendor_id: None,
                class: 0x01,
                subclass: 0x06,
                prog_if: 0x01,
            }),
        );

        assert_eq!(
            stage_initramfs_driver_artifact("shared-class.cell", &pack, true),
            StageArtifactResult::Staged
        );

        let ahci_a = fake_device(0x8086, 0x2922, 0x01, 0x06, 0x01);
        let ahci_b = fake_device(0x8086, 0x2829, 0x01, 0x06, 0x01);

        assert_eq!(
            best_match_for(&ahci_a).map(|entry| entry.manifest_name),
            Some(String::from("shared-class"))
        );
        assert_eq!(
            best_match_for(&ahci_b).map(|entry| entry.manifest_name),
            Some(String::from("shared-class"))
        );
    }

    #[test_case]
    fn bound_locators_are_tracked_once() {
        reset_for_tests();

        let locator = PackedPciLocation::new(0, 0, 1, 0);
        assert!(!is_device_bound(locator));
        mark_bound(locator);
        mark_bound(locator);
        assert!(is_device_bound(locator));
        assert_eq!(
            BOUND_PCI_LOCATORS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1
        );
    }
}
