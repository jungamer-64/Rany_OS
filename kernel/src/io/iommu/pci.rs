// ============================================================================
// kernel/src/io/iommu/pci.rs
// ============================================================================
//! PCI device IOMMU integration
//!
//! Functions for setting up IOMMU protection for PCI devices.

#[cfg(not(test))]
use super::api::is_iommu_enabled;
#[cfg(not(test))]
use super::groups::{get_iommu_group_manager, RealPciTopology};
#[cfg(not(test))]
use super::registry::get_iommu_driver;
#[cfg(not(test))]
use super::types::{DeviceId, IommuDomainType};
#[cfg(not(test))]
use crate::io::iommu::intel::controller::dma::DomainManager;
#[cfg(not(test))]
use spin::Mutex;
use crate::io::iommu::intel::registers::ecap_bits;
use crate::io::iommu::intel::registry::get_iommu_registry;

#[cfg(not(test))]
#[allow(unused_imports)]
use pci_driver::{AtsController, PcieBdf, pcie_ext_config, pcie_ext_manager};

#[cfg(not(test))]
static AHCI_PASSTHROUGH_DOMAIN: Mutex<Option<u16>> = Mutex::new(None);

#[cfg(not(test))]
fn is_ahci_legacy(device: &crate::io::pci::PciDeviceInfo) -> bool {
    device.class_code.class == 0x01 && device.class_code.subclass == 0x06
}

#[cfg(not(test))]
fn desired_domain_type(device: &crate::io::pci::PciDeviceInfo) -> IommuDomainType {
    if is_ahci_legacy(device) {
        IommuDomainType::Passthrough
    } else {
        IommuDomainType::Translated
    }
}

#[cfg(not(test))]
fn domain_type_str(domain_type: IommuDomainType) -> &'static str {
    match domain_type {
        IommuDomainType::Translated => "Translated",
        IommuDomainType::Passthrough => "Passthrough",
    }
}

#[cfg(not(test))]
fn get_or_create_ahci_passthrough_domain(
    driver: &alloc::sync::Arc<crate::io::iommu::IommuBackend>,
) -> Option<u16> {
    {
        let guard = AHCI_PASSTHROUGH_DOMAIN.lock();
        if let Some(domain_id) = *guard {
            return Some(domain_id);
        }
    }

    match driver.create_domain(None, IommuDomainType::Passthrough) {
        Ok(domain_id) => {
            let mut guard = AHCI_PASSTHROUGH_DOMAIN.lock();
            if guard.is_none() {
                *guard = Some(domain_id);
            }
            Some((*guard).unwrap_or(domain_id))
        }
        Err(e) => {
            log::error!(
                "[IOMMU] Failed to create AHCI passthrough domain: {:?}",
                e
            );
            None
        }
    }
}
// ============================================================================
// 【設計書 7.2】PCIデバイスへのIOMMU自動設定
// ============================================================================

/// PCIデバイスにIOMMUドメインを自動設定
/// IOMMUが有効な場合は自動的にドメインを作成してデバイスをアタッチします。
///
/// ACS (Access Control Services) を考慮したIOMMUグループを構築します。
/// デバイスは、属するIOMMUグループのドメインに割り当てられます。
///
/// # Security Note
/// IOMMU Registry and Group Manager are MANDATORY for secure operation.
/// Fallback to legacy/no-grouping mode is disabled to prevent spoofing.
#[cfg(not(test))]
pub fn setup_iommu_for_pci_device(device: &mut crate::io::pci::PciDeviceInfo) -> Option<u16> {
    if !is_iommu_enabled() {
        return None;
    }

    // AHCI legacy passthrough mode is still supported for specialized hardware.
    if is_ahci_legacy(device) {
        return setup_iommu_for_pci_device_with_driver(device);
    }

    // Critical: Grouping is mandatory for security. Fail if registry or manager are missing.
    let registry = match get_iommu_registry() {
        Some(registry) => registry,
        None => {
            log::error!("[IOMMU][SECURITY] Global registry not found - blocking device protection");
            return None;
        }
    };
    let iommu_group_manager = match get_iommu_group_manager() {
        Some(manager) => manager,
        None => {
            log::error!("[IOMMU][SECURITY] Group manager not found - blocking device protection");
            return None;
        }
    };
    let pcie_ext_manager = match pcie_ext_manager() {
        Some(manager) => manager,
        None => {
            log::error!("[IOMMU][SECURITY] PCIe ext manager not found - cannot verify ACS topology");
            return None;
        }
    };

    let device_id = DeviceId::new(
        device.segment,
        device.bdf.bus(),
        device.bdf.device(),
        device.bdf.function(),
    );

    let (controller, controller_idx) = resolve_controller(registry, device_id)?;

    let (iommu_group, newly_created) =
        match iommu_group_manager.find_or_create_group(
            device_id,
            controller,
            controller_idx,
            &RealPciTopology::new(pcie_ext_manager),
        ) {
            Ok(group_info) => group_info,
            Err(e) => {
                log::error!(
                    "[IOMMU] Failed to get/create IOMMU group for device {:?}: {:?}",
                    device_id,
                    e
                );
                return None;
            }
        };

    let domain_id = iommu_group.domain_id;

    try_enable_ats(controller, pcie_ext_manager, device, device_id);

    if let Err(e) = controller.attach_device(device_id, domain_id) {
        log::error!(
            "[IOMMU] Attach failed for device {:?} to domain {}: {:?}\n",
            device_id,
            domain_id,
            e
        );
        return None;
    }

    device.iommu_domain_id = Some(domain_id);
    log_device_protection(device_id, &iommu_group, domain_id, newly_created);

    Some(domain_id)
}

#[cfg(not(test))]
fn resolve_controller(
    registry: &'static crate::io::iommu::intel::registry::IommuRegistry,
    device_id: DeviceId,
) -> Option<(&'static alloc::sync::Arc<crate::io::iommu::intel::controller::IommuController>, usize)> {
    let controller_idx = registry
        .find_controller_index_for_device(
            device_id.segment,
            device_id.bus,
            device_id.device,
            device_id.function,
        )
        .unwrap_or(0);
    let controller = registry.controllers.get(controller_idx)?;
    Some((controller, controller_idx))
}

#[cfg(not(test))]
fn try_enable_ats(
    controller: &alloc::sync::Arc<crate::io::iommu::intel::controller::IommuController>,
    pcie_ext_manager: &pci_driver::PcieExtManager,
    device: &crate::io::pci::PciDeviceInfo,
    device_id: DeviceId,
) {
    if (controller.ecap & ecap_bits::ECAP_DT) == 0 {
        return;
    }
    if !pci_driver::device_supports_ats(
        pcie_ext_manager.config(),
        PcieBdf::from_bdf_address(&device.bdf),
    ) {
        return;
    }

    let ats_enabled_for_device = match controller.ats_enabled_devices.lock() {
        Ok(set) => set.contains(&device_id),
        Err(_) => {
            log::warn!(
                "[IOMMU] ats_enabled_devices lock poisoned while checking ATS for device {:?} - assuming ATS NOT enabled",
                device_id
            );
            false
        }
    };

    if ats_enabled_for_device {
        return;
    }

    if let Some(config) = pcie_ext_config() {
        if let Ok(ats_ctrl) =
            AtsController::new(config, PcieBdf::from_bdf_address(&device.bdf))
        {
            if let Err(e) = ats_ctrl.enable_ats(0) {
                log::warn!(
                    "[IOMMU] Failed to enable ATS for device {:?}: {:?}",
                    device_id,
                    e
                );
            } else {
                log::info!("[IOMMU] Enabled ATS for device {:?}", device_id);
                use crate::io::iommu::security::DeviceTrustLevel;
                controller.enable_ats_for_device(device_id, DeviceTrustLevel::Trusted);
            }
        }
    }
}

#[cfg(not(test))]
fn log_device_protection(
    device_id: DeviceId,
    iommu_group: &crate::io::iommu::types::IommuGroup,
    domain_id: u16,
    newly_created: bool,
) {
    if newly_created {
        log::info!(
            "[IOMMU] Protected PCI device {:?} in new group {:?} (domain {})",
            device_id,
            iommu_group.id,
            domain_id
        );
    } else {
        log::info!(
            "[IOMMU] Protected PCI device {:?} in existing group {:?} (domain {})",
            device_id,
            iommu_group.id,
            domain_id
        );
    }
}

#[cfg(not(test))]
fn setup_iommu_for_pci_device_with_driver(
    device: &mut crate::io::pci::PciDeviceInfo,
) -> Option<u16> {
    if !is_iommu_enabled() {
        return None;
    }

    let driver = get_iommu_driver()?;
    let domain_type = desired_domain_type(device);
    let device_id = DeviceId::new(
        device.segment,
        device.bdf.bus(),
        device.bdf.device(),
        device.bdf.function(),
    );

    if let Some(existing) = device.iommu_domain_id {
        if driver.attach_device(device_id, existing).is_ok() {
            return Some(existing);
        }
    }

    if domain_type == IommuDomainType::Translated {
        let default_domain = 0u16;
        if driver.attach_device(device_id, default_domain).is_ok() {
            device.iommu_domain_id = Some(default_domain);
            log::info!(
                "[IOMMU] Protected PCI device {:?} in default domain {} ({} / no ACS grouping)",
                device_id,
                default_domain,
                domain_type_str(domain_type)
            );
            return Some(default_domain);
        }
    } else if let Some(domain_id) = get_or_create_ahci_passthrough_domain(driver) {
        if driver.attach_device(device_id, domain_id).is_ok() {
            device.iommu_domain_id = Some(domain_id);
            log::info!(
                "[IOMMU] Protected PCI device {:?} in shared domain {} ({} / AHCI legacy)",
                device_id,
                domain_id,
                domain_type_str(domain_type)
            );
            return Some(domain_id);
        }
    }

    let domain_id = match driver.create_domain(None, domain_type) {
        Ok(domain_id) => domain_id,
        Err(e) => {
            log::error!(
                "[IOMMU] Failed to create {} domain for device {:?}: {:?}",
                domain_type_str(domain_type),
                device_id,
                e
            );
            return None;
        }
    };

    if let Err(e) = driver.attach_device(device_id, domain_id) {
        log::error!(
            "[IOMMU] Attach failed for device {:?} to domain {} ({}): {:?}",
            device_id,
            domain_id,
            domain_type_str(domain_type),
            e
        );
        return None;
    }

    device.iommu_domain_id = Some(domain_id);
    log::info!(
        "[IOMMU] Protected PCI device {:?} in per-device domain {} ({} / no ACS grouping)",
        device_id,
        domain_id,
        domain_type_str(domain_type)
    );

    Some(domain_id)
}

/// すべてのPCIデバイスにIOMMUドメインを設定
///
/// PCI初期化後に呼び出して、全デバイスを保護します。
#[cfg(not(test))]
pub fn setup_iommu_for_all_pci_devices(devices: &mut [crate::io::pci::PciDeviceInfo]) {
    if !is_iommu_enabled() {
        log::info!("[IOMMU] Skipping PCI device protection (IOMMU not enabled)\n");
        return;
    }

    let mut protected_count = 0;
    for device in devices.iter_mut() {
        // ブリッジデバイスはスキップ（ホストブリッジはIOMMUで保護不要）
        if device.is_pci_bridge() {
            continue;
        }

        if setup_iommu_for_pci_device(device).is_some() {
            protected_count += 1;
        }
    }

    log::info!(
        "[IOMMU] Protected {} PCI devices with IOMMU domains\n",
        protected_count
    );
}
