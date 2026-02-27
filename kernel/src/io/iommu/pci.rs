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
use crate::io::iommu::intel::registers::ecap_bits;
use crate::io::iommu::intel::registry::get_iommu_registry;
#[cfg(not(test))]
use spin::Mutex;

#[cfg(not(test))]
#[allow(unused_imports)]
use pci_driver::{pcie_ext_config, pcie_ext_manager, AtsController, PcieBdf};

#[cfg(not(test))]
static AHCI_PASSTHROUGH_DOMAIN: Mutex<Option<u16>> = Mutex::new(None);

#[cfg(not(test))]
fn is_ahci_legacy(device: &crate::io::pci::PciDeviceInfo) -> bool {
    device.class_code.class == 0x01 && device.class_code.subclass == 0x06
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

    // Critical: Grouping is mandatory for security. Fail if driver or manager are missing.
    let driver = match get_iommu_driver() {
        Some(driver) => driver,
        None => {
            log::error!("[IOMMU][SECURITY] IOMMU driver not found - blocking device protection");
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
            log::error!(
                "[IOMMU][SECURITY] PCIe ext manager not found - cannot verify ACS topology"
            );
            return None;
        }
    };

    let device_id = DeviceId::new(
        device.segment,
        device.bdf.bus(),
        device.bdf.device(),
        device.bdf.function(),
    );

    // SECURITY: Use Translation by default for all devices.
    // AHCI devices NO LONGER use Passthrough even if trusted, to prevent DMA attacks
    // from compromised storage controllers.
    let domain_type = IommuDomainType::Translated;

    // Resolve controller index (relevant for Intel multi-IOMMU systems)
    let controller_idx = match **driver {
        crate::io::iommu::IommuBackend::Intel(_) => {
            let registry =
                get_iommu_registry().expect("Intel registry must exist if backend is Intel");
            registry
                .find_controller_index_for_device(
                    device_id.segment,
                    device_id.bus,
                    device_id.device,
                    device_id.function,
                )
                .unwrap_or(0)
        }
        crate::io::iommu::IommuBackend::Amd(_) => 0, // AMD driver manages multiple units internally
    };

    let (iommu_group, newly_created) = match iommu_group_manager.find_or_create_group(
        device_id,
        driver,
        controller_idx,
        &RealPciTopology::new(pcie_ext_manager),
        domain_type,
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

    // ATS support check (Intel specific for now in this function, but safe to call)
    if let crate::io::iommu::IommuBackend::Intel(ref _intel_ctrl) = **driver {
        let registry = get_iommu_registry().expect("Intel registry must exist");
        if let Some(controller) = registry.controllers.get(controller_idx) {
            try_enable_ats(controller, pcie_ext_manager, device, device_id);
        }
    }

    if let Err(e) = driver.attach_device(device_id, domain_id) {
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
fn try_enable_ats(
    controller: &alloc::sync::Arc<crate::io::iommu::intel::controller::IommuController>,
    pcie_ext_manager: &'static pci_driver::PcieExtManager,
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

    let trust_level = determine_trust_level(pcie_ext_manager, device);

    if trust_level == crate::io::iommu::security::DeviceTrustLevel::Untrusted {
        log::warn!(
            "[IOMMU][SECURITY] ATS disabled for UNTRUSTED device {:?}",
            device_id
        );
        return;
    }

    if let Some(config) = pcie_ext_config() {
        if let Ok(ats_ctrl) = AtsController::new(config, PcieBdf::from_bdf_address(&device.bdf)) {
            if let Err(e) = ats_ctrl.enable_ats(0) {
                log::warn!(
                    "[IOMMU] Failed to enable ATS for device {:?}: {:?}",
                    device_id,
                    e
                );
            } else {
                log::info!(
                    "[IOMMU] Enabled ATS for device {:?} (Trust: {:?})",
                    device_id,
                    trust_level
                );
                controller.enable_ats_for_device(device_id, trust_level);
            }
        }
    }
}

#[cfg(not(test))]
fn determine_trust_level(
    pcie_ext_manager: &'static pci_driver::PcieExtManager,
    device: &crate::io::pci::PciDeviceInfo,
) -> crate::io::iommu::security::DeviceTrustLevel {
    use crate::io::iommu::security::DeviceTrustLevel;
    use pci_driver::HotPlugController;
    use super::groups::PciTopologyProvider;

    let topology = RealPciTopology::new(pcie_ext_manager);
    let mut current_bus = device.bdf.bus();

    // Check all bridges in the path from device to root complex
    loop {
        if let Some((parent_bus, parent_dev, parent_func)) = topology.find_parent_bridge(current_bus) {
            let parent_bdf = pci_driver::PcieBdf::new(parent_bus, parent_dev, parent_func);
            
            // Check if this bridge/port is hot-plug capable (e.g., Thunderbolt, ExpressCard)
            if let Ok(hp_ctrl) = HotPlugController::new(pcie_ext_manager.config(), parent_bdf) {
                if hp_ctrl.is_hotplug_capable() {
                    log::warn!(
                        "[IOMMU][SECURITY] Device {:?} is behind hot-pluggable port {:?} - marking UNTRUSTED",
                        device.bdf,
                        parent_bdf
                    );
                    return DeviceTrustLevel::Untrusted;
                }
            }
            
            current_bus = parent_bus;
            if current_bus == 0 {
                break;
            }
        } else {
            break;
        }
    }

    // Internal devices (not behind hot-pluggable ports) are considered Trusted
    DeviceTrustLevel::Trusted
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
