//! PCI device IOMMU integration
//!
//! Functions for setting up IOMMU protection for PCI devices.

use super::controller::dma::DomainManager;
use super::{DeviceId, ecap_bits, get_iommu_group_manager, get_iommu_registry, is_iommu_enabled};

#[allow(unused_imports)]
use pci_driver::{AtsController, PcieBdf, pcie_ext_config, pcie_ext_manager};

// ============================================================================
// 【設計書 7.2】PCIデバイスへのIOMMU自動設定
// ============================================================================

/// PCIデバイスにIOMMUドメインを自動設定
/// IOMMUが有効な場合は自動的にドメインを作成してデバイスをアタッチします。
///
/// ACS (Access Control Services) を考慮したIOMMUグループを構築します。
/// デバイスは、属するIOMMUグループのドメインに割り当てられます。
#[cfg(not(test))]
pub fn setup_iommu_for_pci_device(device: &mut crate::io::pci::PciDeviceInfo) -> Option<u16> {
    let registry = get_iommu_registry()?; // NotInitialized -> None
    let iommu_group_manager = get_iommu_group_manager()?;
    let pcie_ext_manager = pcie_ext_manager()?;

    let device_id = DeviceId::new(
        device.segment,
        device.bdf.bus(),
        device.bdf.device(),
        device.bdf.function(),
    );
    let numa_hint = 0; // Use device's NUMA hint if available (not available in PciDeviceInfo yet)

    // 1. Determine IOMMU Group and get/create its domain
    let (iommu_group, newly_created) =
        match iommu_group_manager.find_or_create_group(device_id, registry, pcie_ext_manager) {
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
    let controller_idx = iommu_group.controller_idx;

    let controller = registry.controllers.get(controller_idx)?;

    // 2. Enable ATS for the device if supported and not already enabled by this IOMMU
    if (controller.ecap & ecap_bits::ECAP_DT) != 0
        && pci_driver::device_supports_ats(
            pcie_ext_manager.config(),
            PcieBdf::from_bdf_address(&device.bdf),
        )
    {
        // Check if ATS is already enabled for this device on this controller
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

        if !ats_enabled_for_device {
            // Attempt to enable ATS
            if let Some(config) = pcie_ext_config() {
                if let Ok(ats_ctrl) =
                    AtsController::new(config, PcieBdf::from_bdf_address(&device.bdf))
                {
                    // STU (Smallest Translation Unit) is usually 0 (4KB).
                    if let Err(e) = ats_ctrl.enable_ats(0) {
                        log::warn!(
                            "[IOMMU] Failed to enable ATS for device {:?}: {:?}",
                            device_id,
                            e
                        );
                    } else {
                        log::info!("[IOMMU] Enabled ATS for device {:?}", device_id);
                        controller.enable_ats_for_device(device_id);
                    }
                }
            }
        }
    }

    // 3. Attach the device to the determined domain
    if let Err(e) = controller.attach_device(device_id, domain_id) {
        log::error!(
            "[IOMMU] Attach failed for device {:?} to domain {}: {:?}\n",
            device_id,
            domain_id,
            e
        );
        return None;
    }

    // 4. Update device info
    device.iommu_domain_id = Some(domain_id);
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
