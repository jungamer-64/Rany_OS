// ============================================================================
// kernel/src/io/iommu/groups.rs
// ============================================================================

use crate::io::iommu::intel::controller::dma::DomainManager;
use crate::io::iommu::intel::registry::IommuRegistry;
use super::types::{DeviceId, IommuDomainType, IommuError, IommuGroup, IommuGroupId};
use crate::sync::PoisonLock;
use hashbrown::HashMap;
use pci_driver::{AcsController, PcieBdf, PcieError, PcieExtManager};
use spin::Once;

/// Manages the allocation and lookup of IOMMU Groups.
#[cfg(not(test))]
pub struct IommuGroupManager {
    /// Maps IommuGroupId to an IommuGroup instance.
    groups: PoisonLock<HashMap<IommuGroupId, IommuGroup>>,
    /// Tracks which devices have been assigned to which group.
    device_to_group: PoisonLock<HashMap<DeviceId, IommuGroupId>>,
    // Next available group ID for internal grouping logic (if DeviceId is not used as direct ID).
    // For now, DeviceId is the group ID.
}

#[cfg(not(test))]
impl IommuGroupManager {
    pub fn new() -> Self {
        Self {
            groups: PoisonLock::new(HashMap::new()),
            device_to_group: PoisonLock::new(HashMap::new()),
        }
    }

    /// Finds or creates an IOMMU Group for a given device.
    /// This is the core logic for IOMMU grouping.
    ///
    /// # Arguments
    /// * `device` - The PCI DeviceId of the device to group.
    /// * `iommu_registry` - The global IOMMU registry.
    /// * `pcie_ext_manager` - The PCIe extended capabilities manager for topology and ACS checks.
    ///
    /// # Returns
    /// A tuple containing the `IommuGroup` and a boolean indicating if it was newly created.
    pub fn find_or_create_group(
        &self,
        device: DeviceId,
        iommu_registry: &'static IommuRegistry,
        pcie_ext_manager: &'static PcieExtManager,
    ) -> Result<(IommuGroup, bool), IommuError> {
        let mut groups_guard = self.groups.lock().map_err(|_| IommuError::Poisoned)?;
        let mut device_to_group_guard = self
            .device_to_group
            .lock()
            .map_err(|_| IommuError::Poisoned)?;

        // 1. Check if device is already in a group
        if let Some(group_id) = device_to_group_guard.get(&device) {
            if let Some(group) = groups_guard.get(group_id) {
                return Ok((group.clone(), false));
            }
        }

        // 2. Determine the IOMMU Group ID for this device
        // This involves walking up the PCI hierarchy and checking ACS capabilities.
        let group_id =
            Self::determine_group_id_for_device(device, pcie_ext_manager).map_err(|e| {
                log::error!(
                    "[IOMMU] Failed to determine IOMMU group for device {:?}: {:?}",
                    device,
                    e
                );
                e
            })?;

        // 3. Check if a group with this ID already exists
        if let Some(group) = groups_guard.get(&group_id) {
            device_to_group_guard.insert(device, group.id);
            return Ok((group.clone(), false));
        }

        // 4. Create a new IOMMU Group and assign a new domain
        // Find the appropriate IOMMU controller for this device
        let controller_idx = iommu_registry
            .find_controller_index_for_device(
                device.segment,
                device.bus,
                device.device,
                device.function,
            )
            .ok_or(IommuError::DeviceNotFound)?;

        let controller = iommu_registry.controllers[controller_idx].clone(); // Clone Arc for internal use

        let domain_id = controller.create_domain(None, IommuDomainType::Translated)?;
        let new_group = IommuGroup {
            id: group_id,
            domain_id,
            controller_idx,
        };

        groups_guard.insert(group_id, new_group.clone());
        device_to_group_guard.insert(device, group_id);

        log::info!(
            "[IOMMU] Created new group {:?} with domain {} for device {:?}",
            group_id,
            domain_id,
            device
        );

        Ok((new_group, true))
    }

    /// Determines the IOMMU Group ID for a given device by traversing the PCI hierarchy.
    /// The Group ID will be the DeviceId of the "topmost" device in the group that *cannot* be isolated.
    /// If a device is fully isolated, its own DeviceId is its Group ID.
    fn determine_group_id_for_device(
        device: DeviceId,
        pcie_ext_manager: &'static PcieExtManager,
    ) -> Result<IommuGroupId, PcieError> {
        let config = pcie_ext_manager.config();
        let mut current_bdf = PcieBdf::new(device.bus, device.device, device.function);

        // All functions of a multi-function device must be in the same group unless fully isolated.
        // For simplicity, we group all functions under function 0's device ID.
        // A more robust implementation might check for ARI (Alternative Routing-ID) or internal ACS.
        let mut group_root_bdf = PcieBdf::new(current_bdf.bus, current_bdf.device, 0);

        // Walk up the PCI hierarchy
        loop {
            // Check for multifunction device (if not function 0, assume it shares group with function 0)
            if current_bdf.function != 0 {
                // For simplicity, all functions of a multi-function device are in the same group.
                // The group ID will be that of function 0.
                group_root_bdf = PcieBdf::new(current_bdf.bus, current_bdf.device, 0);
            }

            // Read header type to check if it's a bridge
            let header_type = config
                .read8(current_bdf, pci_driver::config_regs::HEADER_TYPE)
                .ok_or(PcieError::ConfigError)?;

            let is_pci_to_pci_bridge = (header_type & 0x7F) == 0x01; // Type 1 header

            if is_pci_to_pci_bridge {
                // It's a bridge. Check its ACS capabilities.
                if let Some(acs_ctrl) = AcsController::new(config, current_bdf).ok() {
                    if acs_ctrl.is_isolation_enabled() {
                        // This bridge provides sufficient isolation for devices downstream.
                        // So, the current device (or its function 0 root) is the group leader.
                        break;
                    }
                }
            } else {
                // Not a bridge, or a root port, or ACS is not sufficient.
                // The group extends further upstream or this is the root of the group.
                // Need to find the upstream device.
            }

            // Find upstream device (e.g., bridge or root complex)
            // This is a simplification. A full implementation would traverse the ACPI/DMAR/PCIe topology.
            // For now, if it's not a bridge that isolates, then the group extends to the upstream bus.
            // If it's a device on bus 0 (root complex), it's its own group.
            if current_bdf.bus == 0 {
                break; // Reached bus 0, assuming root complex provides isolation
            }

            // Find the bridge that owns `current_bdf.bus`
            let mut found_parent_bridge = false;
            for device_info in pcie_ext_manager.devices() {
                // If it's a type 1 header (PCI-to-PCI bridge)
                if (config
                    .read8(device_info.bdf, pci_driver::config_regs::HEADER_TYPE)
                    .unwrap_or(0)
                    & 0x7F)
                    == 0x01
                {
                    // Secondary Bus Number (0x19), Subordinate Bus Number (0x1A) for Type 1 Header
                    let secondary_bus = config.read8(device_info.bdf, 0x19).unwrap_or(0);
                    let _subordinate_bus = config.read8(device_info.bdf, 0x1A).unwrap_or(0);

                    if secondary_bus == current_bdf.bus {
                        // Found the parent bridge.
                        current_bdf = device_info.bdf;
                        found_parent_bridge = true;
                        break;
                    }
                }
            }

            if !found_parent_bridge {
                // No parent bridge found, must be root complex device or error in topology.
                // Assume it's isolated at this point.
                break;
            }
        }

        Ok(DeviceId::new(
            device.segment,
            group_root_bdf.bus,
            group_root_bdf.device,
            group_root_bdf.function,
        ))
    }
}

#[cfg(not(test))]
pub static IOMMU_GROUP_MANAGER: Once<IommuGroupManager> = Once::new();

#[cfg(not(test))]
/// Get reference to the IOMMU Group manager
pub fn get_iommu_group_manager() -> Option<&'static IommuGroupManager> {
    IOMMU_GROUP_MANAGER.get()
}
