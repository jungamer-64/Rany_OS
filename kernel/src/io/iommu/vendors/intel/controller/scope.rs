//! Resolves catalogued DMAR paths while retaining every configuration resource.

use crate::drivers::pci::BdfAddress;
use crate::drivers::pci::resource::FunctionResources;
use crate::io::iommu::types::{DeviceId, IommuDeviceScope, IommuError};
use alloc::sync::Arc;
use alloc::vec::Vec;

pub(super) struct ResolvedScopes {
    pub(super) scopes: Vec<IommuDeviceScope>,
    pub(super) resources: Vec<Arc<FunctionResources>>,
}

pub(super) fn resolve(
    segment: u16,
    scopes: &[crate::drivers::acpi::dmar::DeviceScope],
) -> Result<ResolvedScopes, IommuError> {
    let mut resolved = ResolvedScopes {
        scopes: Vec::new(),
        resources: Vec::new(),
    };
    resolved
        .scopes
        .try_reserve_exact(scopes.len())
        .map_err(|_| IommuError::MetadataAllocation)?;
    // LOOP_PROOF: mode=bounded; reason=The catalogued scope list and each PCI path have finite byte lengths.;
    for scope in scopes {
        // IOAPIC, HPET and namespace scopes do not admit PCI DMA endpoints.
        if !matches!(scope.scope_type, 1 | 2) {
            continue;
        }
        if segment != 0 {
            return Err(IommuError::NotSupported);
        }
        if scope.path.is_empty() {
            return Err(IommuError::FirmwareScope);
        }
        resolved
            .resources
            .try_reserve(scope.path.len())
            .map_err(|_| IommuError::MetadataAllocation)?;
        let mut bus = scope.start_bus;
        let mut visited = [false; 256];
        // LOOP_PROOF: mode=bounded; reason=Every firmware PCI path entry is visited once; repeated buses are rejected.;
        for (index, entry) in scope.path.iter().enumerate() {
            if entry.device >= 32 || entry.function >= 8 || visited[bus as usize] {
                return Err(IommuError::FirmwareScope);
            }
            visited[bus as usize] = true;
            let bdf = BdfAddress::new(bus, entry.device, entry.function);
            let resource =
                crate::drivers::pci::resource::retain(bdf).map_err(|error| match error {
                    crate::drivers::pci::resource::FunctionResourceError::Absent => {
                        IommuError::DeviceNotFound
                    }
                    crate::drivers::pci::resource::FunctionResourceError::Busy => IommuError::InUse,
                    crate::drivers::pci::resource::FunctionResourceError::Exhausted => {
                        IommuError::MetadataAllocation
                    }
                })?;
            let device = DeviceId::new(segment, bus, entry.device, entry.function);
            let last = index + 1 == scope.path.len();
            if last && scope.scope_type == 1 {
                resolved.scopes.push(IommuDeviceScope::Endpoint(device));
            } else {
                let buses = resource
                    .bridge_buses()
                    .map_err(|_| IommuError::FirmwareScope)?;
                let secondary = buses.secondary();
                let subordinate = buses.subordinate();
                if last {
                    resolved.scopes.push(IommuDeviceScope::SubHierarchy {
                        bridge: device,
                        secondary,
                        subordinate,
                    });
                } else {
                    bus = secondary;
                }
            }
            resolved.resources.push(resource);
        }
    }
    Ok(resolved)
}
