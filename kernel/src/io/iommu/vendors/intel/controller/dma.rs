// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/dma.rs
// ============================================================================

//! Domain and DMA Mapping Management
//!
//! This module contains DMA-related methods for `IommuController` via `DomainManager` trait.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::vendors::intel::registry::get_iommu_registry;
use crate::io::iommu::vendors::intel::tables::{PasidTable, ScalableContextEntry};

use super::{HardwareContext, IommuController};

mod domain_manager_impl;

fn align_down(value: u64, align: usize) -> u64 {
    crate::util::align_down_u64(value, align as u64)
}

fn align_up(value: u64, align: usize) -> u64 {
    crate::util::align_up_u64(value, align as u64)
}

fn try_map_rmrr_region(
    domain: &IommuDomain,
    _device: DeviceId,
    start: u64,
    size: u64,
) -> Result<(), IommuError> {
    // Security: RMRR regions are parsed from trusted ACPI tables.
    // We use map_privileged here because these regions are often located in
    // BIOS-reserved memory that is protected from general DMA in the
    // global security monitor.
    match unsafe { domain.map_privileged(start, start, size, true, true) } {
        Ok(()) => Ok(()),
        Err(IommuError::AlreadyMapped) => Ok(()),
        Err(_err) => Err(IommuError::RmrrMapFailed),
    }
}

fn map_rmrr_for_device(domain: &IommuDomain, device: DeviceId) -> Result<(), IommuError> {
    if domain.domain_type() == IommuDomainType::Passthrough {
        return Ok(());
    }
    let Some(registry) = get_iommu_registry() else {
        return Ok(());
    };
    let page_size = crate::mm::types::PAGE_SIZE_4K;
    for region in registry.reserved_regions() {
        if region.segment != device.segment
            || !region.scopes.iter().any(|scope| scope.matches(device))
        {
            continue;
        }
        let start = align_down(region.base, page_size);
        let end = align_up(region.limit.saturating_add(1), page_size);
        if end > start {
            try_map_rmrr_region(domain, device, start, end - start)?;
        }
    }
    Ok(())
}

pub trait DomainManager {
    fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError>;
    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError>;
    fn domain(&self, id: u16) -> Option<Arc<IommuDomain>>;
    fn destroy_domain(&self, id: u16) -> Result<(), IommuError>;
    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError>;
    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError>;
    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError>;
    fn handle_command_queue_entry(
        &self,
        kind: &crate::io::iommu::runtime::command::queue::IommuCommandKind,
    ) -> Result<i32, ()>;
}

/// A hardware context can outlive a failed command. Its domain and PASID
/// backing remain owned from publication until confirmed revocation.
pub(in crate::io::iommu) enum DeviceBinding {
    Publishing(PublishedContext),
    Attached(PublishedContext),
    Revoking {
        context: Option<PublishedContext>,
        operation: ContextRevocation,
    },
    Isolated,
}

pub(in crate::io::iommu) struct PublishedContext {
    domain: Arc<IommuDomain>,
    pasid: Option<PasidTable>,
}

impl DeviceBinding {
    pub(super) fn domain_id(&self) -> Option<u16> {
        match self {
            Self::Attached(context) => Some(context.domain.id()),
            _ => None,
        }
    }

    pub(super) fn retained_domain_id(&self) -> Option<u16> {
        match self {
            Self::Publishing(context)
            | Self::Attached(context)
            | Self::Revoking {
                context: Some(context),
                ..
            } => Some(context.domain.id()),
            _ => None,
        }
    }

    pub(super) fn fault_domain_id(&self, pasid: Option<u32>) -> Option<u16> {
        match self {
            Self::Publishing(context)
            | Self::Attached(context)
            | Self::Revoking {
                context: Some(context),
                ..
            } => {
                if let Some(table) = &context.pasid {
                    table.domain_id(pasid.unwrap_or(0))
                } else {
                    Some(context.domain.id())
                }
            }
            _ => None,
        }
    }
}

impl PublishedContext {
    pub(in crate::io::iommu) fn new(domain: Arc<IommuDomain>, pasid: Option<PasidTable>) -> Self {
        Self { domain, pasid }
    }

    /// # Safety
    /// The context never reached hardware, or its removal and cache
    /// invalidations have completed.
    pub(in crate::io::iommu) unsafe fn retire(self) {
        if let Some(pasid) = self.pasid {
            unsafe {
                pasid.directory.retire_after_invalidation();
                pasid.table.retire_after_invalidation();
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::io::iommu) enum ContextRevocation {
    Detach,
    Isolate(crate::io::iommu::runtime::security::IsolationReason),
}

impl IommuController {
    pub(in crate::io::iommu) fn domain_for_device(
        &self,
        device: DeviceId,
    ) -> Result<Option<Arc<IommuDomain>>, IommuError> {
        let bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        Ok(match bindings.get(&device) {
            Some(DeviceBinding::Attached(context)) => Some(Arc::clone(&context.domain)),
            _ => None,
        })
    }

    pub(super) fn revoke_device_context(
        &self,
        device: DeviceId,
        operation: ContextRevocation,
    ) -> Result<(), IommuError> {
        use crate::io::iommu::runtime::security::{AtsChangeReason, SecurityEvent};

        if device.segment != self.segment || device.device >= 32 || device.function >= 8 {
            return Err(IommuError::InvalidAddress);
        }
        let mut bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        if matches!(bindings.get(&device), Some(DeviceBinding::Isolated)) {
            return Ok(());
        }
        if !bindings.contains_key(&device) {
            bindings
                .try_reserve(1)
                .map_err(|_| IommuError::MetadataAllocation)?;
        }
        let (context, operation) = match bindings.remove(&device) {
            Some(DeviceBinding::Attached(context) | DeviceBinding::Publishing(context)) => {
                (Some(context), operation)
            }
            Some(DeviceBinding::Revoking {
                context,
                operation: pending,
            }) => {
                let operation = match pending {
                    ContextRevocation::Detach => operation,
                    ContextRevocation::Isolate(_) => pending,
                };
                (context, operation)
            }
            Some(DeviceBinding::Isolated) => unreachable!("isolated binding handled above"),
            None => (None, operation),
        };
        bindings.insert(device, DeviceBinding::Revoking { context, operation });
        let domain_id = bindings
            .get(&device)
            .and_then(DeviceBinding::retained_domain_id);
        self.clear_context_present(device);
        let ats_closed = self.close_ats(device)?;
        self.invalidate_context_translations(domain_id)?;
        let retired = bindings.remove(&device);
        if matches!(operation, ContextRevocation::Isolate(_)) {
            bindings.insert(device, DeviceBinding::Isolated);
        }
        drop(bindings);
        if let Some(DeviceBinding::Revoking {
            context: Some(context),
            ..
        }) = retired
        {
            // SAFETY: Present was cleared and context/PASID/IOTLB/ATS
            // invalidations completed while admitting no new device binding.
            unsafe { context.retire() };
        }
        if ats_closed {
            let reason = match operation {
                ContextRevocation::Detach => AtsChangeReason::DeviceDetach,
                ContextRevocation::Isolate(_) => AtsChangeReason::SecurityPolicy,
            };
            self.notify_security(SecurityEvent::AtsStateChanged {
                source_id: device.requester_id(),
                enabled: false,
                reason,
            });
        }
        if let ContextRevocation::Isolate(reason) = operation {
            self.notify_security(SecurityEvent::DeviceIsolated {
                source_id: device.requester_id(),
                reason,
            });
        }
        Ok(())
    }

    pub(crate) fn isolate_device(
        &self,
        device: DeviceId,
        reason: crate::io::iommu::runtime::security::IsolationReason,
    ) -> Result<(), IommuError> {
        self.revoke_device_context(device, ContextRevocation::Isolate(reason))
    }

    pub(crate) fn clear_context_present(&self, device: DeviceId) {
        let mut hardware = match self.hardware.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let bus = usize::from(device.bus);
        let devfn = usize::from(device.requester_id() & 0xff);
        if self.is_scalable_mode_enabled() {
            if let Some(entry) = hardware
                .scalable_context_tables
                .get_mut(bus)
                .and_then(|t| t.get_mut(devfn))
            {
                entry.qwords[0] &= !1;
            }
        } else if let Some(entry) = hardware
            .legacy_context_tables
            .get_mut(bus)
            .and_then(|t| t.get_mut(devfn))
        {
            entry.lo &= !1;
        }
    }

    pub(in crate::io::iommu) fn prepare_pasid(
        &self,
        domain: &IommuDomain,
    ) -> Result<PasidTable, IommuError> {
        let mut table = PasidTable::new(6)?;
        if domain.domain_type() == IommuDomainType::Passthrough {
            table.setup_passthrough_entry(0, domain.id())?;
        } else {
            table.setup_sl_entry(
                0,
                domain.page_table_addr(),
                self.selected_agaw_code(),
                domain.id(),
            )?;
        }
        Ok(table)
    }

    pub(in crate::io::iommu) fn publish_context(
        &self,
        hw: &mut HardwareContext,
        bus: usize,
        devfn: usize,
        binding: &PublishedContext,
    ) -> Result<(), IommuError> {
        let root_entry = hw
            .root_table
            .as_mut()
            .and_then(|table| table.get_mut(bus))
            .ok_or(IommuError::HardwareError)?;
        if let Some(pasid) = &binding.pasid {
            let table = hw
                .scalable_context_tables
                .get_mut(bus)
                .ok_or(IommuError::InvalidAddress)?;
            let table_phys = table.phys_addr();
            let entry = table.get_mut(devfn).ok_or(IommuError::InvalidAddress)?;
            if entry.is_present() {
                return Err(IommuError::AlreadyMapped);
            }
            let mut next = ScalableContextEntry::new();
            next.set_pasid_dir(pasid.phys_addr(), pasid.pds());
            // The binding admits requester-ID DMA through entry zero and leaves PASIDE clear.
            next.set_rid2pasid(0);
            next.set_fault_enable();
            next.set_present();
            entry.qwords[1..].copy_from_slice(&next.qwords[1..]);
            core::sync::atomic::fence(Ordering::Release);
            entry.qwords[0] = next.qwords[0];
            if !root_entry.is_present() {
                root_entry.set_context_table_pair(table_phys, table_phys + 0x1000);
            }
        } else {
            let table = hw
                .legacy_context_tables
                .get_mut(bus)
                .ok_or(IommuError::InvalidAddress)?;
            let table_phys = table.phys_addr();
            let entry = table.get_mut(devfn).ok_or(IommuError::InvalidAddress)?;
            if entry.is_present() {
                return Err(IommuError::AlreadyMapped);
            }
            let did = binding.domain.id();
            let agaw = self.selected_agaw_code();
            if binding.domain.domain_type() == IommuDomainType::Passthrough {
                entry.set_passthrough(did, agaw);
            } else {
                entry.set_sl_pt(binding.domain.page_table_addr(), did, agaw);
            }
            if !root_entry.is_present() {
                root_entry.set_context_table(table_phys);
            }
        }
        Ok(())
    }

    pub(crate) fn resolve_domain_for_attach(
        &self,
        domain_id: u16,
        device: DeviceId,
    ) -> Result<(Arc<IommuDomain>, usize, usize), IommuError> {
        let domain_arc = self
            .domains
            .lock()
            .map_err(|_| IommuError::HardwareError)?
            .get(&domain_id)
            .cloned()
            .ok_or(IommuError::DomainNotFound)?;
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);
        // Retain the domain through hardware and device-registry publication.
        // Observed addresses alone would allow teardown to race this attach.
        Ok((domain_arc, bus, devfn))
    }
}
