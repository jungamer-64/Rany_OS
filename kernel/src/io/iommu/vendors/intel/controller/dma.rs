// ============================================================================
// kernel/src/io/iommu/backends/intel/controller/dma.rs
// ============================================================================

//! Domain and DMA Mapping Management
//!
//! This module contains DMA-related methods for `IommuController` via `DomainManager` trait.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::io::iommu::core::domain::{InvalidateFlags, InvalidateRequest, IommuDomain, IommuInvalidator};
use crate::io::iommu::backends::intel::registry::get_iommu_registry;
use crate::io::iommu::backends::intel::registers::ecap_bits;
use crate::io::iommu::backends::intel::tables::{ContextEntry, PasidTable, ScalableContextEntry};
use crate::io::iommu::types::{DeviceId, DmaMapping, IommuDomainType, IommuError, PteFormat};

use super::{HardwareContext, IommuController};
use super::qi_ops::InvalidationOps;

mod domain_manager_impl;
pub(crate) mod cache;


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
        if region.segment != device.segment || !region.devices.iter().any(|d| *d == device) {
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
    fn create_domain(&self, numa_node: Option<usize>, domain_type: IommuDomainType) -> Result<u16, IommuError>;
    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError>;
    fn get_domain_numa(&self, domain_id: u16) -> Option<usize>;
    fn domain(&self, id: u16) -> Option<Arc<IommuDomain>>;
    fn destroy_domain(&self, id: u16) -> Result<(), IommuError>;
    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError>;
    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError>;
    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError>;
    fn map_dma(&self, device: &DeviceId, iova: u64, phys: u64, size: u64, read: bool, write: bool) -> Result<(), IommuError>;
    fn unmap_dma(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError>;
    fn unmap_dma_async(&self, device: &DeviceId, iova: u64) -> impl core::future::Future<Output = Result<DmaMapping, IommuError>> + Send;
    fn handle_command_queue_entry(&self, kind: &crate::io::iommu::runtime::command::queue::IommuCommandKind) -> Result<i32, ()>;
}

impl IommuController {
    fn setup_scalable_pasid(
        &self,
        context_entry: &mut ScalableContextEntry,
        domain_type: IommuDomainType,
        page_table_addr: u64,
        domain_id: u16,
        device: DeviceId,
    ) -> Result<(), IommuError> {
        let mut pasid_table = PasidTable::new(6)?;
        if domain_type == IommuDomainType::Passthrough {
            pasid_table.setup_passthrough_entry(0, domain_id)?;
        } else {
            pasid_table.setup_sl_entry(0, page_table_addr, 2, domain_id)?;
        }
        context_entry.set_pasid_dir(pasid_table.phys_addr(), pasid_table.pds());
        context_entry.set_rid2pasid(0);
        context_entry.set_pasid_enable();
        context_entry.set_fault_enable();
        context_entry.set_present();
        self.device_pasid_tables.lock().map_err(|_| IommuError::HardwareError)?.insert(device, pasid_table);
        Ok(())
    }

    pub(crate) fn attach_device_scalable(
        &self,
        hw: &mut HardwareContext,
        bus: usize,
        devfn: usize,
        domain_type: IommuDomainType,
        page_table_addr: u64,
        domain_id: u16,
        device: DeviceId,
    ) -> Result<(), IommuError> {
        let root_table = hw.root_table.as_mut().ok_or(IommuError::HardwareError)?;
        let context_table = hw.scalable_context_tables.get_mut(bus).ok_or(IommuError::InvalidAddress)?;
        let ctx_phys = context_table.phys_addr();
        root_table.get_mut(bus).ok_or(IommuError::InvalidAddress)?.set_context_table_pair(ctx_phys, ctx_phys + 0x1000);
        let context_entry = context_table.get_mut(devfn).ok_or(IommuError::InvalidAddress)?;
        *context_entry = ScalableContextEntry::new();
        self.setup_scalable_pasid(context_entry, domain_type, page_table_addr, domain_id, device)?;
        Ok(())
    }

    pub(crate) fn attach_device_legacy(
        hw: &mut HardwareContext,
        bus: usize,
        devfn: usize,
        domain_type: IommuDomainType,
        page_table_addr: u64,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        let root_table = hw.root_table.as_mut().ok_or(IommuError::HardwareError)?;
        let context_table = hw.legacy_context_tables.get_mut(bus).ok_or(IommuError::InvalidAddress)?;
        let ctx_phys = context_table.phys_addr();
        let root_entry = root_table.get_mut(bus).ok_or(IommuError::InvalidAddress)?;
        if !root_entry.is_present() { root_entry.set_context_table(ctx_phys); }
        let context_entry = context_table.get_mut(devfn).ok_or(IommuError::InvalidAddress)?;
        if domain_type == IommuDomainType::Passthrough {
            context_entry.set_passthrough(domain_id);
        } else {
            context_entry.set_sl_pt(page_table_addr, domain_id, 2);
        }
        Ok(())
    }

    fn should_invalidate_device_tlb(&self, device: &DeviceId) -> bool {
        (self.ecap & ecap_bits::ECAP_DT) != 0 && match self.ats_enabled_devices.lock() {
            Ok(set) => set.contains(device),
            Err(_) => false,
        }
    }

    /// Issue QI IOTLB and (optional) Device-TLB invalidations for an unmap.
    /// Unified implementation using IommuInvalidator logic.
    pub(crate) fn qi_invalidate_unmap(
        &self,
        domain_id: u16,
        device: &DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let mut flags = InvalidateFlags::empty();
        if self.should_invalidate_device_tlb(device) {
            flags |= InvalidateFlags::ATS_AWARE;
        }
        let req = InvalidateRequest {
            domain_id,
            kind: crate::io::iommu::core::domain::InvalidateKind::Pages { start_iova: iova, bytes: size },
            flags,
        };
        self.process_invalidations(&[req])
    }

    pub(crate) fn resolve_device_domain(&self, device: &DeviceId) -> Result<(u16, Arc<IommuDomain>), IommuError> {
        let domain_id = self.device_domains.lock().map_err(|_| IommuError::HardwareError)?
            .get(device).copied().ok_or(IommuError::DeviceNotFound)?;
        let domain_arc = self.domains.lock().map_err(|_| IommuError::HardwareError)?
            .get(&domain_id).cloned().ok_or(IommuError::DomainNotFound)?;
        Ok((domain_id, domain_arc))
    }

    pub(crate) fn check_and_clear_ats(&self, device: DeviceId) {
        let ats_was_enabled = match self.ats_enabled_devices.lock() {
            Ok(set) => set.contains(&device),
            Err(_) => false,
        };
        if ats_was_enabled {
            self.disable_ats_for_device(device, crate::io::iommu::runtime::security::AtsChangeReason::DeviceDetach);
        }
    }

    pub(crate) fn clear_hw_context_entry(&self, bus: usize, devfn: usize, device: DeviceId) -> Result<(), IommuError> {
        let mut hw = self.hardware.lock().map_err(|_| IommuError::HardwareError)?;
        if self.is_scalable_mode_enabled() {
            if let Some(entry) = hw.scalable_context_tables.get_mut(bus).and_then(|t| t.get_mut(devfn)) {
                *entry = ScalableContextEntry::default();
            }
            self.device_pasid_tables.lock().map_err(|_| IommuError::HardwareError)?.remove(&device);
        } else {
            if let Some(entry) = hw.legacy_context_tables.get_mut(bus).and_then(|t| t.get_mut(devfn)) {
                *entry = ContextEntry::default();
            }
        }
        Ok(())
    }

    pub(crate) fn resolve_domain_for_attach(&self, domain_id: u16, device: DeviceId) -> Result<(IommuDomainType, u64, usize, usize), IommuError> {
        let domain_arc = self.domains.lock().map_err(|_| IommuError::HardwareError)?
            .get(&domain_id).cloned().ok_or(IommuError::DomainNotFound)?;
        map_rmrr_for_device(&domain_arc, device)?;
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);
        Ok((domain_arc.domain_type(), domain_arc.page_table_addr(), bus, devfn))
    }
}
