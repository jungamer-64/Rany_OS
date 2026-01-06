// ============================================================================
// kernel/src/io/iommu/intel/controller/dma.rs
// ============================================================================

//! Domain and DMA Mapping Management
//!
//! This module contains DMA-related methods for `IommuController` via `DomainManager` trait.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::io::iommu::domain::IommuDomain;
use crate::io::iommu::intel::registry::get_iommu_registry;
use crate::io::iommu::intel::registers::ecap_bits;
use crate::io::iommu::intel::tables::{ContextEntry, PasidTable, ScalableContextEntry};
use crate::io::iommu::types::{DeviceId, DmaMapping, IommuDomainType, IommuError, PteFormat};
use x86_64::PhysAddr;

use super::IommuController;

// Import Invalidation traits (if/when moved)
use super::init::CapabilityManager;
use super::qi_ops::InvalidationOps;

fn align_down(value: u64, align: usize) -> u64 {
    let align = align as u64;
    if align == 0 { return value; }
    value & !(align - 1)
}

fn align_up(value: u64, align: usize) -> u64 {
    let align = align as u64;
    if align == 0 { return value; }
    (value + align - 1) & !(align - 1)
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

fn kernel_phys_range() -> Option<(u64, u64)> {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }

    let start = unsafe { &__kernel_start as *const u8 as u64 };
    let end = unsafe { &__kernel_end as *const u8 as u64 };
    if end <= start {
        return None;
    }

    let start_phys = crate::mm::global_translate(crate::mm::higher_half::VirtAddr::new(start))?.as_u64();
    let end_phys = crate::mm::global_translate(crate::mm::higher_half::VirtAddr::new(end - 1))?.as_u64();
    Some((start_phys, end_phys.saturating_add(1)))
}

fn validate_rmrr_region(start: u64, end: u64) -> Result<(), IommuError> {
    let size = end.saturating_sub(start);
    if size == 0 {
        return Ok(());
    }

    // Hard block if it overlaps the kernel image.
    if let Some((kstart, kend)) = kernel_phys_range() {
        if ranges_overlap(start, end, kstart, kend) {
            log::error!(
                "[IOMMU][SECURITY] RMRR overlaps kernel image: {:#x}-{:#x} vs {:#x}-{:#x}",
                start,
                end,
                kstart,
                kend
            );
            return Err(IommuError::RmrrMapFailed);
        }
    } else {
        log::warn!(
            "[IOMMU] Unable to resolve kernel physical range for RMRR validation"
        );
    }

    // Best-effort bounds check against known physical memory.
    let max_phys = crate::mm::frame_allocator::pmm_managed_end().unwrap_or(0);
    if max_phys != 0 && end > max_phys {
        log::error!(
            "[IOMMU][SECURITY] RMRR outside known RAM: {:#x}-{:#x} (max {:#x})",
            start,
            end,
            max_phys
        );
        return Err(IommuError::RmrrMapFailed);
    }

    // Warn if the range is not within managed regions (may be firmware-reserved).
    if !crate::mm::frame_allocator::is_range_managed_by_pmm(PhysAddr::new(start), size) {
        log::warn!(
            "[IOMMU] RMRR outside managed RAM: {:#x}-{:#x} (allowing reserved region)",
            start,
            end
        );
    }

    Ok(())
}

/// Map RMRR (Reserved Memory Region Reporting) regions for a device.
///
/// RMRR regions are memory areas that the BIOS has allocated for device use
/// (e.g., USB keyboard buffer for legacy support). These MUST be identity-mapped
/// in the device's IOMMU domain, or the device will malfunction or corrupt memory.
///
/// # Critical Security Note
///
/// RMRR mapping failure is a **critical error** that should prevent device use:
/// - If mapping fails, the device may access unmapped memory, causing DMA faults
/// - Or worse, the device may access wrong memory, corrupting system state
/// - BIOS-reserved regions may contain critical firmware data
///
/// # Returns
///
/// - `Ok(())` if all required RMRR regions are successfully mapped
/// - `Err(IommuError::RmrrMapFailed)` if any required region fails to map
fn map_rmrr_for_device(domain: &IommuDomain, device: DeviceId) -> Result<(), IommuError> {
    if domain.domain_type() == IommuDomainType::Passthrough {
        return Ok(());
    }

    let Some(registry) = get_iommu_registry() else {
        return Ok(());
    };

    let page_size = crate::io::iommu::PAGE_SIZE_4K;
    let mut mapped_count = 0u32;
    #[allow(unused_assignments)]
    let mut error_count = 0u32;

    for region in registry.reserved_regions() {
        if region.segment != device.segment {
            continue;
        }
        if region.devices.is_empty() {
            log::warn!(
                "[IOMMU] RMRR region has empty device scope: seg={}, base={:#x}, limit={:#x}",
                region.segment,
                region.base,
                region.limit
            );
            continue;
        }
        if !region.devices.iter().any(|d| *d == device) {
            continue;
        }

        let start = align_down(region.base, page_size);
        let end = align_up(region.limit.saturating_add(1), page_size);
        if end <= start {
            continue;
        }
        let size = end - start;

        if let Err(e) = validate_rmrr_region(start, end) {
            log::error!(
                "[IOMMU][CRITICAL] RMRR validation failed for {:04x}:{:02x}:{:02x}.{}: \
                 region {:#x}-{:#x}, error: {:?}",
                device.segment, device.bus, device.device, device.function,
                start, start + size, e
            );
            return Err(IommuError::RmrrMapFailed);
        }

        match domain.map(start, start, size, true, true) {
            Ok(()) => {
                mapped_count += 1;
                log::debug!(
                    "[IOMMU] RMRR mapped for {:04x}:{:02x}:{:02x}.{}: {:#x}-{:#x}",
                    device.segment, device.bus, device.device, device.function,
                    start, start + size
                );
            }
            Err(IommuError::AlreadyMapped) => {
                // Already mapped, that's fine
                mapped_count += 1;
            }
            Err(err) => {
                log::error!(
                    "[IOMMU][CRITICAL] RMRR map FAILED for {:04x}:{:02x}:{:02x}.{}: \
                     region {:#x}-{:#x}, error: {:?}",
                    device.segment, device.bus, device.device, device.function,
                    start, start + size, err
                );
                log::error!(
                    "[IOMMU][CRITICAL] Device {:04x}:{:02x}:{:02x}.{} should NOT be used - \
                     RMRR failure may cause DMA faults or memory corruption!",
                    device.segment, device.bus, device.device, device.function
                );
                // Return error immediately - device must not be used
                return Err(IommuError::RmrrMapFailed);
            }
        }
    }

    if error_count > 0 {
        log::error!(
            "[IOMMU] RMRR mapping summary for {:04x}:{:02x}:{:02x}.{}: {} success, {} FAILED",
            device.segment, device.bus, device.device, device.function,
            mapped_count, error_count
        );
        return Err(IommuError::RmrrMapFailed);
    }

    Ok(())
}

pub trait DomainManager {
    /// Create a new domain with an optional NUMA node affinity hint
    fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError>;

    /// Set a domain's NUMA affinity (best-effort)
    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError>;

    /// Get domain NUMA hint
    fn get_domain_numa(&self, domain_id: u16) -> Option<usize>;

    /// Get a domain by ID
    fn domain(&self, id: u16) -> Option<Arc<IommuDomain>>;

    /// Attach a device to a domain
    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError>;

    /// Detach a device from its domain
    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError>;

    /// Get the domain associated with a device (enables driver-side caching)
    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError>;

    /// Map DMA region for a device
    fn map_dma(
        &self,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError>;

    /// Unmap DMA region for a device
    fn unmap_dma(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError>;

    /// Unmap DMA region for a device (Async)
    fn unmap_dma_async(
        &self,
        device: &DeviceId,
        iova: u64,
    ) -> impl core::future::Future<Output = Result<DmaMapping, IommuError>> + Send;

    /// Handle a command queue entry directly
    fn handle_command_queue_entry(
        &self,
        kind: &crate::io::iommu::cmdqueue::IommuCommandKind,
    ) -> Result<i32, ()>;
}

impl DomainManager for IommuController {
    fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let id = self.next_domain_id.fetch_add(1, Ordering::Relaxed) as u16;

        let supports_2mb = self.supports_2mb_pages();
        let supports_1gb = self.supports_1gb_pages();
        let max_addr_bits = self.max_guest_address_width().min(48);

        let domain = IommuDomain::new(
            id,
            numa_node,
            supports_2mb,
            supports_1gb,
            max_addr_bits,
            domain_type,
            self.page_table_pool.clone(),
            PteFormat::Intel,
        );
        let domain_arc = Arc::new(domain);
        if let Some(notifier) = self.security_notifier.get() {
            let _ = domain_arc.set_security_notifier(Arc::clone(notifier));
        }

        #[cfg(test)]
        println!("[IOMMU TEST] create_domain inserting id = {}", id);

        match self.domains.lock() {
            Ok(mut domains) => {
                #[cfg(test)]
                println!("[IOMMU TEST] domains.lock() acquired (Ok)");
                domains.insert(id, domain_arc.clone());
            }
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned in create_domain - cannot create domain");
                return Err(IommuError::HardwareError);
            }
        }

        #[cfg(test)]
        println!("[IOMMU TEST] create_domain done id = {}", id);

        Ok(id)
    }

    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
        let domain_arc = match self.domains.lock() {
            Ok(domains) => domains
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?,
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned in set_domain_numa - cannot set NUMA");
                return Err(IommuError::HardwareError);
            }
        };

        domain_arc.set_numa_node(numa_node);
        Ok(())
    }

    fn get_domain_numa(&self, domain_id: u16) -> Option<usize> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&domain_id).and_then(|d| d.numa_node()),
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned in get_domain_numa - returning None");
                None
            }
        }
    }

    fn domain(&self, id: u16) -> Option<Arc<IommuDomain>> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&id).cloned(),
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned (domain) - returning None");
                None
            }
        }
    }

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        let domain_arc = {
            let domains = self.domains.lock().map_err(|_| IommuError::HardwareError)?;
            domains
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?
        };
        map_rmrr_for_device(&domain_arc, device)?;
        let domain_type = domain_arc.domain_type();
        let page_table_addr = domain_arc.page_table_addr();

        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        let mut hw_guard = self
            .hardware
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let hw = &mut *hw_guard;

        // Get root table (must be initialized)
        let root_table = hw.root_table.as_mut().ok_or(IommuError::HardwareError)?;

        if self.is_scalable_mode_enabled() {
            let context_table = hw
                .scalable_context_tables
                .get_mut(bus)
                .ok_or(IommuError::InvalidAddress)?;
            let ctx_phys = context_table.phys_addr();

            // Setup root entry using scalable layout (two 4KB halves)
            let root_entry = root_table.get_mut(bus).ok_or(IommuError::InvalidAddress)?;
            root_entry.set_context_table_pair(ctx_phys, ctx_phys + 0x1000);

            // Setup scalable context entry
            let context_entry = context_table
                .get_mut(devfn)
                .ok_or(IommuError::InvalidAddress)?;
            *context_entry = ScalableContextEntry::new();

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

            let mut device_pasid_tables = self
                .device_pasid_tables
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            device_pasid_tables.insert(device, pasid_table);
        } else {
            let context_table = hw
                .legacy_context_tables
                .get_mut(bus)
                .ok_or(IommuError::InvalidAddress)?;
            let ctx_phys = context_table.phys_addr();

            // Setup root entry using legacy layout
            let root_entry = root_table.get_mut(bus).ok_or(IommuError::InvalidAddress)?;
            if !root_entry.is_present() {
                root_entry.set_context_table(ctx_phys);
            }

            // Setup context entry using safe accessor
            let context_entry = context_table
                .get_mut(devfn)
                .ok_or(IommuError::InvalidAddress)?;

            // 48-bit address width (AGAW = 2)
            if domain_type == IommuDomainType::Passthrough {
                context_entry.set_passthrough(domain_id);
            } else {
                context_entry.set_sl_pt(page_table_addr, domain_id, 2);
            }
        }

        let mut device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        device_domains.insert(device, domain_id);

        Ok(())
    }

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        let mut device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        device_domains.remove(&device);

        // Clear context entry in hardware using safe accessor
        let mut hw = self
            .hardware
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        if self.is_scalable_mode_enabled() {
            let context_table = hw
                .scalable_context_tables
                .get_mut(bus)
                .ok_or(IommuError::InvalidAddress)?;
            if let Some(context_entry) = context_table.get_mut(devfn) {
                *context_entry = ScalableContextEntry::default();
            }

            let mut device_pasid_tables = self
                .device_pasid_tables
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            device_pasid_tables.remove(&device);
        } else {
            let context_table = hw
                .legacy_context_tables
                .get_mut(bus)
                .ok_or(IommuError::InvalidAddress)?;
            if let Some(context_entry) = context_table.get_mut(devfn) {
                *context_entry = ContextEntry::default();
            }
        }

        Ok(())
    }

    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError> {
        let domain_id = match self.device_domains.lock() {
            Ok(guard) => guard.get(&device).copied(),
            Err(_) => {
                log::error!(
                    "[IOMMU] device_domains lock poisoned (get_domain_for_device) - returning None"
                );
                return Err(IommuError::HardwareError);
            }
        };
        Ok(domain_id)
    }

    fn map_dma(
        &self,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let domain_id = {
            let guard = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            guard
                .get(device)
                .copied()
                .ok_or(IommuError::DeviceNotFound)?
        };

        let domain_arc = {
            let domains_guard = self.domains.lock().map_err(|_| IommuError::HardwareError)?;
            domains_guard
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?
        };
        domain_arc.map(iova, phys, size, read, write)
    }

    fn unmap_dma(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let domain_id = {
            let guard = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            guard
                .get(device)
                .copied()
                .ok_or(IommuError::DeviceNotFound)?
        };

        let domain_arc = {
            let domains_guard = self.domains.lock().map_err(|_| IommuError::HardwareError)?;
            domains_guard
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?
        };
        domain_arc.unmap(iova).map(|mapping| {
            if mapping.size >= 2 * 1024 * 1024 {
                unsafe { self.invalidate_iotlb_direct(domain_id) };
            } else {
                if self.is_queued_invalidation_enabled() {
                    let num_pages = (mapping.size / 4096) as u64;
                    for i in 0..num_pages {
                        let page_addr = iova + i * 4096;
                        let _ = self.qi_invalidate_iotlb_page(domain_id, page_addr, true);
                    }
                    let _ = self.qi_wait_sync();
                } else {
                    unsafe { self.invalidate_iotlb_direct(domain_id) };
                }
            }

            // Invalidate Device-TLB (ATS)
            let use_ats = (self.ecap & ecap_bits::ECAP_DT) != 0
                && self.is_queued_invalidation_enabled()
                && match self.ats_enabled_devices.lock() {
                    Ok(set) => set.contains(device),
                    Err(_) => true, // Conservative
                };
            if use_ats {
                if mapping.size >= 2 * 1024 * 1024 {
                    let _ = self.qi_invalidate_device_tlb(device.requester_id(), domain_id);
                } else {
                    let num_pages = (mapping.size / 4096) as u64;
                    for i in 0..num_pages {
                        let page_addr = iova + i * 4096;
                        let _ = self.qi_invalidate_device_tlb_page(
                            device.requester_id(),
                            domain_id,
                            page_addr,
                            0,
                        );
                    }
                }
                let _ = self.qi_wait_sync();
            }

            mapping
        })
    }

    async fn unmap_dma_async(
        &self,
        device: &DeviceId,
        iova: u64,
    ) -> Result<DmaMapping, IommuError> {
        let domain_id = {
            let guard = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            guard
                .get(device)
                .copied()
                .ok_or(IommuError::DeviceNotFound)?
        };

        let domain_arc = {
            let domains_guard = self.domains.lock().map_err(|_| IommuError::HardwareError)?;
            domains_guard
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?
        };
        let mapping = domain_arc.unmap(iova)?;

        if self.is_queued_invalidation_enabled() {
            let num_pages = (mapping.size / 4096) as u64;
            if mapping.size >= 2 * 1024 * 1024 {
                self.qi_invalidate_iotlb_domain(domain_id, true)?;
            } else {
                for i in 0..num_pages {
                    let page_addr = iova + i * 4096;
                    self.qi_invalidate_iotlb_page(domain_id, page_addr, true)?;
                }
            }

            let use_ats = (self.ecap & ecap_bits::ECAP_DT) != 0
                && match self.ats_enabled_devices.lock() {
                    Ok(set) => set.contains(device),
                    Err(_) => true,
                };

            if use_ats {
                if mapping.size >= 2 * 1024 * 1024 {
                    self.qi_invalidate_device_tlb(device.requester_id(), domain_id)?;
                } else {
                    for i in 0..num_pages {
                        let page_addr = iova + i * 4096;
                        self.qi_invalidate_device_tlb_page(
                            device.requester_id(),
                            domain_id,
                            page_addr,
                            0,
                        )?;
                    }
                }
            }

            self.qi_wait_async().await?;
        } else {
            unsafe { self.invalidate_iotlb_direct(domain_id) };
        }

        Ok(mapping)
    }

    fn handle_command_queue_entry(
        &self,
        kind: &crate::io::iommu::cmdqueue::IommuCommandKind,
    ) -> Result<i32, ()> {
        use crate::io::iommu::cmdqueue::IommuCommandKind;
        match kind {
            IommuCommandKind::MapRegion {
                domain,
                iova,
                phys,
                size,
                read,
                write,
            } => match self.domains.lock() {
                Ok(dom_map) => {
                    let domain_arc = dom_map.get(domain).cloned();
                    drop(dom_map);
                    if let Some(domain_arc) = domain_arc {
                        match domain_arc.map(*iova, *phys, *size, *read, *write) {
                            Ok(_) => {
                                unsafe { self.invalidate_iotlb_direct(*domain) };
                                Ok(0)
                            }
                            Err(_) => Err(()),
                        }
                    } else {
                        Err(())
                    }
                }
                Err(_) => Err(()),
            },
            IommuCommandKind::MapRegionDevice { .. } => Err(()),
            IommuCommandKind::UnmapRegion {
                domain,
                iova,
                size: _,
            } => match self.domains.lock() {
                Ok(dom_map) => {
                    let domain_arc = dom_map.get(domain).cloned();
                    drop(dom_map);
                    if let Some(domain_arc) = domain_arc {
                        match domain_arc.unmap(*iova) {
                            Ok(_) => {
                                unsafe { self.invalidate_iotlb_direct(*domain) };
                                Ok(0)
                            }
                            Err(_) => Err(()),
                        }
                    } else {
                        Err(())
                    }
                }
                Err(_) => Err(()),
            },
            IommuCommandKind::UnmapRegionDevice { .. } => Err(()),
            IommuCommandKind::InvalidateIotlbDomain { domain } => {
                unsafe { self.invalidate_iotlb_direct(*domain) };
                Ok(0)
            }
            IommuCommandKind::InvalidateIotlbGlobal => {
                unsafe { self.invalidate_iotlb_global() };
                Ok(0)
            }
        }
    }
}
