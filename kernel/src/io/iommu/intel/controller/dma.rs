// ============================================================================
// kernel/src/io/iommu/intel/controller/dma.rs
// ============================================================================

//! Domain and DMA Mapping Management
//!
//! This module contains DMA-related methods for `IommuController` via `DomainManager` trait.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::io::iommu::intel::registers::ecap_bits::ECAP_DT;
use crate::io::iommu::intel::registers::{ecap_bits, regs};
use crate::io::iommu::intel::tables::ContextEntry;
use crate::io::iommu::domain::IommuDomain;
use crate::io::iommu::types::{DeviceId, DmaMapping, IommuDomainType, IommuError, PteFormat};

use super::IommuController;
use crate::sync::PoisonLock;

// Import Invalidation traits (if/when moved)
use super::init::CapabilityManager;
use super::qi_ops::InvalidationOps;

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
    fn domain(&self, id: u16) -> Option<Arc<PoisonLock<IommuDomain>>>;

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
        kind: &crate::io::iommu_cmdqueue::IommuCommandKind,
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

        let domain = IommuDomain::new(
            id,
            numa_node,
            supports_2mb,
            supports_1gb,
            domain_type,
            self.page_table_pool.clone(),
            PteFormat::Intel,
        );
        let domain_arc = Arc::new(PoisonLock::new(domain));

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

        let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
        domain.numa_node = numa_node;
        Ok(())
    }

    fn get_domain_numa(&self, domain_id: u16) -> Option<usize> {
        match self.domains.lock() {
            Ok(domains) => {
                if let Some(d) = domains.get(&domain_id) {
                    match d.lock() {
                        Ok(guard) => guard.numa_node,
                        Err(_) => {
                            log::error!(
                                "[IOMMU] Domain lock poisoned in get_domain_numa - returning None"
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            }
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned in get_domain_numa - returning None");
                None
            }
        }
    }

    fn domain(&self, id: u16) -> Option<Arc<PoisonLock<IommuDomain>>> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&id).cloned(),
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned (domain) - returning None");
                None
            }
        }
    }

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        let domains = self.domains.lock().map_err(|_| IommuError::HardwareError)?;
        let domain_arc = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        let domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;

        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        let mut hw = self
            .hardware
            .lock()
            .map_err(|_| IommuError::HardwareError)?;

        // Get context table physical address first (before borrowing root entry)
        let ctx_phys = hw
            .context_tables
            .get(bus)
            .ok_or(IommuError::InvalidAddress)?
            .phys_addr();

        // Get root table (must be initialized)
        let root_table = hw.root_table.as_mut().ok_or(IommuError::HardwareError)?;

        // Setup root entry using safe accessor
        let root_entry = root_table.get_mut(bus).ok_or(IommuError::InvalidAddress)?;
        if !root_entry.is_present() {
            root_entry.set_context_table(ctx_phys);
        }

        // Setup context entry using safe accessor
        let context_table = hw
            .context_tables
            .get_mut(bus)
            .ok_or(IommuError::InvalidAddress)?;
        let context_entry = context_table
            .get_mut(devfn)
            .ok_or(IommuError::InvalidAddress)?;

        // 48-bit address width (AGAW = 2)
        if domain.domain_type() == IommuDomainType::Passthrough {
            context_entry.set_passthrough(domain.id());
        } else {
            context_entry.set_sl_pt(domain.page_table_addr(), domain.id(), 2);
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
        let context_table = hw
            .context_tables
            .get_mut(bus)
            .ok_or(IommuError::InvalidAddress)?;
        let context_entry = context_table
            .get_mut(devfn)
            .ok_or(IommuError::InvalidAddress)?;
        *context_entry = ContextEntry::default();

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
        let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;

        domain.map(iova, phys, size, read, write)
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
        let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;

        domain.unmap(iova).map(|mapping| {
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
        let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;

        let mapping = domain.unmap(iova)?;
        drop(domain); // Release lock

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
        kind: &crate::io::iommu_cmdqueue::IommuCommandKind,
    ) -> Result<i32, ()> {
        use crate::io::iommu_cmdqueue::IommuCommandKind;
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
                    if let Some(domain_arc) = dom_map.get(domain) {
                        match domain_arc.lock() {
                            Ok(mut d) => match d.map(*iova, *phys, *size, *read, *write) {
                                Ok(_) => {
                                    unsafe { self.invalidate_iotlb_direct(*domain) };
                                    Ok(0)
                                }
                                Err(_) => Err(()),
                            },
                            Err(_) => Err(()),
                        }
                    } else {
                        Err(())
                    }
                }
                Err(_) => Err(()),
            },
            IommuCommandKind::UnmapRegion {
                domain,
                iova,
                size: _,
            } => match self.domains.lock() {
                Ok(dom_map) => {
                    if let Some(domain_arc) = dom_map.get(domain) {
                        match domain_arc.lock() {
                            Ok(mut d) => match d.unmap(*iova) {
                                Ok(_) => {
                                    unsafe { self.invalidate_iotlb_direct(*domain) };
                                    Ok(0)
                                }
                                Err(_) => Err(()),
                            },
                            Err(_) => Err(()),
                        }
                    } else {
                        Err(())
                    }
                }
                Err(_) => Err(()),
            },
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
