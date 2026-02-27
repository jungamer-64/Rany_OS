// ============================================================================
// kernel/src/io/iommu/intel/controller/qi_ops.rs
// ============================================================================

//! Queued Invalidation Operations
//!
//! This module contains QI-related methods for `IommuController` via `InvalidationOps` trait.

use core::sync::atomic::Ordering;

use super::utils::IommuUtils;
use super::{InvalidationWaiter, IommuController};
use crate::io::iommu::types::IommuError;
use crate::io::iommu::core::domain::{
    InvalidateFlags, InvalidateKind, InvalidateRequest, IommuInvalidator,
};
use crate::io::iommu::backends::intel::qi::{InvalidationQueue, InvalidationQueueEntry};
use crate::io::iommu::backends::intel::registers::regs;

fn submit_invalidation_locked(
    controller: &IommuController,
    iq: &mut InvalidationQueue,
    entry: InvalidationQueueEntry,
) -> Result<u64, IommuError> {
    if iq.is_full() {
        iq.record_full_check();
        let head = (controller.read64(regs::IQH) >> 4) as usize;
        iq.record_head_refresh();
        iq.update_head(head);
        if iq.is_full() {
            iq.record_wait();
            let cached_head = iq.cached_head() as u64;
            if let Err(e) = controller.wait_for_condition(
                || (controller.read64(regs::IQH) >> 4) != cached_head,
                100_000, // 100ms
                true,
            ) {
                iq.record_wait_timeout();
                return Err(e);
            }
            let head = (controller.read64(regs::IQH) >> 4) as usize;
            iq.record_head_refresh();
            iq.update_head(head);
            if iq.is_full() {
                iq.record_wait_timeout();
                return Err(IommuError::Timeout);
            }
        }
    }

    iq.submit(entry);
    iq.record_submit();
    let tail = iq.tail() as u64; // Tail is in entry units
    controller.write64(regs::IQT, tail << 4);
    Ok(tail)
}

pub trait InvalidationOps {
    /// Check if Queued Invalidation is enabled
    fn is_queued_invalidation_enabled(&self) -> bool;

    /// Submit a queued invalidation request
    fn submit_invalidation(&self, entry: InvalidationQueueEntry) -> Result<(), IommuError>;

    /// Submit a global IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_global(&self) -> Result<(), IommuError>;

    /// Submit a domain IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_domain(&self, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a page-selective IOTLB invalidation via queued invalidation
    fn qi_invalidate_iotlb_page(
        &self,
        domain_id: u16,
        addr: u64,
        am: u8,
    ) -> Result<(), IommuError>;

    /// Submit a global context-cache invalidation via queued invalidation
    fn qi_invalidate_context_global(&self) -> Result<(), IommuError>;

    /// Submit a device-selective context-cache invalidation via queued invalidation
    fn qi_invalidate_context_device(&self, source_id: u16, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a global IEC invalidation via queued invalidation
    fn qi_invalidate_iec_global(&self) -> Result<(), IommuError>;

    /// Submit an indexed IEC invalidation via queued invalidation
    fn qi_invalidate_iec_indexed(&self, index: u16) -> Result<(), IommuError>;

    /// Submit a Device-TLB invalidation via queued invalidation
    fn qi_invalidate_device_tlb_all(&self, source_id: u16) -> Result<(), IommuError>;

    /// Submit a range-selective Device-TLB invalidation
    fn qi_invalidate_device_tlb_range(
        &self,
        source_id: u16,
        iova: u64,
        am: u8,
    ) -> Result<(), IommuError>;

    /// Submit a page-selective Device-TLB invalidation
    fn qi_invalidate_device_tlb_page(
        &self,
        source_id: u16,
        iova: u64,
    ) -> Result<(), IommuError>;

    /// Submit a global PASID cache invalidation
    fn qi_invalidate_pasid_cache_global(&self) -> Result<(), IommuError>;

    /// Submit a domain PASID cache invalidation
    fn qi_invalidate_pasid_cache_domain(&self, domain_id: u16) -> Result<(), IommuError>;

    /// Submit a PASID-based IOTLB invalidation
    fn qi_invalidate_pasid_iotlb(&self, domain_id: u16, pasid: u32) -> Result<(), IommuError>;

    /// Submit a wait descriptor and synchronize
    fn qi_wait_sync(&self) -> Result<(), IommuError>;

    /// Submit a wait descriptor and wait asynchronously for completion
    fn qi_wait_async<'a>(&'a self) -> InvalidationWaiter<'a>;

    /// Wake pending async invalidation waiter (called from interrupt handler)
    fn wake_invalidation_waiter(&self);
}

impl InvalidationOps for IommuController {
    #[inline]
    fn is_queued_invalidation_enabled(&self) -> bool {
        self.qi_enabled.load(Ordering::Acquire)
    }

    fn submit_invalidation(&self, entry: InvalidationQueueEntry) -> Result<(), IommuError> {
        let mut guard = match self.invalidation_queue.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[IOMMU] invalidation_queue lock poisoned");
                return Err(IommuError::HardwareError);
            }
        };

        let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;
        let _ = submit_invalidation_locked(self, iq, entry)?;
        Ok(())
    }

    #[inline]
    fn qi_invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iotlb_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_domain(domain_id);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iotlb_page(
        &self,
        domain_id: u16,
        addr: u64,
        am: u8,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate(3, domain_id, false, addr, am);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_context_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::context_cache_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_context_device(&self, source_id: u16, domain_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::context_cache_invalidate(3, domain_id, source_id);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iec_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iec_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_iec_indexed(&self, index: u16) -> Result<(), IommuError> {
        // Use mask 0 for exact index match (one entry)
        let entry = InvalidationQueueEntry::iec_invalidate(1, index, 0);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_device_tlb_all(&self, source_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_all(source_id);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_device_tlb_range(
        &self,
        source_id: u16,
        iova: u64,
        am: u8,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_range(source_id, iova, am);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_device_tlb_page(
        &self,
        source_id: u16,
        iova: u64,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_page(source_id, iova);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_pasid_cache_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::pasid_cache_invalidate_global();
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_pasid_cache_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::pasid_cache_invalidate_domain(domain_id);
        self.submit_invalidation(entry)
    }

    #[inline]
    fn qi_invalidate_pasid_iotlb(&self, domain_id: u16, pasid: u32) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::pasid_iotlb_invalidate(domain_id, pasid);
        self.submit_invalidation(entry)
    }

    fn qi_wait_sync(&self) -> Result<(), IommuError> {
        let (status_virt, expected_data) = {
            let mut guard = match self.invalidation_queue.lock() {
                Ok(g) => g,
                Err(_) => return Err(IommuError::HardwareError),
            };
            let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;
            let (entry, seq) = iq.wait_entry();
            let virt = iq.status_virtual_address();
            let _ = submit_invalidation_locked(self, iq, entry)?;
            (virt, seq)
        };

        self.wait_for_condition(
            || {
                let status = unsafe { core::ptr::read_volatile(status_virt as *const u32) };
                // Use wrap-around safe comparison (distance in u32 space)
                status.wrapping_sub(expected_data) < (1u32 << 31)
            },
            100_000,
            true,
        )
    }

    fn qi_wait_async<'a>(&'a self) -> InvalidationWaiter<'a> {
        let result = match self.invalidation_queue.lock() {
            Ok(mut guard) => {
                if let Some(iq) = guard.as_mut() {
                    let (entry, expected_data) = iq.wait_entry();
                    let status_virt = iq.status_virtual_address();
                    let submit_result = submit_invalidation_locked(self, iq, entry);
                    Ok((submit_result, status_virt, expected_data))
                } else {
                    Err(IommuError::NotPresent)
                }
            }
            Err(_err) => Err(IommuError::HardwareError) // Changed to _err and kept original error type
        };

        match result {
            Ok((submit_result, status_virt, expected_data)) => InvalidationWaiter {
                controller: self,
                submit_result: submit_result.map(|_| ()),
                status_virt,
                expected_data,
            },
            Err(e) => InvalidationWaiter {
                controller: self,
                submit_result: Err(e),
                status_virt: 0,
                expected_data: 0,
            },
        }
    }

    fn wake_invalidation_waiter(&self) {
        self.pending_waiters.wake_all_from_isr();
    }
}

impl IommuController {
    fn process_single_invalidation(
        &self,
        req: &InvalidateRequest,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        self.process_single_invalidation_nosync(req, any_ats)
    }

    fn process_single_invalidation_nosync(
        &self,
        req: &InvalidateRequest,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        match req.kind {
            InvalidateKind::Pages {
                start_iova,
                bytes,
            } => self.invalidate_pages_nosync(req.domain_id, start_iova, bytes, any_ats),
            InvalidateKind::Domain => self.invalidate_domain_nosync(req.domain_id),
            InvalidateKind::Global => self.invalidate_global_nosync(),
            InvalidateKind::Context { source_id } => self.invalidate_context_nosync(source_id),
            InvalidateKind::Iec { global, index } => self.invalidate_iec_nosync(global, index),
            InvalidateKind::PasidIotlb { pasid } => {
                if self.is_queued_invalidation_enabled() {
                    self.qi_invalidate_pasid_iotlb(req.domain_id, pasid)?;
                }
                Ok(())
            }
            InvalidateKind::PasidCache { pasid: _ } => {
                if self.is_queued_invalidation_enabled() {
                    self.qi_invalidate_pasid_cache_domain(req.domain_id)?;
                }
                Ok(())
            }
        }
    }

    fn invalidate_pages(
        &self,
        domain_id: u16,
        start_iova: u64,
        size: u64,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        self.invalidate_pages_nosync(domain_id, start_iova, size, any_ats)?;
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }
        Ok(())
    }

    fn invalidate_pages_nosync(
        &self,
        domain_id: u16,
        start_iova: u64,
        size: u64,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        if self.is_queued_invalidation_enabled() {
            let num_pages = (size + 4095) / 4096;
            let am = if num_pages > 1 {
                64 - (num_pages - 1).leading_zeros() as u8
            } else {
                0
            };
            
            if am > 6 || (start_iova & ((4096 << am) - 1)) != 0 {
                self.qi_invalidate_iotlb_domain(domain_id)?;
            } else {
                self.qi_invalidate_iotlb_page(domain_id, start_iova, am)?;
            }

            if any_ats {
                let _ = self.invalidate_device_tlbs(domain_id, Some(start_iova), Some(am));
            }
        } else {
            unsafe { self.invalidate_iotlb_direct(domain_id); }
        }
        Ok(())
    }

    fn invalidate_device_tlbs(
        &self,
        domain_id: u16,
        iova: Option<u64>,
        am: Option<u8>,
    ) -> Result<(), IommuError> {
        let device_domains = self.device_domains.lock().map_err(|_| IommuError::Poisoned)?;
        let ats_devices = self.ats_enabled_devices.lock().map_err(|_| IommuError::Poisoned)?;
        
        for device in ats_devices.iter() {
            if let Some(&did) = device_domains.get(device) {
                if did == domain_id {
                    let source_id = device.requester_id();
                    match (iova, am) {
                        (Some(iova_val), Some(am_val)) => {
                            let _ = self.qi_invalidate_device_tlb_range(source_id, iova_val, am_val);
                        }
                        (Some(iova_val), None) => {
                            let _ = self.qi_invalidate_device_tlb_page(source_id, iova_val);
                        }
                        _ => {
                            let _ = self.qi_invalidate_device_tlb_all(source_id);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn invalidate_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        self.invalidate_domain_nosync(domain_id)?;
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }
        Ok(())
    }

    fn invalidate_domain_nosync(&self, domain_id: u16) -> Result<(), IommuError> {
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_iotlb_domain(domain_id)?;
            let _ = self.invalidate_device_tlbs(domain_id, None, None);
        } else {
            unsafe { self.invalidate_iotlb_direct(domain_id) };
        }
        Ok(())
    }

    fn invalidate_global(&self) -> Result<(), IommuError> {
        self.invalidate_global_nosync()?;
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }
        Ok(())
    }

    fn invalidate_global_nosync(&self) -> Result<(), IommuError> {
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_iotlb_global()?;
            // For global, we should ideally invalidate ALL Device-TLBs, 
            // but usually a global IOTLB flush is enough if followed by domain flushes.
            // To be safe, iterate over all ATS devices.
            let ats_devices = self.ats_enabled_devices.lock().map_err(|_| IommuError::Poisoned)?;
            for device in ats_devices.iter() {
                let _ = self.qi_invalidate_device_tlb_all(device.requester_id());
            }
        } else {
            unsafe { self.invalidate_iotlb_global() };
        }
        Ok(())
    }

    fn invalidate_context(&self, source_id: u16) -> Result<(), IommuError> {
        self.invalidate_context_nosync(source_id)?;
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }
        Ok(())
    }

    fn invalidate_context_nosync(&self, _source_id: u16) -> Result<(), IommuError> {
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_context_global()?;
        }
        Ok(())
    }

    pub(crate) fn invalidate_iec(&self, global: bool, index: u16) -> Result<(), IommuError> {
        self.invalidate_iec_nosync(global, index)?;
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }
        Ok(())
    }

    fn invalidate_iec_nosync(&self, global: bool, index: u16) -> Result<(), IommuError> {
        if global {
            self.qi_invalidate_iec_global()?;
        } else {
            self.qi_invalidate_iec_indexed(index)?; 
        }
        Ok(())
    }
}

impl IommuInvalidator for IommuController {
    fn process_invalidations(&self, requests: &[InvalidateRequest]) -> Result<(), IommuError> {
        if requests.is_empty() {
            return Ok(());
        }

        // Advance epoch before invalidation to mark current quarantine entries
        let epoch = if let Ok(guard) = self.iova_allocator.lock() {
            guard.as_ref().map(|a| a.advance_epoch())
        } else {
            None
        };

        let any_ats = requests
            .iter()
            .any(|r| r.flags.contains(InvalidateFlags::ATS_AWARE));

        for req in requests {
            self.process_single_invalidation_nosync(req, any_ats)?;
        }

        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }

        // Complete epoch after invalidation is confirmed by hardware.
        // This safely drains the quarantine rings.
        if let Some(e) = epoch {
            if let Ok(guard) = self.iova_allocator.lock() {
                if let Some(alloc) = guard.as_ref() {
                    alloc.complete_epoch(e);
                }
            }
        }

        Ok(())
    }

    fn invalidate_async(&self, request: InvalidateRequest) -> impl core::future::Future<Output = Result<(), IommuError>> + Send {
        let any_ats = request.flags.contains(InvalidateFlags::ATS_AWARE);
        
        // Advance epoch before invalidation
        let epoch = if let Ok(guard) = self.iova_allocator.lock() {
            guard.as_ref().map(|a| a.advance_epoch())
        } else {
            None
        };

        let res = self.process_single_invalidation_nosync(&request, any_ats);
        
        async move {
            res?;
            if self.is_queued_invalidation_enabled() {
                self.qi_wait_async().await?;
            }
            
            // Complete epoch after async invalidation finishes
            if let Some(e) = epoch {
                if let Ok(guard) = self.iova_allocator.lock() {
                    if let Some(alloc) = guard.as_ref() {
                        alloc.complete_epoch(e);
                    }
                }
            }
            Ok(())
        }
    }
}
