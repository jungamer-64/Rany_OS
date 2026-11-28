// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/invalidation.rs
// ============================================================================

//! High-level IOMMU Invalidation Logic
//!
//! This module implements the `IommuInvalidator` trait and general invalidation
//! management for the Intel IOMMU.

use super::IommuController;
use super::qi_ops::InvalidationOps;
use crate::io::iommu::common::domain::{
    InvalidateFlags, InvalidateKind, InvalidateRequest, IommuInvalidator,
};
use crate::io::iommu::types::IommuError;
use crate::io::iommu::vendors::intel::qi::{InvalidationQueueEntry, PageInvalidation};

impl IommuController {
    pub(crate) fn process_single_invalidation_nosync(
        &self,
        req: &InvalidateRequest,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        match req.kind {
            InvalidateKind::Pages { start_iova, bytes } => {
                self.invalidate_pages_nosync(req.domain_id, start_iova, bytes, any_ats)
            }
            InvalidateKind::Domain => self.invalidate_domain_nosync(req.domain_id, any_ats),
            InvalidateKind::Global => self.invalidate_global_nosync(),
        }
    }

    pub(crate) fn invalidate_pages_nosync(
        &self,
        domain_id: u16,
        start_iova: u64,
        size: u64,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        if size == 0 {
            return Ok(());
        }

        if self.is_queued_invalidation_enabled() {
            let Some(pages) = PageInvalidation::covering(self.cap, start_iova, size) else {
                return self.invalidate_domain_nosync(domain_id, any_ats);
            };
            self.submit_invalidation(InvalidationQueueEntry::iotlb_invalidate_pages(
                domain_id, pages,
            ))?;
            if any_ats {
                self.invalidate_device_tlbs(domain_id, Some(pages))?;
            }
        } else {
            unsafe {
                self.invalidate_iotlb_direct(domain_id)?;
            }
        }
        Ok(())
    }

    fn invalidate_device_tlbs(
        &self,
        domain_id: u16,
        pages: Option<PageInvalidation>,
    ) -> Result<(), IommuError> {
        let device_domains = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        let ats_devices = self.ats_devices.lock().map_err(|_| IommuError::Poisoned)?;

        for device in ats_devices.keys() {
            if let Some(did) = device_domains
                .get(device)
                .and_then(super::dma::DeviceBinding::retained_domain_id)
                && did == domain_id
            {
                let source_id = device.requester_id();
                if let Some(pages) = pages {
                    self.submit_invalidation(InvalidationQueueEntry::device_tlb_invalidate_pages(
                        source_id, pages,
                    ))?;
                } else {
                    self.qi_invalidate_device_tlb_all(source_id)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn invalidate_domain(
        &self,
        domain_id: u16,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        self.invalidate_domain_nosync(domain_id, any_ats)?;
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }
        Ok(())
    }

    pub(crate) fn invalidate_domain_nosync(
        &self,
        domain_id: u16,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_iotlb_domain(domain_id)?;
            if any_ats {
                self.invalidate_device_tlbs(domain_id, None)?;
            }
        } else {
            unsafe { self.invalidate_iotlb_direct(domain_id)? };
        }
        Ok(())
    }

    pub(crate) fn invalidate_global_nosync(&self) -> Result<(), IommuError> {
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_iotlb_global()?;
            // IOTLB completion alone does not cover translations cached by ATS devices.
            let ats_devices = self.ats_devices.lock().map_err(|_| IommuError::Poisoned)?;
            for device in ats_devices.keys() {
                self.qi_invalidate_device_tlb_all(device.requester_id())?;
            }
        } else {
            if !self
                .ats_devices
                .lock()
                .map_err(|_| IommuError::Poisoned)?
                .is_empty()
            {
                return Err(IommuError::NotSupported);
            }
            // SAFETY: this controller owns the register resource, and the
            // direct routine observes global IOTLB completion before returning.
            unsafe { self.invalidate_iotlb_global()? };
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

    pub(crate) fn invalidate_iec_nosync(&self, global: bool, index: u16) -> Result<(), IommuError> {
        if global {
            self.qi_invalidate_iec_global()?;
        } else {
            self.qi_invalidate_iec_indexed(index)?;
        }
        Ok(())
    }
}

#[deny(unsafe_code)]
impl IommuInvalidator for IommuController {
    fn process_invalidations(&self, requests: &[InvalidateRequest]) -> Result<(), IommuError> {
        if requests.is_empty() {
            return Ok(());
        }

        let any_ats = requests
            .iter()
            .any(|r| r.flags.contains(InvalidateFlags::ATS_AWARE));

        for req in requests {
            self.process_single_invalidation_nosync(req, any_ats)?;
        }

        // Note: ATS Device-TLB invalidation for Domain/Global/Pages kinds
        // is already dispatched inside process_single_invalidation_nosync
        // via invalidate_domain_nosync / invalidate_global_nosync / invalidate_pages_nosync.
        // No additional dispatch is needed here.

        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }

        Ok(())
    }

    fn invalidate_async(
        &self,
        request: InvalidateRequest,
    ) -> impl core::future::Future<Output = Result<(), IommuError>> + Send {
        async move {
            let any_ats = request.flags.contains(InvalidateFlags::ATS_AWARE);
            self.process_single_invalidation_nosync(&request, any_ats)?;
            if self.is_queued_invalidation_enabled() {
                self.qi_wait_async().await?;
            }

            Ok(())
        }
    }
}
