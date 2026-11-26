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
            // Security: Use saturating addition to prevent overflow when calculating num_pages.
            // A wrapped small size would cause partial invalidation and potential UAF.
            let num_pages = size.saturating_add(4095) / 4096;
            if num_pages == 0 {
                return Ok(());
            }

            let am = if num_pages > 1 {
                // Find log2 of next power of two
                64 - (num_pages - 1).leading_zeros() as u8
            } else {
                0
            };

            // Security: Fallback to domain-selective if the mask is not supported by hardware
            // or if the range is not naturally aligned to the mask size.
            let cap_am = self.cap_am();
            let mask_val = if am < 64 { (1u64 << am) - 1 } else { !0u64 };
            let alignment_mask = mask_val.saturating_mul(4096);
            let fallback_to_domain = am > cap_am || am >= 60 || (start_iova & alignment_mask) != 0;

            if fallback_to_domain {
                self.qi_invalidate_iotlb_domain(domain_id)?;
            } else {
                self.qi_invalidate_iotlb_page(domain_id, start_iova, am)?;
            }

            if any_ats {
                if fallback_to_domain {
                    // SECURITY: If we fell back for IOTLB, we MUST fall back for Device-TLB too
                    self.invalidate_device_tlbs(domain_id, None, None)?;
                } else {
                    self.invalidate_device_tlbs(domain_id, Some(start_iova), Some(am))?;
                }
            }
        } else {
            unsafe {
                self.invalidate_iotlb_direct(domain_id)?;
            }
        }
        Ok(())
    }

    pub(crate) fn invalidate_device_tlbs(
        &self,
        domain_id: u16,
        iova: Option<u64>,
        am: Option<u8>,
    ) -> Result<(), IommuError> {
        let device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        let ats_devices = self.ats_devices.lock().map_err(|_| IommuError::Poisoned)?;

        for device in ats_devices.keys() {
            if let Some(&did) = device_domains.get(device)
                && did == domain_id
            {
                let source_id = device.requester_id();
                match (iova, am) {
                    (Some(iova_val), Some(am_val)) => {
                        self.qi_invalidate_device_tlb_range(source_id, iova_val, am_val)?;
                    }
                    (Some(iova_val), None) => {
                        self.qi_invalidate_device_tlb_page(source_id, iova_val)?;
                    }
                    _ => {
                        self.qi_invalidate_device_tlb_all(source_id)?;
                    }
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
                self.invalidate_device_tlbs(domain_id, None, None)?;
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
