// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/init.rs
// ============================================================================

//! Controller Initialization and Capability Detection
//!
//! This module contains initialization and capability-related methods for `IommuController` via `CapabilityManager` trait.

use super::IommuController;
use crate::io::iommu::vendors::intel::registers::{cap_bits, ecap_bits};

pub trait CapabilityManager {
    /// Check if Queued Invalidation is supported
    fn supports_queued_invalidation(&self) -> bool;

    /// Check if 2MB super-pages are supported
    fn supports_2mb_pages(&self) -> bool;

    /// Check if 1GB super-pages are supported
    fn supports_1gb_pages(&self) -> bool;

    /// Check if Scalable Mode is supported
    fn supports_scalable_mode(&self) -> bool;
}

impl CapabilityManager for IommuController {
    #[inline]
    fn supports_queued_invalidation(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_QI) != 0
    }

    #[inline]
    fn supports_2mb_pages(&self) -> bool {
        (self.cap & cap_bits::CAP_SLLPS_2M) != 0
    }

    #[inline]
    fn supports_1gb_pages(&self) -> bool {
        (self.cap & cap_bits::CAP_SLLPS_1G) != 0
    }

    #[inline]
    fn supports_scalable_mode(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_SMTS) != 0
    }
}
