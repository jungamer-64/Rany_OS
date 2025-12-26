// ============================================================================
// kernel/src/io/iommu/controller/init.rs
// ============================================================================

//! Controller Initialization and Capability Detection
//!
//! This module contains initialization and capability-related methods for `IommuController` via `CapabilityManager` trait.

use super::super::{IommuCapabilities, IommuController, cap_bits, ecap_bits};

pub trait CapabilityManager {
    /// Check if Queued Invalidation is supported
    fn supports_queued_invalidation(&self) -> bool;

    /// Check if Interrupt Remapping is supported
    fn supports_interrupt_remapping(&self) -> bool;

    /// Check if 2MB super-pages are supported
    fn supports_2mb_pages(&self) -> bool;

    /// Check if 1GB super-pages are supported
    fn supports_1gb_pages(&self) -> bool;

    /// Check if Posted Interrupts are supported
    fn supports_posted_interrupts(&self) -> bool;

    /// Check if Scalable Mode is supported
    fn supports_scalable_mode(&self) -> bool;

    /// Check if Performance Monitoring is supported
    fn supports_performance_monitoring(&self) -> bool;

    /// Check if Page Request Services are supported
    fn supports_page_request(&self) -> bool;

    /// Get capability information
    fn capabilities(&self) -> IommuCapabilities;
}

impl CapabilityManager for IommuController {
    #[inline]
    fn supports_queued_invalidation(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_QI) != 0
    }

    #[inline]
    fn supports_interrupt_remapping(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_IR) != 0
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
    fn supports_posted_interrupts(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_PIDS) != 0
    }

    #[inline]
    fn supports_scalable_mode(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_SMTS) != 0
    }

    #[inline]
    fn supports_performance_monitoring(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_PMC) != 0
    }

    #[inline]
    fn supports_page_request(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_PRS) != 0
    }

    fn capabilities(&self) -> IommuCapabilities {
        IommuCapabilities {
            queued_invalidation: self.supports_queued_invalidation(),
            interrupt_remapping: self.supports_interrupt_remapping(),
            super_page_2mb: self.supports_2mb_pages(),
            super_page_1gb: self.supports_1gb_pages(),
            page_walk_coherency: (self.cap & cap_bits::CAP_PWC) != 0,
            snoop_control: (self.cap & cap_bits::CAP_SC) != 0,
            posted_interrupts: self.supports_posted_interrupts(),
            scalable_mode: self.supports_scalable_mode(),
            performance_monitoring: self.supports_performance_monitoring(),
        }
    }
}
