//! DMA service failure classification preserves whether ordinary allocation
//! recovery is permitted. Published translation owners stay in retirement.

use crate::domain::DomainResourceAdmissionError;
use crate::io::iommu::api::MapErrorKind;
use crate::io::iommu::types::IommuError;
use crate::mm::phys::frame_allocator::FrameAllocError;
use crate::resource_registry::dma::DmaAllocationError;
use kernel_api::error::KapiError;

pub(super) fn allocation_error(error: DmaAllocationError) -> KapiError {
    match error {
        DmaAllocationError::OwnerAdmission(cause) => match cause {
            DomainResourceAdmissionError::UnknownOwner
            | DomainResourceAdmissionError::OwnerTerminated => KapiError::NotFound,
            DomainResourceAdmissionError::RegistryUnavailable => KapiError::IoError,
        },
        DmaAllocationError::OwnerMismatch => KapiError::PermissionDenied,
        DmaAllocationError::RegistryExhausted => KapiError::ResourceExhausted,
        DmaAllocationError::AllocationFailed | DmaAllocationError::MetadataAllocationFailed => {
            KapiError::OutOfMemory
        }
        DmaAllocationError::InvalidSize => KapiError::InvalidSize,
        DmaAllocationError::MappingRejected(cause) => rejected_mapping(cause),
        // After publication, a physical/metadata cause does not grant ordinary
        // CPU release or allocation rollback. Retirement owns the backing.
        DmaAllocationError::TranslationPending(_) | DmaAllocationError::MappingFailed => {
            KapiError::IoError
        }
    }
}

fn rejected_mapping(cause: MapErrorKind) -> KapiError {
    match cause {
        MapErrorKind::InvalidSize => KapiError::InvalidSize,
        MapErrorKind::InvalidAlignment => KapiError::InvalidAlignment,
        MapErrorKind::RetirementCapacity | MapErrorKind::OutOfIova => KapiError::ResourceExhausted,
        MapErrorKind::PageTableFull => KapiError::OutOfMemory,
        MapErrorKind::DomainNotFound => KapiError::NotFound,
        MapErrorKind::IommuError(cause) => match cause {
            IommuError::NotInitialized | IommuError::RuntimeUnavailable => {
                KapiError::NotInitialized
            }
            IommuError::NotPresent | IommuError::NotSupported => KapiError::NotSupported,
            IommuError::InvalidAddress => KapiError::InvalidAddress,
            IommuError::InvalidAlignment => KapiError::InvalidAlignment,
            IommuError::OutOfMemory | IommuError::MetadataAllocation => KapiError::OutOfMemory,
            IommuError::OutOfIova | IommuError::GenerationExhausted => KapiError::ResourceExhausted,
            IommuError::DomainNotFound | IommuError::DeviceNotFound => KapiError::NotFound,
            IommuError::Timeout => KapiError::Timeout,
            IommuError::PhysicalAllocation(cause) => match cause {
                FrameAllocError::Uninitialized => KapiError::NotInitialized,
                FrameAllocError::Exhausted | FrameAllocError::MetadataAllocation => {
                    KapiError::OutOfMemory
                }
                FrameAllocError::InvalidRange => KapiError::InvalidAddress,
                FrameAllocError::Alignment => KapiError::InvalidAlignment,
                FrameAllocError::InvalidNode => KapiError::NotFound,
                FrameAllocError::AlreadyInitialized => KapiError::AlreadyExists,
            },
            _ => KapiError::IoError,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn physical_admission_causes_remain_actionable_at_the_dma_service_boundary() {
        for (cause, expected) in [
            (FrameAllocError::Uninitialized, KapiError::NotInitialized),
            (FrameAllocError::Exhausted, KapiError::OutOfMemory),
            (FrameAllocError::MetadataAllocation, KapiError::OutOfMemory),
            (FrameAllocError::Alignment, KapiError::InvalidAlignment),
            (FrameAllocError::InvalidRange, KapiError::InvalidAddress),
            (FrameAllocError::InvalidNode, KapiError::NotFound),
        ] {
            let rejected = DmaAllocationError::MappingRejected(MapErrorKind::IommuError(
                IommuError::PhysicalAllocation(cause),
            ));
            assert_eq!(allocation_error(rejected), expected);
        }
        assert_eq!(
            allocation_error(DmaAllocationError::RegistryExhausted),
            KapiError::ResourceExhausted
        );
        assert_eq!(
            allocation_error(DmaAllocationError::InvalidSize),
            KapiError::InvalidSize
        );
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn a_published_failure_is_not_reported_as_ordinary_allocation_rollback() {
        let cause = MapErrorKind::PageTableFull;
        assert_eq!(
            allocation_error(DmaAllocationError::MappingRejected(cause)),
            KapiError::OutOfMemory
        );
        assert_eq!(
            allocation_error(DmaAllocationError::TranslationPending(cause)),
            KapiError::IoError
        );
    }
}
