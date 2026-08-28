//! Allocation extents owned by one buddy allocator.
//!
//! Admission allocates metadata before frames enter the free index. Allocation
//! and release need no heap growth and run under the allocator's exclusive
//! borrow. Free bitmaps are a search index; they cannot authorize a release.
#![forbid(unsafe_code)]

use crate::mm::types::FrameIndex;
use alloc::vec::Vec;

/// Failure to admit physical frames; no frames are published on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameInventoryError {
    /// The half-open range is empty, reversed, or includes reserved frame zero.
    InvalidRange,
    /// Frames are already present in this allocator's inventory.
    Overlap,
    /// Storage for the inventory could not be reserved.
    MetadataAllocationFailed,
}

/// A failed extent transition leaves all allocation metadata unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExtentError {
    InvalidExtent,
    UnmanagedFrame,
    AlreadyAllocated,
    NotAllocationHead,
    OrderMismatch { allocated: usize, requested: usize },
    CorruptTail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameState {
    Vacant,
    Head(u8),
    Tail,
}

#[derive(Debug)]
struct FrameRegion {
    start: FrameIndex,
    // Fixed-length after admission. Vec owns and initializes every element;
    // no pointer, borrowed slice, or independently updated length is retained.
    states: Vec<FrameState>,
}

#[derive(Debug)]
pub(super) struct FrameAllocations {
    regions: Vec<FrameRegion>,
}

impl FrameAllocations {
    pub(super) const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Reserve tracking storage before publishing a managed range.
    ///
    /// # Errors
    /// Invalid or overlapping ranges and allocation failure leave the inventory
    /// unchanged. Adjacent ranges are allowed, including for a coalesced extent.
    pub(super) fn admit(
        &mut self,
        start: FrameIndex,
        end: FrameIndex,
    ) -> Result<(), FrameInventoryError> {
        let count = end
            .as_usize()
            .checked_sub(start.as_usize())
            .filter(|&count| count != 0 && start.as_usize() != 0)
            .ok_or(FrameInventoryError::InvalidRange)?;
        let position = self.regions.partition_point(|region| region.start < start);
        if self.regions.iter().any(|region| {
            start.as_usize() < region.start.as_usize() + region.states.len() && region.start < end
        }) {
            return Err(FrameInventoryError::Overlap);
        }
        let mut states = Vec::new();
        states
            .try_reserve_exact(count)
            .map_err(|_| FrameInventoryError::MetadataAllocationFailed)?;
        states.resize(count, FrameState::Vacant);
        self.regions
            .try_reserve(1)
            .map_err(|_| FrameInventoryError::MetadataAllocationFailed)?;
        self.regions.insert(position, FrameRegion { start, states });
        Ok(())
    }

    fn region_position(&self, frame: FrameIndex) -> Option<usize> {
        self.regions
            .partition_point(|region| region.start <= frame)
            .checked_sub(1)
    }

    fn state(&self, frame: FrameIndex) -> Option<FrameState> {
        let region = self.regions.get(self.region_position(frame)?)?;
        region
            .states
            .get(frame.as_usize() - region.start.as_usize())
            .copied()
    }

    /// Region membership is not allocation or release authority.
    pub(super) fn contains(&self, frame: FrameIndex) -> bool {
        self.state(frame).is_some()
    }

    pub(super) fn contains_range(&self, start: FrameIndex, end: FrameIndex) -> bool {
        if start >= end {
            return false;
        }
        let mut cursor = start.as_usize();
        for region in &self.regions {
            let region_end = region.start.as_usize() + region.states.len();
            if region_end <= cursor {
                continue;
            }
            if region.start.as_usize() > cursor {
                return false;
            }
            cursor = region_end;
            if cursor >= end.as_usize() {
                return true;
            }
        }
        false
    }

    pub(super) fn is_allocated(&self, frame: FrameIndex) -> bool {
        matches!(
            self.state(frame),
            Some(FrameState::Head(_) | FrameState::Tail)
        )
    }

    fn extent_end(frame: FrameIndex, order: usize) -> Result<usize, ExtentError> {
        let shift = u32::try_from(order).map_err(|_| ExtentError::InvalidExtent)?;
        let count = 1usize
            .checked_shl(shift)
            .ok_or(ExtentError::InvalidExtent)?;
        if !frame.as_usize().is_multiple_of(count) {
            return Err(ExtentError::InvalidExtent);
        }
        frame
            .as_usize()
            .checked_add(count)
            .ok_or(ExtentError::InvalidExtent)
    }

    /// Commit a prevalidated extent without allocation or externally visible
    /// intermediate state. The exclusive borrow covers both validation passes.
    fn write_extent(&mut self, start: FrameIndex, end: usize, head: FrameState) {
        for region in &mut self.regions {
            let range_start = start.as_usize().max(region.start.as_usize());
            let range_end = end.min(region.start.as_usize() + region.states.len());
            if range_start >= range_end {
                continue;
            }
            for (offset, state) in region
                .states
                .iter_mut()
                .enumerate()
                .take(range_end - region.start.as_usize())
                .skip(range_start - region.start.as_usize())
            {
                *state = if head == FrameState::Vacant
                    || region.start.as_usize() + offset == start.as_usize()
                {
                    head
                } else {
                    FrameState::Tail
                };
            }
        }
    }

    /// Record the whole selected extent before removing it from the free index.
    ///
    /// # Errors
    /// Rejects overflow, misalignment, unmanaged frames, or any live constituent
    /// frame. No metadata changes on rejection.
    pub(super) fn allocate(&mut self, frame: FrameIndex, order: usize) -> Result<(), ExtentError> {
        let end = Self::extent_end(frame, order)?;
        let encoded_order = u8::try_from(order).map_err(|_| ExtentError::InvalidExtent)?;
        for index in frame.as_usize()..end {
            match self.state(FrameIndex::new(index)) {
                Some(FrameState::Vacant) => {}
                Some(_) => return Err(ExtentError::AlreadyAllocated),
                None => return Err(ExtentError::UnmanagedFrame),
            }
        }
        self.write_extent(frame, end, FrameState::Head(encoded_order));
        Ok(())
    }

    /// Consume exactly one live extent before returning its frames to the index.
    ///
    /// # Errors
    /// Rejects an unknown/tail/already released frame, wrong order, invalid
    /// extent, or corrupt constituent tracking. The live extent is retained.
    pub(super) fn release(&mut self, frame: FrameIndex, order: usize) -> Result<(), ExtentError> {
        let allocated = match self.state(frame) {
            Some(FrameState::Head(allocated)) => usize::from(allocated),
            Some(_) => return Err(ExtentError::NotAllocationHead),
            None => return Err(ExtentError::UnmanagedFrame),
        };
        if allocated != order {
            return Err(ExtentError::OrderMismatch {
                allocated,
                requested: order,
            });
        }
        let end = Self::extent_end(frame, order)?;
        for index in frame.as_usize() + 1..end {
            if self.state(FrameIndex::new(index)) != Some(FrameState::Tail) {
                return Err(ExtentError::CorruptTail);
            }
        }
        self.write_extent(frame, end, FrameState::Vacant);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn admission_rejects_overlap_and_preserves_live_extents() {
        let mut map = FrameAllocations::new();
        assert_eq!(map.admit(FrameIndex::new(8), FrameIndex::new(16)), Ok(()));
        assert_eq!(map.allocate(FrameIndex::new(8), 2), Ok(()));
        assert_eq!(
            map.admit(FrameIndex::new(10), FrameIndex::new(18)),
            Err(FrameInventoryError::Overlap)
        );
        assert!(map.is_allocated(FrameIndex::new(11)));
        assert!(!map.contains(FrameIndex::new(16)));
        assert_eq!(map.release(FrameIndex::new(8), 2), Ok(()));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn invalid_extent_does_not_partially_publish() {
        let mut map = FrameAllocations::new();
        assert_eq!(map.admit(FrameIndex::new(8), FrameIndex::new(10)), Ok(()));
        assert_eq!(
            map.allocate(FrameIndex::new(8), 2),
            Err(ExtentError::UnmanagedFrame)
        );
        assert!(!map.is_allocated(FrameIndex::new(8)));
        assert_eq!(
            map.allocate(FrameIndex::new(9), 1),
            Err(ExtentError::InvalidExtent)
        );
        assert_eq!(
            map.allocate(FrameIndex::new(usize::MAX), 0),
            Err(ExtentError::InvalidExtent)
        );
        assert_eq!(
            map.allocate(FrameIndex::new(8), usize::MAX),
            Err(ExtentError::InvalidExtent)
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn exact_release_rejects_tails_wrong_orders_and_duplicates() {
        let mut map = FrameAllocations::new();
        assert_eq!(map.admit(FrameIndex::new(8), FrameIndex::new(16)), Ok(()));
        assert_eq!(map.allocate(FrameIndex::new(8), 2), Ok(()));
        assert_eq!(
            map.release(FrameIndex::new(9), 0),
            Err(ExtentError::NotAllocationHead)
        );
        assert_eq!(
            map.release(FrameIndex::new(8), 1),
            Err(ExtentError::OrderMismatch {
                allocated: 2,
                requested: 1
            })
        );
        assert_eq!(
            map.allocate(FrameIndex::new(8), 0),
            Err(ExtentError::AlreadyAllocated)
        );
        assert_eq!(map.release(FrameIndex::new(8), 2), Ok(()));
        assert_eq!(
            map.release(FrameIndex::new(8), 2),
            Err(ExtentError::NotAllocationHead)
        );
        for frame in 8..12 {
            assert!(!map.is_allocated(FrameIndex::new(frame)));
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn adjacent_regions_support_coalesced_extents_but_holes_do_not() {
        let mut map = FrameAllocations::new();
        assert_eq!(map.admit(FrameIndex::new(10), FrameIndex::new(12)), Ok(()));
        assert_eq!(map.admit(FrameIndex::new(8), FrameIndex::new(10)), Ok(()));
        assert_eq!(map.admit(FrameIndex::new(14), FrameIndex::new(16)), Ok(()));
        assert_eq!(
            map.allocate(FrameIndex::new(8), 3),
            Err(ExtentError::UnmanagedFrame)
        );
        assert_eq!(map.allocate(FrameIndex::new(8), 2), Ok(()));
        assert_eq!(map.release(FrameIndex::new(8), 2), Ok(()));
        assert!(!map.contains(FrameIndex::new(12)));
        assert!(map.contains_range(FrameIndex::new(8), FrameIndex::new(12)));
        assert!(!map.contains_range(FrameIndex::new(8), FrameIndex::new(16)));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn independent_allocators_do_not_share_metadata() {
        let mut first = FrameAllocations::new();
        let mut second = FrameAllocations::new();
        for map in [&mut first, &mut second] {
            assert_eq!(map.admit(FrameIndex::new(8), FrameIndex::new(16)), Ok(()));
        }
        assert_eq!(first.allocate(FrameIndex::new(8), 1), Ok(()));
        assert!(!second.is_allocated(FrameIndex::new(8)));
        assert_eq!(
            second.release(FrameIndex::new(8), 1),
            Err(ExtentError::NotAllocationHead)
        );
        assert_eq!(first.release(FrameIndex::new(8), 1), Ok(()));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn admission_rejects_reserved_empty_and_reversed_ranges() {
        let mut map = FrameAllocations::new();
        for (start, end) in [(0, 8), (8, 8), (9, 8)] {
            assert_eq!(
                map.admit(FrameIndex::new(start), FrameIndex::new(end)),
                Err(FrameInventoryError::InvalidRange)
            );
        }
        assert!(!map.contains(FrameIndex::new(8)));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn metadata_capacity_failure_does_not_admit_frames() {
        let mut map = FrameAllocations::new();
        assert_eq!(
            map.admit(FrameIndex::new(1), FrameIndex::new(usize::MAX)),
            Err(FrameInventoryError::MetadataAllocationFailed)
        );
        assert!(!map.contains(FrameIndex::new(1)));
        assert_eq!(map.admit(FrameIndex::new(8), FrameIndex::new(12)), Ok(()));
    }
}
