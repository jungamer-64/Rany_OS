//! Allocation geometry and bounded initialization for the boot memory map.
//! No firmware calls, pointers, or handoff publication authority live here.

#![forbid(unsafe_code)]

use core::alloc::Layout;
use core::mem::MaybeUninit;

pub(crate) const PAGE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyError {
    EmptyCapacity,
    LayoutOverflow,
    Capacity { required: usize, available: usize },
    CountChanged { expected: usize, written: usize },
}

/// The exact page allocation layout and its requested descriptor capacity.
#[derive(Debug)]
pub(crate) struct MemoryMapLayout {
    allocation: Layout,
    capacity: usize,
}

impl MemoryMapLayout {
    /// # Errors
    /// Rejects empty storage and overflow in descriptor bytes or page rounding,
    /// including allocations whose byte extent exceeds Rust's slice limit.
    pub(crate) fn new(capacity: usize) -> Result<Self, CopyError> {
        if capacity == 0 {
            return Err(CopyError::EmptyCapacity);
        }
        let records = Layout::array::<boot_proto::MemoryDescriptor>(capacity)
            .map_err(|_| CopyError::LayoutOverflow)?;
        let bytes = records
            .size()
            .checked_add(PAGE_BYTES - 1)
            .ok_or(CopyError::LayoutOverflow)?
            / PAGE_BYTES
            * PAGE_BYTES;
        let allocation =
            Layout::from_size_align(bytes, PAGE_BYTES).map_err(|_| CopyError::LayoutOverflow)?;
        Ok(Self {
            allocation,
            capacity,
        })
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn bytes(&self) -> usize {
        self.allocation.size()
    }

    pub(crate) fn pages(&self) -> usize {
        self.bytes() / PAGE_BYTES
    }
}

/// Completes a single snapshot or reports the written prefix without publishing
/// it. Even a faulty iterator's size hint cannot permit an out-of-bounds write.
///
/// # Errors
/// Capacity rejection happens before writing. A changed descriptor count keeps
/// partial progress in the returned error; no successful count is fabricated.
pub(crate) fn copy_records<T: Copy>(
    records: impl ExactSizeIterator<Item = T>,
    slots: &mut [MaybeUninit<T>],
) -> Result<usize, CopyError> {
    let expected = records.len();
    if expected > slots.len() {
        return Err(CopyError::Capacity {
            required: expected,
            available: slots.len(),
        });
    }
    let mut written = 0;
    for record in records {
        if written == expected {
            return Err(CopyError::CountChanged { expected, written });
        }
        let Some(slot) = slots.get_mut(written) else {
            return Err(CopyError::CountChanged { expected, written });
        };
        slot.write(record);
        written += 1;
    }
    if written != expected {
        return Err(CopyError::CountChanged { expected, written });
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_keeps_page_extent_separate_from_descriptor_capacity() -> Result<(), CopyError> {
        let layout = MemoryMapLayout::new(103)?;
        assert_eq!(layout.capacity(), 103);
        assert_eq!(layout.pages(), 2);
        assert_eq!(layout.bytes(), 8192);
        Ok(())
    }

    #[test]
    fn layout_rejects_empty_and_overflowing_allocations() {
        assert!(matches!(
            MemoryMapLayout::new(0),
            Err(CopyError::EmptyCapacity)
        ));
        assert!(matches!(
            MemoryMapLayout::new(usize::MAX),
            Err(CopyError::LayoutOverflow)
        ));
        let slice_limit =
            isize::MAX as usize / core::mem::size_of::<boot_proto::MemoryDescriptor>();
        assert!(matches!(
            MemoryMapLayout::new(slice_limit),
            Err(CopyError::LayoutOverflow)
        ));
    }

    #[test]
    fn exact_capacity_is_fully_initialized() -> Result<(), CopyError> {
        let mut slots = [MaybeUninit::uninit(); 3];
        assert_eq!(copy_records([1u8, 2, 3].into_iter(), &mut slots)?, 3);
        Ok(())
    }

    #[test]
    fn insufficient_capacity_is_not_a_successful_prefix() {
        let consumed = core::cell::Cell::new(0);
        let mut slots = [MaybeUninit::new(99u8); 2];
        let records = [1u8, 2, 3]
            .into_iter()
            .inspect(|_| consumed.set(consumed.get() + 1));
        assert_eq!(
            copy_records(records, &mut slots),
            Err(CopyError::Capacity {
                required: 3,
                available: 2
            })
        );
        assert_eq!(consumed.get(), 0);
    }

    #[test]
    fn empty_map_has_no_initialized_records() -> Result<(), CopyError> {
        let mut slots = [MaybeUninit::<u8>::uninit(); 2];
        assert_eq!(copy_records([].into_iter(), &mut slots)?, 0);
        Ok(())
    }

    struct ChangedCount {
        records: core::array::IntoIter<u8, 2>,
        declared: usize,
    }

    impl Iterator for ChangedCount {
        type Item = u8;
        fn next(&mut self) -> Option<u8> {
            self.records.next()
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.declared, Some(self.declared))
        }
    }

    impl ExactSizeIterator for ChangedCount {}

    #[test]
    fn iterator_undercount_cannot_overrun_or_publish_partial_progress() {
        let mut slots = [MaybeUninit::uninit(); 1];
        let records = ChangedCount {
            records: [1, 2].into_iter(),
            declared: 1,
        };
        assert_eq!(
            copy_records(records, &mut slots),
            Err(CopyError::CountChanged {
                expected: 1,
                written: 1
            })
        );
    }

    #[test]
    fn iterator_overcount_preserves_actual_written_prefix() {
        let mut slots = [MaybeUninit::uninit(); 3];
        let records = ChangedCount {
            records: [1, 2].into_iter(),
            declared: 3,
        };
        assert_eq!(
            copy_records(records, &mut slots),
            Err(CopyError::CountChanged {
                expected: 3,
                written: 2
            })
        );
    }
}
