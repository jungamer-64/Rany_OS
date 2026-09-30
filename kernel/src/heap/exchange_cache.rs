//! CPU cache entries retain an allocated block, not a globally free block.
//! Each class has one canonical Layout, including alignment. Returning a cached
//! allocation consumes its entry; failed insertion returns that same entry.
#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use core::alloc::Layout;
use core::ptr::NonNull;

const CLASSES: usize = 6;
const CAPACITY: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct CacheClass(usize);

impl CacheClass {
    pub(crate) fn for_layout(layout: Layout) -> Option<Self> {
        let bytes = layout
            .size()
            .max(layout.align())
            .max(8)
            .checked_next_power_of_two()?;
        let index = bytes.trailing_zeros() as usize - 3;
        (index < CLASSES).then_some(Self(index))
    }

    pub(crate) fn layout(self) -> Layout {
        // The private checked index selects a small nonzero power of two; no
        // runtime request can reach an invalid Layout through this projection.
        let bytes = 8 << self.0;
        Layout::from_size_align(bytes, bytes).expect("checked canonical cache layout")
    }
}

pub(crate) struct CachedAllocation {
    ptr: NonNull<u8>,
    class: CacheClass,
}

#[expect(
    unsafe_code,
    reason = "cache entries move exclusive stable allocations between CPUs"
)]
// SAFETY: the private entry owns one live allocation without a borrow or
// reclaimer; moving it transfers exclusive reuse authority. The owning heap
// retains stable CPU-independent RAM, and cache mutation is externally locked.
unsafe impl Send for CachedAllocation {}

impl CachedAllocation {
    /// # Safety
    /// Transfer one exclusive live block from the owning heap, using the class's
    /// canonical Layout. No aliases, independent cache entry or free operation
    /// may survive this transfer. The owning cache registry retains that heap.
    #[expect(
        unsafe_code,
        reason = "allocation release is the unique raw allocator ownership boundary"
    )]
    pub(crate) unsafe fn retain(ptr: NonNull<u8>, class: CacheClass) -> Self {
        Self { ptr, class }
    }

    pub(crate) fn into_pointer(self) -> NonNull<u8> {
        self.ptr
    }
}

#[repr(align(128))]
pub(crate) struct ExchangeCache {
    blocks: [[Option<CachedAllocation>; CAPACITY]; CLASSES],
    counts: [usize; CLASSES],
}

impl ExchangeCache {
    pub(crate) const fn new() -> Self {
        Self {
            blocks: [const { [const { None }; CAPACITY] }; CLASSES],
            counts: [0; CLASSES],
        }
    }

    pub(crate) fn take(&mut self, class: CacheClass) -> Option<CachedAllocation> {
        let count = self.counts[class.0].checked_sub(1)?;
        let block = self.blocks[class.0][count].take();
        self.counts[class.0] = count;
        block
    }

    /// # Errors
    /// A full class returns the allocation unchanged for backing deallocation;
    /// failure never discards or duplicates its exclusive cache ownership.
    pub(crate) fn insert(&mut self, block: CachedAllocation) -> Result<(), CachedAllocation> {
        let class = block.class;
        let count = self.counts[class.0];
        if count == CAPACITY {
            return Err(block);
        }
        self.blocks[class.0][count] = Some(block);
        self.counts[class.0] = count + 1;
        Ok(())
    }

    pub(crate) fn steal(&mut self, class: CacheClass) -> Option<CachedAllocation> {
        // Keep the victim's reserve rather than draining its hot working set.
        if self.counts[class.0] <= CAPACITY / 2 {
            None
        } else {
            self.take(class)
        }
    }
}
