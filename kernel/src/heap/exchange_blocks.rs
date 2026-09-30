//! Exclusive block allocator for Exchange Heap backing RAM. Every physical
//! block has an initialized header outside its payload; adjacency is represented
//! by the next header's previous extent, never by inspecting caller bytes.
#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use super::HeapMemory;
use core::alloc::Layout;
use core::ptr::NonNull;

const CLASSES: usize = usize::BITS as usize;

#[derive(Clone, Copy)]
struct BlockHeader {
    extent: usize,
    previous_extent: usize,
    next_free: Option<NonNull<BlockHeader>>,
    previous_free: Option<NonNull<BlockHeader>>,
    free: bool,
}

#[derive(Clone, Copy)]
struct AllocationPrefix {
    block: NonNull<BlockHeader>,
}

const HEADER_BYTES: usize = core::mem::size_of::<BlockHeader>();
const PREFIX_BYTES: usize = core::mem::size_of::<AllocationPrefix>();
const HEADER_ALIGN: usize = core::mem::align_of::<BlockHeader>();
const MIN_EXTENT: usize = HEADER_BYTES + PREFIX_BYTES + HEADER_ALIGN;

/// Backing allocator statistics include reserved metadata/padding and cached
/// blocks. A block held in a CPU cache is not globally free/coalescible RAM.
#[derive(Debug, Clone, Copy)]
pub struct ExtendedHeapStats {
    pub allocated: usize,
    pub free: usize,
    pub alloc_count: u64,
    pub dealloc_count: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    pub non_empty_classes: u64,
}

pub(crate) struct ExchangeBlocks {
    backing: Option<HeapMemory>,
    lists: [Option<NonNull<BlockHeader>>; CLASSES],
    available: u64,
    allocated: usize,
    alloc_count: u64,
    dealloc_count: u64,
    split_count: u64,
    coalesce_count: u64,
}

#[expect(
    unsafe_code,
    reason = "intrusive links point into retained exclusively owned RAM"
)]
// SAFETY: moving the exclusive owner transfers all header/list authority.
// RAM is retained, CPU-independent and stable; all writes require &mut self.
// No references into metadata or reclaimers survive the move.
unsafe impl Send for ExchangeBlocks {}

impl ExchangeBlocks {
    pub(crate) const fn empty() -> Self {
        Self {
            backing: None,
            lists: [None; CLASSES],
            available: 0,
            allocated: 0,
            alloc_count: 0,
            dealloc_count: 0,
            split_count: 0,
            coalesce_count: 0,
        }
    }

    /// # Errors
    /// A second admission returns the untouched incoming owner. Existing
    /// allocations and their metadata remain valid; initialization is not repair.
    #[expect(
        unsafe_code,
        reason = "initializes the first header in exclusive admitted RAM"
    )]
    pub(crate) fn initialize(&mut self, memory: HeapMemory) -> Result<(), HeapMemory> {
        if self.backing.is_some() {
            return Err(memory);
        }
        let extent = memory.size();
        let block = memory.base().cast::<BlockHeader>();
        self.backing = Some(memory);
        // SAFETY: HeapMemory admits page-aligned writable RAM with page-exact
        // nonzero extent, larger than a header. No prior header/payload exists.
        unsafe {
            block.as_ptr().write(BlockHeader {
                extent,
                previous_extent: 0,
                next_free: None,
                previous_free: None,
                free: true,
            });
            self.link_free(block);
        }
        Ok(())
    }

    fn floor_class(extent: usize) -> usize {
        (usize::BITS - 1 - extent.leading_zeros()) as usize
    }

    /// Metadata, worst-case alignment padding and nonzero payload precede list
    /// mutation. The search rounds up; free blocks are indexed by rounding down,
    /// so one bitmap lookup always selects a sufficiently large block.
    fn required_extent(layout: Layout) -> Option<usize> {
        let align = layout.align().max(HEADER_ALIGN);
        let bytes = HEADER_BYTES
            .checked_add(PREFIX_BYTES)?
            .checked_add(align - 1)?
            .checked_add(layout.size().max(1))?;
        let extent = bytes.checked_add(HEADER_ALIGN - 1)? & !(HEADER_ALIGN - 1);
        (extent <= isize::MAX as usize).then_some(extent)
    }

    /// # Safety
    /// `block` is an initialized, exclusively owned header in this slab, not
    /// currently linked in any free list. Its extent includes no live payload.
    #[expect(
        unsafe_code,
        reason = "list links only name initialized free headers owned by this allocator"
    )]
    unsafe fn link_free(&mut self, block: NonNull<BlockHeader>) {
        // SAFETY: caller supplies an initialized owned header, not on a list;
        // &mut self excludes all simultaneous metadata mutation.
        let header = unsafe { &mut *block.as_ptr() };
        let class = Self::floor_class(header.extent);
        header.free = true;
        header.previous_free = None;
        header.next_free = self.lists[class];
        if let Some(next) = header.next_free {
            // SAFETY: the existing head is initialized and disjoint from block.
            unsafe { (*next.as_ptr()).previous_free = Some(block) };
        }
        self.lists[class] = Some(block);
        self.available |= 1u64 << class;
    }

    /// # Safety
    /// `block` is a live member of this allocator's free list, with reciprocal
    /// initialized links; no independently owned allocation aliases the header.
    #[expect(
        unsafe_code,
        reason = "constant-time unlink of a live owned intrusive list member"
    )]
    unsafe fn unlink_free(&mut self, block: NonNull<BlockHeader>) {
        // SAFETY: caller supplies a live member of exactly one owned free list.
        let header = unsafe { block.as_ptr().read() };
        let class = Self::floor_class(header.extent);
        if let Some(previous) = header.previous_free {
            // SAFETY: reciprocal links identify an initialized, disjoint member.
            unsafe { (*previous.as_ptr()).next_free = header.next_free };
        } else {
            self.lists[class] = header.next_free;
        }
        if let Some(next) = header.next_free {
            // SAFETY: reciprocal links identify an initialized, disjoint member.
            unsafe { (*next.as_ptr()).previous_free = header.previous_free };
        }
        if self.lists[class].is_none() {
            self.available &= !(1u64 << class);
        }
    }

    /// # Safety
    /// The initialized owned block's exact extent ends at the slab end or the
    /// next initialized header. No arbitrary interior/payload position is valid.
    #[expect(
        unsafe_code,
        reason = "adjacency visits initialized header boundaries, never payload storage"
    )]
    unsafe fn successor(
        &self,
        block: NonNull<BlockHeader>,
        extent: usize,
    ) -> Option<NonNull<BlockHeader>> {
        let end = self.backing.as_ref()?.end();
        if block.as_ptr().addr() + extent == end {
            None
        } else {
            // SAFETY: caller's block extent is inside the retained slab. Every
            // nonterminal block end is another initialized, aligned header.
            Some(unsafe { block.byte_add(extent) })
        }
    }

    /// Returns None without mutating state for an impossible layout, an empty
    /// allocator or exhausted eligible size classes. No fallible work follows
    /// unlink/publication of an allocation. Payload includes no metadata bytes.
    #[expect(
        unsafe_code,
        reason = "splits exclusive RAM and initializes metadata before publication"
    )]
    pub(crate) fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let required = Self::required_extent(layout)?;
        let class = Self::floor_class(required.checked_next_power_of_two()?);
        let eligible = self.available & (u64::MAX << class);
        if eligible == 0 {
            return None;
        }
        let block = self.lists[eligible.trailing_zeros() as usize]?;
        // SAFETY: the bitmap/list relation publishes only fully initialized
        // free headers, disjoint from every live/cached payload.
        let original = unsafe { block.as_ptr().read() };
        let align = layout.align().max(HEADER_ALIGN);
        let payload_addr =
            (block.as_ptr().addr() + HEADER_BYTES + PREFIX_BYTES + align - 1) & !(align - 1);
        let used = (payload_addr - block.as_ptr().addr() + layout.size().max(1) + HEADER_ALIGN - 1)
            & !(HEADER_ALIGN - 1);
        let remaining = original.extent - used;
        let extent = if remaining >= MIN_EXTENT {
            used
        } else {
            original.extent
        };

        // SAFETY: chosen free extent covers worst-case padding and payload;
        // the split writes fully initialized aligned headers before linking.
        unsafe {
            self.unlink_free(block);
            block.as_ptr().write(BlockHeader {
                extent,
                previous_extent: original.previous_extent,
                next_free: None,
                previous_free: None,
                free: false,
            });
            if remaining >= MIN_EXTENT {
                let tail = block.byte_add(extent);
                tail.as_ptr().write(BlockHeader {
                    extent: remaining,
                    previous_extent: extent,
                    next_free: None,
                    previous_free: None,
                    free: true,
                });
                if let Some(next) = self.successor(tail, remaining) {
                    (*next.as_ptr()).previous_extent = remaining;
                }
                self.link_free(tail);
                self.split_count = self.split_count.saturating_add(1);
            }
            let payload = block.cast::<u8>().with_addr(
                core::num::NonZeroUsize::new(payload_addr).expect("owned RAM is nonzero"),
            );
            payload
                .byte_sub(PREFIX_BYTES)
                .cast::<AllocationPrefix>()
                .as_ptr()
                .write(AllocationPrefix { block });
            self.allocated += extent;
            self.alloc_count = self.alloc_count.saturating_add(1);
            Some(payload)
        }
    }

    /// # Safety
    /// `ptr` is an exclusive live allocation returned by this allocator, with
    /// the exact original Layout. No outstanding borrow or prior deallocation
    /// remains. Cached blocks must leave their cache before reaching this boundary.
    #[expect(
        unsafe_code,
        reason = "consumes an allocation and coalesces only initialized adjacent headers"
    )]
    pub(crate) unsafe fn deallocate(&mut self, ptr: NonNull<u8>, _layout: Layout) {
        // SAFETY: allocation publication wrote the aligned prefix outside the
        // caller's payload. Caller consumes its live allocation exactly once.
        let prefix = unsafe {
            ptr.byte_sub(PREFIX_BYTES)
                .cast::<AllocationPrefix>()
                .as_ptr()
                .read()
        };
        // SAFETY: the private prefix retains the initialized owning header.
        let header = unsafe { prefix.block.as_ptr().read() };
        let mut block = prefix.block;
        let mut extent = header.extent;
        let mut previous_extent = header.previous_extent;

        // SAFETY: adjacency extents are maintained only in initialized headers;
        // allocated/cached neighbors retain free=false and are never inspected
        // through their payload. Unlink is constant-time before coalescing.
        unsafe {
            let next = self.successor(block, extent);
            if previous_extent != 0 {
                let previous = block.byte_sub(previous_extent);
                let previous_header = previous.as_ptr().read();
                if previous_header.free {
                    self.unlink_free(previous);
                    block = previous;
                    extent += previous_extent;
                    previous_extent = previous_header.previous_extent;
                    self.coalesce_count = self.coalesce_count.saturating_add(1);
                }
            }
            if let Some(next) = next {
                let next_header = next.as_ptr().read();
                if next_header.free {
                    self.unlink_free(next);
                    extent += next_header.extent;
                    self.coalesce_count = self.coalesce_count.saturating_add(1);
                }
            }
            block.as_ptr().write(BlockHeader {
                extent,
                previous_extent,
                next_free: None,
                previous_free: None,
                free: true,
            });
            if let Some(next) = self.successor(block, extent) {
                (*next.as_ptr()).previous_extent = extent;
            }
            self.link_free(block);
        }
        self.allocated -= header.extent;
        self.dealloc_count = self.dealloc_count.saturating_add(1);
    }

    pub(crate) fn stats(&self) -> ExtendedHeapStats {
        let total = self.backing.as_ref().map_or(0, HeapMemory::size);
        ExtendedHeapStats {
            allocated: self.allocated,
            free: total - self.allocated,
            alloc_count: self.alloc_count,
            dealloc_count: self.dealloc_count,
            split_count: self.split_count,
            coalesce_count: self.coalesce_count,
            non_empty_classes: self.available,
        }
    }
}
