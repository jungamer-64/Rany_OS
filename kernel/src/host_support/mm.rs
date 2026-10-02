use x86_64::PhysAddr;
use x86_64::VirtAddr;

#[path = "../mm/reclaim/pool.rs"]
pub(crate) mod reclaim;

pub mod magazine {
    pub struct Magazine<T, const N: usize> {
        _marker: core::marker::PhantomData<T>,
    }
    impl<T, const N: usize> Magazine<T, N> {
        pub fn new() -> Self {
            Self {
                _marker: core::marker::PhantomData,
            }
        }
    }
    // Clone implementation might be needed if IovaMagazine is cloned in tests
    impl<T, const N: usize> Clone for Magazine<T, N> {
        fn clone(&self) -> Self {
            Self::new()
        }
    }
    impl<T, const N: usize> Copy for Magazine<T, N> {}
}

pub mod memcg {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct MemcgId;
    impl MemcgId {
        pub const ROOT: Self = Self;
    }
}

// Address-space tests execute the production occupancy implementation.
#[path = "../mm/bitmap.rs"]
pub mod bitmap;
#[path = "../mm/phys/fast_allocator.rs"]
pub mod fast_allocator;

// Minimal remote-free / quarantine shim used by IOVA allocator
pub mod remote_free {
    use alloc::collections::VecDeque;

    #[derive(Debug, Clone, Copy, Default)]
    pub struct QuarantineEntry {
        pub addr: u64,
        pub epoch: u32,
        pub size_class: u8,
    }

    #[derive(Debug)]
    pub struct QuarantineRing<const CAP: usize> {
        buf: VecDeque<QuarantineEntry>,
    }

    impl<const CAP: usize> QuarantineRing<CAP> {
        pub const fn new() -> Self {
            Self {
                buf: VecDeque::new(),
            }
        }

        pub fn push(&mut self, addr: u64, size_class: u8, epoch: u32) -> bool {
            if self.buf.len() >= CAP {
                false
            } else {
                self.buf.push_back(QuarantineEntry {
                    addr,
                    epoch,
                    size_class,
                });
                true
            }
        }

        pub fn push_entry(&mut self, entry: QuarantineEntry) -> bool {
            self.push(entry.addr, entry.size_class, entry.epoch)
        }

        pub fn drain_older_than(
            &mut self,
            completed_epoch: u32,
            limit: usize,
            out: &mut [QuarantineEntry],
        ) -> usize {
            let mut count = 0usize;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while count < limit {
                if let Some(front) = self.buf.front() {
                    if front.epoch <= completed_epoch {
                        let e = self.buf.pop_front().unwrap();
                        out[count] = e;
                        count += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            count
        }

        pub fn drain_all(&mut self, out: &mut [QuarantineEntry]) -> usize {
            let mut count = 0usize;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while count < out.len() {
                if let Some(e) = self.buf.pop_front() {
                    out[count] = e;
                    count += 1;
                } else {
                    break;
                }
            }
            count
        }
    }
}

#[path = "../mm/types.rs"]
pub mod types;
#[path = "../mm/value.rs"]
pub mod value;

/// Host RAM has the same exclusive release contract as admitted physical RAM.
/// Identity mapping is the host boundary; the backing Layout is retained by its
/// owner, so an address observation cannot reconstruct allocation authority.
pub mod frame_allocator {
    use super::types::NumaNodeId;
    use alloc::alloc::{alloc_zeroed, dealloc};
    use core::alloc::Layout;
    use core::ptr::NonNull;
    use x86_64::PhysAddr;
    use x86_64::structures::paging::{PageSize, PhysFrame};

    

    #[derive(Debug)]
    struct HostBacking {
        pointer: NonNull<u8>,
        layout: Layout,
    }
    // SAFETY: this immutable owner only releases storage after the last disjoint
    // host physical extent has consumed its ownership; it never grants RAM access.
    unsafe impl Send for HostBacking {}
    unsafe impl Sync for HostBacking {}
    impl Drop for HostBacking {
        fn drop(&mut self) {
            // SAFETY: all disjoint extent owners have released their references.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }
    #[derive(Debug)]
    pub struct PhysicalAllocation {
        backing: core::mem::ManuallyDrop<alloc::sync::Arc<HostBacking>>,
        offset: usize,
        bytes: usize,
        node: NumaNodeId,
    }
    // SAFETY: the owner transfers exclusive host allocation access; NonNull is
    // never dereferenced through a shared reference or freed without consuming it.
    unsafe impl Send for PhysicalAllocation {}
    impl PhysicalAllocation {
        pub fn start_address(&self) -> PhysAddr {
            PhysAddr::new(self.as_u64())
        }
        pub fn as_u64(&self) -> u64 {
            (self.backing.pointer.as_ptr().addr() + self.offset) as u64
        }
        pub fn size_bytes(&self) -> u64 {
            self.bytes as u64
        }
        pub fn page_count(&self) -> usize {
            self.bytes / 4096
        }
        pub fn node(&self) -> NumaNodeId {
            self.node
        }
        pub fn frame<S: PageSize>(&self) -> Result<PhysFrame<S>, FrameAllocError> {
            if S::SIZE > self.size_bytes() {
                return Err(FrameAllocError::InvalidRange);
            }
            PhysFrame::from_start_address(self.start_address())
                .map_err(|_| FrameAllocError::Alignment)
        }
        pub fn split(mut self, first_pages: usize) -> Result<(Self, Self), Self> {
            if first_pages == 0 || first_pages >= self.page_count() {
                return Err(self);
            }
            let bytes = first_pages * 4096;
            let second = Self {
                backing: core::mem::ManuallyDrop::new(alloc::sync::Arc::clone(&self.backing)),
                offset: self.offset + bytes,
                bytes: self.bytes - bytes,
                node: self.node,
            };
            self.bytes = bytes;
            Ok((self, second))
        }
        pub fn release(mut self) {
            // SAFETY: this unique extent consumes exactly one retained backing
            // reference. Forgetting an extent deliberately leaks that reference.
            drop(unsafe { core::mem::ManuallyDrop::take(&mut self.backing) });
        }
    }
    pub fn alloc_contiguous_frames_aligned_on_node(
        node: NumaNodeId,
        frames: usize,
        alignment: usize,
    ) -> Result<PhysicalAllocation, FrameAllocError> {
        if node != NumaNodeId::NODE_0 {
            return Err(FrameAllocError::InvalidNode);
        }
        if frames == 0 {
            return Err(FrameAllocError::InvalidRange);
        }
        if !alignment.is_power_of_two() {
            return Err(FrameAllocError::Alignment);
        }
        let bytes = frames
            .checked_mul(4096)
            .ok_or(FrameAllocError::InvalidRange)?;
        let layout = Layout::from_size_align(bytes, alignment.max(4096))
            .map_err(|_| FrameAllocError::InvalidRange)?;
        // SAFETY: a valid nonzero Layout grants exclusive writable host RAM.
        let backing =
            NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(FrameAllocError::Exhausted)?;
        // A failed Arc admission drops HostBacking and returns its RAM using
        // the retained Layout; allocation and metadata exhaustion stay distinct.
        let backing = alloc::sync::Arc::try_new(HostBacking {
            pointer: backing,
            layout,
        })
        .map_err(|_| FrameAllocError::MetadataAllocation)?;
        Ok(PhysicalAllocation {
            backing: core::mem::ManuallyDrop::new(backing),
            offset: 0,
            bytes,
            node,
        })
    }
    pub fn alloc_contiguous_frames_aligned(
        frames: usize,
        alignment: usize,
    ) -> Result<PhysicalAllocation, FrameAllocError> {
        alloc_contiguous_frames_aligned_on_node(NumaNodeId::NODE_0, frames, alignment)
    }
    pub fn alloc_contiguous_frames(frames: usize) -> Result<PhysicalAllocation, FrameAllocError> {
        alloc_contiguous_frames_aligned(frames, 4096)
    }
    pub fn alloc_frame() -> Result<PhysicalAllocation, FrameAllocError> {
        alloc_contiguous_frames(1)
    }
    pub(crate) fn node_distance(from: NumaNodeId, to: NumaNodeId) -> Option<u8> {
        (from == NumaNodeId::NODE_0 && to == NumaNodeId::NODE_0).then_some(10)
    }
    pub fn alloc_frame_on_numa_node(
        node: NumaNodeId,
    ) -> Result<PhysicalAllocation, FrameAllocError> {
        alloc_contiguous_frames_aligned_on_node(node, 1, 4096)
    }
    pub fn dealloc_frame(owner: PhysicalAllocation) {
        owner.release();
    }
    pub(crate) fn drain_current_cache() -> usize {
        0 // hosted RAM is returned directly; it has no CPU frame magazine
    }
    pub fn dealloc_contiguous_frames(owner: PhysicalAllocation) {
        owner.release();
    }
    pub fn pmm_managed_end() -> Option<u64> {
        None
    }
    pub fn is_range_managed_by_pmm(_addr: PhysAddr, size: u64) -> bool {
        size != 0
    }
    pub fn memory_pressure_level() -> u8 {
        0
    }
    pub(crate) fn allocation_order(_: NumaNodeId) -> Option<&'static [Option<NumaNodeId>; 8]> {
        static ORDER: [Option<NumaNodeId>; 8] = [
            Some(NumaNodeId::NODE_0),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        Some(&ORDER)
    }
}

// Re-export frame allocator helpers at `crate::mm::phys::frame_allocator::dealloc_frame` etc.
pub use frame_allocator::dealloc_frame;
pub use frame_allocator::memory_pressure_level;

// Minimal `higher_half` shim (for tests): small wrappers around u64 addresses
pub mod higher_half {
    #[derive(Clone, Copy, Debug)]
    pub struct VirtAddr(u64);
    impl VirtAddr {
        pub const fn new(addr: u64) -> Self {
            Self(addr)
        }
        pub const fn as_u64(&self) -> u64 {
            self.0
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct PhysAddr(u64);
    impl PhysAddr {
        pub const fn new(addr: u64) -> Self {
            Self(addr)
        }
        pub const fn as_u64(&self) -> u64 {
            self.0
        }
    }
}

// Global translate helper for tests (use kernel `higher_half` types)
pub fn global_translate(
    virt: crate::mm::virt::higher_half::VirtAddr,
) -> Option<crate::mm::virt::higher_half::PhysAddr> {
    let v = x86_64::VirtAddr::new(virt.as_u64());
    let p = mapping::virt_to_phys(v);
    Some(crate::mm::virt::higher_half::PhysAddr::new(p.as_u64()))
}

// Minimal address translation helpers for tests/benches.
pub mod mapping {
    use x86_64::{PhysAddr, VirtAddr};

    pub fn virt_to_phys(addr: VirtAddr) -> PhysAddr {
        PhysAddr::new(addr.as_u64())
    }

    pub fn phys_to_virt(addr: PhysAddr) -> VirtAddr {
        VirtAddr::new(addr.as_u64())
    }
}

pub fn mapping_phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64())
}

/// 4K page size constant for compatibility with drivers/tests
pub const PAGE_SIZE_4K: usize = 4096;

// ======================================================================
// Wrapper sub-modules mirroring the new directory-based module hierarchy
// ======================================================================
pub mod phys {
    pub mod fast_allocator {
        #[allow(clippy::wildcard_imports)]
        pub use super::super::fast_allocator::*;
    }
    pub mod frame_allocator {
        #[allow(clippy::wildcard_imports)]
        pub use super::super::frame_allocator::*;
    }
}

pub mod virt {
    pub mod higher_half {
        #[allow(clippy::wildcard_imports)]
        pub use super::super::higher_half::*;

        pub fn global_translate(virt: VirtAddr) -> Option<PhysAddr> {
            let phys = super::mapping::virt_to_phys(x86_64::VirtAddr::new(virt.as_u64()));
            Some(PhysAddr::new(phys.as_u64()))
        }
    }
    pub mod mapping {
        #[allow(clippy::wildcard_imports)]
        pub use super::super::mapping::*;
    }
}

#[path = "../mm/cache/exchange_heap.rs"]
pub mod exchange_heap;

pub mod cache {
    pub use super::exchange_heap;
    pub mod magazine {
        #[allow(clippy::wildcard_imports)]
        pub use super::super::magazine::*;
    }
}

#[path = "../mm/numa/placement.rs"]
pub mod numa_placement;

pub mod numa {
    pub use super::numa_placement as placement;
    pub fn num_nodes() -> usize {
        topology::num_nodes()
    }

    pub fn current_node() -> usize {
        topology::current_node()
    }

    pub mod topology {

        pub fn num_nodes() -> usize {
            1
        }
        pub fn current_node() -> usize {
            0
        }
    }
}

pub mod meta {
    pub mod memcg {
        pub use super::super::memcg::*;
    }
}

#[cfg(feature = "buddy_freelist")]
#[path = "../mm/phys/buddy_freelist.rs"]
pub mod buddy_freelist;
