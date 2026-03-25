use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use core::ptr::NonNull;
use x86_64::PhysAddr;
use x86_64::VirtAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

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

// Minimal fast allocator shim used by IOMMU tests
pub mod fast_allocator {

    pub const PAGE_SIZE_4K: u64 = 4096;
    pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
    pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

    #[derive(Clone, Copy, Debug)]
    pub enum PageGranularity {
        Page4K,
        Page2M,
        Page1G,
    }

    impl PageGranularity {
        pub fn size_bytes(&self) -> u64 {
            match self {
                PageGranularity::Page4K => PAGE_SIZE_4K,
                PageGranularity::Page2M => PAGE_SIZE_2M,
                PageGranularity::Page1G => PAGE_SIZE_1G,
            }
        }
    }

    use core::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    pub struct FastBitmapAllocator {
        base: u64,
        size: u64,
        next: AtomicU64,
    }

    impl FastBitmapAllocator {
        pub fn new(base: u64, size: u64) -> Self {
            Self {
                base,
                size,
                next: AtomicU64::new(0),
            }
        }

        pub fn allocate_4k(&self) -> Option<u64> {
            self.allocate_with_size(PAGE_SIZE_4K)
        }
        pub fn allocate_2m(&self) -> Option<u64> {
            self.allocate_with_size(PAGE_SIZE_2M)
        }
        pub fn allocate_1g(&self) -> Option<u64> {
            self.allocate_with_size(PAGE_SIZE_1G)
        }

        fn allocate_with_size(&self, sz: u64) -> Option<u64> {
            // Simple atomic bump allocator
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                let cur = self.next.load(Ordering::Relaxed);
                if cur + sz > self.size {
                    return None;
                }
                if self
                    .next
                    .compare_exchange(cur, cur + sz, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return Some(self.base + cur);
                }
            }
        }

        pub fn allocate_4k_below(&self, limit: u64) -> Option<u64> {
            self.allocate_below(PAGE_SIZE_4K, limit)
        }
        pub fn allocate_2m_below(&self, limit: u64) -> Option<u64> {
            self.allocate_below(PAGE_SIZE_2M, limit)
        }
        pub fn allocate_1g_below(&self, limit: u64) -> Option<u64> {
            self.allocate_below(PAGE_SIZE_1G, limit)
        }

        fn allocate_below(&self, sz: u64, limit: u64) -> Option<u64> {
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                let cur = self.next.load(Ordering::Relaxed);
                if cur + sz > self.size || self.base + cur + sz > limit {
                    return None;
                }
                if self
                    .next
                    .compare_exchange(cur, cur + sz, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return Some(self.base + cur);
                }
            }
        }

        pub fn allocate_contiguous(&self, _size: u64, _align: u64) -> Option<u64> {
            // Align up current pointer and allocate
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                let cur = self.next.load(Ordering::Relaxed);
                let aligned = ((cur + (_align - 1)) / _align) * _align;
                if aligned + _size > self.size {
                    return None;
                }
                if self
                    .next
                    .compare_exchange(cur, aligned + _size, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return Some(self.base + aligned);
                }
            }
        }

        pub fn free_immediate(&self, _addr: u64, _gran: PageGranularity) -> Result<(), ()> {
            Ok(())
        }

        pub fn reserve(&self, _start: u64, _size: u64) -> Result<(), ()> {
            Ok(())
        }

        pub fn reconfigure_for_cpu_ids(&mut self, _cpu_ids: &[usize]) {}

        pub fn enable_single_writer_arenas(&self) {}

        pub fn drain_remote_frees(&self) {}
        pub fn base(&self) -> u64 {
            self.base
        }
        pub fn size(&self) -> u64 {
            self.size
        }
    }
}

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

pub mod types {
    #[derive(Clone, Copy)]
    pub struct NumaNodeId(pub u8);
    impl NumaNodeId {
        pub fn new(n: u8) -> Self {
            Self(n)
        }
        pub fn as_usize(&self) -> usize {
            self.0 as usize
        }
    }
    pub const PAGE_SIZE_4K: usize = 4096;
    pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
    pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;
}

pub mod frame_allocator {
    use x86_64::PhysAddr;
    use x86_64::structures::paging::{PhysFrame, Size4KiB};

    pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
        super::buddy_alloc_frame()
    }

    pub fn alloc_frame_on_numa_node(node: super::types::NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
        super::buddy_alloc_frame_on_node(node)
    }

    pub fn alloc_contiguous_frames(frames: usize) -> Option<PhysAddr> {
        super::buddy_alloc_contiguous_frames(frames)
    }

    pub fn dealloc_contiguous_frames(_phys: PhysAddr, _frames: usize) {
        // No-op in test shim
    }

    pub fn pmm_managed_end() -> Option<u64> {
        None
    }

    pub fn is_range_managed_by_pmm(_addr: PhysAddr, _size: u64) -> bool {
        true
    }

    pub fn dealloc_frame(frame: PhysFrame<Size4KiB>) {
        super::buddy_dealloc_frame(frame);
    }

    /// Memory pressure hint for tests (0 = no pressure)
    pub fn memory_pressure_level() -> u8 {
        0
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

pub fn buddy_alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    let layout = Layout::from_size_align(4096, 4096).ok()?;
    let ptr = unsafe { alloc_zeroed(layout) };
    let ptr = NonNull::new(ptr)?;
    let phys = PhysAddr::new(ptr.as_ptr() as u64);
    match PhysFrame::from_start_address(phys) {
        Ok(frame) => Some(frame),
        Err(_) => {
            unsafe { dealloc(ptr.as_ptr(), layout) };
            None
        }
    }
}

pub fn buddy_alloc_frame_on_node(_node: types::NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
    buddy_alloc_frame()
}

pub fn buddy_alloc_contiguous_frames(frame_count: usize) -> Option<PhysAddr> {
    if frame_count == 0 {
        return None;
    }
    let bytes = frame_count.checked_mul(4096)?;
    let layout = Layout::from_size_align(bytes, 4096).ok()?;
    let ptr = unsafe { alloc_zeroed(layout) };
    let ptr = NonNull::new(ptr)?;
    Some(PhysAddr::new(ptr.as_ptr() as u64))
}

pub fn buddy_dealloc_frame(frame: PhysFrame<Size4KiB>) {
    let layout = Layout::from_size_align(4096, 4096).expect("buddy layout");
    let ptr = frame.start_address().as_u64() as *mut u8;
    unsafe { dealloc(ptr, layout) };
}

// Convenience wrappers for IOMMU/legacy APIs used in some modules/tests
pub fn alloc_contiguous_frames(frames: usize) -> Option<PhysAddr> {
    buddy_alloc_contiguous_frames(frames)
}

pub fn dealloc_contiguous_frames(_phys: PhysAddr, _frames: usize) {
    // Test shim: no-op - memory will be reclaimed when the test process exits.
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
    pub mod buddy_allocator {
        /// Stub for buddy_allocator_stats (test shim)
        pub struct BuddyAllocatorStats {
            pub total_frames: usize,
            pub free_frames: usize,
            pub split_count: u64,
            pub coalesce_count: u64,
            pub order_stats: [(usize, usize); 19],
        }
        pub fn buddy_allocator_stats() -> BuddyAllocatorStats {
            BuddyAllocatorStats {
                total_frames: 0,
                free_frames: 0,
                split_count: 0,
                coalesce_count: 0,
                order_stats: [(0, 0); 19],
            }
        }
    }
    pub mod unified_alloc {
        pub fn memory_pressure_level() -> u8 {
            0
        }
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

pub mod cache {
    pub mod magazine {
        #[allow(clippy::wildcard_imports)]
        pub use super::super::magazine::*;
    }
}

pub mod numa {
    pub fn num_nodes() -> usize {
        topology::num_nodes()
    }

    pub fn current_node() -> usize {
        topology::current_node()
    }

    pub mod topology {
        use alloc::alloc::{alloc_zeroed, dealloc};
        use core::alloc::Layout;
        use core::ptr::NonNull;

        pub const MAX_NUMA_NODES: usize = 8;

        pub fn num_nodes() -> usize {
            1
        }
        pub fn current_node() -> usize {
            0
        }

        pub fn allocate_zeroed_on_node(
            layout: Layout,
            _node: Option<usize>,
        ) -> Option<NonNull<u8>> {
            unsafe {
                let ptr = alloc_zeroed(layout);
                NonNull::new(ptr)
            }
        }

        pub fn allocate_zeroed_on_node_with_info(
            layout: Layout,
            _node: Option<usize>,
        ) -> Option<(NonNull<u8>, usize)> {
            unsafe {
                let ptr = alloc_zeroed(layout);
                NonNull::new(ptr).map(|p| (p, 0))
            }
        }

        pub unsafe fn deallocate_on_node(ptr: NonNull<u8>, layout: Layout, _node: Option<usize>) {
            unsafe {
                dealloc(ptr.as_ptr(), layout);
            }
        }
    }
}

pub mod meta {
    pub mod memcg {
        #[allow(wildcard_imports)]
        pub use super::super::memcg::*;
    }
}
