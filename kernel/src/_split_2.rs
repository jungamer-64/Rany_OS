use super::*;



// For unit testing we expose a small set of modules via the library entry
// point. This keeps most of the kernel as a binary-only crate while still
// allowing targeted library-style tests (e.g. security/capability) to run
// under `cargo test --lib` without pulling the entire binary test harness.
#[cfg(all(test, not(feature = "full_mm_tests")))]
pub mod security;

// QEMU suite exports are compiled when `qemu-test-export` is enabled and are
// consumed by `qemu-suites/*` orchestrators.
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// Expose additional modules when building tests so unit tests inside those
// modules can be executed via `cargo test --lib`.
// Also expose the `graphics` module when compiling benches via the
// `bench` feature so Criterion benches can access framebuffer types and
// helpers. This keeps the default binary layout unchanged while allowing
// convenient benching during development.
#[cfg(any(not(test), test, feature = "bench", feature = "full_mm_tests"))]
pub mod graphics;

// Provide fallback TLS symbols on host Windows builds where the kernel
// linker script is not used. This prevents undefined reference linker
// errors for `__tls_start` / `__tls_end` when building the binary for
// `cargo test` on Windows hosts.
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub static __tls_start: u8 = 0;
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub static __tls_end: u8 = 0;

// Minimal test/bench `mm::numa` shim to satisfy IOMMU tests and benchmark builds
// without pulling in the full memory subsystem and its heavy dependencies.
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod fs;

// Intrusive collections for kernel use (always available)
pub mod collections;

#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod mm;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod io;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod task;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod sync;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod ipc;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod net;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod domain;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod security;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod service_impl;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod util;
#[cfg(any(not(test), test, feature = "full_mm_tests"))]
pub mod time;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod unwind;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod error;
pub mod memory;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod smp;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod interrupts;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod sas;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod panic_handler;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod thermal;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod monitor;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod watchdog;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod power;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod loader;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod console;

#[cfg(not(feature = "full_mm_tests"))]
#[cfg(any(test, feature = "bench"))]
pub mod mm {
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

    pub mod numa {
        use alloc::alloc::{Layout as ALayout, alloc_zeroed, dealloc};
        use core::alloc::Layout;
        use core::ptr::NonNull;

        /// Return the number of NUMA nodes (test shim: single node)
        pub fn num_nodes() -> usize {
            1
        }

        /// Return current node id (test shim: 0)
        pub fn current_node() -> usize {
            0
        }

        /// Allocate zeroed memory on a given node (test shim uses the global allocator)
        pub fn allocate_zeroed_on_node(
            layout: Layout,
            _node: Option<usize>,
        ) -> Option<NonNull<u8>> {
            unsafe {
                let ptr = alloc_zeroed(layout);
                NonNull::new(ptr)
            }
        }

        pub unsafe fn deallocate_on_node(
            ptr: NonNull<u8>,
            layout: Layout,
            _node: Option<usize>,
        ) {
            unsafe { dealloc(ptr.as_ptr(), layout); }
        }
    }

    pub mod memcg {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub struct MemcgId;
        impl MemcgId {
            pub const ROOT: Self = Self;
        }
    }


    // Minimal per-CPU stubs used by IOMMU unit tests. These avoid pulling the
    // full per-CPU subsystem into the test build while providing the API
    // expected by `iommu.rs`.
    pub mod per_cpu {
        use core::array;

        /// Cache entry for device to domain mapping (test shim)
        #[derive(Clone, Copy, Default)]
        pub struct DomainCacheEntry {
            pub device_id: u16,
            pub domain_id: u16,
            pub controller_idx: u8,
            pub valid: bool,
        }

        /// Per-CPU domain cache (test shim)
        pub struct PerCpuDomainCache {
            pub entries: [DomainCacheEntry; Self::CACHE_SIZE],
        }

        impl PerCpuDomainCache {
            pub const CACHE_SIZE: usize = 64;

            pub fn new() -> Self {
                Self {
                    entries: [DomainCacheEntry {
                        device_id: 0,
                        domain_id: 0,
                        controller_idx: 0,
                        valid: false,
                    }; Self::CACHE_SIZE],
                }
            }

            pub fn lookup(&self, device_id: u16) -> Option<(u16, u8)> {
                let idx = (device_id as usize) % Self::CACHE_SIZE;
                let entry = self.entries[idx];
                if entry.valid && entry.device_id == device_id {
                    Some((entry.domain_id, entry.controller_idx))
                } else {
                    None
                }
            }

            pub fn insert(&mut self, device_id: u16, domain_id: u16, controller_idx: u8) {
                let idx = (device_id as usize) % Self::CACHE_SIZE;
                self.entries[idx] = DomainCacheEntry {
                    device_id,
                    domain_id,
                    controller_idx,
                    valid: true,
                };
            }

            pub fn invalidate(&mut self, device_id: u16) {
                let idx = (device_id as usize) % Self::CACHE_SIZE;
                if self.entries[idx].device_id == device_id {
                    self.entries[idx].valid = false;
                }
            }
        }

        pub const IOVA_MAG_CAPACITY: usize = 256;
        pub const MAX_IOMMU_CONTROLLERS: usize = 8;

        // IOVA_MM_MIGRATION_PLAN Phase 1.1: Magazine<T, N>の型エイリアス
        use crate::mm::magazine::Magazine;
        pub type IovaMagazine = Magazine<u64, IOVA_MAG_CAPACITY>;

        // Small per-CPU PtMagazine capacity for page tables
        pub const PT_MAG_CAPACITY: usize = 8;

        #[derive(Clone, Copy)]
        pub struct PtMagEntry {
            pub phys: u64,
            pub virt: usize,
            pub node: u8,
        }

        impl PtMagEntry {
            pub const fn empty() -> Self {
                Self { phys: 0, virt: 0, node: 0 }
            }
            pub const fn is_valid(&self) -> bool {
                self.phys != 0
            }
        }

        pub struct PtMagazine {
            entries: [PtMagEntry; PT_MAG_CAPACITY],
            len: usize,
            preferred_node: u8,
        }

        impl PtMagazine {
            pub fn new() -> Self {
                Self {
                    entries: [PtMagEntry::empty(); PT_MAG_CAPACITY],
                    len: 0,
                    preferred_node: 0,
                }
            }

            pub fn pop(&mut self) -> Option<PtMagEntry> {
                if self.len == 0 { None } else {
                    self.len -= 1;
                    let entry = self.entries[self.len];
                    self.entries[self.len] = PtMagEntry::empty();
                    Some(entry)
                }
            }

            pub fn push(&mut self, entry: PtMagEntry) -> bool {
                if self.len >= PT_MAG_CAPACITY { false } else {
                    self.entries[self.len] = entry;
                    self.len += 1;
                    true
                }
            }

            pub fn available(&self) -> usize {
                PT_MAG_CAPACITY - self.len
            }

            pub fn len(&self) -> usize {
                self.len
            }

            pub fn preferred_node(&self) -> u8 {
                self.preferred_node
            }
        }

        /// Per-CPU data (test shim)
        pub struct PerCpuData {
            pub iommu_domain_cache: PerCpuDomainCache,
            pub iova_magazines: [IovaMagazine; MAX_IOMMU_CONTROLLERS],
            pub pt_magazine: PtMagazine,
        }

        impl PerCpuData {
            pub fn new() -> Self {
                Self {
                    iommu_domain_cache: PerCpuDomainCache::new(),
                    iova_magazines: array::from_fn(|_| IovaMagazine::new()),
                    pt_magazine: PtMagazine::new(),
                }
            }
        }

        /// Try to get the current CPU id (test shim: single CPU 0)
        pub fn try_current_cpu_id() -> Option<usize> {
            Some(0)
        }

        /// Whether current execution is in interrupt context (test shim: false)
        pub fn in_interrupt_context() -> bool {
            false
        }

        /// Maximum CPUs for the test/bench shim
        pub const MAX_CPUS: usize = 8;

        use alloc::boxed::Box;
        use core::sync::atomic::{AtomicBool, Ordering};

        // Lazily-initialized static per-cpu data for unit tests
        static PER_CPU_INIT: AtomicBool = AtomicBool::new(false);
        static mut PER_CPU_PTR: *mut PerCpuData = core::ptr::null_mut();

        /// Get a mutable reference to per-CPU data (test shim)
        pub unsafe fn current_per_cpu_mut() -> Option<&'static mut PerCpuData> { unsafe {
            if !PER_CPU_INIT.load(Ordering::SeqCst) {
                let boxed = Box::new(PerCpuData::new());
                let ptr = Box::into_raw(boxed);
                PER_CPU_PTR = ptr;
                PER_CPU_INIT.store(true, Ordering::SeqCst);
            }
            (PER_CPU_PTR as *mut PerCpuData).as_mut()
        }}

        /// Get an immutable reference to per-CPU data (test shim)
        pub unsafe fn current_per_cpu() -> Option<&'static PerCpuData> { unsafe {
            if !PER_CPU_INIT.load(Ordering::SeqCst) {
                let boxed = Box::new(PerCpuData::new());
                let ptr = Box::into_raw(boxed);
                PER_CPU_PTR = ptr;
                PER_CPU_INIT.store(true, Ordering::SeqCst);
            }
            (PER_CPU_PTR as *mut PerCpuData).as_ref()
        }}
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

        pub struct FastBitmapAllocator {
            base: u64,
            size: u64,
            next: AtomicU64,
        }

        impl FastBitmapAllocator {
            pub fn new(base: u64, size: u64) -> Self {
                Self { base, size, next: AtomicU64::new(0) }
            }

            pub fn allocate_4k(&self) -> Option<u64> { self.allocate_with_size(PAGE_SIZE_4K) }
            pub fn allocate_2m(&self) -> Option<u64> { self.allocate_with_size(PAGE_SIZE_2M) }
            pub fn allocate_1g(&self) -> Option<u64> { self.allocate_with_size(PAGE_SIZE_1G) }

            fn allocate_with_size(&self, sz: u64) -> Option<u64> {
                // Simple atomic bump allocator
                loop {
                    let cur = self.next.load(Ordering::Relaxed);
                    if cur + sz > self.size {
                        return None;
                    }
                    if self.next.compare_exchange(cur, cur + sz, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                        return Some(self.base + cur);
                    }
                }
            }

            pub fn allocate_4k_below(&self, limit: u64) -> Option<u64> { self.allocate_below(PAGE_SIZE_4K, limit) }
            pub fn allocate_2m_below(&self, limit: u64) -> Option<u64> { self.allocate_below(PAGE_SIZE_2M, limit) }
            pub fn allocate_1g_below(&self, limit: u64) -> Option<u64> { self.allocate_below(PAGE_SIZE_1G, limit) }

            fn allocate_below(&self, sz: u64, limit: u64) -> Option<u64> {
                loop {
                    let cur = self.next.load(Ordering::Relaxed);
                    if cur + sz > self.size || self.base + cur + sz > limit {
                        return None;
                    }
                    if self.next.compare_exchange(cur, cur + sz, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                        return Some(self.base + cur);
                    }
                }
            }

            pub fn allocate_contiguous(&self, _size: u64, _align: u64) -> Option<u64> {
                // Align up current pointer and allocate
                loop {
                    let cur = self.next.load(Ordering::Relaxed);
                    let aligned = ((cur + (_align - 1)) / _align) * _align;
                    if aligned + _size > self.size {
                        return None;
                    }
                    if self.next.compare_exchange(cur, aligned + _size, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                        return Some(self.base + aligned);
                    }
                }
            }

            pub fn free_immediate(&self, _addr: u64, _gran: PageGranularity) -> Result<(), ()> { Ok(()) }

            pub fn reserve(&self, _start: u64, _size: u64) -> Result<(), ()> { Ok(()) }

            pub fn reconfigure_for_cpu_ids(&mut self, _cpu_ids: &[usize]) {}

            pub fn enable_single_writer_arenas(&self) {}

            pub fn drain_remote_frees(&self) {}
            pub fn base(&self) -> u64 { self.base }
            pub fn size(&self) -> u64 { self.size }
        }
    }

    // Minimal remote-free / quarantine shim used by IOVA allocator
    pub mod remote_free {
        use alloc::collections::VecDeque;

        #[derive(Clone, Copy, Default)]
        pub struct QuarantineEntry {
            pub addr: u64,
            pub epoch: u32,
            pub size_class: u8,
        }

        pub struct QuarantineRing<const CAP: usize> {
            buf: VecDeque<QuarantineEntry>,
        }

        impl<const CAP: usize> QuarantineRing<CAP> {
            pub fn new() -> Self { Self { buf: VecDeque::new() } }

            pub fn push(&mut self, addr: u64, size_class: u8, epoch: u32) -> bool {
                if self.buf.len() >= CAP { false } else {
                    self.buf.push_back(QuarantineEntry { addr, epoch, size_class });
                    true
                }
            }

            pub fn drain_older_than(&mut self, completed_epoch: u32, limit: usize, out: &mut [QuarantineEntry]) -> usize {
                let mut count = 0usize;
                while count < limit {
                    if let Some(front) = self.buf.front() {
                        if front.epoch <= completed_epoch {
                            let e = self.buf.pop_front().unwrap();
                            out[count] = e;
                            count += 1;
                        } else { break; }
                    } else { break; }
                }
                count
            }

            pub fn drain_all(&mut self, out: &mut [QuarantineEntry]) -> usize {
                let mut count = 0usize;
                while count < out.len() {
                    if let Some(e) = self.buf.pop_front() { out[count] = e; count += 1; } else { break; }
                }
                count
            }
        }
    }

    pub mod types {
        #[derive(Clone, Copy)]
        pub struct NumaNodeId(pub u8);
        impl NumaNodeId {
            pub fn new(n: u8) -> Self { Self(n) }
            pub fn as_usize(&self) -> usize { self.0 as usize }
        }
    }

    pub mod frame_allocator {
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        use x86_64::PhysAddr;

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
        pub fn memory_pressure_level() -> u8 { 0 }
    }

    // Re-export frame allocator helpers at `crate::mm::dealloc_frame` etc.
    pub use frame_allocator::dealloc_frame;
    pub use frame_allocator::memory_pressure_level;

    // Minimal `higher_half` shim (for tests): small wrappers around u64 addresses
    pub mod higher_half {
        #[derive(Clone, Copy, Debug)]
        pub struct VirtAddr(u64);
        impl VirtAddr {
            pub const fn new(addr: u64) -> Self { Self(addr) }
            pub const fn as_u64(&self) -> u64 { self.0 }
        }

        #[derive(Clone, Copy, Debug)]
        pub struct PhysAddr(u64);
        impl PhysAddr {
            pub const fn new(addr: u64) -> Self { Self(addr) }
            pub const fn as_u64(&self) -> u64 { self.0 }
        }
    }

    // Global translate helper for tests (use kernel `higher_half` types)
    pub fn global_translate(virt: crate::mm::higher_half::VirtAddr) -> Option<crate::mm::higher_half::PhysAddr> {
        let v = x86_64::VirtAddr::new(virt.as_u64());
        let p = mapping::virt_to_phys(v);
        Some(crate::mm::higher_half::PhysAddr::new(p.as_u64()))
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
}
