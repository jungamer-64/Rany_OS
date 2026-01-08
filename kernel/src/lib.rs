// When not running tests or benches, compile as `no_std`. For benches we
// enable the standard library so benchmark harnesses (Criterion) and
// alloc-dependent graphics helpers can build and run under the host test
// runner.
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(feature = "full_mm_tests", allow(unsafe_op_in_unsafe_fn))]
#![cfg_attr(feature = "full_mm_tests", feature(abi_x86_interrupt))]

// Interrupt helper macro moved to a shared module so it's visible in both the
// library and binary crate (define_interrupt! is used by modules included by
// `main.rs`). See `interrupt_macros.rs` for the implementation.
#[macro_use]
mod interrupt_macros;

// For unit testing we expose a small set of modules via the library entry
// point. This keeps most of the kernel as a binary-only crate while still
// allowing targeted library-style tests (e.g. security/capability) to run
// under `cargo test --lib` without pulling the entire binary test harness.
#[cfg(test)]
pub mod security;

// Expose additional modules when building tests so unit tests inside those
// modules can be executed via `cargo test --lib`.
// Also expose the `graphics` module when compiling benches via the
// `bench` feature so Criterion benches can access framebuffer types and
// helpers. This keeps the default binary layout unchanged while allowing
// convenient benching during development.
#[cfg(any(test, feature = "bench"))]
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
#[cfg(feature = "full_mm_tests")]
pub mod fs;



#[cfg(feature = "full_mm_tests")]
pub mod mm;

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
            dealloc(ptr.as_ptr(), layout);
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
            super::buddy_alloc_frame_on_node(node.as_usize())
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

    pub fn buddy_alloc_frame_on_node(_node: usize) -> Option<PhysFrame<Size4KiB>> {
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

// Minimal IPC/RRef shims for tests (avoid pulling full IPC/SAS stack).
#[cfg(test)]
pub mod ipc {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DomainId(u64);

    impl DomainId {
        pub const fn new(id: u64) -> Self {
            Self(id)
        }

        pub const fn as_u64(self) -> u64 {
            self.0
        }
    }

    pub mod rref {
        use alloc::boxed::Box;
        use core::ops::{Deref, DerefMut};
        use core::ptr::NonNull;

        use super::DomainId;

        #[derive(Debug)]
        pub struct RRef<T: ?Sized> {
            ptr: NonNull<T>,
            owner: DomainId,
        }

        impl<T> RRef<T> {
            pub fn new(owner: DomainId, val: T) -> Self {
                let boxed = Box::new(val);
                let ptr = NonNull::new(Box::into_raw(boxed)).expect("RRef Box pointer is null");
                Self { ptr, owner }
            }
        }

        impl<T: ?Sized> RRef<T> {
            pub unsafe fn from_raw(ptr: NonNull<T>, owner: DomainId) -> Self {
                Self { ptr, owner }
            }

            pub fn into_raw(self) -> (NonNull<T>, DomainId) {
                let ptr = self.ptr;
                let owner = self.owner;
                core::mem::forget(self);
                (ptr, owner)
            }
        }

        impl<T: ?Sized> Deref for RRef<T> {
            type Target = T;

            fn deref(&self) -> &Self::Target {
                unsafe { self.ptr.as_ref() }
            }
        }

        impl<T: ?Sized> DerefMut for RRef<T> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                unsafe { self.ptr.as_mut() }
            }
        }

        impl<T: ?Sized> Drop for RRef<T> {
            fn drop(&mut self) {
                unsafe {
                    drop(Box::from_raw(self.ptr.as_ptr()));
                }
            }
        }

        unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
        unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RawPartsError {
            TypeMismatch,
            SizeMismatch,
        }

        pub struct RRefRawParts {
            ptr: NonNull<u8>,
            owner: DomainId,
            meta: usize,
            #[cfg(debug_assertions)]
            size: usize,
            #[cfg(debug_assertions)]
            type_hash: u64,
            drop_fn: unsafe fn(NonNull<u8>, DomainId, usize),
        }

        unsafe impl Send for RRefRawParts {}
        unsafe impl Sync for RRefRawParts {}

        impl RRefRawParts {
            pub fn from_rref<T: Sized>(rref: RRef<T>) -> Self {
                #[cfg(debug_assertions)]
                let size = core::mem::size_of_val(&*rref);
                #[cfg(debug_assertions)]
                let type_hash = debug_type_hash(&*rref);
                let (ptr, owner) = rref.into_raw();
                // Simplified: avoid unstable ptr::metadata / ptr::from_raw_parts usage by
                // only supporting sized `RRef<T>` in the test shim. Store meta as zero.
                let meta = 0usize;

                // Embed type-specific drop function (Sized-only for test shim)
                unsafe fn drop_impl<T: Sized>(ptr: NonNull<u8>, owner: DomainId, _meta: usize) {
                    // For sized types we can reconstruct the typed pointer directly.
                    let data_ptr = ptr.as_ptr() as *mut T;
                    let rref: RRef<T> = unsafe { RRef::from_raw(NonNull::new_unchecked(data_ptr), owner) };
                    drop(rref);
                }

                Self {
                    ptr: ptr.cast(),
                    owner,
                    meta,
                    #[cfg(debug_assertions)]
                    size,
                    #[cfg(debug_assertions)]
                    type_hash,
                    drop_fn: drop_impl::<T>,
                }
            }

            pub unsafe fn into_rref<T: Sized>(self) -> Result<RRef<T>, RawPartsError> {
                // Reconstruct typed pointer - test shim assumes sized T.
                let typed_ptr = self.ptr.as_ptr() as *mut T;

                #[cfg(debug_assertions)]
                {
                    let typed_ref: &T = unsafe { &*typed_ptr };
                    let actual_size = core::mem::size_of_val(typed_ref);
                    let actual_hash = debug_type_hash(typed_ref);
                    if self.type_hash != actual_hash {
                        return Err(RawPartsError::TypeMismatch);
                    }
                    if self.size != actual_size {
                        return Err(RawPartsError::SizeMismatch);
                    }
                }

                Ok(unsafe { RRef::from_raw(NonNull::new_unchecked(typed_ptr), self.owner) })
            }

            pub unsafe fn drop_erased(self) {
                unsafe { (self.drop_fn)(self.ptr, self.owner, self.meta) };
            }

            pub(crate) fn into_components(
                self,
            ) -> (NonNull<u8>, DomainId, usize, unsafe fn(NonNull<u8>, DomainId, usize)) {
                (self.ptr, self.owner, self.meta, self.drop_fn)
            }

            pub fn owner(&self) -> DomainId {
                self.owner
            }
        }

        #[cfg(debug_assertions)]
        fn debug_type_hash<T: ?Sized>(val: &T) -> u64 {
            const FNV_OFFSET: u64 = 0xcbf29ce484222325;
            const FNV_PRIME: u64 = 0x100000001b3;
            let mut hash = FNV_OFFSET;
            for byte in core::any::type_name::<T>().as_bytes() {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(FNV_PRIME);
            }
            hash ^= (core::mem::size_of_val(val) as u64) << 32;
            hash ^= (core::mem::align_of_val(val) as u64) << 48;
            hash
        }
    }

    pub use rref::RRef;
}

// Minimal task/time shims for tests and benches
#[cfg(any(test, feature = "bench"))]
pub mod task {
    pub mod timer {
        /// Return current tick in milliseconds (test stub)
        pub fn current_tick() -> u64 {
            0
        }
    }

    /// Convenience: expose `current_tick` at `crate::task::current_tick()` for
    /// code that expects that symbol (legacy usage in some modules).
    #[deprecated(
        note = "Test shim `crate::task::current_tick()` is deprecated; call `crate::task::timer::current_tick()` directly."
    )]
    pub fn current_tick() -> u64 {
        timer::current_tick()
    }

    pub mod scheduler {
        /// Yield the current task (test stub - no-op)
        pub fn yield_current(_cpu_id: usize) {}
    }

    pub mod per_core_executor {
        pub fn spawn<F>(_future: F)
        where
            F: core::future::Future<Output = ()> + 'static,
        {
        }
    }

    pub async fn sleep_ms(_ms: u64) {}

    /// Synchronous helper to drive a Future to completion in tests
    pub fn block_on<F: core::future::Future>(future: F) -> F::Output {
        use alloc::sync::Arc;
        
        use core::sync::atomic::{AtomicBool, Ordering};
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        let flag = Arc::new(AtomicBool::new(false));

        unsafe fn clone_data(data: *const ()) -> RawWaker {
            let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
            let cloned = arc.clone();
            let _ = Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
        }

        unsafe fn wake_data(data: *const ()) {
            let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        unsafe fn wake_by_ref_data(data: *const ()) {
            let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
            let _ = Arc::into_raw(arc);
        }

        unsafe fn drop_data(data: *const ()) {
            let _arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
        }

        const VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone_data, wake_data, wake_by_ref_data, drop_data);

        let raw = RawWaker::new(Arc::into_raw(flag.clone()) as *const (), &VTABLE);
        let waker = unsafe { Waker::from_raw(raw) };
        let mut cx = Context::from_waker(&waker);

        // Pin the future on the heap and poll a Pin<&mut F>
        let mut boxed = Box::pin(future);

        loop {
            match core::pin::Pin::new(&mut boxed).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => {
                    while !flag.load(Ordering::SeqCst) {
                        core::hint::spin_loop();
                    }
                    flag.store(false, Ordering::SeqCst);
                }
            }
        }
    }

    pub mod fuel {
        use core::cell::Cell;

        thread_local! {
            static CURRENT_FUEL: Cell<u64> = Cell::new(0);
            static FUEL_ACTIVE: Cell<bool> = Cell::new(false);
        }

        pub struct Fuel;

        impl Fuel {
            pub fn refill(amount: u64) {
                FUEL_ACTIVE.with(|a| a.set(amount > 0));
                CURRENT_FUEL.with(|c| c.set(amount));
            }

            pub fn consume(amount: u64) -> bool {
                // If fuel is not active (amount==0 at refill), treat as unlimited and always allow
                let active = FUEL_ACTIVE.with(|a| a.get());
                if !active {
                    return true;
                }
                CURRENT_FUEL.with(|c| {
                    let current = c.get();
                    if let Some(remaining) = current.checked_sub(amount) {
                        c.set(remaining);
                        true
                    } else {
                        c.set(0);
                        false
                    }
                })
            }

            pub fn remaining() -> u64 {
                CURRENT_FUEL.with(|c| c.get())
            }

            pub fn is_active() -> bool {
                FUEL_ACTIVE.with(|a| a.get())
            }

            pub fn exhaust() {
                FUEL_ACTIVE.with(|a| a.set(false));
                CURRENT_FUEL.with(|c| c.set(0))
            }
        }

        pub struct FuelConfig {
            pub default_fuel: u64,
        }

        impl FuelConfig {
            pub const DEFAULT: Self = Self {
                default_fuel: 10_000,
            };
        }
    }

    // Minimal preemption shim used by unit tests to avoid pulling the full
    // preemption implementation into every test build while keeping the API
    // expected by I/O modules and interrupts.
    pub mod preemption {
        /// Lightweight stats struct mirroring the real implementation used by monitors.
        #[derive(Debug, Clone)]
        pub struct PreemptionStats {
            pub forced_preemptions: u64,
            pub voluntary_yields: u64,
            pub current_time_slice: u64,
            pub enabled: bool,
        }

        /// Minimal controller stub that exposes only `stats()` for tests.
        pub struct PreemptionController;

        impl PreemptionController {
            pub fn stats(&self) -> PreemptionStats {
                PreemptionStats {
                    forced_preemptions: 0,
                    voluntary_yields: 0,
                    current_time_slice: 0,
                    enabled: false,
                }
            }
        }

        /// Return a static reference to the stub controller.
        pub fn preemption_controller() -> &'static PreemptionController {
            static CTRL: PreemptionController = PreemptionController;
            &CTRL
        }

        /// No-op stubs used by code paths that call into preemption during tests.
        pub fn voluntary_yield() {}
        pub fn yield_point() {}
        pub fn is_preemption_pending() -> bool {
            false
        }
        pub fn clear_preemption_pending() {}
        pub fn check_and_clear_yield_request() -> bool {
            false
        }
        pub fn handle_timer_tick(_tick: u64) {}
        pub fn set_preemption_pending() {}
        pub fn request_yield() {}
        pub fn decrement_time_slice() {}
        pub fn notify_task_started(_tick: u64) {}
    }

    // Basic smp shim for test builds
    pub mod smp {
        pub fn current_cpu() -> u32 { 0 }
        pub fn cpu_count() -> usize { 1 }
        pub fn try_current_cpu_id() -> Option<u32> { Some(0) }
    }

    // Minimal work_stealing_advanced shim used by NUMA helpers in tests
    pub mod work_stealing_advanced {
        pub struct NumaTopology;
        impl NumaTopology {
            pub fn get() -> &'static Self {
                static T: NumaTopology = NumaTopology;
                &T
            }

            pub fn num_nodes(&self) -> usize { 1 }

            pub fn get_cores_in_node(&self, _node: usize) -> &'static [u32] {
                static CORES: [u32; 1] = [0];
                &CORES
            }

            pub fn get_numa_node(&self, _cpu: u32) -> usize { 0 }
        }
    }

    // Minimal memory helpers for tests
    pub mod memory {
        pub fn physical_memory_offset() -> u64 { 0 }
        pub fn total_memory_kb() -> u64 { 1024 * 1024 }
        pub fn free_memory_kb() -> u64 { 512 * 1024 }
    }

    // Minimal interrupts shim
    pub mod interrupts {
        pub fn get_timer_ticks() -> u64 { 0 }
    }

    // Minimal domain system stub
    pub mod domain_system {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct DomainId(pub u64);

        impl DomainId {
            pub const fn new(v: u64) -> Self {
                DomainId(v)
            }

            pub fn as_u64(&self) -> u64 {
                self.0
            }
        }

        impl core::fmt::Display for DomainId {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "DomainId({})", self.0)
            }
        }
    }

    // Task context counters used by procfs tests
    pub mod context {
        use core::sync::atomic::AtomicU64;
        pub static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
    }

    // Minimal IO shims for tests
    pub mod io {
        pub mod log {
            pub fn early_print_char(_c: u8) {}
        }

        pub mod interrupt_manager {
            pub fn send_ipi(_apic_id: u32, _vector: u8) {}
            pub fn broadcast_ipi(_vector: u8) {}
        }

        pub mod nvme {
            /// Minimal NVMe completion type for tests
            #[derive(Clone, Copy, Debug)]
            pub struct NvmeCompletion {
                pub cid: u16,
                pub status: u16,
            }

            impl NvmeCompletion {
                pub fn is_success(&self) -> bool { (self.status & 0x1) != 0 }
                pub fn command_id(&self) -> u16 { self.cid }
            }

            /// Minimal driver handle stub used in `with_driver` closures.
            #[derive(Debug)]
            pub struct NvmePollingDriver;

            impl NvmePollingDriver {
                pub fn new() -> Self { NvmePollingDriver }

                /// Submit a read command (test stub)
                pub unsafe fn submit_read(&self, _core_id: u32, _nsid: u32, _lba: u64, _blocks: u16, _prp1: u64, _prp2: u64) -> Result<u16, &'static str> {
                    Err("no-driver")
                }

                /// Submit a write command (test stub)
                pub unsafe fn submit_write(&self, _core_id: u32, _nsid: u32, _lba: u64, _blocks: u16, _prp1: u64, _prp2: u64) -> Result<u16, &'static str> {
                    Err("no-driver")
                }

                pub fn check_completion(&self, _core_id: u32, _cid: u16) -> Option<NvmeCompletion> { None }
                pub fn register_waker(&self, _core_id: u32, _cid: u16, _waker: core::task::Waker) {}
            }

            pub mod global {
                use crate::task::io::nvme::NvmePollingDriver;

                pub fn with_driver<F, R>(_f: F) -> Option<R>
                where
                    F: FnOnce(&NvmePollingDriver) -> R,
                {
                    None
                }

                pub fn with_driver_mut<F, R>(_f: F) -> Option<R>
                where
                    F: FnOnce(&mut NvmePollingDriver) -> R,
                {
                    None
                }
            }
        }
    }
    // Minimal process manager stub for tests (provides `process_manager()` and types used by `procfs` tests)
    pub mod process {
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use alloc::string::String;
        use core::sync::atomic::{AtomicU64, Ordering};
        use spin::RwLock;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct ProcessId(u64);
        impl ProcessId {
            pub const KERNEL: Self = Self(0);
            pub const INIT: Self = Self(1);
            pub const fn new(id: u64) -> Self { Self(id) }
            pub fn as_u64(&self) -> u64 { self.0 }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ProcessState { Running, Blocked, Ready, Stopped, Zombie, Dead, Creating }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct UserId(u32);
        impl UserId { pub fn as_u32(&self) -> u32 { self.0 } }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct GroupId(u32);
        impl GroupId { pub fn as_u32(&self) -> u32 { self.0 } }

        #[derive(Clone, Debug)]
        pub struct Credentials { pub uid: UserId, pub gid: GroupId }

        #[derive(Clone, Debug)]
        pub struct ProcessInner {
            pub name: String,
            pub state: ProcessState,
            pub ppid: ProcessId,
            pub credentials: Credentials,
            pub threads: Vec<u64>,
            pub priority: Priority,
            pub cmdline: Vec<String>,
            pub memcg_id: crate::mm::memcg::MemcgId,
            pub exit_code: Option<u64>,
        }

        impl ProcessInner {
            pub fn threads(&self) -> &Vec<u64> { &self.threads }
        }

        #[derive(Clone, Copy, Debug)]
        pub struct Priority(i8);
        impl Priority { pub fn as_i8(&self) -> i8 { self.0 } }

        pub type Process = Arc<RwLock<ProcessInner>>;

        pub struct ProcessManager;
        impl ProcessManager {
            pub fn count(&self) -> usize { 0 }
            pub fn get(&self, _pid: ProcessId) -> Option<Process> { None }
            pub fn create(&self, _ppid: ProcessId, _name: &str) -> Result<ProcessId, ()> { Err(()) }
        }

        static PROCESS_MANAGER: ProcessManager = ProcessManager;
        pub fn process_manager() -> &'static ProcessManager { &PROCESS_MANAGER }

        /// Minimal process info type used by some subsystems
        #[derive(Debug)]
        pub struct ProcessInfo {
            pub pid: ProcessId,
            pub numa_scan_addr: core::sync::atomic::AtomicU64,
        }

        pub fn get_current_process() -> ProcessId { ProcessId::new(1) }

        // Helper to return current process memcg id (used by some tests)
        pub fn get_current_process_memcg_id() -> crate::mm::memcg::MemcgId { crate::mm::memcg::MemcgId::ROOT }

        // Re-export the minimal io::nvme driver for compatibility with code that
        // expects `crate::io::nvme` in test builds. This points at `crate::task::io::nvme`.
        pub mod nvme {
            pub use crate::task::io::nvme::*;
        }
    }

    // Test shim removed: tests and benches should use the canonical
    // `crate::task::TaskId` directly. If you see failures related to TaskId
    // field access, please update tests to use `as_u64()` accessor.

    /// Minimal interrupt_waker shim used by some I/O drivers in tests and benches.
    pub mod interrupt_waker {
        #[derive(Clone, Copy)]
        pub enum InterruptSource {
            VirtioBlk(u8),
            VirtioNet(u8),
            Other(u8),
        }

        pub fn wake_from_interrupt(_src: InterruptSource) {
            // No-op in tests/bench harness
        }
    }
}

#[cfg(any(test, feature = "bench"))]
pub mod time {
    /// High-resolution time in nanoseconds (test stub using system clock)
    pub fn precise_time_nanos() -> u64 {
        // Use std for test builds to provide a monotonic-like value
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    /// Minimal SystemClock stub used by benches/tests
    pub struct SystemClock;
    impl SystemClock {
        /// Return TSC frequency in Hz if known. Test/bench stub returns None.
        pub fn tsc_frequency(&self) -> Option<u64> {
            None
        }
    }

    pub fn system_clock() -> SystemClock {
        SystemClock
    }

    /// Return uptime in milliseconds (test stub)
    pub fn get_uptime_ms() -> u64 {
        0
    }

    /// Current tick in milliseconds (legacy alias)
    pub fn current_tick() -> u64 {
        get_uptime_ms()
    }

    /// Return current Unix time in seconds (test stub)
    pub fn now() -> u64 {
        precise_time_nanos() / 1_000_000_000
    }

    /// High-precision current time in nanoseconds
    pub fn current_time_ns() -> u64 {
        precise_time_nanos()
    }

    /// PIT delay stub used by audio controller code in tests/benches
    pub struct Pit;
    impl Pit {
        pub fn delay_us(&self, _us: u64) {}
    }
    pub fn pit() -> Pit {
        Pit
    }
}

pub mod pcid_support;

#[cfg(all(test, not(feature = "bench")))]
pub mod io {
    // Include only the IOMMU implementation for test builds to avoid
    // pulling in the whole I/O subsystem and its wide dependency graph.
    #[path = "iommu/mod.rs"]
    pub mod iommu;

    /// Minimal logger shim for test builds. Kernel code calls `io::log::early_print`,
    /// `io::log::init()` and `io::log::notify_heap_available()` during early boot. We
    /// provide lightweight no-op implementations here so unit tests can run without
    /// pulling the full I/O logging subsystem into the test build.
    pub mod log {
        /// Early boot serial-like print used before the full logger is initialized.
        pub fn early_print(_s: &str) {}

        /// Early boot single-character print used by low-level routines.
        pub fn early_print_char(_c: u8) {}

        /// Initialize the logger. Returns Ok(()) for the test shim.
        pub fn init() -> Result<(), ()> {
            Ok(())
        }

        /// Notify the logging subsystem that the heap is now available.
        pub fn notify_heap_available() {}
    }

    pub mod interrupt_manager {
        pub fn send_ipi(_apic_id: u32, _vector: u8) {}
        pub fn broadcast_ipi(_vector: u8) {}
    }

    // Minimal PCI stub for test builds so IOMMU functions that reference
    // `crate::io::pci::PciDeviceInfo` compile.
    pub mod pci {
        #[derive(Debug, Clone, Copy)]
        pub struct Bus(pub u8);
        #[derive(Debug, Clone, Copy)]
        pub struct Device(pub u8);
        #[derive(Debug, Clone, Copy)]
        pub struct Function(pub u8);

        #[derive(Debug, Clone, Copy)]
        pub struct Bdf {
            pub bus: Bus,
            pub device: Device,
            pub function: Function,
        }

        #[derive(Debug)]
        pub struct PciDeviceInfo {
            pub bdf: Bdf,
            pub iommu_domain_id: Option<u16>,
        }

        impl PciDeviceInfo {
            pub fn is_pci_bridge(&self) -> bool {
                false
            }
        }
    }

    pub mod nvme {
        // Re-export the task-scoped NVMe driver for compatibility in test builds.
        // Tests expect `crate::io::nvme::NvmePollingDriver` and driver-global helpers.
        pub use crate::task::io::nvme::NvmePollingDriver;

        pub mod global {
            use crate::task::io::nvme::NvmePollingDriver;

            pub fn with_driver<F, R>(_f: F) -> Option<R>
            where
                F: FnOnce(&NvmePollingDriver) -> R,
            {
                None
            }

            pub fn with_driver_mut<F, R>(_f: F) -> Option<R>
            where
                F: FnOnce(&mut NvmePollingDriver) -> R,
            {
                None
            }
        }
    }

    // Minimal MMIO stubs used by the IOMMU unit tests. These provide
    // deterministic behavior suitable for unit testing.
    pub mod mmio {
        pub fn mmio_read_u8(_addr: usize) -> u8 {
            0
        }
        pub fn mmio_read_u16(_addr: usize) -> u16 {
            0
        }
        pub fn mmio_read_u32(_addr: usize) -> u32 {
            0
        }
        pub fn mmio_read_u64(_addr: usize) -> u64 {
            0
        }
        pub fn mmio_write_u8(_addr: usize, _v: u8) {}
        pub fn mmio_write_u16(_addr: usize, _v: u16) {}
        pub fn mmio_write_u32(_addr: usize, _v: u32) {}
        pub fn mmio_write_u64(_addr: usize, _v: u64) {}
    }

    // Expose a minimal ACPI module in tests so IOMMU init can call into
    // `crate::io::acpi::dmar::parse_dmar` without pulling the full ACPI
    // runtime dependencies into every unit test. This delegates only the
    // DMAR parsing API to the acpi driver crate.
    pub mod acpi {
        pub mod dmar {
            pub use acpi_driver::dmar::*;
        }
        pub mod ivrs {
            pub use acpi_driver::ivrs::*;
        }
    }
}

// When building benches enable a *minimal* I/O module that only includes
// `crate::io::log` so benchmark harnesses can access logging helpers while
// avoiding the heavy dependencies of the full I/O subsystem.
#[cfg(feature = "bench")]
#[path = "io/bench_mod.rs"]
pub mod io;

#[cfg(any(test, feature = "bench"))]
pub use hal;

// Some graphics modules depend on the `alloc` crate and other internal
// modules (e.g. unwind). When compiling benches we need to make these
// available so the bench harness can build the same code paths we
// exercise at runtime.
#[cfg(any(test, feature = "bench"))]
extern crate alloc;

#[cfg(test)]
pub mod unwind;

#[cfg(any(test, feature = "bench"))]
pub mod driver_registry;
#[cfg(any(test, feature = "bench"))]
pub mod loader;
#[cfg(any(test, feature = "bench"))]
pub mod sync;

#[cfg(any(test, feature = "bench"))]
pub mod sas;

#[cfg(any(test, feature = "bench"))]
pub mod util;

#[cfg(any(test, feature = "bench"))]
pub mod nvme {
    pub use crate::io::nvme::*;
}

// Re-export task-scoped shims at crate root so modules that reference
// `crate::memory`, `crate::smp`, `crate::interrupts`, and
// `crate::domain_system` compile in test builds without changes.
#[cfg(any(test, feature = "bench"))]
pub use crate::task::memory as memory;
#[cfg(any(test, feature = "bench"))]
pub use crate::task::smp as smp;
#[cfg(any(test, feature = "bench"))]
pub use crate::task::interrupts as interrupts;
#[cfg(any(test, feature = "bench"))]
pub use crate::task::domain_system as domain_system;

#[cfg(test)]
mod async_swapout_sim_lib {
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::sync::{Arc, Condvar, Mutex};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SwapKind {
        File,
        Anon,
    }

    #[derive(Clone, Copy, Debug)]
    struct SwapEntry {
        frame: usize,
        kind: SwapKind,
    }

    #[test]
    fn async_swapout_sim_short_baseline() {
        // Simulation parameters (short baseline run)
        // Allow overriding via environment variables for quick parameter sweeps
        let channel_size: usize = std::env::var("ASYNC_SWAPOUT_CHANNEL_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(512);
        let batch_size: usize = std::env::var("ASYNC_SWAPOUT_BATCH_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(16);
        let reserved_file_slots: usize = std::env::var("ASYNC_SWAPOUT_RESERVED_FILE_SLOTS").ok().and_then(|v| v.parse().ok()).unwrap_or(channel_size / 8);
        let token_bucket_capacity: usize = std::env::var("ASYNC_SWAPOUT_TOKEN_CAPACITY").ok().and_then(|v| v.parse().ok()).unwrap_or(channel_size / 4);
        let token_refill_per_batch: usize = std::env::var("ASYNC_SWAPOUT_TOKEN_REFILL").ok().and_then(|v| v.parse().ok()).unwrap_or(batch_size / 2);

        let threads: usize = std::env::var("ASYNC_SWAPOUT_THREADS").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
        let iters: usize = std::env::var("ASYNC_SWAPOUT_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(400); // each thread iterations
        // Optional processing delay (ms) to simulate slower I/O via env var
        let proc_delay_ms: u64 = std::env::var("ASYNC_SWAPOUT_PROCESSING_DELAY_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);

        // Shared state
        let queue = Arc::new((Mutex::new(VecDeque::<SwapEntry>::new()), Condvar::new()));
        let pending = Arc::new(Mutex::new(HashSet::<usize>::new()));
        let file_queue_count = Arc::new(AtomicUsize::new(0));
        let queue_len_max = Arc::new(AtomicUsize::new(0));
        let tokens = Arc::new(AtomicUsize::new(token_bucket_capacity));

        let enqueue_success = Arc::new(AtomicUsize::new(0));
        let enqueue_failures = Arc::new(AtomicUsize::new(0));
        let processed = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Worker thread
        {
            let queue = queue.clone();
            let pending = pending.clone();
            let file_queue_count = file_queue_count.clone();
            let queue_len_max = queue_len_max.clone();
            let tokens = tokens.clone();
            let processed = processed.clone();
            let shutdown = shutdown.clone();

            thread::spawn(move || {
                loop {
                    // Wait for work or shutdown
                    let mut batch = Vec::new();
                    {
                        let (lock, cvar) = &*queue;
                        let mut q = lock.lock().unwrap();
                        while q.is_empty() && !shutdown.load(Ordering::Acquire) {
                            q = cvar.wait(q).unwrap();
                        }

                        if q.is_empty() && shutdown.load(Ordering::Acquire) {
                            break;
                        }

                        for _ in 0..batch_size {
                            if let Some(e) = q.pop_front() {
                                batch.push(e);
                            } else {
                                break;
                            }
                        }

                        // update observed queue length
                        let cur = q.len();
                        loop {
                            let old = queue_len_max.load(Ordering::Acquire);
                            if cur <= old || queue_len_max.compare_exchange(old, cur, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                                break;
                            }
                        }
                    }

                    if batch.is_empty() {
                        continue;
                    }

                    // process batch (simulate I/O)
                    for entry in batch.iter() {
                        match entry.kind {
                            SwapKind::File => {
                                // simulate page writeback latency
                                thread::sleep(Duration::from_millis(proc_delay_ms));
                                file_queue_count.fetch_sub(1, Ordering::AcqRel);
                            }
                            SwapKind::Anon => {
                                // simulate zswap store latency (faster)
                                thread::sleep(Duration::from_millis(proc_delay_ms));
                            }
                        }

                        // mark processed and clear pending
                        processed.fetch_add(1, Ordering::AcqRel);
                        pending.lock().unwrap().remove(&entry.frame);
                    }

                    // refill tokens after processing batch
                    loop {
                        let cur = tokens.load(Ordering::Acquire);
                        if cur >= token_bucket_capacity { break; }
                        let new = (cur + token_refill_per_batch).min(token_bucket_capacity);
                        if tokens.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire).is_ok() { break; }
                    }
                }
            });
        }

        // Enqueuer threads
        let mut joiners = Vec::new();
        let start = Instant::now();
        for t in 0..threads {
            let queue = queue.clone();
            let pending = pending.clone();
            let file_queue_count = file_queue_count.clone();
            let tokens = tokens.clone();
            let enqueue_success = enqueue_success.clone();
            let enqueue_failures = enqueue_failures.clone();

            let j = thread::spawn(move || {
                for i in 0..iters {
                    let is_file = ((i + t) % 2) == 0;
                    let frame = (t * iters) + i; // unique frame id per attempt

                    // try pending check
                    {
                        let mut p = pending.lock().unwrap();
                        if p.contains(&frame) {
                            enqueue_failures.fetch_add(1, Ordering::AcqRel);
                            continue;
                        }

                        // capacity check
                        let (lock, cvar) = &*queue;
                        let mut q = lock.lock().unwrap();
                        if q.len() >= channel_size {
                            enqueue_failures.fetch_add(1, Ordering::AcqRel);
                            continue;
                        }

                        // reservation for file writes
                        if !is_file {
                            let total = q.len();
                            let file_q = file_queue_count.load(Ordering::Acquire);
                            let free_slots = channel_size.saturating_sub(total);
                            if free_slots <= reserved_file_slots && file_q >= reserved_file_slots {
                                enqueue_failures.fetch_add(1, Ordering::AcqRel);
                                continue;
                            }
                        }

                        // token consumption for anon
                        if !is_file {
                            let ok = loop {
                                let cur = tokens.load(Ordering::Acquire);
                                if cur == 0 {
                                    enqueue_failures.fetch_add(1, Ordering::AcqRel);
                                    break false;
                                }
                                if tokens.compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                                    break true;
                                }
                            };
                            if !ok { continue; }
                        }

                        // all checks passed: insert
                        p.insert(frame);
                        if is_file {
                            file_queue_count.fetch_add(1, Ordering::AcqRel);
                        }
                        q.push_back(SwapEntry { frame, kind: if is_file { SwapKind::File } else { SwapKind::Anon } });
                        cvar.notify_one();
                        enqueue_success.fetch_add(1, Ordering::AcqRel);
                    }
                }
            });
            joiners.push(j);
        }

        for j in joiners { j.join().unwrap(); }

        // Give worker time to finish processing
        loop {
            let (lock, _) = &*queue;
            let q = lock.lock().unwrap();
            if q.is_empty() { break; }
            drop(q);
            thread::sleep(Duration::from_millis(10));
        }

        // shutdown and wait a moment
        shutdown.store(true, Ordering::Release);
        {
            let (lock, cvar) = &*queue;
            drop(lock.lock().unwrap());
            cvar.notify_all();
        }
        // Wait for workers to finish processing enqueued items (respect proc_delay_ms)
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while processed.load(Ordering::Acquire) < enqueue_success.load(Ordering::Acquire) && Instant::now() < wait_deadline {
            thread::sleep(Duration::from_millis(10));
        }

        let elapsed = start.elapsed();
        let success = enqueue_success.load(Ordering::Acquire);
        let failures = enqueue_failures.load(Ordering::Acquire);
        let processed = processed.load(Ordering::Acquire);
        let tokens_left = tokens.load(Ordering::Acquire);
        let max_q = queue_len_max.load(Ordering::Acquire);

        println!("async_swapout_sim_short_baseline: threads={} iters={} time={:?}", threads, iters, elapsed);
        println!("enq_success={}, enq_failures={}, processed={}, tokens_left={}, max_queue_len={}", success, failures, processed, tokens_left, max_q);

        // Basic sanity checks
        assert_eq!(processed, success);
        assert!(success > 0);
    }
}
