// When not running tests or benches, compile as `no_std`. For benches we
// enable the standard library so benchmark harnesses (Criterion) and
// alloc-dependent graphics helpers can build and run under the host test
// runner.
#![cfg_attr(not(any(test, feature = "std")), no_std)]

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
#[cfg(any(test, feature = "bench"))]
pub mod mm {
    use alloc::alloc::{Layout, alloc_zeroed, dealloc};
    use core::ptr::NonNull;
    use x86_64::PhysAddr;
    use x86_64::VirtAddr;
    use x86_64::structures::paging::{PhysFrame, Size4KiB};

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
            let l = ALayout::from_size_align(layout.size(), layout.align()).ok()?;
            let ptr = unsafe { alloc_zeroed(l) };
            NonNull::new(ptr)
        }

        /// Deallocate memory previously allocated by `allocate_zeroed_on_node`
        pub unsafe fn deallocate_on_node(ptr: NonNull<u8>, layout: Layout, _node: Option<usize>) {
            let l = ALayout::from_size_align(layout.size(), layout.align()).unwrap();
            unsafe {
                dealloc(ptr.as_ptr(), l);
            }
        }
    }

    // Minimal per-CPU stubs used by IOMMU unit tests. These avoid pulling the
    // full per-CPU subsystem into the test build while providing the API
    // expected by `iommu.rs`.
    pub mod per_cpu {
        use alloc::vec::Vec;

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

        /// Small per-CPU IOVA magazine (test shim)
        pub struct IovaMagazine {
            cache: Vec<u64>,
            capacity: usize,
        }

        impl IovaMagazine {
            pub fn new(capacity: usize) -> Self {
                Self {
                    cache: Vec::new(),
                    capacity,
                }
            }

            pub fn push(&mut self, iova: u64) -> bool {
                if self.cache.len() < self.capacity {
                    self.cache.push(iova);
                    true
                } else {
                    false
                }
            }

            pub fn pop(&mut self) -> Option<u64> {
                self.cache.pop()
            }
        }

        /// Per-CPU data (test shim)
        pub struct PerCpuData {
            pub iommu_domain_cache: PerCpuDomainCache,
            pub iova_magazine: IovaMagazine,
        }

        impl PerCpuData {
            pub fn new() -> Self {
                Self {
                    iommu_domain_cache: PerCpuDomainCache::new(),
                    iova_magazine: IovaMagazine::new(256),
                }
            }
        }

        /// Try to get the current CPU id (test shim: not initialized)
        pub fn try_current_cpu_id() -> Option<usize> {
            None
        }

        /// Maximum CPUs for the test/bench shim
        pub const MAX_CPUS: usize = 8;

        /// Get a mutable reference to per-CPU data (test shim: not available)
        /// Returning `None` is acceptable for unit tests and forces global
        /// allocator fallback paths to be exercised.
        pub unsafe fn current_per_cpu_mut() -> Option<&'static mut PerCpuData> {
            None
        }

        /// Get an immutable reference to per-CPU data (test shim: not available)
        pub unsafe fn current_per_cpu() -> Option<&'static PerCpuData> {
            None
        }
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
        use core::any::TypeId;
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
            #[cfg(debug_assertions)]
            size: usize,
            #[cfg(debug_assertions)]
            type_id: TypeId,
            drop_fn: unsafe fn(NonNull<u8>, DomainId),
        }

        unsafe impl Send for RRefRawParts {}
        unsafe impl Sync for RRefRawParts {}

        impl RRefRawParts {
            pub fn from_rref<T: 'static>(rref: RRef<T>) -> Self {
                let (ptr, owner) = rref.into_raw();

                unsafe fn drop_impl<T: 'static>(ptr: NonNull<u8>, owner: DomainId) {
                    let rref: RRef<T> = unsafe { RRef::from_raw(ptr.cast(), owner) };
                    drop(rref);
                }

                Self {
                    ptr: ptr.cast(),
                    owner,
                    #[cfg(debug_assertions)]
                    size: core::mem::size_of::<T>(),
                    #[cfg(debug_assertions)]
                    type_id: TypeId::of::<T>(),
                    drop_fn: drop_impl::<T>,
                }
            }

            pub unsafe fn into_rref<T: 'static>(self) -> Result<RRef<T>, RawPartsError> {
                #[cfg(debug_assertions)]
                {
                    if self.type_id != TypeId::of::<T>() {
                        return Err(RawPartsError::TypeMismatch);
                    }
                    if self.size != core::mem::size_of::<T>() {
                        return Err(RawPartsError::SizeMismatch);
                    }
                }

                Ok(unsafe { RRef::from_raw(self.ptr.cast(), self.owner) })
            }

            pub unsafe fn drop_erased(self) {
                unsafe { (self.drop_fn)(self.ptr, self.owner) };
            }

            pub fn owner(&self) -> DomainId {
                self.owner
            }
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
        use core::pin::Pin;
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

    /// PIT delay stub used by audio controller code in tests/benches
    pub struct Pit;
    impl Pit {
        pub fn delay_us(&self, _us: u64) {}
    }
    pub fn pit() -> Pit {
        Pit
    }
}

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

        /// Initialize the logger. Returns Ok(()) for the test shim.
        pub fn init() -> Result<(), ()> {
            Ok(())
        }

        /// Notify the logging subsystem that the heap is now available.
        pub fn notify_heap_available() {}
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
