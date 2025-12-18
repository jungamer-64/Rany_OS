// When not running tests or benches, compile as `no_std`. For benches we
// enable the standard library so benchmark harnesses (Criterion) and
// alloc-dependent graphics helpers can build and run under the host test
// runner.
#![cfg_attr(not(any(test, feature = "std")), no_std)]

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

// Minimal test/bench `mm::numa` shim to satisfy IOMMU tests and benchmark builds
// without pulling in the full memory subsystem and its heavy dependencies.
#[cfg(any(test, feature = "bench"))]
pub mod mm {
    pub mod numa {
        use alloc::alloc::{alloc_zeroed, dealloc, Layout as ALayout};
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
        pub fn allocate_zeroed_on_node(layout: Layout, _node: Option<usize>) -> Option<NonNull<u8>> {
            let l = ALayout::from_size_align(layout.size(), layout.align()).ok()?;
            let ptr = unsafe { alloc_zeroed(l) };
            NonNull::new(ptr)
        }

        /// Deallocate memory previously allocated by `allocate_zeroed_on_node`
        pub unsafe fn deallocate_on_node(ptr: NonNull<u8>, layout: Layout, _node: Option<usize>) {
            let l = ALayout::from_size_align(layout.size(), layout.align()).unwrap();
            unsafe { dealloc(ptr.as_ptr(), l); }
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
                Self { entries: [DomainCacheEntry { device_id: 0, domain_id: 0, controller_idx: 0, valid: false }; Self::CACHE_SIZE] }
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
                self.entries[idx] = DomainCacheEntry { device_id, domain_id, controller_idx, valid: true };
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
                Self { cache: Vec::new(), capacity }
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
                Self { iommu_domain_cache: PerCpuDomainCache::new(), iova_magazine: IovaMagazine::new(256) }
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
}

// Minimal task/time shims for tests and benches
#[cfg(any(test, feature = "bench"))]
pub mod task {
    pub mod timer {
        /// Return current tick in milliseconds (test stub)
        pub fn current_tick() -> u64 { 0 }
    }

    /// Convenience: expose `current_tick` at `crate::task::current_tick()` for
    /// code that expects that symbol (legacy usage in some modules).
    #[deprecated(note = "Test shim `crate::task::current_tick()` is deprecated; call `crate::task::timer::current_tick()` directly.")]
    pub fn current_tick() -> u64 { timer::current_tick() }

    pub mod scheduler {
        /// Yield the current task (test stub - no-op)
        pub fn yield_current(_cpu_id: usize) {}
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
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
    }

    /// Minimal SystemClock stub used by benches/tests
    pub struct SystemClock;
    impl SystemClock {
        /// Return TSC frequency in Hz if known. Test/bench stub returns None.
        pub fn tsc_frequency(&self) -> Option<u64> { None }
    }

    pub fn system_clock() -> SystemClock { SystemClock }

    /// Return uptime in milliseconds (test stub)
    pub fn get_uptime_ms() -> u64 { 0 }

    /// PIT delay stub used by audio controller code in tests/benches
    pub struct Pit;
    impl Pit {
        pub fn delay_us(&self, _us: u64) {}
    }
    pub fn pit() -> Pit { Pit }
}


#[cfg(all(test, not(feature = "bench")))]
pub mod io {
    // Include only the IOMMU implementation for test builds to avoid
    // pulling in the whole I/O subsystem and its wide dependency graph.
    #[path = "iommu.rs"]
    pub mod iommu;

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
        pub fn mmio_read_u8(_addr: usize) -> u8 { 0 }
        pub fn mmio_read_u16(_addr: usize) -> u16 { 0 }
        pub fn mmio_read_u32(_addr: usize) -> u32 { 0 }
        pub fn mmio_read_u64(_addr: usize) -> u64 { 0 }
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
