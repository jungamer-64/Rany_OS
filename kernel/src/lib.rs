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

// Minimal test-only `mm::numa` shim to satisfy IOMMU tests without
// pulling in the full memory subsystem and its heavy dependencies.
#[cfg(test)]
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
}



#[cfg(test)]
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
}

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
