//! Once-only admission of loader-owned RAM. Geometry is copyable observation;
//! HeapMemory is not. No Drop/release path can return it to another allocator.
#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use boot_proto::{BootstrapHeapGeometry, BootstrapMemoryError, MappedHeapRange};
use core::alloc::Layout;
use core::ptr::NonNull;

#[derive(Debug)]
pub(crate) struct HeapMemory {
    base: NonNull<u8>,
    layout: Layout,
}

// SAFETY: this unique owner has no dereference or reclamation API. Its globally
// mapped RAM is retained for the kernel lifetime. Moving it transfers exclusive
// allocation authority; the receiving allocator serializes metadata access.
#[expect(
    unsafe_code,
    reason = "bootstrap RAM ownership is CPU-independent; allocator mutation is locked"
)]
unsafe impl Send for HeapMemory {}

impl HeapMemory {
    /// # Safety
    /// The range is exclusively owned, writable, stable RAM for the kernel
    /// lifetime; no other allocator/device may access it. The mapping is retained
    /// and the caller transfers ownership only once. Geometry alone is not proof.
    #[expect(
        unsafe_code,
        reason = "boot ABI admission establishes RAM ownership, not just numeric validity"
    )]
    unsafe fn admit(range: MappedHeapRange) -> Self {
        // Exposed provenance comes from the firmware/hardware boot boundary;
        // range construction checked nonzero address, alignment, and extent.
        let base = NonNull::new(core::ptr::with_exposed_provenance_mut(range.start()))
            .expect("checked bootstrap range cannot start at zero");
        Self {
            base,
            layout: range.layout(),
        }
    }

    pub(crate) fn start(&self) -> usize {
        self.base.as_ptr().addr()
    }
    pub(crate) fn size(&self) -> usize {
        self.layout.size()
    }
    pub(crate) fn end(&self) -> usize {
        self.start() + self.size()
    }
}

#[derive(Debug)]
pub(crate) struct BootstrapHeaps {
    kernel: HeapMemory,
    exchange: HeapMemory,
    geometry: BootstrapHeapGeometry,
}

impl BootstrapHeaps {
    /// # Safety
    /// Called once at the loader-to-kernel ownership boundary. The loader owns
    /// exactly the described slab, retains its HHDM mapping, and relinquishes all
    /// RAM access/release rights. It is disjoint from firmware, kernel, boot
    /// data, page tables and every other live allocation. No device owns it.
    /// # Errors
    /// Invalid ABI geometry grants no access or allocator initialization rights.
    #[expect(
        unsafe_code,
        reason = "unique boot handoff consumes external firmware allocation authority"
    )]
    pub(crate) unsafe fn from_handoff(
        descriptor: boot_proto::BootstrapHeapDescriptor,
        hhdm_start: u64,
        mapped_physical_limit: u64,
    ) -> Result<Self, BootstrapMemoryError> {
        let geometry = descriptor.geometry(hhdm_start, mapped_physical_limit)?;
        let [kernel, exchange] = geometry.ranges();
        // SAFETY: caller transfers one exclusive slab; the validated split is
        // nonoverlapping and page-exact, and neither owner can be cloned/freed.
        let kernel = unsafe { HeapMemory::admit(kernel) };
        // SAFETY: same slab transfer, disjoint from the kernel range above.
        let exchange = unsafe { HeapMemory::admit(exchange) };
        Ok(Self {
            kernel,
            exchange,
            geometry,
        })
    }

    pub(super) fn into_parts(self) -> (HeapMemory, HeapMemory, BootstrapHeapGeometry) {
        (self.kernel, self.exchange, self.geometry)
    }
}
