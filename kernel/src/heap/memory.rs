//! Exclusive heap RAM admission. Loader RAM has no PMM return authority; a
//! retained PMM loan may be returned only after every heap block is retired.
//! Geometry remains observation and cannot manufacture either ownership.
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
    physical: Option<crate::mm::phys::frame_allocator::PhysicalAllocation>,
}

#[expect(
    unsafe_code,
    reason = "bootstrap RAM ownership is CPU-independent; allocator mutation is locked"
)]
// SAFETY: this unique owner has no public dereference or reclamation API. Its
// globally mapped RAM is retained for the kernel lifetime. Moving it transfers
// exclusive allocation authority; receiving allocators serialize metadata access.
unsafe impl Send for HeapMemory {}

impl HeapMemory {
    // Only allocator boundaries inside this ownership namespace can project
    // provenance. Numeric observations elsewhere do not grant a RAM view.
    pub(super) fn base(&self) -> NonNull<u8> {
        self.base
    }

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
            physical: None,
        }
    }

    /// # Safety
    /// The exclusive RAM allocation has a retained writable HHDM mapping and
    /// no device or translation owner can access it. Transfer occurs once.
    #[expect(
        unsafe_code,
        reason = "HHDM RAM admission transfers physical ownership into the heap"
    )]
    pub(super) unsafe fn from_physical(
        backing: crate::mm::phys::frame_allocator::PhysicalAllocation,
    ) -> Self {
        let virtual_base =
            crate::mm::virt::mapping::phys_to_virt(backing.start_address()).as_u64() as usize;
        let layout = Layout::from_size_align(backing.size_bytes() as usize, 4096)
            .expect("PMM supplies a valid page extent");
        let base = NonNull::new(core::ptr::with_exposed_provenance_mut(virtual_base))
            .expect("admitted HHDM RAM is nonzero");
        Self {
            base,
            layout,
            physical: Some(backing),
        }
    }

    /// Consumes a PMM loan after all heap blocks have been returned. Loader RAM
    /// retains its external ownership contract and cannot be returned to PMM.
    pub(super) fn into_physical(
        mut self,
    ) -> Result<crate::mm::phys::frame_allocator::PhysicalAllocation, Self> {
        match self.physical.take() {
            Some(backing) => Ok(backing),
            None => Err(self),
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
