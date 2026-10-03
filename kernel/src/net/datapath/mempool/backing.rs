//! Packet RAM and headers have separate lifetimes. Mapping caches retain RAM
//! after a dynamic header returns; fixed-pool headers retain it for recycling.

use crate::mm::phys::frame_allocator::{PhysicalAllocation, alloc_contiguous_frames};
use crate::mm::types::PAGE_SIZE_4K;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use kernel_api::dma::DmaByteCount;
use kernel_api::resource::memory::PhysicalAddress;
use kernel_api::resource::net::{PacketBufferMemory, PacketRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketAllocationError {
    InvalidSize,
    PhysicalMemory,
    Metadata,
    DirectMap,
    Acquisition,
}

pub(super) struct PacketStorage {
    allocation: Option<PhysicalAllocation>,
}
impl PacketStorage {
    pub(super) fn allocate(size: usize) -> Result<Arc<Self>, PacketAllocationError> {
        if size == 0 || size > isize::MAX as usize {
            return Err(PacketAllocationError::InvalidSize);
        }
        let pages = size
            .checked_add(PAGE_SIZE_4K - 1)
            .ok_or(PacketAllocationError::InvalidSize)?
            / PAGE_SIZE_4K;
        let allocation =
            alloc_contiguous_frames(pages).map_err(|_| PacketAllocationError::PhysicalMemory)?;
        let storage = Self {
            allocation: Some(allocation),
        };
        let pointer = storage.pointer()?;
        // SAFETY: this fresh contiguous allocation is exclusively owned here.
        // Its permanent RAM direct map is initialized before any header, CPU
        // window, or device mapping can observe it.
        unsafe { pointer.as_ptr().write_bytes(0, size) };
        Arc::try_new(storage).map_err(|_| PacketAllocationError::Metadata)
    }
    pub(super) fn physical(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.allocation.as_ref().expect("retained RAM").as_u64())
    }
    pub(super) fn pointer(&self) -> Result<NonNull<u8>, PacketAllocationError> {
        let allocation = self.allocation.as_ref().expect("retained RAM");
        let base = allocation
            .as_u64()
            .checked_add(crate::mm::virt::mapping::physical_memory_offset())
            .ok_or(PacketAllocationError::DirectMap)?;
        let last = base
            .checked_add(allocation.size_bytes() - 1)
            .ok_or(PacketAllocationError::DirectMap)?;
        x86_64::VirtAddr::try_new(base).map_err(|_| PacketAllocationError::DirectMap)?;
        x86_64::VirtAddr::try_new(last).map_err(|_| PacketAllocationError::DirectMap)?;
        let base = usize::try_from(base).map_err(|_| PacketAllocationError::DirectMap)?;
        NonNull::new(core::ptr::with_exposed_provenance_mut(base))
            .ok_or(PacketAllocationError::DirectMap)
    }
}
impl Drop for PacketStorage {
    fn drop(&mut self) {
        // Every device translation retains an Arc to this storage until its
        // IOTLB retirement completes. CPU windows retain it through their header.
        self.allocation.take().expect("retained RAM").release();
    }
}

struct DynamicPacket {
    memory: MaybeUninit<PacketBufferMemory>,
}
unsafe fn retire_dynamic(owner: NonNull<()>) {
    // SAFETY: acquisition transferred one Box to this exactly-once last-region
    // callback. Hardware translation owners independently retain backing RAM.
    let mut header = unsafe { Box::from_raw(owner.cast::<DynamicPacket>().as_ptr()) };
    // SAFETY: construction initialized this header before publishing any lease;
    // the last counted lease has now ended all header users.
    unsafe { header.memory.assume_init_drop() };
}

pub(crate) fn allocate_packet(
    capacity: usize,
    headroom: usize,
) -> Result<PacketRef, PacketAllocationError> {
    let capacity = DmaByteCount::new(capacity).ok_or(PacketAllocationError::InvalidSize)?;
    if headroom > capacity.get() {
        return Err(PacketAllocationError::InvalidSize);
    }
    let storage = PacketStorage::allocate(capacity.get())?;
    let data = storage.pointer()?;
    let physical = storage.physical();
    let mut header = Box::try_new(DynamicPacket {
        memory: MaybeUninit::uninit(),
    })
    .map_err(|_| PacketAllocationError::Metadata)?;
    let owner = NonNull::from(header.as_mut()).cast();
    // SAFETY: freshly initialized RAM and the stable Box have no independent
    // access. The header retains storage until all windows/descriptor visits
    // return; mapping owners can extend RAM lifetime beyond header retirement.
    header.memory.write(unsafe {
        PacketBufferMemory::new(data, capacity, physical, storage, owner, retire_dynamic)
    });
    let memory = NonNull::new(header.memory.as_mut_ptr()).expect("stable Box header");
    // SAFETY: this is the sole initial acquisition of an unpublished live header.
    let packet = match unsafe { PacketRef::acquire(memory, headroom) } {
        Ok(packet) => packet,
        Err(_) => {
            // SAFETY: no lease was published and the initialized header is ours.
            unsafe { header.memory.assume_init_drop() };
            return Err(PacketAllocationError::Acquisition);
        }
    };
    let _retirement_owner = Box::into_raw(header);
    Ok(packet)
}
