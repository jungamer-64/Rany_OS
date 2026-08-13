//! Shared real-mode AP trampoline installation.

use ap_trampoline::{TrampolinePageMut, TrampolinePhysAddr};
use boot_proto::ApTrampolineDescriptor;
use log::info;
use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;

const PREFERRED_PHYSICAL_ADDRESS: u64 = 0x8000;

/// Allocates and installs the one AP trampoline page handed to the kernel.
pub fn install() -> ApTrampolineDescriptor {
    let allocation = boot::allocate_pages(
        AllocateType::Address(PREFERRED_PHYSICAL_ADDRESS),
        MemoryType::LOADER_DATA,
        1,
    )
    .or_else(|_| {
        boot::allocate_pages(
            AllocateType::MaxAddress(0x000f_ffff),
            MemoryType::LOADER_DATA,
            1,
        )
    });

    let Ok(allocation) = allocation else {
        info!("AP trampoline allocation unavailable");
        return ApTrampolineDescriptor::default();
    };
    let address = allocation.as_ptr() as u64;
    let Ok(physical) = TrampolinePhysAddr::new(address) else {
        info!("AP trampoline allocation is outside the startup address space");
        return ApTrampolineDescriptor::default();
    };
    let installed = unsafe { TrampolinePageMut::from_raw_ptr(address as *mut u8) }
        .and_then(|mut page| page.install(physical));
    if let Err(error) = installed {
        info!("AP trampoline installation failed: {}", error);
        return ApTrampolineDescriptor::default();
    }

    match ApTrampolineDescriptor::new(address) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            info!("AP trampoline descriptor rejected: {}", error);
            ApTrampolineDescriptor::default()
        }
    }
}
