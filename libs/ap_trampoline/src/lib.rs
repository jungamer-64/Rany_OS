// ============================================================================
// libs/ap_trampoline/src/lib.rs
// ============================================================================
#![no_std]
#![allow(clippy::cargo_common_metadata)]

mod addr;
mod image;
mod mailbox;
mod trampoline_asm;

pub use addr::{PageTable32Addr, TrampolinePhysAddr, TrampolineVirtAddr};
pub use image::{TrampolinePageMut, trampoline_bytes, trampoline_bytes_checked};
pub use mailbox::{
    ApBootFlags, ApTrampolineLaunchInfo, TrampolineMailboxHandle, TrampolineMailboxReadHandle,
};

pub const TRAMPOLINE_SIZE: usize = 4096;
pub const MAILBOX_OFFSET: usize = 0xE0;
pub const LAYOUT_VERSION: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn mailbox_fits_reserved_page() {
        assert!(
            MAILBOX_OFFSET + size_of::<crate::mailbox::ApTrampolineMailbox>() <= TRAMPOLINE_SIZE
        );
    }

    #[test]
    fn layout_version_is_nonzero() {
        assert!(LAYOUT_VERSION > 0);
    }
}
