#![no_std]
#![allow(clippy::cargo_common_metadata)]

pub const TRAMPOLINE_SIZE: usize = 4096;
pub const MAILBOX_OFFSET: usize = 0x200;
pub const LAYOUT_VERSION: u32 = 1;

pub struct ApBootFlags;

impl ApBootFlags {
    pub const TRAMPOLINE_READY: u32 = 1 << 0;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApTrampolineMailbox {
    pub ap_slot: u32,
    pub cpu_id: u32,
    pub page_table: u64,
    pub stack_ptr: u64,
    pub entry_point: u64,
    pub probe_addr: u64,
}

pub static TRAMPOLINE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ap_trampoline.bin"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trampoline_fits_reserved_page() {
        assert!(TRAMPOLINE_BYTES.len() <= TRAMPOLINE_SIZE);
    }

    #[test]
    fn mailbox_fits_reserved_page() {
        assert!(MAILBOX_OFFSET + core::mem::size_of::<ApTrampolineMailbox>() <= TRAMPOLINE_SIZE);
    }

    #[test]
    fn layout_version_is_nonzero() {
        assert!(LAYOUT_VERSION > 0);
    }

    #[test]
    fn mailbox_offsets_match_asm_contract() {
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, ap_slot), 0);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, cpu_id), 4);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, page_table), 8);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, stack_ptr), 16);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, entry_point), 24);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, probe_addr), 32);
    }
}
