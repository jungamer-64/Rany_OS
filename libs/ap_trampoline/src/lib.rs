#![no_std]
#![allow(clippy::cargo_common_metadata)]

mod trampoline_asm;

use core::ptr::addr_of;
use core::slice;

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

struct TrampolineLayout {
    len: usize,
    long_mode_far_ptr: usize,
    gdt_descriptor_base: usize,
    gdt_code_base: usize,
    gdt_data_base: usize,
}

unsafe extern "C" {
    static __ap_trampoline_start: u8;
    static __ap_trampoline_end: u8;
    static __ap_patch_long_mode_far_ptr: u8;
    static __ap_patch_gdt_descriptor_base: u8;
    static __ap_patch_gdt_code_base: u8;
    static __ap_patch_gdt_data_base: u8;
}

pub fn trampoline_bytes() -> &'static [u8] {
    let start = trampoline_start();
    let layout = trampoline_layout();
    unsafe { slice::from_raw_parts(start as *const u8, layout.len) }
}

pub fn patch_trampoline(image: &mut [u8], trampoline_addr: u64) -> Result<(), &'static str> {
    let layout = trampoline_layout();
    let trampoline_base =
        u32::try_from(trampoline_addr).map_err(|_| "AP trampoline must reside below 4 GiB")?;
    let long_mode_entry_offset = layout
        .long_mode_far_ptr
        .checked_add(6)
        .ok_or("AP trampoline long mode entry offset overflowed")?;
    let long_mode_entry = trampoline_base
        .checked_add(
            u32::try_from(long_mode_entry_offset)
                .map_err(|_| "AP trampoline long mode entry offset exceeds u32")?,
        )
        .ok_or("AP trampoline long mode entry overflowed")?;
    let gdt_base = trampoline_base
        .checked_add(
            u32::try_from(layout.gdt_descriptor_base + 6)
                .map_err(|_| "AP trampoline GDT base offset exceeds u32")?,
        )
        .ok_or("AP trampoline GDT base overflowed")?;

    patch_u32(image, layout.long_mode_far_ptr, long_mode_entry)?;
    patch_u32(image, layout.gdt_descriptor_base, gdt_base)?;
    patch_segment_base(image, layout.gdt_code_base, trampoline_base)?;
    patch_segment_base(image, layout.gdt_data_base, trampoline_base)?;

    Ok(())
}

fn trampoline_layout() -> TrampolineLayout {
    let start = trampoline_start();
    let end = symbol_addr(addr_of!(__ap_trampoline_end));

    TrampolineLayout {
        len: end
            .checked_sub(start)
            .expect("AP trampoline end precedes start"),
        long_mode_far_ptr: symbol_offset(start, addr_of!(__ap_patch_long_mode_far_ptr)),
        gdt_descriptor_base: symbol_offset(start, addr_of!(__ap_patch_gdt_descriptor_base)),
        gdt_code_base: symbol_offset(start, addr_of!(__ap_patch_gdt_code_base)),
        gdt_data_base: symbol_offset(start, addr_of!(__ap_patch_gdt_data_base)),
    }
}

fn trampoline_start() -> usize {
    symbol_addr(addr_of!(__ap_trampoline_start))
}

fn symbol_addr(symbol: *const u8) -> usize {
    symbol as usize
}

fn symbol_offset(start: usize, symbol: *const u8) -> usize {
    symbol_addr(symbol)
        .checked_sub(start)
        .expect("AP trampoline symbol precedes start")
}

fn patch_u32(image: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    ensure_patch_room(image, offset, 4)?;
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn patch_segment_base(image: &mut [u8], offset: usize, base: u32) -> Result<(), &'static str> {
    ensure_patch_room(image, offset, 6)?;
    image[offset..offset + 2].copy_from_slice(&(base as u16).to_le_bytes());
    image[offset + 2] = (base >> 16) as u8;
    image[offset + 5] = (base >> 24) as u8;
    Ok(())
}

fn ensure_patch_room(image: &[u8], offset: usize, len: usize) -> Result<(), &'static str> {
    let end = offset
        .checked_add(len)
        .ok_or("AP trampoline patch offset overflowed")?;
    if image.len() < end {
        return Err("AP trampoline image is smaller than expected");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trampoline_fits_reserved_page() {
        assert!(trampoline_bytes().len() <= TRAMPOLINE_SIZE);
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

    #[test]
    fn patch_slots_start_zeroed() {
        let bytes = trampoline_bytes();
        let layout = trampoline_layout();

        assert_eq!(read_u32(bytes, layout.long_mode_far_ptr), 0);
        assert_eq!(read_u32(bytes, layout.gdt_descriptor_base), 0);
        assert_eq!(read_segment_base(bytes, layout.gdt_code_base), 0);
        assert_eq!(read_segment_base(bytes, layout.gdt_data_base), 0);
    }

    #[test]
    fn patch_trampoline_populates_absolute_addresses() {
        let bytes = trampoline_bytes();
        let layout = trampoline_layout();
        let mut image = [0u8; TRAMPOLINE_SIZE];
        image[..bytes.len()].copy_from_slice(bytes);

        patch_trampoline(&mut image[..bytes.len()], 0x8000).unwrap();

        assert_eq!(
            read_u32(&image, layout.long_mode_far_ptr),
            0x8000 + (layout.long_mode_far_ptr as u32) + 6
        );
        assert_eq!(
            read_u32(&image, layout.gdt_descriptor_base),
            0x8000 + (layout.gdt_descriptor_base as u32) + 6
        );
        assert_eq!(read_segment_base(&image, layout.gdt_code_base), 0x8000);
        assert_eq!(read_segment_base(&image, layout.gdt_data_base), 0x8000);
    }

    #[test]
    fn patch_trampoline_rejects_short_image() {
        let mut image = [0u8; 8];
        assert_eq!(
            patch_trampoline(&mut image, 0x8000),
            Err("AP trampoline image is smaller than expected")
        );
    }

    fn read_u32(image: &[u8], offset: usize) -> u32 {
        let bytes: [u8; 4] = image[offset..offset + 4].try_into().unwrap();
        u32::from_le_bytes(bytes)
    }

    fn read_segment_base(image: &[u8], offset: usize) -> u32 {
        let low = u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap()) as u32;
        low | ((image[offset + 2] as u32) << 16) | ((image[offset + 5] as u32) << 24)
    }
}
