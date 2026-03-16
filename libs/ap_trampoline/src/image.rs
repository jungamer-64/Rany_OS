// ============================================================================
// libs/ap_trampoline/src/image.rs
// ============================================================================
use core::mem::size_of;
use core::ptr::NonNull;
use core::ptr::addr_of;
use core::slice;

use crate::MAILBOX_OFFSET;
use crate::TRAMPOLINE_SIZE;
use crate::addr::TrampolinePhysAddr;
use crate::mailbox::ApTrampolineMailbox;

const FAR_POINTER_SIZE: usize = 6;
const GDT_DESCRIPTOR_SIZE: usize = 6;
const GDT_ENTRY_COUNT: usize = 4;
pub(crate) const GDT_SIZE: usize = GDT_ENTRY_COUNT * size_of::<u64>();
const GDT_FLAT_LIMIT: u32 = 0x000F_FFFF;
pub(crate) const GDT32_CODE_SELECTOR: u16 = 0x08;
pub(crate) const GDT32_DATA_SELECTOR: u16 = 0x10;
const GDT64_CODE_SELECTOR: u16 = 0x18;
const GDT_ACCESS_CODE: u8 = 0x9A;
const GDT_ACCESS_DATA: u8 = 0x92;
const GDT_FLAGS_32: u8 = 0xC;
const GDT_FLAGS_64: u8 = 0xA;

pub struct TrampolinePageMut<'a> {
    page: &'a mut [u8; TRAMPOLINE_SIZE],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrampolineImage {
    start: usize,
    layout: TrampolineLayout,
}

impl<'a> TrampolinePageMut<'a> {
    pub fn try_from_slice(page: &'a mut [u8]) -> Result<Self, &'static str> {
        match page.len().cmp(&TRAMPOLINE_SIZE) {
            core::cmp::Ordering::Less => {
                return Err("AP trampoline page is smaller than expected");
            }
            core::cmp::Ordering::Greater => {
                return Err("AP trampoline page must be exactly one page");
            }
            core::cmp::Ordering::Equal => {}
        }

        // Safety: the length check above guarantees the conversion succeeds.
        let page: &mut [u8; TRAMPOLINE_SIZE] = page.try_into().unwrap();

        Ok(Self { page })
    }

    /// # Safety
    ///
    /// `ptr` must point to a valid writable trampoline page that remains live
    /// for at least the lifetime `'a` of the returned [`TrampolinePageMut`].
    /// The caller must also ensure no other references to that page exist for
    /// the duration of `'a`.
    pub unsafe fn from_raw_ptr(ptr: *mut u8) -> Result<TrampolinePageMut<'a>, &'static str> {
        let ptr = NonNull::new(ptr).ok_or("AP trampoline page pointer is null")?;
        if !(ptr.as_ptr() as usize).is_multiple_of(TRAMPOLINE_SIZE) {
            return Err("AP trampoline page pointer is misaligned");
        }
        let page = unsafe { &mut *ptr.cast::<[u8; TRAMPOLINE_SIZE]>().as_ptr() };
        Ok(TrampolinePageMut { page })
    }

    pub fn install(&mut self, trampoline_addr: TrampolinePhysAddr) -> Result<(), &'static str> {
        let image = resolve_trampoline_image()?;
        let layout = image.layout;
        let template = unsafe { trampoline_template(image) };
        let page = &mut self.page[..];

        page.fill(0);
        page[..template.len()].copy_from_slice(template);
        patch_trampoline_image(&mut page[..template.len()], trampoline_addr, layout)?;
        // Keep the mailbox scrub explicit so future template changes cannot
        // accidentally preserve stale launch data across installs.
        page[layout.mailbox..layout.mailbox + size_of::<ApTrampolineMailbox>()].fill(0);

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrampolineLayout {
    len: usize,
    long_mode_entry: usize,
    long_mode_far_ptr: usize,
    gdt_descriptor: usize,
    gdt: usize,
    mailbox: usize,
}

#[derive(Debug, Clone, Copy)]
struct LayoutRange {
    offset: usize,
    len: usize,
}

unsafe extern "C" {
    static __ap_trampoline_start: u8;
    static __ap_trampoline_end: u8;
    static __ap_long_mode_entry: u8;
    static __ap_patch_long_mode_far_ptr: u8;
    static __ap_patch_gdt_descriptor: u8;
    static __ap_patch_gdt: u8;
    static __ap_mailbox: u8;
}

pub fn trampoline_bytes() -> &'static [u8] {
    match trampoline_bytes_checked() {
        Ok(bytes) => bytes,
        Err(err) => panic!("{err}"),
    }
}

pub fn trampoline_bytes_checked() -> Result<&'static [u8], &'static str> {
    let image = resolve_trampoline_image()?;
    Ok(unsafe { trampoline_template(image) })
}

pub(crate) fn trampoline_mailbox_offset_checked() -> Result<usize, &'static str> {
    Ok(resolve_trampoline_layout()?.mailbox)
}

fn resolve_trampoline_image() -> Result<TrampolineImage, &'static str> {
    // Safety: the linker script and `trampoline_asm.rs` define these symbols as
    // a contiguous trampoline image for the lifetime of the kernel image.
    let symbols = unsafe { load_trampoline_symbols() };
    let layout = validate_trampoline_layout(TrampolineLayout {
        len: symbols
            .end
            .checked_sub(symbols.start)
            .ok_or("AP trampoline end precedes start")?,
        long_mode_entry: symbol_offset(symbols.start, symbols.long_mode_entry)?,
        long_mode_far_ptr: symbol_offset(symbols.start, symbols.long_mode_far_ptr)?,
        gdt_descriptor: symbol_offset(symbols.start, symbols.gdt_descriptor)?,
        gdt: symbol_offset(symbols.start, symbols.gdt)?,
        mailbox: symbol_offset(symbols.start, symbols.mailbox)?,
    })?;

    Ok(TrampolineImage {
        start: symbols.start,
        layout,
    })
}

fn resolve_trampoline_layout() -> Result<TrampolineLayout, &'static str> {
    Ok(resolve_trampoline_image()?.layout)
}

fn validate_trampoline_layout(layout: TrampolineLayout) -> Result<TrampolineLayout, &'static str> {
    if layout.len > TRAMPOLINE_SIZE {
        return Err("AP trampoline image exceeds reserved page");
    }
    if layout.mailbox != MAILBOX_OFFSET {
        return Err("AP trampoline mailbox offset mismatch");
    }
    if layout.long_mode_entry >= layout.len {
        return Err("AP trampoline long mode entry lies outside the image");
    }

    let mailbox_end = range_end(layout.mailbox, size_of::<ApTrampolineMailbox>())?;
    if mailbox_end != layout.len {
        return Err("AP trampoline mailbox must end at the image boundary");
    }

    let ranges = [
        LayoutRange {
            offset: layout.long_mode_far_ptr,
            len: FAR_POINTER_SIZE,
        },
        LayoutRange {
            offset: layout.gdt_descriptor,
            len: GDT_DESCRIPTOR_SIZE,
        },
        LayoutRange {
            offset: layout.gdt,
            len: GDT_SIZE,
        },
        LayoutRange {
            offset: layout.mailbox,
            len: size_of::<ApTrampolineMailbox>(),
        },
    ];

    for range in ranges {
        let end = range_end(range.offset, range.len)?;
        if end > layout.len {
            return Err("AP trampoline layout range exceeds the image boundary");
        }
        if range.len == 0 {
            return Err("AP trampoline layout range is empty");
        }
        if range_contains(range, layout.long_mode_entry)? {
            return Err("AP trampoline long mode entry overlaps a patch range");
        }
    }

    for (index, lhs) in ranges.iter().enumerate() {
        for rhs in &ranges[index + 1..] {
            if ranges_overlap(*lhs, *rhs)? {
                return Err("AP trampoline layout ranges overlap");
            }
        }
    }

    Ok(layout)
}

fn ranges_overlap(lhs: LayoutRange, rhs: LayoutRange) -> Result<bool, &'static str> {
    let lhs_end = range_end(lhs.offset, lhs.len)?;
    let rhs_end = range_end(rhs.offset, rhs.len)?;
    Ok(lhs.offset < rhs_end && rhs.offset < lhs_end)
}

fn range_contains(range: LayoutRange, offset: usize) -> Result<bool, &'static str> {
    let end = range_end(range.offset, range.len)?;
    Ok(range.offset <= offset && offset < end)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrampolineSymbols {
    start: usize,
    end: usize,
    long_mode_entry: usize,
    long_mode_far_ptr: usize,
    gdt_descriptor: usize,
    gdt: usize,
    mailbox: usize,
}

unsafe fn load_trampoline_symbols() -> TrampolineSymbols {
    TrampolineSymbols {
        start: addr_of!(__ap_trampoline_start) as usize,
        end: addr_of!(__ap_trampoline_end) as usize,
        long_mode_entry: addr_of!(__ap_long_mode_entry) as usize,
        long_mode_far_ptr: addr_of!(__ap_patch_long_mode_far_ptr) as usize,
        gdt_descriptor: addr_of!(__ap_patch_gdt_descriptor) as usize,
        gdt: addr_of!(__ap_patch_gdt) as usize,
        mailbox: addr_of!(__ap_mailbox) as usize,
    }
}

/// # Safety
///
/// `image.start..image.start + image.layout.len` must describe the immutable
/// linker-defined trampoline image for the lifetime of the program.
unsafe fn trampoline_template(image: TrampolineImage) -> &'static [u8] {
    unsafe { slice::from_raw_parts(image.start as *const u8, image.layout.len) }
}

fn symbol_offset(start: usize, symbol: usize) -> Result<usize, &'static str> {
    symbol
        .checked_sub(start)
        .ok_or("AP trampoline symbol precedes start")
}

fn patch_trampoline_image(
    image: &mut [u8],
    trampoline_addr: TrampolinePhysAddr,
    layout: TrampolineLayout,
) -> Result<(), &'static str> {
    let trampoline_base = trampoline_addr.as_u32();
    let long_mode_entry = trampoline_base
        .checked_add(
            u32::try_from(layout.long_mode_entry)
                .map_err(|_| "AP trampoline long mode entry offset exceeds u32")?,
        )
        .ok_or("AP trampoline long mode entry overflowed")?;
    let gdt_base = trampoline_base
        .checked_add(
            u32::try_from(layout.gdt).map_err(|_| "AP trampoline GDT base offset exceeds u32")?,
        )
        .ok_or("AP trampoline GDT base overflowed")?;
    let gdt = build_gdt(trampoline_base);

    patch_far_ptr(
        image,
        layout.long_mode_far_ptr,
        long_mode_entry,
        GDT64_CODE_SELECTOR,
    )?;
    patch_gdt_descriptor(
        image,
        layout.gdt_descriptor,
        gdt_base,
        (GDT_SIZE - 1) as u16,
    )?;
    patch_gdt(image, layout.gdt, &gdt)?;

    Ok(())
}

fn patch_far_ptr(
    image: &mut [u8],
    offset: usize,
    entry_offset: u32,
    selector: u16,
) -> Result<(), &'static str> {
    let mut far_ptr = [0u8; FAR_POINTER_SIZE];
    far_ptr[..4].copy_from_slice(&entry_offset.to_le_bytes());
    far_ptr[4..].copy_from_slice(&selector.to_le_bytes());
    patch_bytes(image, offset, &far_ptr)
}

fn patch_gdt_descriptor(
    image: &mut [u8],
    offset: usize,
    base: u32,
    limit: u16,
) -> Result<(), &'static str> {
    let mut descriptor = [0u8; GDT_DESCRIPTOR_SIZE];
    descriptor[..2].copy_from_slice(&limit.to_le_bytes());
    descriptor[2..].copy_from_slice(&base.to_le_bytes());
    patch_bytes(image, offset, &descriptor)
}

fn patch_gdt(
    image: &mut [u8],
    offset: usize,
    gdt: &[u64; GDT_ENTRY_COUNT],
) -> Result<(), &'static str> {
    let mut table = [0u8; GDT_SIZE];
    for (index, entry) in gdt.iter().enumerate() {
        let entry_offset = index * size_of::<u64>();
        table[entry_offset..entry_offset + size_of::<u64>()].copy_from_slice(&entry.to_le_bytes());
    }

    patch_bytes(image, offset, &table)
}

fn build_gdt(trampoline_base: u32) -> [u64; GDT_ENTRY_COUNT] {
    [
        0,
        encode_gdt_descriptor(
            trampoline_base,
            GDT_FLAT_LIMIT,
            GDT_ACCESS_CODE,
            GDT_FLAGS_32,
        ),
        encode_gdt_descriptor(
            trampoline_base,
            GDT_FLAT_LIMIT,
            GDT_ACCESS_DATA,
            GDT_FLAGS_32,
        ),
        encode_gdt_descriptor(0, GDT_FLAT_LIMIT, GDT_ACCESS_CODE, GDT_FLAGS_64),
    ]
}

fn encode_gdt_descriptor(base: u32, limit: u32, access: u8, flags: u8) -> u64 {
    u64::from(limit & 0xFFFF)
        | (u64::from(base & 0xFFFF) << 16)
        | (u64::from((base >> 16) & 0xFF) << 32)
        | (u64::from(access) << 40)
        | (u64::from(((limit >> 16) & 0x0F) | (u32::from(flags) << 4)) << 48)
        | (u64::from((base >> 24) & 0xFF) << 56)
}

fn patch_bytes(image: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), &'static str> {
    ensure_patch_room(image, offset, bytes.len())?;
    image[offset..offset + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

fn ensure_patch_room(image: &[u8], offset: usize, len: usize) -> Result<(), &'static str> {
    let end = range_end(offset, len)?;
    if image.len() < end {
        return Err("AP trampoline image is smaller than expected");
    }
    Ok(())
}

fn range_end(offset: usize, len: usize) -> Result<usize, &'static str> {
    offset
        .checked_add(len)
        .ok_or("AP trampoline layout offset overflowed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trampoline_fits_reserved_page() {
        assert!(trampoline_bytes_checked().unwrap().len() <= TRAMPOLINE_SIZE);
    }

    #[test]
    fn patch_slots_start_zeroed() {
        let bytes = trampoline_bytes_checked().unwrap();
        let layout = resolve_trampoline_layout().unwrap();

        assert!(
            bytes[layout.long_mode_far_ptr..layout.long_mode_far_ptr + FAR_POINTER_SIZE]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(
            bytes[layout.gdt_descriptor..layout.gdt_descriptor + GDT_DESCRIPTOR_SIZE]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(
            bytes[layout.gdt..layout.gdt + GDT_SIZE]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(
            bytes[layout.mailbox..layout.mailbox + size_of::<ApTrampolineMailbox>()]
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn trampoline_length_matches_mailbox_boundary() {
        let layout = resolve_trampoline_layout().unwrap();

        assert_eq!(layout.mailbox, MAILBOX_OFFSET);
        assert_eq!(
            layout.len,
            MAILBOX_OFFSET + size_of::<ApTrampolineMailbox>()
        );
    }

    #[test]
    fn trampoline_page_requires_exact_page_size() {
        let mut short = [0u8; TRAMPOLINE_SIZE - 1];
        assert!(matches!(
            TrampolinePageMut::try_from_slice(&mut short),
            Err("AP trampoline page is smaller than expected")
        ));

        let mut long = [0u8; TRAMPOLINE_SIZE + 1];
        assert!(matches!(
            TrampolinePageMut::try_from_slice(&mut long),
            Err("AP trampoline page must be exactly one page")
        ));

        let mut exact = [0u8; TRAMPOLINE_SIZE];
        assert!(TrampolinePageMut::try_from_slice(&mut exact).is_ok());
    }

    #[test]
    fn trampoline_page_from_raw_ptr_rejects_invalid_addresses() {
        assert!(matches!(
            unsafe { TrampolinePageMut::from_raw_ptr(core::ptr::null_mut()) },
            Err("AP trampoline page pointer is null")
        ));

        let mut page = [0u8; TRAMPOLINE_SIZE + 1];
        let misaligned = unsafe { page.as_mut_ptr().add(1) };
        assert!(matches!(
            unsafe { TrampolinePageMut::from_raw_ptr(misaligned) },
            Err("AP trampoline page pointer is misaligned")
        ));
    }

    #[test]
    fn trampoline_page_install_zeroes_mailbox_and_rest_of_page() {
        let layout = resolve_trampoline_layout().unwrap();
        let mut page = [0xAAu8; TRAMPOLINE_SIZE];
        let mut trampoline_page = TrampolinePageMut::try_from_slice(&mut page).unwrap();

        trampoline_page
            .install(TrampolinePhysAddr::new(0x8000).unwrap())
            .unwrap();

        assert!(
            page[layout.mailbox..layout.mailbox + size_of::<ApTrampolineMailbox>()]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(
            page[trampoline_bytes_checked().unwrap().len()..TRAMPOLINE_SIZE]
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn trampoline_page_install_patches_far_ptr_and_gdt() {
        let layout = resolve_trampoline_layout().unwrap();
        let trampoline_addr = TrampolinePhysAddr::new(0x8000).unwrap();
        let mut page = [0u8; TRAMPOLINE_SIZE];

        TrampolinePageMut::try_from_slice(&mut page)
            .unwrap()
            .install(trampoline_addr)
            .unwrap();

        let long_mode_entry = trampoline_addr.as_u32() + layout.long_mode_entry as u32;
        let gdt_base = trampoline_addr.as_u32() + layout.gdt as u32;

        let mut expected_far_ptr = [0u8; FAR_POINTER_SIZE];
        expected_far_ptr[..4].copy_from_slice(&long_mode_entry.to_le_bytes());
        expected_far_ptr[4..].copy_from_slice(&GDT64_CODE_SELECTOR.to_le_bytes());
        assert_eq!(
            &page[layout.long_mode_far_ptr..layout.long_mode_far_ptr + FAR_POINTER_SIZE],
            &expected_far_ptr
        );

        let mut expected_descriptor = [0u8; GDT_DESCRIPTOR_SIZE];
        expected_descriptor[..2].copy_from_slice(&((GDT_SIZE - 1) as u16).to_le_bytes());
        expected_descriptor[2..].copy_from_slice(&gdt_base.to_le_bytes());
        assert_eq!(
            &page[layout.gdt_descriptor..layout.gdt_descriptor + GDT_DESCRIPTOR_SIZE],
            &expected_descriptor
        );

        let mut expected_gdt = [0u8; GDT_SIZE];
        for (index, entry) in build_gdt(trampoline_addr.as_u32()).iter().enumerate() {
            let offset = index * size_of::<u64>();
            expected_gdt[offset..offset + size_of::<u64>()].copy_from_slice(&entry.to_le_bytes());
        }
        assert_eq!(&page[layout.gdt..layout.gdt + GDT_SIZE], &expected_gdt);
    }

    #[test]
    fn layout_validation_rejects_out_of_range_slots() {
        let mut layout = resolve_trampoline_layout().unwrap();
        layout.gdt = layout.len;

        assert_eq!(
            validate_trampoline_layout(layout),
            Err("AP trampoline layout range exceeds the image boundary")
        );
    }

    #[test]
    fn layout_validation_rejects_overlapping_slots() {
        let mut layout = resolve_trampoline_layout().unwrap();
        layout.gdt_descriptor = layout.long_mode_far_ptr;

        assert_eq!(
            validate_trampoline_layout(layout),
            Err("AP trampoline layout ranges overlap")
        );
    }

    #[test]
    fn layout_validation_rejects_long_mode_entry_inside_patch_slot() {
        let mut layout = resolve_trampoline_layout().unwrap();
        layout.long_mode_entry = layout.gdt;

        assert_eq!(
            validate_trampoline_layout(layout),
            Err("AP trampoline long mode entry overlaps a patch range")
        );
    }
}
