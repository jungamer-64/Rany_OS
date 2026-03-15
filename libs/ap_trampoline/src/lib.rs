#![no_std]
#![allow(clippy::cargo_common_metadata)]

mod trampoline_asm;

use core::mem::{align_of, size_of};
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::ptr::{NonNull, addr_of};
use core::slice;

pub const TRAMPOLINE_SIZE: usize = 4096;
pub const MAILBOX_OFFSET: usize = 0xE0;
pub const LAYOUT_VERSION: u32 = 2;

const LOW_MEM_LIMIT: u64 = 0x10_0000;
const MAILBOX_MAGIC: u32 = u32::from_le_bytes(*b"APMB");
const FAR_POINTER_SIZE: usize = 6;
const GDT_DESCRIPTOR_SIZE: usize = 6;
const GDT_ENTRY_COUNT: usize = 4;
const GDT_SIZE: usize = GDT_ENTRY_COUNT * size_of::<u64>();
const GDT_FLAT_LIMIT: u32 = 0x000F_FFFF;
const GDT32_CODE_SELECTOR: u16 = 0x08;
const GDT32_DATA_SELECTOR: u16 = 0x10;
const GDT64_CODE_SELECTOR: u16 = 0x18;
const GDT_ACCESS_CODE: u8 = 0x9A;
const GDT_ACCESS_DATA: u8 = 0x92;
const GDT_FLAGS_32: u8 = 0xC;
const GDT_FLAGS_64: u8 = 0xA;

pub struct ApBootFlags;

impl ApBootFlags {
    pub const TRAMPOLINE_READY: u32 = 1 << 0;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrampolinePhysAddr(u32);

impl TrampolinePhysAddr {
    pub fn new(addr: u64) -> Result<Self, &'static str> {
        let addr32 = u32::try_from(addr).map_err(|_| "AP trampoline address exceeds u32")?;
        if addr >= LOW_MEM_LIMIT {
            return Err("AP trampoline must reside below 1 MiB");
        }
        if addr32 as usize % TRAMPOLINE_SIZE != 0 {
            return Err("AP trampoline must be 4 KiB aligned");
        }

        Ok(Self(addr32))
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    pub const fn sipi_vector(self) -> u8 {
        (self.0 / TRAMPOLINE_SIZE as u32) as u8
    }
}

impl TryFrom<u64> for TrampolinePhysAddr {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<usize> for TrampolinePhysAddr {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrampolineVirtAddr(NonZeroUsize);

impl TrampolineVirtAddr {
    pub fn new(addr: usize) -> Result<Self, &'static str> {
        let addr = NonZeroUsize::new(addr).ok_or("AP trampoline virtual address is null")?;
        if !addr.get().is_multiple_of(TRAMPOLINE_SIZE) {
            return Err("AP trampoline virtual address must be 4 KiB aligned");
        }

        Ok(Self(addr))
    }

    pub const fn as_usize(self) -> usize {
        self.0.get()
    }
}

impl TryFrom<usize> for TrampolineVirtAddr {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTable32Addr(u32);

impl PageTable32Addr {
    pub fn new(addr: u64) -> Result<Self, &'static str> {
        let addr32 = u32::try_from(addr).map_err(|_| "AP page table base exceeds u32")?;
        if addr32 as usize % TRAMPOLINE_SIZE != 0 {
            return Err("AP page table base must be 4 KiB aligned");
        }

        Ok(Self(addr32))
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }
}

impl TryFrom<u64> for PageTable32Addr {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApTrampolineLaunchInfo {
    ap_slot: u32,
    cpu_id: NonZeroU32,
    page_table: PageTable32Addr,
    stack_ptr: NonZeroU64,
    entry_point: NonZeroU64,
    probe_addr: Option<NonZeroU64>,
}

impl ApTrampolineLaunchInfo {
    pub const fn new(
        ap_slot: u32,
        cpu_id: NonZeroU32,
        page_table: PageTable32Addr,
        stack_ptr: NonZeroU64,
        entry_point: NonZeroU64,
        probe_addr: Option<NonZeroU64>,
    ) -> Self {
        Self {
            ap_slot,
            cpu_id,
            page_table,
            stack_ptr,
            entry_point,
            probe_addr,
        }
    }

    pub const fn ap_slot(&self) -> u32 {
        self.ap_slot
    }

    pub const fn cpu_id(&self) -> NonZeroU32 {
        self.cpu_id
    }

    pub const fn page_table(&self) -> PageTable32Addr {
        self.page_table
    }

    pub const fn stack_ptr(&self) -> NonZeroU64 {
        self.stack_ptr
    }

    pub const fn entry_point(&self) -> NonZeroU64 {
        self.entry_point
    }

    pub const fn probe_addr(&self) -> Option<NonZeroU64> {
        self.probe_addr
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApTrampolineMailbox {
    magic: u32,
    layout_version: u32,
    ap_slot: u32,
    cpu_id: u32,
    page_table: u64,
    stack_ptr: u64,
    entry_point: u64,
    probe_addr: u64,
}

impl ApTrampolineMailbox {
    fn from_launch_info(info: ApTrampolineLaunchInfo) -> Self {
        Self {
            magic: MAILBOX_MAGIC,
            layout_version: LAYOUT_VERSION,
            ap_slot: info.ap_slot(),
            cpu_id: info.cpu_id().get(),
            page_table: info.page_table().as_u64(),
            stack_ptr: info.stack_ptr().get(),
            entry_point: info.entry_point().get(),
            probe_addr: info.probe_addr().map_or(0, NonZeroU64::get),
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.magic != MAILBOX_MAGIC {
            return Err("AP trampoline mailbox magic mismatch");
        }
        if self.layout_version != LAYOUT_VERSION {
            return Err("AP trampoline mailbox layout version mismatch");
        }
        if self.cpu_id == 0 {
            return Err("AP trampoline mailbox CPU ID is zero");
        }
        let _ = PageTable32Addr::new(self.page_table)?;
        let _ =
            NonZeroU64::new(self.stack_ptr).ok_or("AP trampoline mailbox stack pointer is zero")?;
        let _ =
            NonZeroU64::new(self.entry_point).ok_or("AP trampoline mailbox entry point is zero")?;

        Ok(())
    }

    fn read_verified_from_ptr(ptr: NonNull<Self>) -> Result<Self, &'static str> {
        let mailbox = unsafe { core::ptr::read_volatile(ptr.as_ptr()) };
        mailbox.validate()?;
        Ok(mailbox)
    }

    fn write_volatile_to_ptr(ptr: NonNull<Self>, launch_info: ApTrampolineLaunchInfo) {
        let mailbox = Self::from_launch_info(launch_info);
        unsafe {
            core::ptr::write_volatile(ptr.as_ptr(), mailbox);
        }
    }

    pub const fn ap_slot(&self) -> u32 {
        self.ap_slot
    }

    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    pub const fn page_table(&self) -> u64 {
        self.page_table
    }

    pub const fn stack_ptr(&self) -> u64 {
        self.stack_ptr
    }

    pub const fn entry_point(&self) -> u64 {
        self.entry_point
    }

    pub const fn probe_addr(&self) -> u64 {
        self.probe_addr
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrampolineMailboxHandle {
    ptr: NonNull<ApTrampolineMailbox>,
}

// The handle is a validated mailbox address. Callers are responsible for the
// synchronization rules around reads/writes to the shared trampoline page.
unsafe impl Send for TrampolineMailboxHandle {}
unsafe impl Sync for TrampolineMailboxHandle {}

impl TrampolineMailboxHandle {
    /// # Safety
    ///
    /// `ptr` must point to a valid, mapped `ApTrampolineMailbox` for the
    /// lifetime of the handle.
    pub unsafe fn from_raw_ptr(ptr: *mut ApTrampolineMailbox) -> Result<Self, &'static str> {
        Ok(Self {
            ptr: validate_mailbox_ptr(ptr)?,
        })
    }

    /// # Safety
    ///
    /// `trampoline_virt` must refer to a valid mapped trampoline page whose
    /// mailbox region is readable and writable for the lifetime of the handle.
    pub unsafe fn from_trampoline_virt(
        trampoline_virt: TrampolineVirtAddr,
    ) -> Result<Self, &'static str> {
        let layout = trampoline_layout_checked()?;
        let addr = trampoline_virt
            .as_usize()
            .checked_add(layout.mailbox)
            .ok_or("AP trampoline mailbox address overflowed")?;

        unsafe { Self::from_raw_ptr(addr as *mut ApTrampolineMailbox) }
    }

    pub fn write_launch(&self, launch_info: ApTrampolineLaunchInfo) -> Result<(), &'static str> {
        ApTrampolineMailbox::write_volatile_to_ptr(self.ptr, launch_info);
        Ok(())
    }

    pub fn read_verified(&self) -> Result<ApTrampolineMailbox, &'static str> {
        ApTrampolineMailbox::read_verified_from_ptr(self.ptr)
    }
}

pub struct TrampolinePageMut<'a> {
    page: &'a mut [u8; TRAMPOLINE_SIZE],
}

impl<'a> TrampolinePageMut<'a> {
    pub fn try_from_slice(page: &'a mut [u8]) -> Result<Self, &'static str> {
        if page.len() < TRAMPOLINE_SIZE {
            return Err("AP trampoline page is smaller than expected");
        }
        if page.len() > TRAMPOLINE_SIZE {
            return Err("AP trampoline page must be exactly one page");
        }

        let page = page
            .try_into()
            .map_err(|_| "AP trampoline page must be exactly one page")?;

        Ok(Self { page })
    }

    /// # Safety
    ///
    /// `ptr` must point to a valid writable 4 KiB page for the returned
    /// lifetime.
    pub unsafe fn from_raw_ptr(ptr: *mut u8) -> Result<Self, &'static str> {
        let ptr = NonNull::new(ptr).ok_or("AP trampoline page pointer is null")?;
        let page = unsafe { &mut *ptr.cast::<[u8; TRAMPOLINE_SIZE]>().as_ptr() };
        Ok(Self { page })
    }

    pub fn install(&mut self, trampoline_addr: TrampolinePhysAddr) -> Result<(), &'static str> {
        let layout = trampoline_layout_checked()?;
        let template = trampoline_bytes_checked()?;
        let page = &mut self.page[..];

        page.fill(0);
        page[..template.len()].copy_from_slice(template);
        patch_trampoline_inner(&mut page[..template.len()], trampoline_addr, layout)?;
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
    let start = trampoline_start();
    let layout = trampoline_layout_checked()?;
    Ok(unsafe { slice::from_raw_parts(start as *const u8, layout.len) })
}

fn trampoline_layout_checked() -> Result<TrampolineLayout, &'static str> {
    let start = trampoline_start();
    let end = symbol_addr(addr_of!(__ap_trampoline_end));

    validate_trampoline_layout(TrampolineLayout {
        len: end
            .checked_sub(start)
            .ok_or("AP trampoline end precedes start")?,
        long_mode_entry: symbol_offset(start, addr_of!(__ap_long_mode_entry))?,
        long_mode_far_ptr: symbol_offset(start, addr_of!(__ap_patch_long_mode_far_ptr))?,
        gdt_descriptor: symbol_offset(start, addr_of!(__ap_patch_gdt_descriptor))?,
        gdt: symbol_offset(start, addr_of!(__ap_patch_gdt))?,
        mailbox: symbol_offset(start, addr_of!(__ap_mailbox))?,
    })
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

fn trampoline_start() -> usize {
    symbol_addr(addr_of!(__ap_trampoline_start))
}

fn symbol_addr(symbol: *const u8) -> usize {
    symbol as usize
}

fn symbol_offset(start: usize, symbol: *const u8) -> Result<usize, &'static str> {
    symbol_addr(symbol)
        .checked_sub(start)
        .ok_or("AP trampoline symbol precedes start")
}

fn patch_trampoline_inner(
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

fn validate_mailbox_ptr(
    ptr: *mut ApTrampolineMailbox,
) -> Result<NonNull<ApTrampolineMailbox>, &'static str> {
    let ptr = NonNull::new(ptr).ok_or("AP trampoline mailbox address is null")?;
    if !(ptr.as_ptr() as usize).is_multiple_of(align_of::<ApTrampolineMailbox>()) {
        return Err("AP trampoline mailbox address is misaligned");
    }
    Ok(ptr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_info() -> ApTrampolineLaunchInfo {
        ApTrampolineLaunchInfo::new(
            2,
            NonZeroU32::new(3).unwrap(),
            PageTable32Addr::new(0x2000).unwrap(),
            NonZeroU64::new(0x9000).unwrap(),
            NonZeroU64::new(0xfeed_beef).unwrap(),
            NonZeroU64::new(0x1000),
        )
    }

    #[test]
    fn trampoline_fits_reserved_page() {
        assert!(trampoline_bytes_checked().unwrap().len() <= TRAMPOLINE_SIZE);
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
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, magic), 0);
        assert_eq!(
            core::mem::offset_of!(ApTrampolineMailbox, layout_version),
            4
        );
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, ap_slot), 8);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, cpu_id), 12);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, page_table), 16);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, stack_ptr), 24);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, entry_point), 32);
        assert_eq!(core::mem::offset_of!(ApTrampolineMailbox, probe_addr), 40);
    }

    #[test]
    fn trampoline_phys_addr_rejects_out_of_range_values() {
        assert_eq!(
            TrampolinePhysAddr::new(u64::from(u32::MAX) + 1),
            Err("AP trampoline address exceeds u32")
        );
        assert_eq!(
            TrampolinePhysAddr::new(LOW_MEM_LIMIT),
            Err("AP trampoline must reside below 1 MiB")
        );
        assert_eq!(
            TrampolinePhysAddr::new(0x8100),
            Err("AP trampoline must be 4 KiB aligned")
        );
    }

    #[test]
    fn trampoline_virt_addr_rejects_invalid_values() {
        assert_eq!(
            TrampolineVirtAddr::new(0),
            Err("AP trampoline virtual address is null")
        );
        assert_eq!(
            TrampolineVirtAddr::new(0x8100),
            Err("AP trampoline virtual address must be 4 KiB aligned")
        );
        assert_eq!(TrampolineVirtAddr::new(0x1000).unwrap().as_usize(), 0x1000);
    }

    #[test]
    fn page_table_addr_rejects_invalid_values() {
        assert_eq!(
            PageTable32Addr::new(u64::from(u32::MAX) + 1),
            Err("AP page table base exceeds u32")
        );
        assert_eq!(
            PageTable32Addr::new(0x2100),
            Err("AP page table base must be 4 KiB aligned")
        );
    }

    #[test]
    fn patch_slots_start_zeroed() {
        let bytes = trampoline_bytes_checked().unwrap();
        let layout = trampoline_layout_checked().unwrap();

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
        let layout = trampoline_layout_checked().unwrap();

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
    fn mailbox_handle_from_raw_ptr_rejects_invalid_addresses() {
        assert_eq!(
            unsafe { TrampolineMailboxHandle::from_raw_ptr(core::ptr::null_mut()) },
            Err("AP trampoline mailbox address is null")
        );

        #[repr(align(8))]
        struct Aligned([u8; size_of::<ApTrampolineMailbox>() + 1]);

        let mut storage = Aligned([0u8; size_of::<ApTrampolineMailbox>() + 1]);
        let misaligned = unsafe { storage.0.as_mut_ptr().add(1) } as *mut ApTrampolineMailbox;
        assert_eq!(
            unsafe { TrampolineMailboxHandle::from_raw_ptr(misaligned) },
            Err("AP trampoline mailbox address is misaligned")
        );
    }

    #[test]
    fn mailbox_handle_round_trips_launch_mailbox() {
        let mut mailbox = core::mem::MaybeUninit::<ApTrampolineMailbox>::uninit();
        let handle = unsafe { TrampolineMailboxHandle::from_raw_ptr(mailbox.as_mut_ptr()) }.unwrap();
        let launch_info = launch_info();

        handle.write_launch(launch_info).unwrap();

        assert_eq!(
            handle.read_verified().unwrap(),
            ApTrampolineMailbox::from_launch_info(launch_info)
        );
    }

    #[test]
    fn mailbox_read_verified_rejects_magic_mismatch() {
        let mut mailbox = ApTrampolineMailbox::from_launch_info(launch_info());
        mailbox.magic = 0;
        let handle = unsafe { TrampolineMailboxHandle::from_raw_ptr(&mut mailbox) }.unwrap();

        assert_eq!(
            handle.read_verified(),
            Err("AP trampoline mailbox magic mismatch")
        );
    }

    #[test]
    fn mailbox_read_verified_rejects_layout_mismatch() {
        let mut mailbox = ApTrampolineMailbox::from_launch_info(launch_info());
        mailbox.layout_version += 1;
        let handle = unsafe { TrampolineMailboxHandle::from_raw_ptr(&mut mailbox) }.unwrap();

        assert_eq!(
            handle.read_verified(),
            Err("AP trampoline mailbox layout version mismatch")
        );
    }

    #[test]
    fn trampoline_page_install_zeroes_mailbox_and_rest_of_page() {
        let layout = trampoline_layout_checked().unwrap();
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
    fn layout_validation_rejects_out_of_range_slots() {
        let mut layout = trampoline_layout_checked().unwrap();
        layout.gdt = layout.len;

        assert_eq!(
            validate_trampoline_layout(layout),
            Err("AP trampoline layout range exceeds the image boundary")
        );
    }

    #[test]
    fn layout_validation_rejects_overlapping_slots() {
        let mut layout = trampoline_layout_checked().unwrap();
        layout.gdt_descriptor = layout.long_mode_far_ptr;

        assert_eq!(
            validate_trampoline_layout(layout),
            Err("AP trampoline layout ranges overlap")
        );
    }
}
