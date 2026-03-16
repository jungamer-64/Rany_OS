// ============================================================================
// libs/ap_trampoline/src/mailbox.rs
// ============================================================================
use core::mem::align_of;
use core::num::{NonZeroU32, NonZeroU64};
use core::ptr::NonNull;
use core::sync::atomic::{Ordering, fence};

use crate::LAYOUT_VERSION;
use crate::addr::{PageTable32Addr, TrampolineVirtAddr};
use crate::image::trampoline_mailbox_offset_checked;

const MAILBOX_MAGIC: u32 = u32::from_le_bytes(*b"APMB");

pub struct ApBootFlags;

impl ApBootFlags {
    pub const TRAMPOLINE_READY: u32 = 1 << 0;
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

#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApTrampolineMailbox {
    magic: u32,
    layout_version: u32,
    ap_slot: u32,
    cpu_id: u32,
    page_table: u64,
    stack_ptr: u64,
    entry_point: u64,
    probe_addr: u64,
}

pub(crate) const MAILBOX_PAGE_TABLE_OFFSET: usize =
    core::mem::offset_of!(ApTrampolineMailbox, page_table);
pub(crate) const MAILBOX_STACK_PTR_OFFSET: usize =
    core::mem::offset_of!(ApTrampolineMailbox, stack_ptr);
pub(crate) const MAILBOX_ENTRY_POINT_OFFSET: usize =
    core::mem::offset_of!(ApTrampolineMailbox, entry_point);

impl ApTrampolineMailbox {
    pub(crate) fn from_launch_info(info: ApTrampolineLaunchInfo) -> Self {
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

    pub(crate) fn try_into_launch_info(self) -> Result<ApTrampolineLaunchInfo, &'static str> {
        if self.magic != MAILBOX_MAGIC {
            return Err("AP trampoline mailbox magic mismatch");
        }
        if self.layout_version != LAYOUT_VERSION {
            return Err("AP trampoline mailbox layout version mismatch");
        }
        Ok(ApTrampolineLaunchInfo::new(
            self.ap_slot,
            NonZeroU32::new(self.cpu_id).ok_or("AP trampoline mailbox CPU ID is zero")?,
            PageTable32Addr::new(self.page_table)?,
            NonZeroU64::new(self.stack_ptr).ok_or("AP trampoline mailbox stack pointer is zero")?,
            NonZeroU64::new(self.entry_point).ok_or("AP trampoline mailbox entry point is zero")?,
            NonZeroU64::new(self.probe_addr),
        ))
    }

    /// # Safety
    ///
    /// `ptr` must be valid to read a fully initialized mailbox value via a
    /// volatile load for the duration of this call.
    pub(crate) unsafe fn read_verified_from_ptr(
        ptr: *const Self,
    ) -> Result<ApTrampolineLaunchInfo, &'static str> {
        let mailbox = unsafe { core::ptr::read_volatile(ptr) };
        mailbox.try_into_launch_info()
    }

    /// # Safety
    ///
    /// `ptr` must be valid to write a mailbox value via a volatile store for
    /// the duration of this call, and no conflicting accesses may occur.
    pub(crate) unsafe fn write_volatile_to_ptr(
        ptr: NonNull<Self>,
        launch_info: ApTrampolineLaunchInfo,
    ) {
        let mailbox = Self::from_launch_info(launch_info);
        unsafe {
            core::ptr::write_volatile(ptr.as_ptr(), mailbox);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TrampolineMailboxHandle {
    ptr: NonNull<ApTrampolineMailbox>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrampolineMailboxReadHandle {
    ptr: *const ApTrampolineMailbox,
}

// The handle is a validated writable mailbox address. Constructors validate the
// pointer but do not enforce uniqueness, so callers must ensure no other
// writable handle targets the same mailbox concurrently.
unsafe impl Send for TrampolineMailboxHandle {}
// Read handles may move between threads, but are intentionally not `Sync`:
// volatile loads alone do not provide synchronization for shared concurrent
// reads through the same handle.
unsafe impl Send for TrampolineMailboxReadHandle {}

impl TrampolineMailboxHandle {
    /// # Safety
    ///
    /// `ptr` must point to a valid, mapped writable AP trampoline mailbox for the
    /// lifetime of the handle.
    pub unsafe fn from_ptr(ptr: *mut u8) -> Result<Self, &'static str> {
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
        let mailbox_offset = trampoline_mailbox_offset_checked()?;
        let addr = trampoline_virt
            .as_usize()
            .checked_add(mailbox_offset)
            .ok_or("AP trampoline mailbox address overflowed")?;

        Ok(Self {
            ptr: validate_mailbox_ptr(addr as *mut u8)?,
        })
    }

    /// Writes a new launch mailbox image and publishes it for AP startup.
    pub fn write_launch(&mut self, launch_info: ApTrampolineLaunchInfo) {
        // Safety: the handle constructor validates the mailbox address and the
        // mutable borrow guarantees no concurrent access through this handle.
        unsafe { ApTrampolineMailbox::write_volatile_to_ptr(self.ptr, launch_info) };
        fence(Ordering::SeqCst);
    }

    pub fn read_verified(&self) -> Result<ApTrampolineLaunchInfo, &'static str> {
        self.read_handle().read_verified()
    }

    pub fn read_handle(&self) -> TrampolineMailboxReadHandle {
        TrampolineMailboxReadHandle {
            ptr: self.ptr.as_ptr().cast_const(),
        }
    }
}

impl TrampolineMailboxReadHandle {
    /// # Safety
    ///
    /// `ptr` must point to a valid, mapped readable AP trampoline mailbox for
    /// the lifetime of the handle.
    pub unsafe fn from_const_ptr(ptr: *const u8) -> Result<Self, &'static str> {
        Ok(Self {
            ptr: validate_mailbox_const_ptr(ptr)?,
        })
    }

    pub fn read_verified(&self) -> Result<ApTrampolineLaunchInfo, &'static str> {
        // Safety: the read handle constructor validates the mailbox address and
        // ties further reads to that checked location.
        unsafe { ApTrampolineMailbox::read_verified_from_ptr(self.ptr) }
    }
}

fn validate_mailbox_ptr(ptr: *mut u8) -> Result<NonNull<ApTrampolineMailbox>, &'static str> {
    let ptr = NonNull::new(ptr).ok_or("AP trampoline mailbox address is null")?;
    if !(ptr.as_ptr() as usize).is_multiple_of(align_of::<ApTrampolineMailbox>()) {
        return Err("AP trampoline mailbox address is misaligned");
    }
    Ok(ptr.cast())
}

fn validate_mailbox_const_ptr(ptr: *const u8) -> Result<*const ApTrampolineMailbox, &'static str> {
    Ok(validate_mailbox_ptr(ptr.cast_mut())?.as_ptr().cast_const())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAILBOX_OFFSET;
    use core::mem::{MaybeUninit, align_of, offset_of};

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

    fn launch_info_without_probe() -> ApTrampolineLaunchInfo {
        ApTrampolineLaunchInfo::new(
            2,
            NonZeroU32::new(3).unwrap(),
            PageTable32Addr::new(0x2000).unwrap(),
            NonZeroU64::new(0x9000).unwrap(),
            NonZeroU64::new(0xfeed_beef).unwrap(),
            None,
        )
    }

    #[test]
    fn mailbox_offsets_match_asm_contract() {
        assert_eq!(offset_of!(ApTrampolineMailbox, magic), 0);
        assert_eq!(offset_of!(ApTrampolineMailbox, layout_version), 4);
        assert_eq!(offset_of!(ApTrampolineMailbox, ap_slot), 8);
        assert_eq!(offset_of!(ApTrampolineMailbox, cpu_id), 12);
        assert_eq!(offset_of!(ApTrampolineMailbox, page_table), 16);
        assert_eq!(offset_of!(ApTrampolineMailbox, stack_ptr), 24);
        assert_eq!(offset_of!(ApTrampolineMailbox, entry_point), 32);
        assert_eq!(offset_of!(ApTrampolineMailbox, probe_addr), 40);
    }

    #[test]
    fn mailbox_handles_reject_invalid_addresses() {
        assert_eq!(
            unsafe { TrampolineMailboxHandle::from_ptr(core::ptr::null_mut::<u8>()) },
            Err("AP trampoline mailbox address is null")
        );
        assert_eq!(
            unsafe { TrampolineMailboxReadHandle::from_const_ptr(core::ptr::null::<u8>()) },
            Err("AP trampoline mailbox address is null")
        );

        #[repr(align(8))]
        struct Aligned([u8; 2]);

        let mut storage = Aligned([0u8; 2]);
        let misaligned_mut = unsafe { storage.0.as_mut_ptr().add(1) };
        let misaligned_const = misaligned_mut as *const u8;
        assert_eq!(
            unsafe { TrampolineMailboxHandle::from_ptr(misaligned_mut) },
            Err("AP trampoline mailbox address is misaligned")
        );
        assert_eq!(
            unsafe { TrampolineMailboxReadHandle::from_const_ptr(misaligned_const) },
            Err("AP trampoline mailbox address is misaligned")
        );
    }

    #[test]
    fn mailbox_handle_from_trampoline_virt_uses_contract_offset() {
        let trampoline_virt = TrampolineVirtAddr::new(0x1000_0000).unwrap();
        let handle =
            unsafe { TrampolineMailboxHandle::from_trampoline_virt(trampoline_virt) }.unwrap();

        assert_eq!(
            handle.ptr.as_ptr() as usize,
            trampoline_virt.as_usize() + MAILBOX_OFFSET
        );
    }

    #[test]
    fn mailbox_handle_round_trips_launch_mailbox() {
        let mut mailbox = MaybeUninit::<ApTrampolineMailbox>::uninit();
        let mut handle =
            unsafe { TrampolineMailboxHandle::from_ptr(mailbox.as_mut_ptr().cast()) }.unwrap();
        let launch_info = launch_info();

        handle.write_launch(launch_info);

        assert_eq!(handle.read_verified().unwrap(), launch_info);
    }

    #[test]
    fn mailbox_handle_round_trips_launch_mailbox_without_probe() {
        let mut mailbox = MaybeUninit::<ApTrampolineMailbox>::uninit();
        let mut handle =
            unsafe { TrampolineMailboxHandle::from_ptr(mailbox.as_mut_ptr().cast()) }.unwrap();
        let launch_info = launch_info_without_probe();

        handle.write_launch(launch_info);

        assert_eq!(handle.read_verified().unwrap().probe_addr(), None);
    }

    #[test]
    fn mailbox_read_verified_rejects_magic_mismatch() {
        let mut mailbox = ApTrampolineMailbox::from_launch_info(launch_info());
        mailbox.magic = 0;
        let handle = unsafe {
            TrampolineMailboxReadHandle::from_const_ptr(
                (&mailbox as *const ApTrampolineMailbox).cast(),
            )
        }
        .unwrap();

        assert_eq!(
            handle.read_verified(),
            Err("AP trampoline mailbox magic mismatch")
        );
    }

    #[test]
    fn mailbox_read_verified_rejects_zero_cpu_id() {
        let mut mailbox = ApTrampolineMailbox::from_launch_info(launch_info());
        mailbox.cpu_id = 0;
        let handle = unsafe {
            TrampolineMailboxReadHandle::from_const_ptr(
                (&mailbox as *const ApTrampolineMailbox).cast(),
            )
        }
        .unwrap();

        assert_eq!(
            handle.read_verified(),
            Err("AP trampoline mailbox CPU ID is zero")
        );
    }

    #[test]
    fn mailbox_read_verified_rejects_zero_page_table() {
        let mut mailbox = ApTrampolineMailbox::from_launch_info(launch_info());
        mailbox.page_table = 0;
        let handle = unsafe {
            TrampolineMailboxReadHandle::from_const_ptr(
                (&mailbox as *const ApTrampolineMailbox).cast(),
            )
        }
        .unwrap();

        assert_eq!(
            handle.read_verified(),
            Err("AP page table base must not be zero")
        );
    }

    #[test]
    fn mailbox_read_verified_rejects_layout_mismatch() {
        let mut mailbox = ApTrampolineMailbox::from_launch_info(launch_info());
        mailbox.layout_version += 1;
        let handle = unsafe {
            TrampolineMailboxReadHandle::from_const_ptr(
                (&mailbox as *const ApTrampolineMailbox).cast(),
            )
        }
        .unwrap();

        assert_eq!(
            handle.read_verified(),
            Err("AP trampoline mailbox layout version mismatch")
        );
    }

    #[test]
    fn mailbox_alignment_matches_contract() {
        assert_eq!(align_of::<ApTrampolineMailbox>(), 8);
    }
}
