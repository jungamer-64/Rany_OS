// ============================================================================
// kernel/src/io/iommu/amd/mod.rs
// ============================================================================

//! AMD-Vi backend driver (skeleton).

pub mod cmd;
pub mod tables;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::poll_fn;
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::Poll;

use x86_64::PhysAddr;

use crate::io::acpi::ivrs::{IvhdDeviceEntry, IvmdInfo};
use crate::io::iommu::cmdqueue::{CommandQueue, IommuCommandKind};
use crate::io::iommu::tables::{phys_to_virt_usize, virt_ptr_to_phys};
use crate::io::mmio::{mmio_read_u32, mmio_read_u64, mmio_write_u32, mmio_write_u64};
use crate::io::iommu::{IovaAllocatorFast, IovaGranularity, PAGE_SIZE_4K};
use crate::io::iommu::security::{SecurityEvent, SecurityNotifier};
use crate::mm::alloc_contiguous_frames;
use crate::mm::mapping::phys_to_virt;
use crate::sync::{PoisonLock, WakerQueue};
use hashbrown::HashMap;

use super::config::IommuConfig;
use super::domain::IommuDomain as DomainState;
use super::IommuBackend;
use super::page_table_pool::PageTablePool;
use super::registry::{get_iommu_driver, init_driver};
use super::types::{DeviceId, IommuDomainType, IommuError, PteFormat};

const MMIO_DEV_TABLE_OFFSET: u64 = 0x0000;
const MMIO_EVT_BUF_OFFSET: u64 = 0x0010;
const MMIO_CONTROL_OFFSET: u64 = 0x0018;
const MMIO_MSI_ADDR_LO_OFFSET: u64 = 0x015c;
const MMIO_MSI_ADDR_HI_OFFSET: u64 = 0x0160;
const MMIO_MSI_DATA_OFFSET: u64 = 0x0164;
const MMIO_EVT_HEAD_OFFSET: u64 = 0x2010;
const MMIO_EVT_TAIL_OFFSET: u64 = 0x2018;
const MMIO_STATUS_OFFSET: u64 = 0x2020;

const CONTROL_IOMMU_EN: u64 = 1 << 0;
const CONTROL_EVT_LOG_EN: u64 = 1 << 2;
const CONTROL_EVT_INT_EN: u64 = 1 << 3;
const CONTROL_CMDBUF_EN: u64 = 1 << 12;

const DEV_ENTRY_MODE_SHIFT: u64 = 9;
const PAGE_MODE_4_LEVEL: u64 = 0x04;
const PM_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

const DTE_FLAG_V: u64 = 1 << 0;
const DTE_FLAG_TV: u64 = 1 << 1;
const DTE_FLAG_IR: u64 = 1 << 61;
const DTE_FLAG_IW: u64 = 1 << 62;

const DEV_TABLE_ENTRY_SIZE: usize = 32;
const EVENT_ENTRY_SIZE: u32 = 16;
const EVT_BUFFER_BYTES: u32 = 8192;
const EVT_BUFFER_SIZE_MASK: u64 = 0x9 << 56;

const MMIO_STATUS_EVT_OVERFLOW_MASK: u32 = 1 << 0;
const MMIO_STATUS_EVT_INT_MASK: u32 = 1 << 1;
const MMIO_STATUS_EVT_RUN_MASK: u32 = 1 << 3;

const EVENT_TYPE_SHIFT: u32 = 28;
const EVENT_TYPE_MASK: u32 = 0x0f;
const EVENT_TYPE_ILL_DEV: u8 = 0x1;
const EVENT_TYPE_IO_FAULT: u8 = 0x2;
const EVENT_TYPE_DEV_TAB_ERR: u8 = 0x3;
const EVENT_TYPE_PAGE_TAB_ERR: u8 = 0x4;
const EVENT_TYPE_ILL_CMD: u8 = 0x5;
const EVENT_TYPE_CMD_HARD_ERR: u8 = 0x6;
const EVENT_TYPE_IOTLB_INV_TO: u8 = 0x7;
const EVENT_TYPE_INV_DEV_REQ: u8 = 0x8;
const EVENT_TYPE_INV_PPR_REQ: u8 = 0x9;
const EVENT_TYPE_RMP_FAULT: u8 = 0x0d;
const EVENT_TYPE_RMP_HW_ERR: u8 = 0x0e;
const EVENT_DEVID_MASK: u32 = 0xffff;
const EVENT_DEVID_SHIFT: u32 = 0;
const EVENT_DOMID_MASK_LO: u32 = 0xffff;
const EVENT_DOMID_MASK_HI: u32 = 0xf0000;
const EVENT_FLAGS_MASK: u32 = 0x0fff;
const EVENT_FLAGS_SHIFT: u32 = 0x10;

const AMD_FAULT_QUEUE_SIZE: usize = 128;
const AMD_FAULT_LOG_RATE_LIMIT: usize = 128;
// Use a fixed IOMMU fault vector number to avoid depending on `interrupts` during lib builds
const AMD_IOMMU_FAULT_VECTOR: u8 = 0x50u8;
const AMD_DEFAULT_MAX_ADDR_BITS: u8 = 48; // TODO: derive from AMD-Vi capability registers.

const IVHD_INIT_PASS: u8 = 1 << 0;
const IVHD_EINT_PASS: u8 = 1 << 1;
const IVHD_NMI_PASS: u8 = 1 << 2;
const IVHD_SYSMGT1: u8 = 1 << 4;
const IVHD_SYSMGT2: u8 = 1 << 5;
const IVHD_LINT0_PASS: u8 = 1 << 6;
const IVHD_LINT1_PASS: u8 = 1 << 7;

const DEV_ENTRY_INIT_PASS: u8 = 0xb8;
const DEV_ENTRY_EINT_PASS: u8 = 0xb9;
const DEV_ENTRY_NMI_PASS: u8 = 0xba;
const DEV_ENTRY_SYSMGT1: u8 = 0x68;
const DEV_ENTRY_SYSMGT2: u8 = 0x69;
const DEV_ENTRY_LINT0_PASS: u8 = 0xbe;
const DEV_ENTRY_LINT1_PASS: u8 = 0xbf;

fn set_dte_bit(entry: &mut AmdDeviceTableEntry, bit: u8) {
    let idx = (bit >> 6) & 0x03;
    let shift = bit & 0x3f;
    entry.data[idx as usize] |= 1u64 << shift;
}

fn apply_ivhd_flags(entry: &mut AmdDeviceTableEntry, flags: u8) {
    if (flags & IVHD_INIT_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_INIT_PASS);
    }
    if (flags & IVHD_EINT_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_EINT_PASS);
    }
    if (flags & IVHD_NMI_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_NMI_PASS);
    }
    if (flags & IVHD_SYSMGT1) != 0 {
        set_dte_bit(entry, DEV_ENTRY_SYSMGT1);
    }
    if (flags & IVHD_SYSMGT2) != 0 {
        set_dte_bit(entry, DEV_ENTRY_SYSMGT2);
    }
    if (flags & IVHD_LINT0_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_LINT0_PASS);
    }
    if (flags & IVHD_LINT1_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_LINT1_PASS);
    }
}

#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct AmdDeviceTableEntry {
    data: [u64; 4],
}

impl Default for AmdDeviceTableEntry {
    fn default() -> Self {
        Self { data: [0; 4] }
    }
}

struct AmdDeviceTable {
    segment: u16,
    phys_base: u64,
    virt_base: NonNull<AmdDeviceTableEntry>,
    size_bytes: u64,
    entry_count: usize,
    lock: PoisonLock<()>,
}

// SAFETY: AmdDeviceTable contains raw pointers to a contiguous region of kernel memory
// which is accessed with proper synchronization using `lock`. It is therefore safe to
// treat the structure as `Send` and `Sync` across threads.
unsafe impl Send for AmdDeviceTable {}
unsafe impl Sync for AmdDeviceTable {}

impl AmdDeviceTable {
    fn new(segment: u16, entry_count: usize) -> Result<Self, IommuError> {
        if entry_count == 0 {
            return Err(IommuError::InvalidAddress);
        }

        debug_assert_eq!(size_of::<AmdDeviceTableEntry>(), DEV_TABLE_ENTRY_SIZE);

        let entry_bytes = size_of::<AmdDeviceTableEntry>() as u64;
        let mut size_bytes = (entry_count as u64)
            .checked_mul(entry_bytes)
            .ok_or(IommuError::InvalidAddress)?;
        if size_bytes < PAGE_SIZE_4K {
            size_bytes = PAGE_SIZE_4K;
        }
        size_bytes = size_bytes.next_power_of_two();

        let frame_count = (size_bytes / PAGE_SIZE_4K) as usize;
        let phys_base =
            alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
        let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
        let entry_ptr = NonNull::new(virt_base.as_u64() as *mut AmdDeviceTableEntry)
            .ok_or(IommuError::HardwareError)?;

        unsafe {
            ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, size_bytes as usize);
        }

        Ok(Self {
            segment,
            phys_base: phys_base.as_u64(),
            virt_base: entry_ptr,
            size_bytes,
            entry_count: (size_bytes / entry_bytes) as usize,
            lock: PoisonLock::new(()),
        })
    }

    fn program(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        if (self.phys_base & 0xfff) != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        let size_field = (self.size_bytes >> 12).saturating_sub(1);
        let entry = (self.phys_base & !0xfff) | size_field;
        let mmio_base = phys_to_virt_usize(unit.base_addr);
        mmio_write_u64(mmio_base + MMIO_DEV_TABLE_OFFSET as usize, entry);
        Ok(())
    }

    fn write_entry(&self, devid: u16, entry: AmdDeviceTableEntry) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        let index = devid as usize;
        if index >= self.entry_count {
            return Err(IommuError::DeviceNotFound);
        }
        unsafe {
            self.virt_base.as_ptr().add(index).write_volatile(entry);
        }
        Ok(())
    }

    fn clear_entry(&self, devid: u16) -> Result<(), IommuError> {
        self.write_entry(devid, AmdDeviceTableEntry::default())
    }

    fn fill(&self, entry: AmdDeviceTableEntry) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        for idx in 0..self.entry_count {
            unsafe {
                self.virt_base.as_ptr().add(idx).write_volatile(entry);
            }
        }
        Ok(())
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
struct AmdEventEntry {
    data: [u32; 4],
}

impl AmdEventEntry {
    fn event_type(&self) -> u8 {
        ((self.data[1] >> EVENT_TYPE_SHIFT) & EVENT_TYPE_MASK) as u8
    }

    fn devid(&self) -> u16 {
        ((self.data[0] >> EVENT_DEVID_SHIFT) & EVENT_DEVID_MASK) as u16
    }

    fn domain_id(&self) -> u32 {
        (self.data[0] & EVENT_DOMID_MASK_HI) | (self.data[1] & EVENT_DOMID_MASK_LO)
    }

    fn flags(&self) -> u16 {
        ((self.data[1] >> EVENT_FLAGS_SHIFT) & EVENT_FLAGS_MASK) as u16
    }

    fn address(&self) -> u64 {
        ((self.data[3] as u64) << 32) | (self.data[2] as u64)
    }
}

struct AmdEventLog {
    phys_base: u64,
    virt_base: NonNull<u32>,
    size_bytes: u64,
    processing: AtomicBool,
}

// SAFETY: AmdEventLog holds a stable buffer pointer accessed via atomics and MMIO.
unsafe impl Send for AmdEventLog {}
unsafe impl Sync for AmdEventLog {}

impl AmdEventLog {
    fn new() -> Result<Self, IommuError> {
        let size_bytes = EVT_BUFFER_BYTES as u64;
        let frame_count = (size_bytes / PAGE_SIZE_4K) as usize;
        let phys_base =
            alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
        let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
        let entry_ptr =
            NonNull::new(virt_base.as_u64() as *mut u32).ok_or(IommuError::HardwareError)?;

        unsafe {
            ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, size_bytes as usize);
        }

        Ok(Self {
            phys_base: phys_base.as_u64(),
            virt_base: entry_ptr,
            size_bytes,
            processing: AtomicBool::new(false),
        })
    }

    fn program(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        if (self.phys_base & 0xfff) != 0 {
            return Err(IommuError::InvalidAlignment);
        }
        if self.size_bytes != EVT_BUFFER_BYTES as u64 {
            return Err(IommuError::NotSupported);
        }

        let entry = (self.phys_base & !0xfff) | EVT_BUFFER_SIZE_MASK;
        let mmio_base = phys_to_virt_usize(unit.base_addr);
        mmio_write_u64(mmio_base + MMIO_EVT_BUF_OFFSET as usize, entry);
        mmio_write_u32(mmio_base + MMIO_EVT_HEAD_OFFSET as usize, 0);
        mmio_write_u32(mmio_base + MMIO_EVT_TAIL_OFFSET as usize, 0);
        Ok(())
    }

    fn try_lock(&self) -> Option<AmdEventLogGuard<'_>> {
        if self
            .processing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(AmdEventLogGuard { log: self })
        } else {
            None
        }
    }

    fn read_entry(&self, offset: u32) -> Option<AmdEventEntry> {
        let offset_end = offset as u64 + EVENT_ENTRY_SIZE as u64;
        if offset_end > self.size_bytes {
            return None;
        }
        let base = self.virt_base.as_ptr() as *const u8;
        let ptr = unsafe { base.add(offset as usize) as *const u32 };
        let mut data = [0u32; 4];
        for idx in 0..4 {
            data[idx] = unsafe { ptr.add(idx).read_volatile() };
        }
        Some(AmdEventEntry { data })
    }
}

struct AmdEventLogGuard<'a> {
    log: &'a AmdEventLog,
}

impl Drop for AmdEventLogGuard<'_> {
    fn drop(&mut self) {
        self.log.processing.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug)]
struct AmdFaultEvent {
    segment: u16,
    devid: u16,
    domain_id: u32,
    flags: u16,
    address: u64,
    event_type: u8,
    raw: [u32; 4],
    is_overflow: bool,
}

impl AmdFaultEvent {
    fn from_entry(segment: u16, entry: AmdEventEntry) -> Self {
        Self {
            segment,
            devid: entry.devid(),
            domain_id: entry.domain_id(),
            flags: entry.flags(),
            address: entry.address(),
            event_type: entry.event_type(),
            raw: entry.data,
            is_overflow: false,
        }
    }

    fn overflow(segment: u16) -> Self {
        Self {
            segment,
            devid: 0,
            domain_id: 0,
            flags: 0,
            address: 0,
            event_type: 0,
            raw: [0; 4],
            is_overflow: true,
        }
    }
}

struct AmdDeferredFaultQueue {
    events: [Option<AmdFaultEvent>; AMD_FAULT_QUEUE_SIZE],
    head: AtomicUsize,
    tail: AtomicUsize,
    dropped: AtomicUsize,
}

impl AmdDeferredFaultQueue {
    const fn new() -> Self {
        Self {
            events: [None; AMD_FAULT_QUEUE_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    fn push(&self, event: AmdFaultEvent) {
        const MAX_RETRIES: usize = 16;
        for _ in 0..MAX_RETRIES {
            let tail = self.tail.load(Ordering::Relaxed);
            let next_tail = (tail + 1) % AMD_FAULT_QUEUE_SIZE;
            let head = self.head.load(Ordering::Acquire);
            if next_tail == head {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if self
                .tail
                .compare_exchange_weak(tail, next_tail, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                unsafe {
                    let ptr = &self.events as *const _
                        as *mut [Option<AmdFaultEvent>; AMD_FAULT_QUEUE_SIZE];
                    core::ptr::write_volatile(&mut (*ptr)[tail], Some(event));
                }
                return;
            }
            core::hint::spin_loop();
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn pop(&self) -> Option<AmdFaultEvent> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let event = unsafe {
            let ptr =
                &self.events as *const _ as *mut [Option<AmdFaultEvent>; AMD_FAULT_QUEUE_SIZE];
            (*ptr)[head].take()
        };
        self.head
            .store((head + 1) % AMD_FAULT_QUEUE_SIZE, Ordering::Release);
        event
    }

    fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }

    fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail
    }
}

static AMD_DEFERRED_FAULT_QUEUE: AmdDeferredFaultQueue = AmdDeferredFaultQueue::new();
static AMD_FAULT_WAKERS: WakerQueue = WakerQueue::new();
static AMD_CMD_WAITERS: WakerQueue = WakerQueue::new();

pub fn drain_deferred_faults() -> usize {
    drain_deferred_faults_with_driver(None)
}

pub(crate) fn drain_deferred_faults_with_driver(driver: Option<&AmdIommuDriver>) -> usize {
    let mut count = 0usize;
    while let Some(event) = AMD_DEFERRED_FAULT_QUEUE.pop() {
        if event.is_overflow {
            log::warn!("[IOMMU][AMD-Vi] Event log overflow");
        } else {
            let (bus, device, function) = devid_to_bdf(event.devid);
            log::error!(
                "[IOMMU][AMD-Vi] Event {} seg={} devid={:02x}:{:02x}.{} domain=0x{:05x} addr=0x{:x} flags=0x{:03x} raw={:08x}:{:08x}:{:08x}:{:08x}",
                event_type_name(event.event_type),
                event.segment,
                bus,
                device,
                function,
                event.domain_id,
                event.address,
                event.flags,
                event.raw[0],
                event.raw[1],
                event.raw[2],
                event.raw[3],
            );
            if let Some(driver) = driver {
                driver.notify_security(SecurityEvent::DmaViolation {
                    source_id: event.devid,
                    fault_address: event.address,
                    reason: event.event_type,
                    domain_id: Some(event.domain_id),
                });
            }
        }
        count += 1;
    }

    let dropped = AMD_DEFERRED_FAULT_QUEUE.take_dropped();
    if dropped > 0 {
        log::warn!(
            "[IOMMU][AMD-Vi] {} event(s) dropped due to queue overflow",
            dropped
        );
        if let Some(driver) = driver {
            driver.notify_security(SecurityEvent::EventsDropped {
                count: dropped as u64,
            });
        }
    }

    count
}

async fn wait_for_fault_events() {
    poll_fn(|cx| {
        if !AMD_DEFERRED_FAULT_QUEUE.is_empty() {
            return Poll::Ready(());
        }
        AMD_FAULT_WAKERS.register(cx.waker());
        if !AMD_DEFERRED_FAULT_QUEUE.is_empty() {
            return Poll::Ready(());
        }
        Poll::Pending
    })
    .await;
}

pub async fn fault_handler_task() {
    loop {
        let driver = get_iommu_driver().and_then(|backend| match backend.as_ref() {
            IommuBackend::Amd(driver) => Some(driver),
            _ => None,
        });
        let _ = drain_deferred_faults_with_driver(driver);
        wait_for_fault_events().await;
    }
}

pub fn spawn_fault_handler_task() {
    crate::task::per_core_executor::spawn(fault_handler_task());
}

#[cfg(not(test))]
const AMD_COMMAND_QUEUE_BATCH: usize = 64;

#[cfg(not(test))]
async fn command_queue_worker() {
    loop {
        let driver = get_iommu_driver().and_then(|backend| match backend.as_ref() {
            IommuBackend::Amd(driver) => Some(driver),
            _ => None,
        });

        let Some(driver) = driver else {
            break;
        };

        let Some(cq) = driver.command_queue.as_ref() else {
            break;
        };

        let processed = cq.process_up_to(
            |kind| driver.handle_command_queue_entry(kind).map_err(|_| ()),
            AMD_COMMAND_QUEUE_BATCH,
        );

        if processed == 0 {
            cq.wait_for_work().await;
        }
    }
}

#[cfg(not(test))]
fn spawn_command_queue_worker() {
    crate::task::per_core_executor::spawn(command_queue_worker());
}

fn msi_message(vector: u8) -> (u64, u32) {
    const MSI_ADDRESS_BASE: u64 = 0xFEE0_0000;
    let apic_id: u64 = {
        #[cfg(feature = "apic")]
        {
            crate::io::interrupt_manager::current_apic_id() as u64
        }
        #[cfg(not(feature = "apic"))]
        {
            0u64
        }
    };
    let address = MSI_ADDRESS_BASE | (apic_id << 12);
    let data = vector as u32;
    (address, data)
}

fn event_type_name(event_type: u8) -> &'static str {
    match event_type {
        EVENT_TYPE_ILL_DEV => "ILLEGAL_DEVICE_TABLE_ENTRY",
        EVENT_TYPE_IO_FAULT => "IO_PAGE_FAULT",
        EVENT_TYPE_DEV_TAB_ERR => "DEV_TABLE_HARDWARE_ERROR",
        EVENT_TYPE_PAGE_TAB_ERR => "PAGE_TABLE_HARDWARE_ERROR",
        EVENT_TYPE_ILL_CMD => "ILLEGAL_COMMAND",
        EVENT_TYPE_CMD_HARD_ERR => "COMMAND_HARDWARE_ERROR",
        EVENT_TYPE_IOTLB_INV_TO => "IOTLB_INV_TIMEOUT",
        EVENT_TYPE_INV_DEV_REQ => "INVALID_DEVICE_REQUEST",
        EVENT_TYPE_INV_PPR_REQ => "INVALID_PPR_REQUEST",
        EVENT_TYPE_RMP_FAULT => "RMP_PAGE_FAULT",
        EVENT_TYPE_RMP_HW_ERR => "RMP_HARDWARE_ERROR",
        _ => "UNKNOWN",
    }
}

fn devid_to_bdf(devid: u16) -> (u8, u8, u8) {
    let bus = (devid >> 8) as u8;
    let devfn = (devid & 0xff) as u8;
    let device = (devfn >> 3) & 0x1f;
    let function = devfn & 0x07;
    (bus, device, function)
}

#[derive(Debug, Clone)]
pub struct AmdIommuUnit {
    pub segment: u16,
    pub base_addr: u64,
    pub flags: u8,
    pub device_id: u16,
    pub iommu_info: u16,
    pub iommu_feature: u32,
    pub device_entries: Vec<IvhdDeviceEntry>,
}

#[derive(Debug, Clone, Copy)]
pub struct AmdIvmdRange {
    pub segment: u16,
    pub devid_start: u16,
    pub devid_end: u16,
    pub range_start: u64,
    /// End address (exclusive), computed as start + length.
    pub range_end: u64,
    pub unity_map: bool,
    pub read: bool,
    pub write: bool,
    pub exclusion: bool,
}

impl AmdIvmdRange {
    fn from_ivmd(ivmd: IvmdInfo) -> Option<Self> {
        const IVMD_TYPE_ALL: u8 = 0x20;
        const IVMD_TYPE: u8 = 0x21;
        const IVMD_TYPE_RANGE: u8 = 0x22;
        const IVMD_FLAG_UNITY_MAP: u8 = 0x01;
        const IVMD_FLAG_IR: u8 = 0x02;
        const IVMD_FLAG_IW: u8 = 0x04;
        const IVMD_FLAG_EXCL_RANGE: u8 = 0x08;

        let (devid_start, devid_end) = match ivmd.block_type {
            IVMD_TYPE_ALL => (0, u16::MAX),
            IVMD_TYPE => (ivmd.device_id, ivmd.device_id),
            IVMD_TYPE_RANGE => (ivmd.device_id, ivmd.aux),
            _ => return None,
        };

        if devid_end < devid_start {
            return None;
        }

        let exclusion = (ivmd.flags & IVMD_FLAG_EXCL_RANGE) != 0;
        let read = (ivmd.flags & IVMD_FLAG_IR) != 0;
        let write = (ivmd.flags & IVMD_FLAG_IW) != 0;
        let unity_map = (ivmd.flags & IVMD_FLAG_UNITY_MAP) != 0;

        Some(Self {
            segment: ivmd.pci_segment,
            devid_start,
            devid_end,
            range_start: ivmd.range_start,
            range_end: ivmd.range_start.saturating_add(ivmd.range_length),
            unity_map,
            read,
            write,
            exclusion,
        })
    }

    fn applies_to_devid(&self, devid: u16) -> bool {
        devid >= self.devid_start && devid <= self.devid_end
    }
}

pub struct AmdIommuDriver {
    units: Vec<AmdIommuUnit>,
    ivmd_ranges: Vec<AmdIvmdRange>,
    cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
    event_logs: Vec<Option<AmdEventLog>>,
    device_tables: HashMap<u16, AmdDeviceTable>,
    domains: PoisonLock<HashMap<u16, AmdDomainInfo>>,
    device_domains: PoisonLock<HashMap<DeviceId, u16>>,
    next_domain_id: AtomicU64,
    page_table_pool: Arc<PageTablePool>,
    command_queue: Option<CommandQueue>,
    iova_allocator: IovaAllocatorFast,
    enabled: AtomicBool,
    security_notifier: spin::Once<Arc<dyn SecurityNotifier>>,
}

#[derive(Clone)]
struct AmdDomainInfo {
    domain: Arc<DomainState>,
}

impl AmdIommuDriver {
    pub fn new(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
        event_logs: Vec<Option<AmdEventLog>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Self {
        let page_table_pool = PageTablePool::new(crate::mm::numa::num_nodes().max(1), 32);
        let iova_bits = AMD_DEFAULT_MAX_ADDR_BITS.min(48).max(12);
        let iova_base = PAGE_SIZE_4K;
        let iova_limit = 1u64 << iova_bits;
        let iova_size = iova_limit.saturating_sub(iova_base);
        let iova_allocator = IovaAllocatorFast::new(iova_base, iova_size);
        let alloc_base = iova_allocator.base();
        let alloc_end = alloc_base.saturating_add(iova_allocator.size());
        
        // Reserve IVMD unity-mapped ranges
        for range in &ivmd_ranges {
            if !range.unity_map || range.exclusion {
                continue;
            }

            let start = align_down(range.range_start, PAGE_SIZE_4K);
            let end = align_up(range.range_end, PAGE_SIZE_4K);
            if end <= start {
                continue;
            }

            let clamped_start = start.max(alloc_base);
            let clamped_end = end.min(alloc_end);
            if clamped_end <= clamped_start {
                continue;
            }

            let reserve_size = clamped_end - clamped_start;
            match iova_allocator.reserve(clamped_start, reserve_size) {
                Ok(()) | Err(IommuError::AlreadyMapped) => {}
                Err(IommuError::InvalidAddress) => {
                    log::warn!(
                        "AMD-Vi IVMD reservation outside IOVA window: range={:#x}-{:#x}",
                        clamped_start,
                        clamped_end
                    );
                }
                Err(err) => {
                    log::warn!("AMD-Vi IVMD IOVA reservation failed: {:?}", err);
                }
            }
        }
        let mut domain_map = HashMap::new();
        let default_domain = DomainState::new(
            0,
            None,
            false,
            false,
            AMD_DEFAULT_MAX_ADDR_BITS,
            IommuDomainType::Translated,
            page_table_pool.clone(),
            PteFormat::Amd,
        );
        let default_domain = Arc::new(default_domain);
        domain_map.insert(
            0,
            AmdDomainInfo {
                domain: default_domain,
            },
        );

        Self {
            units,
            ivmd_ranges,
            cmd_states,
            event_logs,
            device_tables,
            domains: PoisonLock::new(domain_map),
            device_domains: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(1),
            page_table_pool,
            command_queue: Some(CommandQueue::new_with_numa(None)),
            iova_allocator,
            enabled: AtomicBool::new(false),
            security_notifier: spin::Once::new(),
        }
    }

    pub fn register_driver(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
        event_logs: Vec<Option<AmdEventLog>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Result<(), IommuError> {
        if get_iommu_driver().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        let driver = AmdIommuDriver::new(
            units,
            ivmd_ranges,
            cmd_states,
            event_logs,
            device_tables,
        );
        driver.populate_default_entries()?;
        init_driver(Arc::new(IommuBackend::Amd(driver)));
        Ok(())
    }

    pub fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let mut set = false;
        self.security_notifier.call_once(|| {
            set = true;
            notifier
        });

        if set {
            if let Some(notifier) = self.security_notifier.get() {
                match self.domains.lock() {
                    Ok(domains) => {
                        for info in domains.values() {
                            let _ = info.domain.set_security_notifier(Arc::clone(notifier));
                        }
                    }
                    Err(_) => {
                        log::error!(
                            "[IOMMU][AMD-Vi] Domains map poisoned while propagating security notifier"
                        );
                    }
                }
            }
        }

        set
    }

    fn notify_security(&self, event: SecurityEvent) {
        if let Some(notifier) = self.security_notifier.get() {
            notifier.notify(event);
        }
    }

    pub fn find_unit_for_device(&self, device: DeviceId) -> Option<&AmdIommuUnit> {
        let devid = device.requester_id();
        self.units
            .iter()
            .find(|unit| unit.segment == device.segment && unit.covers_devid(devid))
    }

    pub fn ivmd_ranges_for_device(&self, device: DeviceId) -> Vec<AmdIvmdRange> {
        let devid = device.requester_id();
        self.ivmd_ranges
            .iter()
            .copied()
            .filter(|range| range.segment == device.segment && range.applies_to_devid(devid))
            .collect()
    }

    fn ivhd_flags_for_device(&self, device: DeviceId) -> u8 {
        let mut flags = 0u8;
        let devid = device.requester_id();
        let unit = match self.find_unit_for_device(device) {
            Some(unit) => unit,
            None => return flags,
        };

        for entry in &unit.device_entries {
            match entry {
                IvhdDeviceEntry::All { flags: entry_flags } => flags |= *entry_flags,
                IvhdDeviceEntry::Select {
                    devid: entry_devid,
                    flags: entry_flags,
                } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::Range {
                    start,
                    end,
                    flags: entry_flags,
                } => {
                    if devid >= *start && devid <= *end {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::Alias {
                    devid: entry_devid,
                    alias,
                    flags: entry_flags,
                } => {
                    if *entry_devid == devid || *alias == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::AliasRange {
                    start,
                    end,
                    alias,
                    flags: entry_flags,
                } => {
                    if (devid >= *start && devid <= *end) || *alias == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::ExtSelect {
                    devid: entry_devid,
                    flags: entry_flags,
                    ..
                } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::ExtRange {
                    start,
                    end,
                    flags: entry_flags,
                    ..
                } => {
                    if devid >= *start && devid <= *end {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::Special {
                    devid: entry_devid,
                    flags: entry_flags,
                    ..
                } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::AcpiHid {
                    devid: entry_devid,
                    flags: entry_flags,
                } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
            }
        }

        flags
    }

    fn ivhd_global_flags(&self, segment: u16) -> u8 {
        let mut flags = 0u8;
        for unit in &self.units {
            if unit.segment != segment {
                continue;
            }
            for entry in &unit.device_entries {
                if let IvhdDeviceEntry::All { flags: entry_flags } = entry {
                    flags |= *entry_flags;
                }
            }
        }
        flags
    }

    fn domain_for_id(&self, domain_id: u16) -> Result<Arc<DomainState>, IommuError> {
        let domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let info = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        Ok(info.domain.clone())
    }

    fn device_table_for_segment(&self, segment: u16) -> Result<&AmdDeviceTable, IommuError> {
        self.device_tables
            .get(&segment)
            .ok_or(IommuError::NotPresent)
    }

    fn build_dte_entry(
        &self,
        domain_id: u16,
        domain: &DomainState,
        ivhd_flags: u8,
    ) -> Result<AmdDeviceTableEntry, IommuError> {
        let mut entry = AmdDeviceTableEntry::default();
        entry.data[0] |= DTE_FLAG_V | DTE_FLAG_TV | DTE_FLAG_IR | DTE_FLAG_IW;

        if domain.domain_type != IommuDomainType::Passthrough {
            let root_phys = virt_ptr_to_phys(domain.page_table as *const u8)?;
            if (root_phys & 0xfff) != 0 {
                return Err(IommuError::InvalidAlignment);
            }
            entry.data[0] |=
                (root_phys & PM_ADDR_MASK) | (PAGE_MODE_4_LEVEL << DEV_ENTRY_MODE_SHIFT);
        }

        if ivhd_flags != 0 {
            apply_ivhd_flags(&mut entry, ivhd_flags);
        }

        entry.data[1] |= domain_id as u64;
        Ok(entry)
    }

    fn alias_devids_for_device(&self, device: DeviceId) -> Vec<u16> {
        let mut aliases = Vec::new();
        let devid = device.requester_id();
        let unit = match self.find_unit_for_device(device) {
            Some(unit) => unit,
            None => return aliases,
        };

        for entry in &unit.device_entries {
            match entry {
                IvhdDeviceEntry::Alias {
                    devid: entry_devid,
                    alias,
                    ..
                } => {
                    if *entry_devid == devid && *alias != devid {
                        aliases.push(*alias);
                    }
                }
                IvhdDeviceEntry::AliasRange {
                    start, end, alias, ..
                } => {
                    if devid >= *start && devid <= *end && *alias != devid {
                        aliases.push(*alias);
                    }
                }
                _ => {}
            }
        }

        aliases.sort_unstable();
        aliases.dedup();
        aliases
    }

    fn map_ivmd_ranges_for_device(
        &self,
        device: DeviceId,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        let ranges = self.ivmd_ranges_for_device(device);
        if ranges.is_empty() {
            return Ok(());
        }

        let domain = self.domain_for_id(domain_id)?;
        map_ivmd_ranges(domain.as_ref(), &ranges)
    }

    fn reject_excluded_ivmd_range(
        &self,
        device: DeviceId,
        phys_addr: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        if size == 0 {
            return Ok(());
        }
        let end = phys_addr
            .checked_add(size)
            .ok_or(IommuError::InvalidAddress)?;
        for range in self.ivmd_ranges_for_device(device) {
            if !range.exclusion {
                continue;
            }
            if range.range_end <= range.range_start {
                continue;
            }
            if phys_addr < range.range_end && end > range.range_start {
                return Err(IommuError::InvalidAddress);
            }
        }
        Ok(())
    }

    fn device_id_from_devid(segment: u16, devid: u16) -> DeviceId {
        let bus = (devid >> 8) as u8;
        let devfn = (devid & 0xff) as u8;
        let device = (devfn >> 3) & 0x1f;
        let function = devfn & 0x07;
        DeviceId::new(segment, bus, device, function)
    }

    fn invalidate_device_entry_by_devid(&self, segment: u16, devid: u16) -> Result<(), IommuError> {
        let device = Self::device_id_from_devid(segment, devid);
        self.invalidate_device_entry(device)
    }

    fn write_device_entries_for_domain(
        &self,
        device: DeviceId,
        aliases: &[u16],
        domain_id: Option<u16>,
    ) -> Result<(), IommuError> {
        let table = self.device_table_for_segment(device.segment)?;
        let devid = device.requester_id();
        match domain_id {
            Some(domain_id) => {
                let domain = self.domain_for_id(domain_id)?;
                let flags = AmdIommuDriver::ivhd_flags_for_device(self, device);
                let entry = self.build_dte_entry(domain_id, domain.as_ref(), flags)?;
                table.write_entry(devid, entry)?;
                for alias in aliases {
                    table.write_entry(*alias, entry)?;
                }
            }
            None => {
                table.clear_entry(devid)?;
                for alias in aliases {
                    table.clear_entry(*alias)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn domain_id_for_device(&self, device: DeviceId) -> Result<u16, IommuError> {
        let device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        device_domains
            .get(&device)
            .copied()
            .ok_or(IommuError::DomainNotFound)
    }

    fn populate_default_entries(&self) -> Result<(), IommuError> {
        let default_domain = self.domain_for_id(0)?;
        map_ivmd_ranges(default_domain.as_ref(), &self.ivmd_ranges)?;

        for (segment, table) in &self.device_tables {
            let flags = AmdIommuDriver::ivhd_global_flags(self, *segment);
            let domain = self.domain_for_id(0)?;
            let entry = self.build_dte_entry(0, domain.as_ref(), flags)?;
            table.fill(entry)?;
        }

        if let Err(err) = self.invalidate_all_entries() {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        Ok(())
    }

    fn invalidate_all_entries(&self) -> Result<(), IommuError> {
        let mut has_state = false;
        for idx in 0..self.cmd_states.len() {
            if self.cmd_states[idx].is_none() {
                continue;
            }
            has_state = true;
            self.with_cmd_state(idx, |state| {
                state.submit_and_wait(cmd::AmdCommand::invalidate_all())
            })?;
        }

        if !has_state {
            return Err(IommuError::NotSupported);
        }
        Ok(())
    }

    fn find_unit_index_for_device(&self, device: DeviceId) -> Option<usize> {
        let devid = device.requester_id();
        self.units.iter().enumerate().find_map(|(idx, unit)| {
            if unit.segment == device.segment && unit.covers_devid(devid) {
                Some(idx)
            } else {
                None
            }
        })
    }

    fn with_cmd_state<F, R>(&self, unit_idx: usize, f: F) -> Result<R, IommuError>
    where
        F: FnOnce(&mut AmdCommandState) -> Result<R, IommuError>,
    {
        let state = self
            .cmd_states
            .get(unit_idx)
            .and_then(|state| state.as_ref())
            .ok_or(IommuError::NotSupported)?;

        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(IommuError::Poisoned),
        };
        f(&mut *guard)
    }

    async fn submit_cmd_async(
        &self,
        unit_idx: usize,
        cmd: cmd::AmdCommand,
    ) -> Result<(), IommuError> {
        let state = self
            .cmd_states
            .get(unit_idx)
            .and_then(|state| state.as_ref())
            .ok_or(IommuError::NotSupported)?;

        let token = {
            let mut guard = match state.lock() {
                Ok(guard) => guard,
                Err(_) => return Err(IommuError::Poisoned),
            };
            guard.submit_and_wait_token(cmd, true)?
        };

        token.wait_async().await
    }

    fn invalidate_device_entry(&self, device: DeviceId) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_device_entry(devid))
        })
    }

    fn invalidate_iotlb_pages(
        &self,
        device: DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_iotlb_pages(
                devid, 0, iova, size, None,
            ))
        })
    }

    fn invalidate_iommu_pages(
        &self,
        device: DeviceId,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_iommu_pages(
                domain_id, iova, size, None,
            ))
        })
    }

    async fn invalidate_iotlb_pages_async(
        &self,
        device: DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        self.submit_cmd_async(
            unit_idx,
            cmd::AmdCommand::invalidate_iotlb_pages(devid, 0, iova, size, None),
        )
        .await
    }

    async fn invalidate_iommu_pages_async(
        &self,
        device: DeviceId,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        self.submit_cmd_async(
            unit_idx,
            cmd::AmdCommand::invalidate_iommu_pages(domain_id, iova, size, None),
        )
        .await
    }

    fn invalidate_domain_pages(
        &self,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let mut has_state = false;
        for idx in 0..self.cmd_states.len() {
            if self.cmd_states[idx].is_none() {
                continue;
            }
            has_state = true;
            self.with_cmd_state(idx, |state| {
                state.submit_and_wait(cmd::AmdCommand::invalidate_iommu_pages(
                    domain_id, iova, size, None,
                ))
            })?;
        }

        if !has_state {
            return Err(IommuError::NotSupported);
        }
        Ok(())
    }

    fn poll_event_log(&self, unit_idx: usize, unit: &AmdIommuUnit) {
        let log = match self.event_logs.get(unit_idx).and_then(|log| log.as_ref()) {
            Some(log) => log,
            None => return,
        };

        let _guard = match log.try_lock() {
            Some(guard) => guard,
            None => return,
        };

        let mmio_base = phys_to_virt_usize(unit.base_addr);
        let status = mmio_read_u32(mmio_base + MMIO_STATUS_OFFSET as usize);
        let clear_mask = status & (MMIO_STATUS_EVT_INT_MASK | MMIO_STATUS_EVT_OVERFLOW_MASK);
        if clear_mask != 0 {
            mmio_write_u32(mmio_base + MMIO_STATUS_OFFSET as usize, clear_mask);
        }

        if status & MMIO_STATUS_EVT_RUN_MASK == 0 {
            if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
                self.restart_event_log(mmio_base);
                AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::overflow(unit.segment));
            } else {
                self.enable_event_log(mmio_base);
            }
            return;
        }

        let mut head = mmio_read_u32(mmio_base + MMIO_EVT_HEAD_OFFSET as usize);
        let tail = mmio_read_u32(mmio_base + MMIO_EVT_TAIL_OFFSET as usize);
        if head >= EVT_BUFFER_BYTES || tail >= EVT_BUFFER_BYTES {
            return;
        }

        let mut processed = 0usize;
        while head != tail && processed < AMD_FAULT_LOG_RATE_LIMIT {
            if let Some(entry) = log.read_entry(head) {
                if entry.event_type() == 0 {
                    break;
                }
                AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::from_entry(unit.segment, entry));
            }
            head = (head + EVENT_ENTRY_SIZE) % EVT_BUFFER_BYTES;
            mmio_write_u32(mmio_base + MMIO_EVT_HEAD_OFFSET as usize, head);
            processed += 1;
        }

        if status & MMIO_STATUS_EVT_OVERFLOW_MASK != 0 {
            self.restart_event_log(mmio_base);
            AMD_DEFERRED_FAULT_QUEUE.push(AmdFaultEvent::overflow(unit.segment));
        }
    }

    fn restart_event_log(&self, mmio_base: usize) {
        let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
        if (control & CONTROL_EVT_LOG_EN) != 0 {
            control &= !CONTROL_EVT_LOG_EN;
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        mmio_write_u32(
            mmio_base + MMIO_STATUS_OFFSET as usize,
            MMIO_STATUS_EVT_OVERFLOW_MASK,
        );
        control |= CONTROL_EVT_LOG_EN;
        mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
    }

    fn enable_event_log(&self, mmio_base: usize) {
        let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
        if (control & CONTROL_EVT_LOG_EN) == 0 {
            control |= CONTROL_EVT_LOG_EN;
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
    }

    fn program_event_log_interrupt(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        let (addr, data) = msi_message(AMD_IOMMU_FAULT_VECTOR);
        let mmio_base = phys_to_virt_usize(unit.base_addr);
        mmio_write_u32(
            mmio_base + MMIO_MSI_ADDR_LO_OFFSET as usize,
            (addr & 0xffff_ffff) as u32,
        );
        mmio_write_u32(
            mmio_base + MMIO_MSI_ADDR_HI_OFFSET as usize,
            (addr >> 32) as u32,
        );
        mmio_write_u32(mmio_base + MMIO_MSI_DATA_OFFSET as usize, data);
        Ok(())
    }
}

impl AmdIommuUnit {
    fn covers_devid(&self, devid: u16) -> bool {
        self.device_entries.iter().any(|entry| match entry {
            IvhdDeviceEntry::All { .. } => true,
            IvhdDeviceEntry::Select {
                devid: entry_devid, ..
            } => *entry_devid == devid,
            IvhdDeviceEntry::Range { start, end, .. } => devid >= *start && devid <= *end,
            IvhdDeviceEntry::Alias {
                devid: entry_devid,
                alias,
                ..
            } => *entry_devid == devid || *alias == devid,
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => (devid >= *start && devid <= *end) || *alias == devid,
            IvhdDeviceEntry::ExtSelect {
                devid: entry_devid, ..
            } => *entry_devid == devid,
            IvhdDeviceEntry::ExtRange { start, end, .. } => devid >= *start && devid <= *end,
            IvhdDeviceEntry::Special {
                devid: entry_devid, ..
            } => *entry_devid == devid,
            IvhdDeviceEntry::AcpiHid {
                devid: entry_devid, ..
            } => *entry_devid == devid,
        })
    }
}

const AMD_CMD_WAIT_MAX_POLLS: u64 = 1_000_000;

struct AmdCommandWaitToken {
    sync_ptr: NonNull<u64>,
    expected_seq: u64,
}

impl AmdCommandWaitToken {
    fn is_complete(&self) -> bool {
        // Commands complete in order; a newer sequence implies this one finished.
        (unsafe { self.sync_ptr.as_ptr().read_volatile() }) >= self.expected_seq
    }

    fn wait_blocking(self) -> Result<(), IommuError> {
        let mut spins = 0u64;
        while !self.is_complete() {
            spins += 1;
            if spins > AMD_CMD_WAIT_MAX_POLLS {
                return Err(IommuError::Timeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    async fn wait_async(self) -> Result<(), IommuError> {
        #[cfg(test)]
        {
            let _ = self;
            return Ok(());
        }

        #[cfg(not(test))]
        {
            let mut polls = 0u64;
            let token = self;
            poll_fn(|cx| {
                if token.is_complete() {
                    return Poll::Ready(Ok(()));
                }
                polls += 1;
                if polls > AMD_CMD_WAIT_MAX_POLLS {
                    return Poll::Ready(Err(IommuError::Timeout));
                }
                AMD_CMD_WAITERS.register(cx.waker());
                if token.is_complete() {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            })
            .await
        }
    }
}

struct AmdCommandState {
    buffer: cmd::AmdCommandBuffer,
    sync_ptr: NonNull<u64>,
    sync_phys: u64,
    seq: AtomicU64,
}

// SAFETY: `AmdCommandState` contains raw pointers to memory used for command buffer
// completion synchronization (`sync_ptr`). Access to this state is synchronized by
// PoisonLock wrappers when used in `cmd_states`, ensuring safe concurrent access.
unsafe impl Send for AmdCommandState {}
unsafe impl Sync for AmdCommandState {}

impl AmdCommandState {
    fn submit(&mut self, cmd: cmd::AmdCommand) -> Result<(), IommuError> {
        let _ = self.buffer.submit(cmd)?;
        Ok(())
    }

    fn submit_and_wait_token(
        &mut self,
        cmd: cmd::AmdCommand,
        interrupt: bool,
    ) -> Result<AmdCommandWaitToken, IommuError> {
        let next_seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        self.submit(cmd)?;
        self.submit(cmd::AmdCommand::completion_wait(
            self.sync_phys,
            next_seq,
            interrupt,
        ))?;
        Ok(AmdCommandWaitToken {
            sync_ptr: self.sync_ptr,
            expected_seq: next_seq,
        })
    }

    fn submit_and_wait(&mut self, cmd: cmd::AmdCommand) -> Result<(), IommuError> {
        #[cfg(test)]
        {
            self.submit(cmd)?;
            return Ok(());
        }

        #[cfg(not(test))]
        {
            let token = self.submit_and_wait_token(cmd, false)?;
            token.wait_blocking()
        }
    }
}

fn init_command_state(unit: &AmdIommuUnit) -> Result<AmdCommandState, IommuError> {
    let frame_count = cmd::CMD_BUFFER_BYTES / (PAGE_SIZE_4K as usize);
    let phys_base = alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
    let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
    let buffer_ptr = NonNull::new(virt_base.as_u64() as *mut cmd::AmdCommand)
        .ok_or(IommuError::HardwareError)?;

    // Zero the command buffer to satisfy hardware expectations.
    unsafe {
        core::ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, cmd::CMD_BUFFER_BYTES);
    }

    let sync_phys = alloc_contiguous_frames(1).ok_or(IommuError::OutOfMemory)?;
    let sync_virt = phys_to_virt(PhysAddr::new(sync_phys.as_u64()));
    let sync_ptr = NonNull::new(sync_virt.as_u64() as *mut u64).ok_or(IommuError::HardwareError)?;
    unsafe {
        sync_ptr.as_ptr().write_volatile(0);
    }

    let mmio_base = phys_to_virt_usize(unit.base_addr) as u64;
    let buffer = unsafe {
        cmd::AmdCommandBuffer::new(
            mmio_base,
            phys_base.as_u64(),
            buffer_ptr,
            cmd::CMD_BUFFER_ENTRIES,
        )?
    };

    unsafe {
        buffer.program()?;
        buffer.enable();
    }

    let mut state = AmdCommandState {
        buffer,
        sync_ptr,
        sync_phys: sync_phys.as_u64(),
        seq: AtomicU64::new(0),
    };

    if let Err(err) = state.submit_and_wait(cmd::AmdCommand::invalidate_all()) {
        log::warn!(
            "AMD-Vi command buffer invalidate_all failed for unit @ {:#x}: {:?}",
            unit.base_addr,
            err
        );
    }

    Ok(state)
}

fn init_command_states(units: &[AmdIommuUnit]) -> Vec<Option<PoisonLock<AmdCommandState>>> {
    let mut states = Vec::with_capacity(units.len());
    for unit in units {
        match init_command_state(unit) {
            Ok(state) => {
                log::info!(
                    "AMD-Vi command buffer enabled for unit @ {:#x}",
                    unit.base_addr
                );
                states.push(Some(PoisonLock::new(state)));
            }
            Err(err) => {
                log::warn!(
                    "AMD-Vi command buffer init failed for unit @ {:#x}: {:?}",
                    unit.base_addr,
                    err
                );
                states.push(None);
            }
        }
    }
    states
}

fn init_event_logs(units: &[AmdIommuUnit]) -> Vec<Option<AmdEventLog>> {
    let mut logs = Vec::with_capacity(units.len());
    for unit in units {
        match AmdEventLog::new() {
            Ok(log) => {
                if let Err(err) = log.program(unit) {
                    log::warn!(
                        "AMD-Vi event log program failed for unit @ {:#x}: {:?}",
                        unit.base_addr,
                        err
                    );
                    logs.push(None);
                } else {
                    logs.push(Some(log));
                }
            }
            Err(err) => {
                log::warn!(
                    "AMD-Vi event log alloc failed for unit @ {:#x}: {:?}",
                    unit.base_addr,
                    err
                );
                logs.push(None);
            }
        }
    }
    logs
}

fn max_devid_for_entries(entries: &[IvhdDeviceEntry]) -> u16 {
    let mut max = 0;
    for entry in entries {
        let entry_max = match entry {
            IvhdDeviceEntry::All { .. } => return u16::MAX,
            IvhdDeviceEntry::Select { devid, .. } => *devid,
            IvhdDeviceEntry::Range { start, end, .. } => (*start).max(*end),
            IvhdDeviceEntry::Alias { devid, alias, .. } => (*devid).max(*alias),
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => (*start).max(*end).max(*alias),
            IvhdDeviceEntry::ExtSelect { devid, .. } => *devid,
            IvhdDeviceEntry::ExtRange { start, end, .. } => (*start).max(*end),
            IvhdDeviceEntry::Special { devid, .. } => *devid,
            IvhdDeviceEntry::AcpiHid { devid, .. } => *devid,
        };

        if entry_max > max {
            max = entry_max;
        }
    }
    max
}

fn init_device_tables(units: &[AmdIommuUnit]) -> Result<HashMap<u16, AmdDeviceTable>, IommuError> {
    let mut max_by_segment = HashMap::<u16, u16>::new();
    for unit in units {
        let max_devid = max_devid_for_entries(&unit.device_entries);
        max_by_segment
            .entry(unit.segment)
            .and_modify(|current| {
                if max_devid > *current {
                    *current = max_devid;
                }
            })
            .or_insert(max_devid);
    }

    let mut tables = HashMap::new();
    for (segment, max_devid) in max_by_segment {
        let entry_count = (max_devid as usize).saturating_add(1);
        let table = AmdDeviceTable::new(segment, entry_count)?;
        tables.insert(segment, table);
    }
    Ok(tables)
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn map_ivmd_ranges(domain: &DomainState, ranges: &[AmdIvmdRange]) -> Result<(), IommuError> {
    let page_size = PAGE_SIZE_4K;
    let mut exclusions = Vec::new();

    for range in ranges {
        if !range.exclusion {
            continue;
        }

        let start = align_down(range.range_start, page_size);
        let end = align_up(range.range_end, page_size);
        if end <= start {
            continue;
        }
        exclusions.push((start, end));
    }

    for range in ranges {
        if !range.unity_map || range.exclusion {
            continue;
        }

        let start = align_down(range.range_start, page_size);
        let end = align_up(range.range_end, page_size);
        if end <= start {
            continue;
        }

        let mut segments = alloc::vec![(start, end)];
        if !exclusions.is_empty() {
            for (ex_start, ex_end) in &exclusions {
                let mut next = Vec::new();
                for (seg_start, seg_end) in segments {
                    if *ex_end <= seg_start || *ex_start >= seg_end {
                        next.push((seg_start, seg_end));
                        continue;
                    }
                    if *ex_start > seg_start {
                        next.push((seg_start, *ex_start));
                    }
                    if *ex_end < seg_end {
                        next.push((*ex_end, seg_end));
                    }
                }
                segments = next;
                if segments.is_empty() {
                    break;
                }
            }
        }

        for (seg_start, seg_end) in segments {
            if seg_end <= seg_start {
                continue;
            }
            let size = seg_end - seg_start;
            match domain.map(seg_start, seg_start, size, range.read, range.write) {
                Ok(()) => {}
                Err(IommuError::AlreadyMapped) => {}
                Err(err) => return Err(err),
            }
        }
    }

    Ok(())
}

impl AmdIommuDriver {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(crate) fn enable(&self) -> Result<(), IommuError> {
        for (idx, unit) in self.units.iter().enumerate() {
            let table = self
                .device_tables
                .get(&unit.segment)
                .ok_or(IommuError::NotPresent)?;
            table.program(unit)?;

            let mmio_base = phys_to_virt_usize(unit.base_addr);
            let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
            control |= CONTROL_IOMMU_EN;
            if self
                .cmd_states
                .get(idx)
                .and_then(|state| state.as_ref())
                .is_some()
            {
                control |= CONTROL_CMDBUF_EN;
            } else {
                control &= !CONTROL_CMDBUF_EN;
            }
            if self
                .event_logs
                .get(idx)
                .and_then(|log| log.as_ref())
                .is_some()
            {
                if let Err(err) = self.program_event_log_interrupt(unit) {
                    log::warn!(
                        "AMD-Vi event log interrupt init failed for unit @ {:#x}: {:?}",
                        unit.base_addr,
                        err
                    );
                    control &= !CONTROL_EVT_INT_EN;
                } else {
                    control |= CONTROL_EVT_INT_EN;
                }
                control |= CONTROL_EVT_LOG_EN;
            } else {
                control &= !CONTROL_EVT_LOG_EN;
                control &= !CONTROL_EVT_INT_EN;
            }
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn disable(&self) -> Result<(), IommuError> {
        for unit in &self.units {
            let mmio_base = phys_to_virt_usize(unit.base_addr);
            let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
            control &=
                !(CONTROL_IOMMU_EN | CONTROL_CMDBUF_EN | CONTROL_EVT_LOG_EN | CONTROL_EVT_INT_EN);
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    pub(crate) fn handle_fault(&self) {
        for (idx, unit) in self.units.iter().enumerate() {
            self.poll_event_log(idx, unit);
        }
        AMD_FAULT_WAKERS.wake_all_from_isr();
    }

    pub(crate) fn wake_invalidation_waiters(&self) {
        AMD_CMD_WAITERS.wake_all_from_isr();
    }

    pub(crate) fn map_interrupt(
        &self,
        _segment: u16,
        _bus: u8,
        _device: u8,
        _function: u8,
        _vector: u8,
        _dest_id: u32,
        _logical: bool,
    ) -> Result<u16, IommuError> {
        Err(IommuError::NotSupported)
    }

    pub(crate) fn get_remap_msi_message(&self, _handle: u16) -> (u64, u32) {
        (0, 0)
    }

    /// Allocate an IOVA address
    ///
    /// The IovaAllocatorFast is lock-free internally with per-CPU magazine caching.
    fn allocate_iova(&self, size: u64, mask: Option<u64>) -> Result<u64, IommuError> {
        let iova = match mask {
            Some(limit) => self.iova_allocator.allocate_with_limit(size, IovaGranularity::Page4K, limit),
            None => self.iova_allocator.allocate(size, IovaGranularity::Page4K),
        };
        iova.ok_or(IommuError::OutOfMemory)
    }

    /// Fast path IOVA allocation (4KB pages)
    ///
    /// IovaAllocatorFast already provides O(1) allocation with per-CPU magazine,
    /// so this just delegates to allocate_iova.
    fn allocate_iova_fast(&self, size: u64, mask: Option<u64>) -> Result<u64, IommuError> {
        self.allocate_iova(size, mask)
    }

    /// Free an IOVA address
    fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.iova_allocator.free(iova, size)
    }

    /// Fast path IOVA free (4KB pages)
    ///
    /// IovaAllocatorFast already provides O(1) free with per-CPU magazine,
    /// so this just delegates to free_iova.
    fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.free_iova(iova, size)
    }

    pub(crate) unsafe fn map_for_dma(
        &self,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_dma_with_perms(phys_addr, size, true, true) }
    }

    pub(crate) unsafe fn map_for_dma_with_perms(
        &self,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        let iova = self.allocate_iova_fast(size, None)?;
        let domain = self.domain_for_id(0)?;
        if let Err(err) = domain.map(iova, phys_addr.as_u64(), size, read, write) {
            let _ = self.free_iova_fast(iova, size);
            return Err(err);
        }
        if let Err(err) = self.invalidate_domain_pages(0, iova, size) {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        Ok(iova)
    }

    pub(crate) fn unmap_dma(&self, iova: u64, _size: u64) -> Result<(), IommuError> {
        let domain = self.domain_for_id(0)?;
        let mapping = domain.unmap(iova)?;
        let mapped_size = mapping.size;
        if let Err(err) = self.invalidate_domain_pages(0, iova, mapped_size) {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        let _ = self.free_iova_fast(iova, mapped_size);
        Ok(())
    }

    pub(crate) unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_device_with_perms(device, phys_addr, size, true, true) }
    }

    pub(crate) unsafe fn map_for_device_with_perms(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        let domain_id = self.domain_id_for_device(*device)?;
        self.reject_excluded_ivmd_range(*device, phys_addr.as_u64(), size)?;
        let mask = crate::io::iommu::api::get_device_dma_mask(device);
        let iova = self.allocate_iova_fast(size, mask)?;
        if let Some(ref cq) = self.command_queue {
            let cmd = IommuCommandKind::MapRegionDevice {
                device: *device,
                iova,
                phys: phys_addr.as_u64(),
                size,
                read,
                write,
            };
            let comp = match cq.submit(cmd) {
                Ok(comp) => comp,
                Err(_) => {
                    let _ = self.free_iova_fast(iova, size);
                    return Err(IommuError::HardwareError);
                }
            };
            let rc = comp.wait_blocking();
            if rc == 0 {
                return Ok(iova);
            }
            return Err(IommuError::HardwareError);
        }

        let domain = self.domain_for_id(domain_id)?;

        if let Err(err) = domain.map(iova, phys_addr.as_u64(), size, read, write) {
            let _ = self.free_iova_fast(iova, size);
            return Err(err);
        }

        self.invalidate_iommu_pages(*device, domain_id, iova, size)?;
        self.invalidate_iotlb_pages(*device, iova, size)?;
        Ok(iova)
    }

    pub(crate) async unsafe fn map_for_device_with_perms_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        let domain_id = self.domain_id_for_device(*device)?;
        self.reject_excluded_ivmd_range(*device, phys_addr.as_u64(), size)?;
        let mask = crate::io::iommu::api::get_device_dma_mask(device);
        let iova = self.allocate_iova_fast(size, mask)?;
        if let Some(ref cq) = self.command_queue {
            let cmd = IommuCommandKind::MapRegionDevice {
                device: *device,
                iova,
                phys: phys_addr.as_u64(),
                size,
                read,
                write,
            };
            let comp = match cq.submit_async(cmd).await {
                Ok(comp) => comp,
                Err(_) => {
                    let _ = self.free_iova_fast(iova, size);
                    return Err(IommuError::HardwareError);
                }
            };
            let rc = comp.await;
            if rc == 0 {
                return Ok(iova);
            }
            return Err(IommuError::HardwareError);
        }

        let domain = self.domain_for_id(domain_id)?;

        if let Err(err) = domain.map(iova, phys_addr.as_u64(), size, read, write) {
            let _ = self.free_iova_fast(iova, size);
            return Err(err);
        }

        self.invalidate_iommu_pages_async(*device, domain_id, iova, size)
            .await?;
        self.invalidate_iotlb_pages_async(*device, iova, size).await?;
        Ok(iova)
    }

    pub(crate) async unsafe fn map_for_device_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_device_with_perms_async(device, phys_addr, size, true, true).await }
    }

    pub(crate) fn unmap_for_device(
        &self,
        device: &DeviceId,
        iova: u64,
        _size: u64,
    ) -> Result<(), IommuError> {
        let domain_id = self.domain_id_for_device(*device)?;
        let domain = self.domain_for_id(domain_id)?;
        if let Some(ref cq) = self.command_queue {
            let mapping = domain.mapping(iova).ok_or(IommuError::NotMapped)?;
            let cmd = IommuCommandKind::UnmapRegionDevice {
                device: *device,
                iova,
                size: mapping.size,
            };
            let comp = cq
                .submit(cmd)
                .map_err(|_| IommuError::HardwareError)?;
            let rc = comp.wait_blocking();
            if rc == 0 {
                return Ok(());
            }
            return Err(IommuError::HardwareError);
        }
        let mapping = domain.unmap(iova)?;

        self.invalidate_iommu_pages(*device, domain_id, iova, mapping.size)?;
        self.invalidate_iotlb_pages(*device, iova, mapping.size)?;
        let _ = self.free_iova_fast(iova, mapping.size);
        Ok(())
    }

    pub(crate) async fn unmap_for_device_async(
        &self,
        device: &DeviceId,
        iova: u64,
        _size: u64,
    ) -> Result<(), IommuError> {
        let domain_id = self.domain_id_for_device(*device)?;
        let domain = self.domain_for_id(domain_id)?;
        if let Some(ref cq) = self.command_queue {
            let mapping = domain.mapping(iova).ok_or(IommuError::NotMapped)?;
            let cmd = IommuCommandKind::UnmapRegionDevice {
                device: *device,
                iova,
                size: mapping.size,
            };
            let comp = cq
                .submit_async(cmd)
                .await
                .map_err(|_| IommuError::HardwareError)?;
            let rc = comp.await;
            if rc == 0 {
                return Ok(());
            }
            return Err(IommuError::HardwareError);
        }
        let mapping = domain.unmap(iova)?;

        self.invalidate_iommu_pages_async(*device, domain_id, iova, mapping.size)
            .await?;
        self.invalidate_iotlb_pages_async(*device, iova, mapping.size)
            .await?;
        let _ = self.free_iova_fast(iova, mapping.size);
        Ok(())
    }

    fn handle_command_queue_entry(&self, kind: &IommuCommandKind) -> Result<i32, ()> {
        match kind {
            IommuCommandKind::MapRegionDevice {
                device,
                iova,
                phys,
                size,
                read,
                write,
            } => {
                let size = *size;
                if size == 0 {
                    return Err(());
                }
                let align = crate::mm::PAGE_SIZE_4K as u64;
                if (iova & (align - 1) != 0)
                    || (phys & (align - 1) != 0)
                    || (size & (align - 1) != 0)
                {
                    let _ = self.free_iova_fast(*iova, size);
                    return Err(());
                }

                if self
                    .reject_excluded_ivmd_range(*device, *phys, size)
                    .is_err()
                {
                    let _ = self.free_iova_fast(*iova, size);
                    return Err(());
                }

                let domain_id = match self.domain_id_for_device(*device) {
                    Ok(domain_id) => domain_id,
                    Err(_) => {
                        let _ = self.free_iova_fast(*iova, size);
                        return Err(());
                    }
                };

                let domain = match self.domain_for_id(domain_id) {
                    Ok(domain) => domain,
                    Err(_) => {
                        let _ = self.free_iova_fast(*iova, size);
                        return Err(());
                    }
                };

                match domain.map(*iova, *phys, size, *read, *write) {
                    Ok(()) => {}
                    Err(err) => {
                        if err != IommuError::AlreadyMapped && err != IommuError::Poisoned {
                            let _ = self.free_iova_fast(*iova, size);
                        }
                        return Err(());
                    }
                }

                if self
                    .invalidate_iommu_pages(*device, domain_id, *iova, size)
                    .is_err()
                {
                    return Err(());
                }
                if self.invalidate_iotlb_pages(*device, *iova, size).is_err() {
                    return Err(());
                }

                Ok(0)
            }
            IommuCommandKind::UnmapRegionDevice { device, iova, size: _ } => {
                let domain_id = match self.domain_id_for_device(*device) {
                    Ok(domain_id) => domain_id,
                    Err(_) => return Err(()),
                };
                let domain = match self.domain_for_id(domain_id) {
                    Ok(domain) => domain,
                    Err(_) => return Err(()),
                };
                let mapping = match domain.unmap(*iova) {
                    Ok(mapping) => mapping,
                    Err(_) => return Err(()),
                };

                if self
                    .invalidate_iommu_pages(*device, domain_id, *iova, mapping.size)
                    .is_err()
                {
                    return Err(());
                }
                if self
                    .invalidate_iotlb_pages(*device, *iova, mapping.size)
                    .is_err()
                {
                    return Err(());
                }
                let _ = self.free_iova_fast(*iova, mapping.size);
                Ok(0)
            }
            IommuCommandKind::InvalidateIotlbGlobal => {
                if self.invalidate_all_entries().is_ok() {
                    Ok(0)
                } else {
                    Err(())
                }
            }
            IommuCommandKind::InvalidateIotlbDomain { .. } => Err(()),
            IommuCommandKind::MapRegion { .. } => Err(()),
            IommuCommandKind::UnmapRegion { .. } => Err(()),
        }
    }

    pub(crate) fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let raw_id = self.next_domain_id.fetch_add(1, Ordering::Relaxed);
        if raw_id > u16::MAX as u64 {
            return Err(IommuError::OutOfMemory);
        }
        let domain_id = raw_id as u16;
        let domain = DomainState::new(
            domain_id,
            numa_node,
            false,
            false,
            AMD_DEFAULT_MAX_ADDR_BITS,
            domain_type,
            self.page_table_pool.clone(),
            PteFormat::Amd,
        );
        let domain = Arc::new(domain);
        if let Some(notifier) = self.security_notifier.get() {
            let _ = domain.set_security_notifier(Arc::clone(notifier));
        }
        let info = AmdDomainInfo { domain };

        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        if domains.insert(domain_id, info).is_some() {
            return Err(IommuError::HardwareError);
        }
        Ok(domain_id)
    }

    pub(crate) fn attach_device(
        &self,
        device: DeviceId,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }
        let _domain = self.domain_for_id(domain_id)?;
        let aliases = self.alias_devids_for_device(device);

        let existing = {
            let device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            if let Some(existing) = device_domains.get(&device) {
                Some(*existing)
            } else {
                None
            }
        };

        if existing == Some(domain_id) {
            self.map_ivmd_ranges_for_device(device, domain_id)?;
            return Ok(());
        }

        self.map_ivmd_ranges_for_device(device, domain_id)?;

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, domain_id)
        };

        if let Err(err) = self.write_device_entries_for_domain(device, &aliases, Some(domain_id)) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            match previous {
                Some(prev_id) => {
                    device_domains.insert(device, prev_id);
                    let _ = self.write_device_entries_for_domain(device, &aliases, Some(prev_id));
                }
                None => {
                    device_domains.remove(&device);
                    let _ = self.write_device_entries_for_domain(device, &aliases, None);
                }
            }
            return Err(err);
        }

        if let Err(err) = self.invalidate_device_entry(device) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            match previous {
                Some(prev_id) => {
                    device_domains.insert(device, prev_id);
                    let _ = self.write_device_entries_for_domain(device, &aliases, Some(prev_id));
                }
                None => {
                    device_domains.remove(&device);
                    let _ = self.write_device_entries_for_domain(device, &aliases, None);
                }
            }
            return Err(err);
        }

        for alias in &aliases {
            if let Err(err) = self.invalidate_device_entry_by_devid(device.segment, *alias) {
                let mut device_domains = self
                    .device_domains
                    .lock()
                    .map_err(|_| IommuError::Poisoned)?;
                match previous {
                    Some(prev_id) => {
                        device_domains.insert(device, prev_id);
                        let _ =
                            self.write_device_entries_for_domain(device, &aliases, Some(prev_id));
                    }
                    None => {
                        device_domains.remove(&device);
                        let _ = self.write_device_entries_for_domain(device, &aliases, None);
                    }
                }
                return Err(err);
            }
        }

        Ok(())
    }

    pub(crate) fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }
        let aliases = self.alias_devids_for_device(device);

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.remove(&device)
        };

        let previous_domain = previous.ok_or(IommuError::DeviceNotFound)?;

        if let Err(err) = self.write_device_entries_for_domain(device, &aliases, None) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, previous_domain);
            let _ = self.write_device_entries_for_domain(device, &aliases, Some(previous_domain));
            return Err(err);
        }

        if let Err(err) = self.invalidate_device_entry(device) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, previous_domain);
            let _ = self.write_device_entries_for_domain(device, &aliases, Some(previous_domain));
            return Err(err);
        }

        for alias in &aliases {
            if let Err(err) = self.invalidate_device_entry_by_devid(device.segment, *alias) {
                let mut device_domains = self
                    .device_domains
                    .lock()
                    .map_err(|_| IommuError::Poisoned)?;
                device_domains.insert(device, previous_domain);
                let _ =
                    self.write_device_entries_for_domain(device, &aliases, Some(previous_domain));
                return Err(err);
            }
        }

        Ok(())
    }

    pub(crate) fn set_domain_numa(
        &self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        domain.set_numa_node(numa_node);
        Ok(())
    }

    /// Get domain by ID
    pub(crate) fn get_domain(&self, domain_id: u16) -> Result<Arc<DomainState>, IommuError> {
        self.domain_for_id(domain_id)
    }

    pub(crate) fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        Ok(domain.numa_node())
    }

    pub(crate) fn dump_diagnostics(&self) {
        let unit_count = self.units.len();
        let cmd_ready = self.cmd_states.iter().filter(|state| state.is_some()).count();
        let evt_ready = self.event_logs.iter().filter(|log| log.is_some()).count();

        log::info!(
            "[IOMMU][AMD-Vi] units={} cmd_buffers={} event_logs={} enabled={}",
            unit_count,
            cmd_ready,
            evt_ready,
            self.is_enabled()
        );

        match self.domains.lock() {
            Ok(domains) => {
                log::info!("[IOMMU][AMD-Vi] domains={}", domains.len());
            }
            Err(_) => {
                log::warn!("[IOMMU][AMD-Vi] domains lock poisoned");
            }
        }

        match self.device_domains.lock() {
            Ok(device_domains) => {
                log::info!("[IOMMU][AMD-Vi] device_mappings={}", device_domains.len());
            }
            Err(_) => {
                log::warn!("[IOMMU][AMD-Vi] device_domains lock poisoned");
            }
        }

        if let Some(cq) = self.command_queue.as_ref() {
            log::info!(
                "[IOMMU][AMD-Vi] CQ: processed={} cancelled={} cancel_attempts={} reclaimed={} backpressure={}",
                cq.processed_total(),
                cq.cancelled_total(),
                cq.cancel_attempts_total(),
                cq.reclaimed_total(),
                cq.send_backpressure_total()
            );
        } else {
            log::info!("[IOMMU][AMD-Vi] CQ: not initialized");
        }
    }

    // ========================================================================
    // Flush Operations (for emergency isolation)
    // ========================================================================

    /// Invalidate IOTLB entries for a specific domain.
    pub(crate) fn invalidate_iotlb(
        &self,
        domain_id: u16,
        _iova: Option<u64>,
    ) -> Result<(), IommuError> {
        // AMD-Vi uses INVALIDATE_IOMMU_PAGES command
        // For emergency isolation, we invalidate all pages in the domain
        self.invalidate_domain_all(domain_id)
    }

    /// Invalidate all IOTLB entries globally.
    pub(crate) fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        // Invalidate all domains - AMD-Vi doesn't have a single global invalidation
        // so we iterate through known domains
        let domain_ids: Vec<u16> = match self.domains.lock() {
            Ok(domains) => domains.keys().cloned().collect(),
            Err(_) => return Err(IommuError::Poisoned),
        };

        for domain_id in domain_ids {
            let _ = self.invalidate_domain_all(domain_id);
        }

        Ok(())
    }

    /// Invalidate context cache globally.
    pub(crate) fn invalidate_context_global(&self) -> Result<(), IommuError> {
        // AMD-Vi uses device table entries; invalidation is done via
        // INVALIDATE_DEVTAB_ENTRY command
        // For global invalidation, we flush all known devices
        self.invalidate_all_device_entries()
    }

    /// Lookup the domain ID for a device.
    pub(crate) fn lookup_device_domain(&self, source_id: u16) -> Option<u16> {
        let device_id = DeviceId::from_bdf(source_id);
        match self.device_domains.lock() {
            Ok(device_domains) => device_domains.get(&device_id).copied(),
            Err(_) => None,
        }
    }

    /// Invalidate all pages in a domain.
    fn invalidate_domain_all(&self, domain_id: u16) -> Result<(), IommuError> {
        use crate::io::iommu::amd::cmd::AmdCommand;

        for (idx, _unit) in self.units.iter().enumerate() {
            if let Some(cmd_state) = self.cmd_states.get(idx).and_then(|s| s.as_ref()) {
                // Use invalidate_iommu_pages with size = u64::MAX to invalidate all pages
                // domain_id: target domain
                // address: 0 (start from beginning)
                // size: u64::MAX (entire address space)
                // pasid: None (no PASID)
                let cmd = AmdCommand::invalidate_iommu_pages(
                    domain_id,
                    0,         // address
                    u64::MAX,  // size = all pages
                    None,      // pasid
                );
                if let Ok(mut state) = cmd_state.lock() {
                    let _ = state.submit_and_wait(cmd);
                }
            }
        }
        Ok(())
    }

    /// Invalidate all device table entries.
    fn invalidate_all_device_entries(&self) -> Result<(), IommuError> {
        use crate::io::iommu::amd::cmd::AmdCommand;

        let device_ids: Vec<u16> = match self.device_domains.lock() {
            Ok(device_domains) => device_domains.keys().map(|d| d.bdf()).collect(),
            Err(_) => return Err(IommuError::Poisoned),
        };

        for (idx, _unit) in self.units.iter().enumerate() {
            if let Some(cmd_state) = self.cmd_states.get(idx).and_then(|s| s.as_ref()) {
                if let Ok(mut state) = cmd_state.lock() {
                    for devid in &device_ids {
                        let cmd = AmdCommand::invalidate_device_entry(*devid);
                        let _ = state.submit(cmd);
                    }
                    // Submit a completion wait to flush all pending commands
                    let completion = AmdCommand::completion_wait(
                        state.sync_phys,
                        state.seq.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1,
                        false,
                    );
                    let _ = state.submit(completion);
                }
            }
        }
        Ok(())
    }
}

impl super::interface::IommuHardwareContext for AmdIommuDriver {
    fn allocate_iova_aligned(&self, _size: u64, _alignment: u64) -> Result<u64, IommuError> {
        // AMD-Vi uses identity mapping (iova = phys_addr), so allocation is a no-op.
        // For non-identity scenarios, integrate with IovaAllocator.
        Err(IommuError::NotSupported)
    }

    fn allocate_iova_masked(
        &self,
        _size: u64,
        _alignment: u64,
        _mask: u64,
    ) -> Result<u64, IommuError> {
        // AMD-Vi uses identity mapping; masked allocation not supported.
        Err(IommuError::NotSupported)
    }

    fn free_iova(&self, _iova: u64, _size: u64) -> Result<(), IommuError> {
        // No-op for identity mapping
        Ok(())
    }
}

/// Initialize AMD-Vi using ACPI IVRS table at `ivrs_addr`.

pub unsafe fn init_iommu_from_ivrs(
    ivrs_addr: usize,
    config: IommuConfig,
) -> Result<(), IommuError> {
    if !config.enabled {
        log::info!("IOMMU disabled by kernel configuration");
        return Err(IommuError::NotPresent);
    }

    let ivrs_info = match unsafe { crate::io::acpi::ivrs::parse_ivrs(ivrs_addr) } {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to parse IVRS: {}", e);
            return Err(IommuError::HardwareError);
        }
    };

    let mut units = Vec::new();
    for ivhd in ivrs_info.ivhds {
        units.push(AmdIommuUnit {
            segment: ivhd.pci_segment,
            base_addr: ivhd.iommu_base,
            flags: ivhd.flags,
            device_id: ivhd.device_id,
            iommu_info: ivhd.iommu_info,
            iommu_feature: ivhd.iommu_feature,
            device_entries: ivhd.device_entries,
        });
    }

    if units.is_empty() {
        return Err(IommuError::NotPresent);
    }

    let mut ivmd_ranges = Vec::new();
    for ivmd in ivrs_info.ivmds {
        if let Some(range) = AmdIvmdRange::from_ivmd(ivmd) {
            ivmd_ranges.push(range);
        }
    }

    let cmd_states = init_command_states(&units);
    let cmd_ready = cmd_states.iter().filter(|buf| buf.is_some()).count();
    let event_logs = init_event_logs(&units);
    let evt_ready = event_logs.iter().filter(|log| log.is_some()).count();

    let device_tables = init_device_tables(&units)?;
    for unit in &units {
        let table = device_tables
            .get(&unit.segment)
            .ok_or(IommuError::NotPresent)?;
        table.program(unit)?;
    }

    let unit_count = units.len();
    let ivmd_count = ivmd_ranges.len();
    let table_count = device_tables.len();
    AmdIommuDriver::register_driver(units, ivmd_ranges, cmd_states, event_logs, device_tables)?;
    #[cfg(not(test))]
    spawn_command_queue_worker();
    crate::io::iommu::api::set_global_dma_mapping_allowed(config.allow_global_mappings);
    log::info!(
        "AMD-Vi IVRS parsed ({} unit(s), {} IVMD range(s), {} cmd buffer(s) ready, {} event log(s) ready, {} device table(s))",
        unit_count,
        ivmd_count,
        cmd_ready,
        evt_ready,
        table_count
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_driver(entries: Vec<IvhdDeviceEntry>) -> AmdIommuDriver {
        let unit = AmdIommuUnit {
            segment: 0,
            base_addr: 0,
            flags: 0,
            device_id: 0,
            iommu_info: 0,
            iommu_feature: 0,
            device_entries: entries,
        };

        AmdIommuDriver {
            units: alloc::vec![unit],
            ivmd_ranges: Vec::new(),
            cmd_states: Vec::new(),
            event_logs: Vec::new(),
            device_tables: HashMap::new(),
            domains: PoisonLock::new(HashMap::new()),
            device_domains: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(1),
            page_table_pool: PageTablePool::new(1, 1),
            command_queue: None,
            iova_allocator: PoisonLock::new(IovaAllocator::new(
                crate::io::iommu::iova_allocator::PAGE_SIZE_4K,
                (1u64 << AMD_DEFAULT_MAX_ADDR_BITS)
                    .saturating_sub(crate::io::iommu::iova_allocator::PAGE_SIZE_4K),
            )),
            enabled: AtomicBool::new(false),
            security_notifier: spin::Once::new(),
        }
    }

    #[test]
    fn test_alias_devids_for_device_dedup() {
        let device = DeviceId::new(0, 1, 0, 0);
        let devid = device.requester_id();
        let driver = make_driver(alloc::vec![
            IvhdDeviceEntry::Select { devid, flags: 0 },
            IvhdDeviceEntry::Alias {
                devid,
                alias: 0x0200,
                flags: 0,
            },
            IvhdDeviceEntry::AliasRange {
                start: devid,
                end: devid + 3,
                alias: 0x0300,
                flags: 0,
            },
            IvhdDeviceEntry::Alias {
                devid,
                alias: 0x0200,
                flags: 0,
            },
            IvhdDeviceEntry::Alias {
                devid,
                alias: devid,
                flags: 0,
            },
        ]);

        let aliases = driver.alias_devids_for_device(device);
        assert_eq!(aliases, alloc::vec![0x0200, 0x0300]);
    }

    #[test]
    fn test_alias_devids_for_device_no_match() {
        let driver = make_driver(alloc::vec![IvhdDeviceEntry::Select {
            devid: 0x0100,
            flags: 0,
        }]);
        let device = DeviceId::new(0, 2, 0, 0);
        let aliases = driver.alias_devids_for_device(device);
        assert!(aliases.is_empty());
    }

    #[test]
    fn test_ivhd_flags_for_device_combined() {
        let device = DeviceId::new(0, 2, 0, 0);
        let devid = device.requester_id();
        let driver = make_driver(alloc::vec![
            IvhdDeviceEntry::All { flags: 0x01 },
            IvhdDeviceEntry::Select { devid, flags: 0x02 },
            IvhdDeviceEntry::Range {
                start: devid,
                end: devid + 0x0f,
                flags: 0x04,
            },
            IvhdDeviceEntry::Alias {
                devid: 0x0100,
                alias: devid,
                flags: 0x08,
            },
            IvhdDeviceEntry::AliasRange {
                start: 0x0300,
                end: 0x030f,
                alias: devid,
                flags: 0x10,
            },
            IvhdDeviceEntry::ExtSelect {
                devid,
                flags: 0x20,
                ext_flags: 0,
            },
            IvhdDeviceEntry::ExtRange {
                start: devid,
                end: devid,
                flags: 0x40,
                ext_flags: 0,
            },
            IvhdDeviceEntry::Special {
                devid,
                flags: 0x80,
                handle: 0,
                variety: 0,
            },
        ]);

        let flags = driver.ivhd_flags_for_device(device);
        assert_eq!(flags, 0xff);
    }

    #[test]
    fn test_ivhd_flags_for_device_acpi_hid() {
        let device = DeviceId::new(0, 2, 0, 0);
        let devid = device.requester_id();
        let driver = make_driver(alloc::vec![IvhdDeviceEntry::AcpiHid { devid, flags: 0x03 }]);

        let flags = driver.ivhd_flags_for_device(device);
        assert_eq!(flags, 0x03);
    }

    #[test]
    fn test_map_ivmd_ranges_exclusion_splits() {
        let pool = PageTablePool::new(1, 1);
        let mut domain = DomainState::new(
            0,
            None,
            false,
            false,
            AMD_DEFAULT_MAX_ADDR_BITS,
            IommuDomainType::Translated,
            pool,
            PteFormat::Amd,
        );

        let ranges = alloc::vec![
            AmdIvmdRange {
                segment: 0,
                devid_start: 0,
                devid_end: u16::MAX,
                range_start: 0x1000,
                range_end: 0x5000,
                unity_map: true,
                read: true,
                write: true,
                exclusion: false,
            },
            AmdIvmdRange {
                segment: 0,
                devid_start: 0,
                devid_end: u16::MAX,
                range_start: 0x2000,
                range_end: 0x3000,
                unity_map: false,
                read: true,
                write: true,
                exclusion: true,
            },
        ];

        map_ivmd_ranges(&domain, &ranges).expect("map ivmd ranges");

        let mappings = domain.mappings_snapshot();
        assert!(mappings.contains_key(&0x1000));
        assert!(mappings.contains_key(&0x3000));
        assert!(!mappings.contains_key(&0x2000));
        assert_eq!(mappings.len(), 2);
    }

    #[test]
    fn test_map_for_device_rejects_exclusion_range() {
        let device = DeviceId::new(0, 0, 1, 0);
        let devid = device.requester_id();
        let mut driver = make_driver(Vec::new());
        driver.ivmd_ranges = alloc::vec![AmdIvmdRange {
            segment: device.segment,
            devid_start: devid,
            devid_end: devid,
            range_start: 0x2000,
            range_end: 0x3000,
            unity_map: false,
            read: true,
            write: true,
            exclusion: true,
        }];

        let domain_id = 1u16;
        let domain = DomainState::new(
            domain_id,
            None,
            false,
            false,
            AMD_DEFAULT_MAX_ADDR_BITS,
            IommuDomainType::Translated,
            driver.page_table_pool.clone(),
            PteFormat::Amd,
        );
        let domain = alloc::sync::Arc::new(domain);
        {
            let mut domains = match driver.domains.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            domains.insert(domain_id, AmdDomainInfo { domain });
        }

        {
            let mut device_domains = match driver.device_domains.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            device_domains.insert(device, domain_id);
        }

        let result =
            unsafe { driver.map_for_device(&device, PhysAddr::new(0x2000), 0x1000) };
        assert_eq!(result, Err(IommuError::InvalidAddress));
    }
}
