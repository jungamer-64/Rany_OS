// ============================================================================
// src/io/nvme.rs - NVMe Driver Implementation
// ============================================================================
//!
//! NVMe (Non-Volatile Memory Express) ドライバ
//!
//! ## 設計原則 (仕様書 6.3準拠)
//! - Per-Core Submission/Completion Queue pairs
//! - ポーリングモードによる低レイテンシ
//! - MSI-X割り込みサポート
//! - 非同期ブロックデバイスAPI
//!
//! ## NVMe仕様
//! - Admin Queue: デバイス管理コマンド
//! - I/O Queues: データ転送 (per-CPU)
//! - Doorbell registers: キュー通知

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

// ============================================================================
// NVMe Constants and Register Definitions
// ============================================================================

/// NVMe controller register offsets
pub mod regs {
    /// Controller Capabilities (8 bytes)
    pub const CAP: u64 = 0x00;
    /// Version (4 bytes)
    pub const VS: u64 = 0x08;
    /// Interrupt Mask Set (4 bytes)
    pub const INTMS: u64 = 0x0C;
    /// Interrupt Mask Clear (4 bytes)
    pub const INTMC: u64 = 0x10;
    /// Controller Configuration (4 bytes)
    pub const CC: u64 = 0x14;
    /// Controller Status (4 bytes)
    pub const CSTS: u64 = 0x1C;
    /// NVM Subsystem Reset (4 bytes)
    pub const NSSR: u64 = 0x20;
    /// Admin Queue Attributes (4 bytes)
    pub const AQA: u64 = 0x24;
    /// Admin Submission Queue Base Address (8 bytes)
    pub const ASQ: u64 = 0x28;
    /// Admin Completion Queue Base Address (8 bytes)
    pub const ACQ: u64 = 0x30;
    /// Doorbell stride (calculated from CAP)
    pub const SQ0TDBL: u64 = 0x1000;
}

/// Controller Configuration bits
pub mod cc_bits {
    pub const CC_EN: u32 = 1 << 0; // Enable
    pub const CC_CSS_NVM: u32 = 0 << 4; // NVM command set
    pub const CC_MPS_SHIFT: u32 = 7; // Memory page size shift
    pub const CC_AMS_RR: u32 = 0 << 11; // Round robin arbitration
    pub const CC_SHN_NONE: u32 = 0 << 14; // No shutdown notification
    pub const CC_IOSQES: u32 = 6 << 16; // I/O SQ entry size (64 bytes)
    pub const CC_IOCQES: u32 = 4 << 20; // I/O CQ entry size (16 bytes)
}

/// Controller Status bits
pub mod csts_bits {
    pub const CSTS_RDY: u32 = 1 << 0; // Ready
    pub const CSTS_CFS: u32 = 1 << 1; // Controller fatal status
    pub const CSTS_SHST_NORMAL: u32 = 0 << 2; // Normal operation
    pub const CSTS_NSSRO: u32 = 1 << 4; // NVM subsystem reset occurred
    pub const CSTS_PP: u32 = 1 << 5; // Processing paused
}

/// NVMe Admin opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminOpcode {
    DeleteIOSQ = 0x00,
    CreateIOSQ = 0x01,
    GetLogPage = 0x02,
    DeleteIOCQ = 0x04,
    CreateIOCQ = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEventRequest = 0x0C,
    NamespaceManagement = 0x0D,
    FirmwareCommit = 0x10,
    FirmwareImageDownload = 0x11,
    NamespaceAttachment = 0x15,
}

/// NVMe I/O opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOpcode {
    Flush = 0x00,
    Write = 0x01,
    Read = 0x02,
    WriteUncorrectable = 0x04,
    Compare = 0x05,
    WriteZeroes = 0x08,
    DatasetManagement = 0x09,
    Verify = 0x0C,
    ReservationRegister = 0x0D,
    ReservationReport = 0x0E,
    ReservationAcquire = 0x11,
    ReservationRelease = 0x15,
}

/// NVMe status codes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeStatus {
    Success = 0x00,
    InvalidCommandOpcode = 0x01,
    InvalidFieldInCommand = 0x02,
    CommandIdConflict = 0x03,
    DataTransferError = 0x04,
    CommandsAbortedPowerLoss = 0x05,
    InternalError = 0x06,
    CommandAbortRequested = 0x07,
    CommandAbortedSqDeletion = 0x08,
    CommandAbortedFailedFuse = 0x09,
    CommandAbortedMissingFuse = 0x0A,
    InvalidNamespaceOrFormat = 0x0B,
    CommandSequenceError = 0x0C,
    // Media and Data Integrity errors
    WriteProtected = 0x82,
    Unknown = 0xFF,
}

impl From<u16> for NvmeStatus {
    fn from(value: u16) -> Self {
        let sc = ((value >> 1) & 0xFF) as u8;
        match sc {
            0x00 => NvmeStatus::Success,
            0x01 => NvmeStatus::InvalidCommandOpcode,
            0x02 => NvmeStatus::InvalidFieldInCommand,
            0x03 => NvmeStatus::CommandIdConflict,
            0x04 => NvmeStatus::DataTransferError,
            0x06 => NvmeStatus::InternalError,
            0x0B => NvmeStatus::InvalidNamespaceOrFormat,
            _ => NvmeStatus::Unknown,
        }
    }
}

// ============================================================================
// NVMe Command Structures
// ============================================================================

/// NVMe Submission Queue Entry (64 bytes)
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCommand {
    /// Command dword 0 (opcode, fuse, psdt, cid)
    pub cdw0: u32,
    /// Namespace identifier
    pub nsid: u32,
    /// Reserved
    pub cdw2: u32,
    pub cdw3: u32,
    /// Metadata pointer
    pub mptr: u64,
    /// PRP entry 1 (data pointer)
    pub prp1: u64,
    /// PRP entry 2 (data pointer or PRP list)
    pub prp2: u64,
    /// Command dwords 10-15
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl NvmeCommand {
    /// Create a new command with opcode and command ID
    pub fn new(opcode: u8, cid: u16) -> Self {
        Self {
            cdw0: (opcode as u32) | ((cid as u32) << 16),
            ..Default::default()
        }
    }

    /// Create an Identify command
    pub fn identify(cid: u16, nsid: u32, cns: u8, prp1: u64) -> Self {
        let mut cmd = Self::new(AdminOpcode::Identify as u8, cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = cns as u32;
        cmd
    }

    /// Create a Read command
    pub fn read(cid: u16, nsid: u32, slba: u64, nlb: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new(IoOpcode::Read as u8, cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = slba as u32;
        cmd.cdw11 = (slba >> 32) as u32;
        cmd.cdw12 = nlb as u32;
        cmd
    }

    /// Create a Write command
    pub fn write(cid: u16, nsid: u32, slba: u64, nlb: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new(IoOpcode::Write as u8, cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = slba as u32;
        cmd.cdw11 = (slba >> 32) as u32;
        cmd.cdw12 = nlb as u32;
        cmd
    }

    /// Create a Flush command
    pub fn flush(cid: u16, nsid: u32) -> Self {
        let mut cmd = Self::new(IoOpcode::Flush as u8, cid);
        cmd.nsid = nsid;
        cmd
    }

    /// Create a Create I/O Submission Queue command
    pub fn create_io_sq(cid: u16, sqid: u16, qsize: u16, prp1: u64, cqid: u16) -> Self {
        let mut cmd = Self::new(AdminOpcode::CreateIOSQ as u8, cid);
        cmd.prp1 = prp1;
        cmd.cdw10 = (sqid as u32) | (((qsize - 1) as u32) << 16);
        cmd.cdw11 = (cqid as u32) << 16 | 1; // Physically contiguous
        cmd
    }

    /// Create a Create I/O Completion Queue command
    pub fn create_io_cq(cid: u16, cqid: u16, qsize: u16, prp1: u64, iv: u16) -> Self {
        let mut cmd = Self::new(AdminOpcode::CreateIOCQ as u8, cid);
        cmd.prp1 = prp1;
        cmd.cdw10 = (cqid as u32) | (((qsize - 1) as u32) << 16);
        cmd.cdw11 = (iv as u32) << 16 | 0x03; // IEN | PC
        cmd
    }
}

/// NVMe Completion Queue Entry (16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCompletion {
    /// Command specific
    pub result: u32,
    /// Reserved
    pub rsvd: u32,
    /// SQ head pointer
    pub sq_head: u16,
    /// SQ identifier
    pub sq_id: u16,
    /// Command identifier
    pub cid: u16,
    /// Status field
    pub status: u16,
}

impl NvmeCompletion {
    /// Get the phase bit
    pub fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    /// Get status code
    pub fn get_status(&self) -> NvmeStatus {
        NvmeStatus::from(self.status)
    }

    /// Check if successful
    pub fn is_success(&self) -> bool {
        (self.status >> 1) & 0xFF == 0
    }
}

// ============================================================================
// NVMe Queue Implementation
// ============================================================================

/// Maximum queue depth
pub const MAX_QUEUE_DEPTH: u16 = 1024;
/// Admin queue depth (smaller)
pub const ADMIN_QUEUE_DEPTH: u16 = 32;
/// Default I/O queue depth
pub const IO_QUEUE_DEPTH: u16 = 256;

/// NVMe Submission Queue
pub struct SubmissionQueue {
    /// Queue entries
    entries: *mut NvmeCommand,
    /// Queue depth
    depth: u16,
    /// Current tail (producer index)
    tail: AtomicU16,
    /// Doorbell address
    doorbell: *mut u32,
    /// Free command IDs bitmap
    free_ids: AtomicU64,
}

unsafe impl Send for SubmissionQueue {}
unsafe impl Sync for SubmissionQueue {}

impl SubmissionQueue {
    /// Create a new submission queue
    ///
    /// # Safety
    /// Caller must ensure memory is properly allocated and aligned
    pub unsafe fn new(entries: *mut NvmeCommand, depth: u16, doorbell: *mut u32) -> Self {
        Self {
            entries,
            depth,
            tail: AtomicU16::new(0),
            doorbell,
            free_ids: AtomicU64::new((1u64 << depth.min(64)) - 1),
        }
    }

    /// Allocate a command ID
    pub fn alloc_cid(&self) -> Option<u16> {
        loop {
            let bitmap = self.free_ids.load(Ordering::Acquire);
            if bitmap == 0 {
                return None;
            }

            let idx = bitmap.trailing_zeros() as u16;
            let new_bitmap = bitmap & !(1u64 << idx);

            if self
                .free_ids
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
        }
    }

    /// Free a command ID
    pub fn free_cid(&self, cid: u16) {
        loop {
            let bitmap = self.free_ids.load(Ordering::Acquire);
            let new_bitmap = bitmap | (1u64 << cid);

            if self
                .free_ids
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Submit a command
    ///
    /// # Safety
    /// Caller must ensure command is valid
    pub unsafe fn submit(&self, cmd: NvmeCommand) { unsafe {
        let tail = self.tail.load(Ordering::Acquire);

        // Write command to queue
        core::ptr::write_volatile(self.entries.add(tail as usize), cmd);

        // Memory barrier
        core::sync::atomic::fence(Ordering::Release);

        // Update tail
        let new_tail = (tail + 1) % self.depth;
        self.tail.store(new_tail, Ordering::Release);

        // Ring doorbell
        core::ptr::write_volatile(self.doorbell, new_tail as u32);
    }}
}

/// NVMe Completion Queue
pub struct CompletionQueue {
    /// Queue entries
    entries: *mut NvmeCompletion,
    /// Queue depth
    depth: u16,
    /// Current head (consumer index)
    head: AtomicU16,
    /// Expected phase bit
    phase: AtomicBool,
    /// Doorbell address
    doorbell: *mut u32,
    /// Pending wakers per CID
    wakers: Mutex<Vec<Option<Waker>>>,
}

unsafe impl Send for CompletionQueue {}
unsafe impl Sync for CompletionQueue {}

impl CompletionQueue {
    /// Create a new completion queue
    ///
    /// # Safety
    /// Caller must ensure memory is properly allocated
    pub unsafe fn new(entries: *mut NvmeCompletion, depth: u16, doorbell: *mut u32) -> Self {
        let mut wakers = Vec::with_capacity(depth as usize);
        wakers.resize(depth as usize, None);

        Self {
            entries,
            depth,
            head: AtomicU16::new(0),
            phase: AtomicBool::new(true),
            doorbell,
            wakers: Mutex::new(wakers),
        }
    }

    /// Register a waker for a command ID
    pub fn register_waker(&self, cid: u16, waker: Waker) {
        let mut wakers = self.wakers.lock();
        if let Some(slot) = wakers.get_mut(cid as usize) {
            *slot = Some(waker);
        }
    }

    /// Poll for completions
    pub fn poll(&self) -> Option<NvmeCompletion> {
        let head = self.head.load(Ordering::Acquire);
        let expected_phase = self.phase.load(Ordering::Acquire);

        // Memory barrier
        core::sync::atomic::fence(Ordering::Acquire);

        let cqe = unsafe { *self.entries.add(head as usize) };

        if cqe.phase() != expected_phase {
            return None;
        }

        // Update head
        let new_head = (head + 1) % self.depth;
        self.head.store(new_head, Ordering::Release);

        // Toggle phase at wrap
        if new_head == 0 {
            self.phase.store(!expected_phase, Ordering::Release);
        }

        // Ring doorbell
        unsafe {
            core::ptr::write_volatile(self.doorbell, new_head as u32);
        }

        // Wake pending future
        let mut wakers = self.wakers.lock();
        if let Some(waker) = wakers.get_mut(cqe.cid as usize).and_then(|w| w.take()) {
            drop(wakers);
            waker.wake();
        }

        Some(cqe)
    }

    /// Process all pending completions
    pub fn process_all(&self) -> usize {
        let mut count = 0;
        while self.poll().is_some() {
            count += 1;
        }
        count
    }
}

/// NVMe Queue Pair (Submission + Completion)
pub struct NvmeQueuePair {
    /// Submission queue
    pub sq: SubmissionQueue,
    /// Completion queue
    pub cq: CompletionQueue,
    /// Queue ID
    pub id: u16,
}

// ============================================================================
// NVMe Controller
// ============================================================================

/// NVMe controller identification data (partial)
#[repr(C)]
pub struct NvmeIdentifyController {
    /// PCI Vendor ID
    pub vid: u16,
    /// PCI Subsystem Vendor ID
    pub ssvid: u16,
    /// Serial Number (20 bytes)
    pub sn: [u8; 20],
    /// Model Number (40 bytes)
    pub mn: [u8; 40],
    /// Firmware Revision (8 bytes)
    pub fr: [u8; 8],
    /// Recommended Arbitration Burst
    pub rab: u8,
    /// IEEE OUI Identifier
    pub ieee: [u8; 3],
    /// Controller Multi-Path I/O and Namespace Sharing
    pub cmic: u8,
    /// Maximum Data Transfer Size
    pub mdts: u8,
    /// Controller ID
    pub cntlid: u16,
    /// Version
    pub ver: u32,
    // ... more fields follow in full 4096-byte structure
}

/// NVMe namespace identification data (partial)
#[repr(C)]
pub struct NvmeIdentifyNamespace {
    /// Namespace Size (in logical blocks)
    pub nsze: u64,
    /// Namespace Capacity (in logical blocks)
    pub ncap: u64,
    /// Namespace Utilization (in logical blocks)
    pub nuse: u64,
    /// Namespace Features
    pub nsfeat: u8,
    /// Number of LBA Formats
    pub nlbaf: u8,
    /// Formatted LBA Size
    pub flbas: u8,
    // ... more fields follow
}

/// NVMe error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeError {
    /// Controller not ready
    NotReady,
    /// Controller fatal status
    ControllerFatal,
    /// Queue creation failed
    QueueCreationFailed,
    /// Command failed
    CommandFailed(NvmeStatus),
    /// Timeout
    Timeout,
    /// Invalid parameter
    InvalidParameter,
    /// No namespace
    NoNamespace,
    /// Queue full
    QueueFull,
    /// Allocation failed
    AllocationFailed,
}

/// NVMe controller configuration
#[derive(Clone, Debug)]
pub struct NvmeConfig {
    /// Controller capabilities
    pub cap: u64,
    /// Maximum Queue Entries Supported
    pub mqes: u16,
    /// Doorbell Stride
    pub dstrd: u32,
    /// Memory Page Size Minimum
    pub mpsmin: u32,
    /// Memory Page Size Maximum
    pub mpsmax: u32,
    /// Maximum Data Transfer Size (in memory page units)
    pub mdts: u8,
    /// Number of namespaces
    pub nn: u32,
}

impl Default for NvmeConfig {
    fn default() -> Self {
        Self {
            cap: 0,
            mqes: 0,
            dstrd: 0,
            mpsmin: 0,
            mpsmax: 0,
            mdts: 0,
            nn: 0,
        }
    }
}

/// NVMe namespace information
#[derive(Clone, Debug)]
pub struct NvmeNamespace {
    /// Namespace ID
    pub nsid: u32,
    /// Size in blocks
    pub nsze: u64,
    /// Block size in bytes
    pub block_size: u32,
    /// LBA format index
    pub lba_format: u8,
}

/// NVMe Controller
pub struct NvmeController {
    /// MMIO base address
    mmio_base: u64,
    /// Controller configuration
    config: NvmeConfig,
    /// Admin queue pair
    admin_queue: Option<NvmeQueuePair>,
    /// I/O queue pairs (per-CPU)
    io_queues: Vec<Arc<Mutex<NvmeQueuePair>>>,
    /// Active namespaces
    namespaces: Vec<NvmeNamespace>,
    /// Controller ready flag
    ready: AtomicBool,
    /// Command completion results (cid -> result)
    completions: Mutex<Vec<Option<NvmeCompletion>>>,
}

unsafe impl Send for NvmeController {}
unsafe impl Sync for NvmeController {}

impl NvmeController {
    /// Create a new NVMe controller
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            config: NvmeConfig::default(),
            admin_queue: None,
            io_queues: Vec::new(),
            namespaces: Vec::new(),
            ready: AtomicBool::new(false),
            completions: Mutex::new(Vec::new()),
        }
    }

    /// Read a 32-bit register
    unsafe fn read32(&self, offset: u64) -> u32 { unsafe {
        let ptr = (self.mmio_base + offset) as *const u32;
        core::ptr::read_volatile(ptr)
    }}

    /// Write a 32-bit register
    unsafe fn write32(&self, offset: u64, value: u32) { unsafe {
        let ptr = (self.mmio_base + offset) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }}

    /// Read a 64-bit register
    unsafe fn read64(&self, offset: u64) -> u64 { unsafe {
        let ptr = (self.mmio_base + offset) as *const u64;
        core::ptr::read_volatile(ptr)
    }}

    /// Write a 64-bit register
    unsafe fn write64(&self, offset: u64, value: u64) { unsafe {
        let ptr = (self.mmio_base + offset) as *mut u64;
        core::ptr::write_volatile(ptr, value);
    }}

    /// Initialize the controller
    ///
    /// # Safety
    /// Caller must ensure MMIO address is valid
    pub unsafe fn init(&mut self) -> Result<(), NvmeError> { unsafe {
        // Step 1: Read capabilities
        self.config.cap = self.read64(regs::CAP);
        self.config.mqes = ((self.config.cap & 0xFFFF) + 1) as u16;
        self.config.dstrd = ((self.config.cap >> 32) & 0xF) as u32;
        self.config.mpsmin = ((self.config.cap >> 48) & 0xF) as u32;
        self.config.mpsmax = ((self.config.cap >> 52) & 0xF) as u32;

        // Step 2: Disable controller if enabled
        let cc = self.read32(regs::CC);
        if cc & cc_bits::CC_EN != 0 {
            self.write32(regs::CC, cc & !cc_bits::CC_EN);

            // Wait for not ready
            for _ in 0..10000 {
                if self.read32(regs::CSTS) & csts_bits::CSTS_RDY == 0 {
                    break;
                }
            }
        }

        // Step 3: Allocate admin queues
        let aq_depth = ADMIN_QUEUE_DEPTH.min(self.config.mqes);
        self.allocate_admin_queues(aq_depth)?;

        // Step 4: Configure and enable controller
        let mps = self.config.mpsmin; // Use minimum page size (4KB)
        let cc = cc_bits::CC_EN
            | cc_bits::CC_CSS_NVM
            | (mps << cc_bits::CC_MPS_SHIFT)
            | cc_bits::CC_AMS_RR
            | cc_bits::CC_IOSQES
            | cc_bits::CC_IOCQES;

        self.write32(regs::CC, cc);

        // Step 5: Wait for ready
        for _ in 0..100000 {
            let csts = self.read32(regs::CSTS);
            if csts & csts_bits::CSTS_CFS != 0 {
                return Err(NvmeError::ControllerFatal);
            }
            if csts & csts_bits::CSTS_RDY != 0 {
                break;
            }
        }

        if self.read32(regs::CSTS) & csts_bits::CSTS_RDY == 0 {
            return Err(NvmeError::Timeout);
        }

        // Step 6: Identify controller
        self.identify_controller()?;

        // Step 7: Identify namespaces
        self.identify_namespaces()?;

        // Step 8: Create I/O queues (one per CPU for now)
        // TODO: Detect CPU count
        self.create_io_queues(1)?;

        self.ready.store(true, Ordering::Release);
        Ok(())
    }}

    /// Allocate admin queue pair
    unsafe fn allocate_admin_queues(&mut self, depth: u16) -> Result<(), NvmeError> { unsafe {
        // Allocate submission queue
        let sq_size = core::mem::size_of::<NvmeCommand>() * depth as usize;
        let sq_layout = alloc::alloc::Layout::from_size_align(sq_size, 4096)
            .map_err(|_| NvmeError::AllocationFailed)?;
        let sq_ptr = alloc::alloc::alloc_zeroed(sq_layout) as *mut NvmeCommand;
        if sq_ptr.is_null() {
            return Err(NvmeError::AllocationFailed);
        }

        // Allocate completion queue
        let cq_size = core::mem::size_of::<NvmeCompletion>() * depth as usize;
        let cq_layout = alloc::alloc::Layout::from_size_align(cq_size, 4096)
            .map_err(|_| NvmeError::AllocationFailed)?;
        let cq_ptr = alloc::alloc::alloc_zeroed(cq_layout) as *mut NvmeCompletion;
        if cq_ptr.is_null() {
            alloc::alloc::dealloc(sq_ptr as *mut u8, sq_layout);
            return Err(NvmeError::AllocationFailed);
        }

        // Set admin queue attributes
        let aqa = ((depth - 1) as u32) | (((depth - 1) as u32) << 16);
        self.write32(regs::AQA, aqa);

        // Set queue base addresses
        self.write64(regs::ASQ, sq_ptr as u64);
        self.write64(regs::ACQ, cq_ptr as u64);

        // Calculate doorbell addresses
        let stride = 4 << self.config.dstrd;
        let sq_doorbell = (self.mmio_base + regs::SQ0TDBL) as *mut u32;
        let cq_doorbell = (self.mmio_base + regs::SQ0TDBL + stride as u64) as *mut u32;

        let sq = SubmissionQueue::new(sq_ptr, depth, sq_doorbell);
        let cq = CompletionQueue::new(cq_ptr, depth, cq_doorbell);

        self.admin_queue = Some(NvmeQueuePair { sq, cq, id: 0 });

        // Initialize completions storage
        let mut completions = self.completions.lock();
        completions.resize(depth as usize, None);

        Ok(())
    }}

    /// Identify controller
    unsafe fn identify_controller(&mut self) -> Result<(), NvmeError> { unsafe {
        // Allocate identify buffer (4KB)
        let layout = alloc::alloc::Layout::from_size_align(4096, 4096)
            .map_err(|_| NvmeError::AllocationFailed)?;
        let buffer = alloc::alloc::alloc_zeroed(layout);
        if buffer.is_null() {
            return Err(NvmeError::AllocationFailed);
        }

        // Submit identify controller command
        let admin = self.admin_queue.as_ref().ok_or(NvmeError::NotReady)?;
        let cid = admin.sq.alloc_cid().ok_or(NvmeError::QueueFull)?;

        let cmd = NvmeCommand::identify(cid, 0, 1, buffer as u64); // CNS=1: controller
        admin.sq.submit(cmd);

        // Poll for completion
        let cqe = self.poll_admin_completion(cid, 1000)?;
        if !cqe.is_success() {
            alloc::alloc::dealloc(buffer, layout);
            return Err(NvmeError::CommandFailed(cqe.get_status()));
        }

        // Parse identify data
        let id_ctrl = &*(buffer as *const NvmeIdentifyController);
        self.config.mdts = id_ctrl.mdts;
        self.config.nn = 1; // Assume at least one namespace

        alloc::alloc::dealloc(buffer, layout);
        admin.sq.free_cid(cid);

        Ok(())
    }}

    /// Identify namespaces
    unsafe fn identify_namespaces(&mut self) -> Result<(), NvmeError> { unsafe {
        let layout = alloc::alloc::Layout::from_size_align(4096, 4096)
            .map_err(|_| NvmeError::AllocationFailed)?;
        let buffer = alloc::alloc::alloc_zeroed(layout);
        if buffer.is_null() {
            return Err(NvmeError::AllocationFailed);
        }

        // Identify namespace 1
        let admin = self.admin_queue.as_ref().ok_or(NvmeError::NotReady)?;
        let cid = admin.sq.alloc_cid().ok_or(NvmeError::QueueFull)?;

        let cmd = NvmeCommand::identify(cid, 1, 0, buffer as u64); // CNS=0: namespace
        admin.sq.submit(cmd);

        let cqe = self.poll_admin_completion(cid, 1000)?;
        if cqe.is_success() {
            let id_ns = &*(buffer as *const NvmeIdentifyNamespace);

            // Get LBA format
            let flbas = id_ns.flbas & 0xF;
            let lbaf_offset = 128 + flbas as usize * 4;
            let lbaf = *((buffer.add(lbaf_offset)) as *const u32);
            let lba_ds = ((lbaf >> 16) & 0xFF) as u8;
            let block_size = 1u32 << lba_ds;

            self.namespaces.push(NvmeNamespace {
                nsid: 1,
                nsze: id_ns.nsze,
                block_size,
                lba_format: flbas,
            });
        }

        alloc::alloc::dealloc(buffer, layout);
        admin.sq.free_cid(cid);

        Ok(())
    }}

    /// Create I/O queue pairs
    unsafe fn create_io_queues(&mut self, num_queues: u16) -> Result<(), NvmeError> { unsafe {
        let queue_depth = IO_QUEUE_DEPTH.min(self.config.mqes);

        for qid in 1..=num_queues {
            // Allocate CQ first
            let cq_size = core::mem::size_of::<NvmeCompletion>() * queue_depth as usize;
            let cq_layout = alloc::alloc::Layout::from_size_align(cq_size, 4096)
                .map_err(|_| NvmeError::AllocationFailed)?;
            let cq_ptr = alloc::alloc::alloc_zeroed(cq_layout) as *mut NvmeCompletion;
            if cq_ptr.is_null() {
                return Err(NvmeError::AllocationFailed);
            }

            // Create CQ via admin command
            let admin = self.admin_queue.as_ref().ok_or(NvmeError::NotReady)?;
            let cid = admin.sq.alloc_cid().ok_or(NvmeError::QueueFull)?;

            let cmd = NvmeCommand::create_io_cq(cid, qid, queue_depth, cq_ptr as u64, qid - 1);
            admin.sq.submit(cmd);

            let cqe = self.poll_admin_completion(cid, 1000)?;
            admin.sq.free_cid(cid);
            if !cqe.is_success() {
                alloc::alloc::dealloc(cq_ptr as *mut u8, cq_layout);
                return Err(NvmeError::QueueCreationFailed);
            }

            // Allocate SQ
            let sq_size = core::mem::size_of::<NvmeCommand>() * queue_depth as usize;
            let sq_layout = alloc::alloc::Layout::from_size_align(sq_size, 4096)
                .map_err(|_| NvmeError::AllocationFailed)?;
            let sq_ptr = alloc::alloc::alloc_zeroed(sq_layout) as *mut NvmeCommand;
            if sq_ptr.is_null() {
                return Err(NvmeError::AllocationFailed);
            }

            // Create SQ via admin command
            let cid = admin.sq.alloc_cid().ok_or(NvmeError::QueueFull)?;
            let cmd = NvmeCommand::create_io_sq(cid, qid, queue_depth, sq_ptr as u64, qid);
            admin.sq.submit(cmd);

            let cqe = self.poll_admin_completion(cid, 1000)?;
            admin.sq.free_cid(cid);
            if !cqe.is_success() {
                alloc::alloc::dealloc(sq_ptr as *mut u8, sq_layout);
                return Err(NvmeError::QueueCreationFailed);
            }

            // Calculate doorbell addresses
            let stride = 4 << self.config.dstrd;
            let sq_doorbell =
                (self.mmio_base + regs::SQ0TDBL + (qid as u64 * 2) * stride as u64) as *mut u32;
            let cq_doorbell =
                (self.mmio_base + regs::SQ0TDBL + (qid as u64 * 2 + 1) * stride as u64) as *mut u32;

            let sq = SubmissionQueue::new(sq_ptr, queue_depth, sq_doorbell);
            let cq = CompletionQueue::new(cq_ptr, queue_depth, cq_doorbell);

            self.io_queues
                .push(Arc::new(Mutex::new(NvmeQueuePair { sq, cq, id: qid })));
        }

        Ok(())
    }}

    /// Poll admin queue for a specific completion
    fn poll_admin_completion(&self, cid: u16, max_polls: u32) -> Result<NvmeCompletion, NvmeError> {
        let admin = self.admin_queue.as_ref().ok_or(NvmeError::NotReady)?;

        for _ in 0..max_polls {
            if let Some(cqe) = admin.cq.poll() {
                if cqe.cid == cid {
                    return Ok(cqe);
                }
                // Store other completions for their waiters
                let mut completions = self.completions.lock();
                if let Some(slot) = completions.get_mut(cqe.cid as usize) {
                    *slot = Some(cqe);
                }
            }
        }

        Err(NvmeError::Timeout)
    }

    /// Check if controller is ready
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Get namespaces
    pub fn namespaces(&self) -> &[NvmeNamespace] {
        &self.namespaces
    }

    /// Async read operation
    pub fn read_async<'a>(&'a self, nsid: u32, slba: u64, buf: &'a mut [u8]) -> NvmeReadFuture<'a> {
        NvmeReadFuture {
            controller: self,
            nsid,
            slba,
            buf,
            submitted: false,
            cid: None,
            queue_idx: 0,
        }
    }

    /// Async write operation
    pub fn write_async<'a>(&'a self, nsid: u32, slba: u64, buf: &'a [u8]) -> NvmeWriteFuture<'a> {
        NvmeWriteFuture {
            controller: self,
            nsid,
            slba,
            buf,
            submitted: false,
            cid: None,
            queue_idx: 0,
        }
    }

    /// Handle interrupt
    pub fn handle_interrupt(&self) {
        // Process all I/O queues
        for queue in &self.io_queues {
            let qp = queue.lock();
            qp.cq.process_all();
        }
    }
}

// ============================================================================
// Async Futures
// ============================================================================

/// Future for async read
pub struct NvmeReadFuture<'a> {
    controller: &'a NvmeController,
    nsid: u32,
    slba: u64,
    buf: &'a mut [u8],
    submitted: bool,
    cid: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for NvmeReadFuture<'a> {
    type Output = Result<usize, NvmeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.controller.is_ready() {
            return Poll::Ready(Err(NvmeError::NotReady));
        }

        if !self.submitted {
            // Find namespace block size
            let ns = self
                .controller
                .namespaces()
                .iter()
                .find(|n| n.nsid == self.nsid)
                .ok_or(NvmeError::NoNamespace)?;

            let block_size = ns.block_size as usize;
            if self.buf.len() % block_size != 0 {
                return Poll::Ready(Err(NvmeError::InvalidParameter));
            }

            let nlb = (self.buf.len() / block_size) as u16;

            // Get I/O queue
            let queue = self
                .controller
                .io_queues
                .get(self.queue_idx)
                .ok_or(NvmeError::NotReady)?;
            let qp = queue.lock();

            // Allocate CID
            let cid = qp.sq.alloc_cid().ok_or(NvmeError::QueueFull)?;
            self.cid = Some(cid);

            // Submit read command
            let cmd = NvmeCommand::read(
                cid,
                self.nsid,
                self.slba,
                nlb - 1,
                self.buf.as_ptr() as u64,
                0,
            );

            unsafe {
                qp.sq.submit(cmd);
            }

            // Register waker
            qp.cq.register_waker(cid, cx.waker().clone());

            self.submitted = true;
            return Poll::Pending;
        }

        // Check for completion
        let queue = self
            .controller
            .io_queues
            .get(self.queue_idx)
            .ok_or(NvmeError::NotReady)?;
        let qp = queue.lock();

        if let Some(cqe) = qp.cq.poll() {
            // SAFETY: submitted=true なら cid は必ず Some
            // アセンブリ: Option の分岐条件 (test + cmov) を除去
            let cid = unsafe { self.cid.unwrap_unchecked() };
            if cqe.cid == cid {
                qp.sq.free_cid(cqe.cid);
                if cqe.is_success() {
                    return Poll::Ready(Ok(self.buf.len()));
                } else {
                    return Poll::Ready(Err(NvmeError::CommandFailed(cqe.get_status())));
                }
            }
        }

        // Re-register waker
        if let Some(cid) = self.cid {
            qp.cq.register_waker(cid, cx.waker().clone());
        }

        Poll::Pending
    }
}

/// Future for async write
pub struct NvmeWriteFuture<'a> {
    controller: &'a NvmeController,
    nsid: u32,
    slba: u64,
    buf: &'a [u8],
    submitted: bool,
    cid: Option<u16>,
    queue_idx: usize,
}

impl<'a> Future for NvmeWriteFuture<'a> {
    type Output = Result<usize, NvmeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.controller.is_ready() {
            return Poll::Ready(Err(NvmeError::NotReady));
        }

        if !self.submitted {
            let ns = self
                .controller
                .namespaces()
                .iter()
                .find(|n| n.nsid == self.nsid)
                .ok_or(NvmeError::NoNamespace)?;

            let block_size = ns.block_size as usize;
            if self.buf.len() % block_size != 0 {
                return Poll::Ready(Err(NvmeError::InvalidParameter));
            }

            let nlb = (self.buf.len() / block_size) as u16;

            let queue = self
                .controller
                .io_queues
                .get(self.queue_idx)
                .ok_or(NvmeError::NotReady)?;
            let qp = queue.lock();

            let cid = qp.sq.alloc_cid().ok_or(NvmeError::QueueFull)?;
            self.cid = Some(cid);

            let cmd = NvmeCommand::write(
                cid,
                self.nsid,
                self.slba,
                nlb - 1,
                self.buf.as_ptr() as u64,
                0,
            );

            unsafe {
                qp.sq.submit(cmd);
            }
            qp.cq.register_waker(cid, cx.waker().clone());

            self.submitted = true;
            return Poll::Pending;
        }

        let queue = self
            .controller
            .io_queues
            .get(self.queue_idx)
            .ok_or(NvmeError::NotReady)?;
        let qp = queue.lock();

        if let Some(cqe) = qp.cq.poll() {
            // SAFETY: submitted=true なら cid は必ず Some
            let cid = unsafe { self.cid.unwrap_unchecked() };
            if cqe.cid == cid {
                qp.sq.free_cid(cqe.cid);
                if cqe.is_success() {
                    return Poll::Ready(Ok(self.buf.len()));
                } else {
                    return Poll::Ready(Err(NvmeError::CommandFailed(cqe.get_status())));
                }
            }
        }

        if let Some(cid) = self.cid {
            qp.cq.register_waker(cid, cx.waker().clone());
        }

        Poll::Pending
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static NVME_CONTROLLER: Mutex<Option<NvmeController>> = Mutex::new(None);

/// Initialize the global NVMe controller
///
/// # Safety
/// Caller must ensure MMIO address is valid
pub unsafe fn init_nvme(mmio_base: u64) -> Result<(), NvmeError> { unsafe {
    let mut controller = NvmeController::new(mmio_base);
    controller.init()?;

    if let Some(ns) = controller.namespaces().first() {
        crate::log!(
            "NVMe initialized: {} blocks x {} bytes\n",
            ns.nsze,
            ns.block_size
        );
    }

    *NVME_CONTROLLER.lock() = Some(controller);
    Ok(())
}}

/// Handle NVMe interrupt
pub fn handle_nvme_interrupt() {
    if let Some(ctrl) = NVME_CONTROLLER.lock().as_ref() {
        ctrl.handle_interrupt();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvme_command_size() {
        assert_eq!(core::mem::size_of::<NvmeCommand>(), 64);
    }

    #[test]
    fn test_nvme_completion_size() {
        assert_eq!(core::mem::size_of::<NvmeCompletion>(), 16);
    }

    #[test]
    fn test_nvme_status_from() {
        assert_eq!(NvmeStatus::from(0), NvmeStatus::Success);
        assert_eq!(NvmeStatus::from(0x02), NvmeStatus::InvalidCommandOpcode);
    }
}
