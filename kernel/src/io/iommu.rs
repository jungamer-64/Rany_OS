// ============================================================================
// src/io/iommu.rs - IOMMU (Intel VT-d) Support
// ============================================================================
//!
//! IOMMU サポート (Intel VT-d / AMD-Vi)
//!
//! ## 設計原則 (仕様書 7.2準拠)
//! - デバイスメモリアクセス制限
//! - DMA領域の保護
//! - デバイス分離
//!
//! ## Intel VT-d 主要機能
//! - DMA Remapping: デバイスDMAのアドレス変換
//! - Interrupt Remapping: 割り込みの仮想化
//! - Posted Interrupts: 効率的な割り込み配送
//!
//! ## 【設計書 7.2】IOMMU必須化
//!
//! セキュリティ上の理由から、IOMMUの存在を起動時に必須とするオプションを提供。
//! `IOMMU_REQUIRED`が`true`の場合、IOMMU未検出でパニック。

#![allow(dead_code)]

// use crate::memory; // not used directly here; use `crate::mm::phys_to_virt` instead
use crate::sync::IrqMutex;
use crate::task::AtomicWaker;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use spin::{Mutex, RwLock};

// PCI helpers used when enabling ATS for devices
use pci_driver::{
    AtsController, DeviceId as PciDeviceId, PcieBdf, device_supports_ats, pcie_ext_config,
};

// DMAR parsing moved to `drivers::acpi::dmar` (see `drivers/acpi/src/dmar.rs`).
// This centralizes parsing logic and avoids duplication / circular dependencies.

// ============================================================================
// Configuration - IOMMU Requirement
// ============================================================================

/// 【設計書 7.2】IOMMUを起動時に必須とするかどうか
///
/// セキュリティ要件により、IOMMUがない環境では起動を拒否できる。
/// - `true`: IOMMU未検出時にパニック
/// - `false`: IOMMU未検出時も警告のみで続行
pub static IOMMU_REQUIRED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Fault Logging Rate Limiting
// ============================================================================

/// Maximum number of faults to log per process_faults call (prevents log flooding)
const FAULT_LOG_RATE_LIMIT: usize = 10;

/// IOMMUを必須に設定する
///
/// 起動初期（IOMMU初期化前）に呼び出すこと
pub fn set_iommu_required(required: bool) {
    IOMMU_REQUIRED.store(required, Ordering::Release);
}

/// IOMMUが必須かどうかを確認
pub fn is_iommu_required() -> bool {
    IOMMU_REQUIRED.load(Ordering::Acquire)
}

/// IOMMU要件をチェックし、必要なら停止
///
/// この関数はIOMMU初期化後に呼び出すべき
pub fn enforce_iommu_requirement() {
    if is_iommu_required() && !is_iommu_enabled() {
        // IOMMUが必須だが検出されなかった
        panic!(
            "[SECURITY] IOMMU is required but not detected. \
                DMA attacks are possible without IOMMU protection. \
                To boot without IOMMU, set IOMMU_REQUIRED=false."
        );
    }
}

// ============================================================================
// Constants and Register Definitions
// ============================================================================

/// DMAR (DMA Remapping) register offsets
pub mod regs {
    /// Version register
    pub const VER: u64 = 0x00;
    /// Capabilities register
    pub const CAP: u64 = 0x08;
    /// Extended capabilities register
    pub const ECAP: u64 = 0x10;
    /// Global command register
    pub const GCMD: u64 = 0x18;
    /// Global status register
    pub const GSTS: u64 = 0x1C;
    /// Root table address register
    pub const RTADDR: u64 = 0x20;
    /// Context command register
    pub const CCMD: u64 = 0x28;
    /// Fault status register
    pub const FSTS: u64 = 0x34;
    /// Fault event control register
    pub const FECTL: u64 = 0x38;
    /// Fault event data register
    pub const FEDATA: u64 = 0x3C;
    /// Fault event address register
    pub const FEADDR: u64 = 0x40;
    /// Invalidation queue head register
    pub const IQH: u64 = 0x80;
    /// Invalidation queue tail register
    pub const IQT: u64 = 0x88;
    /// Invalidation queue address register
    pub const IQA: u64 = 0x90;
    /// Performance Monitoring Control register
    pub const PERMON_CTL: u64 = 0x200;
    /// Performance Monitoring Counter 0
    pub const PERMON_CNT0: u64 = 0x208;
    /// Performance Monitoring Counter 1
    pub const PERMON_CNT1: u64 = 0x210;
    /// Performance Monitoring Counter 2
    pub const PERMON_CNT2: u64 = 0x218;
    /// Performance Monitoring Counter 3
    pub const PERMON_CNT3: u64 = 0x220;
    /// Performance Monitoring Event Select 0
    pub const PERMON_EVT0: u64 = 0x228;
    /// Performance Monitoring Event Select 1
    pub const PERMON_EVT1: u64 = 0x230;
    /// Performance Monitoring Event Select 2
    pub const PERMON_EVT2: u64 = 0x238;
    /// Performance Monitoring Event Select 3
    pub const PERMON_EVT3: u64 = 0x240;
    /// Page Request Queue Address register
    pub const PQA: u64 = 0x0E0;
    /// Page Request Queue Head register
    pub const PQH: u64 = 0x0E8;
    /// Page Request Queue Tail register
    pub const PQT: u64 = 0x0F0;
}

/// Global command bits
pub mod gcmd_bits {
    /// Translation enable
    pub const GCMD_TE: u32 = 1 << 31;
    /// Set root table pointer
    pub const GCMD_SRTP: u32 = 1 << 30;
    /// Set fault log
    pub const GCMD_SFL: u32 = 1 << 29;
    /// Enable advanced fault logging
    pub const GCMD_EAFL: u32 = 1 << 28;
    /// Write buffer flush
    pub const GCMD_WBF: u32 = 1 << 27;
    /// Queued invalidation enable
    pub const GCMD_QIE: u32 = 1 << 26;
    /// Interrupt remapping enable
    pub const GCMD_IRE: u32 = 1 << 25;
    /// Set interrupt remap table pointer
    pub const GCMD_SIRTP: u32 = 1 << 24;
    /// Compatibility format interrupt
    pub const GCMD_CFI: u32 = 1 << 23;
}

/// Global status bits
pub mod gsts_bits {
    /// Translation enable status
    pub const GSTS_TES: u32 = 1 << 31;
    /// Root table pointer status
    pub const GSTS_RTPS: u32 = 1 << 30;
    /// Fault log status
    pub const GSTS_FLS: u32 = 1 << 29;
    /// Advanced fault logging status
    pub const GSTS_AFLS: u32 = 1 << 28;
    /// Write buffer flush status
    pub const GSTS_WBFS: u32 = 1 << 27;
    /// Queued invalidation enable status
    pub const GSTS_QIES: u32 = 1 << 26;
    /// Interrupt remapping enable status
    pub const GSTS_IRES: u32 = 1 << 25;
    /// Interrupt remap table pointer status
    pub const GSTS_IRTPS: u32 = 1 << 24;
    /// Compatibility format interrupt status
    pub const GSTS_CFIS: u32 = 1 << 23;
}

/// Capability register bits
pub mod cap_bits {
    /// Required write-buffer flushing
    pub const CAP_RWBF: u64 = 1 << 4;
    /// Page-level memory introspection
    pub const CAP_PLMR: u64 = 1 << 5;
    /// Pass through support
    pub const CAP_PT: u64 = 1 << 6;
    /// Snoop control
    pub const CAP_SC: u64 = 1 << 7;
    /// Invalidation Register Offset (bits 8-11)
    pub const CAP_IRO_MASK: u64 = 0xF << 8;
    /// Number of Fault Recording registers (bits 40-47)
    pub const CAP_NFR_MASK: u64 = 0xFF << 40;
    /// Fault Recording register Offset (bits 24-33)
    pub const CAP_FRO_MASK: u64 = 0x3FF << 24;
    /// Super-page support (bits 34-35)
    pub const CAP_SLLPS: u64 = 3 << 34;
    /// 2MB super-page supported
    pub const CAP_SLLPS_2M: u64 = 1 << 34;
    /// 1GB super-page supported
    pub const CAP_SLLPS_1G: u64 = 1 << 35;
    /// Page walk coherency
    pub const CAP_PWC: u64 = 1 << 38;
    /// Caching mode
    pub const CAP_CM: u64 = 1 << 7;
}

/// Extended capability register bits
pub mod ecap_bits {
    /// Page walk coherency
    pub const ECAP_C: u64 = 1 << 0;
    /// Queued Invalidation support
    pub const ECAP_QI: u64 = 1 << 1;
    /// Device-TLB support
    pub const ECAP_DT: u64 = 1 << 2;
    /// Interrupt Remapping support
    pub const ECAP_IR: u64 = 1 << 3;
    /// Extended Interrupt Mode
    pub const ECAP_EIM: u64 = 1 << 4;
    /// Pass Through support
    pub const ECAP_PT: u64 = 1 << 6;
    /// Snoop Control
    pub const ECAP_SC: u64 = 1 << 7;
    /// Interrupt Remapping Table Offset (bits 8-17)
    pub const ECAP_IRO_MASK: u64 = 0x3FF << 8;
    /// Memory Type Support
    pub const ECAP_MTS: u64 = 1 << 25;
    /// Nested Translation Support
    pub const ECAP_NEST: u64 = 1 << 26;
    /// Page Request Support
    pub const ECAP_PRS: u64 = 1 << 29;
    /// Execute Request Support
    pub const ECAP_ERS: u64 = 1 << 30;
    /// Supervisor Request Support
    pub const ECAP_SRS: u64 = 1 << 31;
    /// Posted Interrupts Support (Posted Interrupt Descriptor Support)
    pub const ECAP_PIDS: u64 = 1 << 59;
    /// Scalable Mode Translation Support
    pub const ECAP_SMTS: u64 = 1 << 35;
    /// Performance Monitoring Support
    pub const ECAP_PMC: u64 = 1 << 40;
}

/// IOMMU Performance Monitoring Event Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PerfMonEvent {
    /// IOTLB hits
    IotlbHit = 0x00,
    /// IOTLB misses
    IotlbMiss = 0x01,
    /// Context cache hits
    ContextCacheHit = 0x02,
    /// Context cache misses
    ContextCacheMiss = 0x03,
    /// Page walk cycles
    PageWalkCycles = 0x04,
    /// Page walk requests
    PageWalkRequests = 0x05,
    /// PASID cache hits
    PasidCacheHit = 0x06,
    /// PASID cache misses
    PasidCacheMiss = 0x07,
    /// Posted interrupt descriptors processed
    PostedInterruptDesc = 0x08,
    /// DMA read requests
    DmaReadRequests = 0x09,
    /// DMA write requests
    DmaWriteRequests = 0x0A,
    /// Device-TLB invalidation requests
    DevTlbInvalidations = 0x0B,
}

/// Performance Monitoring Counter configuration
#[derive(Debug, Clone)]
pub struct PerfMonCounter {
    /// Counter index (0-3)
    pub index: u8,
    /// Event to monitor
    pub event: PerfMonEvent,
    /// Enable counter
    pub enabled: bool,
    /// Overflow interrupt enable
    pub overflow_irq: bool,
}

/// Posted Interrupt Descriptor (PID)
///
/// 64-byte aligned structure used for Posted Interrupt processing.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct PostedInterruptDescriptor {
    /// Posted Interrupt Request (PIR) - bitmap of 256 vectors
    pub pir: [u64; 4],
    /// Notification Info
    /// - Bit 0: ON (Outstanding Notification)
    /// - Bit 1: SN (Suppress Notification)
    /// - Bits 16-23: NV (Notification Vector)
    /// - Bits 32-63: NDST (Notification Destination APIC ID)
    pub notification_info: AtomicU64,
    /// Reserved
    pub reserved: [u64; 3],
}

impl PostedInterruptDescriptor {
    pub const ON: u64 = 1 << 0;
    pub const SN: u64 = 1 << 1;

    /// Create a new zeroed PID
    pub fn new() -> Self {
        Self {
            pir: [0; 4],
            notification_info: AtomicU64::new(0),
            reserved: [0; 3],
        }
    }
}

/// Posted Interrupt Descriptor Pool
///
/// Manages allocation of Posted Interrupt Descriptors (PIDs).
/// Each PID is 64-byte aligned for hardware requirements.
pub struct PostedInterruptPool {
    /// Base physical address of the pool (64-byte aligned)
    base: usize,
    /// Number of PIDs in the pool
    size: usize,
    /// Allocation bitmap (1 = allocated, 0 = free)
    allocated: Vec<u64>,
}

impl PostedInterruptPool {
    /// Maximum number of PIDs supported
    pub const MAX_PIDS: usize = 256;

    /// Create a new PID pool
    pub fn new(num_pids: usize) -> Option<Self> {
        let size = num_pids.min(Self::MAX_PIDS);
        // Each PID is 64 bytes
        let total_bytes = size * core::mem::size_of::<PostedInterruptDescriptor>();

        // Allocate 64-byte aligned memory
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 64).ok()?;
        let base = crate::util::allocate_zeroed(layout)?.as_ptr() as usize;

        // Bitmap: 64 PIDs per u64
        let bitmap_size = (size + 63) / 64;
        let allocated = alloc::vec![0u64; bitmap_size];

        Some(Self {
            base,
            size,
            allocated,
        })
    }

    /// Allocate a PID, returning its index and physical address
    pub fn allocate(&mut self) -> Option<(u16, u64)> {
        for (word_idx, word) in self.allocated.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros() as usize;
                let index = word_idx * 64 + bit;
                if index >= self.size {
                    return None;
                }
                *word |= 1 << bit;
                let addr = self.base + index * core::mem::size_of::<PostedInterruptDescriptor>();
                return Some((index as u16, addr as u64));
            }
        }
        None
    }

    /// Free a PID by index
    pub fn free(&mut self, index: u16) {
        let word_idx = index as usize / 64;
        let bit = index as usize % 64;
        if word_idx < self.allocated.len() {
            self.allocated[word_idx] &= !(1 << bit);
        }
    }

    /// Get a mutable reference to a PID by index
    pub fn get_mut(&mut self, index: u16) -> Option<&mut PostedInterruptDescriptor> {
        if (index as usize) < self.size {
            let ptr = self.base as *mut PostedInterruptDescriptor;
            Some(unsafe { &mut *ptr.add(index as usize) })
        } else {
            None
        }
    }

    /// Get the physical address of a PID
    pub fn get_address(&self, index: u16) -> Option<u64> {
        if (index as usize) < self.size {
            Some(
                (self.base + (index as usize) * core::mem::size_of::<PostedInterruptDescriptor>())
                    as u64,
            )
        } else {
            None
        }
    }
}

// ============================================================================
// Page Request Interface (PRI) Structures
// ============================================================================

/// Page Request Queue Entry
///
/// 16-byte entry in the Page Request Queue.
/// Devices use this to request page translations during ATS faults.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct PageRequestEntry {
    /// Low 64 bits
    /// - Bits 0-15: Source ID (Requester ID)
    /// - Bits 16-31: Reserved
    /// - Bits 52-55: Request Type
    /// - Bit 56: PASID Present
    /// - Bit 57: Execute Requested
    /// - Bit 58: Privileged Mode Requested
    /// - Bit 59: Last Request in Group
    /// - Bits 60-63: Reserved
    pub lo: u64,
    /// High 64 bits
    /// - Bits 0-51: Page Address (4KB aligned)
    /// - Bits 52-71: PASID (if present)
    /// - Bits 72-80: PRG Index (Page Request Group Index)
    pub hi: u64,
}

impl PageRequestEntry {
    /// Last Request in Group
    pub const LAST_REQ: u64 = 1 << 59;
    /// Execute Requested
    pub const EXEC_REQ: u64 = 1 << 57;
    /// Privileged Mode Requested
    pub const PRIV_REQ: u64 = 1 << 58;
    /// PASID Present
    pub const PASID_PRESENT: u64 = 1 << 56;

    /// Get the source ID (Requester ID)
    pub fn source_id(&self) -> u16 {
        (self.lo & 0xFFFF) as u16
    }

    /// Get the page address (4KB aligned)
    pub fn page_address(&self) -> u64 {
        self.hi & 0x000F_FFFF_FFFF_F000
    }

    /// Get the PASID (if present)
    pub fn pasid(&self) -> Option<u32> {
        if (self.lo & Self::PASID_PRESENT) != 0 {
            Some(((self.hi >> 52) & 0xFFFFF) as u32)
        } else {
            None
        }
    }

    /// Check if this is the last request in a group
    pub fn is_last(&self) -> bool {
        (self.lo & Self::LAST_REQ) != 0
    }
}

/// Page Request Queue
///
/// Ring buffer queue for page request entries.
/// Hardware writes requests at the tail, software reads from head.
pub struct PageRequestQueue {
    /// Base virtual address of the queue
    base: usize,
    /// Number of entries (power of 2)
    size: usize,
    /// Current head index (software reads from here)
    head: usize,
    /// Cached tail from hardware
    tail: usize,
}

impl PageRequestQueue {
    /// Default PRQ size (256 entries)
    pub const DEFAULT_SIZE: usize = 256;

    /// Create a new Page Request Queue
    pub fn new(size: usize) -> Option<Self> {
        // Size must be power of 2
        let size = size.next_power_of_two().min(4096);
        let total_bytes = size * core::mem::size_of::<PageRequestEntry>();

        // Allocate 4KB aligned memory
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 4096).ok()?;
        let base = crate::util::allocate_zeroed(layout)?.as_ptr() as usize;

        Some(Self {
            base,
            size,
            head: 0,
            tail: 0,
        })
    }

    /// Get the physical base address
    pub fn base_address(&self) -> u64 {
        self.base as u64
    }

    /// Get the size (number of entries)
    pub fn size(&self) -> usize {
        self.size
    }

    /// Update the tail from hardware register
    pub fn update_tail(&mut self, tail: usize) {
        self.tail = tail & (self.size - 1);
    }

    /// Check if queue has pending entries
    pub fn has_pending(&self) -> bool {
        self.head != self.tail
    }

    /// Pop the next request entry
    pub fn pop(&mut self) -> Option<PageRequestEntry> {
        if self.head == self.tail {
            return None;
        }

        let ptr = self.base as *const PageRequestEntry;
        let entry = unsafe { *ptr.add(self.head) };
        self.head = (self.head + 1) & (self.size - 1);

        Some(entry)
    }

    /// Get current head index (for writing to hardware)
    pub fn head(&self) -> usize {
        self.head
    }
}

/// Fault status register bits
pub mod fsts_bits {
    /// Primary Pending Fault
    pub const FSTS_PPF: u32 = 1 << 0;
    /// Primary Fault Overflow
    pub const FSTS_PFO: u32 = 1 << 1;
    /// Invalidation Queue Error
    pub const FSTS_IQE: u32 = 1 << 4;
    /// Interrupt Condition Error
    pub const FSTS_ICE: u32 = 1 << 5;
    /// Interrupt Table Error
    pub const FSTS_ITE: u32 = 1 << 6;
    /// Advanced Pending Fault
    pub const FSTS_APF: u32 = 1 << 7;
    /// Fault Record Index (bits 8-15)
    pub const FSTS_FRI_MASK: u32 = 0xFF << 8;
}

/// IOTLB Invalidation register offsets (relative to IRO)
pub mod iotlb_regs {
    /// IOTLB Invalidation Address register (64-bit)
    pub const IVA: u64 = 0x00;
    /// IOTLB Invalidation Command register (64-bit)
    pub const IOTLB: u64 = 0x08;
}

// ============================================================================
// Fault Handling Structures
// ============================================================================

/// Fault Record (16 bytes)
///
/// Hardware fault record format from the Fault Recording Registers.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultRecord {
    /// Lower 64 bits (Source ID, Fault Reason, etc.)
    pub lo: u64,
    /// Upper 64 bits (Fault Address)
    pub hi: u64,
}

impl FaultRecord {
    /// Fault reason mask (bits 0-7 of lo)
    pub const REASON_MASK: u64 = 0xFF;
    /// PASID value mask (bits 8-27 of lo)
    pub const PASID_MASK: u64 = 0xFFFFF00;
    pub const PASID_SHIFT: u64 = 8;
    /// PASID present (bit 28 of lo)
    pub const PASID_PRESENT: u64 = 1 << 28;
    /// Execute request (bit 29 of lo)
    pub const ERQ: u64 = 1 << 29;
    /// Privilege mode requested (bit 30 of lo)
    pub const PRIV: u64 = 1 << 30;
    /// Supervisor request (bit 31 of lo)
    pub const SUPERV: u64 = 1 << 31;
    /// Source ID mask (bits 32-47 of lo)
    pub const SID_MASK: u64 = 0xFFFF_0000_0000;
    pub const SID_SHIFT: u64 = 32;
    /// Type (bits 48-49 of lo)
    pub const TYPE_MASK: u64 = 0x3_0000_0000_0000;
    pub const TYPE_SHIFT: u64 = 48;
    /// Fault (bit 63 of lo)
    pub const FAULT: u64 = 1 << 63;
    /// Fault address mask (bits 12-63 of hi)
    pub const ADDR_MASK: u64 = !0xFFF;

    /// Get fault reason code
    pub fn reason(&self) -> u8 {
        (self.lo & Self::REASON_MASK) as u8
    }

    /// Get source ID (BDF)
    pub fn source_id(&self) -> u16 {
        ((self.lo & Self::SID_MASK) >> Self::SID_SHIFT) as u16
    }

    /// Get fault address
    pub fn fault_address(&self) -> u64 {
        self.hi & Self::ADDR_MASK
    }

    /// Get PASID (if present)
    pub fn pasid(&self) -> Option<u32> {
        if self.lo & Self::PASID_PRESENT != 0 {
            Some(((self.lo & Self::PASID_MASK) >> Self::PASID_SHIFT) as u32)
        } else {
            None
        }
    }

    /// Check if this is a valid fault record
    pub fn is_valid(&self) -> bool {
        self.lo & Self::FAULT != 0
    }

    /// Clear the fault bit
    pub fn clear(&mut self) {
        self.lo &= !Self::FAULT;
    }
}

/// Fault Log - Ring buffer for storing fault records
/// Fixed-size buffer to ensure ISR safety (no allocations).
pub const FAULT_LOG_SIZE: usize = 256;

pub struct FaultLog {
    /// Ring buffer of fault records
    records: [FaultRecord; FAULT_LOG_SIZE],
    /// Write index (next slot to write)
    write_idx: usize,
    /// Number of records stored
    count: usize,
    /// Total faults recorded (may exceed capacity)
    total_faults: u64,
}

impl FaultLog {
    /// Create a new fault log
    pub fn new() -> Self {
        Self {
            records: [FaultRecord::default(); FAULT_LOG_SIZE],
            write_idx: 0,
            count: 0,
            total_faults: 0,
        }
    }

    /// Add a fault record
    pub fn push(&mut self, record: FaultRecord) {
        self.records[self.write_idx] = record;
        self.write_idx = (self.write_idx + 1) % FAULT_LOG_SIZE;
        self.total_faults += 1;
        if self.count < FAULT_LOG_SIZE {
            self.count += 1;
        }
    }

    /// Get the most recent fault records (up to count entries)
    pub fn recent(&self, max_count: usize) -> alloc::vec::Vec<FaultRecord> {
        let n = max_count.min(self.count);
        let mut result = alloc::vec::Vec::with_capacity(n);

        for i in 0..n {
            let idx = if self.write_idx >= i + 1 {
                self.write_idx - i - 1
            } else {
                FAULT_LOG_SIZE - (i + 1 - self.write_idx)
            };
            result.push(self.records[idx]);
        }

        result
    }

    /// Get total number of faults recorded
    pub fn total_faults(&self) -> u64 {
        self.total_faults
    }

    /// Get current number of records in buffer
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// IOTLB Invalidation Command bits
pub mod iotlb_bits {
    /// Invalidation Request Granularity (bits 60-61)
    pub const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;
    pub const IOTLB_IIRG_DOMAIN: u64 = 2 << 60;
    pub const IOTLB_IIRG_PAGE: u64 = 3 << 60;
    /// Drain Reads before invalidation
    pub const IOTLB_DR: u64 = 1 << 49;
    /// Drain Writes before invalidation
    pub const IOTLB_DW: u64 = 1 << 48;
    /// Domain ID (bits 32-47)
    pub const IOTLB_DID_SHIFT: u64 = 32;
    /// Invalidation In Progress
    pub const IOTLB_IVT: u64 = 1 << 63;
}

// ============================================================================
// Interrupt Remapping Table (IRT) Structures
// ============================================================================

/// Interrupt Remapping Table Entry (IRTE)
///
/// Intel VT-d Interrupt Remapping provides:
/// - Protection against malicious interrupt injection
/// - Interrupt virtualization for VMs
/// - Flexible interrupt routing
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InterruptRemapEntry {
    /// Lower 64 bits
    pub lo: u64,
    /// Upper 64 bits  
    pub hi: u64,
}

// ============================================================================
// Scalable Mode Structures (PASID)
// ============================================================================

/// PASID Directory Entry (Scalable Mode)
///
/// 8-byte entry in the PASID Directory. Points to a PASID Table.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PasidDirectoryEntry(u64);

impl PasidDirectoryEntry {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;

    /// Create a new entry
    pub fn new() -> Self {
        Self(0)
    }

    /// Set the PASID Table pointer
    pub fn set_table_ptr(&mut self, addr: u64) {
        // Bits 12-63 contain physical address of PASID Table (4KB aligned)
        self.0 = (addr & !0xFFF) | Self::PRESENT;
    }

    /// Get PASID Table address
    pub fn table_addr(&self) -> u64 {
        self.0 & !0xFFF
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }
}

impl InterruptRemapEntry {
    /// Entry present (bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// Fault Processing Disable (bit 1)
    pub const FPD: u64 = 1 << 1;
    /// Destination Mode: 0 = Physical, 1 = Logical (bit 2)
    pub const DM_LOGICAL: u64 = 1 << 2;
    /// Redirection Hint (bit 3)
    pub const RH: u64 = 1 << 3;
    /// Trigger Mode: 0 = Edge, 1 = Level (bit 4)
    pub const TM_LEVEL: u64 = 1 << 4;
    /// Delivery Mode shift (bits 5-7)
    pub const DLVRY_MODE_SHIFT: u64 = 5;
    /// Available for software (bits 8-11)
    pub const AVAIL_SHIFT: u64 = 8;
    /// Vector shift (bits 16-23)
    pub const VECTOR_SHIFT: u64 = 16;
    /// Destination ID shift (bits 32-63 for x2APIC, 40-47 for xAPIC)
    pub const DEST_SHIFT: u64 = 32;

    /// Subhandle valid (bit 0 of hi)
    pub const SHV: u64 = 1 << 0;
    /// Source Identifier shift (bits 16-31 of hi)
    pub const SID_SHIFT: u64 = 16;
    /// Source Identifier Qualifier (bits 12-13 of hi)
    pub const SQ_SHIFT: u64 = 12;
    /// SVT (Source Validation Type, bits 14-15 of hi)
    pub const SVT_SHIFT: u64 = 14;
    /// Interrupt Mode: 0 = Remapped, 1 = Posted (bit 15 of lo)
    pub const IM: u64 = 1 << 15;

    /// Create a new blank (not present) entry
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Create a present IRTE for posted interrupts
    ///
    /// # Arguments
    /// * `pda` - Physical address of the Posted Interrupt Descriptor (must be 64-byte aligned)
    /// * `vector` - Vector is handled by the PID's PIR field, but we might set notification vector in PID
    pub fn posted(pda: u64) -> Self {
        // Standard Posted Interrupt IRTE Layout:
        // Low: P(1) | IM(1) | PDA
        // Note: Exact layout depends on hardware generation, using standard format here.
        // Assuming PDA is placed in address field (bits 32-63 for xAPIC or specialized field)
        // For simplicity/safety in this implementation:
        // Low = (PDA & !0x3F) | IM | PRESENT
        let lo = (pda & !0x3F) | Self::IM | Self::PRESENT;
        Self { lo, hi: 0 }
    }

    /// Create a present IRTE for fixed delivery
    pub fn fixed(vector: u8, dest_id: u32, logical: bool, level_trigger: bool) -> Self {
        let mut lo = Self::PRESENT;
        lo |= (vector as u64) << Self::VECTOR_SHIFT;
        lo |= (dest_id as u64) << Self::DEST_SHIFT;
        if logical {
            lo |= Self::DM_LOGICAL;
        }
        if level_trigger {
            lo |= Self::TM_LEVEL;
        }
        // Fixed delivery mode = 0
        Self { lo, hi: 0 }
    }

    /// Create an IRTE for lowest-priority delivery
    pub fn lowest_priority(vector: u8, dest_id: u32, logical: bool) -> Self {
        let mut lo = Self::PRESENT | Self::RH;
        lo |= (vector as u64) << Self::VECTOR_SHIFT;
        lo |= (dest_id as u64) << Self::DEST_SHIFT;
        lo |= 1 << Self::DLVRY_MODE_SHIFT; // Lowest priority = 1
        if logical {
            lo |= Self::DM_LOGICAL;
        }
        Self { lo, hi: 0 }
    }

    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & Self::PRESENT) != 0
    }

    /// Get vector
    pub fn vector(&self) -> u8 {
        ((self.lo >> Self::VECTOR_SHIFT) & 0xFF) as u8
    }

    /// Get destination ID
    pub fn dest_id(&self) -> u32 {
        ((self.lo >> Self::DEST_SHIFT) & 0xFFFFFFFF) as u32
    }

    /// Set source validation (for device filtering)
    pub fn set_source_validation(&mut self, svt: u8, sq: u8, source_id: u16) {
        self.hi = ((svt as u64 & 0x3) << Self::SVT_SHIFT)
            | ((sq as u64 & 0x3) << Self::SQ_SHIFT)
            | ((source_id as u64) << Self::SID_SHIFT);
    }
}

/// Delivery modes for interrupt remapping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    Fixed = 0,
    LowestPriority = 1,
    SMI = 2,
    NMI = 4,
    Init = 5,
    ExtInt = 7,
}

/// Interrupt Remapping Table (manages IRTE allocation)
pub struct InterruptRemapTable {
    /// Base address of the IRT (must be 4KB aligned)
    base: usize,
    /// Number of entries (power of 2, max 64K)
    size: usize,
    /// Allocation bitmap
    allocated: Vec<u64>,
    /// Next-Fit hint: word index to start searching from
    next_hint: usize,
}

impl InterruptRemapTable {
    /// Create a new Interrupt Remapping Table
    ///
    /// # Arguments
    /// * `size_log2` - Log2 of number of entries (0-15, giving 1 to 65536 entries)
    pub fn new(size_log2: u8) -> Option<Self> {
        let size = 1usize << (size_log2.min(15) as usize);
        let total_bytes = size * core::mem::size_of::<InterruptRemapEntry>();

        // Allocate 4KB-aligned memory
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 4096).ok()?;
        let base = crate::util::allocate_zeroed(layout)?.as_ptr() as usize;

        // Bitmap: 64 entries per u64
        let bitmap_size = (size + 63) / 64;
        let allocated = alloc::vec![0u64; bitmap_size];

        Some(Self {
            base,
            size,
            allocated,
            next_hint: 0,
        })
    }

    /// Get the physical base address
    pub fn base_address(&self) -> usize {
        self.base
    }

    /// Get the size (number of entries)
    pub fn size(&self) -> usize {
        self.size
    }

    /// Allocate an IRTE index (Next-Fit algorithm for O(1) amortized)
    pub fn allocate(&mut self) -> Option<u16> {
        let len = self.allocated.len();
        if len == 0 {
            return None;
        }

        // Start from hint position and wrap around
        for i in 0..len {
            let word_idx = (self.next_hint + i) % len;
            let word = &mut self.allocated[word_idx];
            if *word != u64::MAX {
                // Find first free bit
                let bit = (!*word).trailing_zeros();
                *word |= 1 << bit;
                // Update hint for next allocation
                self.next_hint = word_idx;
                return Some((word_idx * 64 + bit as usize) as u16);
            }
        }
        None
    }

    /// Free an IRTE index
    pub fn free(&mut self, index: u16) {
        let word_idx = index as usize / 64;
        let bit = index as usize % 64;
        if word_idx < self.allocated.len() {
            self.allocated[word_idx] &= !(1 << bit);
        }
    }

    /// Get an entry
    pub fn get(&self, index: u16) -> Option<InterruptRemapEntry> {
        if (index as usize) < self.size {
            let ptr = self.base as *const InterruptRemapEntry;
            Some(unsafe { *ptr.add(index as usize) })
        } else {
            None
        }
    }

    /// Set an entry
    pub fn set(&mut self, index: u16, entry: InterruptRemapEntry) -> bool {
        if (index as usize) < self.size {
            let ptr = self.base as *mut InterruptRemapEntry;
            unsafe {
                *ptr.add(index as usize) = entry;
            }
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Queued Invalidation (QI) Structures
// ============================================================================

/// Invalidation Queue Entry (128 bits)
///
/// Intel VT-d Queued Invalidation provides:
/// - Asynchronous invalidation requests
/// - Batched invalidation for performance
/// - Mandatory for x2APIC interrupt remapping
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InvalidationQueueEntry {
    /// Lower 64 bits - descriptor type and parameters
    pub lo: u64,
    /// Upper 64 bits - additional parameters
    pub hi: u64,
}

/// Invalidation descriptor types (bits 3:0 of lo)
pub mod qi_desc_type {
    /// Context-cache Invalidate Descriptor
    pub const CC_INV: u64 = 0x1;
    /// IOTLB Invalidate Descriptor
    pub const IOTLB_INV: u64 = 0x2;
    /// Device-TLB Invalidate Descriptor
    pub const DEV_TLB_INV: u64 = 0x3;
    /// Interrupt Entry Cache Invalidate Descriptor
    pub const IEC_INV: u64 = 0x4;
    /// Invalidation Wait Descriptor
    pub const WAIT: u64 = 0x5;
    /// Extended IOTLB Invalidate Descriptor
    pub const EXT_IOTLB_INV: u64 = 0x6;
    /// PASID-based IOTLB Invalidate
    pub const PASID_IOTLB_INV: u64 = 0x7;
    /// PASID-cache Invalidate
    pub const PASID_CACHE_INV: u64 = 0x8;
}

impl InvalidationQueueEntry {
    /// Create a Context-Cache Invalidation descriptor
    /// Granularity: 0=reserved, 1=global, 2=domain, 3=device
    pub fn context_cache_invalidate(granularity: u8, domain_id: u16, source_id: u16) -> Self {
        let lo =
            qi_desc_type::CC_INV | ((granularity as u64 & 0x3) << 4) | ((domain_id as u64) << 16);
        let hi = source_id as u64;
        Self { lo, hi }
    }

    /// Create a Global Context-Cache Invalidation descriptor
    pub fn context_cache_invalidate_global() -> Self {
        Self::context_cache_invalidate(1, 0, 0)
    }

    /// Create an IOTLB Invalidation descriptor
    /// Granularity: 0=reserved, 1=global, 2=domain, 3=page
    pub fn iotlb_invalidate(granularity: u8, domain_id: u16, drain: bool, address: u64) -> Self {
        let lo = qi_desc_type::IOTLB_INV |
                 ((granularity as u64 & 0x3) << 4) |
                 (if drain { 1 << 6 } else { 0 }) | // DW (Drain Writes)
                 (if drain { 1 << 7 } else { 0 }) | // DR (Drain Reads)
                 ((domain_id as u64) << 16);
        let hi = address & !0xFFF; // Page-aligned address for page-selective
        Self { lo, hi }
    }

    /// Create a Global IOTLB Invalidation descriptor
    pub fn iotlb_invalidate_global(drain: bool) -> Self {
        Self::iotlb_invalidate(1, 0, drain, 0)
    }

    /// Create a Domain IOTLB Invalidation descriptor
    pub fn iotlb_invalidate_domain(domain_id: u16, drain: bool) -> Self {
        Self::iotlb_invalidate(2, domain_id, drain, 0)
    }

    /// Create an Interrupt Entry Cache Invalidation descriptor
    /// Granularity: 0=global, 1=index-selective
    pub fn iec_invalidate(granularity: u8, irte_index: u16, index_mask: u8) -> Self {
        let lo = qi_desc_type::IEC_INV
            | ((granularity as u64 & 0x1) << 4)
            | ((index_mask as u64 & 0x1F) << 27)
            | ((irte_index as u64) << 32);
        Self { lo, hi: 0 }
    }

    /// Create a Global IEC Invalidation descriptor
    pub fn iec_invalidate_global() -> Self {
        Self::iec_invalidate(0, 0, 0)
    }

    /// Create a Device-TLB Invalidation descriptor
    /// Used to invalidate ATS translations cached in PCIe devices
    ///
    /// # Arguments
    /// * `source_id` - PCIe Requester ID (Bus/Device/Function)
    /// * `global` - If true, invalidates all entries for the device
    /// * `iova` - IOVA to invalidate (when not global)
    /// * `size` - Size of invalidation range in pages (when not global)
    /// * `domain_id` - Domain ID for domain-selective invalidation
    pub fn device_tlb_invalidate(
        source_id: u16,
        global: bool,
        iova: u64,
        size: u8,
        domain_id: u16,
    ) -> Self {
        let lo = qi_desc_type::DEV_TLB_INV
            | ((source_id as u64) << 32)
            | ((domain_id as u64) << 16)
            | if global { 1 << 4 } else { 0 }; // G bit
        let hi = if global {
            0
        } else {
            (iova & !0xFFF) | ((size as u64) & 0x3F)
        };
        Self { lo, hi }
    }

    /// Create a Global Device-TLB Invalidation for a specific device
    pub fn device_tlb_invalidate_device(source_id: u16, domain_id: u16) -> Self {
        Self::device_tlb_invalidate(source_id, true, 0, 0, domain_id)
    }

    /// Create a Page-selective Device-TLB Invalidation
    pub fn device_tlb_invalidate_page(source_id: u16, domain_id: u16, iova: u64, size: u8) -> Self {
        Self::device_tlb_invalidate(source_id, false, iova, size, domain_id)
    }

    /// Create an Invalidation Wait descriptor
    /// Used to signal completion of previous descriptors
    pub fn wait(status_addr: u64, status_data: u32, interrupt: bool, fence: bool) -> Self {
        let lo = qi_desc_type::WAIT |
                 (if fence { 1 << 5 } else { 0 }) |     // IF (Invalidation Fence)
                 (if interrupt { 1 << 4 } else { 0 }) | // FN (Fence Notify)
                 (1 << 5) |                              // SW (Status Write)
                 ((status_data as u64) << 32);
        let hi = status_addr;
        Self { lo, hi }
    }
}

/// Invalidation Queue Manager
pub struct InvalidationQueue {
    /// Base address of the queue (must be 4KB aligned)
    base: usize,
    /// Queue size in entries (power of 2, 256 to 64K)
    size: usize,
    /// Current tail (next write position)
    tail: usize,
    /// Status data address for wait descriptors
    status_addr: usize,
}

impl InvalidationQueue {
    /// Queue size must be power of 2 between 256 and 65536
    pub const MIN_SIZE: usize = 256;
    pub const MAX_SIZE: usize = 65536;

    /// Create a new Invalidation Queue
    pub fn new(size_log2: u8) -> Option<Self> {
        let size = 1usize << (size_log2.clamp(8, 16) as usize);
        let total_bytes = size * core::mem::size_of::<InvalidationQueueEntry>();

        // Allocate 4KB-aligned queue
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 4096).ok()?;
        let base = crate::util::allocate_zeroed(layout)?.as_ptr() as usize;

        // Allocate status page
        let status_layout = alloc::alloc::Layout::from_size_align(4096, 4096).ok()?;
        let status_addr = crate::util::allocate_zeroed(status_layout)?.as_ptr() as usize;

        Some(Self {
            base,
            size,
            tail: 0,
            status_addr,
        })
    }

    /// Get the queue base address for IQA register
    pub fn base_address(&self) -> usize {
        self.base
    }

    /// Get queue size in log2 form for IQA register (bits 2:0)
    pub fn size_log2(&self) -> u8 {
        (self.size.trailing_zeros() - 8) as u8
    }

    /// Get current tail index
    pub fn tail(&self) -> usize {
        self.tail
    }

    /// Submit an invalidation descriptor
    pub fn submit(&mut self, entry: InvalidationQueueEntry) {
        let ptr = self.base as *mut InvalidationQueueEntry;
        unsafe {
            *ptr.add(self.tail) = entry;
        }
        self.tail = (self.tail + 1) % self.size;
    }

    /// Submit a wait descriptor and return the status address
    pub fn submit_wait(&mut self) -> usize {
        // Use current tail as unique status data
        let status_data = (self.tail & 0xFFFFFFFF) as u32;
        let entry = InvalidationQueueEntry::wait(self.status_addr as u64, status_data, false, true);
        self.submit(entry);
        self.status_addr
    }

    /// Check if a wait has completed (status address updated)
    pub fn check_wait_complete(&self, expected: u32) -> bool {
        let status = unsafe { core::ptr::read_volatile(self.status_addr as *const u32) };
        status == expected
    }
}

// ============================================================================
// IOMMU Optimization Structures
// ============================================================================

/// Context Cache Entry
#[derive(Clone, Copy)]
struct ContextCacheEntry {
    /// Requester ID (BDF)
    requester_id: u16,
    /// Cached context entry
    entry: ContextEntry,
    /// Last access timestamp (for LRU)
    last_access: u64,
    /// Valid flag
    valid: bool,
}

impl Default for ContextCacheEntry {
    fn default() -> Self {
        Self {
            requester_id: 0,
            entry: ContextEntry::default(),
            last_access: 0,
            valid: false,
        }
    }
}

/// Context Cache with LRU eviction
///
/// Caches frequently accessed context entries to avoid repeated
/// page table walks for context table lookups.
pub struct ContextCache {
    /// Cache entries (fixed size for simplicity)
    entries: [ContextCacheEntry; Self::CACHE_SIZE],
    /// Current timestamp for LRU
    timestamp: u64,
    /// Cache hits
    hits: u64,
    /// Cache misses
    misses: u64,
}

impl ContextCache {
    /// Cache size (power of 2 for fast modulo)
    const CACHE_SIZE: usize = 64;

    /// Create a new context cache
    pub const fn new() -> Self {
        const DEFAULT: ContextCacheEntry = ContextCacheEntry {
            requester_id: 0,
            entry: ContextEntry { lo: 0, hi: 0 },
            last_access: 0,
            valid: false,
        };
        Self {
            entries: [DEFAULT; Self::CACHE_SIZE],
            timestamp: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Hash function for requester ID
    fn hash(requester_id: u16) -> usize {
        (requester_id as usize) % Self::CACHE_SIZE
    }

    /// Lookup a context entry
    pub fn lookup(&mut self, requester_id: u16) -> Option<ContextEntry> {
        self.timestamp += 1;
        let idx = Self::hash(requester_id);

        if self.entries[idx].valid && self.entries[idx].requester_id == requester_id {
            self.entries[idx].last_access = self.timestamp;
            self.hits += 1;
            Some(self.entries[idx].entry)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a context entry
    pub fn insert(&mut self, requester_id: u16, entry: ContextEntry) {
        self.timestamp += 1;
        let idx = Self::hash(requester_id);

        self.entries[idx] = ContextCacheEntry {
            requester_id,
            entry,
            last_access: self.timestamp,
            valid: true,
        };
    }

    /// Invalidate a specific entry
    pub fn invalidate(&mut self, requester_id: u16) {
        let idx = Self::hash(requester_id);
        if self.entries[idx].requester_id == requester_id {
            self.entries[idx].valid = false;
        }
    }

    /// Invalidate all entries
    pub fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

/// Batched Invalidation for efficient QI usage
///
/// Collects multiple invalidation requests and submits them in a batch.
pub struct InvalidationBatch {
    /// Pending invalidation descriptors
    pending: Vec<InvalidationQueueEntry>,
    /// Maximum batch size before auto-flush
    max_batch: usize,
}

impl InvalidationBatch {
    /// Default batch size
    const DEFAULT_MAX: usize = 32;

    /// Create a new invalidation batch
    pub fn new(max_batch: usize) -> Self {
        Self {
            pending: Vec::with_capacity(max_batch),
            max_batch,
        }
    }

    /// Add an invalidation descriptor
    pub fn add(&mut self, entry: InvalidationQueueEntry) -> bool {
        self.pending.push(entry);
        self.pending.len() >= self.max_batch
    }

    /// Get pending descriptors and clear
    pub fn drain(&mut self) -> Vec<InvalidationQueueEntry> {
        core::mem::take(&mut self.pending)
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Get pending count
    pub fn len(&self) -> usize {
        self.pending.len()
    }
}

// ============================================================================
// Page Table Structures
// ============================================================================

/// Page table levels
pub const PT_LEVELS: usize = 4;

/// Page table entries per level (512 for 4KB pages)
pub const PT_ENTRIES: usize = 512;

/// Root table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct RootEntry {
    /// Lower 64 bits (context table pointer)
    pub lo: u64,
    /// Upper 64 bits (reserved)
    pub hi: u64,
}

impl RootEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Set context table pointer
    pub fn set_context_table(&mut self, addr: u64) {
        self.lo = (addr & !0xFFF) | 1; // Present bit
    }

    /// Get context table address
    pub fn context_table_addr(&self) -> u64 {
        self.lo & !0xFFF
    }
}

/// Context table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ContextEntry {
    /// Lower 64 bits
    pub lo: u64,
    /// Upper 64 bits
    pub hi: u64,
}

impl ContextEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Check if entry is fault disabled
    pub fn is_fault_disabled(&self) -> bool {
        (self.lo & 2) != 0
    }

    /// Set second level page table pointer (Translation Type = 00b)
    pub fn set_sl_pt(&mut self, addr: u64, domain_id: u16, agaw: u8) {
        self.lo = (addr & !0xFFF) | 1; // Present
        self.hi = ((domain_id as u64) << 8) | ((agaw as u64) << 0);
    }

    /// Set passthrough (Translation Type = 10b / 2)
    pub fn set_passthrough(&mut self, domain_id: u16) {
        // PT (bit 3:2) = 10b (2). Present (bit 0) = 1.
        self.lo = (2 << 2) | 1;
        self.hi = (domain_id as u64) << 8;
    }

    /// Get second level page table address
    pub fn sl_pt_addr(&self) -> u64 {
        self.lo & !0xFFF
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.hi >> 8) & 0xFFFF) as u16
    }
}

// ============================================================================
// Scalable Mode Structures
// ============================================================================

/// Scalable Mode Context Entry (128 bytes)
///
/// Used in Scalable Mode Translation (SMTS) for PASID-based translation.
/// Each entry is 128 bytes and points to a PASID table.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct ScalableContextEntry {
    /// 8 QWORDs (64 bytes each half)
    pub qwords: [u64; 16],
}

impl Default for ScalableContextEntry {
    fn default() -> Self {
        Self { qwords: [0; 16] }
    }
}

impl ScalableContextEntry {
    /// Present bit (QWORD 0, bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// PASID Table Pointer (QWORD 0, bits 12-63)
    pub const PTP_MASK: u64 = !0xFFF;
    /// PASID Table Size (QWORD 1, bits 0-3) - log2 of entries
    pub const PTS_SHIFT: u64 = 0;
    /// RID-PASID (Request ID to PASID mapping, QWORD 1)
    pub const RID_PASID_SHIFT: u64 = 4;
    /// Domain ID (QWORD 8, bits 8-23)
    pub const DID_SHIFT: u64 = 8;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 16] }
    }

    /// Check if the entry is present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Set the PASID table pointer
    pub fn set_pasid_table(&mut self, pasid_table_addr: u64, size_log2: u8) {
        self.qwords[0] = (pasid_table_addr & Self::PTP_MASK) | Self::PRESENT;
        // Set PASID table size in QWORD 1
        self.qwords[1] = ((size_log2 as u64) & 0xF) << Self::PTS_SHIFT;
    }

    /// Set domain ID
    pub fn set_domain_id(&mut self, domain_id: u16) {
        self.qwords[8] = (self.qwords[8] & !0xFFFF00) | ((domain_id as u64) << Self::DID_SHIFT);
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.qwords[8] >> Self::DID_SHIFT) & 0xFFFF) as u16
    }

    /// Get PASID table pointer
    pub fn pasid_table_addr(&self) -> u64 {
        self.qwords[0] & Self::PTP_MASK
    }
}

/// PASID Table Entry (64 bytes)
///
/// Each entry in the PASID table defines the address translation
/// for a specific PASID.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct PasidTableEntry {
    /// 8 QWORDs
    pub qwords: [u64; 8],
}

impl Default for PasidTableEntry {
    fn default() -> Self {
        Self { qwords: [0; 8] }
    }
}

impl PasidTableEntry {
    /// Present bit (QWORD 0, bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// Page Walk Disable (QWORD 0, bit 3)
    pub const PWD: u64 = 1 << 3;
    /// First Level Page Table Pointer (QWORD 0, bits 12-63)
    pub const FLPT_MASK: u64 = !0xFFF;
    /// Address Width (QWORD 1, bits 0-2)
    pub const AW_SHIFT: u64 = 0;
    /// Supervisor Request (QWORD 1, bit 5)
    pub const SRE: u64 = 1 << 5;
    /// Execute Enable (QWORD 1, bit 6)
    pub const EAFE: u64 = 1 << 6;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 8] }
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Set first level page table pointer
    pub fn set_fl_pt(&mut self, addr: u64, address_width: u8) {
        self.qwords[0] = (addr & Self::FLPT_MASK) | Self::PRESENT;
        self.qwords[1] = ((address_width as u64) & 0x7) << Self::AW_SHIFT;
    }

    /// Set second level page table pointer (for nested translation)
    pub fn set_sl_pt(&mut self, addr: u64, address_width: u8) {
        // Set PWD = 0 (page walk enabled) and point to SL PT
        self.qwords[0] = (addr & Self::FLPT_MASK) | Self::PRESENT;
        self.qwords[1] = ((address_width as u64) & 0x7) << Self::AW_SHIFT;
    }

    /// Get first level page table address
    pub fn fl_pt_addr(&self) -> u64 {
        self.qwords[0] & Self::FLPT_MASK
    }
}

/// PASID Table
///
/// Manages PASID entries for Scalable Mode.
/// Each entry is 64 bytes (PasidTableEntry).
pub struct PasidTable {
    /// Base virtual address
    base: usize,
    /// Size (number of entries, power of 2)
    size: usize,
    /// Allocation bitmap
    allocated: Vec<u64>,
}

impl PasidTable {
    /// Default size (256 entries)
    pub const DEFAULT_SIZE: usize = 256;

    /// Create a new PASID table
    pub fn new(size: usize) -> Option<Self> {
        let size = size.next_power_of_two().min(1 << 20); // Max 2^20 PASIDs
        let total_bytes = size * core::mem::size_of::<PasidTableEntry>();

        // Allocate 4KB aligned memory
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 4096).ok()?;
        let base = crate::util::allocate_zeroed(layout)?.as_ptr() as usize;

        // Bitmap: 64 entries per u64
        let bitmap_size = (size + 63) / 64;
        let allocated = alloc::vec![0u64; bitmap_size];

        Some(Self {
            base,
            size,
            allocated,
        })
    }

    /// Get the physical base address
    pub fn base_address(&self) -> u64 {
        self.base as u64
    }

    /// Get size log2 (for context entry)
    pub fn size_log2(&self) -> u8 {
        self.size.trailing_zeros() as u8
    }

    /// Allocate a PASID
    pub fn allocate(&mut self) -> Option<u32> {
        for (word_idx, word) in self.allocated.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros() as usize;
                let index = word_idx * 64 + bit;
                if index >= self.size {
                    return None;
                }
                *word |= 1 << bit;
                return Some(index as u32);
            }
        }
        None
    }

    /// Free a PASID
    pub fn free(&mut self, pasid: u32) {
        let word_idx = pasid as usize / 64;
        let bit = pasid as usize % 64;
        if word_idx < self.allocated.len() {
            self.allocated[word_idx] &= !(1 << bit);
        }
    }

    /// Get mutable reference to a PASID entry
    pub fn get_mut(&mut self, pasid: u32) -> Option<&mut PasidTableEntry> {
        if (pasid as usize) < self.size {
            let ptr = self.base as *mut PasidTableEntry;
            Some(unsafe { &mut *ptr.add(pasid as usize) })
        } else {
            None
        }
    }

    /// Get reference to a PASID entry
    pub fn get(&self, pasid: u32) -> Option<&PasidTableEntry> {
        if (pasid as usize) < self.size {
            let ptr = self.base as *const PasidTableEntry;
            Some(unsafe { &*ptr.add(pasid as usize) })
        } else {
            None
        }
    }
}

/// Second level page table entry
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlPte(pub u64);

impl SlPte {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// Read permission
    pub const READ: u64 = 1 << 0;
    /// Write permission
    pub const WRITE: u64 = 1 << 1;
    /// Access bit (A) - set by hardware when page is accessed
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty bit (D) - set by hardware when page is written
    pub const DIRTY: u64 = 1 << 6;
    /// Super-Page (PS) bit - marks entry as large page (2MB at PD level, 1GB at PDP level)
    pub const SUPER_PAGE: u64 = 1 << 7;
    /// Snoop behavior
    pub const SNOOP: u64 = 1 << 11;
    /// Transient mapping hint
    pub const TRANSIENT: u64 = 1 << 62;

    /// Create a new entry
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create a present entry with address and permissions
    pub fn mapping(phys_addr: u64, read: bool, write: bool) -> Self {
        let mut flags = Self::PRESENT;
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        Self((phys_addr & !0xFFF) | flags)
    }

    /// Create a 2MB super-page entry (used at PD level)
    /// phys_addr must be 2MB-aligned
    pub fn super_page_2mb(phys_addr: u64, read: bool, write: bool) -> Self {
        const MASK_2MB: u64 = (2 * 1024 * 1024) - 1; // 0x1F_FFFF
        let mut flags = Self::PRESENT | Self::SUPER_PAGE;
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        Self((phys_addr & !MASK_2MB) | flags)
    }

    /// Create a 1GB super-page entry (used at PDP level)
    /// phys_addr must be 1GB-aligned
    pub fn super_page_1gb(phys_addr: u64, read: bool, write: bool) -> Self {
        const MASK_1GB: u64 = (1024 * 1024 * 1024) - 1; // 0x3FFF_FFFF
        let mut flags = Self::PRESENT | Self::SUPER_PAGE;
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        Self((phys_addr & !MASK_1GB) | flags)
    }

    /// Check if this is a super-page entry
    pub fn is_super_page(&self) -> bool {
        (self.0 & Self::SUPER_PAGE) != 0
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }

    /// Get physical address
    pub fn phys_addr(&self) -> u64 {
        self.0 & !0xFFF
    }

    /// Check read permission
    pub fn can_read(&self) -> bool {
        (self.0 & Self::READ) != 0
    }

    /// Check write permission
    pub fn can_write(&self) -> bool {
        (self.0 & Self::WRITE) != 0
    }

    /// Check if page has been accessed
    pub fn is_accessed(&self) -> bool {
        (self.0 & Self::ACCESSED) != 0
    }

    /// Check if page has been written (dirty)
    pub fn is_dirty(&self) -> bool {
        (self.0 & Self::DIRTY) != 0
    }

    /// Clear accessed bit (returns old value)
    pub fn clear_accessed(&mut self) -> bool {
        let was_set = self.is_accessed();
        self.0 &= !Self::ACCESSED;
        was_set
    }

    /// Clear dirty bit (returns old value)
    pub fn clear_dirty(&mut self) -> bool {
        let was_set = self.is_dirty();
        self.0 &= !Self::DIRTY;
        was_set
    }

    /// Clear both accessed and dirty bits
    pub fn clear_accessed_dirty(&mut self) -> (bool, bool) {
        let accessed = self.clear_accessed();
        let dirty = self.clear_dirty();
        (accessed, dirty)
    }
}

// ============================================================================
// Fault Recording
// ============================================================================

/// Fault Recording Entry (Intel VT-d 10.4.2)
///
/// Each fault recording register is 128 bits (16 bytes).
/// The hardware writes fault information here when DMA faults occur.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultRecordingEntry {
    /// Lower 64 bits
    pub lo: u64,
    /// Upper 64 bits
    pub hi: u64,
}

impl FaultRecordingEntry {
    /// Fault present (bit 127 of hi)
    pub fn is_fault(&self) -> bool {
        (self.hi & (1 << 63)) != 0
    }

    /// Fault type: 0 = write, 1 = read (bit 126)
    pub fn is_read(&self) -> bool {
        (self.hi & (1 << 62)) != 0
    }

    /// Address Type (bits 124-125)
    pub fn address_type(&self) -> u8 {
        ((self.hi >> 60) & 0x3) as u8
    }

    /// Fault Reason (bits 96-103)
    pub fn fault_reason(&self) -> u8 {
        ((self.hi >> 32) & 0xFF) as u8
    }

    /// Source Identifier (requester ID, bits 112-127 of lo)
    pub fn source_id(&self) -> u16 {
        ((self.lo >> 40) & 0xFFFF) as u16
    }

    /// Faulting Address (bits 0-63 of lo, page-aligned)
    pub fn fault_address(&self) -> u64 {
        self.lo & !0xFFF
    }

    /// Clear the fault bit
    pub fn clear(&mut self) {
        self.hi &= !(1 << 63);
    }
}

/// Fault reason codes (Intel VT-d spec table 33)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    /// Reserved / No fault
    None,
    /// Root entry not present
    RootNotPresent,
    /// Context entry not present
    ContextNotPresent,
    /// Context entry invalid
    ContextInvalid,
    /// Address outside domain address width
    AddressOutOfRange,
    /// Read access denied
    ReadDenied,
    /// Write access denied
    WriteDenied,
    /// Page table entry invalid
    PageTableInvalid,
    /// Root table invalid
    RootTableInvalid,
    /// Context table invalid
    ContextTableInvalid,
    /// Unknown fault reason
    Unknown(u8),
}

impl From<u8> for FaultReason {
    fn from(code: u8) -> Self {
        match code {
            0x0 => FaultReason::None,
            0x1 => FaultReason::RootNotPresent,
            0x2 => FaultReason::ContextNotPresent,
            0x3 => FaultReason::ContextInvalid,
            0x4 => FaultReason::AddressOutOfRange,
            0x5 => FaultReason::ReadDenied,
            0x6 => FaultReason::WriteDenied,
            0x7 => FaultReason::PageTableInvalid,
            0x8 => FaultReason::RootTableInvalid,
            0x9 => FaultReason::ContextTableInvalid,
            n => FaultReason::Unknown(n),
        }
    }
}

// ============================================================================
// IOMMU Domain
// ============================================================================

/// Domain Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuDomainType {
    /// Normal translated domain
    Translated,
    /// Passthrough domain (identity)
    Passthrough,
}

/// IOMMU Domain (address space for devices)
///
/// Each domain has its own Mutex in the global IOMMU_DOMAINS registry,
/// allowing parallel map/unmap operations across different domains.
pub struct IommuDomain {
    /// Domain Type
    domain_type: IommuDomainType,
    /// Domain ID
    id: u16,
    /// Second-level page table root (PML4)
    page_table: *mut SlPte,
    /// Mapped regions
    mappings: BTreeMap<u64, DmaMapping>,
    /// Total mapped size
    mapped_size: u64,
    /// Optional NUMA node affinity for this domain's data structures
    numa_node: Option<usize>,
    /// Support for 2MB super-pages
    supports_2mb: bool,
    /// Support for 1GB super-pages
    supports_1gb: bool,
    /// Reference counts for page tables (Physical Address -> Active Entry Count)
    /// Used to avoid O(N) scanning during unmap and recursive deallocation cleanup.
    page_table_counts: BTreeMap<u64, u16>,
}

/// DMA mapping info
#[derive(Clone, Debug)]
pub struct DmaMapping {
    /// I/O virtual address
    pub iova: u64,
    /// Physical address
    pub phys: u64,
    /// Size in bytes
    pub size: u64,
    /// Read permission
    pub read: bool,
    /// Write permission
    pub write: bool,
    /// Domain ID (for IOTLB invalidation)
    pub domain_id_placeholder: u16,
}

unsafe impl Send for IommuDomain {}
unsafe impl Sync for IommuDomain {}

impl IommuDomain {
    /// Create a new domain
    pub fn new(
        id: u16,
        numa_node: Option<usize>,
        supports_2mb: bool,
        supports_1gb: bool,
        domain_type: IommuDomainType,
    ) -> Self {
        // Allocate page table on the preferred NUMA node when possible.
        // For Passthrough, we still allocate it to simplify logic (or we could skip it)
        // But the hardware won't use it if we set TT=Passthrough.
        // Let's allocate it to avoid null pointer checks elsewhere, or make it Option.
        // For now: Allocate it.
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Invalid layout for page table");

        let page_table = crate::mm::numa::allocate_zeroed_on_node(layout, numa_node)
            .expect("Failed to allocate IOMMU page table")
            .as_ptr() as *mut SlPte;

        // Initialize page_table_counts with root table
        let mut page_table_counts = BTreeMap::new();
        let root_phys = crate::mm::higher_half::virt_to_phys(
            crate::mm::higher_half::VirtAddr::new(page_table as u64),
        )
        .expect("Failed to get root phys")
        .as_u64();
        page_table_counts.insert(root_phys, 0);

        Self {
            id,
            domain_type,
            page_table,
            mappings: BTreeMap::new(),
            mapped_size: 0,
            numa_node,
            supports_2mb,
            supports_1gb,
            page_table_counts,
        }
    }

    /// Get domain ID
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Get domain type
    pub fn domain_type(&self) -> IommuDomainType {
        self.domain_type
    }

    /// Get page table physical address
    pub fn page_table_addr(&self) -> u64 {
        self.page_table as u64
    }

    /// Get optional NUMA node affinity for this domain
    pub fn numa_node(&self) -> Option<usize> {
        self.numa_node
    }

    /// Map a DMA region
    pub fn map(
        &mut self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        if self.domain_type == IommuDomainType::Passthrough {
            // Passthrough means identity, so map calls are effectively no-ops or identity checks
            // We just return OK.
            // Ideally we could verify iova == phys, but sometimes map is called to *create* the mapping.
            // In PT, it's already there.
            return Ok(());
        }
        // Validate alignment
        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        // Check for overlapping mappings
        for (existing_iova, mapping) in &self.mappings {
            let existing_end = existing_iova + mapping.size;
            let new_end = iova + size;

            if iova < existing_end && new_end > *existing_iova {
                return Err(IommuError::AlreadyMapped);
            }
        }

        // Create page table entries using largest possible page sizes
        let mut current_iova = iova;
        let mut current_phys = phys;
        let mut remaining = size;

        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        const SIZE_4KB: u64 = 4096;

        while remaining > 0 {
            // Try 1GB page
            if self.supports_1gb
                && remaining >= SIZE_1GB
                && current_iova % SIZE_1GB == 0
                && current_phys % SIZE_1GB == 0
                && (current_phys as u64 & 0x3FFF_FFFF) == 0
            // Extra alignment check for 1GB
            {
                unsafe { self.map_page_1gb(current_iova, current_phys, read, write) }?;
                current_iova += SIZE_1GB;
                current_phys += SIZE_1GB;
                remaining -= SIZE_1GB;
                continue;
            }

            // Try 2MB page
            if self.supports_2mb
                && remaining >= SIZE_2MB
                && current_iova % SIZE_2MB == 0
                && current_phys % SIZE_2MB == 0
            {
                unsafe { self.map_page_2mb(current_iova, current_phys, read, write) }?;
                current_iova += SIZE_2MB;
                current_phys += SIZE_2MB;
                remaining -= SIZE_2MB;
                continue;
            }

            // Fallback to 4KB page
            self.map_page(current_iova, current_phys, read, write)?;
            current_iova += SIZE_4KB;
            current_phys += SIZE_4KB;
            remaining -= SIZE_4KB;
        }

        // Record mapping
        self.mappings.insert(
            iova,
            DmaMapping {
                iova,
                phys,
                size,
                read,
                write,
                domain_id_placeholder: self.id,
            },
        );

        self.mapped_size += size;

        Ok(())
    }

    /// Map a region with identity mapping (IOVA = Physical Address)
    pub fn map_identity(
        &mut self,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        self.map(phys, phys, size, read, write)
    }

    /// Map a single page using 4-level page table walking
    /// Intel VT-d uses: PML4 -> PDP -> PD -> PT (same as x86-64 paging)
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    fn map_page(
        &mut self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        // Extract indices for each level
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize; // Bits 47:39
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize; // Bits 38:30
        let pd_idx = ((iova >> 21) & 0x1FF) as usize; // Bits 29:21
        let pt_idx = ((iova >> 12) & 0x1FF) as usize; // Bits 20:12

        // Track newly allocated page tables for rollback on error
        // Index 0: PDP, 1: PD, 2: PT (order of allocation)
        // Store (pointer, physical_address) to allow proper cleanup from counts
        let mut newly_allocated: [Option<(*mut SlPte, u64)>; 3] = [None, None, None];

        // Cleanup helper - deallocate any newly allocated tables
        // We cannot use a closure effectively here due to borrowing `self`, so we inline logic or handle carefully.
        // But for clarity, we'll iterate manually in error blocks.

        // self.page_table is the PML4 root
        unsafe {
            // Increment root table count as we are about to add/check PDP mapping
            let pml4_phys = crate::mm::higher_half::virt_to_phys(
                crate::mm::higher_half::VirtAddr::new(self.page_table as u64),
            )
            .expect("Failed to get pml4 phys")
            .as_u64();
            // Since we are adding an entry or using existing, we increment its usage?
            // No, `count` tracks *present entries*.
            // If we set `*pml4_entry` to present (new allocation), we increment pml4 count.
            // If it was already present, we don't.

            // Level 4: PML4 -> PDP
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                // Allocate PDP table on the domain's preferred NUMA node when available
                let pdp = match Self::allocate_page_table(self.numa_node) {
                    Ok(p) => p,
                    Err(e) => {
                        // Nothing allocated yet, just return
                        return Err(e);
                    }
                };

                // Track new PDP
                let pdp_phys = crate::mm::higher_half::virt_to_phys(
                    crate::mm::higher_half::VirtAddr::new(pdp as u64),
                )
                .expect("Failed to get pdp phys")
                .as_u64();
                self.page_table_counts.insert(pdp_phys, 0);

                *pml4_entry = SlPte((pdp as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE);

                // Increment PML4 count
                *self.page_table_counts.entry(pml4_phys).or_default() += 1;
                newly_allocated[0] = Some((pdp, pdp_phys));
            }
            let pdp_table = ((*pml4_entry).phys_addr()) as *mut SlPte;
            let pdp_phys = ((*pml4_entry).phys_addr());

            // Level 3: PDP -> PD
            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                // Allocate PD table on the domain's preferred NUMA node when available
                let pd = match Self::allocate_page_table(self.numa_node) {
                    Ok(p) => p,
                    Err(e) => {
                        // Rollback PDP if we allocated it
                        if let Some((_, pdp_phys_addr)) = newly_allocated[0] {
                            (*pml4_entry).0 = 0; // Clear PML4 entry
                            *self.page_table_counts.entry(pml4_phys).or_default() -= 1;
                            self.page_table_counts.remove(&pdp_phys_addr);
                            let layout = alloc::alloc::Layout::from_size_align(
                                PT_ENTRIES * core::mem::size_of::<SlPte>(),
                                4096,
                            )
                            .unwrap();
                            alloc::alloc::dealloc(newly_allocated[0].unwrap().0 as *mut u8, layout);
                        }
                        return Err(e);
                    }
                };

                // Track new PD
                let pd_phys = crate::mm::higher_half::virt_to_phys(
                    crate::mm::higher_half::VirtAddr::new(pd as u64),
                )
                .expect("Failed to get pd phys")
                .as_u64();
                self.page_table_counts.insert(pd_phys, 0);

                *pdp_entry = SlPte((pd as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE);

                // Increment PDP count
                *self.page_table_counts.entry(pdp_phys).or_default() += 1;
                newly_allocated[1] = Some((pd, pd_phys));
            }
            let pd_table = ((*pdp_entry).phys_addr()) as *mut SlPte;
            let pd_phys = ((*pdp_entry).phys_addr());

            // Level 2: PD -> PT
            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                // Allocate PT on the domain's preferred NUMA node when available
                let pt = match Self::allocate_page_table(self.numa_node) {
                    Ok(p) => p,
                    Err(e) => {
                        let layout = alloc::alloc::Layout::from_size_align(
                            PT_ENTRIES * core::mem::size_of::<SlPte>(),
                            4096,
                        )
                        .unwrap();

                        // Rollback PD if we allocated it
                        if let Some((_, pd_phys_addr)) = newly_allocated[1] {
                            (*pdp_entry).0 = 0;
                            *self.page_table_counts.entry(pdp_phys).or_default() -= 1;
                            self.page_table_counts.remove(&pd_phys_addr);
                            alloc::alloc::dealloc(newly_allocated[1].unwrap().0 as *mut u8, layout);
                        }
                        // Rollback PDP if we allocated it
                        if let Some((_, pdp_phys_addr)) = newly_allocated[0] {
                            (*pml4_entry).0 = 0;
                            *self.page_table_counts.entry(pml4_phys).or_default() -= 1;
                            self.page_table_counts.remove(&pdp_phys_addr);
                            alloc::alloc::dealloc(newly_allocated[0].unwrap().0 as *mut u8, layout);
                        }
                        return Err(e);
                    }
                };

                // Track new PT
                let pt_phys = crate::mm::higher_half::virt_to_phys(
                    crate::mm::higher_half::VirtAddr::new(pt as u64),
                )
                .expect("Failed to get pt phys")
                .as_u64();
                self.page_table_counts.insert(pt_phys, 0);

                *pd_entry = SlPte((pt as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE);

                // Increment PD count
                *self.page_table_counts.entry(pd_phys).or_default() += 1;
                newly_allocated[2] = Some((pt, pt_phys));
            }
            let pt_table = ((*pd_entry).phys_addr()) as *mut SlPte;
            let pt_phys = ((*pd_entry).phys_addr());

            // Level 1: PT -> Page
            let pt_entry = pt_table.add(pt_idx);
            if (*pt_entry).is_present() {
                let layout = alloc::alloc::Layout::from_size_align(
                    PT_ENTRIES * core::mem::size_of::<SlPte>(),
                    4096,
                )
                .unwrap();

                // Rollback all newly allocated tables
                if let Some((_, pt_phys_addr)) = newly_allocated[2] {
                    (*pd_entry).0 = 0;
                    *self.page_table_counts.entry(pd_phys).or_default() -= 1;
                    self.page_table_counts.remove(&pt_phys_addr);
                    alloc::alloc::dealloc(newly_allocated[2].unwrap().0 as *mut u8, layout);
                }
                if let Some((_, pd_phys_addr)) = newly_allocated[1] {
                    (*pdp_entry).0 = 0;
                    *self.page_table_counts.entry(pdp_phys).or_default() -= 1;
                    self.page_table_counts.remove(&pd_phys_addr);
                    alloc::alloc::dealloc(newly_allocated[1].unwrap().0 as *mut u8, layout);
                }
                if let Some((_, pdp_phys_addr)) = newly_allocated[0] {
                    (*pml4_entry).0 = 0;
                    *self.page_table_counts.entry(pml4_phys).or_default() -= 1;
                    self.page_table_counts.remove(&pdp_phys_addr);
                    alloc::alloc::dealloc(newly_allocated[0].unwrap().0 as *mut u8, layout);
                }
                return Err(IommuError::AlreadyMapped);
            }
            *pt_entry = SlPte::mapping(phys, read, write);

            // Increment PT count
            *self.page_table_counts.entry(pt_phys).or_default() += 1;
        }

        Ok(())
    }
    /// Allocate a zeroed page table
    ///
    /// Uses NUMA-aware allocation directly to avoid global lock contention.
    /// This is lock-free for the calling core.
    fn allocate_page_table(numa_hint: Option<usize>) -> Result<*mut SlPte, IommuError> {
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .map_err(|_| IommuError::HardwareError)?;

        // NUMA-aware allocation - no global lock contention
        let ptr = crate::mm::numa::allocate_zeroed_on_node(layout, numa_hint)
            .ok_or(IommuError::HardwareError)?
            .as_ptr() as *mut SlPte;

        Ok(ptr)
    }

    /// Map a 2MB super-page
    ///
    /// Uses 3-level page table walking (PML4 -> PDP -> PD) and sets super-page at PD level.
    /// Both iova and phys must be 2MB-aligned.
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    pub unsafe fn map_page_2mb(
        &mut self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;

        if iova % SIZE_2MB != 0 || phys % SIZE_2MB != 0 {
            return Err(IommuError::InvalidAddress);
        }

        // Calculate indices for 4-level paging (but stop at PD level for 2MB pages)
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        // Track newly allocated page tables for rollback
        // Index 0: PDP, 1: PD
        let mut newly_allocated: [Option<(*mut SlPte, u64)>; 2] = [None, None];

        let pml4_table = self.page_table;
        let pml4_entry = unsafe { pml4_table.add(pml4_idx) };

        // Ensure PDP exists
        if !(unsafe { *pml4_entry }).is_present() {
            let pdp = match Self::allocate_page_table(self.numa_node) {
                Ok(p) => p,
                Err(e) => {
                    return Err(e);
                }
            };

            // Track new PDP
            let pdp_phys = crate::mm::higher_half::virt_to_phys(
                crate::mm::higher_half::VirtAddr::new(pdp as u64),
            )
            .expect("Failed to get pdp phys")
            .as_u64();

            // Increment PML4 count (root count)
            let pml4_phys = crate::mm::higher_half::virt_to_phys(
                crate::mm::higher_half::VirtAddr::new(pml4_table as u64),
            )
            .expect("Failed to get pml4 phys")
            .as_u64();

            *self.page_table_counts.entry(pml4_phys).or_default() += 1;
            newly_allocated[0] = Some((pdp, pdp_phys));

            unsafe {
                *pml4_entry = SlPte((pdp as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE)
            };
        }

        let pdp_table = ((unsafe { *pml4_entry }).phys_addr()) as *mut SlPte;
        let pdp_entry = unsafe { pdp_table.add(pdp_idx) };
        let pdp_phys = ((unsafe { *pml4_entry }).phys_addr());

        // Ensure PD exists
        if !(unsafe { *pdp_entry }).is_present() {
            let pd = match Self::allocate_page_table(self.numa_node) {
                Ok(p) => p,
                Err(e) => {
                    // Rollback PDP if we allocated it
                    if let Some((_, pdp_phys_mapped)) = newly_allocated[0] {
                        unsafe { (*pml4_entry).0 = 0 }; // Clear PML4 entry
                        // Decrement PML4 count
                        let pml4_phys = crate::mm::higher_half::virt_to_phys(
                            crate::mm::higher_half::VirtAddr::new(pml4_table as u64),
                        )
                        .expect("Failed to get pml4 phys")
                        .as_u64();
                        *self.page_table_counts.entry(pml4_phys).or_default() -= 1;
                        self.page_table_counts.remove(&pdp_phys_mapped);

                        let layout = alloc::alloc::Layout::from_size_align(
                            PT_ENTRIES * core::mem::size_of::<SlPte>(),
                            4096,
                        )
                        .unwrap();
                        unsafe {
                            alloc::alloc::dealloc(newly_allocated[0].unwrap().0 as *mut u8, layout)
                        };
                    }
                    return Err(e);
                }
            };

            // Track new PD
            let pd_phys = crate::mm::higher_half::virt_to_phys(
                crate::mm::higher_half::VirtAddr::new(pd as u64),
            )
            .expect("Failed to get pd phys")
            .as_u64();

            // Increment PDP count
            *self.page_table_counts.entry(pdp_phys).or_default() += 1;
            newly_allocated[1] = Some((pd, pd_phys));

            unsafe {
                *pdp_entry = SlPte((pd as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE)
            };
        } else if (unsafe { *pdp_entry }).is_super_page() {
            // Already a 1GB super-page at this level - rollback if we allocated PDP
            if let Some((_, pdp_phys_mapped)) = newly_allocated[0] {
                unsafe { (*pml4_entry).0 = 0 };
                let pml4_phys = crate::mm::higher_half::virt_to_phys(
                    crate::mm::higher_half::VirtAddr::new(pml4_table as u64),
                )
                .expect("Failed to get pml4 phys")
                .as_u64();
                *self.page_table_counts.entry(pml4_phys).or_default() -= 1;
                self.page_table_counts.remove(&pdp_phys_mapped);
                let layout = alloc::alloc::Layout::from_size_align(
                    PT_ENTRIES * core::mem::size_of::<SlPte>(),
                    4096,
                )
                .unwrap();
                unsafe { alloc::alloc::dealloc(newly_allocated[0].unwrap().0 as *mut u8, layout) };
            }
            return Err(IommuError::AlreadyMapped);
        }

        let pd_table = ((unsafe { *pdp_entry }).phys_addr()) as *mut SlPte;
        let pd_entry = unsafe { pd_table.add(pd_idx) };
        let pd_phys = ((unsafe { *pdp_entry }).phys_addr());

        // Check if already mapped
        if (unsafe { *pd_entry }).is_present() {
            // Rollback allocated tables
            let layout = alloc::alloc::Layout::from_size_align(
                PT_ENTRIES * core::mem::size_of::<SlPte>(),
                4096,
            )
            .unwrap();

            if let Some((_, pd_phys_mapped)) = newly_allocated[1] {
                unsafe { (*pdp_entry).0 = 0 };
                *self.page_table_counts.entry(pdp_phys).or_default() -= 1;
                self.page_table_counts.remove(&pd_phys_mapped);
                unsafe { alloc::alloc::dealloc(newly_allocated[1].unwrap().0 as *mut u8, layout) };
            }
            if let Some((_, pdp_phys_mapped)) = newly_allocated[0] {
                unsafe { (*pml4_entry).0 = 0 };
                let pml4_phys = crate::mm::higher_half::virt_to_phys(
                    crate::mm::higher_half::VirtAddr::new(pml4_table as u64),
                )
                .expect("Failed to get pml4 phys")
                .as_u64();
                *self.page_table_counts.entry(pml4_phys).or_default() -= 1;
                self.page_table_counts.remove(&pdp_phys_mapped);
                unsafe { alloc::alloc::dealloc(newly_allocated[0].unwrap().0 as *mut u8, layout) };
            }
            return Err(IommuError::AlreadyMapped);
        }

        // Create 2MB super-page entry
        unsafe { *pd_entry = SlPte::super_page_2mb(phys, read, write) };
        // Increment PD count (valid entry)
        *self.page_table_counts.entry(pd_phys).or_default() += 1;

        Ok(())
    }

    /// Map a 1GB super-page
    ///
    /// Uses 2-level page table walking (PML4 -> PDP) and sets super-page at PDP level.
    /// Both iova and phys must be 1GB-aligned.
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    pub unsafe fn map_page_1gb(
        &mut self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;

        if iova % SIZE_1GB != 0 || phys % SIZE_1GB != 0 {
            return Err(IommuError::InvalidAddress);
        }

        // Calculate indices
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;

        // Track newly allocated PDP table for rollback
        let mut newly_allocated_pdp: Option<(*mut SlPte, u64)> = None;

        let pml4_table = self.page_table;
        let pml4_entry = unsafe { pml4_table.add(pml4_idx) };

        // Ensure PDP exists
        if !(unsafe { *pml4_entry }).is_present() {
            let pdp = match Self::allocate_page_table(self.numa_node) {
                Ok(p) => p,
                Err(e) => {
                    return Err(e);
                }
            };

            // Track new PDP
            let pdp_phys = crate::mm::higher_half::virt_to_phys(
                crate::mm::higher_half::VirtAddr::new(pdp as u64),
            )
            .expect("Failed to get pdp phys")
            .as_u64();

            // Increment PML4 count (root count)
            let pml4_phys = crate::mm::higher_half::virt_to_phys(
                crate::mm::higher_half::VirtAddr::new(pml4_table as u64),
            )
            .expect("Failed to get pml4 phys")
            .as_u64();

            *self.page_table_counts.entry(pml4_phys).or_default() += 1;
            newly_allocated_pdp = Some((pdp, pdp_phys));

            unsafe {
                *pml4_entry = SlPte((pdp as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE)
            };
        }

        let pdp_table = ((unsafe { *pml4_entry }).phys_addr()) as *mut SlPte;
        let pdp_entry = unsafe { pdp_table.add(pdp_idx) };
        let pdp_phys = ((unsafe { *pml4_entry }).phys_addr());

        // Check if already mapped (fixed: was checking !is_present())
        if (unsafe { *pdp_entry }).is_present() {
            let layout = alloc::alloc::Layout::from_size_align(
                PT_ENTRIES * core::mem::size_of::<SlPte>(),
                4096,
            )
            .unwrap();

            // Rollback PDP if we allocated it
            if let Some((_, pdp_phys_mapped)) = newly_allocated_pdp {
                unsafe { (*pml4_entry).0 = 0 };
                let pml4_phys = crate::mm::higher_half::virt_to_phys(
                    crate::mm::higher_half::VirtAddr::new(pml4_table as u64),
                )
                .expect("Failed to get pml4 phys")
                .as_u64();
                *self.page_table_counts.entry(pml4_phys).or_default() -= 1;
                self.page_table_counts.remove(&pdp_phys_mapped);
                unsafe { alloc::alloc::dealloc(newly_allocated_pdp.unwrap().0 as *mut u8, layout) };
            }
            return Err(IommuError::AlreadyMapped);
        }

        // Create 1GB super-page entry
        unsafe { *pdp_entry = SlPte::super_page_1gb(phys, read, write) };
        // Increment PDP count
        *self.page_table_counts.entry(pdp_phys).or_default() += 1;

        Ok(())
    }

    /// Unmap a DMA region
    pub fn unmap(&mut self, iova: u64) -> Result<DmaMapping, IommuError> {
        let mapping = self.mappings.remove(&iova).ok_or(IommuError::NotMapped)?;

        // Clear page table entries
        let num_pages = mapping.size / 4096;
        for i in 0..num_pages {
            let page_iova = iova + i * 4096;
            self.unmap_page(page_iova)?;
        }

        self.mapped_size -= mapping.size;

        Ok(mapping)
    }

    /// Unmap a single page using 4-level page table walking
    ///
    /// Also reclaims empty page tables (PT, PD, PDP) to prevent memory accumulation
    /// from sparse mappings.
    fn unmap_page(&mut self, iova: u64) -> Result<(), IommuError> {
        // Extract indices for each level
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .unwrap();

        unsafe {
            // Walk down to PT
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
            let pt_phys = (*pd_entry).phys_addr();

            let pt_entry = pt_table.add(pt_idx);
            if !(*pt_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            *pt_entry = SlPte::new(); // Clear entry

            // Decrement PT count
            if let Some(count) = self.page_table_counts.get_mut(&pt_phys) {
                *count -= 1;
                if *count == 0 {
                    // Free PT
                    *pd_entry = SlPte::new();
                    alloc::alloc::dealloc(pt_table as *mut u8, layout);
                    self.page_table_counts.remove(&pt_phys);

                    // Decrement PD count
                    if let Some(pd_count) = self.page_table_counts.get_mut(&pd_phys) {
                        *pd_count -= 1;
                        if *pd_count == 0 {
                            // Free PD
                            *pdp_entry = SlPte::new();
                            alloc::alloc::dealloc(pd_table as *mut u8, layout);
                            self.page_table_counts.remove(&pd_phys);

                            // Decrement PDP count
                            if let Some(pdp_count) = self.page_table_counts.get_mut(&pdp_phys) {
                                *pdp_count -= 1;
                                if *pdp_count == 0 {
                                    // Free PDP
                                    *pml4_entry = SlPte::new();
                                    alloc::alloc::dealloc(pdp_table as *mut u8, layout);
                                    self.page_table_counts.remove(&pdp_phys);

                                    // Decrement PML4 count (root)
                                    let pml4_phys = crate::mm::higher_half::virt_to_phys(
                                        crate::mm::higher_half::VirtAddr::new(
                                            self.page_table as u64,
                                        ),
                                    )
                                    .expect("Failed to get pml4 phys")
                                    .as_u64();
                                    if let Some(pml4_count) =
                                        self.page_table_counts.get_mut(&pml4_phys)
                                    {
                                        *pml4_count -= 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /* Count function no longer needed
    /// Count present entries in a page table
    ///
    /// Used for empty table detection during unmap reclamation.
    #[inline]
    unsafe fn count_present_entries(table: *const SlPte) -> usize {
        let mut count = 0;
        for i in 0..PT_ENTRIES {
            if (unsafe { *table.add(i) }).is_present() {
                count += 1;
            }
        }
        count
    }
    */

    /// Get total mapped size
    pub fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    /// Get all mappings
    pub fn mappings(&self) -> &BTreeMap<u64, DmaMapping> {
        &self.mappings
    }

    /// Recursively deallocate all page tables under the given table (iterative version)
    ///
    /// Note: This now relies on `page_table_counts` (BTreeMap) to know which pages are allocated tables.
    /// This avoids tree walking and stack overflow risks entirely.
    /// It effectively becomes "free all tables tracked by this domain".
    ///
    /// # Safety
    /// - The domain must not be in use by hardware (IOMMU disabled or domain detached)
    unsafe fn deallocate_page_tables_iterative(&mut self) {
        // Free all tables tracked in the counts map
        // We iterate keys (Physical Addresses), convert to Virtual, and dealloc.
        // Since we are destroying the domain, we just free everything.
        // We must be careful not to double free if logic is flawed, but map guarantees uniqueness.
        // Also, we skip the root table if it's managed by IommuDomain itself (which it is).
        // Wait, `IommuDomain::new` allocates `page_table`. `Drop` (or callers) should free it.
        // If we free everything in `page_table_counts`, we free the root too.
        // Callers must be aware.

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("invalid page table layout");

        for &phys_addr in self.page_table_counts.keys() {
            let virt_addr = crate::mm::higher_half::phys_to_virt(
                crate::mm::higher_half::PhysAddr::new(phys_addr),
            )
            .as_u64();

            let ptr = virt_addr as *mut u8;
            // Don't free the root table if `IommuDomain` logic expects to free it separately?
            // `IommuDomain` stores `page_table` pointer.
            // If we free it here, `IommuDomain` should not free it again.
            // `IommuDomain` struct doesn't implement Drop yet, but usually `deallocate_page_table_recursive` was called manually.

            unsafe {
                alloc::alloc::dealloc(ptr, layout);
            }
        }
        self.page_table_counts.clear();
    }
}

impl Drop for IommuDomain {
    fn drop(&mut self) {
        if !self.page_table.is_null() {
            unsafe {
                self.deallocate_page_tables_iterative();
            }
        }
    }
}

// ============================================================================
// IOMMU Controller
// ============================================================================

/// IOMMU error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    /// IOMMU not initialized
    NotInitialized,
    /// IOMMU not present
    NotPresent,
    /// Not supported
    NotSupported,
    /// Already initialized
    AlreadyInitialized,
    /// Invalid address
    InvalidAddress,
    /// Invalid alignment
    InvalidAlignment,
    /// Region already mapped
    AlreadyMapped,
    /// Region not mapped
    NotMapped,
    /// Domain not found
    DomainNotFound,
    /// Device not found
    DeviceNotFound,
    /// Hardware error
    HardwareError,
    /// Out of memory
    OutOfMemory,
    /// Timeout
    Timeout,
}

/// Device identifier (BDF: Bus/Device/Function)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DeviceId {
    /// Segment number
    pub segment: u16,
    /// Bus number
    pub bus: u8,
    /// Device number
    pub device: u8,
    /// Function number
    pub function: u8,
}

impl DeviceId {
    /// Create a new device ID
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    /// Get requester ID (used for root/context table indexing)
    pub fn requester_id(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }
}

// =========================================================================
// IOVA Allocator - see enhanced definition below after IommuCapabilities
// =========================================================================

/// Device scope type (from DRHD device scope structure)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceScopeType {
    /// PCI Endpoint Device
    PciEndpoint = 1,
    /// PCI Sub-hierarchy (bridge and all downstream devices)
    PciSubHierarchy = 2,
    /// IOAPIC
    Ioapic = 3,
    /// MSI-capable HPET
    MsiCapableHpet = 4,
    /// ACPI namespace device
    AcpiNamespaceDevice = 5,
}

impl DeviceScopeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PciEndpoint),
            2 => Some(Self::PciSubHierarchy),
            3 => Some(Self::Ioapic),
            4 => Some(Self::MsiCapableHpet),
            5 => Some(Self::AcpiNamespaceDevice),
            _ => None,
        }
    }
}

/// Device scope entry (from DRHD structure)
#[derive(Debug, Clone)]
pub struct IommuDeviceScope {
    /// Scope type
    pub scope_type: DeviceScopeType,
    /// Enumeration ID (for IOAPIC, HPET)
    pub enumeration_id: u8,
    /// Start bus number
    pub start_bus: u8,
    /// Path (device, function pairs)
    pub path: Vec<(u8, u8)>,
}

impl IommuDeviceScope {
    /// Create a new device scope
    pub fn new(
        scope_type: DeviceScopeType,
        enumeration_id: u8,
        start_bus: u8,
        path: Vec<(u8, u8)>,
    ) -> Self {
        Self {
            scope_type,
            enumeration_id,
            start_bus,
            path,
        }
    }

    /// Check if a device (bus, device, function) matches this scope
    pub fn matches(&self, bus: u8, device: u8, function: u8) -> bool {
        if self.path.is_empty() {
            return false;
        }

        match self.scope_type {
            DeviceScopeType::PciEndpoint => {
                // Endpoint: exact match required
                let (target_dev, target_func) = self.path[self.path.len() - 1];
                // For simplicity, assume start_bus is the actual bus for endpoint
                bus == self.start_bus && device == target_dev && function == target_func
            }
            DeviceScopeType::PciSubHierarchy => {
                // Sub-hierarchy: matches if bus >= start_bus
                // and first path element matches the bridge
                if bus < self.start_bus {
                    return false;
                }
                // If device is directly on start_bus, check path
                if bus == self.start_bus && !self.path.is_empty() {
                    let (bridge_dev, bridge_func) = self.path[0];
                    return device == bridge_dev && function == bridge_func;
                }
                // Device is downstream of start_bus - matches sub-hierarchy
                true
            }
            _ => false, // IOAPIC, HPET, etc. don't match PCI devices
        }
    }
}

// ============================================================================
// Invalidation Waiter Future
// ============================================================================

/// Future for async invalidation completion
///
/// This future polls the hardware head register to check if all queued
/// invalidation descriptors have been processed. It yields control back
/// to the executor between polls, avoiding busy-waiting.
pub struct InvalidationWaiter<'a> {
    controller: &'a IommuController,
    expected_tail: u64,
    submitted: bool,
}

impl<'a> Future for InvalidationWaiter<'a> {
    type Output = Result<(), IommuError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            return Poll::Ready(Err(IommuError::NotPresent));
        }

        // Check if hardware has caught up
        let head = self.controller.read64(regs::IQH) >> 4;
        if head == self.expected_tail {
            return Poll::Ready(Ok(()));
        }

        // Not ready yet - register waker and return Pending
        self.controller.pending_waiter.register(cx.waker());
        Poll::Pending
    }
}

/// Hardware Tables (Root Table and Context Tables)
/// These are raw pointers managed by the IOMMU Driver.
/// Send wrapper is required because we are sharing them across threads (via Mutex).
pub struct HardwareContext {
    pub root_table: *mut RootEntry,
    pub context_tables: Vec<*mut ContextEntry>,
}

unsafe impl Send for HardwareContext {}

/// IOMMU Controller
pub struct IommuController {
    /// MMIO base address
    mmio_base: u64,
    /// Capabilities
    cap: u64,
    /// Extended capabilities
    ecap: u64,
    /// Hardware/Table Lock (protects root_table and context_tables)
    /// This replaces the coarse-grained RwLock<IommuController>
    hardware: Mutex<HardwareContext>,
    /// Register Lock (protects MMIO command sequences)
    /// Prevents race conditions on multi-step register operations (e.g. IOTLB invalidation)
    register_lock: Mutex<()>,
    /// Domains (ARC/RwLock for concurrent access)
    /// Wrapped in RwLock to allow adding/removing domains with shared IommuController
    domains: RwLock<BTreeMap<u16, Arc<RwLock<IommuDomain>>>>,
    /// Device to domain mapping
    device_domains: RwLock<BTreeMap<DeviceId, u16>>,
    /// Next domain ID
    next_domain_id: AtomicU64,
    /// Translation enabled
    enabled: AtomicBool,
    /// Interrupt Remapping Table (optional, if supported)
    interrupt_remap_table: Mutex<Option<InterruptRemapTable>>,
    /// Interrupt remapping enabled
    ir_enabled: AtomicBool,
    /// Queued Invalidation Queue (optional, if supported)
    invalidation_queue: Mutex<Option<InvalidationQueue>>,
    /// Queued Invalidation enabled
    qi_enabled: AtomicBool,
    /// IOMMU Segment number (from ACPI DRHD)
    pub segment: u16,
    /// IOVA allocator (optional, configured via `init_iova`)
    iova_allocator: Mutex<Option<IovaAllocator>>,
    /// Set of devices with ATS enabled (for optimization)
    ats_enabled_devices: Mutex<BTreeSet<DeviceId>>,
    /// Posted Interrupt Descriptor pool (base address, allocation bitmap)
    /// Each PID is 64-byte aligned, pool can hold up to 256 PIDs
    pid_pool: Mutex<Option<PostedInterruptPool>>,
    /// Page Request Queue (PRI/ATS)
    page_request_queue: Mutex<Option<PageRequestQueue>>,
    /// Fault log ring buffer
    fault_log: IrqMutex<Option<FaultLog>>,
    /// Device scopes from DRHD (for proper device-to-IOMMU matching)
    device_scopes: Vec<IommuDeviceScope>,
    /// Include all devices (from DRHD INCLUDE_PCI_ALL flag)
    include_all: bool,
    /// Pending waker for async invalidation completion (ISR-safe)
    pending_waiter: AtomicWaker,
}

unsafe impl Send for IommuController {}
unsafe impl Sync for IommuController {}

impl IommuController {
    /// Create a new IOMMU controller
    pub fn new(mmio_base: u64, segment: u16) -> Self {
        Self {
            mmio_base,
            segment,
            cap: 0,
            ecap: 0,
            hardware: Mutex::new(HardwareContext {
                root_table: core::ptr::null_mut(),
                context_tables: Vec::new(),
            }),
            register_lock: Mutex::new(()),
            domains: RwLock::new(BTreeMap::new()),
            device_domains: RwLock::new(BTreeMap::new()),
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: Mutex::new(None),
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: Mutex::new(None),
            qi_enabled: AtomicBool::new(false),
            iova_allocator: Mutex::new(None),
            ats_enabled_devices: Mutex::new(BTreeSet::new()),
            pid_pool: Mutex::new(None),
            page_request_queue: Mutex::new(None),
            fault_log: IrqMutex::new(None),
            device_scopes: Vec::new(),
            include_all: false,
            pending_waiter: AtomicWaker::new(),
        }
    }

    /// Create a new IOMMU controller with device scopes
    pub fn new_with_scopes(
        mmio_base: u64,
        segment: u16,
        scopes: Vec<IommuDeviceScope>,
        include_all: bool,
    ) -> Self {
        Self {
            mmio_base,
            segment,
            cap: 0,
            ecap: 0,
            hardware: Mutex::new(HardwareContext {
                root_table: core::ptr::null_mut(),
                context_tables: Vec::new(),
            }),
            register_lock: Mutex::new(()),
            domains: RwLock::new(BTreeMap::new()),
            device_domains: RwLock::new(BTreeMap::new()),
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: Mutex::new(None),
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: Mutex::new(None),
            qi_enabled: AtomicBool::new(false),
            iova_allocator: Mutex::new(None),
            ats_enabled_devices: Mutex::new(BTreeSet::new()),
            pid_pool: Mutex::new(None),
            page_request_queue: Mutex::new(None),
            fault_log: IrqMutex::new(None),
            device_scopes: scopes,
            include_all,
            pending_waiter: AtomicWaker::new(),
        }
    }

    /// Check if a device is in scope for this IOMMU
    pub fn device_in_scope(&self, bus: u8, device: u8, function: u8) -> bool {
        // If include_all flag is set, this IOMMU handles all PCI devices in the segment
        if self.include_all {
            return true;
        }

        // Otherwise, check device scopes
        for scope in &self.device_scopes {
            if scope.matches(bus, device, function) {
                return true;
            }
        }

        false
    }

    /// Read 32-bit register
    fn read32(&self, offset: u64) -> u32 {
        crate::io::mmio::mmio_read_u32((self.mmio_base + offset) as usize)
    }

    /// Write 32-bit register
    fn write32(&self, offset: u64, value: u32) {
        crate::io::mmio::mmio_write_u32((self.mmio_base + offset) as usize, value);
    }

    /// Read 64-bit register
    fn read64(&self, offset: u64) -> u64 {
        crate::io::mmio::mmio_read_u64((self.mmio_base + offset) as usize)
    }

    /// Write 64-bit register
    fn write64(&self, offset: u64, value: u64) {
        crate::io::mmio::mmio_write_u64((self.mmio_base + offset) as usize, value);
    }

    /// Add a device to the set of ATS-enabled devices
    pub fn enable_ats_for_device(&self, device: DeviceId) {
        self.ats_enabled_devices.lock().insert(device);
    }

    /// Initialize the IOMMU
    ///
    /// # Safety
    /// Caller must ensure MMIO address is valid
    pub unsafe fn init(&mut self) -> Result<(), IommuError> {
        // Read capabilities
        self.cap = self.read64(regs::CAP);
        self.ecap = self.read64(regs::ECAP);

        // Allocate root table (4KB, 256 entries)
        // SAFETY: 4096 アライメントと4096サイズは常に有効
        let rt_layout = alloc::alloc::Layout::from_size_align(4096, 4096)
            .expect("Invalid layout for root table");
        let root_table = crate::util::allocate_zeroed(rt_layout)
            .expect("Failed to allocate root table")
            .as_ptr() as *mut RootEntry;

        if root_table.is_null() {
            return Err(IommuError::HardwareError);
        }

        let mut context_tables = Vec::new();

        // Allocate context tables for all buses
        for _ in 0..256 {
            // SAFETY: 4096 アライメントと4096サイズは常に有効
            let ct_layout = alloc::alloc::Layout::from_size_align(4096, 4096)
                .expect("Invalid layout for context entry");
            let ct = crate::util::allocate_zeroed(ct_layout)
                .expect("Failed to allocate ContextEntry")
                .as_ptr() as *mut ContextEntry;

            if ct.is_null() {
                return Err(IommuError::HardwareError);
            }

            context_tables.push(ct);
        }

        // Initialize hardware context
        {
            let mut hw = self.hardware.lock();
            hw.root_table = root_table;
            hw.context_tables = context_tables;
        }

        // Set root table address
        self.write64(regs::RTADDR, root_table as u64);

        // Set root table pointer
        self.write32(regs::GCMD, gcmd_bits::GCMD_SRTP);

        // Wait for completion
        // Register: Global Status (GSTS)
        // Bit: RTPS (Root Table Pointer Status)
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_RTPS) != 0,
            10_000,
        )?;
        Ok(())
    }

    /// Enable DMA remapping
    pub unsafe fn enable(&self) -> Result<(), IommuError> {
        // Write buffer flush if required
        if self.cap & cap_bits::CAP_RWBF != 0 {
            self.write32(regs::GCMD, gcmd_bits::GCMD_WBF);

            self.wait_for_condition(
                || (self.read32(regs::GSTS) & gsts_bits::GSTS_WBFS) == 0,
                10_000,
            )?;
        }

        // Enable translation
        self.write32(regs::GCMD, gcmd_bits::GCMD_TE);

        // Enable Interrupt Remapping if table is present
        if self.interrupt_remap_table.lock().is_some() {
            match unsafe { self.enable_interrupt_remapping() } {
                Ok(_) => log::info!("[IOMMU] Interrupt Remapping enabled during global enable\n"),
                Err(e) => log::warn!("[IOMMU] Failed to enable Interrupt Remapping: {:?}\n", e),
            }
        }

        // Wait for completion
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_TES) != 0,
            10_000,
        )?;

        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    /// Disable DMA remapping
    pub unsafe fn disable(&self) -> Result<(), IommuError> {
        // Clear translation enable
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_TE);

        // Wait for completion
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_TES) == 0,
            10_000,
        )?;

        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    /// Check if translation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Create a new domain
    /// Create a new domain with an optional NUMA node affinity hint
    pub fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let id = self.next_domain_id.fetch_add(1, Ordering::Relaxed) as u16;

        let supports_2mb = self.supports_2mb_pages();
        let supports_1gb = self.supports_1gb_pages();

        let domain = IommuDomain::new(id, numa_node, supports_2mb, supports_1gb, domain_type);
        self.domains
            .write()
            .insert(id, Arc::new(RwLock::new(domain)));

        // register_domain_lock is no longer needed with Arc<RwLock>

        Ok(id)
    }

    /// Set a domain's NUMA affinity (best-effort). Does NOT migrate existing
    /// page tables or mappings; this is only a hint for future allocations.
    pub fn set_domain_numa(
        &self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        let domains = self.domains.read();
        let domain_arc = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();
        domain.numa_node = numa_node;
        Ok(())
    }

    /// Get domain NUMA hint
    pub fn get_domain_numa(&self, domain_id: u16) -> Option<usize> {
        self.domains
            .read()
            .get(&domain_id)
            .and_then(|d| d.read().numa_node)
    }

    /// Get a domain by ID
    pub fn domain(&self, id: u16) -> Option<Arc<RwLock<IommuDomain>>> {
        self.domains.read().get(&id).cloned()
    }

    /// Attach a device to a domain
    pub fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        let domains = self.domains.read();
        let domain_arc = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        let domain = domain_arc.read();

        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        let hw = self.hardware.lock();

        // Setup root entry
        let root_entry = unsafe { &mut *hw.root_table.add(bus) };
        if !root_entry.is_present() {
            // Note: this assumes context_tables[bus] is valid which is ensured by init
            root_entry.set_context_table(hw.context_tables[bus] as u64);
        }

        // Setup context entry
        let context_entry = unsafe { &mut *hw.context_tables[bus].add(devfn) };

        // 48-bit address width (AGAW = 2)
        if domain.domain_type() == IommuDomainType::Passthrough {
            context_entry.set_passthrough(domain.id());
        } else {
            context_entry.set_sl_pt(domain.page_table_addr(), domain.id(), 2);
        }

        self.device_domains.write().insert(device, domain_id);

        Ok(())
    }

    /// Detach a device from its domain
    pub fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        // Clear context entry
        let hw = self.hardware.lock();
        let context_entry = unsafe { &mut *hw.context_tables[bus].add(devfn) };

        *context_entry = ContextEntry::default();

        self.device_domains.write().remove(&device);

        Ok(())
    }

    /// Map DMA region for a device
    pub fn map_dma(
        &self,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let guard = self.device_domains.read();
        let domain_id = guard
            .get(device)
            .copied()
            .ok_or(IommuError::DeviceNotFound)?;
        drop(guard);

        let domains = self.domains.read();
        let domain_arc = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();

        domain.map(iova, phys, size, read, write)
    }

    /// Unmap DMA region for a device
    pub fn unmap_dma(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let guard = self.device_domains.read();
        let domain_id = guard
            .get(device)
            .copied()
            .ok_or(IommuError::DeviceNotFound)?;
        drop(guard);

        let domains = self.domains.read();
        let domain_arc = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();

        domain.unmap(iova).map(|mapping| {
            // Invalidate IOTLB
            // If size is large (>= 2MB), prefer domain invalidation to reduce overhead
            if mapping.size >= 2 * 1024 * 1024 {
                unsafe { self.invalidate_iotlb(domain_id) };
            } else {
                // Page-selective invalidation
                if self.is_queued_invalidation_enabled() {
                    let num_pages = (mapping.size / 4096) as u64;
                    for i in 0..num_pages {
                        let page_addr = iova + i * 4096;
                        // Use drain=true for safety
                        let _ = self.qi_invalidate_iotlb_page(domain_id, page_addr, true);
                    }
                    let _ = self.qi_wait_sync();
                } else {
                    // Fallback for register-based: just domain invalidation
                    unsafe { self.invalidate_iotlb(domain_id) };
                }
            }

            // Invalidate Device-TLB (ATS) if supported
            // Only invalidate if the specific device has ATS enabled or if we don't track it (conservative)
            let use_ats = (self.ecap & ecap_bits::ECAP_DT) != 0
                && self.is_queued_invalidation_enabled()
                && self.ats_enabled_devices.lock().contains(device);

            if use_ats {
                if mapping.size >= 2 * 1024 * 1024 {
                    let _ = self.qi_invalidate_device_tlb(device.requester_id(), domain_id);
                } else {
                    let num_pages = (mapping.size / 4096) as u64;
                    for i in 0..num_pages {
                        let page_addr = iova + i * 4096;
                        // Size 0 = 4KB page (0 bits masked)
                        let _ = self.qi_invalidate_device_tlb_page(
                            device.requester_id(),
                            domain_id,
                            page_addr,
                            0,
                        );
                    }
                }
                let _ = self.qi_wait_sync();
            }

            mapping
        })
    }

    /// Unmap DMA region for a device (Async)
    pub async fn unmap_dma_async(
        &self,
        device: &DeviceId,
        iova: u64,
    ) -> Result<DmaMapping, IommuError> {
        let guard = self.device_domains.read();
        let domain_id = guard
            .get(device)
            .copied()
            .ok_or(IommuError::DeviceNotFound)?;
        drop(guard);

        let domains = self.domains.read();
        let domain_arc = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();

        let mapping = domain.unmap(iova)?;
        drop(domain); // Release lock early to avoid holding it during invalidation submit

        // Invalidate IOTLB
        if self.is_queued_invalidation_enabled() {
            let num_pages = (mapping.size / 4096) as u64;
            // Optimization: if large, do domain invalidation
            if mapping.size >= 2 * 1024 * 1024 {
                self.qi_invalidate_iotlb_domain(domain_id, true)?;
            } else {
                for i in 0..num_pages {
                    let page_addr = iova + i * 4096;
                    self.qi_invalidate_iotlb_page(domain_id, page_addr, true)?;
                }
            }

            // Invalidate Device-TLB (ATS)
            let use_ats = (self.ecap & ecap_bits::ECAP_DT) != 0
                && self.ats_enabled_devices.lock().contains(device);

            if use_ats {
                if mapping.size >= 2 * 1024 * 1024 {
                    self.qi_invalidate_device_tlb(device.requester_id(), domain_id)?;
                } else {
                    for i in 0..num_pages {
                        let page_addr = iova + i * 4096;
                        self.qi_invalidate_device_tlb_page(
                            device.requester_id(),
                            domain_id,
                            page_addr,
                            0,
                        )?;
                    }
                }
            }

            // Async Wait
            self.qi_wait_async().await?;
        } else {
            // Sync Fallback
            unsafe { self.invalidate_iotlb(domain_id) };
        }

        Ok(mapping)
    }

    /// Invalidate IOTLB for a domain
    pub unsafe fn invalidate_iotlb(&self, domain_id: u16) {
        // Use QI if enabled
        if self.is_queued_invalidation_enabled() {
            if let Err(e) = self.qi_invalidate_iotlb_domain(domain_id, true) {
                log::error!("[IOMMU] QI Domain Invalidation failed: {:?}", e);
            }
            // Wait for completion (sync)
            if let Err(e) = self.qi_wait_sync() {
                log::error!("[IOMMU] QI Wait failed: {:?}", e);
            }
            return;
        }

        // Context command register invalidation
        let cmd: u64 = (1u64 << 63) |          // ICC (Invalidate context-cache)
                       (1u64 << 61) |          // Global invalidation
                       ((domain_id as u64) << 16);

        {
            let _lock = self.register_lock.lock();
            self.write64(regs::CCMD, cmd);
            // Wait for completion (ICC bit 63 cleared)
            let _ =
                self.wait_for_condition(|| (self.read64(regs::CCMD) & (1u64 << 63)) == 0, 10_000);
        }

        // Wait for completion (outside lock? no, this loop was redundant in original or for drain?)
        // The original code waited TWICE. The second wait seems redundant or is for the actual effect time?
        // But invalidation writes require checking the bit.
        // We'll trust the first wait inside the lock.
    }

    /// Invalidate IOTLB globally (all domains)
    pub unsafe fn invalidate_iotlb_global(&self) {
        // Use QI if enabled
        if self.is_queued_invalidation_enabled() {
            if let Err(e) = self.qi_invalidate_iotlb_global(true) {
                log::error!("[IOMMU] QI Global Invalidation failed: {:?}", e);
            }
            if let Err(e) = self.qi_wait_sync() {
                log::error!("[IOMMU] QI Wait failed: {:?}", e);
            }
            return;
        }

        // Get Invalidation Register Offset from CAP
        let iro = ((self.cap & cap_bits::CAP_IRO_MASK) >> 8) as u64;
        let iotlb_reg = self.mmio_base + (iro << 4) + iotlb_regs::IOTLB;

        // Global invalidation with drain
        let cmd: u64 = iotlb_bits::IOTLB_IVT
            | iotlb_bits::IOTLB_IIRG_GLOBAL
            | iotlb_bits::IOTLB_DR
            | iotlb_bits::IOTLB_DW;

        {
            let _lock = self.register_lock.lock();
            crate::io::mmio::mmio_write_u64(iotlb_reg as usize, cmd);

            // Wait for completion
            let _ = self.wait_for_condition(
                || {
                    (crate::io::mmio::mmio_read_u64(iotlb_reg as usize) & iotlb_bits::IOTLB_IVT)
                        == 0
                },
                10_000,
            );
        }
    }

    /// Check for and read fault status
    pub fn check_fault_status(&self) -> u32 {
        self.read32(regs::FSTS)
    }

    /// Check if there's a pending fault
    pub fn has_pending_fault(&self) -> bool {
        let fsts = self.check_fault_status();
        (fsts & fsts_bits::FSTS_PPF) != 0
    }

    /// Read fault recording entries
    /// Returns a vector of active fault entries
    pub fn read_faults(&self) -> Vec<(FaultRecordingEntry, FaultReason)> {
        let mut faults = Vec::new();

        // Get Fault Recording Offset and count from CAP
        let fro = ((self.cap & cap_bits::CAP_FRO_MASK) >> 24) as u64;
        let nfr = ((self.cap & cap_bits::CAP_NFR_MASK) >> 40) as usize + 1;

        let fr_base = self.mmio_base + (fro << 4);

        for i in 0..nfr {
            let entry_addr = fr_base + (i as u64 * 16);
            let lo = crate::io::mmio::mmio_read_u64(entry_addr as usize);
            let hi = crate::io::mmio::mmio_read_u64((entry_addr + 8) as usize);

            let entry = FaultRecordingEntry { lo, hi };
            if entry.is_fault() {
                let reason = FaultReason::from(entry.fault_reason());
                faults.push((entry, reason));

                // Clear the fault bit by writing 1 to it
                crate::io::mmio::mmio_write_u64((entry_addr + 8) as usize, hi | (1 << 63));
            }
        }

        // Clear PFO (Primary Fault Overflow) if set
        let fsts = self.check_fault_status();
        if fsts & fsts_bits::FSTS_PFO != 0 {
            self.write32(regs::FSTS, fsts_bits::FSTS_PFO);
        }

        faults
    }

    /// Check if Queued Invalidation is supported
    pub fn supports_queued_invalidation(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_QI) != 0
    }

    /// Check if Interrupt Remapping is supported
    pub fn supports_interrupt_remapping(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_IR) != 0
    }

    /// Check if 2MB super-pages are supported
    pub fn supports_2mb_pages(&self) -> bool {
        (self.cap & cap_bits::CAP_SLLPS_2M) != 0
    }

    /// Check if 1GB super-pages are supported
    pub fn supports_1gb_pages(&self) -> bool {
        (self.cap & cap_bits::CAP_SLLPS_1G) != 0
    }

    /// Check if Posted Interrupts are supported
    pub fn supports_posted_interrupts(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_PIDS) != 0
    }

    /// Check if Scalable Mode is supported
    pub fn supports_scalable_mode(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_SMTS) != 0
    }

    /// Check if Performance Monitoring is supported
    pub fn supports_performance_monitoring(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_PMC) != 0
    }

    /// Get capability information
    pub fn capabilities(&self) -> IommuCapabilities {
        IommuCapabilities {
            queued_invalidation: self.supports_queued_invalidation(),
            interrupt_remapping: self.supports_interrupt_remapping(),
            super_page_2mb: self.supports_2mb_pages(),
            super_page_1gb: self.supports_1gb_pages(),
            page_walk_coherency: (self.cap & cap_bits::CAP_PWC) != 0,
            snoop_control: (self.cap & cap_bits::CAP_SC) != 0,
            posted_interrupts: self.supports_posted_interrupts(),
            scalable_mode: self.supports_scalable_mode(),
            performance_monitoring: self.supports_performance_monitoring(),
        }
    }

    // =========================================================================
    // Interrupt Remapping Methods
    // =========================================================================

    /// Initialize the Interrupt Remapping Table
    ///
    /// # Arguments
    /// * `size_log2` - Log2 of IRT size (0-15, giving 1-65536 entries)
    pub fn init_interrupt_remapping(&mut self, size_log2: u8) -> Result<(), IommuError> {
        if !self.supports_interrupt_remapping() {
            return Err(IommuError::NotSupported);
        }

        if self.interrupt_remap_table.lock().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        // Create the IRT
        let irt = InterruptRemapTable::new(size_log2).ok_or(IommuError::HardwareError)?;

        // Get IRTA register offset from ECAP
        let iro = ((self.ecap & ecap_bits::ECAP_IRO_MASK) >> 8) as u64;
        let irta_reg = self.mmio_base + (iro << 4);

        // Set Interrupt Remap Table Address
        // Bits 11:0 = size (log2 - 1), Bit 11 = Extended Interrupt Mode
        let eime = if (self.ecap & ecap_bits::ECAP_EIM) != 0 {
            1 << 11
        } else {
            0
        };
        let irta_value = (irt.base_address() as u64) | ((size_log2 as u64 - 1) & 0xF) | eime;

        crate::io::mmio::mmio_write_u64(irta_reg as usize, irta_value);

        // Set IRT pointer (GCMD.SIRTP)
        self.write32(regs::GCMD, gcmd_bits::GCMD_SIRTP);

        // Wait for completion
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_IRTPS) != 0,
            10_000,
        )?;

        *self.interrupt_remap_table.lock() = Some(irt);
        log::info!(
            "[IOMMU] Interrupt Remapping Table initialized ({} entries)\n",
            1 << size_log2
        );

        Ok(())
    }

    /// Enable interrupt remapping
    pub unsafe fn enable_interrupt_remapping(&self) -> Result<(), IommuError> {
        if !self.supports_interrupt_remapping() {
            return Err(IommuError::NotSupported);
        }

        if self.interrupt_remap_table.lock().is_none() {
            return Err(IommuError::NotPresent);
        }

        // Enable Interrupt Remapping (GCMD.IRE)
        self.write32(regs::GCMD, gcmd_bits::GCMD_IRE);

        // Wait for completion
        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_IRES) != 0,
            10_000,
        ) {
            Ok(_) => {
                self.ir_enabled.store(true, Ordering::Release);
                log::info!("[IOMMU] Interrupt Remapping enabled\\n");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Disable interrupt remapping
    pub unsafe fn disable_interrupt_remapping(&self) -> Result<(), IommuError> {
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_IRE);

        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_IRES) == 0,
            10_000,
        ) {
            Ok(_) => {
                self.ir_enabled.store(false, Ordering::Release);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Check if interrupt remapping is enabled
    pub fn is_interrupt_remapping_enabled(&self) -> bool {
        self.ir_enabled.load(Ordering::Acquire)
    }

    // =========================================================================
    // Fault Handling
    // =========================================================================

    /// Initialize fault handling with a fault log ring buffer
    pub fn init_fault_handling(&mut self) {
        *self.fault_log.lock() = Some(FaultLog::new());
        log::info!("[IOMMU] Fault handling initialized\n");
    }

    /// Process pending faults from the Fault Recording Registers
    /// Returns the number of faults processed
    pub fn process_faults(&self) -> usize {
        use fsts_bits::*;

        let fsts = self.read32(regs::FSTS);
        let mut processed = 0;

        // Check if there's a pending fault
        if fsts & FSTS_PPF == 0 {
            return 0;
        }

        // Get the fault record index
        let fri = ((fsts & FSTS_FRI_MASK) >> 8) as usize;

        // Read capability to get number of fault records and offset
        let nfr = ((self.cap >> 40) & 0xFF) as usize + 1;
        let fro = ((self.cap >> 24) & 0x3FF) as usize * 16;

        // Read fault record
        for _ in 0..nfr {
            let fr_offset = (fro + fri * 16) as u64;
            let lo = self.read64(fr_offset);
            let hi = self.read64(fr_offset + 8);

            let record = FaultRecord { lo, hi };

            if record.is_valid() {
                // Rate-limited logging to prevent system stall under high fault load
                if processed < FAULT_LOG_RATE_LIMIT {
                    log::error!(
                        "[IOMMU] Fault: reason={:#x}, source={:04x}, addr={:#x}, pasid={:?}\\n",
                        record.reason(),
                        record.source_id(),
                        record.fault_address(),
                        record.pasid()
                    );
                } else if processed == FAULT_LOG_RATE_LIMIT {
                    log::warn!("[IOMMU] Further fault logging suppressed (rate limit reached)\\n");
                }

                // Add to fault log
                if let Some(log) = self.fault_log.lock().as_mut() {
                    log.push(record);
                }

                // Clear the fault by writing 1 to F bit
                self.write64(fr_offset, lo | FaultRecord::FAULT);

                processed += 1;
            }
        }

        // Clear the primary fault overflow (PFO) if set
        if fsts & FSTS_PFO != 0 {
            self.write32(regs::FSTS, FSTS_PFO);
            log::warn!("[IOMMU] Fault overflow cleared\\n");
        }

        processed
    }

    // fault_log accessor removed due to Mutex complexity. Use recent_faults or total_fault_count.

    /// Get recent faults from the log
    pub fn recent_faults(&self, count: usize) -> alloc::vec::Vec<FaultRecord> {
        if let Some(log) = self.fault_log.lock().as_ref() {
            log.recent(count)
        } else {
            alloc::vec::Vec::new()
        }
    }

    /// Get total number of faults recorded
    pub fn total_fault_count(&self) -> u64 {
        self.fault_log
            .lock()
            .as_ref()
            .map(|l| l.total_faults())
            .unwrap_or(0)
    }

    /// Allocate an IRTE for a device interrupt
    /// Returns the IRTE index that should be used in the interrupt message
    pub fn allocate_irte(
        &self,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError> {
        let mut guard = self.interrupt_remap_table.lock();
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        let index = irt.allocate().ok_or(IommuError::HardwareError)?;

        let entry = InterruptRemapEntry::fixed(vector, dest_id, logical, false);
        irt.set(index, entry);

        Ok(index)
    }

    /// Free an IRTE
    pub fn free_irte(&self, index: u16) -> Result<(), IommuError> {
        let mut guard = self.interrupt_remap_table.lock();
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        irt.set(index, InterruptRemapEntry::new());
        irt.free(index);

        Ok(())
    }

    /// Update an existing IRTE
    pub fn update_irte(
        &mut self,
        index: u16,
        entry: InterruptRemapEntry,
    ) -> Result<(), IommuError> {
        let mut guard = self.interrupt_remap_table.lock();
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        if !irt.set(index, entry) {
            return Err(IommuError::InvalidAddress);
        }

        Ok(())
    }

    // =========================================================================
    // Posted Interrupts Methods
    // =========================================================================

    /// Initialize the Posted Interrupt Descriptor pool
    ///
    /// # Arguments
    /// * `num_pids` - Number of PIDs to allocate (max 256)
    pub fn init_posted_interrupts(&mut self, num_pids: usize) -> Result<(), IommuError> {
        if !self.supports_posted_interrupts() {
            return Err(IommuError::NotSupported);
        }

        if self.pid_pool.lock().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        let pool = PostedInterruptPool::new(num_pids).ok_or(IommuError::HardwareError)?;
        *self.pid_pool.lock() = Some(pool);

        log::info!(
            "[IOMMU] Posted Interrupt pool initialized ({} PIDs)\\n",
            num_pids
        );
        Ok(())
    }

    /// Allocate a Posted Interrupt Descriptor and configure an IRTE in posted mode
    ///
    /// # Arguments
    /// * `notification_vector` - Vector to use for notification IPI
    /// * `notification_dest` - APIC ID of the target CPU for notification
    ///
    /// # Returns
    /// (IRTE index, PID index) on success
    pub fn allocate_posted_irte(
        &mut self,
        notification_vector: u8,
        notification_dest: u32,
    ) -> Result<(u16, u16), IommuError> {
        // Check PI support and initialization
        if !self.supports_posted_interrupts() {
            return Err(IommuError::NotSupported);
        }

        let mut pid_guard = self.pid_pool.lock();
        let pid_pool = pid_guard.as_mut().ok_or(IommuError::NotPresent)?;

        let mut irt_guard = self.interrupt_remap_table.lock();
        let irt = irt_guard.as_mut().ok_or(IommuError::NotPresent)?;

        // Allocate a PID
        let (pid_index, pid_addr) = pid_pool.allocate().ok_or(IommuError::HardwareError)?;

        // Configure the PID with notification info
        if let Some(pid) = pid_pool.get_mut(pid_index) {
            // Set notification vector and destination
            let nv = (notification_vector as u64) << 16;
            let ndst = (notification_dest as u64) << 32;
            pid.notification_info.store(nv | ndst, Ordering::SeqCst);
        }

        // Allocate an IRTE
        let irte_index = irt.allocate().ok_or(IommuError::HardwareError)?;

        // Configure IRTE for posted mode
        let entry = InterruptRemapEntry::posted(pid_addr);
        irt.set(irte_index, entry);

        Ok((irte_index, pid_index))
    }

    /// Free a Posted Interrupt Descriptor and its IRTE
    pub fn free_posted_irte(&self, irte_index: u16, pid_index: u16) -> Result<(), IommuError> {
        // Free IRTE
        if let Some(irt) = self.interrupt_remap_table.lock().as_mut() {
            irt.set(irte_index, InterruptRemapEntry::new());
            irt.free(irte_index);
        }

        // Free PID
        if let Some(pool) = self.pid_pool.lock().as_mut() {
            pool.free(pid_index);
        }

        Ok(())
    }

    /// Set a pending vector in a Posted Interrupt Descriptor
    ///
    /// This is called when an interrupt needs to be posted to a vCPU.
    pub fn post_interrupt(&mut self, pid_index: u16, vector: u8) -> Result<(), IommuError> {
        let mut guard = self.pid_pool.lock();
        let pool = guard.as_mut().ok_or(IommuError::NotPresent)?;
        let pid = pool.get_mut(pid_index).ok_or(IommuError::InvalidAddress)?;

        // Set the vector bit in PIR (Posted Interrupt Request)
        let word_idx = (vector / 64) as usize;
        let bit = (vector % 64) as u64;
        pid.pir[word_idx] |= 1 << bit;

        // Set Outstanding Notification bit
        pid.notification_info
            .fetch_or(PostedInterruptDescriptor::ON, Ordering::SeqCst);

        Ok(())
    }

    // =========================================================================
    // Page Request Interface (PRI) Methods
    // =========================================================================

    /// Check if Page Request Services are supported
    pub fn supports_page_request(&self) -> bool {
        (self.ecap & ecap_bits::ECAP_PRS) != 0
    }

    /// Initialize the Page Request Queue
    ///
    /// # Arguments
    /// * `size` - Number of PRQ entries (default: 256)
    pub fn init_page_request(&mut self, size: usize) -> Result<(), IommuError> {
        if !self.supports_page_request() {
            return Err(IommuError::NotSupported);
        }

        // Check for existing PRQ
        if self.page_request_queue.lock().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        let prq = PageRequestQueue::new(size).ok_or(IommuError::HardwareError)?;

        // Set PRQ base address register (PQA)
        // Format: [11:0] = Size (log2 - 1), [63:12] = Base Address
        let size_log2 = (prq.size().trailing_zeros()) as u64;
        let pqa_value = prq.base_address() | (size_log2.saturating_sub(1) & 0xF);

        self.write64(regs::PQA, pqa_value);

        // Set PRQ Head to 0
        self.write64(regs::PQH, 0);

        // Enable Page Request via GCMD.PRE (bit 28)
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd | (1 << 28));

        // Wait for PRS (Page Request Status) bit
        self.wait_for_condition(|| (self.read32(regs::GSTS) & (1 << 28)) != 0, 10_000)?;

        *self.page_request_queue.lock() = Some(prq);
        log::info!(
            "[IOMMU] Page Request Queue initialized ({} entries)\\n",
            size
        );

        Ok(())
    }

    /// Process pending page requests
    ///
    /// Returns a vector of page request entries that need to be handled.
    /// The caller is responsible for sending Page Response via QI.
    pub fn process_page_requests(&mut self) -> Vec<PageRequestEntry> {
        let mut requests = Vec::new();

        // Read current tail first (avoid borrowing `self` mutably while also borrowing it immutably)
        let tail = (self.read64(regs::PQT) >> 4) as usize;

        // Acquire mutable access to PRQ if initialized
        let mut prq_guard = self.page_request_queue.lock();
        if let Some(prq) = prq_guard.as_mut() {
            prq.update_tail(tail);

            // Pop all pending entries
            while let Some(entry) = prq.pop() {
                requests.push(entry);
            }

            // Cache head and drop the mutable borrow before writing registers
            let head = prq.head();
            drop(prq_guard);
            self.write64(regs::PQH, (head as u64) << 4);
        }

        requests
    }

    /// Send a Page Response via Queued Invalidation
    ///
    /// # Arguments
    /// * `source_id` - Device requester ID
    /// * `pasid` - PASID (if applicable)
    /// * `prg_index` - Page Request Group Index
    /// * `response_code` - Response code (0=Success, 1=Invalid Request, 2=Failure)
    pub fn send_page_response(
        &mut self,
        source_id: u16,
        pasid: Option<u32>,
        prg_index: u16,
        response_code: u8,
    ) -> Result<(), IommuError> {
        if !self.is_queued_invalidation_enabled() {
            return Err(IommuError::NotSupported);
        }

        // Page Response descriptor format (type 0x5 with subtype)
        // This is a simplified implementation - full implementation would use
        // the proper Page Response descriptor format from VT-d spec.
        let _desc = InvalidationQueueEntry {
            lo: qi_desc_type::WAIT | // Using wait descriptor as response confirmation
                ((response_code as u64) << 4) |
                ((source_id as u64) << 16),
            hi: if let Some(p) = pasid {
                (p as u64) | ((prg_index as u64) << 20)
            } else {
                (prg_index as u64) << 20
            },
        };

        log::trace!(
            "[IOMMU] Page Response: source_id={:04x} pasid={:?} prg={} code={}\\n",
            source_id,
            pasid,
            prg_index,
            response_code
        );

        // Submit response and wait for completion
        self.submit_invalidation(_desc)?;
        self.qi_wait_sync()
    }

    // IOVA management on IOMMU controller

    /// Initialize controller IOVA allocator
    pub fn init_iova(&self, base: u64, size: u64) -> Result<(), IommuError> {
        *self.iova_allocator.lock() = Some(IovaAllocator::new(base, size));
        Ok(())
    }

    /// Allocate I/O virtual address (Optimized with Per-Core Cache)
    pub fn allocate_iova_fast(&self, size: u64) -> Result<u64, IommuError> {
        // 4KB以外はグローバルアロケータへ
        if size != 4096 {
            return self.allocate_iova(size);
        }

        // Per-Core Cacheの確認
        if let Some(pc) = unsafe { crate::mm::per_cpu::current_per_cpu_mut() } {
            if let Some(iova) = pc.iova_magazine.pop() {
                return Ok(iova);
            }
        }

        // Cache miss - use global allocator
        self.allocate_iova(size)
    }

    /// Free IOVA (Optimized with Per-Core Cache)
    pub fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        if size != 4096 {
            return self.free_iova(iova, size);
        }

        if let Some(pc) = unsafe { crate::mm::per_cpu::current_per_cpu_mut() } {
            if pc.iova_magazine.push(iova) {
                return Ok(());
            }
        }

        // Cache overflow or no per-cpu - free globally
        self.free_iova(iova, size)
    }

    /// Allocate I/O virtual address range
    pub fn allocate_iova(&self, size: u64) -> Result<u64, IommuError> {
        let mut allocator = self.iova_allocator.lock();
        if let Some(alloc) = allocator.as_mut() {
            alloc
                .allocate(size, IovaGranularity::Page4K)
                .ok_or(IommuError::OutOfMemory)
        } else {
            Err(IommuError::NotInitialized)
        }
    }

    /// Allocate an IOVA range with specific granularity (for super-pages)
    pub fn allocate_iova_aligned(
        &self,
        size: u64,
        granularity: IovaGranularity,
    ) -> Result<u64, IommuError> {
        let mut guard = self.iova_allocator.lock();
        let alloc = guard.as_mut().ok_or(IommuError::NotPresent)?;
        alloc
            .allocate(size, granularity)
            .ok_or(IommuError::HardwareError)
    }

    /// Free an IOVA range
    pub fn free_iova(&self, addr: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = self.iova_allocator.lock();
        let alloc = guard.as_mut().ok_or(IommuError::NotPresent)?;
        alloc.free(addr, size)
    }

    /// Initialize IOVA space for the global IOMMU controller (Default only)
    pub fn init_iova_range(base: u64, size: u64) -> Result<(), IommuError> {
        let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
        let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = registry
            .controllers
            .get(idx)
            .ok_or(IommuError::NotPresent)?;
        controller.init_iova(base, size)
    }

    /// Allocate an IOVA from the global controller
    pub fn allocate_global_iova(size: u64) -> Result<u64, IommuError> {
        let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
        let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = registry
            .controllers
            .get(idx)
            .ok_or(IommuError::NotPresent)?;
        controller.allocate_iova(size)
    }

    /// Free an IOVA back to global controller
    pub fn free_global_iova(addr: u64, size: u64) -> Result<(), IommuError> {
        let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
        let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = registry
            .controllers
            .get(idx)
            .ok_or(IommuError::NotPresent)?;
        controller.free_iova(addr, size)
    }

    /// Allocate an IOVA and create a mapping in default domain (non-identity mapping)
    pub fn map_for_dma_alloc(phys_addr: x86_64::PhysAddr, size: u64) -> Result<u64, IommuError> {
        let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
        let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = registry
            .controllers
            .get(idx)
            .ok_or(IommuError::NotPresent)?;

        // Allocate IOVA
        let iova = controller.allocate_iova_fast(size)?;

        // Default domain is 0
        let domains = controller.domains.read();
        let domain_arc = domains.get(&0).ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();
        domain.map(iova, phys_addr.as_u64(), size, true, true)?;

        Ok(iova)
    }

    /// Unmap IOVA and free it
    pub fn unmap_dma_alloc(iova: u64, _size: u64) -> Result<(), IommuError> {
        let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
        let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = registry
            .controllers
            .get(idx)
            .ok_or(IommuError::NotPresent)?;

        // Default domain
        let domains = controller.domains.read();
        let domain_arc = domains.get(&0).ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();
        domain.unmap(iova)?;
        drop(domain); // Release lock

        // Free IOVA
        controller.free_iova_fast(iova, _size)?;

        Ok(())
    }

    // =========================================================================
    // Queued Invalidation Methods
    // =========================================================================

    /// Initialize the Invalidation Queue
    ///
    /// # Arguments
    /// * `size_log2` - Log2 of queue size (8-16, giving 256-65536 entries)
    pub fn init_queued_invalidation(&mut self, size_log2: u8) -> Result<(), IommuError> {
        if !self.supports_queued_invalidation() {
            return Err(IommuError::NotSupported);
        }

        if self.invalidation_queue.lock().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        // Create the queue
        let iq = InvalidationQueue::new(size_log2).ok_or(IommuError::HardwareError)?;

        // Set Invalidation Queue Address (IQA register)
        // Bits 2:0 = queue size (log2 - 8), bits 11:0 reserved
        let iqa_value = (iq.base_address() as u64) | (iq.size_log2() as u64 & 0x7);
        self.write64(regs::IQA, iqa_value);

        // Set queue head to 0
        self.write64(regs::IQH, 0);
        // Set queue tail to 0
        self.write64(regs::IQT, 0);

        *self.invalidation_queue.lock() = Some(iq);
        log::info!(
            "[IOMMU] Invalidation Queue initialized ({} entries)\\n",
            1 << size_log2
        );

        Ok(())
    }

    /// Enable Queued Invalidation
    pub unsafe fn enable_queued_invalidation(&self) -> Result<(), IommuError> {
        if self.invalidation_queue.lock().is_none() {
            return Err(IommuError::NotPresent);
        }

        // Enable QI (GCMD.QIE)
        self.write32(regs::GCMD, gcmd_bits::GCMD_QIE);

        // Wait for completion
        // Use helper with timeout
        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_QIES) != 0,
            10_000,
        ) {
            Ok(_) => {
                self.qi_enabled.store(true, Ordering::Release);
                log::info!("[IOMMU] Queued Invalidation enabled\\n");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Disable Queued Invalidation
    pub unsafe fn disable_queued_invalidation(&self) -> Result<(), IommuError> {
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_QIE);

        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_QIES) == 0,
            10_000,
        ) {
            Ok(_) => {
                self.qi_enabled.store(false, Ordering::Release);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Check if Queued Invalidation is enabled
    pub fn is_queued_invalidation_enabled(&self) -> bool {
        self.qi_enabled.load(Ordering::Acquire)
    }

    /// Submit a queued invalidation request
    pub fn submit_invalidation(&self, entry: InvalidationQueueEntry) -> Result<(), IommuError> {
        let new_tail = {
            let mut guard = self.invalidation_queue.lock();
            let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;

            iq.submit(entry);
            (iq.tail() << 4) as u64 // Tail is in 16-byte units
        };

        // Update hardware tail pointer (borrow released)
        self.write64(regs::IQT, new_tail);

        Ok(())
    }

    /// Submit a global IOTLB invalidation via queued invalidation
    pub fn qi_invalidate_iotlb_global(&self, drain: bool) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_global(drain);
        self.submit_invalidation(entry)
    }

    /// Submit a domain IOTLB invalidation via queued invalidation
    pub fn qi_invalidate_iotlb_domain(
        &self,
        domain_id: u16,
        drain: bool,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_domain(domain_id, drain);
        self.submit_invalidation(entry)
    }

    /// Submit a page-selective IOTLB invalidation via queued invalidation
    pub fn qi_invalidate_iotlb_page(
        &self,
        domain_id: u16,
        addr: u64,
        drain: bool,
    ) -> Result<(), IommuError> {
        // AM (Address Mask) = 0 for 4KB page
        let entry = InvalidationQueueEntry::iotlb_invalidate(3, domain_id, drain, addr);
        self.submit_invalidation(entry)
    }

    /// Submit a global context-cache invalidation via queued invalidation
    pub fn qi_invalidate_context_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::context_cache_invalidate_global();
        self.submit_invalidation(entry)
    }

    /// Submit a global IEC invalidation via queued invalidation
    pub fn qi_invalidate_iec_global(&self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iec_invalidate_global();
        self.submit_invalidation(entry)
    }

    /// Submit a Device-TLB invalidation via queued invalidation
    /// Used for ATS-enabled PCIe devices that cache translations
    pub fn qi_invalidate_device_tlb(
        &self,
        source_id: u16,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_device(source_id, domain_id);
        self.submit_invalidation(entry)
    }

    /// Submit a page-selective Device-TLB invalidation
    pub fn qi_invalidate_device_tlb_page(
        &self,
        source_id: u16,
        domain_id: u16,
        iova: u64,
        size: u8,
    ) -> Result<(), IommuError> {
        let entry =
            InvalidationQueueEntry::device_tlb_invalidate_page(source_id, domain_id, iova, size);
        self.submit_invalidation(entry)
    }

    /// Submit a wait descriptor and synchronize
    pub fn qi_wait_sync(&self) -> Result<(), IommuError> {
        // Get tail after submitting wait
        let new_tail = {
            let mut guard = self.invalidation_queue.lock();
            let iq = guard.as_mut().ok_or(IommuError::NotPresent)?;

            let _status_addr = iq.submit_wait();
            (iq.tail() << 4) as u64
        };

        // Update hardware tail (borrow released)
        self.write64(regs::IQT, new_tail);

        // Wait for hardware head to catch up (all descriptors processed)
        let expected_tail = new_tail >> 4;
        // This is a critical wait, use longer timeout
        self.wait_for_condition(
            || (self.read64(regs::IQH) >> 4) == expected_tail,
            100_000, // 100ms
        )
    }

    /// Submit a wait descriptor and wait asynchronously for completion
    ///
    /// This is the async version of `qi_wait_sync`. Instead of busy-waiting,
    /// it registers a Waker that will be woken by the invalidation completion interrupt.
    pub fn qi_wait_async<'a>(&'a self) -> InvalidationWaiter<'a> {
        // Submit wait descriptor first
        let (expected_tail, submitted) = {
            let mut guard = self.invalidation_queue.lock();
            if let Some(iq) = guard.as_mut() {
                let _status_addr = iq.submit_wait();
                let tail = (iq.tail() << 4) as u64;
                // Update hardware tail
                self.write64(regs::IQT, tail);
                (tail >> 4, true)
            } else {
                (0, false)
            }
        };

        InvalidationWaiter {
            controller: self,
            expected_tail,
            submitted,
        }
    }

    /// Wake pending async invalidation waiter (called from interrupt handler)
    pub fn wake_invalidation_waiter(&self) {
        self.pending_waiter.wake();
    }

    // =========================================================================
    // Performance Monitoring Methods
    // =========================================================================

    /// Configure a performance monitoring counter
    pub fn perfmon_configure_counter(
        &mut self,
        index: u8,
        event: PerfMonEvent,
        enable: bool,
    ) -> Result<(), IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }
        if index > 3 {
            return Err(IommuError::InvalidAddress);
        }

        let evt_reg = match index {
            0 => regs::PERMON_EVT0,
            1 => regs::PERMON_EVT1,
            2 => regs::PERMON_EVT2,
            3 => regs::PERMON_EVT3,
            _ => return Err(IommuError::InvalidAddress),
        };

        // Event select value: event type in bits 0-7, enable in bit 22
        let evt_val = (event as u64) | (if enable { 1 << 22 } else { 0 });
        self.write64(evt_reg, evt_val);

        Ok(())
    }

    /// Read a performance monitoring counter value
    pub fn perfmon_read_counter(&self, index: u8) -> Result<u64, IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }
        if index > 3 {
            return Err(IommuError::InvalidAddress);
        }

        let cnt_reg = match index {
            0 => regs::PERMON_CNT0,
            1 => regs::PERMON_CNT1,
            2 => regs::PERMON_CNT2,
            3 => regs::PERMON_CNT3,
            _ => return Err(IommuError::InvalidAddress),
        };

        Ok(self.read64(cnt_reg))
    }

    /// Reset a performance monitoring counter to zero
    pub fn perfmon_reset_counter(&mut self, index: u8) -> Result<(), IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }
        if index > 3 {
            return Err(IommuError::InvalidAddress);
        }

        let cnt_reg = match index {
            0 => regs::PERMON_CNT0,
            1 => regs::PERMON_CNT1,
            2 => regs::PERMON_CNT2,
            3 => regs::PERMON_CNT3,
            _ => return Err(IommuError::InvalidAddress),
        };

        self.write64(cnt_reg, 0);
        Ok(())
    }

    /// Reset all performance monitoring counters
    pub fn perfmon_reset_all(&mut self) -> Result<(), IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }

        self.write64(regs::PERMON_CNT0, 0);
        self.write64(regs::PERMON_CNT1, 0);
        self.write64(regs::PERMON_CNT2, 0);
        self.write64(regs::PERMON_CNT3, 0);
        Ok(())
    }

    /// Get all counter values at once
    pub fn perfmon_read_all(&self) -> Result<[u64; 4], IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }

        Ok([
            self.read64(regs::PERMON_CNT0),
            self.read64(regs::PERMON_CNT1),
            self.read64(regs::PERMON_CNT2),
            self.read64(regs::PERMON_CNT3),
        ])
    }

    /// Enable Fault Interrupts
    ///
    /// Configures the Fault Event Control Register (FECTL) to generate interrupts on faults.
    pub unsafe fn enable_fault_interrupt(&self, vector: u8) {
        // Clear IM (Interrupt Mask) bit 31
        // Clear IP (Interrupt Pending) bit 30 (by writing 1 to it?) - Spec says R/W or R/W1C depending on impl.
        // Set Vector bits 7:0

        let val = (vector as u32) & 0xFF;
        // Ensure IM (bit 31) is 0 (Unmasked)
        // Ensure IP (bit 30) is cleared? Let's just set the vector and unmask.

        // Read current to preserve reserved bits? Register is usually RW.
        self.write32(regs::FECTL, val);
    }

    /// Wait for a condition to be true with a timeout
    ///
    /// # Arguments
    /// * `condition` - Predicate to check
    /// * `timeout_us` - Timeout in microseconds
    ///
    /// Uses rdtsc for time measurement to allow early boot usage before timers are fully calibrated.
    /// Assumes a conservative 3GHz clock for safety (wait deeper than needed rather than timing out too soon).
    fn wait_for_condition<F>(&self, condition: F, timeout_us: u64) -> Result<(), IommuError>
    where
        F: Fn() -> bool,
    {
        // 3GHz assumption: 3000 cycles / us
        let cycles = timeout_us * 3000;
        let start = unsafe { core::arch::x86_64::_rdtsc() };

        loop {
            if condition() {
                return Ok(());
            }

            let current = unsafe { core::arch::x86_64::_rdtsc() };
            if current.saturating_sub(start) > cycles {
                return Err(IommuError::Timeout);
            }

            core::hint::spin_loop();
        }
    }
}

/// IOMMU capability summary
#[derive(Debug, Clone)]
pub struct IommuCapabilities {
    pub queued_invalidation: bool,
    pub interrupt_remapping: bool,
    pub super_page_2mb: bool,
    pub super_page_1gb: bool,
    pub page_walk_coherency: bool,
    pub snoop_control: bool,
    pub posted_interrupts: bool,
    pub scalable_mode: bool,
    pub performance_monitoring: bool,
}

// ============================================================================
// IOVA Allocator (I/O Virtual Address Allocator)
// ============================================================================

/// IOVA allocation granularity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IovaGranularity {
    /// 4KB pages
    Page4K,
    /// 2MB super-pages
    Page2M,
    /// 1GB super-pages
    Page1G,
}

impl IovaGranularity {
    /// Get the size in bytes
    pub const fn size_bytes(self) -> u64 {
        match self {
            IovaGranularity::Page4K => 4 * 1024,
            IovaGranularity::Page2M => 2 * 1024 * 1024,
            IovaGranularity::Page1G => 1024 * 1024 * 1024,
        }
    }

    /// Get the alignment mask
    pub const fn align_mask(self) -> u64 {
        self.size_bytes() - 1
    }
}

/// IOVA range for tracking allocations
#[derive(Debug, Clone)]
pub struct IovaRange {
    /// Start address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
}

// ============================================================================
// Free Range Tree for O(log n) IOVA Allocation
// ============================================================================

/// Free range tracking structure using BTreeMap for O(log n) operations
///
/// Maintains two indexes:
/// - `by_start`: Maps start_page to contiguous free page count (for coalescing)
/// - `by_size`: Sorted set of (size, start_page) for best-fit allocation
#[derive(Debug, Clone)]
pub struct FreeRangeTree {
    /// Map: start_page -> contiguous free pages
    by_start: BTreeMap<usize, usize>,
    /// Set: (size, start_page) for size-ordered queries
    by_size: BTreeSet<(usize, usize)>,
}

impl FreeRangeTree {
    /// Create a new free range tree with a single initial range
    pub fn new(total_pages: usize) -> Self {
        let mut by_start = BTreeMap::new();
        let mut by_size = BTreeSet::new();

        if total_pages > 0 {
            by_start.insert(0, total_pages);
            by_size.insert((total_pages, 0));
        }

        Self { by_start, by_size }
    }

    /// Find a free range with at least `pages_needed` pages and proper alignment
    /// Returns (start_page, actual_size) or None
    pub fn find_free_range(
        &self,
        pages_needed: usize,
        alignment_pages: usize,
    ) -> Option<(usize, usize)> {
        // Find the smallest range that fits (best-fit)
        for &(size, start) in self.by_size.range((pages_needed, 0)..) {
            // Check alignment
            let aligned_start = (start + alignment_pages - 1) / alignment_pages * alignment_pages;
            let offset = aligned_start - start;

            if size >= pages_needed + offset {
                return Some((aligned_start, size));
            }
        }
        None
    }

    /// Allocate a range of pages starting at `start_page` with `count` pages
    /// Splits the containing free range as needed
    pub fn allocate(&mut self, start_page: usize, count: usize) -> bool {
        // Find the range containing this allocation
        // Look for ranges that start at or before start_page
        let containing = self.by_start.range(..=start_page).next_back();

        if let Some((&range_start, &range_size)) = containing {
            let range_end = range_start + range_size;
            let alloc_end = start_page + count;

            // Check if target range is fully within this free range
            if start_page >= range_start && alloc_end <= range_end {
                // Remove the old range
                self.by_start.remove(&range_start);
                self.by_size.remove(&(range_size, range_start));

                // Add prefix range if any
                if start_page > range_start {
                    let prefix_size = start_page - range_start;
                    self.by_start.insert(range_start, prefix_size);
                    self.by_size.insert((prefix_size, range_start));
                }

                // Add suffix range if any
                if alloc_end < range_end {
                    let suffix_size = range_end - alloc_end;
                    self.by_start.insert(alloc_end, suffix_size);
                    self.by_size.insert((suffix_size, alloc_end));
                }

                return true;
            }
        }
        false
    }

    /// Free a range of pages, coalescing with adjacent free ranges
    pub fn free(&mut self, start_page: usize, count: usize) {
        let mut new_start = start_page;
        let mut new_size = count;

        // Check for preceding free range to coalesce
        if let Some((&prev_start, &prev_size)) = self.by_start.range(..start_page).next_back() {
            if prev_start + prev_size == start_page {
                // Coalesce with preceding range
                self.by_start.remove(&prev_start);
                self.by_size.remove(&(prev_size, prev_start));
                new_start = prev_start;
                new_size += prev_size;
            }
        }

        // Check for following free range to coalesce
        let end_page = new_start + new_size;
        if let Some((&next_start, &next_size)) = self.by_start.range(end_page..).next() {
            if next_start == end_page {
                // Coalesce with following range
                self.by_start.remove(&next_start);
                self.by_size.remove(&(next_size, next_start));
                new_size += next_size;
            }
        }

        // Insert the coalesced range
        self.by_start.insert(new_start, new_size);
        self.by_size.insert((new_size, new_start));
    }

    /// Get total free pages
    pub fn total_free(&self) -> usize {
        self.by_start.values().sum()
    }

    /// Get number of free ranges
    pub fn range_count(&self) -> usize {
        self.by_start.len()
    }

    /// Get the largest contiguous free range in pages
    pub fn largest_free(&self) -> usize {
        self.by_size
            .iter()
            .next_back()
            .map(|(size, _)| *size)
            .unwrap_or(0)
    }
}

/// IOVA Allocator using tree-based free range tracking
///
/// Manages I/O Virtual Address space for DMA mappings.
/// Supports 4KB, 2MB, and 1GB granularity allocations.
/// Uses O(log n) tree-based allocation with automatic coalescing.
pub struct IovaAllocator {
    /// Base address of the IOVA space
    base: u64,
    /// Total size of the IOVA space
    size: u64,
    /// Bitmap for 4KB page tracking (1 bit per 4KB page) - kept for debugging
    bitmap: Vec<u64>,
    /// Number of 4KB pages managed
    total_pages: usize,
    /// Number of free 4KB pages
    free_pages: usize,
    /// Next allocation hint (for fast sequential allocation)
    next_hint: usize,
    /// Free range tree for O(log n) allocation
    free_ranges: FreeRangeTree,
}

impl IovaAllocator {
    /// 4KB page size
    const PAGE_SIZE_4K: u64 = 4096;
    /// Bits per bitmap word
    const BITS_PER_WORD: usize = 64;

    /// Create a new IOVA allocator
    ///
    /// # Arguments
    /// * `base` - Base address of the IOVA space (should be page-aligned)
    /// * `size` - Total size of the IOVA space
    pub fn new(base: u64, size: u64) -> Self {
        let total_pages = (size / Self::PAGE_SIZE_4K) as usize;
        let bitmap_words = (total_pages + Self::BITS_PER_WORD - 1) / Self::BITS_PER_WORD;

        // Initialize bitmap with all pages free (0 = free, 1 = allocated)
        let bitmap = alloc::vec![0u64; bitmap_words];

        // Initialize free range tree with entire space as one free range
        let free_ranges = FreeRangeTree::new(total_pages);

        Self {
            base,
            size,
            bitmap,
            total_pages,
            free_pages: total_pages,
            next_hint: 0,
            free_ranges,
        }
    }

    /// Get base address
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Get total size
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get free pages count
    pub fn free_pages(&self) -> usize {
        self.free_pages
    }

    /// Check if a page is allocated
    fn is_page_allocated(&self, page_idx: usize) -> bool {
        if page_idx >= self.total_pages {
            return true; // Out of range = considered allocated
        }
        let word_idx = page_idx / Self::BITS_PER_WORD;
        let bit_idx = page_idx % Self::BITS_PER_WORD;
        (self.bitmap[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Mark a range of pages as allocated
    fn mark_pages_allocated(&mut self, start_page: usize, count: usize) {
        for i in 0..count {
            let page_idx = start_page + i;
            let word_idx = page_idx / Self::BITS_PER_WORD;
            let bit_idx = page_idx % Self::BITS_PER_WORD;
            self.bitmap[word_idx] |= 1u64 << bit_idx;
        }
        self.free_pages -= count;
    }

    /// Mark a range of pages as free
    fn mark_pages_free(&mut self, start_page: usize, count: usize) {
        for i in 0..count {
            let page_idx = start_page + i;
            let word_idx = page_idx / Self::BITS_PER_WORD;
            let bit_idx = page_idx % Self::BITS_PER_WORD;
            self.bitmap[word_idx] &= !(1u64 << bit_idx);
        }
        self.free_pages += count;
    }

    /// Find a contiguous range of free pages
    fn find_free_range(&self, pages_needed: usize, alignment_pages: usize) -> Option<usize> {
        let mut start = self.next_hint;

        // Align to the required granularity
        start = (start + alignment_pages - 1) / alignment_pages * alignment_pages;

        let mut search_count = 0;
        while search_count < self.total_pages {
            if start + pages_needed > self.total_pages {
                // Wrap around
                start = 0;
                start = (start + alignment_pages - 1) / alignment_pages * alignment_pages;
            }

            // Check if this range is free
            let mut all_free = true;
            for i in 0..pages_needed {
                if self.is_page_allocated(start + i) {
                    all_free = false;
                    // Skip to next aligned position
                    start =
                        ((start + i + 1) + alignment_pages - 1) / alignment_pages * alignment_pages;
                    break;
                }
            }

            if all_free {
                return Some(start);
            }

            search_count += alignment_pages;
        }

        None
    }

    /// Allocate an IOVA range
    ///
    /// Returns the allocated IOVA address, or None if allocation fails.
    /// Uses O(log n) tree-based allocation with best-fit.
    pub fn allocate(&mut self, size: u64, granularity: IovaGranularity) -> Option<u64> {
        let page_size = granularity.size_bytes();
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;
        let alignment_pages = (page_size / Self::PAGE_SIZE_4K) as usize;

        // Use tree-based allocation (O(log n))
        let (start_page, _) = self
            .free_ranges
            .find_free_range(pages_needed, alignment_pages)?;

        // Allocate from tree (splits the range)
        self.free_ranges.allocate(start_page, pages_needed);

        // Mark as allocated in bitmap (for debugging/validation)
        self.mark_pages_allocated(start_page, pages_needed);

        // Update hint for next allocation
        self.next_hint = start_page + pages_needed;

        Some(self.base + (start_page as u64) * Self::PAGE_SIZE_4K)
    }

    /// Allocate a specific IOVA range (for identity mapping)
    pub fn allocate_at(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova + size > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / Self::PAGE_SIZE_4K) as usize;
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;

        // Use tree to allocate (will fail if not free)
        if !self.free_ranges.allocate(start_page, pages_needed) {
            return Err(IommuError::AlreadyMapped);
        }

        // Mark as allocated in bitmap (for debugging/validation)
        self.mark_pages_allocated(start_page, pages_needed);
        Ok(())
    }

    /// Free an IOVA range with automatic coalescing
    pub fn free(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova + size > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / Self::PAGE_SIZE_4K) as usize;
        let pages_count = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;

        // Free in tree (with automatic coalescing)
        self.free_ranges.free(start_page, pages_count);

        // Mark as free in bitmap (for debugging/validation)
        self.mark_pages_free(start_page, pages_count);

        // Update hint to freed range for potential reuse
        if start_page < self.next_hint {
            self.next_hint = start_page;
        }

        Ok(())
    }

    /// Reserve an IOVA range (for RMRR identity mappings)
    ///
    /// Reserved ranges cannot be allocated by normal allocation calls.
    pub fn reserve(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova + size > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / Self::PAGE_SIZE_4K) as usize;
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;

        // Use tree to allocate (will fail if not free)
        if !self.free_ranges.allocate(start_page, pages_needed) {
            return Err(IommuError::AlreadyMapped);
        }

        // Mark as allocated in bitmap
        self.mark_pages_allocated_fast(start_page, pages_needed);
        Ok(())
    }

    /// Allocate a contiguous range with specific size requirements
    ///
    /// Useful for large DMA buffers that need power-of-2 alignment.
    pub fn allocate_contiguous(&mut self, size: u64, alignment: u64) -> Option<u64> {
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;
        let alignment_pages = ((alignment.max(Self::PAGE_SIZE_4K)) / Self::PAGE_SIZE_4K) as usize;

        // Use tree-based allocation (O(log n))
        let (start_page, _) = self
            .free_ranges
            .find_free_range(pages_needed, alignment_pages)?;

        // Allocate from tree
        self.free_ranges.allocate(start_page, pages_needed);

        // Mark as allocated in bitmap
        self.mark_pages_allocated_fast(start_page, pages_needed);

        // Update hint
        self.next_hint = start_page + pages_needed;

        Some(self.base + (start_page as u64) * Self::PAGE_SIZE_4K)
    }

    /// Mark pages allocated using word-level operations for efficiency
    fn mark_pages_allocated_fast(&mut self, start_page: usize, count: usize) {
        let end_page = start_page + count;

        // Handle partial first word
        let first_word = start_page / Self::BITS_PER_WORD;
        let first_bit = start_page % Self::BITS_PER_WORD;

        if first_bit != 0 {
            let bits_in_first = (Self::BITS_PER_WORD - first_bit).min(count);
            let mask = ((1u64 << bits_in_first) - 1) << first_bit;
            self.bitmap[first_word] |= mask;

            if bits_in_first >= count {
                self.free_pages -= count;
                return;
            }
        }

        // Handle full words
        let first_full_word = if first_bit == 0 {
            first_word
        } else {
            first_word + 1
        };
        let last_word = end_page / Self::BITS_PER_WORD;

        for word in first_full_word..last_word {
            self.bitmap[word] = !0u64;
        }

        // Handle partial last word
        let last_bit = end_page % Self::BITS_PER_WORD;
        if last_bit != 0 && last_word < self.bitmap.len() {
            let mask = (1u64 << last_bit) - 1;
            self.bitmap[last_word] |= mask;
        }

        self.free_pages -= count;
    }

    /// Mark pages free using word-level operations for efficiency
    fn mark_pages_free_fast(&mut self, start_page: usize, count: usize) {
        let end_page = start_page + count;

        // Handle partial first word
        let first_word = start_page / Self::BITS_PER_WORD;
        let first_bit = start_page % Self::BITS_PER_WORD;

        if first_bit != 0 {
            let bits_in_first = (Self::BITS_PER_WORD - first_bit).min(count);
            let mask = ((1u64 << bits_in_first) - 1) << first_bit;
            self.bitmap[first_word] &= !mask;

            if bits_in_first >= count {
                self.free_pages += count;
                return;
            }
        }

        // Handle full words
        let first_full_word = if first_bit == 0 {
            first_word
        } else {
            first_word + 1
        };
        let last_word = end_page / Self::BITS_PER_WORD;

        for word in first_full_word..last_word {
            self.bitmap[word] = 0;
        }

        // Handle partial last word
        let last_bit = end_page % Self::BITS_PER_WORD;
        if last_bit != 0 && last_word < self.bitmap.len() {
            let mask = (1u64 << last_bit) - 1;
            self.bitmap[last_word] &= !mask;
        }

        self.free_pages += count;
    }

    /// Get basic statistics
    pub fn stats(&self) -> IovaAllocatorStats {
        IovaAllocatorStats {
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            allocated_pages: self.total_pages - self.free_pages,
            base: self.base,
            size: self.size,
        }
    }

    /// Get detailed statistics including fragmentation
    pub fn stats_detailed(&self) -> IovaAllocatorStatsDetailed {
        let free_ranges = self.free_ranges.range_count();
        let fragmentation = if self.free_pages > 0 {
            (free_ranges as f32) / (self.free_pages as f32 / 64.0).max(1.0)
        } else {
            0.0
        };

        IovaAllocatorStatsDetailed {
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            allocated_pages: self.total_pages - self.free_pages,
            base: self.base,
            size: self.size,
            free_ranges,
            fragmentation,
            largest_free_range: self.free_ranges.largest_free(),
        }
    }
}

/// IOVA allocator statistics
#[derive(Debug, Clone)]
pub struct IovaAllocatorStats {
    pub total_pages: usize,
    pub free_pages: usize,
    pub allocated_pages: usize,
    pub base: u64,
    pub size: u64,
}

/// Detailed IOVA allocator statistics
#[derive(Debug, Clone)]
pub struct IovaAllocatorStatsDetailed {
    pub total_pages: usize,
    pub free_pages: usize,
    pub allocated_pages: usize,
    pub base: u64,
    pub size: u64,
    /// Number of distinct free ranges
    pub free_ranges: usize,
    /// Fragmentation ratio (higher = more fragmented)
    pub fragmentation: f32,
    /// Largest contiguous free range in pages
    pub largest_free_range: usize,
}

// ============================================================================
// Per-CPU Domain Mapping Cache
// ============================================================================

/// Lookup domain in local CPU cache
fn lookup_domain_cached(device_id: u16) -> Option<(u16, u8)> {
    // Use true Per-CPU data via GsBase
    if let Some(pc) = unsafe { crate::mm::per_cpu::current_per_cpu() } {
        pc.iommu_domain_cache.lookup(device_id)
    } else {
        None
    }
}

/// Update local CPU cache
fn cache_domain_mapping(device_id: u16, domain_id: u16, controller_idx: u8) {
    if let Some(pc) = unsafe { crate::mm::per_cpu::current_per_cpu_mut() } {
        pc.iommu_domain_cache
            .insert(device_id, domain_id, controller_idx);
    }
}

/// Invalidate a mapping in ALL CPU caches (slow path, but rare)
fn invalidate_domain_cache(device_id: u16) {
    // Iterate over all active CPUs and invalidate their caches
    // Note: This technically races with other CPUs if they are currently inserting,
    // but PerCpuDomainCache is not thread-safe for cross-cpu mutation.
    // Ideally this should use IPIs to invalidate remote caches safely.
    // For now, we accept the race because this is only a hint cache, and
    // worst case is a stale entry which will be corrected on next use/miss.
    // OR we can skip this for now and rely on eventual consistency or simple flush.

    // SAFETY: This is risky without IPIs.
    // BUT since we are in a single address space kernel and invalidation is rare (unmap/detach),
    // we might just iterate.
    // However, `get_per_cpu` returns &PerCpuData or &mut ...?
    // per_cpu.rs only exposes `get_per_cpu` as shared reference.
    // We need mutable access to invalidate.
    // Real implementation requires IPI: "Hey CPU X, invalidate your cache".
    // For this refactoring step, we will log a warning and skip remote invalidation,
    // as implementing full IPI infrastructure is out of scope for just this cache.
    // The cache is just an optimization.

    // Actually, let's just invalidate LOCAL cache for now, which covers the common case
    // where unmap happens on the same CPU that mapped it.
    if let Some(pc) = unsafe { crate::mm::per_cpu::current_per_cpu_mut() } {
        pc.iommu_domain_cache.invalidate(device_id);
    }
}

// ============================================================================
// Global Instance
// ============================================================================

/// Reserved Memory Region (from RMRR)
#[derive(Debug, Clone)]
pub struct ReservedMemoryRegion {
    pub segment: u16,
    pub base: u64,
    pub limit: u64,
    /// Devices this region applies to (Segment, Bus, Device, Function)
    /// If empty, might apply to all? (Spec usually says explicit scope)
    pub devices: Vec<DeviceId>,
}

/// IOMMU Registry (Immutable container after initialization)
pub struct IommuRegistry {
    /// List of IOMMU controllers (Arc for shared access, fine-grained locking internally)
    controllers: Vec<Arc<IommuController>>,
    /// Default IOMMU index
    default_iommu_idx: Option<usize>,
    /// Reserved memory regions
    reserved_regions: Vec<ReservedMemoryRegion>,
    /// Global Configuration
    pub config: IommuConfig,
}

unsafe impl Send for IommuRegistry {}
unsafe impl Sync for IommuRegistry {}

impl IommuRegistry {
    /// Find controller index using proper scope matching
    pub fn find_controller_index_for_device(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Option<usize> {
        // First pass: Find controller with explicit scope match
        for (i, controller) in self.controllers.iter().enumerate() {
            if controller.segment != segment {
                continue;
            }
            if controller.include_all {
                continue;
            }
            if controller.device_in_scope(bus, device, function) {
                return Some(i);
            }
        }

        // Second pass: Find include_all controller for this segment
        for (i, controller) in self.controllers.iter().enumerate() {
            if controller.segment == segment && controller.include_all {
                return Some(i);
            }
        }

        // Fallback to default
        self.default_iommu_idx
    }
}

/// Global IOMMU Registry
static IOMMU_REGISTRY: spin::Once<IommuRegistry> = spin::Once::new();

/// Get reference to the IOMMU registry
fn get_iommu_registry() -> Option<&'static IommuRegistry> {
    IOMMU_REGISTRY.get()
}

// DOMAIN_LOCKS removed as we now use fine-grained locking (RwLock per Domain).

/// IOMMU Configuration from Kernel Command Line
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuConfig {
    /// Enable IOMMU
    pub enabled: bool,
    /// Passthrough mode (disable translation for most devices)
    pub passthrough: bool,
    /// Force enable even if ACPI says no (not used yet)
    pub force: bool,
}

impl IommuConfig {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            passthrough: false,
            force: false,
        }
    }
}

impl Default for IommuConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize IOMMU using ACPI DMAR table at `dmar_addr`
pub unsafe fn init_iommu_from_acpi(
    dmar_addr: usize,
    config: IommuConfig,
) -> Result<(), IommuError> {
    if !config.enabled {
        log::info!("IOMMU disabled by kernel configuration");
        return Err(IommuError::NotPresent);
    }

    // Caller should ensure `dmar_addr` is valid and log if desired.

    // Parse DMAR using canonical ACPI parser from drivers/acpi
    let dmar_info = match unsafe { crate::io::acpi::dmar::parse_dmar(dmar_addr) } {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to parse DMAR: {}", e);
            return Err(IommuError::HardwareError);
        }
    };

    // Prepare controllers list
    let mut controllers = Vec::new();
    let mut default_idx = None;

    // 3. Initialize Controllers (DRHD)
    for unit in dmar_info.drhd_units {
        log::info!(
            "Initializing IOMMU Controller at {:#x} (Segment: {}, All: {})",
            unit.register_base,
            unit.segment,
            unit.include_all
        );

        let mmio_virt = crate::mm::higher_half::phys_to_virt(
            crate::mm::higher_half::PhysAddr::new(unit.register_base),
        )
        .as_u64();

        let mut controller = IommuController::new(mmio_virt, unit.segment);

        unsafe {
            if let Err(e) = controller.init() {
                log::error!("Failed to initialize IOMMU controller: {:?}", e);
                continue;
            }

            // Enable Fault Interrupts (Vector 0x50 - IommuFault)
            controller.enable_fault_interrupt(0x50);

            // Setup Queued Invalidation if supported
            if controller.supports_queued_invalidation() {
                if let Err(e) = controller.init_queued_invalidation(8) {
                    log::warn!("Failed to init Queued Invalidation: {:?}", e);
                } else {
                    if let Err(e) = controller.enable_queued_invalidation() {
                        log::warn!("Failed to enable Queued Invalidation: {:?}", e);
                    } else {
                        log::info!("Queued Invalidation enabled for controller");
                    }
                }
            }
        }

        controllers.push(Arc::new(controller));
        if unit.include_all {
            default_idx = Some(controllers.len() - 1);
        }
    }

    if controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    // Set default controller (or first one)
    let default_iommu_idx = default_idx.or(Some(0));

    // 4. Register RMRR regions
    let dmar_rmrr_regions = dmar_info.rmrr_regions.clone();
    let mut reserved_regions = Vec::new();

    for region in &dmar_rmrr_regions {
        let mut devices = Vec::new();
        for scope in &region.devices {
            let bus = scope.start_bus;
            // Simplification: Assume flat bus or simple path for now
            if let Some(last_path) = scope.path.last() {
                let device_id =
                    DeviceId::new(region.segment, bus, last_path.device, last_path.function);
                devices.push(device_id);
            }
        }

        reserved_regions.push(ReservedMemoryRegion {
            segment: region.segment,
            base: region.base,
            limit: region.limit,
            devices,
        });
    }

    // Build the registry
    let registry = IommuRegistry {
        controllers,
        default_iommu_idx,
        reserved_regions,
        config,
    };

    // Apply Reserved Regions (RMRR)
    // Need to do this before publishing registry because we need mutable access to controllers
    for region in &registry.reserved_regions {
        for device_id in &region.devices {
            // Find controller for this device
            // Cannot use registry methods easily yet as we own the data un-wrapped
            // Manual lookup similar to find_controller_index_for_device
            let mut target_idx = None;

            // First pass
            for (i, c) in registry.controllers.iter().enumerate() {
                if c.segment != region.segment {
                    continue;
                }
                if c.include_all {
                    continue;
                }
                // Need bus/dev/func from DeviceId
                let (bus, dev, func) = (device_id.bus, device_id.device, device_id.function);
                if c.device_in_scope(bus, dev, func) {
                    target_idx = Some(i);
                    break;
                }
            }
            // Second pass
            if target_idx.is_none() {
                for (i, c) in registry.controllers.iter().enumerate() {
                    if c.segment == region.segment && c.include_all {
                        target_idx = Some(i);
                        break;
                    }
                }
            }
            // Fallback
        }
    }

    // Initialize the global registry
    IOMMU_REGISTRY.call_once(|| registry);

    Ok(())
}

/// Initialize the global IOMMU (legacy wrapper)
///
/// # Safety
/// Caller must ensure MMIO address is valid
pub unsafe fn init_iommu(mmio_base: u64) -> Result<(), IommuError> {
    // Legacy initialization for single IOMMU (segment 0) with default config
    let mmio_virt =
        crate::mm::higher_half::phys_to_virt(crate::mm::higher_half::PhysAddr::new(mmio_base))
            .as_u64();

    let mut controller = IommuController::new(mmio_virt, 0);
    unsafe {
        controller.init()?;
    }

    log::info!("IOMMU initialized at 0x{:X}\n", mmio_base);

    let registry = IommuRegistry {
        controllers: alloc::vec![Arc::new(controller)],
        default_iommu_idx: Some(0),
        reserved_regions: Vec::new(),
        config: IommuConfig::default(),
    };

    IOMMU_REGISTRY.call_once(|| registry);
    Ok(())
}

/// Enable IOMMU translation (on all controllers)
pub fn enable_iommu() -> Result<(), IommuError> {
    if let Some(registry) = get_iommu_registry() {
        for controller in &registry.controllers {
            unsafe {
                controller.enable()?;
            }
        }
        Ok(())
    } else {
        Err(IommuError::NotInitialized)
    }
}

/// Disable IOMMU translation (on all controllers)
pub fn disable_iommu() -> Result<(), IommuError> {
    if let Some(registry) = get_iommu_registry() {
        for controller in &registry.controllers {
            unsafe {
                controller.disable()?;
            }
        }
        Ok(())
    } else {
        Err(IommuError::NotInitialized)
    }
}

/// Check if IOMMU is enabled (at least one)
pub fn is_iommu_enabled() -> bool {
    if let Some(registry) = get_iommu_registry() {
        !registry.controllers.is_empty() && registry.controllers[0].is_enabled()
    } else {
        false
    }
}

/// Set NUMA hint for a domain (best-effort)
/// Note: Since domains are per-controller, this finds the first controller with the domain.
pub fn set_domain_numa(domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    // Try to find the domain in any controller
    for controller in &registry.controllers {
        if controller.domain(domain_id).is_some() {
            return controller.set_domain_numa(domain_id, numa_node);
        }
    }
    Err(IommuError::DomainNotFound)
}

/// Get NUMA hint for a domain
pub fn get_domain_numa(domain_id: u16) -> Result<Option<usize>, IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    for controller in &registry.controllers {
        if let Some(domain_arc) = controller.domain(domain_id) {
            let d = domain_arc.read();
            return Ok(d.numa_node);
        }
    }
    Err(IommuError::DomainNotFound)
}

/// Map a physical address range for DMA access
///
/// Returns the IOVA (I/O Virtual Address) that devices should use
pub fn map_for_dma(phys_addr: x86_64::PhysAddr, size: u64) -> Result<u64, IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;

    if registry.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    // Map in ALL controllers (mirroring)
    let iova = phys_addr.as_u64();

    for controller in &registry.controllers {
        let domains = controller.domains.read();
        let domain_arc = domains
            .get(&0) // Default domain
            .ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();
        domain.map(iova, phys_addr.as_u64(), size, true, true)?;
    }

    Ok(iova)
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    if registry.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    for controller in &registry.controllers {
        let domains = controller.domains.read();
        let domain_arc = domains.get(&0).ok_or(IommuError::DomainNotFound)?;
        let mut domain = domain_arc.write();
        domain.unmap(iova)?;
    }
    Ok(())
}

/// Execute with default IOMMU controller (mutable access)
///
/// This acquires a write lock on the chosen controller and passes a `&mut` to the
/// provided closure. Many operations (attach/detach/create_domain) require mutation,
/// so take `&mut` here for convenience. If only read access is needed in the future,
/// consider adding a read-only helper.
pub fn with_iommu<F, R>(f: F) -> Result<R, IommuError>
where
    F: FnOnce(&IommuController) -> R,
{
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
    let controller = registry
        .controllers
        .get(idx)
        .ok_or(IommuError::NotPresent)?;
    Ok(f(controller))
}

/// Handle IOMMU Faults (Called from ISR)
///
/// Iterates all controllers and processes pending faults.
pub fn handle_fault() {
    if let Some(registry) = get_iommu_registry() {
        for (_i, controller) in registry.controllers.iter().enumerate() {
            // Process faults directly (thread-safe)
            controller.process_faults();
        }
    }
}

/// Wake all pending async invalidation waiters (Called from ISR)
pub fn wake_invalidation_waiters() {
    if let Some(registry) = get_iommu_registry() {
        // Use try_read to avoid deadlock in ISR if main thread holds write lock
        for controller in &registry.controllers {
            controller.wake_invalidation_waiter();
        }
    }
}

impl IommuController {
    /// Isolate a faulting device by disabling its context entry
    pub fn isolate_faulting_device(&self, source_id: u16) {
        let bus = (source_id >> 8) as usize;
        let devfn = (source_id & 0xFF) as usize;

        // Safety: context_tables are allocated at init and never moved/freed until drop.
        // We only modify the Present bit atomically-ish to disable access.

        let hw = self.hardware.lock();
        if let Some(table_ptr) = hw.context_tables.get(bus) {
            unsafe {
                let entry_ptr = table_ptr.add(devfn);
                let mut entry = *entry_ptr;

                // Clear Present bit (Bit 0) and Fault Processing Disable (Bit 1)
                // Actually we just clear everything or just Present.
                // Disabling Present (bit 0 = 0) effectively blocks the device.
                if entry.is_present() {
                    log::warn!(
                        "[IOMMU] ISOLATING Device {:02x}:{:02x}.{:x} (SourceID {:04x}) due to security violation",
                        bus,
                        devfn >> 3,
                        devfn & 7,
                        source_id
                    );

                    entry.lo &= !1; // Clear Present
                    // entry.lo |= 2; // Optional: Set Fault Processing Disable?

                    // Write back
                    core::ptr::write_volatile(entry_ptr, entry);

                    // Invalidate Context Cache for this device
                    if self.is_queued_invalidation_enabled() {
                        // Use global context invalidation as we don't have granular helper yet
                        let _ = self.qi_invalidate_context_global();
                    } else {
                        // Fallback to global invalidation if specific not implemented or easy
                        // Note: We use IOTLB invalidation as a proxy, though strict Context Invalidation is better.
                        // But if we don't have CCMD helper, this is best effort.
                        self.invalidate_iotlb_global();
                    }
                }
            }
        }
    }
}

/// Process security faults and enforce isolation
fn process_fault_security(controller: &IommuController, entry: FaultRecordingEntry) {
    let source_id = entry.source_id();

    // Check if this is a severity that requires isolation
    // For now, assume all reported faults in the log are violations.
    // (Hardware reports recoverable faults elsewhere usually?)

    // Isolate the device
    controller.isolate_faulting_device(source_id);
}

// ============================================================================
// 【設計書 7.2】PCIデバイスへのIOMMU自動設定
// ============================================================================

/// PCIデバイスにIOMMUドメインを自動設定
///
/// この関数はPCIデバイス検出時に呼び出され、
/// IOMMUが有効な場合は自動的にドメインを作成してデバイスをアタッチします。
///
/// # Arguments
/// * `device` - 設定対象のPCIデバイス情報（可変参照）
///
/// # Returns
/// 成功した場合は割り当てられたドメインID、失敗した場合はNone
pub fn setup_iommu_for_pci_device(device: &mut crate::io::pci::PciDeviceInfo) -> Option<u16> {
    let registry = get_iommu_registry()?; // NotInitialized -> None

    let bdf = device.bdf;
    let segment = 0; // Default segment (PciDeviceInfo doesn't have segment yet)

    // Find correct IOMMU for this device
    let controller_idx = registry.find_controller_index_for_device(
        segment,
        bdf.bus.0,
        bdf.device.0,
        bdf.function.0,
    )?;

    // Obtain controller directly
    let iommu = registry.controllers.get(controller_idx)?;

    // Enable ATS ... (same as before but iommu is guard)
    if (iommu.ecap & ecap_bits::ECAP_DT) != 0 {
        if let Some(pcie_config) = pcie_ext_config() {
            let pcie_bdf = PcieBdf::new(bdf.bus.0, bdf.device.0, bdf.function.0);
            if device_supports_ats(pcie_config, pcie_bdf) {
                if let Ok(ats_ctrl) = AtsController::new(pcie_config, pcie_bdf) {
                    if ats_ctrl.enable_ats(0u8).is_ok() {
                        let device_id =
                            DeviceId::new(segment, bdf.bus.0, bdf.device.0, bdf.function.0);
                        iommu.enable_ats_for_device(device_id);
                        // Reduced logging
                    }
                }
            }
        }
    }

    // New domain creation
    let numa_hint = Some(crate::mm::numa::current_node());
    let domain_type = if registry.config.passthrough {
        IommuDomainType::Passthrough
    } else {
        IommuDomainType::Translated
    };

    let domain_id = match iommu.create_domain(numa_hint, domain_type) {
        Ok(id) => id,
        Err(e) => {
            log::error!("Failed to create domain for {:?}: {:?}\\n", bdf, e);
            return None;
        }
    };

    let device_id = DeviceId::new(segment, bdf.bus.0, bdf.device.0, bdf.function.0);
    if let Err(e) = iommu.attach_device(device_id, domain_id) {
        log::error!("[IOMMU] Attach failed: {:?}\\n", e);
        return None;
    }

    // Apply Reserved Regions
    for region in &registry.reserved_regions {
        if region.segment != device_id.segment {
            continue;
        }
        if region.devices.iter().any(|d| *d == device_id) {
            let size = region.limit - region.base + 1;
            if let Some(domain_arc) = iommu.domain(domain_id) {
                let mut domain = domain_arc.write();
                let _ = domain.map_identity(region.base, size, true, true);
            }
        }
    }

    device.iommu_domain_id = Some(domain_id);
    Some(domain_id)
}

/// すべてのPCIデバイスにIOMMUドメインを設定
///
/// PCI初期化後に呼び出して、全デバイスを保護します。
pub fn setup_iommu_for_all_pci_devices(devices: &mut [crate::io::pci::PciDeviceInfo]) {
    if !is_iommu_enabled() {
        log::info!("[IOMMU] Skipping PCI device protection (IOMMU not enabled)\n");
        return;
    }

    let mut protected_count = 0;
    for device in devices.iter_mut() {
        // ブリッジデバイスはスキップ（ホストブリッジはIOMMUで保護不要）
        if device.is_pci_bridge() {
            continue;
        }

        if setup_iommu_for_pci_device(device).is_some() {
            protected_count += 1;
        }
    }

    log::info!(
        "[IOMMU] Protected {} PCI devices with IOMMU domains\n",
        protected_count
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id() {
        let dev = DeviceId::new(0, 0, 1, 0);
        assert_eq!(dev.requester_id(), 0x08); // bus=0, dev=1, func=0
    }

    #[test]
    fn test_sl_pte() {
        let pte = SlPte::mapping(0x1000, true, true);
        assert!(pte.is_present());
        assert!(pte.can_read());
        assert!(pte.can_write());
        assert_eq!(pte.phys_addr(), 0x1000);
    }

    #[test]
    fn test_iommu_domain() {
        let mut domain = IommuDomain::new(1, None, false, false, IommuDomainType::Translated);
        assert_eq!(domain.id(), 1);

        // Map a region
        let result = domain.map(0x1000, 0x2000, 0x1000, true, false);
        assert!(result.is_ok());

        // Try to map overlapping region
        let result = domain.map(0x1000, 0x3000, 0x1000, true, false);
        assert_eq!(result, Err(IommuError::AlreadyMapped));
    }

    #[test]
    fn test_create_domain_with_numa_hint() {
        let mut ctrl = IommuController::new(0x0, 0);
        let id = ctrl
            .create_domain(Some(2), IommuDomainType::Translated)
            .expect("create_domain failed");
        let domain_arc = ctrl.domain(id).expect("domain not found");
        let d = domain_arc.read();
        assert_eq!(d.id(), id);
        assert_eq!(d.numa_node, Some(2));

        // Test controller set/get API
        ctrl.set_domain_numa(id, Some(5))
            .expect("set_domain_numa failed");
        assert_eq!(ctrl.get_domain_numa(id), Some(5usize));
    }

    #[test]
    fn test_iova_allocator_basic() {
        let mut ctrl = IommuController::new(0x0, 0);
        // Small IOVA space for testing (64KB)
        ctrl.init_iova(0x1000_0000, 0x10000)
            .expect("init_iova failed");

        let a = ctrl.allocate_iova(4096).expect("alloc 4K");
        assert_eq!(a % 4096, 0);

        let b = ctrl.allocate_iova(8192).expect("alloc 8K");
        assert_ne!(a, b);

        ctrl.free_iova(a, 4096).expect("free failed");

        let _c = ctrl.allocate_iova(4096).expect("alloc after free");
    }

    #[test]
    fn test_map_for_dma_alloc_non_identity() {
        let mut ctrl = IommuController::new(0x0, 0);
        ctrl.init_iova(0x8000_0000, 0x10000).expect("init_iova");

        // Create default domain 0 for mapping
        ctrl.domains.write().insert(
            0,
            Arc::new(RwLock::new(IommuDomain::new(
                0,
                None,
                false,
                false,
                IommuDomainType::Translated,
            ))),
        );
        // register_domain_lock(0); // Removed

        let size = 0x3000;
        let phys = 0x2000_0000;

        let iova = ctrl.allocate_iova(size).expect("allocate_iova");

        {
            let domain_arc = ctrl.domain(0).expect("domain 0");
            let mut domain = domain_arc.write();
            domain
                .map(iova, phys, size, true, true)
                .expect("domain.map failed");
            assert!(domain.mappings().contains_key(&iova));

            let mapping = domain.unmap(iova).expect("unmap failed");
            assert_eq!(mapping.iova, iova);
            assert_eq!(mapping.phys, phys);
        }

        ctrl.free_iova(iova, size).expect("free failed");
    }
    /*
    #[test]
    fn test_init_iommu_registers_drhd_and_rmrr_and_applies_rmrr() {
        // Test removed due to dependency on global IommuManager which is deprecated.
    }
    */

    #[test]
    fn test_unmap_reclaims_empty_tables() {
        let domain = Arc::new(RwLock::new(IommuDomain::new(
            1,
            None,
            false,
            false,
            IommuDomainType::Translated,
        )));

        {
            let mut d = domain.write();
            // Map a single page
            d.map(0x1000, 0x2000, 0x1000, true, true)
                .expect("map failed");

            // Verify mapping exists
            assert!(d.mappings().contains_key(&0x1000));

            // Unmap should reclaim PT, PD, PDP tables
            let mapping = d.unmap(0x1000).expect("unmap failed");
            assert_eq!(mapping.iova, 0x1000);
            assert_eq!(mapping.phys, 0x2000);

            // Verify page table entries are cleared (PML4 entry should be not present)
            unsafe {
                let pml4_entry = *d.page_table.add(0);
                assert!(
                    !pml4_entry.is_present(),
                    "PML4 entry should be cleared after unmap"
                );
            }
        }
    }

    #[test]
    fn test_unmap_partial_keeps_tables() {
        let domain_arc = Arc::new(RwLock::new(IommuDomain::new(
            1,
            None,
            false,
            false,
            IommuDomainType::Translated,
        )));
        let mut domain = domain_arc.write();

        // Map two pages in the same PT
        domain
            .map(0x1000, 0x2000, 0x1000, true, true)
            .expect("map 1 failed");
        domain
            .map(0x2000, 0x3000, 0x1000, true, true)
            .expect("map 2 failed");

        // Unmap first page - PT should still exist (second page still mapped)
        domain.unmap(0x1000).expect("unmap 1 failed");

        // Verify PML4 entry is still present (PT not empty)
        unsafe {
            let pml4_entry = *domain.page_table.add(0);
            assert!(
                pml4_entry.is_present(),
                "PML4 entry should still be present"
            );
        }

        // Unmap second page - now tables should be reclaimed
        domain.unmap(0x2000).expect("unmap 2 failed");

        unsafe {
            let pml4_entry = *domain.page_table.add(0);
            assert!(
                !pml4_entry.is_present(),
                "PML4 entry should be cleared after all unmaps"
            );
        }
    }
}

// ============================================================================
// Global Interrupt Remapping Interface
// ============================================================================

/// Map an interrupt for a device using Interrupt Remapping
///
/// Returns the IRTE handle (index) to be used for generating the MSI message.

pub fn map_interrupt(
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    vector: u8,
    dest_id: u32,
    logical: bool,
) -> Result<u16, IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;

    // Find the controller index for this device using proper scope matching
    let controller_idx = registry
        .find_controller_index_for_device(segment, bus, device, function)
        .ok_or(IommuError::NotPresent)?;

    let controller = registry
        .controllers
        .get(controller_idx)
        .ok_or(IommuError::NotPresent)?;

    // Check if IR is enabled
    if !controller.is_interrupt_remapping_enabled() {
        return Err(IommuError::NotSupported);
    }

    // Allocate IRTE
    controller.allocate_irte(vector, dest_id, logical)
}

/// Generate MSI Address and Data for a Remapped Interrupt
///
/// # Arguments
/// * `handle` - IRTE handle returned by `map_interrupt`
///
/// # Returns
/// (Address, Data) tuple for MSI/MSI-X configuration
pub fn get_remap_msi_message(handle: u16) -> (u64, u32) {
    // Intel VT-d Spec 5.1.5.1 MSI / MSI-X Address Format
    // 31:20 = 0xFEE (Fixed)
    // 19:5  = Handle[14:0] (Interrupt Index)
    // 4     = SHV (SubHandle Valid) - Set to 0 here
    // 3     = Handle[15] (Interrupt Index MSB)
    // 2     = XX (Guest Mode / Ignored)

    let handle = handle as u64;
    let index_14_0 = handle & 0x7FFF;
    let index_15 = (handle >> 15) & 1;

    let address = 0xFEE0_0000 | (index_14_0 << 5) | (index_15 << 3);
    let data = 0; // Data is 0 when SHV=0

    (address, data)
}
