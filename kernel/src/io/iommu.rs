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
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

// PCI helpers used when enabling ATS for devices
use pci_driver::{AtsController, PcieBdf, device_supports_ats, pcie_ext_config};

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
pub struct FaultLog {
    /// Ring buffer of fault records
    records: Vec<FaultRecord>,
    /// Write index (next slot to write)
    write_idx: usize,
    /// Number of records stored
    count: usize,
    /// Total faults recorded (may exceed capacity)
    total_faults: u64,
    /// Capacity (max records)
    capacity: usize,
}

impl FaultLog {
    /// Default capacity
    pub const DEFAULT_CAPACITY: usize = 64;

    /// Create a new fault log
    pub fn new(capacity: usize) -> Self {
        Self {
            records: alloc::vec![FaultRecord::default(); capacity],
            write_idx: 0,
            count: 0,
            total_faults: 0,
            capacity,
        }
    }

    /// Add a fault record
    pub fn push(&mut self, record: FaultRecord) {
        self.records[self.write_idx] = record;
        self.write_idx = (self.write_idx + 1) % self.capacity;
        self.total_faults += 1;
        if self.count < self.capacity {
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
                self.capacity - (i + 1 - self.write_idx)
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

    /// Allocate an IRTE index
    pub fn allocate(&mut self) -> Option<u16> {
        for (word_idx, word) in self.allocated.iter_mut().enumerate() {
            if *word != u64::MAX {
                // Find first free bit
                let bit = (!*word).trailing_zeros();
                *word |= 1 << bit;
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

/// Page Table Pool for reduced allocation overhead
///
/// Pre-allocates page tables and recycles freed ones.
pub struct PageTablePool {
    /// Free page tables (4KB aligned, zeroed)
    free_list: Vec<usize>,
    /// Total allocated
    total_allocated: usize,
    /// Maximum pool size
    max_size: usize,
}

impl PageTablePool {
    /// Default pool size
    const DEFAULT_MAX: usize = 256;

    /// Create a new page table pool
    pub fn new(max_size: usize) -> Self {
        Self {
            free_list: Vec::with_capacity(max_size),
            total_allocated: 0,
            max_size,
        }
    }

    /// Pre-allocate page tables
    pub fn preallocate(&mut self, count: usize) -> Result<(), ()> {
        use core::alloc::Layout;
        let layout = Layout::from_size_align(4096, 4096).map_err(|_| ())?;

        for _ in 0..count.min(self.max_size - self.free_list.len()) {
            if let Some(ptr) = crate::util::allocate_zeroed(layout) {
                self.free_list.push(ptr.as_ptr() as usize);
                self.total_allocated += 1;
            } else {
                return Err(());
            }
        }
        Ok(())
    }

    /// Allocate a page table from pool (or fresh allocation)
    pub fn allocate(&mut self) -> Option<*mut SlPte> {
        if let Some(addr) = self.free_list.pop() {
            // Zero the recycled page table
            unsafe {
                core::ptr::write_bytes(addr as *mut u8, 0, 4096);
            }
            Some(addr as *mut SlPte)
        } else {
            // Allocate new
            use core::alloc::Layout;
            let layout = Layout::from_size_align(4096, 4096).ok()?;
            if let Some(ptr) = crate::util::allocate_zeroed(layout) {
                self.total_allocated += 1;
                Some(ptr.as_ptr() as *mut SlPte)
            } else {
                None
            }
        }
    }

    /// Return a page table to the pool
    pub fn free(&mut self, ptr: *mut SlPte) {
        if self.free_list.len() < self.max_size {
            self.free_list.push(ptr as usize);
        } else {
            // Pool full, actually deallocate (not implemented, just leak for now)
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.free_list.len(), self.total_allocated)
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

        Self {
            id,
            domain_type,
            page_table,
            mappings: BTreeMap::new(),
            mapped_size: 0,
            numa_node,
            supports_2mb,
            supports_1gb,
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

        // self.page_table is the PML4 root
        unsafe {
            // Level 4: PML4 -> PDP
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                // Allocate PDP table on the domain's preferred NUMA node when available
                let pdp = Self::allocate_page_table(self.numa_node)?;
                *pml4_entry = SlPte((pdp as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE);
            }
            let pdp_table = ((*pml4_entry).phys_addr()) as *mut SlPte;

            // Level 3: PDP -> PD
            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                // Allocate PD table on the domain's preferred NUMA node when available
                let pd = Self::allocate_page_table(self.numa_node)?;
                *pdp_entry = SlPte((pd as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE);
            }
            let pd_table = ((*pdp_entry).phys_addr()) as *mut SlPte;

            // Level 2: PD -> PT
            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                // Allocate PT on the domain's preferred NUMA node when available
                let pt = Self::allocate_page_table(self.numa_node)?;
                *pd_entry = SlPte((pt as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE);
            }
            let pt_table = ((*pd_entry).phys_addr()) as *mut SlPte;

            // Level 1: PT -> Page
            let pt_entry = pt_table.add(pt_idx);
            if (*pt_entry).is_present() {
                return Err(IommuError::AlreadyMapped);
            }
            *pt_entry = SlPte::mapping(phys, read, write);
        }

        Ok(())
    }

    /// Allocate a zeroed page table
    fn allocate_page_table(numa_hint: Option<usize>) -> Result<*mut SlPte, IommuError> {
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .map_err(|_| IommuError::HardwareError)?;

        // Prefer NUMA-aware allocation when a hint is available
        let ptr = if let Some(node) = numa_hint {
            crate::mm::numa::allocate_zeroed_on_node(layout, Some(node))
                .ok_or(IommuError::HardwareError)?
        } else {
            crate::util::allocate_zeroed(layout).ok_or(IommuError::HardwareError)?
        }
        .as_ptr() as *mut SlPte;

        Ok(ptr)
    }

    /// Map a 2MB super-page
    ///
    /// Uses 3-level page table walking (PML4 -> PDP -> PD) and sets super-page at PD level.
    /// Both iova and phys must be 2MB-aligned.
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

        let pml4_table = self.page_table;
        let pml4_entry = unsafe { pml4_table.add(pml4_idx) };

        // Ensure PDP exists
        if !(unsafe { *pml4_entry }).is_present() {
            let pdp = Self::allocate_page_table(self.numa_node)?;
            unsafe {
                *pml4_entry = SlPte((pdp as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE)
            };
        }

        let pdp_table = ((unsafe { *pml4_entry }).phys_addr()) as *mut SlPte;
        let pdp_entry = unsafe { pdp_table.add(pdp_idx) };

        // Ensure PD exists
        if !(unsafe { *pdp_entry }).is_present() {
            let pd = Self::allocate_page_table(self.numa_node)?;
            unsafe {
                *pdp_entry = SlPte((pd as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE)
            };
        } else if (unsafe { *pdp_entry }).is_super_page() {
            // Already a 1GB super-page at this level
            return Err(IommuError::AlreadyMapped);
        }

        let pd_table = ((unsafe { *pdp_entry }).phys_addr()) as *mut SlPte;
        let pd_entry = unsafe { pd_table.add(pd_idx) };

        // Check if already mapped
        if !(unsafe { *pd_entry }).is_present() {
            return Err(IommuError::AlreadyMapped);
        }

        // Create 2MB super-page entry
        unsafe { *pd_entry = SlPte::super_page_2mb(phys, read, write) };

        Ok(())
    }

    /// Map a 1GB super-page
    ///
    /// Uses 2-level page table walking (PML4 -> PDP) and sets super-page at PDP level.
    /// Both iova and phys must be 1GB-aligned.
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

        let pml4_table = self.page_table;
        let pml4_entry = unsafe { pml4_table.add(pml4_idx) };

        // Ensure PDP exists
        if !(unsafe { *pml4_entry }).is_present() {
            let pdp = Self::allocate_page_table(self.numa_node)?;
            unsafe {
                *pml4_entry = SlPte((pdp as u64) | SlPte::PRESENT | SlPte::READ | SlPte::WRITE)
            };
        }

        let pdp_table = ((unsafe { *pml4_entry }).phys_addr()) as *mut SlPte;
        let pdp_entry = unsafe { pdp_table.add(pdp_idx) };

        // Check if already mapped
        if !(unsafe { *pdp_entry }).is_present() {
            return Err(IommuError::AlreadyMapped);
        }

        // Create 1GB super-page entry
        unsafe { *pdp_entry = SlPte::super_page_1gb(phys, read, write) };

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
    fn unmap_page(&mut self, iova: u64) -> Result<(), IommuError> {
        // Extract indices for each level
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;

        unsafe {
            // Walk down to PT
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;

            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;

            let pt_entry = pt_table.add(pt_idx);
            if !(*pt_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            *pt_entry = SlPte::new();
        }

        Ok(())
    }

    /// Get total mapped size
    pub fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    /// Get all mappings
    pub fn mappings(&self) -> &BTreeMap<u64, DmaMapping> {
        &self.mappings
    }
}

impl Drop for IommuDomain {
    fn drop(&mut self) {
        if !self.page_table.is_null() {
            let layout = alloc::alloc::Layout::from_size_align(
                PT_ENTRIES * core::mem::size_of::<SlPte>(),
                4096,
            )
            .unwrap();

            unsafe {
                alloc::alloc::dealloc(self.page_table as *mut u8, layout);
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

/// IOMMU Controller
pub struct IommuController {
    /// MMIO base address
    mmio_base: u64,
    /// Capabilities
    cap: u64,
    /// Extended capabilities
    ecap: u64,
    /// Root table
    root_table: *mut RootEntry,
    /// Context tables (per bus)
    context_tables: Vec<*mut ContextEntry>,
    /// Domains
    domains: BTreeMap<u16, IommuDomain>,
    /// Device to domain mapping
    device_domains: BTreeMap<DeviceId, u16>,
    /// Next domain ID
    next_domain_id: AtomicU64,
    /// Translation enabled
    enabled: AtomicBool,
    /// Interrupt Remapping Table (optional, if supported)
    interrupt_remap_table: Option<InterruptRemapTable>,
    /// Interrupt remapping enabled
    ir_enabled: AtomicBool,
    /// Queued Invalidation Queue (optional, if supported)
    invalidation_queue: Option<InvalidationQueue>,
    /// Queued Invalidation enabled
    qi_enabled: AtomicBool,
    /// IOMMU Segment number (from ACPI DRHD)
    pub segment: u16,
    /// IOVA allocator (optional, configured via `init_iova`)
    iova_allocator: Option<IovaAllocator>,
    /// Set of devices with ATS enabled (for optimization)
    ats_enabled_devices: BTreeSet<DeviceId>,
    /// Posted Interrupt Descriptor pool (base address, allocation bitmap)
    /// Each PID is 64-byte aligned, pool can hold up to 256 PIDs
    pid_pool: Option<PostedInterruptPool>,
    /// Page Request Queue (PRI/ATS)
    page_request_queue: Option<PageRequestQueue>,
    /// Fault log ring buffer
    fault_log: Option<FaultLog>,
    /// Device scopes from DRHD (for proper device-to-IOMMU matching)
    device_scopes: Vec<IommuDeviceScope>,
    /// Include all devices (from DRHD INCLUDE_PCI_ALL flag)
    include_all: bool,
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
            root_table: core::ptr::null_mut(),
            context_tables: Vec::new(),
            domains: BTreeMap::new(),
            device_domains: BTreeMap::new(),
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: None,
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: None,
            qi_enabled: AtomicBool::new(false),
            iova_allocator: None,
            ats_enabled_devices: BTreeSet::new(),
            pid_pool: None,
            page_request_queue: None,
            fault_log: None,
            device_scopes: Vec::new(),
            include_all: false,
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
            root_table: core::ptr::null_mut(),
            context_tables: Vec::new(),
            domains: BTreeMap::new(),
            device_domains: BTreeMap::new(),
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: None,
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: None,
            qi_enabled: AtomicBool::new(false),
            iova_allocator: None,
            ats_enabled_devices: BTreeSet::new(),
            pid_pool: None,
            page_request_queue: None,
            fault_log: None,
            device_scopes: scopes,
            include_all,
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
    pub fn enable_ats_for_device(&mut self, device: DeviceId) {
        self.ats_enabled_devices.insert(device);
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
        self.root_table = crate::util::allocate_zeroed(rt_layout)
            .expect("Failed to allocate root table")
            .as_ptr() as *mut RootEntry;

        if self.root_table.is_null() {
            return Err(IommuError::HardwareError);
        }

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

            self.context_tables.push(ct);
        }

        // Set root table address
        self.write64(regs::RTADDR, self.root_table as u64);

        // Set root table pointer
        self.write32(regs::GCMD, gcmd_bits::GCMD_SRTP);

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_RTPS != 0 {
                break;
            }
        }

        Ok(())
    }

    /// Enable DMA remapping
    pub unsafe fn enable(&self) -> Result<(), IommuError> {
        // Write buffer flush if required
        if self.cap & cap_bits::CAP_RWBF != 0 {
            self.write32(regs::GCMD, gcmd_bits::GCMD_WBF);

            for _ in 0..1000 {
                if self.read32(regs::GSTS) & gsts_bits::GSTS_WBFS == 0 {
                    break;
                }
            }
        }

        // Enable translation
        self.write32(regs::GCMD, gcmd_bits::GCMD_TE);

        // Enable Interrupt Remapping if table is present
        if self.interrupt_remap_table.is_some() {
            match unsafe { self.enable_interrupt_remapping() } {
                Ok(_) => log::info!("[IOMMU] Interrupt Remapping enabled during global enable\n"),
                Err(e) => log::warn!("[IOMMU] Failed to enable Interrupt Remapping: {:?}\n", e),
            }
        }

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_TES != 0 {
                self.enabled.store(true, Ordering::Release);
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
    }

    /// Disable DMA remapping
    pub unsafe fn disable(&self) -> Result<(), IommuError> {
        // Clear translation enable
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_TE);

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_TES == 0 {
                self.enabled.store(false, Ordering::Release);
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
    }

    /// Check if translation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Create a new domain
    /// Create a new domain with an optional NUMA node affinity hint
    pub fn create_domain(
        &mut self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let id = self.next_domain_id.fetch_add(1, Ordering::Relaxed) as u16;

        let supports_2mb = self.supports_2mb_pages();
        let supports_1gb = self.supports_1gb_pages();

        let domain = IommuDomain::new(id, numa_node, supports_2mb, supports_1gb, domain_type);
        self.domains.insert(id, domain);

        // Register per-domain lock for parallel operations
        register_domain_lock(id);

        Ok(id)
    }

    /// Set a domain's NUMA affinity (best-effort). Does NOT migrate existing
    /// page tables or mappings; this is only a hint for future allocations.
    pub fn set_domain_numa(
        &mut self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;
        domain.numa_node = numa_node;
        Ok(())
    }

    /// Get domain NUMA hint
    pub fn get_domain_numa(&self, domain_id: u16) -> Option<usize> {
        self.domains.get(&domain_id).and_then(|d| d.numa_node)
    }

    /// Get a domain by ID
    pub fn domain(&self, id: u16) -> Option<&IommuDomain> {
        self.domains.get(&id)
    }

    /// Get a mutable domain by ID
    pub fn domain_mut(&mut self, id: u16) -> Option<&mut IommuDomain> {
        self.domains.get_mut(&id)
    }

    /// Attach a device to a domain
    pub fn attach_device(&mut self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        let domain = self
            .domains
            .get(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;

        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        // Setup root entry
        let root_entry = unsafe { &mut *self.root_table.add(bus) };
        if !root_entry.is_present() {
            root_entry.set_context_table(self.context_tables[bus] as u64);
        }

        // Setup context entry
        let context_entry = unsafe { &mut *self.context_tables[bus].add(devfn) };

        // 48-bit address width (AGAW = 2)
        if domain.domain_type() == IommuDomainType::Passthrough {
            context_entry.set_passthrough(domain.id());
        } else {
            context_entry.set_sl_pt(domain.page_table_addr(), domain.id(), 2);
        }

        self.device_domains.insert(device, domain_id);

        Ok(())
    }

    /// Detach a device from its domain
    pub fn detach_device(&mut self, device: DeviceId) -> Result<(), IommuError> {
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        // Clear context entry
        let context_entry = unsafe { &mut *self.context_tables[bus].add(devfn) };

        *context_entry = ContextEntry::default();

        self.device_domains.remove(&device);

        Ok(())
    }

    /// Map DMA region for a device
    pub fn map_dma(
        &mut self,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let domain_id = self
            .device_domains
            .get(device)
            .copied()
            .ok_or(IommuError::DeviceNotFound)?;

        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;

        domain.map(iova, phys, size, read, write)
    }

    /// Unmap DMA region for a device
    pub fn unmap_dma(&mut self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let domain_id = self
            .device_domains
            .get(device)
            .copied()
            .ok_or(IommuError::DeviceNotFound)?;

        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;

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
                && self.ats_enabled_devices.contains(device);

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

    /// Invalidate IOTLB for a domain
    pub unsafe fn invalidate_iotlb(&mut self, domain_id: u16) {
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

        self.write64(regs::CCMD, cmd);

        // Wait for completion
        for _ in 0..1000 {
            if self.read64(regs::CCMD) & (1u64 << 63) == 0 {
                break;
            }
        }
    }

    /// Invalidate IOTLB globally (all domains)
    pub unsafe fn invalidate_iotlb_global(&mut self) {
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

        crate::io::mmio::mmio_write_u64(iotlb_reg as usize, cmd);

        // Wait for completion
        for _ in 0..1000 {
            let status = crate::io::mmio::mmio_read_u64(iotlb_reg as usize);
            if status & iotlb_bits::IOTLB_IVT == 0 {
                break;
            }
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

        if self.interrupt_remap_table.is_some() {
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
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_IRTPS != 0 {
                break;
            }
        }

        self.interrupt_remap_table = Some(irt);
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

        if self.interrupt_remap_table.is_none() {
            return Err(IommuError::NotPresent);
        }

        // Enable Interrupt Remapping (GCMD.IRE)
        self.write32(regs::GCMD, gcmd_bits::GCMD_IRE);

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_IRES != 0 {
                self.ir_enabled.store(true, Ordering::Release);
                log::info!("[IOMMU] Interrupt Remapping enabled\n");
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
    }

    /// Disable interrupt remapping
    pub unsafe fn disable_interrupt_remapping(&self) -> Result<(), IommuError> {
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_IRE);

        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_IRES == 0 {
                self.ir_enabled.store(false, Ordering::Release);
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
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
        self.fault_log = Some(FaultLog::new(FaultLog::DEFAULT_CAPACITY));
        log::info!("[IOMMU] Fault handling initialized\\n");
    }

    /// Process pending faults from the Fault Recording Registers
    /// Returns the number of faults processed
    pub fn process_faults(&mut self) -> usize {
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
                // Log the fault
                log::error!(
                    "[IOMMU] Fault: reason={:#x}, source={:04x}, addr={:#x}, pasid={:?}\\n",
                    record.reason(),
                    record.source_id(),
                    record.fault_address(),
                    record.pasid()
                );

                // Add to fault log
                if let Some(log) = &mut self.fault_log {
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

    /// Get the fault log for inspection
    pub fn fault_log(&self) -> Option<&FaultLog> {
        self.fault_log.as_ref()
    }

    /// Get recent faults from the log
    pub fn recent_faults(&self, count: usize) -> alloc::vec::Vec<FaultRecord> {
        if let Some(log) = &self.fault_log {
            log.recent(count)
        } else {
            alloc::vec::Vec::new()
        }
    }

    /// Get total number of faults recorded
    pub fn total_fault_count(&self) -> u64 {
        self.fault_log
            .as_ref()
            .map(|l| l.total_faults())
            .unwrap_or(0)
    }

    /// Allocate an IRTE for a device interrupt
    /// Returns the IRTE index that should be used in the interrupt message
    pub fn allocate_irte(
        &mut self,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError> {
        let irt = self
            .interrupt_remap_table
            .as_mut()
            .ok_or(IommuError::NotPresent)?;

        let index = irt.allocate().ok_or(IommuError::HardwareError)?;

        let entry = InterruptRemapEntry::fixed(vector, dest_id, logical, false);
        irt.set(index, entry);

        Ok(index)
    }

    /// Free an IRTE
    pub fn free_irte(&mut self, index: u16) -> Result<(), IommuError> {
        let irt = self
            .interrupt_remap_table
            .as_mut()
            .ok_or(IommuError::NotPresent)?;

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
        let irt = self
            .interrupt_remap_table
            .as_mut()
            .ok_or(IommuError::NotPresent)?;

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

        if self.pid_pool.is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        let pool = PostedInterruptPool::new(num_pids).ok_or(IommuError::HardwareError)?;
        self.pid_pool = Some(pool);

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

        let pid_pool = self.pid_pool.as_mut().ok_or(IommuError::NotPresent)?;
        let irt = self
            .interrupt_remap_table
            .as_mut()
            .ok_or(IommuError::NotPresent)?;

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
    pub fn free_posted_irte(&mut self, irte_index: u16, pid_index: u16) -> Result<(), IommuError> {
        // Free IRTE
        if let Some(irt) = self.interrupt_remap_table.as_mut() {
            irt.set(irte_index, InterruptRemapEntry::new());
            irt.free(irte_index);
        }

        // Free PID
        if let Some(pool) = self.pid_pool.as_mut() {
            pool.free(pid_index);
        }

        Ok(())
    }

    /// Set a pending vector in a Posted Interrupt Descriptor
    ///
    /// This is called when an interrupt needs to be posted to a vCPU.
    pub fn post_interrupt(&mut self, pid_index: u16, vector: u8) -> Result<(), IommuError> {
        let pool = self.pid_pool.as_mut().ok_or(IommuError::NotPresent)?;
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

        if self.page_request_queue.is_some() {
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
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & (1 << 28) != 0 {
                break;
            }
        }

        self.page_request_queue = Some(prq);
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

        if let Some(prq) = self.page_request_queue.as_mut() {
            prq.update_tail(tail);

            // Pop all pending entries
            while let Some(entry) = prq.pop() {
                requests.push(entry);
            }

            // Cache head and drop the mutable borrow before writing registers
            let head = prq.head();
            let _ = prq; // release mutable borrow reference
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
    pub fn init_iova(&mut self, base: u64, size: u64) -> Result<(), IommuError> {
        self.iova_allocator = Some(IovaAllocator::new(base, size));
        Ok(())
    }

    /// Allocate an IOVA range from controller's allocator (4KB granularity)
    pub fn allocate_iova(&mut self, size: u64) -> Result<u64, IommuError> {
        let alloc = self.iova_allocator.as_mut().ok_or(IommuError::NotPresent)?;
        alloc
            .allocate(size, IovaGranularity::Page4K)
            .ok_or(IommuError::HardwareError)
    }

    /// Allocate an IOVA range with specific granularity (for super-pages)
    pub fn allocate_iova_aligned(
        &mut self,
        size: u64,
        granularity: IovaGranularity,
    ) -> Result<u64, IommuError> {
        let alloc = self.iova_allocator.as_mut().ok_or(IommuError::NotPresent)?;
        alloc
            .allocate(size, granularity)
            .ok_or(IommuError::HardwareError)
    }

    /// Free an IOVA range
    pub fn free_iova(&mut self, addr: u64, size: u64) -> Result<(), IommuError> {
        let alloc = self.iova_allocator.as_mut().ok_or(IommuError::NotPresent)?;
        alloc.free(addr, size)
    }

    /// Initialize IOVA space for the global IOMMU controller (Default only)
    pub fn init_iova_range(base: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = IOMMU.lock();
        let idx = guard.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = guard
            .controllers
            .get_mut(idx)
            .ok_or(IommuError::NotPresent)?;
        controller.init_iova(base, size)
    }

    /// Allocate an IOVA from the global controller
    pub fn allocate_global_iova(size: u64) -> Result<u64, IommuError> {
        let mut guard = IOMMU.lock();
        let idx = guard.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = guard
            .controllers
            .get_mut(idx)
            .ok_or(IommuError::NotPresent)?;
        controller.allocate_iova(size)
    }

    /// Free an IOVA back to global controller
    pub fn free_global_iova(addr: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = IOMMU.lock();
        let idx = guard.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = guard
            .controllers
            .get_mut(idx)
            .ok_or(IommuError::NotPresent)?;
        controller.free_iova(addr, size)
    }

    /// Allocate an IOVA and create a mapping in default domain (non-identity mapping)
    pub fn map_for_dma_alloc(phys_addr: x86_64::PhysAddr, size: u64) -> Result<u64, IommuError> {
        let mut guard = IOMMU.lock();
        let idx = guard.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = guard
            .controllers
            .get_mut(idx)
            .ok_or(IommuError::NotPresent)?;

        // Allocate IOVA
        let iova = controller.allocate_iova(size)?;

        // Default domain is 0
        let domain = controller
            .domains
            .get_mut(&0)
            .ok_or(IommuError::DomainNotFound)?;
        domain.map(iova, phys_addr.as_u64(), size, true, true)?;

        Ok(iova)
    }

    /// Unmap IOVA and free it
    pub fn unmap_dma_alloc(iova: u64, _size: u64) -> Result<(), IommuError> {
        let mut guard = IOMMU.lock();
        let idx = guard.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = guard
            .controllers
            .get_mut(idx)
            .ok_or(IommuError::NotPresent)?;

        // Default domain
        let domain = controller
            .domains
            .get_mut(&0)
            .ok_or(IommuError::DomainNotFound)?;
        domain.unmap(iova)?;
        // Free IOVA - size argument used to determine pages freed
        controller.free_iova(iova, _size)?;

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

        if self.invalidation_queue.is_some() {
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

        self.invalidation_queue = Some(iq);
        log::info!(
            "[IOMMU] Invalidation Queue initialized ({} entries)\n",
            1 << size_log2
        );

        Ok(())
    }

    /// Enable Queued Invalidation
    pub unsafe fn enable_queued_invalidation(&self) -> Result<(), IommuError> {
        if self.invalidation_queue.is_none() {
            return Err(IommuError::NotPresent);
        }

        // Enable QI (GCMD.QIE)
        self.write32(regs::GCMD, gcmd_bits::GCMD_QIE);

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_QIES != 0 {
                self.qi_enabled.store(true, Ordering::Release);
                log::info!("[IOMMU] Queued Invalidation enabled\n");
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
    }

    /// Disable Queued Invalidation
    pub unsafe fn disable_queued_invalidation(&self) -> Result<(), IommuError> {
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_QIE);

        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_QIES == 0 {
                self.qi_enabled.store(false, Ordering::Release);
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
    }

    /// Check if Queued Invalidation is enabled
    pub fn is_queued_invalidation_enabled(&self) -> bool {
        self.qi_enabled.load(Ordering::Acquire)
    }

    /// Submit a queued invalidation request
    pub fn submit_invalidation(&mut self, entry: InvalidationQueueEntry) -> Result<(), IommuError> {
        let new_tail = {
            let iq = self
                .invalidation_queue
                .as_mut()
                .ok_or(IommuError::NotPresent)?;

            iq.submit(entry);
            (iq.tail() << 4) as u64 // Tail is in 16-byte units
        };

        // Update hardware tail pointer (borrow released)
        self.write64(regs::IQT, new_tail);

        Ok(())
    }

    /// Submit a global IOTLB invalidation via queued invalidation
    pub fn qi_invalidate_iotlb_global(&mut self, drain: bool) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_global(drain);
        self.submit_invalidation(entry)
    }

    /// Submit a domain IOTLB invalidation via queued invalidation
    pub fn qi_invalidate_iotlb_domain(
        &mut self,
        domain_id: u16,
        drain: bool,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iotlb_invalidate_domain(domain_id, drain);
        self.submit_invalidation(entry)
    }

    /// Submit a page-selective IOTLB invalidation via queued invalidation
    pub fn qi_invalidate_iotlb_page(
        &mut self,
        domain_id: u16,
        addr: u64,
        drain: bool,
    ) -> Result<(), IommuError> {
        // AM (Address Mask) = 0 for 4KB page
        let entry = InvalidationQueueEntry::iotlb_invalidate(3, domain_id, drain, addr);
        self.submit_invalidation(entry)
    }

    /// Submit a global context-cache invalidation via queued invalidation
    pub fn qi_invalidate_context_global(&mut self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::context_cache_invalidate_global();
        self.submit_invalidation(entry)
    }

    /// Submit a global IEC invalidation via queued invalidation
    pub fn qi_invalidate_iec_global(&mut self) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::iec_invalidate_global();
        self.submit_invalidation(entry)
    }

    /// Submit a Device-TLB invalidation via queued invalidation
    /// Used for ATS-enabled PCIe devices that cache translations
    pub fn qi_invalidate_device_tlb(
        &mut self,
        source_id: u16,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        let entry = InvalidationQueueEntry::device_tlb_invalidate_device(source_id, domain_id);
        self.submit_invalidation(entry)
    }

    /// Submit a page-selective Device-TLB invalidation
    pub fn qi_invalidate_device_tlb_page(
        &mut self,
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
    pub fn qi_wait_sync(&mut self) -> Result<(), IommuError> {
        // Get tail after submitting wait
        let new_tail = {
            let iq = self
                .invalidation_queue
                .as_mut()
                .ok_or(IommuError::NotPresent)?;

            let _status_addr = iq.submit_wait();
            (iq.tail() << 4) as u64
        };

        // Update hardware tail (borrow released)
        self.write64(regs::IQT, new_tail);

        // Wait for hardware head to catch up (all descriptors processed)
        let expected_tail = new_tail >> 4;
        for _ in 0..10000 {
            let head = self.read64(regs::IQH) >> 4;
            if head == expected_tail {
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
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

/// Cache entry for device to domain mapping
#[derive(Clone, Copy, Default)]
struct DomainCacheEntry {
    device_id: u16,
    domain_id: u16,
    controller_idx: u8,
    valid: bool,
}

/// Per-CPU cache to reduce lock contention on global IOMMU lock
///
/// Stores frequently accessed device-to-domain mappings.
/// A simple direct-mapped cache is sufficient as devices are usually fixed
/// to a specific core's workload.
pub struct PerCpuDomainCache {
    entries: [DomainCacheEntry; 32],
}

impl PerCpuDomainCache {
    const fn new() -> Self {
        Self {
            entries: [DomainCacheEntry {
                device_id: 0,
                domain_id: 0,
                controller_idx: 0,
                valid: false,
            }; 32],
        }
    }

    fn lookup(&self, device_id: u16) -> Option<(u16, u8)> {
        let idx = (device_id as usize) % 32;
        let entry = self.entries[idx];
        if entry.valid && entry.device_id == device_id {
            Some((entry.domain_id, entry.controller_idx))
        } else {
            None
        }
    }

    fn insert(&mut self, device_id: u16, domain_id: u16, controller_idx: u8) {
        let idx = (device_id as usize) % 32;
        self.entries[idx] = DomainCacheEntry {
            device_id,
            domain_id,
            controller_idx,
            valid: true,
        };
    }

    fn invalidate(&mut self, device_id: u16) {
        let idx = (device_id as usize) % 32;
        if self.entries[idx].device_id == device_id {
            self.entries[idx].valid = false;
        }
    }
}

/// Global cache array (one per CPU, up to 256 CPUs)
static CPU_DOMAIN_CACHES: Mutex<[PerCpuDomainCache; 256]> =
    Mutex::new([PerCpuDomainCache::new(); 256]);

/// Lookup domain in local CPU cache
fn lookup_domain_cached(device_id: u16) -> Option<(u16, u8)> {
    let cpu_id = crate::smp::current_cpu() as usize;
    if cpu_id >= 256 {
        return None;
    }

    // We use a try_lock to avoid blocking on the cache logic if it's contended
    // Failing to lock just means a cache miss, which is fine (correctness preserved)
    if let Some(caches) = CPU_DOMAIN_CACHES.try_lock() {
        caches[cpu_id].lookup(device_id)
    } else {
        None
    }
}

/// Update local CPU cache
fn cache_domain_mapping(device_id: u16, domain_id: u16, controller_idx: u8) {
    let cpu_id = crate::smp::current_cpu() as usize;
    if cpu_id >= 256 {
        return;
    }

    if let Some(mut caches) = CPU_DOMAIN_CACHES.try_lock() {
        caches[cpu_id].insert(device_id, domain_id, controller_idx);
    }
}

/// Invalidate a mapping in ALL CPU caches (slow path, but rare)
fn invalidate_domain_cache(device_id: u16) {
    let mut caches = CPU_DOMAIN_CACHES.lock();
    for cache in caches.iter_mut() {
        cache.invalidate(device_id);
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

/// IOMMU Manager (Manages multiple IOMMU controllers)
pub struct IommuManager {
    /// List of IOMMU controllers
    controllers: Vec<IommuController>,
    /// IOMMU for legacy/all devices (if any unit has include_all)
    default_iommu_idx: Option<usize>,
    /// Reserved memory regions
    reserved_regions: Vec<ReservedMemoryRegion>,
    /// Global Configuration
    pub config: IommuConfig,
}

unsafe impl Send for IommuManager {}
unsafe impl Sync for IommuManager {}

impl IommuManager {
    pub const fn new() -> Self {
        Self {
            controllers: Vec::new(),
            default_iommu_idx: None,
            reserved_regions: Vec::new(),
            config: IommuConfig::new(),
        }
    }

    /// Add a reserved memory region
    pub fn add_reserved_region(&mut self, region: ReservedMemoryRegion) {
        self.reserved_regions.push(region);
    }

    /// Apply reserved regions for a specific device to a domain
    pub fn apply_reserved_regions(
        &self,
        device_id: DeviceId,
        domain_id: u16,
        controller: &mut IommuController,
    ) -> Result<(), IommuError> {
        let domain = controller
            .domain_mut(domain_id)
            .ok_or(IommuError::DomainNotFound)?;

        for region in &self.reserved_regions {
            if region.segment != device_id.segment {
                continue;
            }

            // Check if this device is in the region's scope
            let in_scope = region.devices.iter().any(|d| *d == device_id);

            if in_scope {
                let size = region.limit - region.base + 1;
                log::info!(
                    "[IOMMU] Mapping RMRR for {:?}: {:#x} - {:#x}\n",
                    device_id,
                    region.base,
                    region.limit
                );
                // RMRR regions are typically R/W
                // Ignore overlap errors (might share regions)
                let _ = domain.map_identity(region.base, size, true, true);
            }
        }
        Ok(())
    }

    /// Add a controller
    pub fn add_controller(&mut self, controller: IommuController) {
        self.controllers.push(controller);
    }

    /// Get controller by index
    pub fn get_controller(&self, index: usize) -> Option<&IommuController> {
        self.controllers.get(index)
    }

    /// Get mutable controller by index
    pub fn get_controller_mut(&mut self, index: usize) -> Option<&mut IommuController> {
        self.controllers.get_mut(index)
    }

    /// Find the IOMMU controller responsible for a specific device
    ///
    /// Uses DRHD device scopes for proper matching:
    /// 1. First, check controllers with explicit device scopes
    /// 2. Fallback to include_all controller for the segment
    /// 3. Final fallback to default controller
    ///
    /// # Arguments
    /// * `segment` - PCI segment number
    /// * `bus` - PCI bus number
    /// * `device` - PCI device number
    /// * `function` - PCI function number
    pub fn find_controller_for_device(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Option<&IommuController> {
        // First pass: Find controller with explicit scope match
        for controller in &self.controllers {
            if controller.segment != segment {
                continue;
            }

            // Skip include_all controllers in first pass
            if controller.include_all {
                continue;
            }

            // Check if device matches any scope
            if controller.device_in_scope(bus, device, function) {
                return Some(controller);
            }
        }

        // Second pass: Find include_all controller for this segment
        for controller in &self.controllers {
            if controller.segment == segment && controller.include_all {
                return Some(controller);
            }
        }

        // Fallback to default
        if let Some(idx) = self.default_iommu_idx {
            return self.controllers.get(idx);
        }

        None
    }

    /// Find mutable controller using proper scope matching
    pub fn find_controller_for_device_mut(
        &mut self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Option<&mut IommuController> {
        // First pass: Find controller with explicit scope match
        for i in 0..self.controllers.len() {
            if self.controllers[i].segment != segment {
                continue;
            }
            if self.controllers[i].include_all {
                continue;
            }
            if self.controllers[i].device_in_scope(bus, device, function) {
                return Some(&mut self.controllers[i]);
            }
        }

        // Second pass: Find include_all controller for this segment
        for i in 0..self.controllers.len() {
            if self.controllers[i].segment == segment && self.controllers[i].include_all {
                return Some(&mut self.controllers[i]);
            }
        }

        // Fallback to default
        let idx = self.default_iommu_idx?;
        self.controllers.get_mut(idx)
    }

    /// Find controller index using proper scope matching
    ///
    /// This helps avoid borrow issues when callers need to perform additional
    /// operations on `self` (e.g., reading `reserved_regions`) before obtaining
    /// a mutable handle to the controller.
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

/// Global IOMMU manager
static IOMMU: Mutex<IommuManager> = Mutex::new(IommuManager::new());

/// Per-domain locks for parallel map/unmap operations
/// Key: domain_id, Value: Mutex<()> (domain is stored in IommuController.domains)
/// This allows multiple threads to perform DMA mapping on different domains concurrently.
static DOMAIN_LOCKS: Mutex<BTreeMap<u16, alloc::sync::Arc<spin::Mutex<()>>>> =
    Mutex::new(BTreeMap::new());

/// Acquire a lock for a specific domain
fn lock_domain(domain_id: u16) -> Option<alloc::sync::Arc<spin::Mutex<()>>> {
    let locks = DOMAIN_LOCKS.lock();
    locks.get(&domain_id).cloned()
}

/// Register a new domain lock
fn register_domain_lock(domain_id: u16) {
    DOMAIN_LOCKS
        .lock()
        .insert(domain_id, alloc::sync::Arc::new(spin::Mutex::new(())));
}

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

    let mut manager = IOMMU.lock();
    let mut default_idx = None;

    // 3. Initialize Controllers (DRHD)
    for unit in dmar_info.drhd_units {
        log::info!(
            "Initializing IOMMU Controller at {:#x} (Segment: {}, All: {})",
            unit.register_base,
            unit.segment,
            unit.include_all
        );

        // Map MMIO if necessary (assuming identity or HHDM handled by caller/base)
        // If HHDM/identity mapping is in effect, `register_base` may already be usable.
        // For now, assume the platform provides appropriate mapping (HHDM) and use it directly.
        // Map MMIO using higher half kernel mapper
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
            // Note: We use a hardcoded vector here which must match InterruptVector::IommuFault
            controller.enable_fault_interrupt(0x50);

            // Setup Queued Invalidation if supported
            if controller.supports_queued_invalidation() {
                // Use a reasonable queue size (e.g., 256 entries = 2^8)
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

        manager.add_controller(controller);
        if unit.include_all {
            default_idx = Some(manager.controllers.len() - 1);
        }
    }

    if manager.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    // Set default controller (or first one)
    manager.default_iommu_idx = default_idx.or(Some(0));

    // 4. Register RMRR regions
    // We clone regions to avoid borrowing conflicts with `manager` while iterating `dmar_info`
    let dmar_rmrr_regions = dmar_info.rmrr_regions.clone();

    for region in &dmar_rmrr_regions {
        // Convert dmar::RmrrRegion to iommu::ReservedMemoryRegion
        // We need to convert DeviceScope paths to DeviceId if possible
        // For now, simple conversion logic or just store generic info?
        // Our ReservedMemoryRegion expects `devices: Vec<DeviceId>`.
        // But dmar::DeviceScope -> DeviceId might need bus enumeration context which we don't have easily here?
        // Or we can construct DeviceId from the Path if ScopeType is Endpoint (1) or Bridge.

        let mut devices = Vec::new();
        for scope in &region.devices {
            // Basic scope parsing: start_bus + path
            // Path is (dev, func) list.
            // If path length is 1, it's devices on start_bus.
            // If path length > 1, it's hierarchy.
            // We'll handle simple case: start_bus:dev:func

            let bus = scope.start_bus;
            // Iterate path to find target device
            // The path leads to the device.
            // If multiple entries in path, it traverses bridges.
            // Final device is at the end.

            // Simplification: Assume flat bus or simple path for now
            if let Some(last_path) = scope.path.last() {
                // The assumption here is that start_bus is the root of the path
                // For complex bridges this needs bus walking.
                // For now, we use start_bus + last_path (RISKY but common for simple setups)
                let device_id = DeviceId::new(
                    region.segment,
                    bus, // This might be wrong for deep hierarchy
                    last_path.device,
                    last_path.function,
                );
                devices.push(device_id);
            }
        }

        manager.add_reserved_region(ReservedMemoryRegion {
            segment: region.segment,
            base: region.base,
            limit: region.limit,
            devices,
        });
    }

    Ok(())
}

/// Initialize the global IOMMU
///
/// # Safety
/// Caller must ensure MMIO address is valid
pub unsafe fn init_iommu(mmio_base: u64) -> Result<(), IommuError> {
    // Legacy initialization for single IOMMU (segment 0)
    let mut controller = IommuController::new(mmio_base, 0);
    unsafe {
        controller.init()?;
    }

    log::info!("IOMMU initialized at 0x{:X}\n", mmio_base);

    let mut manager = IOMMU.lock();
    manager.add_controller(controller);
    manager.default_iommu_idx = Some(0);
    Ok(())
}

/// Enable IOMMU translation (on all controllers)
pub fn enable_iommu() -> Result<(), IommuError> {
    let guard = IOMMU.lock();
    for controller in &guard.controllers {
        unsafe {
            controller.enable()?;
        }
    }
    Ok(())
}

/// Disable IOMMU translation (on all controllers)
pub fn disable_iommu() -> Result<(), IommuError> {
    let guard = IOMMU.lock();
    for controller in &guard.controllers {
        unsafe {
            controller.disable()?;
        }
    }
    Ok(())
}

/// Check if IOMMU is enabled (at least one)
pub fn is_iommu_enabled() -> bool {
    let guard = IOMMU.lock();
    !guard.controllers.is_empty() && guard.controllers[0].is_enabled()
}

/// Set NUMA hint for a domain (best-effort)
/// Note: Since domains are per-controller, this finds the first controller with the domain.
pub fn set_domain_numa(domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
    let mut guard = IOMMU.lock();
    // Try to find the domain in any controller
    for controller in &mut guard.controllers {
        if controller.domain(domain_id).is_some() {
            return controller.set_domain_numa(domain_id, numa_node);
        }
    }
    Err(IommuError::DomainNotFound)
}

/// Get NUMA hint for a domain
pub fn get_domain_numa(domain_id: u16) -> Result<Option<usize>, IommuError> {
    let guard = IOMMU.lock();
    for controller in &guard.controllers {
        if let Some(domain) = controller.domain(domain_id) {
            return Ok(domain.numa_node());
        }
    }
    Err(IommuError::DomainNotFound)
}

/// Map a physical address range for DMA access
///
/// Returns the IOVA (I/O Virtual Address) that devices should use
pub fn map_for_dma(phys_addr: x86_64::PhysAddr, size: u64) -> Result<u64, IommuError> {
    let mut guard = IOMMU.lock();

    if guard.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    // Map in ALL controllers (safe default for simple identity mapping)
    // In a real system we should only map for relevant domains, but `map_for_dma` interface
    // implies global reachability.
    let iova = phys_addr.as_u64();

    for controller in &mut guard.controllers {
        let domain = controller
            .domains
            .get_mut(&0) // Default domain
            .ok_or(IommuError::DomainNotFound)?;
        domain.map(iova, phys_addr.as_u64(), size, true, true)?;
    }

    Ok(iova)
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let mut guard = IOMMU.lock();
    if guard.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    for controller in &mut guard.controllers {
        let domain = controller
            .domains
            .get_mut(&0)
            .ok_or(IommuError::DomainNotFound)?;
        domain.unmap(iova)?;
    }
    Ok(())
}

/// Execute with default IOMMU controller
pub fn with_iommu<F, R>(f: F) -> Result<R, IommuError>
where
    F: FnOnce(&mut IommuController) -> R,
{
    let mut guard = IOMMU.lock();
    let idx = guard.default_iommu_idx.ok_or(IommuError::NotPresent)?;
    let controller = guard
        .controllers
        .get_mut(idx)
        .ok_or(IommuError::NotPresent)?;
    Ok(f(controller))
}

/// Handle IOMMU Faults (Called from ISR)
///
/// Iterates all controllers and processes pending faults.
pub fn handle_fault() {
    let mut guard = IOMMU.lock();
    for (i, controller) in guard.controllers.iter_mut().enumerate() {
        if controller.has_pending_fault() {
            let faults = controller.read_faults();
            for (entry, reason) in faults {
                log::error!(
                    "[IOMMU] FAULT on Controller {}: Reason={:?} Addr={:#x} ReqID={:04x} Type={}",
                    i,
                    reason,
                    entry.fault_address(),
                    entry.source_id(),
                    if entry.is_read() { "Read" } else { "Write" }
                );
            }

            // Clear IP bit in FECTL to re-enable interrupts if edge triggered?
            // FECTL is usually level or edge. If edge, we just handled it.
            // If we cleared the Primary Pending Fault (PPF) in FSTS via read_faults() [which writes back 1 to fault bits],
            // then the condition is cleared.
        }
    }
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
    // If there are no controllers registered, we cannot setup IOMMU for devices.
    // Note: We allow setting up domains and applying RMRR even if translation
    // is not yet globally enabled. This lets callers prepare page tables and
    // context entries before calling `enable_iommu()`.
    {
        let guard = IOMMU.lock();
        if guard.controllers.is_empty() {
            return None;
        }
    }

    let bdf = device.bdf;
    // Retrieve segment from device info
    let segment = device.segment;

    // Find correct IOMMU for this device
    // Find controller index while we still have an immutable lock so we can clone reserved regions
    // Also capture passthrough config here to avoid borrowing `IOMMU` across mutable borrows later.
    let (controller_idx, reserved_clone, passthrough) = {
        let guard = IOMMU.lock();
        // Capture passthrough flag early
        let passthrough_val = guard.config.passthrough;

        match guard.find_controller_index_for_device(
            segment,
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
        ) {
            Some(idx) => (idx, guard.reserved_regions.clone(), passthrough_val),
            None => return None,
        }
    };

    // Re-lock and obtain mutable reference to the selected controller
    let mut guard = IOMMU.lock();
    let iommu = match guard.controllers.get_mut(controller_idx) {
        Some(c) => c,
        None => return None,
    };

    // Enable ATS for this device if IOMMU supports Device-TLB (ECAP_DT)
    // and the device has the ATS Extended Capability.
    if (iommu.ecap & ecap_bits::ECAP_DT) != 0 {
        // Check if PCIe Extended Config is available
        if let Some(pcie_config) = pcie_ext_config() {
            let pcie_bdf = PcieBdf::new(bdf.bus.0, bdf.device.0, bdf.function.0);

            // Check if device supports ATS
            if device_supports_ats(pcie_config, pcie_bdf) {
                // Attempt to create ATS controller and enable ATS
                // STU = 0 means 4KB smallest translation unit (default)
                if let Ok(ats_ctrl) = AtsController::new(pcie_config, pcie_bdf) {
                    if ats_ctrl.enable_ats(0u8).is_ok() {
                        let device_id =
                            DeviceId::new(segment, bdf.bus.0, bdf.device.0, bdf.function.0);
                        iommu.enable_ats_for_device(device_id);
                        log::info!(
                            "[IOMMU] ATS enabled for device {:02x}:{:02x}.{}\\n",
                            bdf.bus.0,
                            bdf.device.0,
                            bdf.function.0
                        );
                    }
                }
            }
        }
    }

    // 1. 新しいドメインを作成
    // Prefer creating the domain on the local NUMA node if available
    let numa_hint = Some(crate::mm::numa::current_node());

    // Determine domain type based on config or specific device needs
    let domain_type = if passthrough {
        IommuDomainType::Passthrough
    } else {
        IommuDomainType::Translated
    };

    let domain_id = match iommu.create_domain(numa_hint, domain_type) {
        Ok(id) => id,
        Err(e) => {
            // Debug: report creation failure in test output
            log::error!("Failed to create domain for {:?}: {:?}\\n", bdf, e);
            return None;
        }
    };

    let device_id = DeviceId::new(segment, bdf.bus.0, bdf.device.0, bdf.function.0);

    // 2. デバイスをドメインにアタッチ
    if let Err(e) = iommu.attach_device(device_id, domain_id) {
        log::error!(
            "[IOMMU] Failed to attach device {:?} to domain {}: {:?}\\n",
            bdf,
            domain_id,
            e
        );
        return None;
    }

    // 2.5 Reserved Memory Regions (RMRR) の適用
    // Use cloned reserved regions to avoid borrowing conflicts with `iommu`
    for region in reserved_clone.iter() {
        if region.segment != device_id.segment {
            continue;
        }
        // Check scope
        if region.devices.iter().any(|d| *d == device_id) {
            let size = region.limit - region.base + 1;
            if let Some(domain) = iommu.domain_mut(domain_id) {
                log::info!(
                    "[IOMMU] Applying RMRR {:#x} to device {:?}\n",
                    region.base,
                    bdf
                );
                let _ = domain.map_identity(region.base, size, true, true);
            }
        }
    }

    // 3. デバイス情報を更新
    device.iommu_domain_id = Some(domain_id);

    log::info!(
        "[IOMMU] Device {:02x}:{:02x}.{} -> Domain {} (Seg {})\n",
        bdf.bus.0,
        bdf.device.0,
        bdf.function.0,
        domain_id,
        segment
    );

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
        let domain = ctrl.domain(id).expect("domain not found");
        assert_eq!(domain.id(), id);
        assert_eq!(domain.numa_node(), Some(2));

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
        ctrl.domains.insert(
            0,
            IommuDomain::new(0, None, false, false, IommuDomainType::Translated),
        );
        register_domain_lock(0);

        let size = 0x3000;
        let phys = 0x2000_0000;

        let iova = ctrl.allocate_iova(size).expect("allocate_iova");

        {
            let domain = ctrl.domain_mut(0).expect("domain 0");
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

    #[test]
    fn test_init_iommu_registers_drhd_and_rmrr_and_applies_rmrr() {
        use acpi_driver::tables::AcpiSdtHeader;
        use core::mem;

        // Reset global IOMMU manager to a known state
        {
            let mut guard = IOMMU.lock();
            *guard = IommuManager::new();
        }

        // Build a DMAR table with one DRHD and one RMRR for device bus=0 dev=1 func=0
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

        // ACPI SDT header (DMAR)
        let sdt = AcpiSdtHeader {
            signature: *b"DMAR",
            length: 0, // patched later
            revision: 1,
            checksum: 0,
            oem_id: [0; 6],
            oem_table_id: [0; 8],
            oem_revision: 0,
            creator_id: 0,
            creator_revision: 0,
        };

        let dmar = crate::io::acpi::dmar::DmarHeader {
            header: sdt,
            haw: 0,
            flags: 0,
            _reserved: [0; 10],
        };

        let dmar_bytes = unsafe {
            core::slice::from_raw_parts(
                &dmar as *const _ as *const u8,
                mem::size_of::<crate::io::acpi::dmar::DmarHeader>(),
            )
        };
        buf.extend_from_slice(dmar_bytes);

        // DRHD (type 0) + device scope for device 1.0 on bus 0
        let drhd_hdr = crate::io::acpi::dmar::DmarRemappingHeader {
            type_code: 0,
            length: (mem::size_of::<crate::io::acpi::dmar::DrhdWrapper>()
                + mem::size_of::<crate::io::acpi::dmar::DeviceScopeHeader>()
                + 2) as u16,
        };
        let drhd = crate::io::acpi::dmar::DrhdWrapper {
            header: drhd_hdr,
            flags: 1,
            _reserved: 0,
            segment: 0,
            register_base_addr: 0x1000_0000,
        };
        let drhd_bytes = unsafe {
            core::slice::from_raw_parts(
                &drhd as *const _ as *const u8,
                mem::size_of::<crate::io::acpi::dmar::DrhdWrapper>(),
            )
        };
        buf.extend_from_slice(drhd_bytes);

        let ds = crate::io::acpi::dmar::DeviceScopeHeader {
            type_code: 1,
            length: (mem::size_of::<crate::io::acpi::dmar::DeviceScopeHeader>() + 2) as u8,
            _reserved: 0,
            enumeration_id: 0,
            start_bus: 0,
        };
        let ds_bytes = unsafe {
            core::slice::from_raw_parts(
                &ds as *const _ as *const u8,
                mem::size_of::<crate::io::acpi::dmar::DeviceScopeHeader>(),
            )
        };
        buf.extend_from_slice(ds_bytes);
        // Path: device=1, function=0
        buf.push(1u8);
        buf.push(0u8);

        // RMRR (type 1) for same device
        let rmrr_hdr = crate::io::acpi::dmar::DmarRemappingHeader {
            type_code: 1,
            length: (mem::size_of::<crate::io::acpi::dmar::RmrrWrapper>()
                + mem::size_of::<crate::io::acpi::dmar::DeviceScopeHeader>()
                + 2) as u16,
        };
        let rmrr = crate::io::acpi::dmar::RmrrWrapper {
            header: rmrr_hdr,
            _reserved: 0,
            segment: 0,
            base_address: 0x1000,
            limit_address: 0x1fff,
        };
        let rmrr_bytes = unsafe {
            core::slice::from_raw_parts(
                &rmrr as *const _ as *const u8,
                mem::size_of::<crate::io::acpi::dmar::RmrrWrapper>(),
            )
        };
        buf.extend_from_slice(rmrr_bytes);

        // RMRR device scope
        let rds = crate::io::acpi::dmar::DeviceScopeHeader {
            type_code: 1,
            length: (mem::size_of::<crate::io::acpi::dmar::DeviceScopeHeader>() + 2) as u8,
            _reserved: 0,
            enumeration_id: 0,
            start_bus: 0,
        };
        let rds_bytes = unsafe {
            core::slice::from_raw_parts(
                &rds as *const _ as *const u8,
                mem::size_of::<crate::io::acpi::dmar::DeviceScopeHeader>(),
            )
        };
        buf.extend_from_slice(rds_bytes);
        buf.push(1u8);
        buf.push(0u8);

        // Patch total length
        let total_len = buf.len() as u32;
        buf[4..8].copy_from_slice(&total_len.to_le_bytes());

        let ptr = buf.as_ptr() as usize;

        // Initialize IOMMU from our synthetic DMAR
        unsafe {
            let cfg = IommuConfig::new();
            init_iommu_from_acpi(ptr, cfg).expect("IOMMU init should succeed");
        }

        // Validate manager state has controller & reserved region
        {
            let guard = IOMMU.lock();
            assert!(
                !guard.controllers.is_empty(),
                "Should have at least one controller"
            );
            assert_eq!(
                guard.reserved_regions.len(),
                1,
                "One RMRR region should be registered"
            );
            let rr = &guard.reserved_regions[0];
            assert_eq!(rr.base, 0x1000);
            assert_eq!(rr.limit, 0x1fff);

            // Debug: print controllers and default index
            println!("DEBUG: controllers={}", guard.controllers.len());
            for (i, c) in guard.controllers.iter().enumerate() {
                println!("DEBUG: controller {} segment={}", i, c.segment);
            }
            println!("DEBUG: default_iommu_idx={:?}", guard.default_iommu_idx);
        }

        // Now try to setup IOMMU for a matching PCI device and ensure RMRR is applied
        let mut dev = crate::io::pci::PciDeviceInfo {
            bdf: crate::io::pci::Bdf {
                bus: crate::io::pci::Bus(0),
                device: crate::io::pci::Device(1),
                function: crate::io::pci::Function(0),
            },
            iommu_domain_id: None,
        };
        let domain_opt = setup_iommu_for_pci_device(&mut dev);
        assert!(domain_opt.is_some(), "Domain should be created for device");

        // Verify domain has identity mapping for RMRR
        let domain_id = domain_opt.unwrap();
        {
            let guard = IOMMU.lock();
            let ctrl = &guard.controllers[0];
            let domain = ctrl.domain(domain_id).expect("domain exists");
            // Mapping key should be identity mapping at region.base
            assert!(
                domain.mappings.contains_key(&0x1000),
                "Domain should have mapping for RMRR base"
            );
            let mapping = domain.mappings.get(&0x1000).unwrap();
            assert_eq!(mapping.phys, 0x1000);
            assert_eq!(mapping.size, 0x1000); // 0x1fff - 0x1000 + 1
        }

        // Cleanup: reset global IOMMU
        {
            let mut guard = IOMMU.lock();
            *guard = IommuManager::new();
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
    let mut guard = IOMMU.lock();

    // Find the controller responsible for this device
    // Currently using simple segment matching as per find_controller_for_device
    let controller = guard
        .controllers
        .iter_mut()
        .find(|c| c.segment == segment)
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
