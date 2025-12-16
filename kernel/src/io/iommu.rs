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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

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

    /// Create a new blank (not present) entry
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
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

    /// Set second level page table pointer
    pub fn set_sl_pt(&mut self, addr: u64, domain_id: u16, agaw: u8) {
        self.lo = (addr & !0xFFF) | 1; // Present
        self.hi = ((domain_id as u64) << 8) | ((agaw as u64) << 0);
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

/// IOMMU Domain (address space for devices)
///
/// Each domain has its own Mutex in the global IOMMU_DOMAINS registry,
/// allowing parallel map/unmap operations across different domains.
pub struct IommuDomain {
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
    pub fn new(id: u16, numa_node: Option<usize>) -> Self {
        // Allocate page table on the preferred NUMA node when possible.
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Invalid layout for page table");

        let page_table = crate::mm::numa::allocate_zeroed_on_node(layout, numa_node)
            .expect("Failed to allocate IOMMU page table")
            .as_ptr() as *mut SlPte;

        Self {
            id,
            page_table,
            mappings: BTreeMap::new(),
            mapped_size: 0,
            numa_node,
        }
    }

    /// Get domain ID
    pub fn id(&self) -> u16 {
        self.id
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

        // Create page table entries
        let num_pages = size / 4096;
        for i in 0..num_pages {
            let page_iova = iova + i * 4096;
            let page_phys = phys + i * 4096;

            self.map_page(page_iova, page_phys, read, write)?;
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
    /// IOVA allocator (optional, configured via `init_iova`)
    iova_allocator: Option<IovaAllocator>,
}

unsafe impl Send for IommuController {}
unsafe impl Sync for IommuController {}

impl IommuController {
    /// Create a new IOMMU controller
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
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
        }
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
    pub fn create_domain(&mut self, numa_node: Option<usize>) -> Result<u16, IommuError> {
        let id = self.next_domain_id.fetch_add(1, Ordering::Relaxed) as u16;

        let domain = IommuDomain::new(id, numa_node);
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
        context_entry.set_sl_pt(domain.page_table_addr(), domain.id(), 2);

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

        domain.unmap(iova)
    }

    /// Invalidate IOTLB for a domain
    pub unsafe fn invalidate_iotlb(&self, domain_id: u16) {
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
    pub unsafe fn invalidate_iotlb_global(&self) {
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

    /// Get capability information
    pub fn capabilities(&self) -> IommuCapabilities {
        IommuCapabilities {
            queued_invalidation: self.supports_queued_invalidation(),
            interrupt_remapping: self.supports_interrupt_remapping(),
            super_page_2mb: self.supports_2mb_pages(),
            super_page_1gb: self.supports_1gb_pages(),
            page_walk_coherency: (self.cap & cap_bits::CAP_PWC) != 0,
            snoop_control: (self.cap & cap_bits::CAP_SC) != 0,
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

    /// Initialize IOVA space for the global IOMMU controller
    pub fn init_iova_range(base: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = IOMMU.lock();
        let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;
        controller.init_iova(base, size)
    }

    /// Allocate an IOVA from the global controller
    pub fn allocate_global_iova(size: u64) -> Result<u64, IommuError> {
        let mut guard = IOMMU.lock();
        let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;
        controller.allocate_iova(size)
    }

    /// Free an IOVA back to global controller
    pub fn free_global_iova(addr: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = IOMMU.lock();
        let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;
        controller.free_iova(addr, size)
    }

    /// Allocate an IOVA and create a mapping in default domain (non-identity mapping)
    pub fn map_for_dma_alloc(phys_addr: x86_64::PhysAddr, size: u64) -> Result<u64, IommuError> {
        let mut guard = IOMMU.lock();
        let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;

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
        let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;

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

/// IOVA Allocator using bitmap-based allocation
///
/// Manages I/O Virtual Address space for DMA mappings.
/// Supports 4KB, 2MB, and 1GB granularity allocations.
pub struct IovaAllocator {
    /// Base address of the IOVA space
    base: u64,
    /// Total size of the IOVA space
    size: u64,
    /// Bitmap for 4KB page tracking (1 bit per 4KB page)
    /// We use Vec because the size can be large
    bitmap: Vec<u64>,
    /// Number of 4KB pages managed
    total_pages: usize,
    /// Number of free 4KB pages
    free_pages: usize,
    /// Next allocation hint (for fast sequential allocation)
    next_hint: usize,
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

        Self {
            base,
            size,
            bitmap,
            total_pages,
            free_pages: total_pages,
            next_hint: 0,
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
    pub fn allocate(&mut self, size: u64, granularity: IovaGranularity) -> Option<u64> {
        let page_size = granularity.size_bytes();
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;
        let alignment_pages = (page_size / Self::PAGE_SIZE_4K) as usize;

        // Find a suitable range
        let start_page = self.find_free_range(pages_needed, alignment_pages)?;

        // Mark as allocated
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

        // Check if already allocated
        for i in 0..pages_needed {
            if self.is_page_allocated(start_page + i) {
                return Err(IommuError::AlreadyMapped);
            }
        }

        self.mark_pages_allocated(start_page, pages_needed);
        Ok(())
    }

    /// Free an IOVA range
    pub fn free(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova + size > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / Self::PAGE_SIZE_4K) as usize;
        let pages_count = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;

        self.mark_pages_free(start_page, pages_count);

        // Update hint to freed range for potential reuse
        if start_page < self.next_hint {
            self.next_hint = start_page;
        }

        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> IovaAllocatorStats {
        IovaAllocatorStats {
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            allocated_pages: self.total_pages - self.free_pages,
            base: self.base,
            size: self.size,
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

// ============================================================================
// Global Instance
// ============================================================================

/// Global IOMMU controller (for controller-level operations)
static IOMMU: Mutex<Option<IommuController>> = Mutex::new(None);

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

/// Initialize the global IOMMU
///
/// # Safety
/// Caller must ensure MMIO address is valid
pub unsafe fn init_iommu(mmio_base: u64) -> Result<(), IommuError> {
    let mut controller = IommuController::new(mmio_base);
    unsafe {
        controller.init()?;
    }

    log::info!("IOMMU initialized at 0x{:X}\n", mmio_base);

    *IOMMU.lock() = Some(controller);
    Ok(())
}

/// Enable IOMMU translation
pub fn enable_iommu() -> Result<(), IommuError> {
    let guard = IOMMU.lock();
    let controller = guard.as_ref().ok_or(IommuError::NotPresent)?;

    unsafe { controller.enable() }
}

/// Disable IOMMU translation
pub fn disable_iommu() -> Result<(), IommuError> {
    let guard = IOMMU.lock();
    let controller = guard.as_ref().ok_or(IommuError::NotPresent)?;

    unsafe { controller.disable() }
}

/// Check if IOMMU is enabled
pub fn is_iommu_enabled() -> bool {
    IOMMU.lock().is_some()
}

/// Set NUMA hint for a domain (best-effort)
pub fn set_domain_numa(domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
    // Explicitly propagate the inner result so callers receive any domain-not-found errors.
    let mut guard = IOMMU.lock();
    let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;
    controller.set_domain_numa(domain_id, numa_node)
}

/// Get NUMA hint for a domain
pub fn get_domain_numa(domain_id: u16) -> Result<Option<usize>, IommuError> {
    with_iommu(|iommu| iommu.get_domain_numa(domain_id))
}

/// Map a physical address range for DMA access
///
/// Returns the IOVA (I/O Virtual Address) that devices should use
pub fn map_for_dma(phys_addr: x86_64::PhysAddr, size: u64) -> Result<u64, IommuError> {
    let mut guard = IOMMU.lock();
    let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;

    // For simplicity, use identity mapping (IOVA == physical address)
    // In a more sophisticated implementation, this would allocate from an IOVA space
    let iova = phys_addr.as_u64();

    // Create a mapping in the default domain (domain 0)
    // This is a simplified implementation
    let domain = controller
        .domains
        .get_mut(&0)
        .ok_or(IommuError::DomainNotFound)?;

    domain.map(iova, phys_addr.as_u64(), size, true, true)?;

    Ok(iova)
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let mut guard = IOMMU.lock();
    let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;

    // Unmap from the default domain
    let domain = controller
        .domains
        .get_mut(&0)
        .ok_or(IommuError::DomainNotFound)?;

    domain.unmap(iova)?;
    Ok(())
}

/// Execute with IOMMU controller
pub fn with_iommu<F, R>(f: F) -> Result<R, IommuError>
where
    F: FnOnce(&mut IommuController) -> R,
{
    let mut guard = IOMMU.lock();
    let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;
    Ok(f(controller))
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
    if !is_iommu_enabled() {
        return None;
    }

    let bdf = device.bdf;
    let device_id = DeviceId::new(
        0, // segment（通常0）
        bdf.bus.0,
        bdf.device.0,
        bdf.function.0,
    );

    with_iommu(|iommu| {
        // 1. 新しいドメインを作成
        // Prefer creating the domain on the local NUMA node if available
        let numa_hint = Some(crate::mm::numa::current_node());
        let domain_id = match iommu.create_domain(numa_hint) {
            Ok(id) => id,
            Err(e) => {
                log::info!("[IOMMU] Failed to create domain for {:?}: {:?}\n", bdf, e);
                return None;
            }
        };

        // 2. デバイスをドメインにアタッチ
        if let Err(e) = iommu.attach_device(device_id, domain_id) {
            log::info!(
                "[IOMMU] Failed to attach device {:?} to domain {}: {:?}\n",
                bdf,
                domain_id,
                e
            );
            return None;
        }

        // 3. デバイス情報を更新
        device.iommu_domain_id = Some(domain_id);

        log::info!(
            "[IOMMU] Device {:02x}:{:02x}.{} -> Domain {}\n",
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            domain_id
        );

        Some(domain_id)
    })
    .ok()
    .flatten()
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
        let mut domain = IommuDomain::new(1, None);
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
        let mut ctrl = IommuController::new(0x0);
        let id = ctrl.create_domain(Some(2)).expect("create_domain failed");
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
        let mut ctrl = IommuController::new(0x0);
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
        let mut ctrl = IommuController::new(0x0);
        ctrl.init_iova(0x8000_0000, 0x10000).expect("init_iova");

        // Create default domain 0 for mapping
        ctrl.domains.insert(0, IommuDomain::new(0, None));
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
}
