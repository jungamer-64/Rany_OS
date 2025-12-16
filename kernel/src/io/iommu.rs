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

// Local DMAR parser (minimal, avoids cross-module resolution issues)
// We re-implement a compact DMAR parser here to extract DRHD units and RMRR
// regions without depending on `io::acpi` symbols, which can cause
// circular resolution issues when compiling submodules.
mod local_dmar {
    use alloc::vec::Vec;
    use core::mem;

    #[repr(C, packed)]
    #[derive(Debug, Clone, Copy)]
    struct LocalSdtHeader {
        signature: [u8; 4],
        length: u32,
        revision: u8,
        checksum: u8,
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
        creator_id: u32,
        creator_revision: u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Clone, Copy)]
    struct DmarHeader {
        header: LocalSdtHeader,
        pub haw: u8,
        pub flags: u8,
        _reserved: [u8; 10],
    }

    impl DmarHeader {
        pub const SIGNATURE: &'static [u8; 4] = b"DMAR";

        pub fn is_valid(&self) -> bool {
            self.header.signature == *Self::SIGNATURE
        }
    }

    #[repr(C, packed)]
    #[derive(Debug, Clone, Copy)]
    pub struct DmarRemappingHeader {
        pub type_code: u16,
        pub length: u16,
    }

    #[repr(C, packed)]
    #[derive(Debug, Clone, Copy)]
    pub struct DrhdWrapper {
        pub header: DmarRemappingHeader,
        pub flags: u8,
        _reserved: u8,
        pub segment: u16,
        pub register_base_addr: u64,
    }

    impl DrhdWrapper {
        pub fn include_pci_all(&self) -> bool {
            (self.flags & 0x1) != 0
        }
    }

    #[repr(C, packed)]
    #[derive(Debug, Clone, Copy)]
    pub struct RmrrWrapper {
        pub header: DmarRemappingHeader,
        _reserved: u16,
        pub segment: u16,
        pub base_address: u64,
        pub limit_address: u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Clone, Copy)]
    struct DeviceScopeHeader {
        pub type_code: u8,
        pub length: u8,
        _reserved: u16,
        pub enumeration_id: u8,
        pub start_bus: u8,
    }

    #[derive(Debug, Clone)]
    pub struct DmarInfo {
        pub haw: u8,
        pub flags: u8,
        pub drhd_units: Vec<DrhdUnit>,
        pub rmrr_regions: Vec<RmrrRegion>,
    }

    #[derive(Debug, Clone)]
    pub struct DrhdUnit {
        pub segment: u16,
        pub register_base: u64,
        pub include_all: bool,
        pub devices: Vec<DeviceScope>,
    }

    #[derive(Debug, Clone)]
    pub struct RmrrRegion {
        pub segment: u16,
        pub base: u64,
        pub limit: u64,
        pub devices: Vec<DeviceScope>,
    }

    #[derive(Debug, Clone)]
    pub struct DeviceScope {
        pub scope_type: u8,
        pub enumeration_id: u8,
        pub start_bus: u8,
        pub path: Vec<PciPath>,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct PciPath {
        pub device: u8,
        pub function: u8,
    }

    pub unsafe fn parse_dmar(addr: usize) -> Result<DmarInfo, &'static str> {
        let header = &*(addr as *const DmarHeader);
        if !header.is_valid() {
            return Err("Invalid DMAR signature");
        }

        let table_len = header.header.length as usize;
        let mut offset = mem::size_of::<DmarHeader>();
        let base_ptr = addr as *const u8;

        let mut drhd_units = Vec::new();
        let mut rmrr_regions = Vec::new();

        while offset < table_len {
            let entry_ptr = base_ptr.add(offset) as *const DmarRemappingHeader;
            let entry_type = (*entry_ptr).type_code;
            let entry_len = (*entry_ptr).length as usize;

            if entry_len < mem::size_of::<DmarRemappingHeader>() {
                break; // sanity
            }

            match entry_type {
                0 => {
                    let drhd = &*(entry_ptr as *const DrhdWrapper);
                    let devices = parse_device_scopes(
                        base_ptr.add(offset + mem::size_of::<DrhdWrapper>()),
                        entry_len - mem::size_of::<DrhdWrapper>(),
                    );
                    drhd_units.push(DrhdUnit {
                        segment: drhd.segment,
                        register_base: drhd.register_base_addr,
                        include_all: drhd.include_pci_all(),
                        devices,
                    });
                }
                1 => {
                    let rmrr = &*(entry_ptr as *const RmrrWrapper);
                    let devices = parse_device_scopes(
                        base_ptr.add(offset + mem::size_of::<RmrrWrapper>()),
                        entry_len - mem::size_of::<RmrrWrapper>(),
                    );
                    rmrr_regions.push(RmrrRegion {
                        segment: rmrr.segment,
                        base: rmrr.base_address,
                        limit: rmrr.limit_address,
                        devices,
                    });
                }
                _ => {}
            }

            offset += entry_len;
        }

        Ok(DmarInfo {
            haw: header.haw,
            flags: header.flags,
            drhd_units,
            rmrr_regions,
        })
    }

    unsafe fn parse_device_scopes(mut ptr: *const u8, mut len: usize) -> Vec<DeviceScope> {
        let mut scopes = Vec::new();

        while len >= mem::size_of::<DeviceScopeHeader>() {
            let header = &*(ptr as *const DeviceScopeHeader);
            let scope_len = header.length as usize;

            if scope_len < mem::size_of::<DeviceScopeHeader>() || scope_len > len {
                break;
            }

            let mut path = Vec::new();
            let path_len = scope_len - mem::size_of::<DeviceScopeHeader>();
            let path_count = path_len / 2;
            let path_ptr = ptr.add(mem::size_of::<DeviceScopeHeader>());

            for i in 0..path_count {
                let dev = *path_ptr.add(i * 2);
                let func = *path_ptr.add(i * 2 + 1);
                path.push(PciPath {
                    device: dev,
                    function: func,
                });
            }

            scopes.push(DeviceScope {
                scope_type: header.type_code,
                enumeration_id: header.enumeration_id,
                start_bus: header.start_bus,
                path,
            });

            ptr = ptr.add(scope_len);
            len -= scope_len;
        }

        scopes
    }
}

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

/// PASID Table Entry (Scalable Mode)
///
/// 64-byte entry in the PASID Table.
/// Contains pointer to First-Level (Stage-1) and Second-Level (Stage-2) translation structures.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct PasidTableEntry {
    pub val: [u64; 8],
}

impl PasidTableEntry {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// First-Level Translation Enable
    pub const FLT: u64 = 1 << 50; // In val[0]
    /// Second-Level Translation Enable
    pub const SLT: u64 = 1 << 51; // In val[0]

    /// Set Second-Level (Stage-2) Page Table pointer (SLPTR)
    pub fn set_sl_ptr(&mut self, addr: u64) {
        // SLPTR is in val[0] bits 12-63
        self.val[0] = (self.val[0] & 0xFFF) | (addr & !0xFFF);
        self.val[0] |= Self::PRESENT | Self::SLT;
    }

    /// Set First-Level (Stage-1) Page Table pointer (FLPTR)
    pub fn set_fl_ptr(&mut self, addr: u64) {
        // FLPTR is in val[2] bits 12-63
        self.val[2] = (self.val[2] & 0xFFF) | (addr & !0xFFF);
        // Enable bit is in val[0]
        self.val[0] |= Self::PRESENT | Self::FLT;
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
    /// # Arguments
    /// * `segment` - PCI segment number
    /// * `bus` - PCI bus number
    /// * `device` - PCI device number
    /// * `function` - PCI function number
    pub fn find_controller_for_device(
        &self,
        segment: u16,
        _bus: u8,
        _device: u8,
        _function: u8,
    ) -> Option<&IommuController> {
        // Linear search for now (DRHDs are few)
        // TODO: Implement proper scope matching based on DRHD structures
        // For now, return the default controller or the first one matching segment

        for controller in &self.controllers {
            if controller.segment == segment {
                // In a real implementation with scopes, check if device is in scope
                // For now, simpler matching: match segment
                return Some(controller);
            }
        }

        // Fallback to default
        if let Some(idx) = self.default_iommu_idx {
            return self.controllers.get(idx);
        }

        None
    }

    /// Find mutable controller
    pub fn find_controller_for_device_mut(
        &mut self,
        segment: u16,
        _bus: u8,
        _dev: u8,
        _func: u8,
    ) -> Option<&mut IommuController> {
        // Iterate by index to avoid conflicting borrows
        for i in 0..self.controllers.len() {
            if self.controllers[i].segment == segment {
                return Some(&mut self.controllers[i]);
            }
        }

        let idx = self.default_iommu_idx?;
        return self.controllers.get_mut(idx);
    }

    /// Find controller index for device without taking mutable references.
    /// This helps avoid borrow issues when callers need to perform additional
    /// operations on `self` (e.g., reading `reserved_regions`) before obtaining
    /// a mutable handle to the controller.
    pub fn find_controller_index_for_device(
        &self,
        segment: u16,
        _bus: u8,
        _device: u8,
        _function: u8,
    ) -> Option<usize> {
        if let Some(idx) = self.controllers.iter().position(|c| c.segment == segment) {
            return Some(idx);
        }
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

    // Parse DMAR using the local parser (keeps module dependencies simple)
    let dmar_info = match local_dmar::parse_dmar(dmar_addr) {
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
        let mmio_virt = unit.register_base; // TODO: replace with phys->virt when mapping helper is reliable

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
    if !is_iommu_enabled() {
        return None;
    }

    let bdf = device.bdf;
    // Retrieve segment from device info (if available) or assume 0
    let segment = 0; // TODO: Get from PciDeviceInfo if added

    // Find correct IOMMU for this device
    // Find controller index while we still have an immutable lock so we can clone reserved regions
    let (controller_idx, reserved_clone) = {
        let guard = IOMMU.lock();
        // Check for passthrough mode and bail out early if configured globally
        if guard.config.passthrough {
            // TODO: Implement passthrough handling; for now, we allow setup but note it here
        }

        match guard.find_controller_index_for_device(
            segment,
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
        ) {
            Some(idx) => (idx, guard.reserved_regions.clone()),
            None => return None,
        }
    };

    // Re-lock and obtain mutable reference to the selected controller
    let mut guard = IOMMU.lock();
    let passthrough = guard.config.passthrough;
    let iommu = match guard.controllers.get_mut(controller_idx) {
        Some(c) => c,
        None => return None,
    };

    // Enable ATS for this device if IOMMU supports it (and device does - TODO check device cap)
    // For now we optimistically enable tracking if ECAP_DT is set, assuming driver will enable ATS on device.
    if (iommu.ecap & ecap_bits::ECAP_DT) != 0 {
        let device_id = DeviceId::new(segment, bdf.bus.0, bdf.device.0, bdf.function.0);
        iommu.enable_ats_for_device(device_id);
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
            log::info!("[IOMMU] Failed to create domain for {:?}: {:?}\n", bdf, e);
            return None;
        }
    };

    let device_id = DeviceId::new(segment, bdf.bus.0, bdf.device.0, bdf.function.0);

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
}
