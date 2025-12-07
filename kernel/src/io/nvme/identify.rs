// ============================================================================
// src/io/nvme/identify.rs - NVMe Identify Structures
// ============================================================================
//!
//! NVMe Identify構造体定義
//!
//! NVMe Base Specification 2.0 Section 5.17に基づく構造体。

#![allow(dead_code)]

// ============================================================================
// Identify Controller Data (CNS 01h)
// ============================================================================

/// Identify Controller データ構造 (4096バイト)
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct IdentifyController {
    /// PCI Vendor ID
    pub vid: u16,
    /// PCI Subsystem Vendor ID
    pub ssvid: u16,
    /// Serial Number (20 bytes ASCII)
    pub sn: [u8; 20],
    /// Model Number (40 bytes ASCII)
    pub mn: [u8; 40],
    /// Firmware Revision (8 bytes ASCII)
    pub fr: [u8; 8],
    /// Recommended Arbitration Burst
    pub rab: u8,
    /// IEEE OUI Identifier (3 bytes)
    pub ieee: [u8; 3],
    /// Controller Multi-Path I/O and Namespace Sharing Capabilities
    pub cmic: u8,
    /// Maximum Data Transfer Size
    pub mdts: u8,
    /// Controller ID
    pub cntlid: u16,
    /// Version (NVMe仕様バージョン)
    pub ver: u32,
    /// RTD3 Resume Latency
    pub rtd3r: u32,
    /// RTD3 Entry Latency
    pub rtd3e: u32,
    /// Optional Asynchronous Events Supported
    pub oaes: u32,
    /// Controller Attributes
    pub ctratt: u32,
    /// Read Recovery Levels Supported
    pub rrls: u16,
    /// Reserved
    _reserved1: [u8; 9],
    /// Controller Type
    pub cntrltype: u8,
    /// FRU Globally Unique Identifier (16 bytes)
    pub fguid: [u8; 16],
    /// Command Retry Delay Times
    pub crdt: [u16; 3],
    /// Reserved
    _reserved2: [u8; 106],
    /// NVM Subsystem NVMe Qualified Name
    pub nvmsr: u8,
    /// VPD Write Cycle Information
    pub vwci: u8,
    /// Management Endpoint Capabilities
    pub mec: u8,
    /// Optional Admin Command Support
    pub oacs: u16,
    /// Abort Command Limit
    pub acl: u8,
    /// Asynchronous Event Request Limit
    pub aerl: u8,
    /// Firmware Updates
    pub frmw: u8,
    /// Log Page Attributes
    pub lpa: u8,
    /// Error Log Page Entries
    pub elpe: u8,
    /// Number of Power States Support
    pub npss: u8,
    /// Admin Vendor Specific Command Configuration
    pub avscc: u8,
    /// Autonomous Power State Transition Attributes
    pub apsta: u8,
    /// Warning Composite Temperature Threshold
    pub wctemp: u16,
    /// Critical Composite Temperature Threshold
    pub cctemp: u16,
    /// Maximum Time for Firmware Activation
    pub mtfa: u16,
    /// Host Memory Buffer Preferred Size
    pub hmpre: u32,
    /// Host Memory Buffer Minimum Size
    pub hmmin: u32,
    /// Total NVM Capacity (16 bytes)
    pub tnvmcap: [u8; 16],
    /// Unallocated NVM Capacity (16 bytes)
    pub unvmcap: [u8; 16],
    /// Replay Protected Memory Block Support
    pub rpmbs: u32,
    /// Extended Device Self-test Time
    pub edstt: u16,
    /// Device Self-test Options
    pub dsto: u8,
    /// Firmware Update Granularity
    pub fwug: u8,
    /// Keep Alive Support
    pub kas: u16,
    /// Host Controlled Thermal Management Attributes
    pub hctma: u16,
    /// Minimum Thermal Management Temperature
    pub mntmt: u16,
    /// Maximum Thermal Management Temperature
    pub mxtmt: u16,
    /// Sanitize Capabilities
    pub sanicap: u32,
    /// Host Memory Buffer Minimum Descriptor Entry Size
    pub hmminds: u32,
    /// Host Memory Maximum Descriptors Entries
    pub hmmaxd: u16,
    /// NVM Set Identifier Maximum
    pub nsetidmax: u16,
    /// Endurance Group Identifier Maximum
    pub endgidmax: u16,
    /// ANA Transition Time
    pub anatt: u8,
    /// Asymmetric Namespace Access Capabilities
    pub anacap: u8,
    /// ANA Group Identifier Maximum
    pub anagrpmax: u32,
    /// Number of ANA Group Identifiers
    pub nanagrpid: u32,
    /// Persistent Event Log Size
    pub pels: u32,
    /// Reserved
    _reserved3: [u8; 156],
    /// Submission Queue Entry Size
    pub sqes: u8,
    /// Completion Queue Entry Size
    pub cqes: u8,
    /// Maximum Outstanding Commands
    pub maxcmd: u16,
    /// Number of Namespaces
    pub nn: u32,
    /// Optional NVM Command Support
    pub oncs: u16,
    /// Fused Operation Support
    pub fuses: u16,
    /// Format NVM Attributes
    pub fna: u8,
    /// Volatile Write Cache
    pub vwc: u8,
    /// Atomic Write Unit Normal
    pub awun: u16,
    /// Atomic Write Unit Power Fail
    pub awupf: u16,
    /// NVM Vendor Specific Command Configuration
    pub nvscc: u8,
    /// Namespace Write Protection Capabilities
    pub nwpc: u8,
    /// Atomic Compare & Write Unit
    pub acwu: u16,
    /// Reserved
    _reserved4: u16,
    /// SGL Support
    pub sgls: u32,
    /// Maximum Number of Allowed Namespaces
    pub mnan: u32,
    /// Reserved
    _reserved5: [u8; 224],
    /// NVM Subsystem NVMe Qualified Name
    pub subnqn: [u8; 256],
    /// Reserved
    _reserved6: [u8; 768],
    /// I/O Queue Command Capsule Supported Size
    pub ioccsz: u32,
    /// I/O Response Capsule Supported Size
    pub iorcsz: u32,
    /// In Capsule Data Offset
    pub icdoff: u16,
    /// FBDS & ELBAS Attributes
    pub fcatt: u8,
    /// Maximum SGL Data Block Descriptors
    pub msdbd: u8,
    /// Optional Fabric Commands Support
    pub ofcs: u16,
    /// Reserved
    _reserved7: [u8; 242],
    /// Power State Descriptors (32 x 32 bytes = 1024 bytes)
    pub psd: [PowerStateDescriptor; 32],
    /// Vendor Specific (1024 bytes)
    _vendor_specific: [u8; 1024],
}

impl IdentifyController {
    /// シリアル番号を文字列として取得
    pub fn serial_number(&self) -> &str {
        core::str::from_utf8(&self.sn)
            .unwrap_or("")
            .trim()
    }

    /// モデル番号を文字列として取得
    pub fn model_number(&self) -> &str {
        core::str::from_utf8(&self.mn)
            .unwrap_or("")
            .trim()
    }

    /// ファームウェアリビジョンを文字列として取得
    pub fn firmware_revision(&self) -> &str {
        core::str::from_utf8(&self.fr)
            .unwrap_or("")
            .trim()
    }

    /// 最大データ転送サイズ（バイト）
    pub fn max_data_transfer_size(&self, page_size: usize) -> usize {
        if self.mdts == 0 {
            usize::MAX // 制限なし
        } else {
            page_size << self.mdts
        }
    }

    /// NVMe仕様バージョン（メジャー.マイナー.テリタリ）
    pub fn nvme_version(&self) -> (u16, u8, u8) {
        let major = ((self.ver >> 16) & 0xFFFF) as u16;
        let minor = ((self.ver >> 8) & 0xFF) as u8;
        let tertiary = (self.ver & 0xFF) as u8;
        (major, minor, tertiary)
    }

    /// SQ Entry Size（最小/最大）
    pub fn sq_entry_size(&self) -> (usize, usize) {
        let min = 1 << (self.sqes & 0x0F);
        let max = 1 << ((self.sqes >> 4) & 0x0F);
        (min, max)
    }

    /// CQ Entry Size（最小/最大）
    pub fn cq_entry_size(&self) -> (usize, usize) {
        let min = 1 << (self.cqes & 0x0F);
        let max = 1 << ((self.cqes >> 4) & 0x0F);
        (min, max)
    }
}

impl Default for IdentifyController {
    fn default() -> Self {
        // Safety: ゼロ初期化は安全
        unsafe { core::mem::zeroed() }
    }
}

// ============================================================================
// Power State Descriptor
// ============================================================================

/// Power State Descriptor (32 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PowerStateDescriptor {
    /// Maximum Power (centiwatts)
    pub max_power: u16,
    /// Reserved
    _reserved1: u8,
    /// Flags (NOPS, MXPS)
    pub flags: u8,
    /// Entry Latency (microseconds)
    pub entry_lat: u32,
    /// Exit Latency (microseconds)
    pub exit_lat: u32,
    /// Relative Read Throughput
    pub rrt: u8,
    /// Relative Read Latency
    pub rrl: u8,
    /// Relative Write Throughput
    pub rwt: u8,
    /// Relative Write Latency
    pub rwl: u8,
    /// Idle Power (centiwatts)
    pub idle_power: u16,
    /// Idle Power Scale
    pub idle_scale: u8,
    /// Reserved
    _reserved2: u8,
    /// Active Power (centiwatts)
    pub active_power: u16,
    /// Active Power Workload/Scale
    pub active_scale: u8,
    /// Reserved
    _reserved3: [u8; 9],
}

impl PowerStateDescriptor {
    /// 最大消費電力（ワット）
    pub fn max_power_watts(&self) -> f32 {
        if (self.flags & 0x02) != 0 {
            // MXPS = 1: 0.0001W scale
            self.max_power as f32 * 0.0001
        } else {
            // MXPS = 0: 0.01W scale
            self.max_power as f32 * 0.01
        }
    }

    /// Non-Operational Power State
    pub fn is_non_operational(&self) -> bool {
        (self.flags & 0x01) != 0
    }
}

// ============================================================================
// Identify Namespace Data (CNS 00h)
// ============================================================================

/// Identify Namespace データ構造 (4096バイト)
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct IdentifyNamespace {
    /// Namespace Size (論理ブロック数)
    pub nsze: u64,
    /// Namespace Capacity (論理ブロック数)
    pub ncap: u64,
    /// Namespace Utilization (論理ブロック数)
    pub nuse: u64,
    /// Namespace Features
    pub nsfeat: u8,
    /// Number of LBA Formats
    pub nlbaf: u8,
    /// Formatted LBA Size
    pub flbas: u8,
    /// Metadata Capabilities
    pub mc: u8,
    /// End-to-end Data Protection Capabilities
    pub dpc: u8,
    /// End-to-end Data Protection Type Settings
    pub dps: u8,
    /// Namespace Multi-path I/O and Namespace Sharing Capabilities
    pub nmic: u8,
    /// Reservation Capabilities
    pub rescap: u8,
    /// Format Progress Indicator
    pub fpi: u8,
    /// Deallocate Logical Block Features
    pub dlfeat: u8,
    /// Namespace Atomic Write Unit Normal
    pub nawun: u16,
    /// Namespace Atomic Write Unit Power Fail
    pub nawupf: u16,
    /// Namespace Atomic Compare & Write Unit
    pub nacwu: u16,
    /// Namespace Atomic Boundary Size Normal
    pub nabsn: u16,
    /// Namespace Atomic Boundary Offset
    pub nabo: u16,
    /// Namespace Atomic Boundary Size Power Fail
    pub nabspf: u16,
    /// Namespace Optimal I/O Boundary
    pub noiob: u16,
    /// NVM Capacity (16 bytes)
    pub nvmcap: [u8; 16],
    /// Namespace Preferred Write Granularity
    pub npwg: u16,
    /// Namespace Preferred Write Alignment
    pub npwa: u16,
    /// Namespace Preferred Deallocate Granularity
    pub npdg: u16,
    /// Namespace Preferred Deallocate Alignment
    pub npda: u16,
    /// Namespace Optimal Write Size
    pub nows: u16,
    /// Reserved
    _reserved1: [u8; 18],
    /// ANA Group Identifier
    pub anagrpid: u32,
    /// Reserved
    _reserved2: [u8; 3],
    /// Namespace Attributes
    pub nsattr: u8,
    /// NVM Set Identifier
    pub nvmsetid: u16,
    /// Endurance Group Identifier
    pub endgid: u16,
    /// Namespace Globally Unique Identifier (16 bytes)
    pub nguid: [u8; 16],
    /// IEEE Extended Unique Identifier (8 bytes)
    pub eui64: [u8; 8],
    /// LBA Format 0-15 Support
    pub lbaf: [LbaFormat; 16],
    /// Reserved
    _reserved3: [u8; 192],
    /// Vendor Specific
    _vendor_specific: [u8; 3712],
}

impl IdentifyNamespace {
    /// 現在使用中のLBAフォーマットを取得
    pub fn current_lba_format(&self) -> &LbaFormat {
        let index = (self.flbas & 0x0F) as usize;
        &self.lbaf[index]
    }

    /// 論理ブロックサイズ（バイト）
    pub fn block_size(&self) -> usize {
        self.current_lba_format().data_size()
    }

    /// 名前空間の容量（バイト）
    pub fn capacity_bytes(&self) -> u64 {
        self.ncap * self.block_size() as u64
    }

    /// 名前空間のサイズ（バイト）
    pub fn size_bytes(&self) -> u64 {
        self.nsze * self.block_size() as u64
    }

    /// メタデータサイズ（バイト）
    pub fn metadata_size(&self) -> u16 {
        self.current_lba_format().ms
    }

    /// メタデータが拡張LBAに含まれるか
    pub fn metadata_extended(&self) -> bool {
        (self.flbas & 0x10) != 0
    }
}

impl Default for IdentifyNamespace {
    fn default() -> Self {
        // Safety: ゼロ初期化は安全
        unsafe { core::mem::zeroed() }
    }
}

// ============================================================================
// LBA Format
// ============================================================================

/// LBA Format (4 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LbaFormat {
    /// Metadata Size (バイト)
    pub ms: u16,
    /// LBA Data Size (2^n バイト)
    pub lbads: u8,
    /// Relative Performance
    pub rp: u8,
}

impl LbaFormat {
    /// データサイズ（バイト）
    pub fn data_size(&self) -> usize {
        if self.lbads == 0 {
            0
        } else {
            1 << self.lbads
        }
    }

    /// 相対パフォーマンス
    pub fn relative_performance(&self) -> RelativePerformance {
        match self.rp & 0x03 {
            0 => RelativePerformance::Best,
            1 => RelativePerformance::Better,
            2 => RelativePerformance::Good,
            _ => RelativePerformance::Degraded,
        }
    }
}

/// 相対パフォーマンス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativePerformance {
    /// 最良
    Best = 0,
    /// より良い
    Better = 1,
    /// 良い
    Good = 2,
    /// 低下
    Degraded = 3,
}

// ============================================================================
// CNS Values
// ============================================================================

/// Identify CNS (Controller or Namespace Structure) 値
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentifyCns {
    /// Identify Namespace
    Namespace = 0x00,
    /// Identify Controller
    Controller = 0x01,
    /// Active Namespace ID list
    ActiveNamespaceIdList = 0x02,
    /// Namespace Identification Descriptor list
    NamespaceIdDescriptorList = 0x03,
    /// NVM Set List
    NvmSetList = 0x04,
    /// I/O Command Set specific Identify Namespace
    IoCommandSetNamespace = 0x05,
    /// I/O Command Set specific Identify Controller
    IoCommandSetController = 0x06,
    /// I/O Command Set specific Active Namespace ID list
    IoCommandSetActiveNamespaceIdList = 0x07,
    /// Allocated Namespace ID list
    AllocatedNamespaceIdList = 0x10,
    /// Identify Namespace for an allocated NSID
    AllocatedNamespace = 0x11,
    /// Namespace Attached Controller list
    NamespaceAttachedControllerList = 0x12,
    /// Controller list
    ControllerList = 0x13,
    /// Primary Controller Capabilities
    PrimaryControllerCapabilities = 0x14,
    /// Secondary Controller list
    SecondaryControllerList = 0x15,
    /// Namespace Granularity list
    NamespaceGranularityList = 0x16,
    /// UUID list
    UuidList = 0x17,
    /// Domain list
    DomainList = 0x18,
    /// Endurance Group list
    EnduranceGroupList = 0x19,
    /// I/O Command Set Independent Identify Namespace
    IoCommandSetIndependentNamespace = 0x1C,
}

impl From<IdentifyCns> for u8 {
    fn from(cns: IdentifyCns) -> Self {
        cns as u8
    }
}

// ============================================================================
// Compile-time Size Checks
// ============================================================================

const _: () = {
    assert!(core::mem::size_of::<IdentifyController>() == 4096);
    assert!(core::mem::size_of::<IdentifyNamespace>() == 4096);
    assert!(core::mem::size_of::<PowerStateDescriptor>() == 32);
    assert!(core::mem::size_of::<LbaFormat>() == 4);
};
