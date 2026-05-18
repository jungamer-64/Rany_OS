// ============================================================================
// kernel/src/io/iommu/vendors/intel/registers.rs
// ============================================================================

//! IOMMU Register Definitions
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
    /// Fault event upper address register
    pub const FEUADDR: u64 = 0x44;
    /// Invalidation queue head register
    pub const IQH: u64 = 0x80;
    /// Invalidation queue tail register
    pub const IQT: u64 = 0x88;
    /// Invalidation queue address register
    pub const IQA: u64 = 0x90;
    /// Invalidation event control register
    pub const IECTL: u64 = 0xA0;
    /// Invalidation event data register
    pub const IEDATA: u64 = 0xA4;
    /// Invalidation event address register
    pub const IEADDR: u64 = 0xA8;
    /// Invalidation event upper address register
    pub const IEUADDR: u64 = 0xAC;
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

/// Context Command register bits
pub mod ccmd_bits {
    /// Invalidate Context-Cache (ICC) - bit 63
    /// Set to 1 to initiate invalidation, cleared by hardware when complete
    pub const CCMD_ICC: u64 = 1 << 63;
    /// Context Invalidation Request Granularity (CIRG) - bits 61-62
    pub const CCMD_CIRG_SHIFT: u32 = 61;
    /// Global invalidation
    pub const CCMD_CIRG_GLOBAL: u8 = 0b01;
    /// Domain-selective invalidation
    pub const CCMD_CIRG_DOMAIN: u8 = 0b10;
    /// Device-selective invalidation
    pub const CCMD_CIRG_DEVICE: u8 = 0b11;
    /// Context Invalidation Actual Granularity (CAIG) - bits 59-60 (read-only)
    pub const CCMD_CAIG_SHIFT: u32 = 59;
    pub const CCMD_CAIG_MASK: u64 = 0b11 << 59;
    /// Domain ID field - bits 0-15
    pub const CCMD_DID_MASK: u64 = 0xFFFF;
    /// Source ID field - bits 16-31
    pub const CCMD_SID_SHIFT: u32 = 16;
    pub const CCMD_SID_MASK: u64 = 0xFFFF << 16;
    /// Function Mask - bits 32-33
    pub const CCMD_FM_SHIFT: u32 = 32;
    pub const CCMD_FM_MASK: u64 = 0b11 << 32;
}

/// Root table address register bits
pub mod rtaddr_bits {
    /// Scalable Mode Translation enable (RTT/SMT)
    pub const RTADDR_SMT: u64 = 1 << 11;
}

/// Capability register bits
pub mod cap_bits {
    /// Snoop control (if supported in CAP)
    pub const CAP_SC: u64 = 1 << 3;
    /// Required write-buffer flushing
    pub const CAP_RWBF: u64 = 1 << 4;
    /// Page-level memory introspection
    pub const CAP_PLMR: u64 = 1 << 5;
    /// Pass through support
    pub const CAP_PT: u64 = 1 << 6;
    /// Caching mode
    pub const CAP_CM: u64 = 1 << 7;
    /// Supported Adjusted Guest Address Widths (bits 8-12)
    pub const CAP_SAGAW_MASK: u64 = 0x1F << 8;
    /// Maximum Guest Address Width (bits 16-21)
    pub const CAP_MGAW_MASK: u64 = 0x3F << 16;
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
    /// Address Mask (AM) support (bits 48-53)
    pub const CAP_AM_MASK: u64 = 0x3F << 48;
    /// Page walk coherency
    pub const CAP_PWC: u64 = 1 << 38;
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
    pub const ECAP_SMTS: u64 = 1 << 43;
    /// Performance Monitoring Support
    pub const ECAP_PMC: u64 = 1 << 40;
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
