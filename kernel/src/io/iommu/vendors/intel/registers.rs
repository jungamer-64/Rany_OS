// ============================================================================
// kernel/src/io/iommu/vendors/intel/registers.rs
// ============================================================================

//! IOMMU Register Definitions
pub mod regs {
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
}

/// Global command bits
pub mod gcmd_bits {
    /// Translation enable
    pub const GCMD_TE: u32 = 1 << 31;
    /// Set root table pointer
    pub const GCMD_SRTP: u32 = 1 << 30;
    /// Queued invalidation enable
    pub const GCMD_QIE: u32 = 1 << 26;
    /// Interrupt remapping enable
    pub const GCMD_IRE: u32 = 1 << 25;
}

/// Global status bits
pub mod gsts_bits {
    /// Translation enable status
    pub const GSTS_TES: u32 = 1 << 31;
    /// Root table pointer status
    pub const GSTS_RTPS: u32 = 1 << 30;
    /// Queued invalidation enable status
    pub const GSTS_QIES: u32 = 1 << 26;
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
}

/// Root table address register bits
pub mod rtaddr_bits {
    /// Scalable Mode Translation enable (RTT/SMT)
    pub const RTADDR_SMT: u64 = 1 << 11;
}

/// Capability register bits
pub mod cap_bits {
    /// Supported Adjusted Guest Address Widths (bits 8-12)
    pub const CAP_SAGAW_MASK: u64 = 0x1F << 8;
    /// Maximum Guest Address Width (bits 16-21)
    pub const CAP_MGAW_MASK: u64 = 0x3F << 16;
    /// 2MB super-page supported
    pub const CAP_SLLPS_2M: u64 = 1 << 34;
    /// 1GB super-page supported
    pub const CAP_SLLPS_1G: u64 = 1 << 35;
    /// Address Mask (AM) support (bits 48-53)
    pub const CAP_AM_MASK: u64 = 0x3F << 48;
}

/// Extended capability register bits
pub mod ecap_bits {
    /// Queued Invalidation support
    pub const ECAP_QI: u64 = 1 << 1;
    /// Device-TLB support
    pub const ECAP_DT: u64 = 1 << 2;
    /// Interrupt Remapping Table Offset (bits 8-17)
    pub const ECAP_IRO_MASK: u64 = 0x3FF << 8;
    /// Scalable Mode Translation Support
    pub const ECAP_SMTS: u64 = 1 << 43;
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
    /// Fault Record Index (bits 8-15)
    pub const FSTS_FRI_MASK: u32 = 0xFF << 8;
}

/// IOTLB Invalidation register offsets (relative to IRO)
pub mod iotlb_regs {
    /// IOTLB Invalidation Command register (64-bit)
    pub const IOTLB: u64 = 0x08;
}

/// IOTLB Invalidation Command bits
pub mod iotlb_bits {
    /// Invalidation Request Granularity (bits 60-61)
    pub const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;
    pub const IOTLB_IIRG_DOMAIN: u64 = 2 << 60;
    /// Drain Reads before invalidation
    pub const IOTLB_DR: u64 = 1 << 49;
    /// Drain Writes before invalidation
    pub const IOTLB_DW: u64 = 1 << 48;
    /// Domain ID (bits 32-47)
    pub const IOTLB_DID_SHIFT: u64 = 32;
    /// Invalidation In Progress
    pub const IOTLB_IVT: u64 = 1 << 63;
}
