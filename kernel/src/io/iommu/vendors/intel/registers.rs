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
    /// Interrupt remapping table address register
    pub const IRTA: u64 = 0xB8;
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
    /// Set interrupt remapping table pointer
    pub const GCMD_SIRTP: u32 = 1 << 24;
}

/// Global status bits
pub mod gsts_bits {
    /// Translation enable status
    pub const GSTS_TES: u32 = 1 << 31;
    /// Root table pointer status
    pub const GSTS_RTPS: u32 = 1 << 30;
    /// Queued invalidation enable status
    pub const GSTS_QIES: u32 = 1 << 26;
    /// Interrupt remapping enable status
    pub const GSTS_IRES: u32 = 1 << 25;
    /// Interrupt remapping table pointer status
    pub const GSTS_IRTPS: u32 = 1 << 24;
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
    /// Interrupt remapping support
    pub const ECAP_IR: u64 = 1 << 3;
    /// Extended interrupt mode support
    pub const ECAP_EIM: u64 = 1 << 4;
    /// IOTLB register offset in 16-byte units (bits 8-17)
    pub const ECAP_IRO_MASK: u64 = 0x3FF << 8;
    /// Scalable Mode Translation Support
    pub const ECAP_SMTS: u64 = 1 << 43;
}

/// Fault status register bits
pub mod fsts_bits {
    /// Primary Pending Fault
    pub const FSTS_PPF: u32 = 1 << 1;
    /// Primary Fault Overflow
    pub const FSTS_PFO: u32 = 1 << 0;
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

/// CAP/ECAP-defined register geometry. These registers are immutable for the
/// lifetime of a firmware unit. No register address is accepted from a caller.
#[derive(Debug, Clone, Copy)]
struct RegisterLayout {
    fault_offset: usize,
    fault_count: usize,
    iotlb_offset: usize,
    extent: usize,
}

impl RegisterLayout {
    fn decode(cap: u64, ecap: u64) -> Result<Self, hal::mmio::MmioAccessError> {
        use hal::mmio::MmioAccessError::OutOfBounds;
        let fault_offset = ((cap >> 24) & 0x3ff) as usize * 16;
        let fault_count = ((cap >> 40) & 0xff) as usize + 1;
        let iotlb_offset = ((ecap >> 8) & 0x3ff) as usize * 16;
        let fault_end = fault_offset + fault_count * 16;
        let iotlb_end = iotlb_offset + 16;
        // The fixed register prefix ends after IRTA. Neither variable register
        // bank may alias it or the other bank, including the IOTLB address word.
        if fault_offset < 0xc0
            || iotlb_offset < 0xc0
            || (fault_offset < iotlb_end && iotlb_offset < fault_end)
        {
            return Err(OutOfBounds);
        }
        let extent = (fault_end.max(iotlb_end).max(4096) + 4095) & !4095;
        Ok(Self {
            fault_offset,
            fault_count,
            iotlb_offset,
            extent,
        })
    }
}

/// The probe's immutable capability fields determine the whole claim, including
/// all 256 possible fault records and the complete IOTLB register bank.
pub(crate) fn register_extent(cap: u64, ecap: u64) -> Result<usize, hal::mmio::MmioAccessError> {
    RegisterLayout::decode(cap, ecap).map(|layout| layout.extent)
}

/// Checked Intel register accesses borrow their firmware mapping owner. IRQs
/// perform no allocation, owner lookup, or lock acquisition to derive a register.
pub(crate) struct RegisterBlock {
    mapping: hal::MappedMmio,
    layout: RegisterLayout,
}

macro_rules! fixed_registers {
    ($($name:ident: $value:ty, $access:ident, $constructor:ident, $offset:ident;)*) => {
        impl RegisterBlock {
            $(pub(super) fn $name(&self) -> hal::mmio::MmioRegister<'_, $value, hal::mmio::$access> {
                self.mapping.region().$constructor::<$value>(regs::$offset as usize)
                    .expect("register block construction checked the fixed register prefix")
            })*
        }
    };
}

fixed_registers! {
    capabilities: u64, ReadOnly, read_only, CAP;
    extended_capabilities: u64, ReadOnly, read_only, ECAP;
    global_command: u32, WriteOnly, write_only, GCMD;
    global_status: u32, ReadOnly, read_only, GSTS;
    root_table_address: u64, WriteOnly, write_only, RTADDR;
    context_command: u64, ReadWrite, read_write, CCMD;
    fault_status: u32, ReadWrite, read_write, FSTS;
    fault_control: u32, ReadWrite, read_write, FECTL;
    fault_data: u32, WriteOnly, write_only, FEDATA;
    fault_address: u32, WriteOnly, write_only, FEADDR;
    fault_upper_address: u32, WriteOnly, write_only, FEUADDR;
    queue_head: u64, ReadOnly, read_only, IQH;
    queue_tail: u64, WriteOnly, write_only, IQT;
    queue_address: u64, WriteOnly, write_only, IQA;
    invalidation_control: u32, ReadWrite, read_write, IECTL;
    invalidation_data: u32, WriteOnly, write_only, IEDATA;
    invalidation_address: u32, WriteOnly, write_only, IEADDR;
    invalidation_upper_address: u32, WriteOnly, write_only, IEUADDR;
    interrupt_table_address: u64, WriteOnly, write_only, IRTA;
}

impl RegisterBlock {
    pub(super) fn new(mapping: hal::MappedMmio) -> Result<Self, hal::mmio::MmioAccessError> {
        let region = mapping.region();
        let cap = region.read_only::<u64>(regs::CAP as usize)?.read();
        let ecap = region.read_only::<u64>(regs::ECAP as usize)?.read();
        let layout = RegisterLayout::decode(cap, ecap)?;
        if mapping.len() < layout.extent {
            return Err(hal::mmio::MmioAccessError::OutOfBounds);
        }
        // Validate the widest fixed access; page alignment was required by
        // firmware admission. Dynamic banks are naturally 16-byte aligned.
        region.read_only::<u64>(regs::IRTA as usize)?;
        region.read_only::<u64>(layout.fault_offset)?;
        region.read_only::<u64>(layout.iotlb_offset)?;
        Ok(Self { mapping, layout })
    }

    pub(super) fn fault_count(&self) -> usize {
        self.layout.fault_count
    }

    pub(super) fn fault_record(&self, index: usize) -> Option<FaultRegisters<'_>> {
        if index >= self.layout.fault_count {
            return None;
        }
        let offset = self.layout.fault_offset + index * 16;
        let region = self.mapping.region();
        Some(FaultRegisters {
            low: region
                .read_only::<u64>(offset)
                .expect("validated fault bank has a complete aligned low word"),
            high: region
                .read_only::<u64>(offset + 8)
                .expect("validated fault bank has a complete aligned high word"),
            publication: region
                .read_write::<u32>(offset + 12)
                .expect("validated fault bank contains its highest doubleword"),
        })
    }

    pub(super) fn iotlb_command(&self) -> hal::mmio::MmioRegister<'_, u64, hal::mmio::ReadWrite> {
        self.mapping
            .region()
            .read_write::<u64>(self.layout.iotlb_offset + 8)
            .expect("validated IOTLB bank contains the command word")
    }
}

pub(super) struct FaultRegisters<'mapping> {
    low: hal::mmio::MmioRegister<'mapping, u64, hal::mmio::ReadOnly>,
    high: hal::mmio::MmioRegister<'mapping, u64, hal::mmio::ReadOnly>,
    publication: hal::mmio::MmioRegister<'mapping, u32, hal::mmio::ReadWrite>,
}

impl FaultRegisters<'_> {
    /// Intel VT-d section 11.4.7.6: hardware publishes F last. Check the high
    /// doubleword before reading the remaining fields; hardware may publish using
    /// multiple doubleword writes. Acknowledge only F (RW1CS bit 127).
    pub(super) fn pending(&self) -> Option<crate::io::iommu::runtime::fault_log::FaultRecord> {
        if self.publication.read() & (1 << 31) == 0 {
            return None;
        }
        Some(crate::io::iommu::runtime::fault_log::FaultRecord {
            lo: self.low.read(),
            hi: self.high.read(),
        })
    }

    pub(super) fn acknowledge(&mut self) {
        self.publication.write(1 << 31);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(feature = "std", test)]
    #[cfg_attr(not(feature = "std"), test_case)]
    fn variable_banks_determine_the_claim_extent() {
        // Independent field encodings: FRO=0x3ff, NFR=255, IRO=0x10.
        assert_eq!(
            register_extent((0x3ff << 24) | (255 << 40), 0x10 << 8),
            Ok(0x5000)
        );
        assert_eq!(register_extent(0x10 << 24, 0x3ff << 8), Ok(0x4000));
        assert_eq!(register_extent(0x10 << 24, 0x20 << 8), Ok(0x1000));
    }

    #[cfg_attr(feature = "std", test)]
    #[cfg_attr(not(feature = "std"), test_case)]
    fn register_banks_cannot_alias_fixed_or_variable_registers() {
        assert!(register_extent(0, 0x20 << 8).is_err());
        assert!(register_extent(0x10 << 24, 0).is_err());
        assert!(register_extent(0x20 << 24, 0x20 << 8).is_err());
        assert!(register_extent((0x20 << 24) | (1 << 40), 0x21 << 8).is_err());
        assert_eq!(register_extent(0x20 << 24, 0x21 << 8), Ok(4096));
    }
}
