// ============================================================================
// kernel/src/io/iommu/amd/registers.rs
// ============================================================================

//! AMD-Vi MMIO register offsets and hardware constant definitions.

// MMIO register offsets
pub(crate) const MMIO_DEV_TABLE_OFFSET: u64 = 0x0000;
pub(crate) const MMIO_EVT_BUF_OFFSET: u64 = 0x0010;
pub(crate) const MMIO_CONTROL_OFFSET: u64 = 0x0018;
pub(crate) const MMIO_MSI_ADDR_LO_OFFSET: u64 = 0x015c;
pub(crate) const MMIO_MSI_ADDR_HI_OFFSET: u64 = 0x0160;
pub(crate) const MMIO_MSI_DATA_OFFSET: u64 = 0x0164;
pub(crate) const MMIO_EVT_HEAD_OFFSET: u64 = 0x2010;
pub(crate) const MMIO_EVT_TAIL_OFFSET: u64 = 0x2018;
pub(crate) const MMIO_STATUS_OFFSET: u64 = 0x2020;

// Control register flags
pub(crate) const CONTROL_IOMMU_EN: u64 = 1 << 0;
pub(crate) const CONTROL_EVT_LOG_EN: u64 = 1 << 2;
pub(crate) const CONTROL_EVT_INT_EN: u64 = 1 << 3;
pub(crate) const CONTROL_CMDBUF_EN: u64 = 1 << 12;

// Device table entry page mode fields
pub(crate) const DEV_ENTRY_MODE_SHIFT: u64 = 9;
pub(crate) const PAGE_MODE_4_LEVEL: u64 = 0x04;
pub(crate) const PM_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

// Device table entry flags
pub(crate) const DTE_FLAG_V: u64 = 1 << 0;
pub(crate) const DTE_FLAG_TV: u64 = 1 << 1;
pub(crate) const DTE_FLAG_IR: u64 = 1 << 61;
pub(crate) const DTE_FLAG_IW: u64 = 1 << 62;

// Table entry sizes
pub(crate) const DEV_TABLE_ENTRY_SIZE: usize = 32;
pub(crate) const EVENT_ENTRY_SIZE: u32 = 16;
pub(crate) const EVT_BUFFER_BYTES: u32 = 8192;
pub(crate) const EVT_BUFFER_SIZE_MASK: u64 = 0x9 << 56;

// Event log MMIO status bits
pub(crate) const MMIO_STATUS_EVT_OVERFLOW_MASK: u32 = 1 << 0;
pub(crate) const MMIO_STATUS_EVT_INT_MASK: u32 = 1 << 1;
pub(crate) const MMIO_STATUS_EVT_RUN_MASK: u32 = 1 << 3;

// Event type field extraction
pub(crate) const EVENT_TYPE_SHIFT: u32 = 28;
pub(crate) const EVENT_TYPE_MASK: u32 = 0x0f;
pub(crate) const EVENT_TYPE_ILL_DEV: u8 = 0x1;
pub(crate) const EVENT_TYPE_IO_FAULT: u8 = 0x2;
pub(crate) const EVENT_TYPE_DEV_TAB_ERR: u8 = 0x3;
pub(crate) const EVENT_TYPE_PAGE_TAB_ERR: u8 = 0x4;
pub(crate) const EVENT_TYPE_ILL_CMD: u8 = 0x5;
pub(crate) const EVENT_TYPE_CMD_HARD_ERR: u8 = 0x6;
pub(crate) const EVENT_TYPE_IOTLB_INV_TO: u8 = 0x7;
pub(crate) const EVENT_TYPE_INV_DEV_REQ: u8 = 0x8;
pub(crate) const EVENT_TYPE_INV_PPR_REQ: u8 = 0x9;
pub(crate) const EVENT_TYPE_RMP_FAULT: u8 = 0x0d;
pub(crate) const EVENT_TYPE_RMP_HW_ERR: u8 = 0x0e;
pub(crate) const EVENT_DEVID_MASK: u32 = 0xffff;
pub(crate) const EVENT_DEVID_SHIFT: u32 = 0;
pub(crate) const EVENT_DOMID_MASK_LO: u32 = 0xffff;
pub(crate) const EVENT_DOMID_MASK_HI: u32 = 0xf0000;
pub(crate) const EVENT_FLAGS_MASK: u32 = 0x0fff;
pub(crate) const EVENT_FLAGS_SHIFT: u32 = 0x10;

// Fault / interrupt queue constants
pub(crate) const AMD_FAULT_QUEUE_SIZE: usize = 128;
pub(crate) const AMD_FAULT_LOG_RATE_LIMIT: usize = 128;
// Use a fixed IOMMU fault vector number to avoid depending on `interrupts` during lib builds
pub(crate) const AMD_IOMMU_FAULT_VECTOR: u8 = 0x50u8;
pub(crate) const AMD_DEFAULT_MAX_ADDR_BITS: u8 = 48; // Fallback when EFR is unavailable.

// Extended Feature Register (EFR) — MMIO offset 0x30
pub(crate) const MMIO_EXT_FEATURE_OFFSET: u64 = 0x0030;
pub(crate) const EFR_HATS_SHIFT: u32 = 10;
pub(crate) const EFR_HATS_MASK: u64 = 0x03; // bits [11:10] — Host Address Translation Size

/// Read the supported address width from the IOMMU Extended Feature Register.
///
/// HATS encoding (AMD-Vi spec Table 14):
///  - 0b00 = 4-level page table (48-bit)
///  - 0b01 = 5-level page table (57-bit)
///  - 0b10, 0b11 = reserved
///
/// Falls back to `AMD_DEFAULT_MAX_ADDR_BITS` on unknown values.
#[cfg(not(test))]
pub(super) fn read_max_addr_bits(mmio_base: usize) -> u8 {
    let efr = crate::io::mmio::mmio_read_u64(mmio_base + MMIO_EXT_FEATURE_OFFSET as usize);
    let hats = (efr >> EFR_HATS_SHIFT) & EFR_HATS_MASK;
    match hats {
        0b00 => 48,
        0b01 => 57,
        _ => {
            log::warn!(
                "AMD-Vi: Unknown HATS value {} in EFR {:#x}, defaulting to {} bits",
                hats,
                efr,
                AMD_DEFAULT_MAX_ADDR_BITS
            );
            AMD_DEFAULT_MAX_ADDR_BITS
        }
    }
}

// IVHD device entry flags
pub(crate) const IVHD_INIT_PASS: u8 = 1 << 0;
pub(crate) const IVHD_EINT_PASS: u8 = 1 << 1;
pub(crate) const IVHD_NMI_PASS: u8 = 1 << 2;
pub(crate) const IVHD_SYSMGT1: u8 = 1 << 4;
pub(crate) const IVHD_SYSMGT2: u8 = 1 << 5;
pub(crate) const IVHD_LINT0_PASS: u8 = 1 << 6;
pub(crate) const IVHD_LINT1_PASS: u8 = 1 << 7;

// DTE byte offsets for IVHD flag application
pub(crate) const DEV_ENTRY_INIT_PASS: u8 = 0xb8;
pub(crate) const DEV_ENTRY_EINT_PASS: u8 = 0xb9;
pub(crate) const DEV_ENTRY_NMI_PASS: u8 = 0xba;
pub(crate) const DEV_ENTRY_SYSMGT1: u8 = 0x68;
pub(crate) const DEV_ENTRY_SYSMGT2: u8 = 0x69;
pub(crate) const DEV_ENTRY_LINT0_PASS: u8 = 0xbe;
pub(crate) const DEV_ENTRY_LINT1_PASS: u8 = 0xbf;
