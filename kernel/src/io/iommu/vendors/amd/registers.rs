// ============================================================================
// kernel/src/io/iommu/vendors/amd/registers.rs
// ============================================================================

//! AMD-Vi MMIO register offsets and hardware constant definitions.

use crate::io::iommu::types::IommuError;
use crate::sync::IrqMutex;
use alloc::sync::Arc;
use hal::mmio::{MappedMmio, OwnedMmioRegister, ReadOnly, ReadWrite, WriteOnly};

type ReadRegister = OwnedMmioRegister<u64, ReadOnly>;
type WriteRegister = OwnedMmioRegister<u64, WriteOnly>;
type UpdateRegister = OwnedMmioRegister<u64, ReadWrite>;

struct CommandRegisters {
    base: WriteRegister,
    head: UpdateRegister,
    tail: WriteRegister,
}

struct EventRegisters {
    base: WriteRegister,
    head: UpdateRegister,
    tail: UpdateRegister,
    status: UpdateRegister,
}

/// Every register retains the admitted firmware mapping. Control updates are
/// serialized with IRQ exclusion because command setup and fault handling share
/// the same hardware word. No allocation or hardware wait occurs under a guard.
pub(super) struct AmdRegisters {
    control: IrqMutex<UpdateRegister>,
    command: IrqMutex<CommandRegisters>,
    event: IrqMutex<EventRegisters>,
    device_table: IrqMutex<WriteRegister>,
    interrupt_table: IrqMutex<WriteRegister>,
    extended_features: ReadRegister,
}

impl core::fmt::Debug for AmdRegisters {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AmdRegisters")
            .finish_non_exhaustive()
    }
}

impl AmdRegisters {
    pub(super) fn new(mapping: MappedMmio) -> Result<Self, IommuError> {
        let mapping = Arc::try_new(mapping).map_err(|_| IommuError::OutOfMemory)?;
        let write = |offset| {
            mapping
                .owned_write_only::<u64>(offset)
                .map_err(IommuError::RegisterAccess)
        };
        let read = |offset| {
            mapping
                .owned_read_only::<u64>(offset)
                .map_err(IommuError::RegisterAccess)
        };
        let update = |offset| {
            mapping
                .owned_read_write::<u64>(offset)
                .map_err(IommuError::RegisterAccess)
        };
        Ok(Self {
            control: IrqMutex::new(update(MMIO_CONTROL_OFFSET as usize)?),
            command: IrqMutex::new(CommandRegisters {
                base: write(0x0008)?,
                head: update(0x2000)?,
                tail: write(0x2008)?,
            }),
            event: IrqMutex::new(EventRegisters {
                base: write(MMIO_EVT_BUF_OFFSET as usize)?,
                head: update(MMIO_EVT_HEAD_OFFSET as usize)?,
                tail: update(MMIO_EVT_TAIL_OFFSET as usize)?,
                status: update(MMIO_STATUS_OFFSET as usize)?,
            }),
            device_table: IrqMutex::new(write(MMIO_DEV_TABLE_OFFSET as usize)?),
            interrupt_table: IrqMutex::new(write(MMIO_IRT_BASE_OFFSET as usize)?),
            extended_features: read(MMIO_EXT_FEATURE_OFFSET as usize)?,
        })
    }

    pub(super) fn extended_features(&self) -> u64 {
        self.extended_features.read()
    }

    pub(super) fn update_control(&self, update: impl FnOnce(u64) -> u64) {
        let mut register = self.control.lock();
        let value = update(register.read());
        register.write(value);
    }

    pub(super) fn program_device_table(&self, value: u64) {
        self.device_table.lock().write(value);
    }

    pub(super) fn program_interrupt_table(&self, value: u64) {
        self.interrupt_table.lock().write(value);
    }

    pub(super) fn program_command_buffer(&self, base: u64) {
        let mut registers = self.command.lock();
        registers.base.write(base);
        registers.head.write(0);
        registers.tail.write(0);
    }

    pub(super) fn command_head(&self) -> u64 {
        self.command.lock().head.read()
    }

    pub(super) fn publish_command_tail(&self, tail: u32) {
        hal::mmio::sfence();
        self.command.lock().tail.write(u64::from(tail));
    }

    pub(super) fn program_event_log(&self, base: u64) {
        let mut registers = self.event.lock();
        registers.base.write(base);
        registers.head.write(0);
        registers.tail.write(0);
    }

    pub(super) fn event_status(&self) -> u64 {
        self.event.lock().status.read()
    }

    pub(super) fn acknowledge_event_status(&self, bits: u64) {
        self.event.lock().status.write(bits);
    }

    pub(super) fn event_cursors(&self) -> Option<(u32, u32)> {
        let registers = self.event.lock();
        let head = u32::try_from(registers.head.read()).ok()?;
        let tail = u32::try_from(registers.tail.read()).ok()?;
        if head >= EVT_BUFFER_BYTES
            || tail >= EVT_BUFFER_BYTES
            || !head.is_multiple_of(EVENT_ENTRY_SIZE)
            || !tail.is_multiple_of(EVENT_ENTRY_SIZE)
        {
            return None;
        }
        Some((head, tail))
    }

    pub(super) fn advance_event_head(&self, head: u32) {
        self.event.lock().head.write(u64::from(head));
    }

    pub(super) fn restart_event_log(&self) {
        let mut control = self.control.lock();
        let value = control.read();
        control.write(value & !CONTROL_EVT_LOG_EN);
        self.acknowledge_event_status(MMIO_STATUS_EVT_OVERFLOW_MASK);
        control.write(value | CONTROL_EVT_LOG_EN);
    }
}

// MMIO register offsets
pub(crate) const MMIO_DEV_TABLE_OFFSET: u64 = 0x0000;
pub(crate) const MMIO_EVT_BUF_OFFSET: u64 = 0x0010;
pub(crate) const MMIO_CONTROL_OFFSET: u64 = 0x0018;
pub(crate) const MMIO_IRT_BASE_OFFSET: u64 = 0x0068;
pub(crate) const MMIO_EVT_HEAD_OFFSET: u64 = 0x2010;
pub(crate) const MMIO_EVT_TAIL_OFFSET: u64 = 0x2018;
pub(crate) const MMIO_STATUS_OFFSET: u64 = 0x2020;

// Control register flags
pub(crate) const CONTROL_IOMMU_EN: u64 = 1 << 0;
pub(crate) const CONTROL_EVT_LOG_EN: u64 = 1 << 2;
pub(crate) const CONTROL_EVT_INT_EN: u64 = 1 << 3;
pub(crate) const CONTROL_INT_MAP_EN: u64 = 1 << 4;
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
pub(crate) const MMIO_STATUS_EVT_OVERFLOW_MASK: u64 = 1 << 0;
pub(crate) const MMIO_STATUS_EVT_INT_MASK: u64 = 1 << 1;
pub(crate) const MMIO_STATUS_EVT_RUN_MASK: u64 = 1 << 3;

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
pub(crate) const EFR_IA_SUP: u64 = 1 << 6;
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
pub(super) fn max_addr_bits(efr: u64) -> u8 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn hats_encodings_select_supported_page_table_widths() {
        assert_eq!(max_addr_bits(0), 48);
        assert_eq!(max_addr_bits(1 << EFR_HATS_SHIFT), 57);
        assert_eq!(
            max_addr_bits(2 << EFR_HATS_SHIFT),
            AMD_DEFAULT_MAX_ADDR_BITS
        );
        assert_eq!(
            max_addr_bits(3 << EFR_HATS_SHIFT),
            AMD_DEFAULT_MAX_ADDR_BITS
        );
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
