//! Register ownership is established before DMA addresses are published. Cached
//! offsets are BAR-relative geometry; they never serve as access authority.
//! Each operational register retains the acquired mapping independently.

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use exorust_sync::Mutex;
use hal::mmio::{MappedMmio, MmioAccessError, OwnedMmioRegister, ReadOnly, ReadWrite, WriteOnly};

use super::{
    CONFIG, CRCR, DCBAAP, ERDP, ERSTBA, ERSTSZ, IMAN, IR0, PAGESIZE, PORT_REGISTER_SIZE,
    PORTSC_BASE, USBCMD, USBSTS,
};
use crate::{PortNumber, UsbError, UsbResult};

type Read32 = OwnedMmioRegister<u32, ReadOnly>;
type Write32 = OwnedMmioRegister<u32, WriteOnly>;
type Write64 = OwnedMmioRegister<u64, WriteOnly>;
type ReadWrite32 = OwnedMmioRegister<u32, ReadWrite>;

/// Parsed capability geometry. It is derived once from this mapping and is
/// immutable for the lifetime of all registers belonging to the controller.
pub(super) struct ControllerLimits {
    pub slots: u8,
    pub ports: u8,
    pub context_stride: usize,
    pub scratchpad_pages: u16,
}

pub(super) struct XhciRegisters {
    pub limits: ControllerLimits,
    command: Mutex<ReadWrite32>,
    status: Read32,
    page_size: Read32,
    configure: Mutex<Write32>,
    command_ring: Mutex<Write64>,
    contexts: Mutex<Write64>,
    interrupt: Mutex<ReadWrite32>,
    event_segments: Mutex<Write32>,
    event_table: Mutex<Write64>,
    ports: Vec<Mutex<ReadWrite32>>,
    doorbells: Vec<Mutex<Write32>>,
}

impl XhciRegisters {
    /// All capability-driven offsets and complete register widths are checked
    /// before returning any operational access. Acquisition and retention of
    /// the PCI function, mapping, and cache policy belong to the mapping owner.
    pub fn new(mapping: MappedMmio) -> UsbResult<(Self, Write64)> {
        let mapping = Arc::new(mapping);
        let capabilities = mapping.region();
        let op = usize::from(capabilities.read_only::<u8>(0)?.read());
        let version = capabilities.read_only::<u16>(2)?.read();
        let hcs1 = capabilities.read_only::<u32>(4)?.read();
        let hcs2 = capabilities.read_only::<u32>(8)?.read();
        let hcc1 = capabilities.read_only::<u32>(0x10)?.read();
        let doorbells = capabilities.read_only::<u32>(0x14)?.read() as usize & !3;
        let runtime = capabilities.read_only::<u32>(0x18)?.read() as usize & !31;
        let slots = (hcs1 & 255) as u8;
        let ports = (hcs1 >> 24) as u8;
        if op < 0x20
            || !op.is_multiple_of(4)
            || version < 0x0090
            || slots == 0
            || ports == 0
            || (hcs1 >> 8) & 0x7ff == 0
            || runtime < op
            || doorbells < op
        {
            return Err(UsbError::InvalidController);
        }
        let interrupter = runtime
            .checked_add(IR0)
            .ok_or(MmioAccessError::OffsetOverflow)?;
        let mut port_registers = Vec::new();
        port_registers
            .try_reserve_exact(usize::from(ports))
            .map_err(|_| UsbError::NoResources)?;
        for port in 0..usize::from(ports) {
            let offset = op
                .checked_add(PORTSC_BASE + port * PORT_REGISTER_SIZE)
                .ok_or(MmioAccessError::OffsetOverflow)?;
            port_registers.push(Mutex::new(mapping.owned_read_write(offset)?));
        }
        let mut doorbell_registers = Vec::new();
        doorbell_registers
            .try_reserve_exact(usize::from(slots) + 1)
            .map_err(|_| UsbError::NoResources)?;
        for slot in 0..=usize::from(slots) {
            let offset = doorbells
                .checked_add(slot * 4)
                .ok_or(MmioAccessError::OffsetOverflow)?;
            doorbell_registers.push(Mutex::new(mapping.owned_write_only(offset)?));
        }
        let registers = Self {
            limits: ControllerLimits {
                slots,
                ports,
                context_stride: if hcc1 & 4 != 0 { 64 } else { 32 },
                scratchpad_pages: (((hcs2 >> 21) & 31) << 5 | (hcs2 >> 27) & 31) as u16,
            },
            command: Mutex::new(mapping.owned_read_write(op + USBCMD)?),
            status: mapping.owned_read_only(op + USBSTS)?,
            page_size: mapping.owned_read_only(op + PAGESIZE)?,
            configure: Mutex::new(mapping.owned_write_only(op + CONFIG)?),
            command_ring: Mutex::new(mapping.owned_write_only(op + CRCR)?),
            contexts: Mutex::new(mapping.owned_write_only(op + DCBAAP)?),
            interrupt: Mutex::new(mapping.owned_read_write(interrupter + IMAN)?),
            event_segments: Mutex::new(mapping.owned_write_only(interrupter + ERSTSZ)?),
            event_table: Mutex::new(mapping.owned_write_only(interrupter + ERSTBA)?),
            ports: port_registers,
            doorbells: doorbell_registers,
        };
        let event_dequeue = mapping.owned_write_only(interrupter + ERDP)?;
        Ok((registers, event_dequeue))
    }

    pub fn command(&self) -> u32 {
        self.command.lock().read()
    }
    pub fn update_command(&self, clear: u32, set: u32) {
        let mut register = self.command.lock();
        let value = (register.read() & !clear) | set;
        register.write(value);
    }
    pub fn status(&self) -> u32 {
        self.status.read()
    }
    pub fn supports_4k_pages(&self) -> bool {
        self.page_size.read() & 1 != 0
    }
    pub fn configure_slots(&self) {
        self.configure.lock().write(u32::from(self.limits.slots));
    }
    pub fn set_command_ring(&self, address: u64) {
        self.command_ring.lock().write(address | 1);
    }
    pub fn set_contexts(&self, address: u64) {
        self.contexts.lock().write(address);
    }
    pub fn set_event_table(&self, address: u64) {
        self.event_segments.lock().write(1);
        self.event_table.lock().write(address);
    }
    pub fn enable_interrupt(&self) {
        self.interrupt.lock().write(3);
    }

    pub fn port_status(&self, port: PortNumber) -> UsbResult<u32> {
        let register = self
            .ports
            .get(port.as_usize())
            .ok_or(UsbError::InvalidParameter)?;
        Ok(register.lock().read())
    }

    pub fn update_port(&self, port: PortNumber, clear: u32, set: u32) -> UsbResult<()> {
        let register = self
            .ports
            .get(port.as_usize())
            .ok_or(UsbError::InvalidParameter)?;
        let mut register = register.lock();
        let value = (register.read() & !clear) | set;
        register.write(value);
        Ok(())
    }

    pub fn ring_doorbell(&self, slot: u8, target: u8) -> UsbResult<()> {
        let register = self
            .doorbells
            .get(usize::from(slot))
            .ok_or(UsbError::InvalidDevice)?;
        hal::mmio::sfence();
        register.lock().write(u32::from(target));
        Ok(())
    }
}
