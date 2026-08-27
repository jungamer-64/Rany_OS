extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use exorust_sync::{IrqPoisonLock, IrqPoisonLockGuard};
use spin::Once;

use crate::ApicDestination;

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;
const IOAPICID: u8 = 0x00;
const IOAPICVER: u8 = 0x01;
const IOREDTBL_BASE: u8 = 0x10;

#[derive(Debug)]
pub struct IoApicResource {
    pub registers: hal::MappedMmio,
    pub global_interrupt_base: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicDestination(u8);

impl TryFrom<ApicDestination> for IoApicDestination {
    type Error = IoApicError;

    fn try_from(destination: ApicDestination) -> Result<Self, Self::Error> {
        let value = destination.as_u32();
        let value = u8::try_from(value)
            .map_err(|_| IoApicError::DestinationRequiresInterruptRemapping { destination })?;
        Ok(Self(value))
    }
}

impl IoApicDestination {
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    NotInitialized,
    EmptyTopology,
    InvalidRegisterMapping(hal::MmioAccessError),
    GlobalInterruptRangeOverflow,
    OverlappingGlobalInterruptRange { first: u32, second: u32 },
    GlobalInterruptUnroutable { gsi: u32 },
    DestinationRequiresInterruptRemapping { destination: ApicDestination },
}

impl fmt::Display for IoApicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => formatter.write_str("I/O APIC topology is not initialized"),
            Self::EmptyTopology => formatter.write_str("I/O APIC topology is empty"),
            Self::InvalidRegisterMapping(error) => {
                write!(formatter, "invalid I/O APIC register mapping: {error:?}")
            }
            Self::GlobalInterruptRangeOverflow => {
                formatter.write_str("I/O APIC GSI range overflows")
            }
            Self::OverlappingGlobalInterruptRange { first, second } => write!(
                formatter,
                "I/O APIC global interrupt ranges overlap at {first} and {second}"
            ),
            Self::GlobalInterruptUnroutable { gsi } => {
                write!(
                    formatter,
                    "global interrupt {gsi} is not owned by an I/O APIC"
                )
            }
            Self::DestinationRequiresInterruptRemapping { destination } => write!(
                formatter,
                "APIC destination {} requires interrupt remapping",
                destination.as_u32()
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerMode {
    #[default]
    Edge,
    Level,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Polarity {
    #[default]
    HighActive,
    LowActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectionEntry {
    low: u32,
    high: u32,
}

impl RedirectionEntry {
    pub const fn new(vector: u8) -> Self {
        Self {
            low: vector as u32,
            high: 0,
        }
    }

    pub const fn masked() -> Self {
        Self {
            low: 1 << 16,
            high: 0,
        }
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self {
            low: raw as u32,
            high: (raw >> 32) as u32,
        }
    }

    pub const fn to_raw(self) -> u64 {
        self.low as u64 | ((self.high as u64) << 32)
    }

    pub const fn destination(mut self, destination: IoApicDestination) -> Self {
        self.high = (destination.as_u8() as u32) << 24;
        self
    }

    pub const fn with_trigger_mode(mut self, mode: TriggerMode) -> Self {
        match mode {
            TriggerMode::Edge => self.low &= !(1 << 15),
            TriggerMode::Level => self.low |= 1 << 15,
        }
        self
    }

    pub const fn with_polarity(mut self, polarity: Polarity) -> Self {
        match polarity {
            Polarity::HighActive => self.low &= !(1 << 13),
            Polarity::LowActive => self.low |= 1 << 13,
        }
        self
    }

    pub const fn mask(mut self) -> Self {
        self.low |= 1 << 16;
        self
    }

    pub const fn unmask(mut self) -> Self {
        self.low &= !(1 << 16);
        self
    }

    pub const fn is_masked(self) -> bool {
        self.low & (1 << 16) != 0
    }

    pub const fn vector(self) -> u8 {
        self.low as u8
    }
}

#[derive(Debug)]
pub struct IoApic {
    registers: hal::MappedMmio,
    global_interrupt_base: u32,
    redirection_count: u32,
}

impl IoApic {
    fn discover(resource: IoApicResource) -> Result<Self, IoApicError> {
        resource
            .registers
            .region()
            .write_only::<u32>(IOREGSEL)
            .map_err(IoApicError::InvalidRegisterMapping)?;
        resource
            .registers
            .region()
            .read_write::<u32>(IOWIN)
            .map_err(IoApicError::InvalidRegisterMapping)?;
        let provisional = Self {
            registers: resource.registers,
            global_interrupt_base: resource.global_interrupt_base,
            redirection_count: 0,
        };
        let redirection_count = ((provisional.read(IOAPICVER) >> 16) & 0xff) + 1;
        provisional
            .global_interrupt_base
            .checked_add(redirection_count)
            .ok_or(IoApicError::GlobalInterruptRangeOverflow)?;
        Ok(Self {
            redirection_count,
            ..provisional
        })
    }

    fn read(&self, register: u8) -> u32 {
        let mut selector = self
            .registers
            .region()
            .write_only::<u32>(IOREGSEL)
            .expect("I/O APIC selector fits its mapped register page");
        selector.write(u32::from(register));
        self.registers
            .region()
            .read_only::<u32>(IOWIN)
            .expect("I/O APIC window fits its mapped register page")
            .read()
    }

    fn write(&self, register: u8, value: u32) {
        let mut selector = self
            .registers
            .region()
            .write_only::<u32>(IOREGSEL)
            .expect("I/O APIC selector fits its mapped register page");
        selector.write(u32::from(register));
        let mut window = self
            .registers
            .region()
            .write_only::<u32>(IOWIN)
            .expect("I/O APIC window fits its mapped register page");
        window.write(value);
    }

    fn contains(&self, gsi: u32) -> bool {
        self.global_interrupt_base <= gsi
            && gsi < self.global_interrupt_base + self.redirection_count
    }

    fn local_index(&self, gsi: u32) -> Option<u8> {
        self.contains(gsi)
            .then(|| u8::try_from(gsi - self.global_interrupt_base).ok())
            .flatten()
    }

    fn write_entry(&self, local_index: u8, entry: RedirectionEntry) {
        let register = IOREDTBL_BASE + local_index * 2;
        let raw = entry.to_raw();
        self.write(register, raw as u32 | (1 << 16));
        self.write(register + 1, (raw >> 32) as u32);
        self.write(register, raw as u32);
    }

    fn read_entry(&self, local_index: u8) -> RedirectionEntry {
        let register = IOREDTBL_BASE + local_index * 2;
        RedirectionEntry::from_raw(
            u64::from(self.read(register)) | (u64::from(self.read(register + 1)) << 32),
        )
    }

    pub fn id(&self) -> u8 {
        ((self.read(IOAPICID) >> 24) & 0xf) as u8
    }

    pub fn version(&self) -> u8 {
        (self.read(IOAPICVER) & 0xff) as u8
    }

    pub const fn global_interrupt_base(&self) -> u32 {
        self.global_interrupt_base
    }

    pub const fn redirection_count(&self) -> u32 {
        self.redirection_count
    }
}

#[derive(Debug, Default)]
pub struct IoApicSet {
    controllers: Vec<IoApic>,
}

impl IoApicSet {
    /// Discovers a validated, non-overlapping I/O APIC topology.
    ///
    /// # Errors
    ///
    /// Returns an error for empty input, invalid mappings, or overlapping GSI
    /// ownership.
    pub fn discover(resources: Vec<IoApicResource>) -> Result<Self, IoApicError> {
        if resources.is_empty() {
            return Err(IoApicError::EmptyTopology);
        }
        let mut controllers = resources
            .into_iter()
            .map(IoApic::discover)
            .collect::<Result<Vec<_>, _>>()?;
        controllers.sort_by_key(IoApic::global_interrupt_base);
        for pair in controllers.windows(2) {
            let first_end = pair[0].global_interrupt_base + pair[0].redirection_count;
            if first_end > pair[1].global_interrupt_base {
                return Err(IoApicError::OverlappingGlobalInterruptRange {
                    first: pair[0].global_interrupt_base,
                    second: pair[1].global_interrupt_base,
                });
            }
        }
        let topology = Self { controllers };
        for controller in &topology.controllers {
            for local_index in 0..controller.redirection_count {
                controller.write_entry(local_index as u8, RedirectionEntry::masked());
            }
        }
        Ok(topology)
    }

    pub fn controllers(&self) -> &[IoApic] {
        &self.controllers
    }

    pub fn owner(&self, gsi: u32) -> Option<(&IoApic, u8)> {
        self.controllers
            .iter()
            .find_map(|controller| controller.local_index(gsi).map(|index| (controller, index)))
    }

    /// Writes one redirection entry by global interrupt number.
    ///
    /// # Errors
    ///
    /// Returns an error if no controller owns `gsi`.
    pub fn write_gsi(&self, gsi: u32, entry: RedirectionEntry) -> Result<(), IoApicError> {
        let (controller, local_index) = self
            .owner(gsi)
            .ok_or(IoApicError::GlobalInterruptUnroutable { gsi })?;
        controller.write_entry(local_index, entry);
        Ok(())
    }

    /// Reads one redirection entry by global interrupt number.
    ///
    /// # Errors
    ///
    /// Returns an error if no controller owns `gsi`.
    pub fn read_gsi(&self, gsi: u32) -> Result<RedirectionEntry, IoApicError> {
        let (controller, local_index) = self
            .owner(gsi)
            .ok_or(IoApicError::GlobalInterruptUnroutable { gsi })?;
        Ok(controller.read_entry(local_index))
    }
}

static IO_APICS: Once<IrqPoisonLock<IoApicSet>> = Once::new();

/// Installs the immutable I/O APIC controller topology.
///
/// # Errors
///
/// Returns an error if discovery fails. A previously installed topology is
/// returned unchanged.
pub fn initialize_io_apics(
    resources: Vec<IoApicResource>,
) -> Result<IrqPoisonLockGuard<'static, IoApicSet>, IoApicError> {
    if IO_APICS.get().is_none() {
        let topology = IoApicSet::discover(resources)?;
        IO_APICS.call_once(|| IrqPoisonLock::new(topology));
    }
    io_apics()
}

/// Locks the installed I/O APIC topology.
///
/// # Errors
///
/// Returns `NotInitialized` until firmware discovery installs the topology.
pub fn io_apics() -> Result<IrqPoisonLockGuard<'static, IoApicSet>, IoApicError> {
    IO_APICS
        .get()
        .ok_or(IoApicError::NotInitialized)
        .map(|topology| topology.lock().unwrap_or_else(|error| error.into_inner()))
}
