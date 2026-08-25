use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hal::port_io::PortU8;

const APIC_BASE_MSR: u32 = 0x1b;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
const APIC_X2_ENABLE: u64 = 1 << 10;
const APIC_BASE_MASK: u64 = 0xffff_f000;
const X2APIC_MSR_BASE: u32 = 0x800;
const DELIVERY_STATUS: u32 = 1 << 12;
const DELIVERY_INIT: u32 = 0b101 << 8;
const DELIVERY_STARTUP: u32 = 0b110 << 8;
const LEVEL_ASSERT: u32 = 1 << 14;
const TRIGGER_LEVEL: u32 = 1 << 15;
const DESTINATION_ALL_EXCLUDING_SELF: u32 = 0b11 << 18;
const DELIVERY_WAIT_SPINS: usize = 1_000_000;
const PIT_WAIT_SPINS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApicDestination(u32);

impl ApicDestination {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicMode {
    XApic,
    X2Apic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicModePolicy {
    /// Use x2APIC when the processor supports it, otherwise use xAPIC.
    PreferX2Apic,
    /// Keep the platform in xAPIC mode even when the processor supports x2APIC.
    XApicOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InServiceVectors {
    banks: [u32; 8],
}

impl InServiceVectors {
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.banks.iter().enumerate().flat_map(|(bank, bits)| {
            (0..32u8)
                .filter(move |bit| bits & (1u32 << bit) != 0)
                .map(move |bit| bank as u8 * 32 + bit)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicDeliveryTarget {
    One(ApicDestination),
    AllExcludingSelf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalApicError {
    NotSelected,
    Unsupported,
    InvalidMmioBase { base: u64 },
    DestinationNotAddressable { destination: ApicDestination },
    DeliveryTimedOut { target: ApicDeliveryTarget },
    TimerNotCalibrated,
    TimerCountOverflow,
}

impl fmt::Display for LocalApicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSelected => formatter.write_str("local APIC mode has not been selected"),
            Self::Unsupported => formatter.write_str("local APIC is not supported"),
            Self::InvalidMmioBase { base } => {
                write!(formatter, "invalid local APIC MMIO base {base:#x}")
            }
            Self::DestinationNotAddressable { destination } => write!(
                formatter,
                "xAPIC cannot address destination {}",
                destination.as_u32()
            ),
            Self::DeliveryTimedOut {
                target: ApicDeliveryTarget::One(destination),
            } => write!(
                formatter,
                "IPI delivery to destination {} timed out",
                destination.as_u32()
            ),
            Self::DeliveryTimedOut {
                target: ApicDeliveryTarget::AllExcludingSelf,
            } => formatter.write_str("broadcast IPI delivery timed out"),
            Self::TimerNotCalibrated => formatter.write_str("local APIC timer is not calibrated"),
            Self::TimerCountOverflow => formatter.write_str("local APIC timer count overflowed"),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Register {
    Id = 0x020,
    Version = 0x030,
    Tpr = 0x080,
    Eoi = 0x0b0,
    Sivr = 0x0f0,
    Esr = 0x280,
    IcrLow = 0x300,
    IcrHigh = 0x310,
    LvtTimer = 0x320,
    LvtThermal = 0x330,
    LvtPmc = 0x340,
    LvtLint0 = 0x350,
    LvtLint1 = 0x360,
    LvtError = 0x370,
    TimerInitial = 0x380,
    TimerCurrent = 0x390,
    TimerDivide = 0x3e0,
}

#[derive(Debug)]
pub struct XApic {
    base: u64,
}

impl XApic {
    fn new(base: u64) -> Result<Self, LocalApicError> {
        if base == 0 || !base.is_multiple_of(4096) {
            return Err(LocalApicError::InvalidMmioBase { base });
        }
        Ok(Self { base })
    }

    fn register(&self, register: Register) -> hal::MmioReg<u32> {
        hal::MmioReg::new(self.base as usize, register as usize)
    }

    fn read(&self, register: Register) -> u32 {
        self.register(register).read()
    }

    fn write(&self, register: Register, value: u32) {
        self.register(register).write(value);
    }

    fn in_service_vectors(&self) -> InServiceVectors {
        let mut banks = [0; 8];
        for (bank, bits) in banks.iter_mut().enumerate() {
            *bits = hal::MmioReg::<u32>::new(self.base as usize, 0x100 + bank * 0x10).read();
        }
        InServiceVectors { banks }
    }

    fn destination_high(destination: ApicDestination) -> Result<u32, LocalApicError> {
        let value = destination.as_u32();
        if value > u8::MAX.into() {
            return Err(LocalApicError::DestinationNotAddressable { destination });
        }
        Ok(value << 24)
    }

    fn wait_for_delivery(&self, destination: ApicDestination) -> Result<(), LocalApicError> {
        if spin_until(
            || self.read(Register::IcrLow) & DELIVERY_STATUS == 0,
            DELIVERY_WAIT_SPINS,
        ) {
            Ok(())
        } else {
            Err(LocalApicError::DeliveryTimedOut {
                target: ApicDeliveryTarget::One(destination),
            })
        }
    }

    fn write_icr(&self, destination: ApicDestination, command: u32) -> Result<(), LocalApicError> {
        self.write(Register::IcrHigh, Self::destination_high(destination)?);
        self.write(Register::IcrLow, command);
        self.wait_for_delivery(destination)
    }

    fn write_shorthand_icr(&self, command: u32) -> Result<(), LocalApicError> {
        self.write(Register::IcrHigh, 0);
        self.write(Register::IcrLow, command);
        if spin_until(
            || self.read(Register::IcrLow) & DELIVERY_STATUS == 0,
            DELIVERY_WAIT_SPINS,
        ) {
            Ok(())
        } else {
            Err(LocalApicError::DeliveryTimedOut {
                target: ApicDeliveryTarget::AllExcludingSelf,
            })
        }
    }
}

#[derive(Debug, Default)]
pub struct X2Apic;

impl X2Apic {
    fn msr(register: Register) -> u32 {
        X2APIC_MSR_BASE + register as u32 / 16
    }

    fn read(&self, register: Register) -> u32 {
        unsafe { read_msr(Self::msr(register)) as u32 }
    }

    fn write(&self, register: Register, value: u32) {
        unsafe { write_msr(Self::msr(register), u64::from(value)) }
    }

    fn in_service_vectors(&self) -> InServiceVectors {
        let mut banks = [0; 8];
        for (bank, bits) in banks.iter_mut().enumerate() {
            *bits = unsafe { read_msr(X2APIC_MSR_BASE + 0x10 + bank as u32) as u32 };
        }
        InServiceVectors { banks }
    }

    fn write_icr(&self, destination: ApicDestination, command: u32) -> Result<(), LocalApicError> {
        let value = (u64::from(destination.as_u32()) << 32) | u64::from(command);
        unsafe { write_msr(Self::msr(Register::IcrLow), value) };
        if spin_until(
            || unsafe { read_msr(Self::msr(Register::IcrLow)) as u32 } & DELIVERY_STATUS == 0,
            DELIVERY_WAIT_SPINS,
        ) {
            Ok(())
        } else {
            Err(LocalApicError::DeliveryTimedOut {
                target: ApicDeliveryTarget::One(destination),
            })
        }
    }

    fn write_shorthand_icr(&self, command: u32) -> Result<(), LocalApicError> {
        unsafe { write_msr(Self::msr(Register::IcrLow), u64::from(command)) };
        if spin_until(
            || unsafe { read_msr(Self::msr(Register::IcrLow)) as u32 } & DELIVERY_STATUS == 0,
            DELIVERY_WAIT_SPINS,
        ) {
            Ok(())
        } else {
            Err(LocalApicError::DeliveryTimedOut {
                target: ApicDeliveryTarget::AllExcludingSelf,
            })
        }
    }
}

#[derive(Debug)]
enum Backend {
    XApic(XApic),
    X2Apic(X2Apic),
}

#[derive(Debug)]
pub struct LocalApic {
    backend: Backend,
    enabled: AtomicBool,
    ticks_per_ms: AtomicU64,
}

impl LocalApic {
    /// Builds the local-APIC backend selected by architectural support and
    /// the firmware-derived mode policy.
    ///
    /// # Errors
    ///
    /// Returns an error when APIC support is absent or the xAPIC MMIO base is
    /// invalid.
    pub(super) fn detect(policy: ApicModePolicy) -> Result<Self, LocalApicError> {
        let features = core::arch::x86_64::__cpuid(1);
        if features.edx & (1 << 9) == 0 {
            return Err(LocalApicError::Unsupported);
        }
        let apic_base = unsafe { read_msr(APIC_BASE_MSR) };
        let backend = match select_mode(policy, features.ecx & (1 << 21) != 0) {
            ApicMode::X2Apic => Backend::X2Apic(X2Apic),
            ApicMode::XApic => Backend::XApic(XApic::new(apic_base & APIC_BASE_MASK)?),
        };
        Ok(Self {
            backend,
            enabled: AtomicBool::new(false),
            ticks_per_ms: AtomicU64::new(0),
        })
    }

    pub const fn mode(&self) -> ApicMode {
        match self.backend {
            Backend::XApic(_) => ApicMode::XApic,
            Backend::X2Apic(_) => ApicMode::X2Apic,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn in_service_vectors(&self) -> InServiceVectors {
        match self.backend {
            Backend::XApic(ref xapic) => xapic.in_service_vectors(),
            Backend::X2Apic(ref x2apic) => x2apic.in_service_vectors(),
        }
    }

    /// Enables and initializes the local APIC on the executing CPU.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected xAPIC MMIO base is invalid.
    pub fn initialize_current_cpu(&self) -> Result<(), LocalApicError> {
        let mut apic_base = unsafe { read_msr(APIC_BASE_MSR) } | APIC_GLOBAL_ENABLE;
        match self.backend {
            Backend::XApic(ref xapic) => {
                apic_base &= !APIC_X2_ENABLE;
                if apic_base & APIC_BASE_MASK != xapic.base {
                    return Err(LocalApicError::InvalidMmioBase {
                        base: apic_base & APIC_BASE_MASK,
                    });
                }
            }
            Backend::X2Apic(_) => apic_base |= APIC_X2_ENABLE,
        }
        unsafe { write_msr(APIC_BASE_MSR, apic_base) };

        self.write(Register::Sivr, 0xff | 0x100);
        self.write(Register::Tpr, 0);
        for register in [
            Register::LvtTimer,
            Register::LvtThermal,
            Register::LvtPmc,
            Register::LvtLint0,
            Register::LvtLint1,
            Register::LvtError,
        ] {
            self.write(register, 1 << 16);
        }
        self.write(Register::Esr, 0);
        self.write(Register::Esr, 0);
        self.send_eoi();
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    pub fn id(&self) -> u32 {
        match self.backend {
            Backend::XApic(ref backend) => backend.read(Register::Id) >> 24,
            Backend::X2Apic(ref backend) => backend.read(Register::Id),
        }
    }

    pub fn version(&self) -> u8 {
        (self.read(Register::Version) & 0xff) as u8
    }

    pub fn send_eoi(&self) {
        self.write(Register::Eoi, 0);
    }

    pub fn set_task_priority(&self, priority: u8) {
        self.write(Register::Tpr, u32::from(priority));
    }

    /// Sends a fixed-delivery IPI to one physical APIC destination.
    ///
    /// # Errors
    ///
    /// Returns an error when an xAPIC destination exceeds eight bits or when
    /// delivery does not complete before the bounded timeout.
    pub fn send_ipi(&self, destination: ApicDestination, vector: u8) -> Result<(), LocalApicError> {
        self.write_icr(destination, u32::from(vector))
    }

    /// Sends the INIT assert/deassert sequence to one APIC destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination is not addressable in the selected
    /// mode or either delivery phase times out.
    pub fn send_init(&self, destination: ApicDestination) -> Result<(), LocalApicError> {
        self.write_icr(destination, DELIVERY_INIT | LEVEL_ASSERT | TRIGGER_LEVEL)?;
        self.write_icr(destination, DELIVERY_INIT | TRIGGER_LEVEL)
    }

    /// Sends a startup IPI to one APIC destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination is not addressable in the selected
    /// mode or delivery times out.
    pub fn send_sipi(
        &self,
        destination: ApicDestination,
        vector: u8,
    ) -> Result<(), LocalApicError> {
        self.write_icr(destination, DELIVERY_STARTUP | u32::from(vector))
    }

    /// Sends a fixed-delivery IPI to every CPU except the caller.
    ///
    /// # Errors
    ///
    /// Returns an error when delivery does not complete before the bounded
    /// timeout.
    pub fn broadcast_excluding_self(&self, vector: u8) -> Result<(), LocalApicError> {
        let command = DESTINATION_ALL_EXCLUDING_SELF | u32::from(vector);
        match self.backend {
            Backend::XApic(ref backend) => backend.write_shorthand_icr(command),
            Backend::X2Apic(ref backend) => backend.write_shorthand_icr(command),
        }
    }

    pub fn calibrate_timer(&self) -> Result<(), LocalApicError> {
        let mut pit_command = PortU8::new(0x43);
        let mut pit_data = PortU8::new(0x42);
        let mut pit_gate = PortU8::new(0x61);
        let original_gate = pit_gate.read();
        pit_gate.write(original_gate | 1);
        pit_command.write(0xb0);
        let count = 11_932u16;
        pit_data.write((count & 0xff) as u8);
        pit_data.write((count >> 8) as u8);
        self.write(Register::TimerDivide, 0b0011);
        self.write(Register::TimerInitial, u32::MAX);
        if !spin_until(|| pit_gate.read() & 0x20 != 0, PIT_WAIT_SPINS) {
            pit_gate.write(original_gate & !1);
            self.write(Register::LvtTimer, 1 << 16);
            return Err(LocalApicError::TimerNotCalibrated);
        }
        let elapsed = u32::MAX - self.read(Register::TimerCurrent);
        pit_gate.write(original_gate & !1);
        self.write(Register::LvtTimer, 1 << 16);
        let ticks_per_ms = elapsed / 10;
        if ticks_per_ms == 0 {
            return Err(LocalApicError::TimerNotCalibrated);
        }
        self.ticks_per_ms
            .store(u64::from(ticks_per_ms), Ordering::Release);
        Ok(())
    }

    /// Starts the periodic local APIC timer.
    ///
    /// # Errors
    ///
    /// Returns an error when the timer is not calibrated or the requested
    /// interval cannot be represented by the hardware counter.
    pub fn start_timer(&self, vector: u8, interval_ms: u32) -> Result<(), LocalApicError> {
        let ticks_per_ms = self.ticks_per_ms.load(Ordering::Acquire);
        if ticks_per_ms == 0 {
            return Err(LocalApicError::TimerNotCalibrated);
        }
        let count = ticks_per_ms
            .checked_mul(u64::from(interval_ms))
            .and_then(|count| u32::try_from(count).ok())
            .ok_or(LocalApicError::TimerCountOverflow)?;
        self.write(Register::TimerDivide, 0b0011);
        self.write(Register::LvtTimer, (1 << 17) | u32::from(vector));
        self.write(Register::TimerInitial, count);
        Ok(())
    }

    pub fn stop_timer(&self) {
        self.write(Register::LvtTimer, 1 << 16);
        self.write(Register::TimerInitial, 0);
    }

    pub fn ticks_per_ms(&self) -> u64 {
        self.ticks_per_ms.load(Ordering::Acquire)
    }

    fn read(&self, register: Register) -> u32 {
        match self.backend {
            Backend::XApic(ref backend) => backend.read(register),
            Backend::X2Apic(ref backend) => backend.read(register),
        }
    }

    fn write(&self, register: Register, value: u32) {
        match self.backend {
            Backend::XApic(ref backend) => backend.write(register, value),
            Backend::X2Apic(ref backend) => backend.write(register, value),
        }
    }

    fn write_icr(&self, destination: ApicDestination, command: u32) -> Result<(), LocalApicError> {
        match self.backend {
            Backend::XApic(ref backend) => backend.write_icr(destination, command),
            Backend::X2Apic(ref backend) => backend.write_icr(destination, command),
        }
    }
}

fn spin_until(mut ready: impl FnMut() -> bool, max_spins: usize) -> bool {
    for _ in 0..max_spins {
        if ready() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

const fn select_mode(policy: ApicModePolicy, x2apic_supported: bool) -> ApicMode {
    match (policy, x2apic_supported) {
        (ApicModePolicy::PreferX2Apic, true) => ApicMode::X2Apic,
        (ApicModePolicy::PreferX2Apic | ApicModePolicy::XApicOnly, false)
        | (ApicModePolicy::XApicOnly, true) => ApicMode::XApic,
    }
}

unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

unsafe fn write_msr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xapic_rejects_full_width_destination_instead_of_truncating() {
        assert_eq!(
            XApic::destination_high(ApicDestination::new(0x100)),
            Err(LocalApicError::DestinationNotAddressable {
                destination: ApicDestination::new(0x100)
            })
        );
    }

    #[test]
    fn xapic_encodes_valid_destination_exactly() {
        assert_eq!(
            XApic::destination_high(ApicDestination::new(0xab)),
            Ok(0xab00_0000)
        );
    }

    #[test]
    fn firmware_opt_out_keeps_xapic_on_x2apic_capable_hardware() {
        assert_eq!(
            select_mode(ApicModePolicy::XApicOnly, true),
            ApicMode::XApic
        );
    }

    #[test]
    fn preferred_x2apic_requires_architectural_support() {
        assert_eq!(
            select_mode(ApicModePolicy::PreferX2Apic, true),
            ApicMode::X2Apic
        );
        assert_eq!(
            select_mode(ApicModePolicy::PreferX2Apic, false),
            ApicMode::XApic
        );
    }
}
