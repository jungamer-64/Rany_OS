#![no_std]

mod ioapic;
mod local;

pub use ioapic::{
    IoApic, IoApicDescriptor, IoApicDestination, IoApicError, IoApicSet, Polarity,
    RedirectionEntry, TriggerMode, initialize_io_apics, io_apics,
};
pub use local::{ApicDestination, ApicMode, LocalApic, LocalApicError, X2Apic, XApic};

use spin::Once;

static LOCAL_APIC: Once<Result<LocalApic, LocalApicError>> = Once::new();

/// Returns the typed local APIC backend selected from architectural feature
/// bits and the APIC-base MSR.
///
/// # Errors
///
/// Returns an error when the current platform lacks APIC support or exposes an
/// invalid xAPIC MMIO base.
pub fn local_apic() -> Result<&'static LocalApic, LocalApicError> {
    match LOCAL_APIC.call_once(LocalApic::detect) {
        Ok(apic) => Ok(apic),
        Err(error) => Err(*error),
    }
}

/// Initializes the selected local APIC backend on the executing CPU.
///
/// # Errors
///
/// Returns a typed backend error when detection or per-CPU initialization
/// fails.
pub fn initialize_current_cpu() -> Result<&'static LocalApic, LocalApicError> {
    let apic = local_apic()?;
    apic.initialize_current_cpu()?;
    Ok(apic)
}

pub fn is_apic_enabled() -> bool {
    local_apic().is_ok_and(LocalApic::is_enabled)
}

pub fn check_apic_support() -> bool {
    let features = core::arch::x86_64::__cpuid(1);
    features.edx & (1 << 9) != 0
}

/// Starts the periodic APIC timer on the supplied interrupt vector.
///
/// # Errors
///
/// Returns an error when the local APIC is unavailable, uncalibrated, or the
/// requested interval overflows the hardware counter.
pub fn start_apic_timer_on_vector(vector: u8, interval_ms: u32) -> Result<(), LocalApicError> {
    local_apic()?.start_timer(vector, interval_ms)
}

/// Starts the periodic APIC timer on the legacy timer vector.
///
/// # Errors
///
/// Returns the same errors as [`start_apic_timer_on_vector`].
pub fn start_apic_timer(interval_ms: u32) -> Result<(), LocalApicError> {
    start_apic_timer_on_vector(0x20, interval_ms)
}

/// Signals end-of-interrupt on the current CPU.
///
/// # Errors
///
/// Returns an error when the local APIC backend is unavailable.
pub fn end_of_interrupt() -> Result<(), LocalApicError> {
    local_apic()?.send_eoi();
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApicStats {
    pub mode: ApicMode,
    pub local_apic_id: u32,
    pub local_apic_version: u8,
    pub io_apic_count: usize,
    pub ticks_per_ms: u64,
}

/// Returns the current APIC topology and timer counters.
///
/// # Errors
///
/// Returns an error when the local APIC backend is unavailable.
pub fn get_stats() -> Result<ApicStats, LocalApicError> {
    let local = local_apic()?;
    let io_apic_count = io_apics()
        .map(|topology| topology.controllers().len())
        .unwrap_or(0);
    Ok(ApicStats {
        mode: local.mode(),
        local_apic_id: local.id(),
        local_apic_version: local.version(),
        io_apic_count,
        ticks_per_ms: local.ticks_per_ms(),
    })
}
