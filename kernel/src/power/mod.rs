//! Power commands are owned and executed by the ACPI firmware service.
//! Returning hardware commands remain incomplete, retaining their failure and
//! register owners. A queued request is never reported as physical power-off.

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PowerCommand {
    Shutdown,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Unavailable,
    Working,
    ShutdownRequested,
    ResetRequested,
    ShutdownFailed,
    ResetFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PowerRequestError {
    Unavailable,
    Busy,
    Unsupported,
}

/// Failure before a power command or an unconfirmed hardware publication.
/// Preparation may execute AML methods, so failure never implies their rollback.
/// Published commands retain their owners and cannot be automatically retried.
#[derive(Debug, Clone)]
pub enum PowerFailure {
    Preparation(crate::cpu::FirmwareError),
    Published { cause: crate::cpu::FirmwareError },
}

#[derive(Debug, Clone)]
pub struct PowerSnapshot {
    pub state: PowerState,
    pub power_button_presses: u64,
    pub sleep_button_presses: u64,
    pub idle_entries: u64,
    pub failure: Option<PowerFailure>,
    pub worker_task: Option<crate::task::TaskId>,
    pub worker_failure: Option<crate::cpu::FirmwareError>,
}

pub(crate) struct PowerEvents {
    power_button_presses: AtomicU64,
    sleep_button_presses: AtomicU64,
}
impl PowerEvents {
    pub(crate) const fn new() -> Self {
        Self {
            power_button_presses: AtomicU64::new(0),
            sleep_button_presses: AtomicU64::new(0),
        }
    }
    pub(crate) fn capture(&self, status: u16) {
        if status & (1 << 8) != 0 {
            self.power_button_presses.fetch_add(1, Ordering::Relaxed);
        }
        if status & (1 << 9) != 0 {
            self.sleep_button_presses.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn counts(&self) -> (u64, u64) {
        (
            self.power_button_presses.load(Ordering::Relaxed),
            self.sleep_button_presses.load(Ordering::Relaxed),
        )
    }
}

pub fn snapshot() -> PowerSnapshot {
    let mut snapshot = crate::platform::acpi_hotplug::power_snapshot();
    snapshot.idle_entries = crate::task::idle_entries();
    snapshot
}

pub fn shutdown() -> ! {
    terminal_request(PowerCommand::Shutdown)
}
pub fn reboot() -> ! {
    terminal_request(PowerCommand::Reset)
}

fn terminal_request(command: PowerCommand) -> ! {
    if let Err(error) = crate::platform::acpi_hotplug::request_power(command) {
        log::error!("system power request was rejected: {command:?}: {error:?}");
    }
    // LOOP_PROOF: mode=halt; reason=This terminal task waits for its separately owned firmware command, APIC timer interrupts can preempt the executing stack.;
    loop {
        core::hint::spin_loop();
    }
}
