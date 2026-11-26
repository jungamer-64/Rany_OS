//! Kernel-owned COM1 device and its runtime transport channels.

mod tx;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use hal::IoPortRange;
use serial_driver::{
    BaudRate, DataBits, Parity, SerialError, SerialInterruptBudget, SerialInterruptMode,
    SerialPort, StopBits,
};

use super::byte_queue::RingBuffer;
use crate::sync::IrqPoisonLock;

const TRANSMIT_POLLS: usize = 100_000;
const INTERRUPT_BUDGET: SerialInterruptBudget = match SerialInterruptBudget::new(16, 256, 64) {
    Ok(budget) => budget,
    Err(_) => panic!("COM1 interrupt budget must be nonzero"),
};

static PORT: SerialPort = {
    // SAFETY: The kernel assigns COM1 exclusively to this owner for runtime.
    // Firmware and the assembly entry use the registers before runtime admission.
    let ports = match unsafe { IoPortRange::from_raw_parts(0x3f8, 8) } {
        Ok(ports) => ports,
        Err(_) => panic!("COM1 register range is invalid"),
    };
    match SerialPort::new(ports) {
        Ok(port) => port,
        Err(_) => panic!("COM1 requires eight I/O ports"),
    }
};

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static INTERRUPTS_ROUTED: AtomicBool = AtomicBool::new(false);
static INPUT: IrqPoisonLock<RingBuffer<1024>> = IrqPoisonLock::new(RingBuffer::new());
static TRANSMIT: IrqPoisonLock<tx::TransmitQueues> = IrqPoisonLock::new(tx::TransmitQueues::new());
static DIRECT_OUTPUT: crate::sync::PoisonLock<()> = crate::sync::PoisonLock::new(());

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum Session {
    Console = 0,
    Debugger = 1,
    Panic = 2,
}

impl Session {
    fn load() -> Self {
        match SESSION.load(Ordering::Acquire) {
            value if value == Self::Console as u8 => Self::Console,
            value if value == Self::Debugger as u8 => Self::Debugger,
            value if value == Self::Panic as u8 => Self::Panic,
            _ => unreachable!("COM1 session is assigned from Session"),
        }
    }
}

static SESSION: AtomicU8 = AtomicU8::new(Session::Console as u8);

#[derive(Clone, Copy)]
pub(super) enum Channel {
    Log,
    Console,
    Debugger,
}

impl Channel {
    fn allowed(self) -> bool {
        self.allowed_in(Session::load())
    }

    fn allowed_in(self, session: Session) -> bool {
        match self {
            Self::Log | Self::Console => session == Session::Console,
            Self::Debugger => session == Session::Debugger,
        }
    }
}

pub(crate) fn init() -> Result<(), SerialError> {
    PORT.init(
        BaudRate::Baud115200,
        DataBits::Bits8,
        StopBits::Stop1,
        Parity::None,
    )?;
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

pub(crate) fn start_interrupts() -> Result<(), crate::interrupts::Com1RouteError> {
    if interrupts_routed() {
        return Ok(());
    }
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(crate::interrupts::Com1RouteError::UartUnavailable);
    }
    crate::interrupts::route_com1()?;
    PORT.set_interrupt_mode(SerialInterruptMode::Receive);
    INTERRUPTS_ROUTED.store(true, Ordering::Release);
    Ok(())
}

pub(super) fn interrupts_routed() -> bool {
    INTERRUPTS_ROUTED.load(Ordering::Acquire)
}

pub(crate) fn handle_interrupt() {
    PORT.service_interrupt(
        INTERRUPT_BUDGET,
        |byte| {
            INPUT
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(&[byte])
        },
        || {
            if !log_channel_available() {
                return None;
            }
            TRANSMIT
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .next_byte()
        },
    );
}

#[cfg(feature = "bench")]
pub(super) fn pending_log_bytes() -> usize {
    TRANSMIT
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .log
        .pending()
}

#[cfg(feature = "bench")]
pub(super) fn bench_clear() {
    TRANSMIT
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

#[cfg(feature = "bench")]
pub(super) fn bench_push_log(bytes: &[u8]) -> bool {
    TRANSMIT
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .log
        .push(bytes)
}

#[cfg(feature = "bench")]
pub(super) fn bench_pop_logs(dst: &mut [u8]) -> usize {
    let mut queue = TRANSMIT.lock().unwrap_or_else(|error| error.into_inner());
    let n = dst.len().min(queue.log.pending());
    for byte in &mut dst[..n] {
        *byte = queue.log.pop().expect("checked the pending log bytes");
    }
    n
}

pub(crate) fn reserve_for_debugger() {
    if SESSION
        .compare_exchange(
            Session::Console as u8,
            Session::Debugger as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        TRANSMIT
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        if interrupts_routed() {
            PORT.set_interrupt_mode(SerialInterruptMode::Receive);
        }
    }
}

pub(super) fn log_channel_available() -> bool {
    Channel::Log.allowed()
}

pub(super) fn in_panic() -> bool {
    Session::load() == Session::Panic
}

#[cfg(target_os = "none")]
pub(crate) fn suppress_runtime_serial() {
    SESSION.store(Session::Panic as u8, Ordering::Release);
}

#[cfg(target_os = "none")]
pub(crate) struct FatalSerial {
    port: serial_driver::EmergencyTransmit<'static>,
    last_was_cr: bool,
    failed: bool,
}

#[cfg(target_os = "none")]
impl FatalSerial {
    /// Bypasses retained register locks after the peers have stopped.
    pub(crate) fn take_quiesced(_: crate::panic_handler::QuiescedPeers) -> Self {
        Self::new(PORT.take_emergency())
    }

    pub(crate) fn try_open() -> Option<Self> {
        PORT.try_emergency().map(Self::new)
    }

    fn new(port: serial_driver::EmergencyTransmit<'static>) -> Self {
        Self {
            port,
            last_was_cr: false,
            failed: false,
        }
    }

    pub(crate) fn finish(&self) {
        // Terminal best effort. A failed UART has no retry owner.
        let _drained = self.port.drain(TRANSMIT_POLLS);
    }
}

#[cfg(target_os = "none")]
impl core::fmt::Write for FatalSerial {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        if self.failed {
            return Err(core::fmt::Error);
        }
        for byte in text.bytes() {
            if (byte == b'\n'
                && !self.last_was_cr
                && self.port.send(b'\r', TRANSMIT_POLLS).is_err())
                || self.port.send(byte, TRANSMIT_POLLS).is_err()
            {
                self.failed = true;
                return Err(core::fmt::Error);
            }
            self.last_was_cr = byte == b'\r';
        }
        Ok(())
    }
}

/// Returns the prefix accepted by the queue or handed to the polled UART.
pub(super) fn write(channel: Channel, bytes: &[u8]) -> usize {
    #[cfg(all(test, any(feature = "std", target_os = "linux")))]
    {
        if channel.allowed() {
            return std::io::Write::write(&mut std::io::stderr(), bytes).unwrap_or(0);
        }
        return 0;
    }
    #[cfg(not(all(test, any(feature = "std", target_os = "linux"))))]
    {
        if !channel.allowed() {
            return 0;
        }
        if interrupts_routed() && matches!(channel, Channel::Log | Channel::Console) {
            let admitted = {
                let mut queue = match channel {
                    Channel::Log => {
                        let Ok(queue) = TRANSMIT.try_lock() else {
                            return 0;
                        };
                        queue
                    }
                    _ => TRANSMIT.lock().unwrap_or_else(|error| error.into_inner()),
                };
                channel.allowed()
                    && match channel {
                        Channel::Log => queue.log.push(bytes),
                        _ => queue.console.push(bytes),
                    }
            };
            if admitted && channel.allowed() {
                PORT.set_interrupt_mode(SerialInterruptMode::ReceiveAndTransmit);
            }
            return if admitted { bytes.len() } else { 0 };
        }
        let Ok(_direct) = DIRECT_OUTPUT.try_lock() else {
            return 0;
        };
        bytes
            .iter()
            .take_while(|&&byte| channel.allowed() && PORT.try_send(byte, TRANSMIT_POLLS).is_ok())
            .count()
    }
}

fn read(channel: Channel) -> Option<u8> {
    if !channel.allowed() {
        return None;
    }
    let queued = INPUT
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .pop();
    queued.or_else(|| PORT.try_receive().ok())
}

/// Best-effort drain before a terminal test runner shuts down the virtual UART.
pub(crate) async fn drain_for_shutdown() -> bool {
    if !Channel::Console.allowed() {
        return true;
    }

    let started = crate::time::best_effort_time_nanos();
    let budget = 2 * crate::time::NANOS_PER_SEC;
    // LOOP_PROOF: mode=bounded; reason=The runtime shutdown drain stops at the time or attempt limit even if the UART or diagnostic clock stops.;
    for _ in 0..65_536 {
        let pending = {
            let queues = TRANSMIT.lock().unwrap_or_else(|error| error.into_inner());
            queues.log.pending() != 0 || queues.console.pending() != 0
        };
        if !pending && PORT.transmitter_idle() {
            return true;
        }
        if crate::time::best_effort_time_nanos().saturating_sub(started) >= budget {
            break;
        }
        crate::task::yield_now().await;
    }
    false
}

pub(crate) fn write_console(bytes: &[u8]) -> usize {
    write(Channel::Console, bytes)
}

pub(crate) fn console_available() -> bool {
    Channel::Console.allowed()
}

pub(crate) fn write_debugger(bytes: &[u8]) {
    let _ = write(Channel::Debugger, bytes);
}

pub(crate) fn read_debugger() -> Option<u8> {
    read(Channel::Debugger)
}

/// Read one byte from COM1 for interactive shell input.
///
/// Uses polling fallback so serial shell stays usable even when COM1 IRQ
/// delivery is unavailable in specific QEMU/host configurations.
pub async fn read_byte_for_shell() -> u8 {
    let mut use_timer = true;
    // LOOP_PROOF: mode=event; reason=Receiving a byte returns to the shell, and an empty receive awaits a timer or scheduler yield before retrying.;
    loop {
        if let Some(byte) = read(Channel::Console) {
            return byte;
        }

        if use_timer && crate::interrupts::are_interrupts_enabled() {
            if let Err(cause) = crate::task::sleep_ms(1).await {
                log::warn!("serial timer unavailable, continuing scheduled polling: {cause}");
                use_timer = false;
                crate::task::yield_now().await;
            }
        } else {
            crate::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Channel, Session};

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn exclusive_debugger_and_terminal_diagnostics_have_distinct_transmit_authority() {
        assert!(Channel::Debugger.allowed_in(Session::Debugger));
        assert!(!Channel::Console.allowed_in(Session::Debugger));
        assert!(!Channel::Log.allowed_in(Session::Debugger));
        assert!(!Channel::Console.allowed_in(Session::Panic));
        assert!(!Channel::Log.allowed_in(Session::Panic));
        assert!(!Channel::Debugger.allowed_in(Session::Panic));
    }
}
