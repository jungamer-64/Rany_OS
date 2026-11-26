#![no_std]
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, Ordering};
use exorust_sync::IrqPoisonLock;

use hal::{IoPort, IoPortRange};

mod reg {
    pub const DATA: u16 = 0;
    pub const IER: u16 = 1;
    pub const IIR: u16 = 2;
    pub const FCR: u16 = 2;
    pub const LCR: u16 = 3;
    pub const MCR: u16 = 4;
    pub const LSR: u16 = 5;
    pub const SCRATCH: u16 = 7;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataBits {
    Bits5 = 0b00,
    Bits6 = 0b01,
    Bits7 = 0b10,
    Bits8 = 0b11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StopBits {
    Stop1 = 0b0 << 2,
    Stop2 = 0b1 << 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Parity {
    None = 0b000 << 3,
    Odd = 0b001 << 3,
    Even = 0b011 << 3,
    Mark = 0b101 << 3,
    Space = 0b111 << 3,
}

#[derive(Debug, Clone, Copy)]
struct LineStatus(u8);

impl LineStatus {
    const DATA_READY: u8 = 1 << 0;
    const OVERRUN_ERROR: u8 = 1 << 1;
    const PARITY_ERROR: u8 = 1 << 2;
    const FRAMING_ERROR: u8 = 1 << 3;
    const BREAK_INTERRUPT: u8 = 1 << 4;
    const TX_HOLDING_EMPTY: u8 = 1 << 5;
    const TRANSMITTER_EMPTY: u8 = 1 << 6;
    const FIFO_ERROR: u8 = 1 << 7;
    fn from_u8(val: u8) -> Self {
        Self(val)
    }
    pub fn is_data_ready(&self) -> bool {
        self.0 & Self::DATA_READY != 0
    }
    pub fn is_tx_ready(&self) -> bool {
        self.0 & Self::TX_HOLDING_EMPTY != 0
    }
}

struct InterruptEnable;
impl InterruptEnable {
    const RX_AVAILABLE: u8 = 1 << 0;
    const TX_EMPTY: u8 = 1 << 1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    Baud115200 = 1,
    Baud57600 = 2,
    Baud38400 = 3,
    Baud19200 = 6,
    Baud9600 = 12,
    Baud4800 = 24,
    Baud2400 = 48,
    Baud1200 = 96,
}

pub struct SerialPort {
    registers: SerialRegisters,
    transaction: IrqPoisonLock<()>,
    initialized: AtomicBool,
}

/// The lock protects DLAB multiplexing and each status/data transaction from
/// concurrent interrupt handlers, transmitters, and reconfiguration.
/// Polled output owned by one irrevocable fatal report.
pub struct EmergencyTransmit<'a> {
    registers: &'a SerialRegisters,
    _transaction: Option<exorust_sync::IrqPoisonLockGuard<'a, ()>>,
}

impl EmergencyTransmit<'_> {
    /// # Errors
    /// Returns a timeout when the UART fails to make progress within the budget.
    pub fn send(&self, byte: u8, spin_budget: usize) -> Result<(), SerialError> {
        self.registers.send(byte, spin_budget)
    }

    pub fn drain(&self, spin_budget: usize) -> bool {
        for _ in 0..spin_budget {
            if self.registers.line_status().0 & LineStatus::TRANSMITTER_EMPTY != 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

struct SerialRegisters {
    ports: IoPortRange,
}

impl SerialRegisters {
    fn port_at(&self, offset: u16) -> IoPort<'_, u8> {
        self.ports
            .port(offset)
            .expect("serial register offsets are contained in the UART range")
    }

    fn line_status(&self) -> LineStatus {
        LineStatus::from_u8(self.port_at(reg::LSR).read())
    }
}

impl SerialPort {
    /// Takes exclusive ownership of one UART register allocation.
    ///
    /// # Errors
    /// Returns `InvalidPortRange` unless the allocation contains exactly the
    /// eight UART port numbers. No I/O occurs on failure.
    pub const fn new(ports: IoPortRange) -> Result<Self, SerialError> {
        if ports.len() != 8 {
            return Err(SerialError::InvalidPortRange);
        }
        Ok(Self {
            registers: SerialRegisters { ports },
            transaction: IrqPoisonLock::new(()),
            initialized: AtomicBool::new(false),
        })
    }
    /// # Errors
    ///
    /// On probe failure, the external UART is configured for polled I/O and
    /// its interrupts remain masked. The probe observes receive status at
    /// most `probe_polls` times.
    pub fn init(
        &self,
        baud_rate: BaudRate,
        data_bits: DataBits,
        stop_bits: StopBits,
        parity: Parity,
        probe_polls: usize,
    ) -> Result<(), SerialError> {
        let _transaction = self
            .transaction
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let registers = &self.registers;
        if self.initialized.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut data_port = registers.port_at(reg::DATA);
        let mut ier_port = registers.port_at(reg::IER);
        let mut fcr_port = registers.port_at(reg::FCR);
        let mut lcr_port = registers.port_at(reg::LCR);
        let mut mcr_port = registers.port_at(reg::MCR);
        let mut sr_port = registers.port_at(reg::SCRATCH);
        lcr_port.write(0x03);
        ier_port.write(0x00);
        lcr_port.write(1 << 7);
        let divisor = baud_rate as u16;
        data_port.write((divisor & 0xFF) as u8);
        ier_port.write(((divisor >> 8) & 0xFF) as u8);
        lcr_port.write((data_bits as u8) | (stop_bits as u8) | (parity as u8));
        fcr_port.write(0x01 | 0x02 | 0x04 | 0xC0);
        const EXTERNAL_LINES: u8 = 0x01 | 0x02 | 0x08;
        const LOOPBACK: u8 = 0x10;
        const PROBE: u8 = 0xae;

        mcr_port.write(EXTERNAL_LINES | LOOPBACK);
        data_port.write(PROBE);
        let received = (0..probe_polls).find_map(|_| {
            if registers.line_status().is_data_ready() {
                Some(data_port.read())
            } else {
                core::hint::spin_loop();
                None
            }
        });
        // Polling callers may still use the configured external port after a
        // failed probe. Remove any probe data before reconnecting the pins.
        fcr_port.write(0x01 | 0x02 | 0x04 | 0xc0);
        mcr_port.write(EXTERNAL_LINES);
        if received != Some(PROBE) {
            return Err(SerialError::LoopbackProbe(received));
        }
        sr_port.write(0x55);
        if sr_port.read() != 0x55 {
            return Err(SerialError::ScratchProbe);
        }
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }
    /// Attempts one bounded transmit without waiting for another owner of the
    /// UART transaction lock.
    ///
    /// # Errors
    ///
    /// Returns [`SerialError::Busy`] if another CPU or the interrupt handler is
    /// using the UART, or [`SerialError::TransmitTimeout`] when the device does
    /// not become ready within `spin_budget` observations.
    pub fn try_send(&self, byte: u8, spin_budget: usize) -> Result<(), SerialError> {
        let Some(lock_result) = self.transaction.try_lock() else {
            return Err(SerialError::Busy);
        };
        let _transaction = lock_result.unwrap_or_else(|error| error.into_inner());
        self.registers.send(byte, spin_budget)
    }
}

impl SerialRegisters {
    fn send(&self, byte: u8, spin_budget: usize) -> Result<(), SerialError> {
        for _ in 0..spin_budget {
            if self.line_status().is_tx_ready() {
                self.port_at(reg::DATA).write(byte);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        if self.line_status().is_tx_ready() {
            self.port_at(reg::DATA).write(byte);
            Ok(())
        } else {
            Err(SerialError::TransmitTimeout)
        }
    }
}

impl SerialPort {
    /// # Errors
    ///
    /// Returns `ReceiveUnavailable` if the admission check under the UART
    /// lock fails and `NoData` if no byte is ready.
    pub fn try_receive(&self, can_receive: impl FnOnce() -> bool) -> Result<u8, SerialError> {
        let _transaction = self
            .transaction
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !can_receive() {
            return Err(SerialError::ReceiveUnavailable);
        }
        let registers = &self.registers;
        if registers.line_status().is_data_ready() {
            Ok(registers.port_at(reg::DATA).read())
        } else {
            Err(SerialError::NoData)
        }
    }
    /// Checks whether both the transmit FIFO and shift register are empty.
    ///
    /// Returns false if a concurrent UART transaction prevents the observation.
    pub fn transmitter_idle(&self) -> bool {
        self.transaction.try_lock().is_some_and(|lock_result| {
            let _transaction = lock_result.unwrap_or_else(|error| error.into_inner());
            self.registers.line_status().0 & LineStatus::TRANSMITTER_EMPTY != 0
        })
    }

    /// Selects a UART interrupt mask under the register lock. The caller can
    /// validate or transfer transport ownership before publishing the mask.
    /// Returning `None` leaves the mask unchanged and reports no update.
    pub fn update_interrupt_mode(
        &self,
        select: impl FnOnce() -> Option<SerialInterruptMode>,
    ) -> bool {
        let _transaction = self
            .transaction
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(mode) = select() else {
            return false;
        };
        self.registers
            .port_at(reg::IER)
            .write(mode.register_value());
        true
    }

    /// Takes over a terminal UART even if a stopped context owned its lock.
    ///
    /// The hardware handoff requires the caller to have stopped the normal
    /// UART users permanently, including any context interrupted inside a
    /// register transaction.
    pub fn take_emergency(&self) -> EmergencyTransmit<'_> {
        self.emergency(None)
    }

    /// Attempts emergency output while peers are still potentially active.
    pub fn try_emergency(&self) -> Option<EmergencyTransmit<'_>> {
        let guard = self
            .transaction
            .try_lock()?
            .unwrap_or_else(|error| error.into_inner());
        Some(self.emergency(Some(guard)))
    }

    fn emergency<'a>(
        &'a self,
        guard: Option<exorust_sync::IrqPoisonLockGuard<'a, ()>>,
    ) -> EmergencyTransmit<'a> {
        let registers = &self.registers;
        let mut lcr = registers.port_at(reg::LCR);
        let mut ier = registers.port_at(reg::IER);
        // Recovery may begin in divisor-latch mode or during the loopback test.
        lcr.write(0x03);
        ier.write(0);
        lcr.write(0x83);
        registers
            .port_at(reg::DATA)
            .write(BaudRate::Baud115200 as u8);
        ier.write(0);
        lcr.write(0x03);
        registers.port_at(reg::MCR).write(0x0b);
        registers.port_at(reg::FCR).write(0x01);
        EmergencyTransmit {
            registers,
            _transaction: guard,
        }
    }

    /// Services UART interrupt causes while holding the sole register
    /// transaction lock. Received bytes and pending transmit bytes cross the
    /// driver boundary only through the supplied callbacks.
    pub fn service_interrupt(
        &self,
        budget: SerialInterruptBudget,
        mut receive: impl FnMut(u8) -> bool,
        mut next_transmit: impl FnMut() -> Option<u8>,
    ) -> SerialInterruptReport {
        let _transaction = self
            .transaction
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let registers = &self.registers;
        let mut report = SerialInterruptReport::default();
        let mut causes = 0usize;

        // LOOP_PROOF: mode=bounded; reason=Each handled cause increments the counter and an empty interrupt status ends this admitted ISR budget.;
        while causes < budget.causes {
            // Reading a TX-empty IIR acknowledges that cause. A frame still
            // waiting after the TX budget must retain its next notification.
            if report.transmitted_bytes == budget.transmitted_bytes {
                break;
            }
            let interrupt_id = registers.port_at(reg::IIR).read();
            if (interrupt_id & 1) != 0 {
                break;
            }
            causes += 1;

            match interrupt_id & 0x0e {
                0x02 => {
                    // LOOP_PROOF: mode=bounded; reason=Each write consumes one byte of the admitted transmit budget and an empty source or nonready UART ends the batch.;
                    while report.transmitted_bytes < budget.transmitted_bytes
                        && registers.line_status().is_tx_ready()
                    {
                        let Some(byte) = next_transmit() else {
                            registers
                                .port_at(reg::IER)
                                .write(SerialInterruptMode::Receive.register_value());
                            break;
                        };
                        registers.port_at(reg::DATA).write(byte);
                        report.transmitted_bytes += 1;
                    }
                }
                0x04 | 0x0c => {
                    // LOOP_PROOF: mode=bounded; reason=Every UART read increments delivered or dropped bytes toward the admitted receive budget and empty hardware ends the batch.;
                    while report.received_bytes + report.dropped_bytes < budget.received_bytes {
                        let status = registers.line_status();
                        if !status.is_data_ready() {
                            break;
                        }
                        let byte = registers.port_at(reg::DATA).read();
                        if receive(byte) {
                            report.received_bytes += 1;
                        } else {
                            report.dropped_bytes += 1;
                        }
                    }
                }
                0x06 => {
                    let status = registers.line_status();
                    if status.0
                        & (LineStatus::OVERRUN_ERROR
                            | LineStatus::PARITY_ERROR
                            | LineStatus::FRAMING_ERROR
                            | LineStatus::BREAK_INTERRUPT
                            | LineStatus::FIFO_ERROR)
                        != 0
                    {
                        report.line_errors += 1;
                    }
                }
                _ => break,
            }
        }

        report.budget_exhausted = causes == budget.causes
            || report.received_bytes + report.dropped_bytes == budget.received_bytes
            || report.transmitted_bytes == budget.transmitted_bytes;
        report
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialError {
    InvalidPortRange,
    InvalidInterruptBudget,
    LoopbackProbe(Option<u8>),
    ScratchProbe,
    NoData,
    ReceiveUnavailable,
    Busy,
    TransmitTimeout,
}

/// Interrupt sources enabled at the UART.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialInterruptMode {
    Disabled,
    Receive,
    ReceiveAndTransmit,
}

impl SerialInterruptMode {
    const fn register_value(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::Receive => InterruptEnable::RX_AVAILABLE,
            Self::ReceiveAndTransmit => InterruptEnable::RX_AVAILABLE | InterruptEnable::TX_EMPTY,
        }
    }
}

/// Finite work admitted to one interrupt service pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SerialInterruptBudget {
    causes: usize,
    received_bytes: usize,
    transmitted_bytes: usize,
}

impl SerialInterruptBudget {
    /// Creates a non-empty budget for each independently bounded operation.
    ///
    /// # Errors
    ///
    /// Returns [`SerialError::InvalidInterruptBudget`] when any limit is zero.
    pub const fn new(
        causes: usize,
        received_bytes: usize,
        transmitted_bytes: usize,
    ) -> Result<Self, SerialError> {
        if causes == 0 || received_bytes == 0 || transmitted_bytes == 0 {
            return Err(SerialError::InvalidInterruptBudget);
        }
        Ok(Self {
            causes,
            received_bytes,
            transmitted_bytes,
        })
    }
}

/// Observable progress made by one bounded interrupt service pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SerialInterruptReport {
    /// Bytes accepted by the receive callback.
    pub received_bytes: usize,
    /// Bytes consumed from hardware but rejected by the receive callback.
    pub dropped_bytes: usize,
    /// Bytes obtained from the transmit callback and published to hardware.
    pub transmitted_bytes: usize,
    /// Line-status causes that reported one or more receive errors.
    pub line_errors: usize,
    /// At least one finite work dimension was fully consumed.
    pub budget_exhausted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupt_budget_rejects_unbounded_dimensions() {
        assert_eq!(
            SerialInterruptBudget::new(0, 1, 1),
            Err(SerialError::InvalidInterruptBudget)
        );
        assert_eq!(
            SerialInterruptBudget::new(1, 0, 1),
            Err(SerialError::InvalidInterruptBudget)
        );
        assert_eq!(
            SerialInterruptBudget::new(1, 1, 0),
            Err(SerialError::InvalidInterruptBudget)
        );
        assert!(SerialInterruptBudget::new(8, 64, 64).is_ok());
    }
}
