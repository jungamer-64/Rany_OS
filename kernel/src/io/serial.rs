// ============================================================================
// src/io/serial.rs - Serial Port Driver (UART 16550)
// Debug output and console I/O
// ============================================================================
//!
//! # Serial Port Driver
//!
//! UART 16550 compatible serial port driver.
//! Used for debug output in QEMU and other emulators.
//!
//! ## Features
//! - Async send/receive
//! - Multiple baud rates
//! - FIFO buffer
//! - Interrupt or polling mode
//! - Type-safe register operations

#![allow(dead_code)]

use core::fmt::{self, Write};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;
use x86_64::instructions::port::Port;

// ============================================================================
// Serial port constants and type definitions
// ============================================================================

/// COM port base addresses
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum ComPort {
    Com1 = 0x3F8,
    Com2 = 0x2F8,
    Com3 = 0x3E8,
    Com4 = 0x2E8,
}

/// Register offsets (DLAB=0/1 share same offsets for different registers)
mod reg {
    pub const DATA: u16 = 0;    // R/W: Data Register (DLAB=0)
    pub const DLL: u16 = 0;     // W:   Divisor Latch Low (DLAB=1)
    pub const DLH: u16 = 1;     // W:   Divisor Latch High (DLAB=1)
    pub const IER: u16 = 1;     // R/W: Interrupt Enable Register (DLAB=0)
    pub const FCR: u16 = 2;     // W:   FIFO Control Register
    pub const LCR: u16 = 3;     // R/W: Line Control Register
    pub const MCR: u16 = 4;     // R/W: Modem Control Register
    pub const LSR: u16 = 5;     // R:   Line Status Register
    pub const SCRATCH: u16 = 7; // R/W: Scratch Register
}

/// Data bit length
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataBits {
    Bits5 = 0b00,
    Bits6 = 0b01,
    Bits7 = 0b10,
    Bits8 = 0b11,
}

/// Stop bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StopBits {
    Stop1 = 0b0 << 2,
    Stop2 = 0b1 << 2,
}

/// Parity settings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Parity {
    None  = 0b000 << 3,
    Odd   = 0b001 << 3,
    Even  = 0b011 << 3,
    Mark  = 0b101 << 3,
    Space = 0b111 << 3,
}

/// Line status flags (LSR)
#[derive(Debug, Clone, Copy)]
pub struct LineStatus(u8);

impl LineStatus {
    pub const DATA_READY: u8       = 1 << 0;
    pub const OVERRUN_ERROR: u8    = 1 << 1;
    pub const PARITY_ERROR: u8     = 1 << 2;
    pub const FRAMING_ERROR: u8    = 1 << 3;
    pub const BREAK_INTERRUPT: u8  = 1 << 4;
    pub const TX_HOLDING_EMPTY: u8 = 1 << 5;
    pub const TX_EMPTY: u8         = 1 << 6;
    pub const FIFO_ERROR: u8       = 1 << 7;

    pub fn from_u8(val: u8) -> Self { Self(val) }
    pub fn is_data_ready(&self) -> bool { self.0 & Self::DATA_READY != 0 }
    pub fn is_tx_ready(&self) -> bool { self.0 & Self::TX_HOLDING_EMPTY != 0 }
}

/// Interrupt enable flags (IER)
#[derive(Debug, Clone, Copy)]
pub struct InterruptEnable(u8);

impl InterruptEnable {
    pub const RX_AVAILABLE: u8 = 1 << 0;
    pub const TX_EMPTY: u8     = 1 << 1;
    pub const LINE_STATUS: u8  = 1 << 2;
    pub const MODEM_STATUS: u8 = 1 << 3;
}

/// Baud rate (divisor values for 115200 base)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    Baud115200 = 1,
    Baud57600  = 2,
    Baud38400  = 3,
    Baud19200  = 6,
    Baud9600   = 12,
    Baud4800   = 24,
    Baud2400   = 48,
    Baud1200   = 96,
}

// ============================================================================
// Serial port driver
// ============================================================================

/// Serial port driver
pub struct SerialPort {
    base: u16,
    initialized: AtomicBool,
}

impl SerialPort {
    /// Create a new serial port
    pub const fn new(port: ComPort) -> Self {
        Self {
            base: port as u16,
            initialized: AtomicBool::new(false),
        }
    }

    /// Port access helper
    /// Safety: Race conditions must be managed by caller, but Port itself is stateless
    unsafe fn port_at<T>(&self, offset: u16) -> Port<T> {
        Port::new(self.base + offset)
    }

    /// Initialize the serial port
    pub fn init(
        &self,
        baud_rate: BaudRate,
        data_bits: DataBits,
        stop_bits: StopBits,
        parity: Parity
    ) -> Result<(), SerialError> {
        unsafe {
            let mut data_port: Port<u8> = self.port_at(reg::DATA);
            let mut ier_port: Port<u8>  = self.port_at(reg::IER);
            let mut fcr_port: Port<u8>  = self.port_at(reg::FCR);
            let mut lcr_port: Port<u8>  = self.port_at(reg::LCR);
            let mut mcr_port: Port<u8>  = self.port_at(reg::MCR);
            let mut sr_port: Port<u8>   = self.port_at(reg::SCRATCH);

            // Disable interrupts
            ier_port.write(0x00);

            // Set DLAB bit to enable baud rate setting
            const DLAB: u8 = 1 << 7;
            lcr_port.write(DLAB);

            // Set baud rate
            let divisor = baud_rate as u16;
            data_port.write((divisor & 0xFF) as u8); // DLL
            ier_port.write(((divisor >> 8) & 0xFF) as u8); // DLH

            // Line configuration (clear DLAB while setting)
            let lcr_val = (data_bits as u8) | (stop_bits as u8) | (parity as u8);
            lcr_port.write(lcr_val);

            // FIFO configuration: enable, clear RX/TX, 14-byte trigger
            // Bit definitions: ENABLE(1) | RX_CLEAR(2) | TX_CLEAR(4) | TRIGGER_14(0xC0)
            fcr_port.write(0x01 | 0x02 | 0x04 | 0xC0);

            // Modem control: DTR(1) | RTS(2) | OUT2(8, interrupt gate)
            mcr_port.write(0x01 | 0x02 | 0x08);

            // Loopback test
            // LOOPBACK(0x10) | DTR | RTS | OUT2
            mcr_port.write(0x10 | 0x01 | 0x02 | 0x08);
            
            data_port.write(0xAE);
            if data_port.read() != 0xAE {
                return Err(SerialError::InitFailed);
            }

            // Return to normal mode
            mcr_port.write(0x01 | 0x02 | 0x08);
            
            // Scratch register test
            sr_port.write(0x55);
            if sr_port.read() != 0x55 {
                return Err(SerialError::InitFailed);
            }

            self.initialized.store(true, Ordering::SeqCst);
        }

        Ok(())
    }

    /// Get line status
    pub fn line_status(&self) -> LineStatus {
        unsafe {
            let mut lsr_port: Port<u8> = self.port_at(reg::LSR);
            LineStatus::from_u8(lsr_port.read())
        }
    }

    /// Check if ready to transmit
    pub fn can_transmit(&self) -> bool {
        self.line_status().is_tx_ready()
    }

    /// Check if data is available
    pub fn can_receive(&self) -> bool {
        self.line_status().is_data_ready()
    }

    /// Send a byte (blocking)
    pub fn send(&self, byte: u8) {
        while !self.can_transmit() {
            core::hint::spin_loop();
        }

        unsafe {
            let mut data_port: Port<u8> = self.port_at(reg::DATA);
            data_port.write(byte);
        }
    }

    /// Send a string
    pub fn send_str(&self, s: &str) {
        for byte in s.bytes() {
            self.send(byte);
        }
    }

    /// Receive a byte (non-blocking)
    pub fn try_receive(&self) -> Result<u8, SerialError> {
        if self.can_receive() {
            unsafe {
                let mut data_port: Port<u8> = self.port_at(reg::DATA);
                Ok(data_port.read())
            }
        } else {
            Err(SerialError::NoData)
        }
    }

    /// Interrupt control
    pub fn set_interrupts(&self, rx: bool, tx: bool) {
        let mut flags = 0u8;
        if rx { flags |= InterruptEnable::RX_AVAILABLE; }
        if tx { flags |= InterruptEnable::TX_EMPTY; }

        unsafe {
            let mut ier_port: Port<u8> = self.port_at(reg::IER);
            ier_port.write(flags);
        }
    }
}

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialError {
    InitFailed,
    BufferFull,
    NoData,
    FramingError,
    ParityError,
    OverrunError,
}

// ============================================================================
// Async serial port
// ============================================================================

const RX_BUFFER_SIZE: usize = 256;

/// Receive buffer (simple lock-free SPSC ring buffer)
struct RxBuffer {
    buffer: [AtomicU8; RX_BUFFER_SIZE],
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl RxBuffer {
    const fn new() -> Self {
        const ZERO: AtomicU8 = AtomicU8::new(0);
        Self {
            buffer: [ZERO; RX_BUFFER_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn push(&self, byte: u8) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % RX_BUFFER_SIZE;

        if next_tail == self.head.load(Ordering::Acquire) {
            return false; // Full
        }

        self.buffer[tail].store(byte, Ordering::Relaxed);
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    fn pop(&self) -> Option<u8> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None; // Empty
        }

        let byte = self.buffer[head].load(Ordering::Relaxed);
        self.head.store((head + 1) % RX_BUFFER_SIZE, Ordering::Release);
        Some(byte)
    }
}

/// Async wrapper
pub struct AsyncSerialPort {
    port: SerialPort,
    rx_buffer: RxBuffer,
    waker: Mutex<Option<Waker>>,
}

impl AsyncSerialPort {
    pub const fn new(port: ComPort) -> Self {
        Self {
            port: SerialPort::new(port),
            rx_buffer: RxBuffer::new(),
            waker: Mutex::new(None),
        }
    }

    pub fn init(&self, baud_rate: BaudRate) -> Result<(), SerialError> {
        // Standard configuration: 8N1
        self.port.init(baud_rate, DataBits::Bits8, StopBits::Stop1, Parity::None)
    }

    pub fn handle_interrupt(&self) {
        // ISR context - keep locks minimal.
        // Buffer push is lock-free.
        while let Ok(byte) = self.port.try_receive() {
            self.rx_buffer.push(byte);
        }
        // Notify waiting task
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    pub fn send_str(&self, s: &str) {
        self.port.send_str(s);
    }
    
    pub fn read_byte(&self) -> SerialReadFuture<'_> {
        SerialReadFuture { port: self }
    }
}

pub struct SerialReadFuture<'a> {
    port: &'a AsyncSerialPort,
}

impl<'a> Future for SerialReadFuture<'a> {
    type Output = u8;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 1. Check buffer first
        if let Some(byte) = self.port.rx_buffer.pop() {
            return Poll::Ready(byte);
        }
        // 2. Direct port check (fallback)
        if let Ok(byte) = self.port.port.try_receive() {
            return Poll::Ready(byte);
        }

        // 3. Register waker
        *self.port.waker.lock() = Some(cx.waker().clone());

        // 4. Re-check to prevent race condition after waker registration
        if let Some(byte) = self.port.rx_buffer.pop() {
            return Poll::Ready(byte);
        }

        Poll::Pending
    }
}

// ============================================================================
// Async read line (for shell integration)
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;

/// Input event returned from advanced line reading
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputEvent {
    /// Line submitted (Enter pressed)
    Line(String),
    /// Arrow key pressed
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    /// Home key
    Home,
    /// End key
    End,
    /// Tab key pressed
    Tab,
    /// Ctrl+C (interrupt)
    Interrupt,
    /// Ctrl+D (EOF)
    Eof,
    /// Delete key
    Delete,
}

/// Advanced line editor state
pub struct LineEditor {
    buffer: Vec<u8>,
    cursor_pos: usize,
}

impl LineEditor {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(256),
            cursor_pos: 0,
        }
    }

    /// Get current buffer content as string
    pub fn content(&self) -> String {
        String::from_utf8_lossy(&self.buffer).into_owned()
    }

    /// Set buffer content (for history navigation)
    pub fn set_content(&mut self, s: &str) {
        self.buffer.clear();
        self.buffer.extend_from_slice(s.as_bytes());
        self.cursor_pos = self.buffer.len();
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor_pos = 0;
    }

    /// Get buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Insert character at cursor position
    pub fn insert(&mut self, c: u8) -> bool {
        if self.buffer.len() >= 255 {
            return false;
        }
        if self.cursor_pos == self.buffer.len() {
            self.buffer.push(c);
        } else {
            self.buffer.insert(self.cursor_pos, c);
        }
        self.cursor_pos += 1;
        true
    }

    /// Delete character before cursor (backspace)
    pub fn backspace(&mut self) -> bool {
        if self.cursor_pos > 0 {
            self.cursor_pos -= 1;
            self.buffer.remove(self.cursor_pos);
            true
        } else {
            false
        }
    }

    /// Delete character at cursor position
    pub fn delete(&mut self) -> bool {
        if self.cursor_pos < self.buffer.len() {
            self.buffer.remove(self.cursor_pos);
            true
        } else {
            false
        }
    }

    /// Move cursor left
    pub fn move_left(&mut self) -> bool {
        if self.cursor_pos > 0 {
            self.cursor_pos -= 1;
            true
        } else {
            false
        }
    }

    /// Move cursor right
    pub fn move_right(&mut self) -> bool {
        if self.cursor_pos < self.buffer.len() {
            self.cursor_pos += 1;
            true
        } else {
            false
        }
    }

    /// Move cursor to start
    pub fn move_home(&mut self) {
        self.cursor_pos = 0;
    }

    /// Move cursor to end
    pub fn move_end(&mut self) {
        self.cursor_pos = self.buffer.len();
    }

    /// Get cursor position
    pub fn cursor(&self) -> usize {
        self.cursor_pos
    }
}

/// Read a line from serial port with advanced editing support
/// Returns InputEvent for special keys, allowing shell to handle history
pub async fn read_line_advanced(editor: &mut LineEditor) -> InputEvent {
    let port = serial1();
    
    loop {
        let byte = port.read_byte().await;
        
        match byte {
            // Enter (CR or LF)
            b'\r' | b'\n' => {
                port.port.send(b'\r');
                port.port.send(b'\n');
                let line = editor.content();
                editor.clear();
                return InputEvent::Line(line);
            }
            // Backspace
            0x08 | 0x7F => {
                if editor.backspace() {
                    // Echo: backspace, space, backspace
                    port.port.send(0x08);
                    port.port.send(b' ');
                    port.port.send(0x08);
                }
            }
            // Tab
            b'\t' => {
                return InputEvent::Tab;
            }
            // Ctrl+C
            0x03 => {
                port.port.send(b'^');
                port.port.send(b'C');
                port.port.send(b'\r');
                port.port.send(b'\n');
                editor.clear();
                return InputEvent::Interrupt;
            }
            // Ctrl+D (EOF)
            0x04 => {
                if editor.len() == 0 {
                    return InputEvent::Eof;
                }
            }
            // Escape sequence start
            0x1B => {
                // Read next byte to determine sequence
                let next = port.read_byte().await;
                if next == b'[' {
                    // CSI sequence
                    let code = port.read_byte().await;
                    match code {
                        b'A' => return InputEvent::ArrowUp,
                        b'B' => return InputEvent::ArrowDown,
                        b'C' => {
                            if editor.move_right() {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'C');
                            }
                        }
                        b'D' => {
                            if editor.move_left() {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'D');
                            }
                        }
                        b'H' => {
                            // Home key
                            let moves = editor.cursor();
                            editor.move_home();
                            for _ in 0..moves {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'D');
                            }
                        }
                        b'F' => {
                            // End key
                            let moves = editor.len() - editor.cursor();
                            editor.move_end();
                            for _ in 0..moves {
                                port.port.send(0x1B);
                                port.port.send(b'[');
                                port.port.send(b'C');
                            }
                        }
                        b'3' => {
                            // Delete key (ESC [ 3 ~)
                            let tilde = port.read_byte().await;
                            if tilde == b'~' && editor.delete() {
                                // Redraw from cursor to end
                                redraw_from_cursor(port, editor);
                            }
                        }
                        _ => {
                            // Unknown sequence, ignore
                        }
                    }
                }
            }
            // Printable ASCII
            0x20..=0x7E => {
                if editor.insert(byte) {
                    if editor.cursor() == editor.len() {
                        // Cursor at end, just echo
                        port.port.send(byte);
                    } else {
                        // Cursor in middle, redraw
                        redraw_from_cursor(port, editor);
                    }
                }
            }
            _ => {
                // Ignore other control characters
            }
        }
    }
}

/// Helper to redraw line from cursor position
fn redraw_from_cursor(port: &AsyncSerialPort, editor: &LineEditor) {
    let pos = editor.cursor();
    let content = editor.content();
    
    // Print from cursor to end
    for c in content[pos..].bytes() {
        port.port.send(c);
    }
    // Add space to clear any trailing char
    port.port.send(b' ');
    // Move cursor back to original position
    let moves = content.len() - pos + 1;
    for _ in 0..moves {
        port.port.send(0x1B);
        port.port.send(b'[');
        port.port.send(b'D');
    }
}

/// Read a line from serial port asynchronously (simple version)
/// Returns when Enter is pressed or buffer is full
pub async fn read_line() -> String {
    let port = serial1();
    let mut buffer = Vec::with_capacity(256);
    
    loop {
        let byte = port.read_byte().await;
        
        match byte {
            // Enter (CR or LF)
            b'\r' | b'\n' => {
                port.port.send(b'\r');
                port.port.send(b'\n');
                break;
            }
            // Backspace
            0x08 | 0x7F => {
                if !buffer.is_empty() {
                    buffer.pop();
                    // Echo: backspace, space, backspace
                    port.port.send(0x08);
                    port.port.send(b' ');
                    port.port.send(0x08);
                }
            }
            // Ctrl+C
            0x03 => {
                buffer.clear();
                port.port.send(b'^');
                port.port.send(b'C');
                port.port.send(b'\r');
                port.port.send(b'\n');
                break;
            }
            // Ctrl+D (EOF)
            0x04 => {
                if buffer.is_empty() {
                    // Return empty to signal EOF
                    break;
                }
            }
            // Printable ASCII
            0x20..=0x7E => {
                if buffer.len() < 255 {
                    buffer.push(byte);
                    // Echo the character
                    port.port.send(byte);
                }
            }
            _ => {
                // Ignore other control characters
            }
        }
    }
    
    String::from_utf8_lossy(&buffer).into_owned()
}

// ============================================================================
// Global instance and macros
// ============================================================================

static SERIAL1: AsyncSerialPort = AsyncSerialPort::new(ComPort::Com1);

/// COM1 IRQ number
const COM1_IRQ: u8 = 4;

pub fn init() -> Result<(), SerialError> {
    SERIAL1.init(BaudRate::Baud115200)?;
    SERIAL1.port.set_interrupts(true, false);
    
    // Unmask IRQ4 (COM1) in the PIC
    crate::interrupts::unmask_irq(COM1_IRQ);
    
    // Using literal string to avoid circular reference with formatter
    SERIAL1.send_str("[SERIAL] COM1 initialized (IRQ4 enabled)\n");
    Ok(())
}

pub fn serial1() -> &'static AsyncSerialPort {
    &SERIAL1
}

pub fn handle_interrupt() {
    SERIAL1.handle_interrupt();
}

// Helper struct for safe writing
struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        SERIAL1.send_str(s);
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // Create a temporary Writer and write to it
    // Note: Be careful about deadlocks in interrupt context,
    // but current implementation doesn't use locks so it's safe.
    let mut writer = SerialWriter;
    let _ = writer.write_fmt(args);
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::io::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}
