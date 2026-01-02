//! Serial console logging for headless debugging
//!
//! This module provides a simple serial port logger that can be used
//! before and during UEFI boot services. It writes to COM1 (0x3F8)
//! using direct I/O port access.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

/// COM1 base I/O port address
const COM1_PORT: u16 = 0x3F8;

/// Line Status Register offset
const LSR_OFFSET: u16 = 5;

/// Transmitter Holding Register Empty bit
const LSR_THRE: u8 = 0x20;

/// Whether serial port has been initialized
static SERIAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Serial port writer for COM1
pub struct SerialWriter;

impl SerialWriter {
    /// Create a new serial writer
    pub const fn new() -> Self {
        Self
    }

    /// Initialize COM1 serial port
    ///
    /// Sets up 115200 baud, 8N1 configuration
    pub fn init(&self) {
        unsafe {
            // Disable interrupts
            outb(COM1_PORT + 1, 0x00);

            // Enable DLAB (Divisor Latch Access Bit) to set baud rate
            outb(COM1_PORT + 3, 0x80);

            // Set divisor to 1 (115200 baud)
            // Divisor = 115200 / baud_rate
            // For 115200 baud: divisor = 1
            outb(COM1_PORT + 0, 0x01); // Low byte
            outb(COM1_PORT + 1, 0x00); // High byte

            // 8 bits, no parity, 1 stop bit (8N1)
            outb(COM1_PORT + 3, 0x03);

            // Enable FIFO, clear them, with 14-byte threshold
            outb(COM1_PORT + 2, 0xC7);

            // Enable IRQs, RTS/DSR set
            outb(COM1_PORT + 4, 0x0B);

            // Set in loopback mode for test
            outb(COM1_PORT + 4, 0x1E);

            // Test serial chip (send byte 0xAE and check if received)
            outb(COM1_PORT + 0, 0xAE);

            // Check if serial is faulty (i.e., not same byte as sent)
            if inb(COM1_PORT + 0) != 0xAE {
                // Serial is faulty, but we continue anyway
                // (some emulators don't support loopback test)
            }

            // If serial is working, set it to normal operation mode
            // (not-loopback with IRQs enabled and OUT#1 and OUT#2 bits enabled)
            outb(COM1_PORT + 4, 0x0F);
        }
    }

    /// Check if transmit buffer is empty
    fn is_transmit_empty(&self) -> bool {
        unsafe { (inb(COM1_PORT + LSR_OFFSET) & LSR_THRE) != 0 }
    }

    /// Write a single byte to serial port
    pub fn write_byte(&self, byte: u8) {
        // Wait for transmit buffer to be empty
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }
        unsafe {
            outb(COM1_PORT, byte);
        }
    }

    /// Write a string to serial port
    pub fn write_str_bytes(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                // Send CR before LF for proper line endings
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str_bytes(s);
        Ok(())
    }
}

/// Initialize the serial console
pub fn init() {
    if SERIAL_INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // Already initialized
    }
    SerialWriter::new().init();
}

/// Write formatted output to serial console
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_serial_print(format_args!($($arg)*))
    };
}

/// Write formatted output to serial console with newline
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => {
        $crate::serial_print!("{}\n", format_args!($($arg)*))
    };
}

/// Internal function for serial_print macro
#[doc(hidden)]
pub fn _serial_print(args: fmt::Arguments) {
    // SerialWriter has no state, so we can create a new instance each time
    let mut writer = SerialWriter::new();
    let _ = writer.write_fmt(args);
}

/// Write a single character to serial (used in inline asm debugging)
#[allow(dead_code)]
pub fn write_char(c: char) {
    SerialWriter::new().write_byte(c as u8);
}

// I/O port access functions (x86_64 specific)
#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nostack, nomem, preserves_flags)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nostack, nomem, preserves_flags)
    );
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_writer() {
        // This test would need actual hardware or emulation
        // Just verify the structure compiles
        let writer = SerialWriter::new();
        let _ = writer;
    }
}
