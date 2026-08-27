use super::*;

/// Helper to redraw line from cursor position
pub(crate) fn redraw_from_cursor(port: &AsyncSerialPort, editor: &LineEditor) {
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
    let port = &SERIAL1;
    let mut buffer = Vec::with_capacity(256);

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
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
            0x20..=0x7E if buffer.len() < 255 => {
                buffer.push(byte);
                // Echo the character
                port.port.send(byte);
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

pub(crate) static SERIAL1: AsyncSerialPort = {
    // SAFETY: this static is the serial driver's single COM1 resource owner.
    // Early-console access must finish before this driver is activated.
    let ports = match unsafe { IoPortRange::from_raw_parts(ComPort::Com1 as u16, 8) } {
        Ok(ports) => ports,
        Err(_) => panic!("invalid fixed COM1 allocation"),
    };
    let port = match SerialPort::new(ports) {
        Ok(port) => port,
        Err(_) => panic!("invalid fixed UART register width"),
    };
    AsyncSerialPort::new(port)
};

// Removed: deprecated convenience `init()` function. Prefer registering the driver:
// driver_registry::register_driver(Box::new(SerialDriver::new()));
// DriverRegistry will perform initialization at the appropriate time and context.

// Removed: `serial1()` accessor. Use `crate::io::log::early_print` or the kernel logging APIs instead.

/// Dispatch COM1 interrupt to the serial driver's handler (replaces the old free function)
pub fn dispatch_interrupt() {
    SERIAL1.handle_interrupt();
}

/// Read a byte asynchronously from COM1
pub async fn read_byte() -> u8 {
    SERIAL1.read_byte().await
}

/// Read a byte from COM1 without blocking.
pub fn try_read_byte() -> Option<u8> {
    SERIAL1
        .rx_buffer
        .pop()
        .or_else(|| SERIAL1.port.try_receive().ok())
}

/// Write a byte to COM1 (blocking)
pub fn write_byte(byte: u8) {
    SERIAL1.port.send(byte);
}

/// Write a string to COM1 (blocking)
pub fn write_str(s: &str) {
    SERIAL1.send_str(s);
}

// Helper struct for safe writing
pub(crate) struct SerialWriter;

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

// Removed: `serial_print!` macro. Use `crate::io::log::early_print` or `log::info!`/`log::debug!`.

// Removed: `serial_println!` macro. Use `crate::io::log::early_print` or `log::info!`/`log::debug!`.

// ============================================================================
// Serial Driver implementing Driver trait
// ============================================================================

/// Serial COM1 driver implementing Driver trait
///
/// Wraps the existing AsyncSerialPort and integrates with DriverRegistry.
pub struct SerialDriver {
    initialized: bool,
}

impl SerialDriver {
    /// Create a new Serial driver
    pub fn new() -> Self {
        Self { initialized: false }
    }
}

impl Default for SerialDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for SerialDriver {
    fn name(&self) -> &str {
        "serial-com1"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(1, 0, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Serial
    }

    fn probe(&mut self) -> KapiResult<()> {
        // Initialize COM1
        match SERIAL1.init(BaudRate::Baud115200) {
            Ok(()) => {
                self.initialized = true;
                SERIAL1.send_str("[SERIAL] COM1 driver probed via DriverRegistry\n");
                Ok(())
            }
            Err(_) => Err(kernel_api::KapiError::IoError),
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(kernel_api::KapiError::InvalidHandle);
        }

        // Enable interrupts
        SERIAL1.port.set_interrupts(true, false);

        // Unmasking IRQ must be done by kernel
        // crate::interrupts::unmask_irq(COM1_IRQ);

        SERIAL1.send_str("[SERIAL] COM1 IRQ4 enabled\n");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        // Disable interrupts
        SERIAL1.port.set_interrupts(false, false);
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // ISA device, no PCI/USB ID
        &[]
    }
}
