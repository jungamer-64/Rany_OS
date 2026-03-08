// ============================================================================
// src/io/serial.rs - Serial Port Driver Re-export
// ============================================================================

pub use serial_driver::*;

/// Read one byte from COM1 for interactive shell input.
///
/// Uses polling fallback so serial shell stays usable even when COM1 IRQ
/// delivery is unavailable in specific QEMU/host configurations.
pub async fn read_byte_for_shell() -> u8 {
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        if let Some(byte) = try_read_byte() {
            return byte;
        }

        if crate::interrupts::are_interrupts_enabled() {
            crate::task::sleep_ms(1).await;
        } else {
            crate::task::yield_now().await;
        }
    }
}
