// ============================================================================
// src/io/serial.rs - Kernel serial console input
// ============================================================================

/// Read one byte from COM1 for interactive shell input.
///
/// Uses polling fallback so serial shell stays usable even when COM1 IRQ
/// delivery is unavailable in specific QEMU/host configurations.
pub async fn read_byte_for_shell() -> u8 {
    let mut use_timer = true;
    // LOOP_PROOF: mode=event; reason=Receiving a byte returns to the shell, and an empty receive awaits a timer or scheduler yield before retrying.;
    loop {
        if let Some(byte) = crate::io::log::try_read_serial_byte() {
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
