use super::*;

mod level_parse;
pub use level_parse::*;
impl Log for KernelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let current_level = LevelFilter::iter()
            .nth(CURRENT_LOG_LEVEL.load(Ordering::Relaxed) as usize)
            .unwrap_or(LevelFilter::Info);
        metadata.level() <= current_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let serial_enabled = serial_output_enabled();

        if serial_enabled {
            let use_async = HEAP_AVAILABLE.load(Ordering::Relaxed)
                && !IN_PANIC.load(Ordering::Relaxed)
                && crate::interrupts::are_interrupts_enabled()
                && crate::io::log::async_logging_enabled();
            if use_async {
                if self.try_log_async(record) {
                    start_serial_tx();
                } else {
                    self.log_sync_fallback(record);
                }
            } else {
                self.log_sync(record);
            }
        }

        #[cfg(not(feature = "bench"))]
        if !is_in_panic() && console_mirror_enabled() {
            struct ConsoleLogWriter;
            impl core::fmt::Write for ConsoleLogWriter {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    crate::console::try_write(s);
                    Ok(())
                }
            }

            use core::fmt::Write;
            let _ = write!(ConsoleLogWriter, "{}\n", record.args());
        }
    }

    fn flush(&self) {}
}

impl KernelLogger {
    pub(super) fn try_log_async(&self, record: &Record) -> bool {
        if let Some(mut guard) = LOG_BUFFER.try_lock() {
            self.write_into_async_buffer::<{ LOG_BUFFER_CAPACITY }>(&mut guard, record);
            return true;
        }

        false
    }

    pub(super) fn log_sync_fallback(&self, record: &Record) {
        let _guard = if IN_PANIC.load(Ordering::Relaxed) {
            None
        } else {
            SERIAL_LOCK.try_lock().ok()
        };

        let mut tracker = LastCharTracker::new(SyncLogWriter);
        self.print_header(&mut tracker, record);
        let _ = write!(tracker, "{}", record.args());
        if tracker.last_char != b'\n' {
            let _ = tracker.inner.write_str("\r\n");
        }
    }

    pub(super) fn log_sync(&self, record: &Record) {
        let _guard = if IN_PANIC.load(Ordering::Relaxed) {
            None
        } else {
            Some(SERIAL_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
        };
        let mut tracker = LastCharTracker::new(SyncLogWriter);
        self.print_header(&mut tracker, record);
        let _ = write!(tracker, "{}", record.args());
        if tracker.last_char != b'\n' {
            let _ = tracker.inner.write_str("\r\n");
        }
    }
}

pub(crate) struct LastCharTracker<W: Write> {
    pub(crate) inner: W,
    pub(crate) last_char: u8,
}

impl<W: Write> LastCharTracker<W> {
    pub(super) fn new(inner: W) -> Self {
        Self {
            inner,
            last_char: 0,
        }
    }
}

impl<W: Write> Write for LastCharTracker<W> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if !s.is_empty() {
            self.last_char = s.as_bytes()[s.len() - 1];
        }
        self.inner.write_str(s)
    }
}

pub(crate) struct SyncLogWriter;
impl Write for SyncLogWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        LOGGER.write_raw(s);
        Ok(())
    }
}

pub(crate) struct AsyncLogWriter<'a, const N: usize> {
    buffer: &'a mut RingBuffer<N>,
}

impl<'a, const N: usize> AsyncLogWriter<'a, N> {
    pub(super) fn new(buffer: &'a mut RingBuffer<N>) -> Self {
        Self { buffer }
    }
}

impl<'a, const N: usize> Write for AsyncLogWriter<'a, N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let written = self.buffer.push_bytes(bytes);
        if written < bytes.len() {
            DROPPED_LOG_BYTES.fetch_add((bytes.len() - written) as usize, Ordering::Relaxed);
        }
        Ok(())
    }
}

pub(crate) fn start_serial_tx() {
    if !serial_output_enabled() {
        return;
    }
    LOGGER
        .serial
        .set_interrupt_mode(SerialInterruptMode::ReceiveAndTransmit);
}

pub fn handle_serial_interrupt() {
    let transmit_enabled = serial_output_enabled() && !IN_PANIC.load(Ordering::Relaxed);
    let report = LOGGER.serial.service_interrupt(
        SERIAL_INTERRUPT_BUDGET,
        |byte| {
            INPUT_BUFFER
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push_byte(byte)
        },
        || {
            if transmit_enabled {
                LOG_BUFFER
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .pop_one()
            } else {
                None
            }
        },
    );
    if report.dropped_bytes != 0 {
        DROPPED_SERIAL_INPUT_BYTES.fetch_add(report.dropped_bytes, Ordering::Relaxed);
    }
}

pub fn get_dropped_log_bytes() -> usize {
    DROPPED_LOG_BYTES.load(Ordering::Relaxed)
}

pub fn read_char() -> Option<u8> {
    INPUT_BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pop_one()
}

/// Returns a buffered byte, or polls the UART when IRQ delivery has not yet
/// published one.
pub fn try_read_serial_byte() -> Option<u8> {
    read_char().or_else(|| LOGGER.serial.try_receive().ok())
}

/// Performs bounded best-effort output through the kernel-owned console.
pub fn write_serial_bytes(bytes: &[u8]) {
    if !serial_output_enabled() || !panic_output_allowed() {
        return;
    }
    for &byte in bytes {
        LOGGER.write_byte_raw(byte);
    }
}

pub fn has_char() -> bool {
    !INPUT_BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_empty()
}

pub fn get_dropped_serial_input_bytes() -> usize {
    DROPPED_SERIAL_INPUT_BYTES.load(Ordering::Relaxed)
}

#[cfg(feature = "bench")]
pub fn bench_clear_buffers() {
    LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).clear();
    INPUT_BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    DROPPED_LOG_BYTES.store(0, Ordering::Relaxed);
    DROPPED_SERIAL_INPUT_BYTES.store(0, Ordering::Relaxed);
}

#[cfg(feature = "bench")]
pub fn bench_push_global(data: &[u8]) -> usize {
    LOG_BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push_bytes(data)
}

#[cfg(feature = "bench")]
pub fn bench_pop_global_buf(dst: &mut [u8]) -> usize {
    LOG_BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pop_bulk(dst)
}

#[cfg(feature = "bench")]
pub fn bench_total_pending_bytes() -> usize {
    LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).len()
}

pub fn kick_serial_tx() {
    start_serial_tx();
    if serial_output_enabled() && !IN_PANIC.load(Ordering::Relaxed) {
        handle_serial_interrupt();
    }
}
