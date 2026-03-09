use super::*;
use alloc::string::String;

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
        if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
            if cpu_id < PER_CPU_COUNT {
                if let Some(mut guard) = PER_CORE_LOG_BUFFERS[cpu_id].try_lock() {
                    self.write_into_async_buffer::<{ PER_CORE_BUFFER_CAPACITY }>(
                        &mut guard, record,
                    );
                    return true;
                }
            }
        }

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
        KernelLogger::write_raw(s);
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

    if !IN_PANIC.load(Ordering::Relaxed) {
        let _ = aggregate_per_core_to_global(AGGREGATE_MAX_PER_CALL);
    }

    if IN_PANIC.load(Ordering::Relaxed) {
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        let current = ier.read();
        if (current & 0x02) == 0 {
            ier.write(current | 0x02);
        }
    } else {
        let _io_guard = SERIAL_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        let current = ier.read();
        if (current & 0x02) == 0 {
            ier.write(current | 0x02);
        }
    }
}

pub(crate) fn drain_global_tx_buffer(data_port: &mut PortU8, lsr: &mut PortU8) -> usize {
    if !serial_output_enabled() {
        return 0;
    }
    let mut tmp = [0u8; LSR_TX_BURST];
    let n = {
        let guard = LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner());
        guard.peek_bulk(&mut tmp)
    };
    if n == 0 {
        return 0;
    }
    let mut i = 0usize;
    while i < n {
        if (lsr.read() & LSR_TX_EMPTY) == 0 {
            break;
        }
        data_port.write(tmp[i]);
        i += 1;
    }
    if i > 0 {
        let mut guard = LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner());
        guard.advance_head(i);
    }
    i
}

pub(crate) fn disable_tx_interrupt() {
    if IN_PANIC.load(Ordering::Relaxed) {
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        let current = ier.read();
        ier.write(current & !0x02);
    } else {
        let _io_guard = SERIAL_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        let current = ier.read();
        ier.write(current & !0x02);
    }
}

pub fn handle_serial_interrupt() {
    let mut iir: PortU8 = IoPort::new(SERIAL_PORT_BASE + 2);
    let mut lsr: PortU8 = IoPort::new(SERIAL_PORT_BASE + 5);
    let mut data_port: PortU8 = IoPort::new(SERIAL_PORT_BASE);

    loop {
        let id = iir.read();
        if (id & 1) != 0 {
            break;
        }

        match id & 0x0E {
            0x02 => {
                let total_written = drain_global_tx_buffer(&mut data_port, &mut lsr);
                if total_written == 0 {
                    disable_tx_interrupt();
                }
            }
            0x04 | 0x0C => {
                let mut guard = INPUT_BUFFER.lock().unwrap_or_else(|e| e.into_inner());
                while (lsr.read() & 0x01) != 0 {
                    let byte = data_port.read();
                    let _ = guard.push_byte(byte);
                }
            }
            _ => break,
        }
    }
}

pub(crate) static LOGGER: KernelLogger = KernelLogger;

pub fn get_dropped_log_bytes() -> usize {
    DROPPED_LOG_BYTES.load(Ordering::Relaxed)
}

pub fn read_char() -> Option<u8> {
    INPUT_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).pop_one()
}

pub fn has_char() -> bool {
    !INPUT_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
}

#[cfg(feature = "bench")]
pub fn bench_clear_buffers() {
    LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).clear();
    for i in 0..PER_CPU_COUNT {
        PER_CORE_LOG_BUFFERS[i].lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
    INPUT_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).clear();
    DROPPED_LOG_BYTES.store(0, Ordering::Relaxed);
}

#[cfg(feature = "bench")]
pub fn bench_push_per_core(core: usize, data: &[u8]) -> usize {
    if core >= PER_CPU_COUNT {
        return 0;
    }
    PER_CORE_LOG_BUFFERS[core].lock().unwrap_or_else(|e| e.into_inner()).push_bytes(data)
}

#[cfg(feature = "bench")]
pub fn bench_push_global(data: &[u8]) -> usize {
    LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).push_bytes(data)
}

#[cfg(feature = "bench")]
pub fn bench_pop_global_buf(dst: &mut [u8]) -> usize {
    LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).pop_bulk(dst)
}

#[cfg(feature = "bench")]
pub fn bench_pop_per_core_buf(core: usize, dst: &mut [u8]) -> usize {
    if core >= PER_CPU_COUNT {
        return 0;
    }
    PER_CORE_LOG_BUFFERS[core].lock().unwrap_or_else(|e| e.into_inner()).pop_bulk(dst)
}

#[cfg(feature = "bench")]
pub fn bench_total_pending_bytes() -> usize {
    let mut total = 0usize;
    total += LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).len();
    for i in 0..PER_CPU_COUNT {
        total += PER_CORE_LOG_BUFFERS[i].lock().unwrap_or_else(|e| e.into_inner()).len();
    }
    total
}

pub fn aggregate_per_core_to_global(max_bytes: usize) -> usize {
    let mut moved = 0usize;
    let mut tmp = [0u8; 256];

    for i in 0..PER_CPU_COUNT {
        if moved >= max_bytes {
            break;
        }
        if let Some(mut per_guard) = PER_CORE_LOG_BUFFERS[i].try_lock() {
            let to_read = core::cmp::min(tmp.len(), max_bytes - moved);
            let n = per_guard.peek_bulk(&mut tmp[..to_read]);
            if n == 0 {
                continue;
            }

            let wrote = {
                let mut global_guard = LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner());
                let written = global_guard.push_bytes(&tmp[..n]);
                if written < n {
                    DROPPED_LOG_BYTES.fetch_add(n - written, Ordering::Relaxed);
                }
                written
            };

            if wrote > 0 {
                per_guard.advance_head(wrote);
                moved += wrote;
            }
        }
    }

    moved
}

pub fn kick_serial_tx() {
    start_serial_tx();

    if serial_output_enabled() && !IN_PANIC.load(Ordering::Relaxed) {
        let _io_guard = SERIAL_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut data_port: PortU8 = IoPort::new(SERIAL_PORT_BASE);
        let mut lsr: PortU8 = IoPort::new(SERIAL_PORT_BASE + 5);
        let mut total = 0usize;
        loop {
            let n = drain_global_tx_buffer(&mut data_port, &mut lsr);
            if n == 0 {
                break;
            }
            total += n;
            if total >= 4096 {
                break;
            }
        }
    }
}
