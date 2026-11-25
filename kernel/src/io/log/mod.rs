//! Structured kernel logging and allocation-free boot and panic diagnostics.

mod level_parse;
mod record;

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};

use super::serial::{self, Channel};
use record::WireRecord;

pub use level_parse::set_log_level_from_str;

const PANIC_OUTPUT_NO_OWNER: u16 = crate::cpu::MAX_POSSIBLE_CPUS as u16;

static CONSOLE_MIRROR_ENABLED: AtomicBool = AtomicBool::new(true);
static SERIAL_OUTPUT_ENABLED: AtomicBool = AtomicBool::new(true);
static PANIC_OUTPUT_OWNER: AtomicU16 = AtomicU16::new(PANIC_OUTPUT_NO_OWNER);
static DROPPED_LOG_RECORDS: AtomicUsize = AtomicUsize::new(0);
static LOGGER: KernelLogger = KernelLogger;

struct KernelLogger;

impl Log for KernelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= current_log_level()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if serial::in_panic() || !serial_output_enabled() && !console_mirror_enabled() {
            return;
        }
        // Formatting can call arbitrary Display implementations. Complete it
        // before claiming any shared storage or UART transmission authority.
        let Ok(record) = WireRecord::encode(record) else {
            DROPPED_LOG_RECORDS.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if serial_output_enabled()
            && serial::log_channel_available()
            && serial::write(Channel::Log, record.bytes()) != record.bytes().len()
        {
            DROPPED_LOG_RECORDS.fetch_add(1, Ordering::Relaxed);
        }
        #[cfg(not(feature = "bench"))]
        if console_mirror_enabled() && !serial::in_panic() {
            crate::console::try_write(record.message());
        }
    }

    fn flush(&self) {
        // Runtime delivery is driven by the UART, including after a caller
        // returns. The kernel does not offer a blocking wire-delivery barrier.
    }
}

/// Number of records rejected by formatting limits, queue admission or immediate output.
pub fn dropped_log_records() -> usize {
    DROPPED_LOG_RECORDS.load(Ordering::Relaxed)
}

/// Copies a snapshot of bytes currently pending for the serial transport.
pub fn peek_global_log(dst: &mut [u8]) -> usize {
    serial::copy_pending_logs(dst)
}

pub fn get_log_len() -> usize {
    serial::pending_log_bytes()
}

/// Installs the logger before interrupts and the heap are available.
///
/// # Errors
/// Returns an error if another logger has already been installed.
pub(crate) fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)?;
    let level = if cfg!(feature = "verbose_logging") {
        LevelFilter::Trace
    } else {
        LevelFilter::Info
    };
    set_log_level(level);
    Ok(())
}

pub fn set_log_level(level: LevelFilter) {
    log::set_max_level(level);
}

pub fn current_log_level() -> LevelFilter {
    log::max_level()
}

pub fn set_console_mirror_enabled(enabled: bool) {
    CONSOLE_MIRROR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn console_mirror_enabled() -> bool {
    CONSOLE_MIRROR_ENABLED.load(Ordering::Relaxed)
}

pub fn set_serial_output_enabled(enabled: bool) {
    SERIAL_OUTPUT_ENABLED.store(enabled, Ordering::Release);
}

pub fn serial_output_enabled() -> bool {
    SERIAL_OUTPUT_ENABLED.load(Ordering::Acquire)
}

pub fn enter_panic_mode() {
    if let Some(current) = crate::cpu::CurrentCpu::acquire() {
        let _ = PANIC_OUTPUT_OWNER.compare_exchange(
            PANIC_OUTPUT_NO_OWNER,
            current.id().as_u16(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    serial::enter_panic_mode();
}

fn diagnostic_channel() -> Option<Channel> {
    if !serial::in_panic() {
        return Some(Channel::Console);
    }
    let owner = PANIC_OUTPUT_OWNER.load(Ordering::Acquire);
    (owner == PANIC_OUTPUT_NO_OWNER
        || crate::cpu::CurrentCpu::acquire().is_some_and(|cpu| cpu.id().as_u16() == owner))
    .then_some(Channel::Emergency)
}

struct DiagnosticWriter(Channel);

impl Write for DiagnosticWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut segments = text.split_inclusive('\n');
        // Bound each hardware write on the raw diagnostic path.
        segments.try_for_each(|segment| {
            if let Some(line) = segment.strip_suffix('\n') {
                self.write_bytes(line.as_bytes())?;
                self.write_bytes(if line.ends_with('\r') { b"\n" } else { b"\r\n" })
            } else {
                self.write_bytes(segment.as_bytes())
            }
        })
    }
}

impl DiagnosticWriter {
    fn write_bytes(&self, bytes: &[u8]) -> fmt::Result {
        if serial::write(self.0, bytes) == bytes.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

/// Best-effort raw diagnostics during startup and terminal fault handling.
pub fn early_print(text: &str) {
    print(format_args!("{text}"));
}

pub fn early_print_char(byte: u8) {
    if let Some(channel) = diagnostic_channel() {
        let _ = serial::write(channel, &[byte]);
    }
}

pub fn early_print_dec(number: u64) {
    print(format_args!("{number}"));
}

pub fn early_print_hex(number: u64) {
    print(format_args!("{number:#018x}"));
}

pub fn print(args: fmt::Arguments<'_>) {
    if let Some(channel) = diagnostic_channel() {
        let _ = DiagnosticWriter(channel).write_fmt(args);
    }
}

// Reserved single-byte bring-up trace points are dormant in normal builds.
#[inline]
pub fn debug_serial_mark(_marker: u8) {}

#[cfg(feature = "bench")]
pub fn bench_clear_buffers() {
    serial::bench_clear();
    DROPPED_LOG_RECORDS.store(0, Ordering::Relaxed);
}

#[cfg(feature = "bench")]
pub fn bench_push_global(data: &[u8]) -> usize {
    if serial::bench_push_log(data) {
        data.len()
    } else {
        0
    }
}

#[cfg(feature = "bench")]
pub fn bench_pop_global_buf(dst: &mut [u8]) -> usize {
    serial::bench_pop_logs(dst)
}

#[cfg(feature = "bench")]
pub fn bench_total_pending_bytes() -> usize {
    get_log_len()
}
