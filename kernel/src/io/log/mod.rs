// ============================================================================
// src/io/log.rs - Kernel Logging System using the `log` crate
// ============================================================================
//!
//! カーネル用ロギングシステム。
//!
//! ## 機能
//! - `log`クレートを使用した標準的なログインターフェース
//! - 早期ブート時の直接シリアル出力（ヒープ不要）
//! - 初期化後はシリアルポートへの非同期出力
//! - コンパイル時のログレベルフィルタリング
//! - マルチコア安全なSpinlock保護
//!
//! ## 使用方法
//! ```rust,no_run
//! use log::{info, debug, warn, error, trace};
//!
//! info!("システム起動");
//! debug!("デバッグ情報: {}", /* value */ 0);
//! error!("エラー発生: {:?}", /* err */ "err");
//! ```

use core::fmt::Write;

use crate::sync::{IrqPoisonLock, PoisonLock};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicUsize, Ordering};
use hal::IoPortRange;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use serial_driver::{
    BaudRate, DataBits, Parity, SerialError, SerialInterruptBudget, SerialInterruptMode,
    SerialPort, StopBits,
};

// ============================================================================
// 定数定義
// ============================================================================

/// 非同期ログバッファの容量 (16KB)
mod logger_impl;
pub use logger_impl::*;
mod serial_output;
const LOG_BUFFER_CAPACITY: usize = 16 * 1024;

// ============================================================================
// 定数定義
// ============================================================================

/// 送信待機タイムアウト（ループ回数）
const TX_TIMEOUT_LOOPS: usize = 100_000;

/// 割り込みハンドラが一度に送信する最大バーストサイズ（ISR内のローカルバッファ長）
const LSR_TX_BURST: usize = 64;

const SERIAL_INTERRUPT_BUDGET: SerialInterruptBudget =
    match SerialInterruptBudget::new(16, 256, LSR_TX_BURST) {
        Ok(budget) => budget,
        Err(_) => panic!("fixed serial interrupt budget must be non-zero"),
    };

// ============================================================================
// ログレベル定義
// ============================================================================

/// コンパイル時のログレベル（featureで変更可能）
#[cfg(feature = "verbose_logging")]
const MAX_LOG_LEVEL: LevelFilter = LevelFilter::Trace;

#[cfg(not(feature = "verbose_logging"))]
const MAX_LOG_LEVEL: LevelFilter = LevelFilter::Info;

// ============================================================================
// ロガー状態管理
// ============================================================================

/// ロガーの初期化状態
const LOGGER_UNINITIALIZED: u8 = 0;
const LOGGER_INITIALIZING: u8 = 1;
const LOGGER_READY: u8 = 2;
static LOGGER_INITIALIZED: AtomicU8 = AtomicU8::new(LOGGER_UNINITIALIZED);

/// 現在のログレベル（実行時変更可能）
static CURRENT_LOG_LEVEL: AtomicU8 = AtomicU8::new(LevelFilter::Info as u8);

/// ヒープが使用可能かどうか
static HEAP_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Whether log messages should be mirrored to the on-screen console.
static CONSOLE_MIRROR_ENABLED: AtomicBool = AtomicBool::new(true);

/// Whether serial logging output is enabled.
static SERIAL_OUTPUT_ENABLED: AtomicBool = AtomicBool::new(true);

/// シリアルポート排他制御用Spinlock
///
/// パニックハンドラからの出力時はデッドロック回避のため
/// ロックを試行せず直接出力する（try_lockを使用）。
static SERIAL_LOCK: PoisonLock<()> = PoisonLock::new(());

/// パニック中フラグ（デッドロック回避用）
static IN_PANIC: AtomicBool = AtomicBool::new(false);
const PANIC_OUTPUT_NO_OWNER: u16 = crate::cpu::MAX_POSSIBLE_CPUS as u16;
static PANIC_OUTPUT_OWNER: AtomicU16 = AtomicU16::new(PANIC_OUTPUT_NO_OWNER);
const DEBUG_SERIAL_MARKS_ENABLED: bool = false;

/// 非同期ログバッファ（固定長リングバッファ、ヒープ不要）
const INPUT_BUFFER_CAPACITY: usize = 1024;

/// 固定長リングバッファ（ISR安全: ヒープを使わない）
struct RingBuffer<const N: usize> {
    buf: [u8; N],
    head: usize,
    tail: usize,
    full: bool,
}
impl<const N: usize> RingBuffer<N> {
    #[inline]
    fn normalize_index(index: usize) -> usize {
        if N == 0 {
            0
        } else if index < N {
            index
        } else {
            index % N
        }
    }

    #[inline]
    fn normalized_snapshot(&self) -> (usize, usize, bool) {
        let head = Self::normalize_index(self.head);
        let tail = Self::normalize_index(self.tail);
        let full = self.full && head == tail;
        (head, tail, full)
    }

    #[inline]
    fn sanitize_state(&mut self) {
        if N == 0 {
            self.head = 0;
            self.tail = 0;
            self.full = false;
            return;
        }

        if self.head >= N {
            self.head %= N;
            self.full = false;
        }

        if self.tail >= N {
            self.tail %= N;
            self.full = false;
        }

        if self.full && self.head != self.tail {
            self.full = false;
        }
    }

    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            head: 0,
            tail: 0,
            full: false,
        }
    }

    pub fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        if N == 0 {
            return 0;
        }

        let (head, tail, full) = self.normalized_snapshot();
        if full {
            N
        } else if tail >= head {
            tail - head
        } else {
            N - head + tail
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push_byte(&mut self, b: u8) -> bool {
        if N == 0 {
            return false;
        }
        self.sanitize_state();
        if self.full {
            return false;
        }
        self.buf[self.tail] = b;
        self.tail = (self.tail + 1) % N;
        if self.tail == self.head {
            self.full = true;
        }
        true
    }

    pub fn push_bytes(&mut self, src: &[u8]) -> usize {
        if N == 0 {
            return 0;
        }
        self.sanitize_state();

        let avail = self.capacity() - self.len();
        if avail == 0 {
            return 0;
        }

        let to_write = core::cmp::min(avail, src.len());
        if to_write == 0 {
            return 0;
        }

        let tail = self.tail;
        let first = core::cmp::min(to_write, N - tail);

        self.buf[tail..tail + first].copy_from_slice(&src[..first]);

        if to_write > first {
            let second = to_write - first;
            self.buf[..second].copy_from_slice(&src[first..to_write]);
        }

        self.tail = (self.tail + to_write) % N;
        if self.tail == self.head {
            self.full = true;
        }

        to_write
    }

    pub fn pop_one(&mut self) -> Option<u8> {
        if N == 0 {
            return None;
        }
        self.sanitize_state();
        if self.is_empty() {
            return None;
        }
        let b = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.full = false;
        Some(b)
    }

    #[cfg(feature = "bench")]
    pub fn pop_bulk(&mut self, dst: &mut [u8]) -> usize {
        if N == 0 {
            return 0;
        }
        self.sanitize_state();
        let available = self.len();
        if available == 0 || dst.is_empty() {
            return 0;
        }

        let to_read = core::cmp::min(available, dst.len());
        let head = self.head;

        let first = core::cmp::min(to_read, N - head);
        dst[..first].copy_from_slice(&self.buf[head..head + first]);

        if to_read > first {
            let second = to_read - first;
            dst[first..to_read].copy_from_slice(&self.buf[..second]);
        }

        self.head = (self.head + to_read) % N;
        if to_read > 0 {
            self.full = false;
        }

        to_read
    }

    pub fn peek_bulk(&self, dst: &mut [u8]) -> usize {
        if N == 0 {
            return 0;
        }

        let (head, tail, full) = self.normalized_snapshot();
        let available = if full {
            N
        } else if tail >= head {
            tail - head
        } else {
            N - head + tail
        };
        if available == 0 || dst.is_empty() {
            return 0;
        }

        let to_read = core::cmp::min(available, dst.len());
        let first = core::cmp::min(to_read, N - head);
        dst[..first].copy_from_slice(&self.buf[head..head + first]);

        if to_read > first {
            let second = to_read - first;
            dst[first..to_read].copy_from_slice(&self.buf[..second]);
        }

        to_read
    }

    #[cfg(feature = "bench")]
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.full = false;
    }
}

/// 非同期ログバッファ（送信）
static LOG_BUFFER: IrqPoisonLock<RingBuffer<LOG_BUFFER_CAPACITY>> =
    IrqPoisonLock::new(RingBuffer::new());

/// アプリケーションがヒープ利用可能になった後に非同期ログを有効化するフラグ
static ASYNC_LOG_ENABLED: AtomicBool = AtomicBool::new(false);

/// 非同期ログで切り捨てられたバイト数
static DROPPED_LOG_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Received bytes discarded because the bounded input queue was full.
static DROPPED_SERIAL_INPUT_BYTES: AtomicUsize = AtomicUsize::new(0);

/// 非同期ログを有効化する。
pub fn enable_async_logging() {
    ASYNC_LOG_ENABLED.store(true, Ordering::SeqCst);
}

/// 非同期ログが現在有効かどうかを返す
pub fn async_logging_enabled() -> bool {
    ASYNC_LOG_ENABLED.load(Ordering::Relaxed)
}

/// 非同期入力バッファ（受信）
static INPUT_BUFFER: IrqPoisonLock<RingBuffer<INPUT_BUFFER_CAPACITY>> =
    IrqPoisonLock::new(RingBuffer::new());

// ... (Unit tests for RingBuffer remain largely unchanged except for lock calls)

// ============================================================================
// シリアルポート初期化
// ============================================================================

/// Failure while establishing the kernel logging runtime.
#[derive(Debug)]
pub enum LogInitError {
    Serial(SerialError),
    Logger(SetLoggerError),
}

/// Initializes the kernel-owned serial device.
fn init_serial() -> Result<(), SerialError> {
    LOGGER.serial.init(
        BaudRate::Baud115200,
        DataBits::Bits8,
        StopBits::Stop1,
        Parity::None,
    )
}

/// Starts IRQ-driven input after the interrupt subsystem is ready.
pub(crate) fn start_serial_runtime() {
    LOGGER
        .serial
        .set_interrupt_mode(SerialInterruptMode::Receive);
}

// ============================================================================
// シリアルロガー実装
// ============================================================================

/// Kernel logger and sole runtime owner of the COM1 register allocation.
pub(crate) struct KernelLogger {
    serial: SerialPort,
}

impl KernelLogger {
    #[expect(
        unsafe_code,
        reason = "the platform composition root establishes the fixed COM1 allocation"
    )]
    const fn new() -> Self {
        // SAFETY: COM1 0x3f8..=0x3ff is assigned to this owner for the kernel
        // lifetime. Pre-Rust boot writes are an earlier, single-core phase of
        // this same console lifecycle; no other runtime owner is constructed.
        let ports = match unsafe { IoPortRange::from_raw_parts(0x3f8, 8) } {
            Ok(ports) => ports,
            Err(_) => panic!("fixed COM1 allocation must fit the port domain"),
        };
        let serial = match SerialPort::new(ports) {
            Ok(serial) => serial,
            Err(_) => panic!("fixed COM1 allocation must contain eight ports"),
        };
        Self { serial }
    }
}

pub(crate) static LOGGER: KernelLogger = KernelLogger::new();

/// グローバルログバッファからデータを読み出す
pub fn peek_global_log(dst: &mut [u8]) -> usize {
    LOG_BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .peek_bulk(dst)
}

/// グローバルログバッファ内のデータ長を取得
pub fn get_log_len() -> usize {
    LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// ロガー初期化
pub fn init() -> Result<(), LogInitError> {
    init_serial().map_err(LogInitError::Serial)?;
    loop {
        match LOGGER_INITIALIZED.compare_exchange(
            LOGGER_UNINITIALIZED,
            LOGGER_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(LOGGER_READY) => return Ok(()),
            Err(LOGGER_INITIALIZING) => core::hint::spin_loop(),
            Err(_) => unreachable!("logger initialization state is closed"),
        }
    }
    if let Err(error) = log::set_logger(&LOGGER) {
        LOGGER_INITIALIZED.store(LOGGER_UNINITIALIZED, Ordering::Release);
        return Err(LogInitError::Logger(error));
    }
    log::set_max_level(MAX_LOG_LEVEL);
    LOGGER_INITIALIZED.store(LOGGER_READY, Ordering::Release);
    Ok(())
}

/// ヒープ利用可能通知
pub fn notify_heap_available() {
    HEAP_AVAILABLE.store(true, Ordering::Release);
}

/// 実行時ログレベルを設定
pub fn set_log_level(level: LevelFilter) {
    CURRENT_LOG_LEVEL.store(level as u8, Ordering::Relaxed);
    log::set_max_level(level);
}

/// 現在のログレベルを取得
pub fn current_log_level() -> LevelFilter {
    LevelFilter::iter()
        .nth(CURRENT_LOG_LEVEL.load(Ordering::Relaxed) as usize)
        .unwrap_or(LevelFilter::Info)
}

pub fn set_console_mirror_enabled(enabled: bool) {
    CONSOLE_MIRROR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn console_mirror_enabled() -> bool {
    CONSOLE_MIRROR_ENABLED.load(Ordering::Relaxed)
}

pub fn set_serial_output_enabled(enabled: bool) {
    SERIAL_OUTPUT_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn serial_output_enabled() -> bool {
    SERIAL_OUTPUT_ENABLED.load(Ordering::Relaxed)
}

pub fn is_in_panic() -> bool {
    IN_PANIC.load(Ordering::Relaxed)
}

pub fn set_in_panic(in_panic: bool) {
    IN_PANIC.store(in_panic, Ordering::Relaxed);
}

#[inline]
fn current_log_cpu_id() -> Option<crate::cpu::CpuId> {
    crate::cpu::CurrentCpu::acquire().map(|current| current.id())
}

#[inline]
fn panic_output_owner(value: u16) -> Option<crate::cpu::CpuId> {
    if value == PANIC_OUTPUT_NO_OWNER {
        None
    } else {
        Some(crate::cpu::CpuId::new(value).expect("panic output owner must be a valid CPU ID"))
    }
}

#[inline]
fn panic_output_allowed_for_owner(
    owner: Option<crate::cpu::CpuId>,
    cpu_id: Option<crate::cpu::CpuId>,
) -> bool {
    owner.is_none() || cpu_id == owner
}

pub(crate) fn panic_output_allowed() -> bool {
    if !IN_PANIC.load(Ordering::Relaxed) {
        return true;
    }

    let owner = panic_output_owner(PANIC_OUTPUT_OWNER.load(Ordering::Acquire));
    panic_output_allowed_for_owner(owner, current_log_cpu_id())
}

pub fn enter_panic_mode() {
    set_in_panic(true);
    if let Some(cpu_id) = current_log_cpu_id() {
        let _ = PANIC_OUTPUT_OWNER.compare_exchange(
            PANIC_OUTPUT_NO_OWNER,
            cpu_id.as_u16(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    LOGGER.reset_serial_for_panic();
}

/// Debug-only single-byte serial marker.
///
/// These markers are intentionally lossy: they are dropped while panic output is
/// active or whenever the serial lock is busy, so they never corrupt panic
/// diagnostics.
pub fn debug_serial_mark(marker: u8) {
    if !DEBUG_SERIAL_MARKS_ENABLED {
        let _ = marker;
        return;
    }

    if !serial_output_enabled() || IN_PANIC.load(Ordering::Relaxed) {
        return;
    }

    let Some(_guard) = SERIAL_LOCK.try_lock().ok() else {
        return;
    };

    LOGGER.write_char_raw(marker);
}

/// 早期ブート出力（文字列）
///
/// 通常時はベストエフォート出力とし、シリアルロックが取れない場合は
/// 文字列を破損させるより静かにドロップする。panic 時は device lock を
/// 奪わず、取得できないバイトを捨てる。
pub fn early_print(s: &str) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        None
    } else {
        let Some(guard) = SERIAL_LOCK.try_lock().ok() else {
            return;
        };
        Some(guard)
    };
    LOGGER.write_raw(s);
}

/// 早期ブート出力（1文字）
pub fn early_print_char(c: u8) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        None
    } else {
        let Some(guard) = SERIAL_LOCK.try_lock().ok() else {
            return;
        };
        Some(guard)
    };
    LOGGER.write_char_raw(c);
}

#[inline]
fn ascii_bytes_to_str(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).expect("early numeric buffers contain only ASCII")
}

/// 10進数出力
pub fn early_print_dec(n: u64) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        None
    } else {
        let Some(guard) = SERIAL_LOCK.try_lock().ok() else {
            return;
        };
        Some(guard)
    };
    let mut value = n;
    let mut buf = [0u8; 20];
    let mut start = buf.len();

    if value == 0 {
        start -= 1;
        buf[start] = b'0';
    } else {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while value > 0 {
            start -= 1;
            buf[start] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }

    LOGGER.write_raw(ascii_bytes_to_str(&buf[start..]));
}

/// 16進数出力
pub fn early_print_hex(n: u64) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        None
    } else {
        let Some(guard) = SERIAL_LOCK.try_lock().ok() else {
            return;
        };
        Some(guard)
    };
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';

    let mut shift = 60u32;
    let mut idx = 2usize;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while idx < buf.len() {
        let digit = ((n >> shift) & 0xF) as u8;
        buf[idx] = match digit {
            0..=9 => b'0' + digit,
            _ => b'a' + (digit - 10),
        };
        idx += 1;
        shift = shift.saturating_sub(4);
    }

    LOGGER.write_raw(ascii_bytes_to_str(&buf));
}

/// 改行直前の空白を除去する
pub fn trim_spaces_before_newline(s: &str) -> alloc::string::String {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return alloc::string::String::new();
    }

    let mut out = alloc::string::String::with_capacity(bytes.len());
    let mut i = 0usize;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while out.as_bytes().last().copied() == Some(b' ') {
                out.pop();
            }
            out.push('\n');
            i += 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU16;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn panic_owner_allows_output_when_cpu_id_is_unavailable() {
        let cpu0 = crate::cpu::CpuId::BOOTSTRAP;
        let cpu1 = crate::cpu::CpuId::new(1).unwrap();
        assert!(panic_output_allowed_for_owner(None, None));
        assert!(!panic_output_allowed_for_owner(Some(cpu0), None));
        assert!(panic_output_allowed_for_owner(Some(cpu0), Some(cpu0)));
        assert!(!panic_output_allowed_for_owner(Some(cpu1), Some(cpu0)));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn panic_owner_is_not_pinned_without_cpu_identity() {
        let owner = AtomicU16::new(PANIC_OUTPUT_NO_OWNER);

        if let Some(cpu_id) = None::<crate::cpu::CpuId> {
            let _ = owner.compare_exchange(
                PANIC_OUTPUT_NO_OWNER,
                cpu_id.as_u16(),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }

        assert_eq!(owner.load(Ordering::Acquire), PANIC_OUTPUT_NO_OWNER);
    }
}
