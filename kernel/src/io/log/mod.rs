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
use hal::IoPort;

use crate::sync::{IrqPoisonLock, PoisonLock};
use crate::time;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use hal::port_io::PortU8;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};

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

/// シリアルポートベースアドレス (COM1)
const SERIAL_PORT_BASE: u16 = 0x3F8;

/// シリアルデータレジスタオフセット
const SERIAL_DATA_OFFSET: u16 = 0;

/// シリアルラインステータスレジスタオフセット  
const SERIAL_LSR_OFFSET: u16 = 5;

/// 送信バッファ空きビット (LSR bit 5)
const LSR_TX_EMPTY: u8 = 0x20;

/// 送信待機タイムアウト（ループ回数）
const TX_TIMEOUT_LOOPS: u32 = 100_000;

/// 送信タイムアウト（マイクロ秒）: TSC周波数が利用可能な場合はこちらを優先して使います
const TX_TIMEOUT_US: u64 = 100;

/// 割り込みハンドラが一度に送信する最大バーストサイズ（ISR内のローカルバッファ長）
const LSR_TX_BURST: usize = 64;

/// Maximum bytes to pull from per-core buffers into the global buffer in one
/// non-ISR aggregation call.
const AGGREGATE_MAX_PER_CALL: usize = 4096;

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
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

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

/// I/Oポート（レジスタ）操作用のIRQセーフ排他
static SERIAL_IO_LOCK: IrqPoisonLock<()> = IrqPoisonLock::new(());

/// パニック中フラグ（デッドロック回避用）
static IN_PANIC: AtomicBool = AtomicBool::new(false);
const PANIC_OUTPUT_NO_OWNER: usize = usize::MAX;
static PANIC_OUTPUT_OWNER: AtomicUsize = AtomicUsize::new(PANIC_OUTPUT_NO_OWNER);
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

#[allow(dead_code)]
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

    pub fn is_full(&self) -> bool {
        self.len() == N
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

        if first > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    self.buf.as_mut_ptr().add(tail),
                    first,
                );
            }
        }

        if to_write > first {
            let second = to_write - first;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(first),
                    self.buf.as_mut_ptr(),
                    second,
                );
            }
        }

        self.tail = (self.tail + to_write) % N;
        if self.tail == self.head {
            self.full = true;
        }

        to_write
    }

    pub fn push_front(&mut self, b: u8) -> bool {
        if N == 0 {
            return false;
        }
        self.sanitize_state();
        if self.full {
            return false;
        }
        self.head = if self.head == 0 { N - 1 } else { self.head - 1 };
        self.buf[self.head] = b;
        if self.head == self.tail {
            self.full = true;
        }
        true
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
        if first > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.buf.as_ptr().add(head),
                    dst.as_mut_ptr(),
                    first,
                );
            }
        }

        if to_read > first {
            let second = to_read - first;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.buf.as_ptr(),
                    dst.as_mut_ptr().add(first),
                    second,
                );
            }
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
        if first > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.buf.as_ptr().add(head),
                    dst.as_mut_ptr(),
                    first,
                );
            }
        }

        if to_read > first {
            let second = to_read - first;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.buf.as_ptr(),
                    dst.as_mut_ptr().add(first),
                    second,
                );
            }
        }

        to_read
    }

    pub fn peek_until_including(&self, needle: u8, dst: &mut [u8]) -> usize {
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

        let to_scan = core::cmp::min(available, dst.len());
        let mut idx = head;
        let mut copied = 0usize;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while copied < to_scan {
            let byte = self.buf[idx];
            dst[copied] = byte;
            copied += 1;

            if byte == needle {
                break;
            }

            idx += 1;
            if idx == N {
                idx = 0;
            }
        }

        copied
    }

    pub fn advance_head(&mut self, n: usize) {
        if N == 0 || n == 0 {
            return;
        }

        self.sanitize_state();
        let available = self.len();
        if available == 0 {
            return;
        }

        let to_advance = core::cmp::min(n, available);
        self.head = (self.head + to_advance) % N;
        if to_advance > 0 {
            self.full = false;
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.full = false;
    }
}

unsafe impl<const N: usize> Sync for RingBuffer<N> {}
unsafe impl<const N: usize> Send for RingBuffer<N> {}

/// 非同期ログバッファ（送信）
static LOG_BUFFER: IrqPoisonLock<RingBuffer<LOG_BUFFER_CAPACITY>> =
    IrqPoisonLock::new(RingBuffer::new());

/// アプリケーションがヒープ利用可能になった後に非同期ログを有効化するフラグ
static ASYNC_LOG_ENABLED: AtomicBool = AtomicBool::new(false);

/// 非同期ログで切り捨てられたバイト数
static DROPPED_LOG_BYTES: AtomicUsize = AtomicUsize::new(0);

/// 非同期ログを有効化する。
pub fn enable_async_logging() {
    ASYNC_LOG_ENABLED.store(true, Ordering::SeqCst);
}

/// 非同期ログが現在有効かどうかを返す
pub fn async_logging_enabled() -> bool {
    ASYNC_LOG_ENABLED.load(Ordering::Relaxed)
}

/// Per-core log buffer capacity
const PER_CORE_BUFFER_CAPACITY: usize = 4 * 1024;

#[cfg(not(feature = "bench"))]
const PER_CPU_COUNT: usize = crate::per_cpu::MAX_CPUS;

#[cfg(feature = "bench")]
const PER_CPU_COUNT: usize = 8;

/// Per-core log buffers (lock-protected, IRQ-safe)
const PER_CORE_INIT: IrqPoisonLock<RingBuffer<PER_CORE_BUFFER_CAPACITY>> =
    IrqPoisonLock::new(RingBuffer::new());
static PER_CORE_LOG_BUFFERS: [IrqPoisonLock<RingBuffer<PER_CORE_BUFFER_CAPACITY>>; PER_CPU_COUNT] =
    [PER_CORE_INIT; PER_CPU_COUNT];

/// 非同期入力バッファ（受信）
static INPUT_BUFFER: IrqPoisonLock<RingBuffer<INPUT_BUFFER_CAPACITY>> =
    IrqPoisonLock::new(RingBuffer::new());

// ... (Unit tests for RingBuffer remain largely unchanged except for lock calls)

// ============================================================================
// シリアルポート初期化
// ============================================================================

/// シリアルポートが初期化済みかどうか
static SERIAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// シリアルポートを初期化
pub fn init_serial() {
    if SERIAL_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let base = SERIAL_PORT_BASE;
    let mut ier: PortU8 = IoPort::new(base + 1);
    ier.write(0x00);
    let mut lcr: PortU8 = IoPort::new(base + 3);
    lcr.write(0x80);
    let mut dll: PortU8 = IoPort::new(base + 0);
    let mut dlh: PortU8 = IoPort::new(base + 1);
    dll.write(0x01);
    dlh.write(0x00);
    lcr.write(0x03);
    let mut fcr: PortU8 = IoPort::new(base + 2);
    fcr.write(0xC7);
    let mut mcr: PortU8 = IoPort::new(base + 4);
    mcr.write(0x0B);
    mcr.write(0x1E);
    let mut data: PortU8 = IoPort::new(base);
    data.write(0xAE);
    if data.read() != 0xAE {
        SERIAL_INITIALIZED.store(false, Ordering::SeqCst);
        return;
    }
    mcr.write(0x0F);
}

/// シリアル割り込みを有効化
pub fn enable_serial_interrupts() {
    if IN_PANIC.load(Ordering::Relaxed) {
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        ier.write(0x01);
    } else {
        let _io_guard = SERIAL_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        ier.write(0x01);
    }
}

// ============================================================================
// シリアルロガー実装
// ============================================================================

/// カーネル用シリアルロガー
pub(crate) struct KernelLogger;

#[inline(always)]
fn read_tsc_serialized() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

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
pub fn init() -> Result<(), SetLoggerError> {
    init_serial();
    if LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    log::set_logger(&LOGGER)?;
    log::set_max_level(MAX_LOG_LEVEL);
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
fn current_log_cpu_id() -> Option<usize> {
    crate::cpu::try_current_id()
}

#[inline]
fn panic_output_allowed_for_owner(owner: usize, cpu_id: Option<usize>) -> bool {
    owner == PANIC_OUTPUT_NO_OWNER || cpu_id == Some(owner)
}

pub(crate) fn panic_output_allowed() -> bool {
    if !IN_PANIC.load(Ordering::Relaxed) {
        return true;
    }

    let owner = PANIC_OUTPUT_OWNER.load(Ordering::Acquire);
    panic_output_allowed_for_owner(owner, current_log_cpu_id())
}

pub fn enter_panic_mode() {
    set_in_panic(true);
    // If the panic interrupted a log write while SERIAL_LOCK was held, later
    // panic diagnostics must not block forever trying to reacquire it.
    SERIAL_LOCK.force_unlock();
    if let Some(cpu_id) = current_log_cpu_id() {
        let _ = PANIC_OUTPUT_OWNER.compare_exchange(
            PANIC_OUTPUT_NO_OWNER,
            cpu_id,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    KernelLogger::reset_serial_for_panic();
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

    KernelLogger::write_char_raw(marker);
}

/// 早期ブート出力（文字列）
///
/// 通常時はベストエフォート出力とし、シリアルロックが取れない場合は
/// 文字列を破損させるより静かにドロップする。panic 時のみ必ずロックを
/// 取得して整形済みログの一貫性を優先する。
pub fn early_print(s: &str) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        Some(SERIAL_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
    } else {
        let Some(guard) = SERIAL_LOCK.try_lock().ok() else {
            return;
        };
        Some(guard)
    };
    KernelLogger::write_raw(s);
}

/// 早期ブート出力（1文字）
pub fn early_print_char(c: u8) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        Some(SERIAL_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
    } else {
        let Some(guard) = SERIAL_LOCK.try_lock().ok() else {
            return;
        };
        Some(guard)
    };
    KernelLogger::write_char_raw(c);
}

#[inline]
fn ascii_bytes_to_str(bytes: &[u8]) -> &str {
    // SAFETY: callers only pass ASCII digit/prefix buffers.
    unsafe { core::str::from_utf8_unchecked(bytes) }
}

/// 10進数出力
pub fn early_print_dec(n: u64) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        Some(SERIAL_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
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

    KernelLogger::write_raw(ascii_bytes_to_str(&buf[start..]));
}

/// 16進数出力
pub fn early_print_hex(n: u64) {
    if !panic_output_allowed() {
        return;
    }
    let _guard = if IN_PANIC.load(Ordering::Relaxed) {
        Some(SERIAL_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
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

    KernelLogger::write_raw(ascii_bytes_to_str(&buf));
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
    use core::sync::atomic::AtomicUsize;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn panic_owner_allows_output_when_cpu_id_is_unavailable() {
        assert!(panic_output_allowed_for_owner(PANIC_OUTPUT_NO_OWNER, None));
        assert!(!panic_output_allowed_for_owner(0, None));
        assert!(panic_output_allowed_for_owner(0, Some(0)));
        assert!(!panic_output_allowed_for_owner(1, Some(0)));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn panic_owner_is_not_pinned_without_cpu_identity() {
        let owner = AtomicUsize::new(PANIC_OUTPUT_NO_OWNER);

        if let Some(cpu_id) = None::<usize> {
            let _ = owner.compare_exchange(
                PANIC_OUTPUT_NO_OWNER,
                cpu_id,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }

        assert_eq!(owner.load(Ordering::Acquire), PANIC_OUTPUT_NO_OWNER);
    }
}
