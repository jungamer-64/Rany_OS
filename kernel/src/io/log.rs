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

use crate::sync::IrqMutex;
use crate::time;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use hal::port_io::PortU8;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use spin::Mutex;

// ============================================================================
// 定数定義
// ============================================================================

/// 非同期ログバッファの容量 (16KB)
mod logger_impl;
pub use logger_impl::*;
mod serial_output;
pub use serial_output::*;
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
///
/// ## 注意: CPU周波数依存
/// この値はCPU周波数に依存します。
/// - 1GHz CPUで約100μs
/// - 3GHz CPUで約33μs
/// の待機時間となります。
///
/// ## 将来の改善方針
/// 早期ブート時はタイマーが利用できないためループカウンタを使用していますが、
/// ヒープ初期化後・タイマー初期化後は以下の改善が可能です：
///
/// 1. **タイマーベースの待機**: HPETやAPICタイマーを使用した正確なタイムアウト
/// 2. **非同期ロギング**: リングバッファへの書き込み + 割り込みベースの送信
/// 3. **ロギングレベルの切り替え**: 初期化完了後に高機能ロガーへ移行
///
/// 現時点では、パニック時の信頼性を優先してシンプルなポーリング方式を維持しています。
const TX_TIMEOUT_LOOPS: u32 = 100_000;

/// 送信タイムアウト（マイクロ秒）: TSC周波数が利用可能な場合はこちらを優先して使います
const TX_TIMEOUT_US: u64 = 100;

/// 割り込みハンドラが一度に送信する最大バーストサイズ（ISR内のローカルバッファ長）
/// 16550互換デバイスのFIFOは通常16バイトですが、割り込み頻度低減のため大きめに確保しています。
const ISR_TX_BURST: usize = 64;

/// Maximum bytes to pull from per-core buffers into the global buffer in one
/// non-ISR aggregation call. Kept modest to avoid long blocking in writers.
const AGGREGATE_MAX_PER_CALL: usize = 1024;

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

/// シリアルポート排他制御用Spinlock
///
/// マルチコア環境や割り込みコンテキストでの同時アクセスを防ぐ。
/// 注意: パニックハンドラからの出力時はデッドロック回避のため
/// ロックを試行せず直接出力する（try_lockを使用）。
static SERIAL_LOCK: Mutex<()> = Mutex::new(());

/// I/Oポート（レジスタ）操作用のIRQセーフ排他
///
/// IER のような共有レジスタを read-modify-write する際に競合を避けるため、
/// このロックを使って操作を原子的に行います。
static SERIAL_IO_LOCK: IrqMutex<()> = IrqMutex::new(());

/// パニック中フラグ（デッドロック回避用）
static IN_PANIC: AtomicBool = AtomicBool::new(false);

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
        if self.full {
            N
        } else if self.tail >= self.head {
            self.tail - self.head
        } else {
            N - self.head + self.tail
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.full && (self.head == self.tail)
    }

    pub fn is_full(&self) -> bool {
        self.full
    }

    pub fn push_byte(&mut self, b: u8) -> bool {
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
        debug_assert!(N > 0);
        debug_assert!(self.tail < N && self.head < N);

        // Calculate available space
        let avail = self.capacity() - self.len();
        if avail == 0 {
            return 0;
        }

        let to_write = core::cmp::min(avail, src.len());
        if to_write == 0 {
            return 0;
        }

        // First contiguous chunk (to end of buffer)
        let first = core::cmp::min(to_write, N - self.tail);

        debug_assert!(first <= to_write && first <= N - self.tail);

        if first > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    self.buf.as_mut_ptr().add(self.tail),
                    first,
                );
            }
        }

        if to_write > first {
            let second = to_write - first;
            debug_assert!(second <= N);
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

    /// 先頭に1バイト挿入（未使用時にのみ、ISRからの再挿入用）
    pub fn push_front(&mut self, b: u8) -> bool {
        debug_assert!(N > 0);
        if self.full {
            return false;
        }
        self.head = if self.head == 0 { N - 1 } else { self.head - 1 };
        debug_assert!(self.head < N);
        self.buf[self.head] = b;
        if self.head == self.tail {
            self.full = true;
        }
        true
    }

    pub fn pop_one(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        debug_assert!(self.head < N);
        let b = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.full = false;
        Some(b)
    }

    pub fn pop_bulk(&mut self, dst: &mut [u8]) -> usize {
        debug_assert!(N > 0);
        debug_assert!(self.head < N && self.tail < N);
        let available = self.len();
        if available == 0 || dst.is_empty() {
            return 0;
        }

        let to_read = core::cmp::min(available, dst.len());

        // First contiguous chunk
        let first = core::cmp::min(to_read, N - self.head);
        debug_assert!(first <= to_read);
        if first > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.buf.as_ptr().add(self.head),
                    dst.as_mut_ptr(),
                    first,
                );
            }
        }

        if to_read > first {
            let second = to_read - first;
            debug_assert!(second <= N);
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

    /// Copy up to dst.len() bytes from the head without advancing it.
    pub fn peek_bulk(&self, dst: &mut [u8]) -> usize {
        debug_assert!(N > 0);
        debug_assert!(self.head < N && self.tail < N);
        let available = self.len();
        if available == 0 || dst.is_empty() {
            return 0;
        }

        let to_read = core::cmp::min(available, dst.len());
        let first = core::cmp::min(to_read, N - self.head);
        if first > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.buf.as_ptr().add(self.head),
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

    /// Advance the head by `n` bytes (must be <= len())
    pub fn advance_head(&mut self, n: usize) {
        debug_assert!(n <= self.len());
        self.head = (self.head + n) % N;
        if n > 0 {
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
static LOG_BUFFER: IrqMutex<RingBuffer<LOG_BUFFER_CAPACITY>> = IrqMutex::new(RingBuffer::new());

/// 非同期ログで切り捨てられたバイト数
static DROPPED_LOG_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Per-core log buffer capacity (default per-core to 4 KiB)
const PER_CORE_BUFFER_CAPACITY: usize = 4 * 1024;

// Number of per-core buffers. When building benches we cannot rely on the full
// `crate::mm::per_cpu` module being available, so provide a compile-time
// fallback to a reasonable default.
#[cfg(not(feature = "bench"))]
const PER_CPU_COUNT: usize = crate::mm::per_cpu::MAX_CPUS;

#[cfg(feature = "bench")]
const PER_CPU_COUNT: usize = 8;

/// Per-core log buffers (lock-protected, IRQ-safe)
const PER_CORE_INIT: IrqMutex<RingBuffer<PER_CORE_BUFFER_CAPACITY>> =
    IrqMutex::new(RingBuffer::new());
static PER_CORE_LOG_BUFFERS: [IrqMutex<RingBuffer<PER_CORE_BUFFER_CAPACITY>>; PER_CPU_COUNT] =
    [PER_CORE_INIT; PER_CPU_COUNT];


/// 非同期入力バッファ（受信）
static INPUT_BUFFER: IrqMutex<RingBuffer<INPUT_BUFFER_CAPACITY>> = IrqMutex::new(RingBuffer::new());

// Unit tests for RingBuffer
#[cfg(test)]
mod ringbuffer_tests {
    use super::*;

    #[test_case]
    fn ringbuffer_push_pop_simple() {
        let mut rb = RingBuffer::<8>::new();
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
        assert!(rb.push_byte(1));
        assert!(rb.push_byte(2));
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.pop_one(), Some(1));
        assert_eq!(rb.pop_one(), Some(2));
        assert_eq!(rb.pop_one(), None);
    }

    #[test_case]
    fn ringbuffer_wrap_and_overflow() {
        let mut rb = RingBuffer::<4>::new();
        assert_eq!(rb.push_bytes(&[1, 2, 3, 4]), 4);
        assert!(rb.is_full());
        assert!(!rb.push_byte(5));
        assert_eq!(rb.pop_one(), Some(1));
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.push_bytes(&[6, 7]), 1);
    }
    #[test_case]
    fn push_front_and_restore() {
        let mut rb = RingBuffer::<8>::new();
        rb.push_bytes(&[1, 2, 3]);
        assert_eq!(rb.pop_one(), Some(1));
        assert!(rb.push_front(1));
        assert_eq!(rb.pop_one(), Some(1));
        assert_eq!(rb.pop_one(), Some(2));
        assert_eq!(rb.pop_one(), Some(3));
    }

    #[test_case]
    fn push_front_overflow() {
        let mut rb = RingBuffer::<3>::new();
        assert_eq!(rb.push_bytes(&[1, 2, 3]), 3);
        assert!(!rb.push_front(4));
    }

    #[test_case]
    fn push_bytes_wrap_and_pop_bulk() {
        // Buffer size 8
        let mut rb = RingBuffer::<8>::new();
        assert_eq!(rb.push_bytes(&[1u8, 2, 3, 4, 5, 6]), 6);

        // Pop 4 elements
        let mut out = [0u8; 4];
        assert_eq!(rb.pop_bulk(&mut out), 4);
        assert_eq!(out, [1, 2, 3, 4]);

        // Push bytes that wrap around the buffer end
        assert_eq!(rb.push_bytes(&[7u8, 8, 9, 10, 11]), 5);

        // Now the buffer should contain [5,6,7,8,9,10,11]
        let mut out2 = [0u8; 7];
        assert_eq!(rb.pop_bulk(&mut out2), 7);
        assert_eq!(out2, [5, 6, 7, 8, 9, 10, 11]);
    }

    #[test_case]
    fn per_core_buffer_smoke() {
        // Write to per-core buffer index 0
        let mut guard = PER_CORE_LOG_BUFFERS[0].lock();
        assert_eq!(guard.push_bytes(&[10, 20, 30]), 3);
        assert_eq!(guard.pop_one(), Some(10));
        assert_eq!(guard.pop_one(), Some(20));
        drop(guard);
    }
    #[test_case]
    fn pop_bulk() {
        let mut rb = RingBuffer::<8>::new();
        rb.push_bytes(&[1, 2, 3, 4, 5]);
        let mut buf = [0u8; 3];
        let n = rb.pop_bulk(&mut buf);
        assert_eq!(n, 3);
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(rb.len(), 2);
    }

    #[test_case]
    fn peek_and_advance() {
        let mut rb = RingBuffer::<8>::new();
        assert_eq!(rb.push_bytes(&[1u8, 2, 3, 4, 5]), 5);
        let mut out = [0u8; 4];
        assert_eq!(rb.peek_bulk(&mut out), 4);
        assert_eq!(out, [1, 2, 3, 4]);
        rb.advance_head(2);
        let mut out2 = [0u8; 3];
        assert_eq!(rb.pop_bulk(&mut out2), 3);
        assert_eq!(out2, [3, 4, 5]);
    }

    #[test_case]
    fn aggregate_per_core_to_global_smoke() {
        // Put some data into per-core buffer 0
        let mut g = PER_CORE_LOG_BUFFERS[0].lock();
        assert_eq!(g.push_bytes(&[0xAAu8; 100]), 100);
        drop(g);

        let moved = aggregate_per_core_to_global(200);
        assert!(moved > 0);

        let mut tmp = [0u8; 200];
        let n = LOG_BUFFER.lock().pop_bulk(&mut tmp);
        assert_eq!(n, moved);
    }

    #[test_case]
    fn kick_serial_tx_aggregates_to_global() {
        // Clear buffers
        LOG_BUFFER.lock().clear();
        for i in 0..PER_CPU_COUNT {
            PER_CORE_LOG_BUFFERS[i].lock().clear();
        }
        DROPPED_LOG_BYTES.store(0, Ordering::Relaxed);

        // Put some data into per-core buffer 0
        let mut g = PER_CORE_LOG_BUFFERS[0].lock();
        assert_eq!(g.push_bytes(&[0xBBu8; 64]), 64);
        drop(g);

        // Kick TX (should aggregate into global buffer)
        // NOTE: In test/bench builds we avoid touching hardware I/O. Call the
        // aggregation helper directly to validate behavior.
        let _moved = aggregate_per_core_to_global(AGGREGATE_MAX_PER_CALL);
        let mut tmp = [0u8; 128];
        let n = LOG_BUFFER.lock().pop_bulk(&mut tmp);
        assert!(n > 0);
    }
}

// ============================================================================
// シリアルポート初期化
// ============================================================================

/// シリアルポートが初期化済みかどうか
static SERIAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// シリアルポートを初期化（COM1, 115200 baud, 8N1）
///
/// 早期ブート時に一度だけ呼び出される。
/// 既に初期化済みの場合は何もしない。
pub fn init_serial() {
    if SERIAL_INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // 既に初期化済み
    }

    let base = SERIAL_PORT_BASE;

    // 割り込み無効化
    let mut ier: PortU8 = IoPort::new(base + 1);
    ier.write(0x00);

    // DLAB有効化（ボーレート設定用）
    let mut lcr: PortU8 = IoPort::new(base + 3);
    lcr.write(0x80);

    // ボーレート設定: 115200 (divisor = 1)
    let mut dll: PortU8 = IoPort::new(base + 0);
    let mut dlh: PortU8 = IoPort::new(base + 1);
    dll.write(0x01); // Divisor low byte
    dlh.write(0x00); // Divisor high byte

    // ライン設定: 8 data bits, no parity, 1 stop bit (8N1)
    lcr.write(0x03);

    // FIFO有効化、バッファクリア、14バイトスレッショルド
    let mut fcr: PortU8 = IoPort::new(base + 2);
    fcr.write(0xC7);

    // モデム制御: DTR, RTS, OUT2（割り込みゲート）
    let mut mcr: PortU8 = IoPort::new(base + 4);
    mcr.write(0x0B);

    // ループバックテスト
    mcr.write(0x1E); // loopback mode
    let mut data: PortU8 = IoPort::new(base);
    data.write(0xAE);
    if data.read() != 0xAE {
        // テスト失敗、初期化フラグをリセット
        SERIAL_INITIALIZED.store(false, Ordering::SeqCst);
        return;
    }

    // 通常モードに戻す
    mcr.write(0x0F);
}

/// シリアル割り込みを有効化
pub fn enable_serial_interrupts() {
    if IN_PANIC.load(Ordering::Relaxed) {
        // Avoid locking during panic: best-effort enable
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        ier.write(0x01);
    } else {
        // Make this atomic across cores
        let _io_guard = SERIAL_IO_LOCK.lock();
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        ier.write(0x01); // Enable RX interrupt only initially. TX is enabled on demand.
    }
}

// ============================================================================
// シリアルロガー実装
// ============================================================================

/// カーネル用シリアルロガー
struct KernelLogger;

#[inline]
fn read_tsc_serialized() -> u64 {
    // Use RDTSC which is supported on all x64 CPUs.
    // We don't strictly need RDTSCP's serialization for simple timeouts.
    unsafe { core::arch::x86_64::_rdtsc() }
}
