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

    #[test]
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

    #[test]
    fn ringbuffer_wrap_and_overflow() {
        let mut rb = RingBuffer::<4>::new();
        assert_eq!(rb.push_bytes(&[1, 2, 3, 4]), 4);
        assert!(rb.is_full());
        assert!(!rb.push_byte(5));
        assert_eq!(rb.pop_one(), Some(1));
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.push_bytes(&[6, 7]), 1);
    }
    #[test]
    fn push_front_and_restore() {
        let mut rb = RingBuffer::<8>::new();
        rb.push_bytes(&[1, 2, 3]);
        assert_eq!(rb.pop_one(), Some(1));
        assert!(rb.push_front(1));
        assert_eq!(rb.pop_one(), Some(1));
        assert_eq!(rb.pop_one(), Some(2));
        assert_eq!(rb.pop_one(), Some(3));
    }

    #[test]
    fn push_front_overflow() {
        let mut rb = RingBuffer::<3>::new();
        assert_eq!(rb.push_bytes(&[1, 2, 3]), 3);
        assert!(!rb.push_front(4));
    }

    #[test]
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

    #[test]
    fn per_core_buffer_smoke() {
        // Write to per-core buffer index 0
        let mut guard = PER_CORE_LOG_BUFFERS[0].lock();
        assert_eq!(guard.push_bytes(&[10, 20, 30]), 3);
        assert_eq!(guard.pop_one(), Some(10));
        assert_eq!(guard.pop_one(), Some(20));
        drop(guard);
    }
    #[test]
    fn pop_bulk() {
        let mut rb = RingBuffer::<8>::new();
        rb.push_bytes(&[1, 2, 3, 4, 5]);
        let mut buf = [0u8; 3];
        let n = rb.pop_bulk(&mut buf);
        assert_eq!(n, 3);
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(rb.len(), 2);
    }

    #[test]
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

    #[test]
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

    #[test]
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

impl KernelLogger {
    /// シリアルポートに1バイト書き込み（内部用、ロックなし）
    ///
    /// 送信バッファが空になるまで待機してから書き込む。
    /// タイムアウト時は書き込みをスキップする。
    #[inline]
    fn write_byte_raw(byte: u8) {
        let mut status_port: PortU8 = IoPort::new(SERIAL_PORT_BASE + SERIAL_LSR_OFFSET);
        let mut data_port: PortU8 = IoPort::new(SERIAL_PORT_BASE + SERIAL_DATA_OFFSET);

        // 送信バッファが空になるまで待つ（タイムアウト付き）
        // 可能ならTSC周波数を使った時間ベースの待機を行い、利用できない場合はループカウントでフォールバックします。
        let mut sent = false;

        // Try time-based wait if TSC frequency is known
        if let Some(freq) = time::system_clock().tsc_frequency() {
            // Compute timeout cycles for TX_TIMEOUT_US microseconds (may be 0 for very low freq)
            let timeout_cycles: u64 = (freq as u64).saturating_mul(TX_TIMEOUT_US) / 1_000_000u64;
            let start = read_tsc_serialized();
            while (status_port.read() & LSR_TX_EMPTY) == 0 {
                if read_tsc_serialized().saturating_sub(start) > timeout_cycles {
                    break;
                }
                core::hint::spin_loop();
            }

            if (status_port.read() & LSR_TX_EMPTY) != 0 {
                data_port.write(byte);
                sent = true;
            }
        } else {
            // Fallback to loop-count-based wait (early boot / when time subsystem isn't initialized)
            let mut timeout = TX_TIMEOUT_LOOPS;
            while (status_port.read() & LSR_TX_EMPTY) == 0 && timeout > 0 {
                core::hint::spin_loop(); // CPU省電力ヒント
                timeout -= 1;
            }

            if timeout > 0 {
                data_port.write(byte);
                sent = true;
            }
        }

        // If we couldn't send due to timeout, we simply drop the byte. On panic, the caller
        // may retry or skip. We purposely avoid blocking indefinitely in low-level debug output.
        let _ = sent;
    }

    /// パニック時にシリアルの状態をできるだけクリーンにする試み（FIFOクリア等）
    fn reset_serial_for_panic() {
        // Try to clear FIFOs and disable interrupts to leave the port in a known state.
        let mut fcr: PortU8 = IoPort::new(SERIAL_PORT_BASE + 2);
        fcr.write(0x07); // enable FIFOs and clear RX/TX

        // In panic mode we must not block on locks - perform direct writes to the
        // serial registers. This can race with other cores but avoids deadlocks
        // that would prevent panic output from ever being delivered.
        if IN_PANIC.load(Ordering::Relaxed) {
            let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
            ier.write(0x00); // disable serial interrupts (best-effort)
            return;
        }

        // Otherwise perform atomic RMW using SERIAL_IO_LOCK
        let _io_guard = SERIAL_IO_LOCK.lock();
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        ier.write(0x00); // disable serial interrupts
    }

    /// シリアルポートに直接書き込み（ロックなし、早期ブート/パニック用）
    ///
    /// ロックは `Log::log()` 実装側で取得するため、この関数自体はロックを取らない。
    /// 早期ブート時やパニック時に直接呼び出される。
    fn write_raw(s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                // LFをCRLFに変換（ターミナル互換性）
                Self::write_byte_raw(b'\r');
            }
            Self::write_byte_raw(byte);
        }
    }

    /// シリアルポートに1文字書き込み（ロックなし）
    ///
    /// `write_byte_raw`のエイリアス。早期ブート用関数からの呼び出しに使用。
    #[inline]
    fn write_char_raw(c: u8) {
        Self::write_byte_raw(c);
    }

    /// ログレベルのプレフィックスを取得
    fn level_prefix(level: Level) -> &'static str {
        match level {
            Level::Error => "[ERROR] ",
            Level::Warn => "[WARN]  ",
            Level::Info => "[INFO]  ",
            Level::Debug => "[DEBUG] ",
            Level::Trace => "[TRACE] ",
        }
    }

    /// ログレベルに応じた色コード（ANSIエスケープシーケンス）
    #[allow(dead_code)]
    fn level_color(level: Level) -> &'static str {
        match level {
            Level::Error => "\x1b[31m", // 赤
            Level::Warn => "\x1b[33m",  // 黄
            Level::Info => "\x1b[32m",  // 緑
            Level::Debug => "\x1b[36m", // シアン
            Level::Trace => "\x1b[37m", // 白
        }
    }

    /// Write a record into an async RingBuffer (generic over its capacity)
    fn write_into_async_buffer<const N: usize>(&self, buf: &mut RingBuffer<N>, record: &Record) {
        let writer = AsyncLogWriter::<N>::new(buf);
        let mut tracker = LastCharTracker::new(writer);

        self.print_header(&mut tracker, record);
        let _ = write!(tracker, "{}", record.args());

        if tracker.last_char != b'\n' {
            let _ = tracker.inner.write_str("\r\n");
        }
    }

    fn print_header<W: Write>(&self, w: &mut W, record: &Record) {
        // Timestamp and Core ID
        // Use the RTC when available; for test/bench builds use the test shim in `crate::time`
        #[cfg(any(test, feature = "bench"))]
        let uptime_ms = crate::time::get_uptime_ms();
        #[cfg(not(any(test, feature = "bench")))]
        let uptime_ms = crate::io::rtc::get_uptime_ms();

        let core_id = {
            #[cfg(not(feature = "bench"))]
            {
                crate::smp_advanced::current_core_id()
            }
            #[cfg(feature = "bench")]
            {
                0usize
            }
        };
        let secs = uptime_ms / 1000;
        let millis = uptime_ms % 1000;

        let _ = write!(w, "[");
        // Pad seconds to 5 spaces for alignment
        if secs < 10000 {
            let _ = write!(w, " ");
        }
        if secs < 1000 {
            let _ = write!(w, " ");
        }
        if secs < 100 {
            let _ = write!(w, " ");
        }
        if secs < 10 {
            let _ = write!(w, " ");
        }
        let _ = write!(w, "{}.{:03}] [C{}] ", secs, millis, core_id);

        // ログレベルプレフィックス
        let _ = write!(w, "{}", Self::level_prefix(record.level()));

        // モジュールパス（オプション）
        let target = record.target();
        if !target.is_empty() {
            let _ = write!(w, "[{}] ", target);
        }
    }
}

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

        let use_async = HEAP_AVAILABLE.load(Ordering::Relaxed) && !IN_PANIC.load(Ordering::Relaxed);

        if use_async {
            // Prefer per-core buffer when possible (reduces global contention)
            let mut wrote_async = false;

            if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
                if cpu_id < PER_CPU_COUNT {
                    if let Some(mut guard) = PER_CORE_LOG_BUFFERS[cpu_id].try_lock() {
                        self.write_into_async_buffer::<{ PER_CORE_BUFFER_CAPACITY }>(
                            &mut guard, record,
                        );
                        drop(guard);
                        wrote_async = true;
                    }
                }
            }

            // Global fallback if per-core wasn't available or no CPU id
            if !wrote_async {
                if let Some(mut guard) = LOG_BUFFER.try_lock() {
                    self.write_into_async_buffer::<{ LOG_BUFFER_CAPACITY }>(&mut guard, record);
                    drop(guard);
                    wrote_async = true;
                }
            }

            if wrote_async {
                start_serial_tx();
            } else {
                // Can't do async (contended) -> fall back to sync try_lock or direct write to avoid blocking
                let guard = if IN_PANIC.load(Ordering::Relaxed) {
                    None
                } else {
                    SERIAL_LOCK.try_lock()
                };

                if guard.is_some() {
                    let mut tracker = LastCharTracker::new(SyncLogWriter);
                    self.print_header(&mut tracker, record);
                    let _ = write!(tracker, "{}", record.args());
                    if tracker.last_char != b'\n' {
                        let _ = tracker.inner.write_str("\r\n");
                    }
                } else {
                    // As a last resort, write raw without locks (used for panic or high contention)
                    let mut tracker = LastCharTracker::new(SyncLogWriter);
                    self.print_header(&mut tracker, record);
                    let _ = write!(tracker, "{}", record.args());
                    if tracker.last_char != b'\n' {
                        let _ = tracker.inner.write_str("\r\n");
                    }
                }
            }
        } else {
            // 同期出力
            let _guard = if IN_PANIC.load(Ordering::Relaxed) {
                None
            } else {
                Some(SERIAL_LOCK.lock())
            };
            let mut tracker = LastCharTracker::new(SyncLogWriter);
            self.print_header(&mut tracker, record);
            let _ = write!(tracker, "{}", record.args());
            if tracker.last_char != b'\n' {
                let _ = tracker.inner.write_str("\r\n");
            }
        }

        // 画面への出力（統合実装）
        // パニック中以外、かつロックが取得できた場合のみ出力してデッドロックを回避する
        #[cfg(not(feature = "bench"))]
        if !is_in_panic() {
            if let Some(mut guard) = crate::graphics::global::try_lock_console() {
                if let Some(console) = guard.as_mut() {
                    use core::fmt::Write;
                    let _ = write!(console, "{}\n", record.args());
                }
            }
        }
    }

    fn flush(&self) {
        // シリアル出力はバッファリングしないため何もしない
    }
}

/// `Write` トレイトを実装し、最後の文字を追跡するラッパー
struct LastCharTracker<W: Write> {
    inner: W,
    last_char: u8,
}

impl<W: Write> LastCharTracker<W> {
    fn new(inner: W) -> Self {
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

struct SyncLogWriter;
impl Write for SyncLogWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        KernelLogger::write_raw(s);
        Ok(())
    }
}

struct AsyncLogWriter<'a, const N: usize> {
    buffer: &'a mut RingBuffer<N>,
}

impl<'a, const N: usize> AsyncLogWriter<'a, N> {
    fn new(buffer: &'a mut RingBuffer<N>) -> Self {
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

/// シリアル送信を開始（割り込み有効化）
fn start_serial_tx() {
    // Aggregate per-core buffers into the global buffer in non-ISR context.
    // This keeps ISR work minimal: only the global buffer is drained.
    // Aggregation is also performed by the executor idle loop; this function
    // remains the canonical way to kick the transmitter.
    if !IN_PANIC.load(Ordering::Relaxed) {
        let _ = aggregate_per_core_to_global(AGGREGATE_MAX_PER_CALL);
    }

    if IN_PANIC.load(Ordering::Relaxed) {
        // Avoid locking during panic: direct RMW
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        let current = ier.read();
        if (current & 0x02) == 0 {
            ier.write(current | 0x02);
        }
    } else {
        // IER RMW is atomic across cores
        let _io_guard = SERIAL_IO_LOCK.lock();
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        let current = ier.read();
        if (current & 0x02) == 0 {
            ier.write(current | 0x02);
        }
    }
}

/// シリアル割り込みハンドラ
pub fn handle_serial_interrupt() {
    let mut iir: PortU8 = IoPort::new(SERIAL_PORT_BASE + 2);
    let mut lsr: PortU8 = IoPort::new(SERIAL_PORT_BASE + 5);
    let mut data_port: PortU8 = IoPort::new(SERIAL_PORT_BASE);

    loop {
        let id = iir.read();
        if (id & 1) != 0 {
            break; // 保留中の割り込みなし
        }

        match id & 0x0E {
            0x02 => {
                // THRE (Transmitter Holding Register Empty)
                // ISR now only drains the global buffer. Per-core buffers are
                // aggregated into the global buffer by non-ISR contexts to
                // keep interrupt handling time bounded. TODO: Move aggregation
                // into a dedicated low-priority kernel task.
                let mut tmp = [0u8; ISR_TX_BURST];
                let mut total_written = 0usize;

                // Drain global buffer using peek/advance to avoid push_front semantics
                let n = {
                    let guard = LOG_BUFFER.lock();
                    guard.peek_bulk(&mut tmp)
                };

                if n > 0 {
                    let mut i = 0usize;
                    while i < n {
                        if (lsr.read() & LSR_TX_EMPTY) == 0 {
                            break;
                        }
                        data_port.write(tmp[i]);
                        i += 1;
                    }

                    if i > 0 {
                        let mut guard = LOG_BUFFER.lock();
                        guard.advance_head(i);
                    }

                    total_written += i;
                }

                // If nothing was sent, disable TX interrupt (bypass lock in panic)
                if total_written == 0 {
                    if IN_PANIC.load(Ordering::Relaxed) {
                        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
                        let current = ier.read();
                        ier.write(current & !0x02);
                    } else {
                        let _io_guard = SERIAL_IO_LOCK.lock();
                        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
                        let current = ier.read();
                        ier.write(current & !0x02);
                    }
                }
            }
            0x04 | 0x0C => {
                // RDA (Received Data Available) または Character Timeout
                let mut guard = INPUT_BUFFER.lock();
                while (lsr.read() & 0x01) != 0 {
                    let byte = data_port.read();
                    // 入力バッファが満杯なら切り捨てる
                    let _ = guard.push_byte(byte);
                }
            }
            _ => break,
        }
    }
}

/// グローバルロガーインスタンス
static LOGGER: KernelLogger = KernelLogger;

/// 非同期ロガーによってドロップされたバイト数を取得します。
pub fn get_dropped_log_bytes() -> usize {
    DROPPED_LOG_BYTES.load(Ordering::Relaxed)
}

/// シリアルポートから1文字読み取ります（非ブロッキング）。
pub fn read_char() -> Option<u8> {
    INPUT_BUFFER.lock().pop_one()
}

/// 入力バッファにデータがあるか確認します。
pub fn has_char() -> bool {
    !INPUT_BUFFER.lock().is_empty()
}

// Bench helpers (available under `--features bench`) -------------------------------------------------
#[cfg(feature = "bench")]
/// Clear all buffers and dropped counters (benchmark helper)
pub fn bench_clear_buffers() {
    LOG_BUFFER.lock().clear();
    for i in 0..PER_CPU_COUNT {
        PER_CORE_LOG_BUFFERS[i].lock().clear();
    }
    INPUT_BUFFER.lock().clear();
    DROPPED_LOG_BYTES.store(0, Ordering::Relaxed);
}

#[cfg(feature = "bench")]
/// Push bytes into per-core buffer (returns written bytes)
pub fn bench_push_per_core(core: usize, data: &[u8]) -> usize {
    if core >= PER_CPU_COUNT {
        return 0;
    }
    PER_CORE_LOG_BUFFERS[core].lock().push_bytes(data)
}

#[cfg(feature = "bench")]
/// Push bytes into global buffer (returns written bytes)
pub fn bench_push_global(data: &[u8]) -> usize {
    LOG_BUFFER.lock().push_bytes(data)
}

#[cfg(feature = "bench")]
/// Pop up to dst.len() bytes from global buffer
pub fn bench_pop_global_buf(dst: &mut [u8]) -> usize {
    LOG_BUFFER.lock().pop_bulk(dst)
}

#[cfg(feature = "bench")]
/// Pop up to dst.len() bytes from a per-core buffer
pub fn bench_pop_per_core_buf(core: usize, dst: &mut [u8]) -> usize {
    if core >= PER_CPU_COUNT {
        return 0;
    }
    PER_CORE_LOG_BUFFERS[core].lock().pop_bulk(dst)
}

#[cfg(feature = "bench")]
/// Return total pending bytes across all buffers
pub fn bench_total_pending_bytes() -> usize {
    let mut total = 0usize;
    total += LOG_BUFFER.lock().len();
    for i in 0..PER_CPU_COUNT {
        total += PER_CORE_LOG_BUFFERS[i].lock().len();
    }
    total
}

/// Aggregate up to `max_bytes` from per-core buffers into the global
/// `LOG_BUFFER`. This must be called from non-ISR contexts (executor/idle
/// task or writers). Returns the number of bytes moved.
pub fn aggregate_per_core_to_global(max_bytes: usize) -> usize {
    let mut moved = 0usize;
    let mut tmp = [0u8; 256];

    for i in 0..PER_CPU_COUNT {
        if moved >= max_bytes {
            break;
        }
        // Try to take the per-core buffer without blocking
        if let Some(mut per_guard) = PER_CORE_LOG_BUFFERS[i].try_lock() {
            let to_read = core::cmp::min(tmp.len(), max_bytes - moved);
            let n = per_guard.peek_bulk(&mut tmp[..to_read]);
            if n == 0 {
                continue;
            }

            let wrote = {
                let mut global_guard = LOG_BUFFER.lock();
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

// ============================================================================
// 公開API
// ============================================================================

/// Public helper to kick the serial transmitter from non-ISR contexts.
/// This aggregates per-core buffers into the global buffer and enables TX
/// interrupt when necessary. Useful to call from an executor idle loop.
pub fn kick_serial_tx() {
    // Reuse the existing helper which performs aggregation + IER RMW.
    start_serial_tx();
}

/// Background aggregator task entry point. Move data from per-core buffers to
/// the global buffer and yield when idle. This must never return.
///
/// NOTE: This function is typically driven by the executor idle loop via
/// `kick_serial_tx()`. Direct spawning as a task is no longer recommended.
#[cfg(not(any(test, feature = "bench")))]
pub fn log_aggregator_task(_arg: u64) -> ! {
    loop {
        let moved = aggregate_per_core_to_global(AGGREGATE_MAX_PER_CALL);

        // Yield to allow other work / TX to be serviced
        crate::task::preemption::voluntary_yield();
        crate::task::preemption::yield_point();

        if moved == 0 {
            // Nothing moved — add small delay to avoid busy looping
            core::hint::spin_loop();
        }
    }
}

/// Test/bench stub for log_aggregator_task (never returns, but signature required)
#[cfg(any(test, feature = "bench"))]
pub fn log_aggregator_task(_arg: u64) -> ! {
    loop {
        core::hint::spin_loop();
    }
}


/// ロギングシステムを初期化
///
/// カーネル起動の早い段階で呼び出す。ヒープ初期化前でも動作する。
pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)?;
    log::set_max_level(MAX_LOG_LEVEL);
    CURRENT_LOG_LEVEL.store(MAX_LOG_LEVEL as u8, Ordering::SeqCst);
    LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}

/// ヒープが使用可能になったことを通知
///
/// メモリアロケータ初期化後に呼び出す。
pub fn notify_heap_available() {
    HEAP_AVAILABLE.store(true, Ordering::SeqCst);
}

/// パニック状態を設定（デッドロック回避用）
///
/// パニックハンドラの最初で呼び出す。
/// これにより、ロガーはロックを取得せずに直接出力する。
pub fn enter_panic_mode() {
    IN_PANIC.store(true, Ordering::SeqCst);
    // Attempt to put serial port in a clean state so that panic output has a better chance of being delivered
    KernelLogger::reset_serial_for_panic();
}

/// パニック状態かどうかを判定
pub fn is_in_panic() -> bool {
    IN_PANIC.load(Ordering::Relaxed)
}

/// パニック状態をクリア（通常は使用しない）
#[allow(dead_code)]
pub fn exit_panic_mode() {
    IN_PANIC.store(false, Ordering::SeqCst);
}



/// 実行時にログレベルを変更
pub fn set_log_level(level: LevelFilter) {
    CURRENT_LOG_LEVEL.store(level as u8, Ordering::SeqCst);
    log::set_max_level(level);
}

/// 現在のログレベルを取得
pub fn current_log_level() -> LevelFilter {
    LevelFilter::iter()
        .nth(CURRENT_LOG_LEVEL.load(Ordering::Relaxed) as usize)
        .unwrap_or(LevelFilter::Info)
}

/// ロガーが初期化済みかどうか
pub fn is_initialized() -> bool {
    LOGGER_INITIALIZED.load(Ordering::Relaxed)
}

// ============================================================================
// 早期ブート用ログ（log::Log trait初期化前に使用）
// ============================================================================

/// 早期ブート用の直接シリアル出力
///
/// ヒープやログシステム初期化前に使用する。
/// log!マクロの代わりに使用。
/// ロックなしで直接出力するため、早期ブートやパニック時のみ使用。
#[inline]
pub fn early_print(s: &str) {
    KernelLogger::write_raw(s);
}

/// 早期ブート用の直接シリアル文字出力
#[inline]
pub fn early_print_char(c: u8) {
    KernelLogger::write_char_raw(c);
}

/// 早期ブート用の数値出力（16進数）
pub fn early_print_hex(value: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
    KernelLogger::write_raw("0x");
    for i in (0..16).rev() {
        let nibble = ((value >> (i * 4)) & 0xF) as usize;
        KernelLogger::write_char_raw(HEX_CHARS[nibble]);
    }
}

/// 早期ブート用の数値出力（10進数）
pub fn early_print_dec(value: u64) {
    if value == 0 {
        KernelLogger::write_char_raw(b'0');
        return;
    }

    let mut buf = [0u8; 20];
    let mut pos = 0;
    let mut v = value;

    while v > 0 {
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
        pos += 1;
    }

    while pos > 0 {
        pos -= 1;
        KernelLogger::write_char_raw(buf[pos]);
    }
}

// ============================================================================
// 互換性マクロ（既存コード移行用）
// ============================================================================

/// 早期ブート用ログマクロ（log初期化前）
#[macro_export]
macro_rules! early_log {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct EarlyWriter;
        impl Write for EarlyWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                $crate::io::log::early_print(s);
                Ok(())
            }
        }
        let mut w = EarlyWriter;
        let _ = write!(w, $($arg)*);
        $crate::io::log::early_print_char(b'\n');
    }};
}

/// 早期ブート用ログマクロ（改行なし）
#[macro_export]
macro_rules! early_log_no_newline {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct EarlyWriter;
        impl Write for EarlyWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                $crate::io::log::early_print(s);
                Ok(())
            }
        }
        let mut w = EarlyWriter;
        let _ = write!(w, $($arg)*);
    }};
}


// ============================================================================
// シリアルデバッグコンソール（設計書 §10.2）
// ============================================================================
//
// シリアルコンソールからのデバッグコマンド受信機能。
// 実行中にログレベルを変更したり、システム情報を取得できる。
//
// ## サポートされるコマンド（Ctrl+文字）
// - Ctrl+L: ログレベルサイクル切り替え (Error → Warn → Info → Debug → Trace)
// - Ctrl+S: システムステータス表示
// - Ctrl+H: ヘルプ表示

/// デバッグコンソールのコマンドバイト
pub mod debug_commands {
    /// ログレベルサイクル (Ctrl+L = 0x0C)
    pub const LOG_LEVEL_CYCLE: u8 = 0x0C;
    /// システムステータス (Ctrl+S = 0x13)
    pub const SYSTEM_STATUS: u8 = 0x13;
    /// メモリ表示 (Ctrl+M = 0x0D) - 注: CRと衝突するので別キー使用
    pub const MEMORY_STATUS: u8 = 0x00; // Ctrl+@ として割り当て
    /// ヘルプ (Ctrl+H = 0x08)
    pub const HELP: u8 = 0x08;
}

/// デバッグコンソールコマンドを処理
///
/// シリアル割り込みハンドラから呼び出される。
/// 制御文字を受信した場合にコマンドとして解釈する。
///
/// # Returns
/// コマンドとして処理した場合は`true`、通常文字の場合は`false`
pub fn handle_debug_command(byte: u8) -> bool {
    match byte {
        debug_commands::LOG_LEVEL_CYCLE => {
            cycle_log_level();
            true
        }
        debug_commands::SYSTEM_STATUS => {
            print_system_status();
            true
        }
        debug_commands::HELP => {
            print_debug_help();
            true
        }
        _ => false,
    }
}

/// ログレベルをサイクル切り替え
fn cycle_log_level() {
    let current = current_log_level();
    let next = match current {
        LevelFilter::Off => LevelFilter::Error,
        LevelFilter::Error => LevelFilter::Warn,
        LevelFilter::Warn => LevelFilter::Info,
        LevelFilter::Info => LevelFilter::Debug,
        LevelFilter::Debug => LevelFilter::Trace,
        LevelFilter::Trace => LevelFilter::Error,
    };
    set_log_level(next);
    early_print("\n[DEBUG] Log level changed: ");
    early_print(level_filter_name(next));
    early_print("\n");
}

/// ログレベルを文字列名に変換
fn level_filter_name(level: LevelFilter) -> &'static str {
    match level {
        LevelFilter::Off => "OFF",
        LevelFilter::Error => "ERROR",
        LevelFilter::Warn => "WARN",
        LevelFilter::Info => "INFO",
        LevelFilter::Debug => "DEBUG",
        LevelFilter::Trace => "TRACE",
    }
}

/// システムステータスを表示
fn print_system_status() {
    early_print("\n[DEBUG] === System Status ===\n");
    early_print("[DEBUG] Log level: ");
    early_print(level_filter_name(current_log_level()));
    early_print("\n");
    
    // タイマーtick
    let tick = crate::task::timer::current_tick();
    early_print("[DEBUG] Timer ticks: ");
    early_print_dec(tick);
    early_print("\n");
    
    // パニック統計
    #[cfg(not(feature = "bench"))]
    {
        let panic_stats = crate::panic_handler::panic_stats();
        early_print("[DEBUG] Panic count: ");
        early_print_dec(panic_stats.total_panics);
        early_print("\n");
    }
    
    early_print("[DEBUG] ======================\n");
}

/// デバッグヘルプを表示
fn print_debug_help() {
    early_print("\n[DEBUG] === Debug Console Help ===\n");
    early_print("[DEBUG] Ctrl+L : Cycle log level\n");
    early_print("[DEBUG] Ctrl+S : Show system status\n");
    early_print("[DEBUG] Ctrl+H : Show this help\n");
    early_print("[DEBUG] =============================\n");
}

/// 文字列からログレベルを設定
///
/// シェルコマンド等から呼び出される。
/// alloc依存を排除し、ゼロアロケーションで比較を行います。
///
/// # Arguments
/// * `level_str` - "error", "warn", "info", "debug", "trace" のいずれか（大文字小文字不問）
///
/// # Returns
/// 設定成功時は`Ok(新レベル)`、無効な文字列は`Err`
pub fn set_log_level_from_str(level_str: &str) -> Result<LevelFilter, &'static str> {
    // eq_ignore_ascii_case を使用してヒープアロケーションを回避
    if level_str.eq_ignore_ascii_case("off") {
        set_log_level(LevelFilter::Off);
        return Ok(LevelFilter::Off);
    }
    if level_str.eq_ignore_ascii_case("error") {
        set_log_level(LevelFilter::Error);
        return Ok(LevelFilter::Error);
    }
    if level_str.eq_ignore_ascii_case("warn") || level_str.eq_ignore_ascii_case("warning") {
        set_log_level(LevelFilter::Warn);
        return Ok(LevelFilter::Warn);
    }
    if level_str.eq_ignore_ascii_case("info") {
        set_log_level(LevelFilter::Info);
        return Ok(LevelFilter::Info);
    }
    if level_str.eq_ignore_ascii_case("debug") {
        set_log_level(LevelFilter::Debug);
        return Ok(LevelFilter::Debug);
    }
    if level_str.eq_ignore_ascii_case("trace") {
        set_log_level(LevelFilter::Trace);
        return Ok(LevelFilter::Trace);
    }

    Err("Invalid log level. Use: off, error, warn, info, debug, trace")
}

