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
//! ```rust
//! use log::{info, debug, warn, error, trace};
//! 
//! info!("システム起動");
//! debug!("デバッグ情報: {}", value);
//! error!("エラー発生: {:?}", err);
//! ```

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use spin::Mutex;
use x86_64::instructions::port::Port;

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

/// パニック中フラグ（デッドロック回避用）
static IN_PANIC: AtomicBool = AtomicBool::new(false);

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
    
    unsafe {
        let base = SERIAL_PORT_BASE;
        
        // 割り込み無効化
        let mut ier: Port<u8> = Port::new(base + 1);
        ier.write(0x00);
        
        // DLAB有効化（ボーレート設定用）
        let mut lcr: Port<u8> = Port::new(base + 3);
        lcr.write(0x80);
        
        // ボーレート設定: 115200 (divisor = 1)
        let mut dll: Port<u8> = Port::new(base + 0);
        let mut dlh: Port<u8> = Port::new(base + 1);
        dll.write(0x01); // Divisor low byte
        dlh.write(0x00); // Divisor high byte
        
        // ライン設定: 8 data bits, no parity, 1 stop bit (8N1)
        lcr.write(0x03);
        
        // FIFO有効化、バッファクリア、14バイトスレッショルド
        let mut fcr: Port<u8> = Port::new(base + 2);
        fcr.write(0xC7);
        
        // モデム制御: DTR, RTS, OUT2（割り込みゲート）
        let mut mcr: Port<u8> = Port::new(base + 4);
        mcr.write(0x0B);
        
        // ループバックテスト
        mcr.write(0x1E); // loopback mode
        let mut data: Port<u8> = Port::new(base);
        data.write(0xAE);
        if data.read() != 0xAE {
            // テスト失敗、初期化フラグをリセット
            SERIAL_INITIALIZED.store(false, Ordering::SeqCst);
            return;
        }
        
        // 通常モードに戻す
        mcr.write(0x0F);
    }
}

// ============================================================================
// シリアルロガー実装
// ============================================================================

/// カーネル用シリアルロガー
struct KernelLogger;

impl KernelLogger {
    /// シリアルポートに1バイト書き込み（内部用、ロックなし）
    /// 
    /// 送信バッファが空になるまで待機してから書き込む。
    /// タイムアウト時は書き込みをスキップする。
    #[inline]
    fn write_byte_raw(byte: u8) {
        unsafe {
            let mut status_port: Port<u8> = Port::new(SERIAL_PORT_BASE + SERIAL_LSR_OFFSET);
            let mut data_port: Port<u8> = Port::new(SERIAL_PORT_BASE + SERIAL_DATA_OFFSET);
            
            // 送信バッファが空になるまで待つ（タイムアウト付き）
            let mut timeout = TX_TIMEOUT_LOOPS;
            while (status_port.read() & LSR_TX_EMPTY) == 0 && timeout > 0 {
                core::hint::spin_loop(); // CPU省電力ヒント
                timeout -= 1;
            }
            
            if timeout > 0 {
                data_port.write(byte);
            }
        }
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
            Level::Warn  => "[WARN]  ",
            Level::Info  => "[INFO]  ",
            Level::Debug => "[DEBUG] ",
            Level::Trace => "[TRACE] ",
        }
    }
    
    /// ログレベルに応じた色コード（ANSIエスケープシーケンス）
    #[allow(dead_code)]
    fn level_color(level: Level) -> &'static str {
        match level {
            Level::Error => "\x1b[31m", // 赤
            Level::Warn  => "\x1b[33m", // 黄
            Level::Info  => "\x1b[32m", // 緑
            Level::Debug => "\x1b[36m", // シアン
            Level::Trace => "\x1b[37m", // 白
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
        
        // パニック中でなければロックを取得
        let _guard = if IN_PANIC.load(Ordering::Relaxed) {
            None
        } else {
            Some(SERIAL_LOCK.lock())
        };
        
        // ログレベルプレフィックス
        Self::write_raw(Self::level_prefix(record.level()));
        
        // モジュールパス（オプション）
        if let Some(module) = record.module_path() {
            Self::write_raw("[");
            Self::write_raw(module);
            Self::write_raw("] ");
        }
        
        // メッセージ本文
        // format_args!のアロケーションなし出力
        struct EarlyWriter;
        impl Write for EarlyWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                KernelLogger::write_raw(s);
                Ok(())
            }
        }
        
        let mut writer = EarlyWriter;
        let _ = write!(writer, "{}", record.args());
        
        // 改行
        Self::write_char_raw(b'\r');
        Self::write_char_raw(b'\n');
    }

    fn flush(&self) {
        // シリアル出力はバッファリングしないため何もしない
    }
}

/// グローバルロガーインスタンス
static LOGGER: KernelLogger = KernelLogger;

// ============================================================================
// 公開API
// ============================================================================

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
}

/// パニック状態をクリア（通常は使用しない）
#[allow(dead_code)]
pub fn exit_panic_mode() {
    IN_PANIC.store(false, Ordering::SeqCst);
}

/// 現在パニック中かどうか
pub fn is_in_panic() -> bool {
    IN_PANIC.load(Ordering::Relaxed)
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
// レガシー互換マクロ（廃止予定）
// ============================================================================

/// io_log_info! 互換マクロ
#[macro_export]
macro_rules! io_log_info {
    ($($arg:tt)*) => {
        log::info!($($arg)*)
    };
}

/// io_log_warn! 互換マクロ
#[macro_export]
macro_rules! io_log_warn {
    ($($arg:tt)*) => {
        log::warn!($($arg)*)
    };
}

/// io_log_debug! 互換マクロ
#[macro_export]
macro_rules! io_log_debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*)
    };
}

/// io_log_error! 互換マクロ
#[macro_export]
macro_rules! io_log_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*)
    };
}

// ============================================================================
// 内部log互換モジュール（削除、log crateを使用）
// ============================================================================
// Note: log::info!, log::debug!, log::warn!, log::error!, log::trace! を直接使用してください
