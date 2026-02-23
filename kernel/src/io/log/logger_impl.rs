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
        // diagnostic: print the message content via early_print if heap is available
        if HEAP_AVAILABLE.load(Ordering::Relaxed) {
            let msg = alloc::format!("{}", record.args());
            super::early_print("[LOGDBG] msg=[");
            super::early_print(&msg);
            super::early_print("]\n");
        }
        if !self.enabled(record.metadata()) {
            return;
        }

        let use_async = HEAP_AVAILABLE.load(Ordering::Relaxed) && !IN_PANIC.load(Ordering::Relaxed);
        if use_async {
            if self.try_log_async(record) {
                start_serial_tx();
            } else {
                self.log_sync_fallback(record);
            }
        } else {
            self.log_sync(record);
        }

        // 画面への出力（統合実装）
        // パニック中以外、かつロックが取得できた場合のみ出力してデッドロックを回避する
        #[cfg(not(feature = "bench"))]
        if !is_in_panic() {
            // Helper adapter to use formatting with try_write
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

    fn flush(&self) {
        // シリアル出力はバッファリングしないため何もしない
    }
}

impl KernelLogger {
    /// 非同期バッファへの書き込みを試行。成功した場合trueを返す。
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

    /// 非同期書き込みが競合した場合の同期フォールバック
    pub(super) fn log_sync_fallback(&self, record: &Record) {
        let _guard = if IN_PANIC.load(Ordering::Relaxed) {
            None
        } else {
            SERIAL_LOCK.try_lock()
        };

        let mut tracker = LastCharTracker::new(SyncLogWriter);
        self.print_header(&mut tracker, record);
        let _ = write!(tracker, "{}", record.args());
        if tracker.last_char != b'\n' {
            let _ = tracker.inner.write_str("\r\n");
        }
    }

    /// 同期出力パス（ヒープ未初期化またはパニック時）
    pub(super) fn log_sync(&self, record: &Record) {
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
}

/// `Write` トレイトを実装し、最後の文字を追跡するラッパー
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

/// シリアル送信を開始（割り込み有効化）
pub(crate) fn start_serial_tx() {
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

pub(crate) fn drain_global_tx_buffer(data_port: &mut PortU8, lsr: &mut PortU8) -> usize {
    let mut tmp = [0u8; ISR_TX_BURST];
    let n = {
        let guard = LOG_BUFFER.lock();
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
        let mut guard = LOG_BUFFER.lock();
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
        let _io_guard = SERIAL_IO_LOCK.lock();
        let mut ier: PortU8 = IoPort::new(SERIAL_PORT_BASE + 1);
        let current = ier.read();
        ier.write(current & !0x02);
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
                let total_written = drain_global_tx_buffer(&mut data_port, &mut lsr);
                if total_written == 0 {
                    disable_tx_interrupt();
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
pub(crate) static LOGGER: KernelLogger = KernelLogger;

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
pub(crate) fn cycle_log_level() {
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
pub(crate) fn level_filter_name(level: LevelFilter) -> &'static str {
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
pub(crate) fn print_system_status() {
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
pub(crate) fn print_debug_help() {
    early_print("\n[DEBUG] === Debug Console Help ===\n");
    early_print("[DEBUG] Ctrl+L : Cycle log level\n");
    early_print("[DEBUG] Ctrl+S : Show system status\n");
    early_print("[DEBUG] Ctrl+H : Show this help\n");
    early_print("[DEBUG] =============================\n");
}
