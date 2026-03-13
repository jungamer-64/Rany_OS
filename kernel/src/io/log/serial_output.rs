use super::*;

impl KernelLogger {
    /// シリアルポートに1バイト書き込み（内部用、ロックなし）
    ///
    /// 送信バッファが空になるまで待機してから書き込む。
    /// タイムアウト時は書き込みをスキップする。
    #[inline]
    pub(super) fn write_byte_raw(byte: u8) {
        #[cfg(all(test, target_os = "linux"))]
        {
            std::eprint!("{}", byte as char);
            return;
        }

        if !serial_output_enabled() || !panic_output_allowed() {
            return;
        }
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
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
    pub(super) fn reset_serial_for_panic() {
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
    pub(super) fn write_raw(s: &str) {
        #[cfg(all(test, target_os = "linux"))]
        {
            std::eprint!("{}", s);
            return;
        }

        if !serial_output_enabled() {
            return;
        }
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
    pub(super) fn write_char_raw(c: u8) {
        Self::write_byte_raw(c);
    }

    /// ログレベルのプレフィックスを取得
    pub(super) fn level_prefix(level: Level) -> &'static str {
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
    pub(super) fn level_color(level: Level) -> &'static str {
        match level {
            Level::Error => "\x1b[31m", // 赤
            Level::Warn => "\x1b[33m",  // 黄
            Level::Info => "\x1b[32m",  // 緑
            Level::Debug => "\x1b[36m", // シアン
            Level::Trace => "\x1b[37m", // 白
        }
    }

    /// Write a record into an async RingBuffer (generic over its capacity)
    pub(super) fn write_into_async_buffer<const N: usize>(
        &self,
        buf: &mut RingBuffer<N>,
        record: &Record,
    ) {
        let writer = AsyncLogWriter::<N>::new(buf);
        let mut tracker = LastCharTracker::new(writer);

        self.print_header(&mut tracker, record);

        // Format the record arguments into a temporary string so we can strip any
        // spaces that precede a newline.  This avoids leaving a trailing blank
        // (rendered as an underscore when spaces are visible) at the end of the
        // log line.
        let mut msg = alloc::format!("{}", record.args());
        msg = crate::io::log::trim_spaces_before_newline(&msg);
        let _ = write!(tracker, "{}", msg);

        if tracker.last_char != b'\n' {
            let _ = tracker.inner.write_str("\r\n");
        }
    }

    pub(super) fn print_header<W: Write>(&self, w: &mut W, record: &Record) {
        // Timestamp and Core ID
        // Always use the unified kernel timebase so log timestamps advance with PIT IRQs.
        let uptime_ms = crate::time::get_uptime_ms();

        let core_id = {
            #[cfg(not(feature = "bench"))]
            {
                crate::cpu::current_id()
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
