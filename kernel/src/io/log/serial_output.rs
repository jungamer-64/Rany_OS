use super::*;

impl KernelLogger {
    fn write_header_prefix<W: Write>(
        w: &mut W,
        uptime_nanos: u64,
        cpu_id: Option<crate::cpu::CpuId>,
        level: Level,
        target: &str,
    ) {
        let secs = uptime_nanos / crate::time::NANOS_PER_SEC;
        let micros = (uptime_nanos / crate::time::NANOS_PER_MICRO) % 1_000_000;

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
        let _ = write!(w, "{}.{:06}] ", secs, micros);

        if let Some(cpu_id) = cpu_id {
            let _ = write!(w, "[C{}] ", cpu_id);
        }

        let _ = write!(w, "{}", Self::level_prefix(level));

        if !target.is_empty() {
            let _ = write!(w, "[{}] ", target);
        }
    }

    /// シリアルポートに1バイト書き込み（内部用、ロックなし）
    ///
    /// 送信バッファが空になるまで待機してから書き込む。
    /// タイムアウト時は書き込みをスキップする。
    #[inline]
    pub(super) fn write_byte_raw(&self, byte: u8) {
        #[cfg(all(test, target_os = "linux"))]
        {
            std::eprint!("{}", byte as char);
            return;
        }

        if !serial_output_enabled() || !panic_output_allowed() {
            return;
        }
        // Output is intentionally lossy. The device owner bounds both lock
        // acquisition and readiness; panic output never steals a live lock.
        let _ = self.serial.try_send(byte, TX_TIMEOUT_LOOPS);
    }

    /// パニック時にシリアルの状態をできるだけクリーンにする試み（FIFOクリア等）
    pub(super) fn reset_serial_for_panic(&self) {
        let _ = self.serial.try_quiesce_for_panic();
    }

    /// シリアルポートへ早期ブート・panic 用の bounded output を行う。
    pub(super) fn write_raw(&self, s: &str) {
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
                self.write_byte_raw(b'\r');
            }
            self.write_byte_raw(byte);
        }
    }

    /// シリアルポートに1文字書き込み（ロックなし）
    ///
    /// `write_byte_raw`のエイリアス。早期ブート用関数からの呼び出しに使用。
    #[inline]
    pub(super) fn write_char_raw(&self, c: u8) {
        self.write_byte_raw(c);
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
        // Early boot runs with interrupts masked for a while, so prefer the
        // calibrated TSC clock when available and fall back to PIT-backed uptime.
        let uptime_nanos = crate::time::best_effort_time_nanos();
        let cpu_id = current_log_cpu_id();
        Self::write_header_prefix(w, uptime_nanos, cpu_id, record.level(), record.target());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn header_omits_cpu_field_before_per_cpu_is_ready() {
        let mut out = String::new();
        KernelLogger::write_header_prefix(&mut out, 1_234_000_000, None, Level::Info, "boot");
        assert_eq!(out, "[    1.234000] [INFO]  [boot] ");
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn header_keeps_cpu_field_after_per_cpu_is_ready() {
        let mut out = String::new();
        KernelLogger::write_header_prefix(
            &mut out,
            1_234_000_000,
            Some(crate::cpu::CpuId::new(2).unwrap()),
            Level::Info,
            "boot",
        );
        assert_eq!(out, "[    1.234000] [C2] [INFO]  [boot] ");
    }
}
