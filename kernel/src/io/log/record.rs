use core::fmt::{self, Write};
use log::Record;

use crate::cpu::{CpuId, CurrentCpu};

/// An entire UTF-8 record, including its wire delimiter, must fit before it can
/// be published. Formatting failure never exposes a partial record.
pub(super) const RECORD_CAPACITY: usize = 1024;

pub(super) struct WireRecord {
    bytes: [u8; RECORD_CAPACITY],
    len: usize,
    message_start: usize,
}

impl WireRecord {
    pub(super) fn encode(record: &Record<'_>) -> Result<Self, fmt::Error> {
        let timestamp = crate::time::best_effort_time_nanos();
        let cpu = CurrentCpu::acquire();
        let cpu_id = cpu.as_ref().map(CurrentCpu::id);
        let domain_id = cpu
            .and_then(|cpu| cpu.execution())
            .map(|subject| subject.domain.as_u64());
        Self::render(record, timestamp, cpu_id, domain_id)
    }

    fn render(
        record: &Record<'_>,
        timestamp: u64,
        cpu: Option<CpuId>,
        domain: Option<u64>,
    ) -> Result<Self, fmt::Error> {
        let mut output = Self {
            bytes: [0; RECORD_CAPACITY],
            len: 0,
            message_start: 0,
        };
        let seconds = timestamp / crate::time::NANOS_PER_SEC;
        let micros = (timestamp / crate::time::NANOS_PER_MICRO) % 1_000_000;
        write!(output, "[{seconds:5}.{micros:06}] ")?;
        if let Some(cpu) = cpu {
            write!(output, "[C{cpu}] ")?;
        }
        if let Some(domain) = domain {
            write!(output, "[D{domain}] ")?;
        }
        write!(output, "[{}] ", record.level())?;
        if matches!(record.level(), log::Level::Info | log::Level::Warn) {
            output.write_str(" ")?;
        }
        if !record.target().is_empty() {
            write!(output, "[{}] ", record.target())?;
        }
        output.message_start = output.len;
        LineWriter(&mut output).write_fmt(*record.args())?;
        if !output.bytes().ends_with(b"\n") {
            output.write_str("\r\n")?;
        }
        Ok(output)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[cfg(not(feature = "bench"))]
    pub(super) fn message(&self) -> &str {
        core::str::from_utf8(&self.bytes()[self.message_start..]).expect("record writes only UTF-8")
    }
}

impl Write for WireRecord {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

struct LineWriter<'a>(&'a mut WireRecord);

impl Write for LineWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for part in text.split_inclusive('\n') {
            let Some(line) = part.strip_suffix('\n') else {
                self.0.write_str(part)?;
                continue;
            };
            self.0.write_str(line)?;
            if self.0.bytes()[self.0.message_start..].ends_with(b"\r") {
                self.0.len -= 1;
            }
            // A newline ends the current line only. Preserve previous lines
            // and trim ASCII spaces, including fragments from earlier writes.
            let spaces = self.0.bytes()[self.0.message_start..]
                .iter()
                .rev()
                .take_while(|&&byte| byte == b' ')
                .count();
            self.0.len -= spaces;
            self.0.write_str("\r\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::WireRecord;
    use log::{Level, Record};

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn record_preserves_utf8_and_keeps_the_emitting_domain() {
        let record = Record::builder()
            .level(Level::Info)
            .target("boot")
            .args(format_args!("\u{65e5}\u{672c}\u{8a9e}  \nnext"))
            .build();
        let line = WireRecord::render(
            &record,
            1_234_000_000,
            Some(crate::cpu::CpuId::BOOTSTRAP),
            Some(7),
        )
        .unwrap();
        assert_eq!(
            core::str::from_utf8(line.bytes()),
            Ok("[    1.234000] [C0] [D7] [INFO]  [boot] \u{65e5}\u{672c}\u{8a9e}\r\nnext\r\n")
        );
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn record_rejects_a_body_without_room_for_the_delimiter() {
        let bytes = [b'a'; super::RECORD_CAPACITY - 24];
        let body = core::str::from_utf8(&bytes).unwrap();
        let out = WireRecord::render(
            &Record::builder()
                .level(Level::Info)
                .args(format_args!("{body}"))
                .build(),
            0,
            None,
            None,
        );
        assert!(out.is_err());
    }
}
