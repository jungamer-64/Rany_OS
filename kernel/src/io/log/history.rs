use crate::io::byte_queue::RingBuffer;

const HEADER: usize = size_of::<u16>();

pub(super) struct History<const N: usize> {
    bytes: RingBuffer<N>,
    evicted: bool,
}

impl<const N: usize> History<N> {
    pub(super) const fn new() -> Self {
        assert!(N >= super::record::RECORD_CAPACITY + HEADER);
        Self {
            bytes: RingBuffer::new(),
            evicted: false,
        }
    }

    fn record_len(&self, offset: usize) -> usize {
        let mut header = [0; HEADER];
        self.bytes.copy_at(offset, &mut header);
        usize::from(u16::from_le_bytes(header))
    }

    pub(super) fn record(&mut self, record: &super::record::WireRecord) {
        let bytes = record.bytes();
        let len =
            u16::try_from(bytes.len()).expect("wire record length fits in the history header");
        // LOOP_PROOF: mode=condition; reason=Every eviction removes one positive-length record until the bounded incoming record fits.;
        while self.bytes.spare() < HEADER + bytes.len() {
            let old = self.record_len(0);
            self.bytes.discard(HEADER + old);
            self.evicted = true;
        }
        assert!(self.bytes.push(&len.to_le_bytes()));
        assert!(self.bytes.push(bytes));
    }

    pub(super) fn copy(&self, destination: &mut [u8]) -> (usize, bool) {
        let mut offset = 0;
        let mut written = 0;
        // LOOP_PROOF: mode=condition; reason=Each complete record advances the bounded read cursor or ends the snapshot when the destination is full.;
        while offset < self.bytes.len() {
            let len = self.record_len(offset);
            let end = written + len;
            let Some(output) = destination.get_mut(written..end) else {
                break;
            };
            self.bytes.copy_at(offset + HEADER, output);
            offset += HEADER + len;
            written = end;
        }
        (written, self.evicted || offset != self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::log::record::WireRecord;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn eviction_and_short_reads_keep_complete_utf8_records() {
        const SIZE: usize = 1850;
        let mut history = History::<SIZE>::new();
        let payload = "\u{65e5}".repeat(100);
        let mut expected = [const { None }; 8];
        for (index, slot) in expected.iter_mut().enumerate() {
            let record = WireRecord::encode(
                &log::Record::builder()
                    .level(log::Level::Info)
                    .args(format_args!("{index}: {payload}"))
                    .build(),
            )
            .unwrap();
            history.record(&record);
            *slot = Some(record);
        }

        let mut bytes = [0; SIZE];
        let (written, truncated) = history.copy(&mut bytes);
        assert!(truncated);
        let records = expected.map(Option::unwrap);
        let newest: alloc::vec::Vec<_> = records[3..]
            .iter()
            .flat_map(|record| record.bytes().iter().copied())
            .collect();
        assert_eq!(&bytes[..written], newest);

        let first = records[3].bytes();
        let (written, truncated) = history.copy(&mut bytes[..first.len() + 1]);
        assert!(truncated);
        assert_eq!(&bytes[..written], first);
        assert_eq!(history.copy(&mut bytes[..first.len() - 1]), (0, true));
    }
}
