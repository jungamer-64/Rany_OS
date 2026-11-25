use super::super::byte_queue::RingBuffer;

const LOG_CAPACITY: usize = 16 * 1024;
const CONSOLE_CAPACITY: usize = 4096;
const LENGTH_BYTES: usize = size_of::<u16>();

pub(super) struct FrameQueue<const N: usize> {
    bytes: RingBuffer<N>,
    remaining_in_frame: usize,
    pending_payload: usize,
}

impl<const N: usize> FrameQueue<N> {
    const fn new() -> Self {
        Self {
            bytes: RingBuffer::new(),
            remaining_in_frame: 0,
            pending_payload: 0,
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) -> bool {
        let Ok(length) = u16::try_from(bytes.len()) else {
            return false;
        };
        if length == 0 {
            return true;
        }
        if bytes.len() + LENGTH_BYTES > self.bytes.spare() {
            return false;
        }
        self.bytes.push(&length.to_le_bytes());
        self.bytes.push(bytes);
        self.pending_payload += bytes.len();
        true
    }

    pub(super) fn pop(&mut self) -> Option<u8> {
        if self.pending_payload == 0 {
            return None;
        }
        if self.remaining_in_frame == 0 {
            let low = self.bytes.pop().expect("pending frame contains a length");
            let high = self.bytes.pop().expect("pending frame contains a length");
            self.remaining_in_frame = usize::from(u16::from_le_bytes([low, high]));
        }
        let byte = self
            .bytes
            .pop()
            .expect("frame admission includes its payload");
        self.remaining_in_frame -= 1;
        self.pending_payload -= 1;
        Some(byte)
    }

    pub(super) fn pending(&self) -> usize {
        self.pending_payload
    }

    pub(super) fn copy_pending(&self, output: &mut [u8]) -> usize {
        let mut cursor = 0;
        let mut remaining = self.remaining_in_frame;
        let written = output.len().min(self.pending_payload);
        for byte in &mut output[..written] {
            if remaining == 0 {
                let low = self
                    .bytes
                    .get(cursor)
                    .expect("pending frame contains a length");
                let high = self
                    .bytes
                    .get(cursor + 1)
                    .expect("pending frame contains a length");
                remaining = usize::from(u16::from_le_bytes([low, high]));
                cursor += LENGTH_BYTES;
            }
            *byte = self
                .bytes
                .get(cursor)
                .expect("frame admission includes its payload");
            cursor += 1;
            remaining -= 1;
        }
        written
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.remaining_in_frame = 0;
        self.pending_payload = 0;
    }
}

pub(super) struct TransmitQueues {
    pub(super) log: FrameQueue<LOG_CAPACITY>,
    pub(super) console: FrameQueue<CONSOLE_CAPACITY>,
    prefer_console: bool,
}

impl TransmitQueues {
    pub(super) const fn new() -> Self {
        Self {
            log: FrameQueue::new(),
            console: FrameQueue::new(),
            prefer_console: false,
        }
    }

    pub(super) fn next_byte(&mut self) -> Option<u8> {
        // Each frame stays in service until its last byte goes to the UART.
        // Alternate between the two producers when both have pending frames.
        if self.log.remaining_in_frame != 0 {
            return self.log.pop();
        }
        if self.console.remaining_in_frame != 0 {
            return self.console.pop();
        }

        let console_ready = self.console.pending() != 0;
        if console_ready && (self.prefer_console || self.log.pending() == 0) {
            self.prefer_console = false;
            self.console.pop()
        } else {
            self.prefer_console = true;
            self.log.pop()
        }
    }

    pub(super) fn clear(&mut self) {
        self.log.clear();
        self.console.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameQueue, TransmitQueues};

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn saturation_preserves_whole_records_and_pending_snapshot() {
        let mut queue = FrameQueue::<14>::new();
        assert!(queue.push(b"prior\n"));
        assert!(!queue.push(b"prefix body\n"));

        let mut output = [0; 14];
        assert_eq!(queue.copy_pending(&mut output), 6);
        assert_eq!(&output[..6], b"prior\n");
        for _ in 0..5 {
            assert!(queue.pop().is_some());
        }

        assert!(queue.push(b"next line\n"));
        assert_eq!(queue.copy_pending(&mut output), 11);
        assert_eq!(&output[..11], b"\nnext line\n");
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn console_bytes_do_not_split_an_in_progress_log_frame() {
        let mut queue = TransmitQueues::new();
        assert!(queue.log.push(b"log\r\n"));
        assert_eq!(queue.next_byte(), Some(b'l'));
        assert!(queue.console.push(b"shell"));
        assert!(queue.log.push(b"next\r\n"));

        let remainder = b"og\r\nshellnext\r\n";
        for &byte in remainder {
            assert_eq!(queue.next_byte(), Some(byte));
        }
        assert_eq!(queue.next_byte(), None);
    }
}
