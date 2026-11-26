pub(super) struct RingBuffer<const N: usize> {
    bytes: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> RingBuffer<N> {
    pub(super) const fn new() -> Self {
        assert!(N > 0);
        Self {
            bytes: [0; N],
            head: 0,
            len: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn spare(&self) -> usize {
        N - self.len
    }

    pub(super) fn get(&self, index: usize) -> Option<u8> {
        (index < self.len).then(|| self.bytes[(self.head + index) % N])
    }

    pub(super) fn push(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.spare() {
            return false;
        }
        let tail = (self.head + self.len) % N;
        let first = bytes.len().min(N - tail);
        self.bytes[tail..tail + first].copy_from_slice(&bytes[..first]);
        self.bytes[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.len += bytes.len();
        true
    }

    pub(super) fn copy_at(&self, offset: usize, dst: &mut [u8]) {
        assert!(offset <= self.len && dst.len() <= self.len - offset);
        let start = (self.head + offset) % N;
        let first = dst.len().min(N - start);
        let (tail, head) = dst.split_at_mut(first);
        tail.copy_from_slice(&self.bytes[start..start + first]);
        head.copy_from_slice(&self.bytes[..head.len()]);
    }

    pub(super) fn discard(&mut self, len: usize) {
        assert!(len <= self.len);
        self.head = (self.head + len) % N;
        self.len -= len;
    }

    pub(super) fn pop(&mut self) -> Option<u8> {
        let byte = self.get(0)?;
        self.discard(1);
        Some(byte)
    }

    pub(super) fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}
