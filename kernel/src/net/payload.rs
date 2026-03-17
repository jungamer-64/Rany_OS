use alloc::vec;
use alloc::vec::Vec;
use kernel_api::resource::net::{PacketPayload, PacketRef};

pub struct PacketPayloadView<'a> {
    payload: &'a PacketPayload,
}

impl<'a> PacketPayloadView<'a> {
    pub const fn new(payload: &'a PacketPayload) -> Self {
        Self { payload }
    }

    pub fn total_len(&self) -> usize {
        self.payload.total_len()
    }

    pub fn is_empty(&self) -> bool {
        self.total_len() == 0
    }

    pub fn first_byte(&self) -> Option<u8> {
        match self.payload {
            PacketPayload::Single(packet) => packet.data().first().copied(),
            PacketPayload::Chain(chain) => chain
                .segments()
                .iter()
                .find_map(|segment| segment.data().first().copied()),
        }
    }

    pub fn first_segment(&self) -> Option<&'a PacketRef> {
        match self.payload {
            PacketPayload::Single(packet) => Some(packet),
            PacketPayload::Chain(chain) => chain.segments().first(),
        }
    }

    pub fn for_each_chunk(&self, mut f: impl FnMut(&[u8])) {
        match self.payload {
            PacketPayload::Single(packet) => {
                let data = packet.data();
                if !data.is_empty() {
                    f(data);
                }
            }
            PacketPayload::Chain(chain) => {
                for segment in chain.segments() {
                    let data = segment.data();
                    if !data.is_empty() {
                        f(data);
                    }
                }
            }
        }
    }

    pub fn copy_range(&self, offset: usize, dst: &mut [u8]) -> usize {
        if dst.is_empty() || offset >= self.total_len() {
            return 0;
        }

        let mut copied = 0usize;
        let mut cursor = 0usize;
        match self.payload {
            PacketPayload::Single(packet) => {
                let data = packet.data();
                let start = offset.min(data.len());
                let len = dst.len().min(data.len().saturating_sub(start));
                dst[..len].copy_from_slice(&data[start..start + len]);
                len
            }
            PacketPayload::Chain(chain) => {
                for segment in chain.segments() {
                    let data = segment.data();
                    if data.is_empty() {
                        continue;
                    }
                    let seg_start = cursor;
                    let seg_end = cursor.saturating_add(data.len());
                    cursor = seg_end;

                    if offset >= seg_end {
                        continue;
                    }

                    let local_offset = offset.saturating_sub(seg_start);
                    let available = data.len().saturating_sub(local_offset);
                    let take = available.min(dst.len().saturating_sub(copied));
                    if take == 0 {
                        break;
                    }
                    dst[copied..copied + take]
                        .copy_from_slice(&data[local_offset..local_offset + take]);
                    copied += take;
                    if copied == dst.len() {
                        break;
                    }
                }
                copied
            }
        }
    }

    pub fn read_vec(&self, offset: usize, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let copied = self.copy_range(offset, &mut out);
        out.truncate(copied);
        out
    }

    pub fn read_array<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        (self.copy_range(offset, &mut out) == N).then_some(out)
    }

    pub fn copy_all_into(&self, dst: &mut [u8]) -> usize {
        self.copy_range(0, dst)
    }
}
