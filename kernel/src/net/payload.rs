use crate::net::l3::ipv4::IpProtocol;
use alloc::vec;
use alloc::vec::Vec;
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;
use kernel_api::resource::net::{PacketPayload, PacketRef};

pub struct PacketPayloadView<'a> {
    payload: &'a PacketPayload,
}

impl<'a> PacketPayloadView<'a> {
    pub const fn new(payload: &'a PacketPayload) -> Self {
        Self { payload }
    }

    pub const fn payload(&self) -> &'a PacketPayload {
        self.payload
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

    pub fn cursor(&self) -> PacketPayloadCursor<'_> {
        PacketPayloadCursor {
            view: PacketPayloadView::new(self.payload),
            offset: 0,
        }
    }
}

pub struct PacketPayloadCursor<'a> {
    view: PacketPayloadView<'a>,
    offset: usize,
}

impl<'a> PacketPayloadCursor<'a> {
    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn remaining(&self) -> usize {
        self.view.total_len().saturating_sub(self.offset)
    }

    pub fn skip(&mut self, len: usize) -> bool {
        if len > self.remaining() {
            return false;
        }
        self.offset += len;
        true
    }

    pub fn read_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let out = self.view.read_array::<N>(self.offset)?;
        self.offset += N;
        Some(out)
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        self.read_array::<1>().map(|bytes| bytes[0])
    }

    pub fn read_u16_be(&mut self) -> Option<u16> {
        self.read_array::<2>().map(u16::from_be_bytes)
    }

    pub fn read_u32_be(&mut self) -> Option<u32> {
        self.read_array::<4>().map(u32::from_be_bytes)
    }

    pub fn read_vec(&mut self, len: usize) -> Vec<u8> {
        let bytes = self.view.read_vec(self.offset, len);
        self.offset = self.offset.saturating_add(bytes.len());
        bytes
    }

    pub fn copy_into(&mut self, dst: &mut [u8]) -> usize {
        let copied = self.view.copy_range(self.offset, dst);
        self.offset = self.offset.saturating_add(copied);
        copied
    }
}

pub fn alloc_packet_with_headroom(len: usize, headroom: usize) -> Option<PacketRef> {
    if let Some(mut packet) = crate::net::datapath::mempool::alloc_packet() {
        let available_headroom = packet.headroom();
        let capacity = packet.capacity().saturating_sub(available_headroom);
        if headroom <= available_headroom && len <= capacity {
            packet.set_len(len);
            return Some(packet);
        }
    }

    let dma_len = len.saturating_add(headroom.max(DEFAULT_PACKET_HEADROOM));
    let dma_buf = crate::io::dma::TypedDmaSlice::<crate::io::dma::CpuOwned>::new(dma_len)?;
    let mut packet = crate::net::datapath::mempool::packet_ref_from_dma_slice(dma_buf);
    let available_headroom = packet.headroom();
    let capacity = packet.capacity().saturating_sub(available_headroom);
    if headroom > available_headroom || len > capacity {
        return None;
    }
    packet.set_len(len);
    Some(packet)
}

fn alloc_packet_for_len(len: usize) -> Option<PacketRef> {
    alloc_packet_with_headroom(len, DEFAULT_PACKET_HEADROOM)
}

pub fn packet_from_bytes(data: &[u8]) -> Option<PacketRef> {
    let len = data.len();
    let mut packet = alloc_packet_for_len(len)?;
    if len > 0 {
        packet.data_mut()[..len].copy_from_slice(data);
    }
    Some(packet)
}

pub fn subslice_offset(container: &[u8], subslice: &[u8]) -> Option<usize> {
    let base = container.as_ptr() as usize;
    let sub = subslice.as_ptr() as usize;
    let end = base.checked_add(container.len())?;
    let sub_end = sub.checked_add(subslice.len())?;
    (sub >= base && sub_end <= end).then_some(sub - base)
}

pub fn payload_from_packet_range(
    packet: &PacketRef,
    offset: usize,
    len: usize,
) -> Option<PacketPayload> {
    let packet_len = packet.data().len();
    if offset.checked_add(len)? > packet_len {
        return None;
    }

    let mut packet = packet.clone();
    packet.advance(offset);
    packet.set_len(len);
    Some(PacketPayload::single(packet))
}

pub fn payload_from_subslice(
    packet: &PacketRef,
    container: &[u8],
    subslice: &[u8],
) -> Option<PacketPayload> {
    let offset = subslice_offset(container, subslice)?;
    payload_from_packet_range(packet, offset, subslice.len())
}

pub fn payload_range(payload: &PacketPayload, offset: usize, len: usize) -> Option<PacketPayload> {
    payload.slice(offset, len)
}

pub fn ipv6_transport_payload(payload: &PacketPayload) -> Option<(IpProtocol, PacketPayload)> {
    const IPV6_HEADER_SIZE: usize = 40;
    const EXT_HEADER_HOP_BY_HOP: u8 = 0;
    const EXT_HEADER_ROUTING: u8 = 43;
    const EXT_HEADER_FRAGMENT: u8 = 44;
    const EXT_HEADER_AUTH: u8 = 51;
    const EXT_HEADER_DESTINATION: u8 = 60;
    const EXT_HEADER_NO_NEXT: u8 = 59;
    const MAX_EXTENSION_HEADERS: usize = 16;

    let view = PacketPayloadView::new(payload);
    if view.total_len() < IPV6_HEADER_SIZE {
        return None;
    }

    let mut next_header = IpProtocol::from(view.read_array::<1>(6)?[0]);
    let mut offset = IPV6_HEADER_SIZE;
    let mut headers_seen = 0usize;

    loop {
        headers_seen += 1;
        if headers_seen > MAX_EXTENSION_HEADERS {
            return None;
        }

        match u8::from(next_header) {
            EXT_HEADER_HOP_BY_HOP | EXT_HEADER_ROUTING | EXT_HEADER_DESTINATION => {
                let header = view.read_array::<3>(offset)?;
                if header[0] == EXT_HEADER_NO_NEXT {
                    return None;
                }
                if u8::from(next_header) == EXT_HEADER_ROUTING && header[2] == 0 {
                    return None;
                }
                let ext_len = (header[1] as usize + 1) * 8;
                if offset.checked_add(ext_len)? > view.total_len() {
                    return None;
                }
                next_header = IpProtocol::from(header[0]);
                offset += ext_len;
            }
            EXT_HEADER_AUTH => {
                let header = view.read_array::<2>(offset)?;
                if header[0] == EXT_HEADER_NO_NEXT {
                    return None;
                }
                let ext_len = (header[1] as usize + 2) * 4;
                if offset.checked_add(ext_len)? > view.total_len() {
                    return None;
                }
                next_header = IpProtocol::from(header[0]);
                offset += ext_len;
            }
            EXT_HEADER_FRAGMENT => {
                let header = view.read_array::<8>(offset)?;
                let off_and_flags = u16::from_be_bytes([header[2], header[3]]);
                let frag_offset = (off_and_flags & 0xfff8) >> 3;
                let more_fragments = (off_and_flags & 0x1) != 0;
                if frag_offset != 0 || more_fragments {
                    return None;
                }
                next_header = IpProtocol::from(header[0]);
                offset += 8;
            }
            _ => break,
        }
    }

    let transport_len = view.total_len().checked_sub(offset)?;
    payload_range(payload, offset, transport_len).map(|transport| (next_header, transport))
}

pub fn payload_from_bytes(data: &[u8]) -> Option<PacketPayload> {
    packet_from_bytes(data).map(PacketPayload::single)
}
