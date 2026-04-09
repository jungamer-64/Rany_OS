use crate::net::l3::ipv4::IpProtocol;
use alloc::vec;
use alloc::vec::Vec;
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;
use kernel_api::resource::net::{PacketPayload, PacketRef};

#[derive(Debug, Clone)]
pub struct PayloadSpan {
    payload: PacketPayload,
    offset: usize,
    len: usize,
}

impl PayloadSpan {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        Some(Self::from_payload(payload_from_bytes(data)?))
    }

    pub fn from_payload(payload: PacketPayload) -> Self {
        let len = payload.total_len();
        Self {
            payload,
            offset: 0,
            len,
        }
    }

    pub fn from_range(payload: PacketPayload, offset: usize, len: usize) -> Option<Self> {
        let total_len = payload.total_len();
        if offset > total_len || len > total_len.saturating_sub(offset) {
            return None;
        }
        Some(Self {
            payload,
            offset,
            len,
        })
    }

    pub fn payload(&self) -> &PacketPayload {
        &self.payload
    }

    pub fn total_len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn to_payload(&self) -> Option<PacketPayload> {
        payload_range(&self.payload, self.offset, self.len)
    }

    pub fn slice(&self, offset: usize, len: usize) -> Option<Self> {
        if offset > self.len || len > self.len.saturating_sub(offset) {
            return None;
        }
        Self::from_range(self.payload.clone(), self.offset + offset, len)
    }

    pub fn byte_at(&self, index: usize) -> Option<u8> {
        if index >= self.len {
            return None;
        }
        PacketPayloadView::new(&self.payload)
            .read_array::<1>(self.offset + index)
            .map(|bytes| bytes[0])
    }

    pub fn as_contiguous_slice(&self) -> Option<&[u8]> {
        match &self.payload {
            PacketPayload::Single(packet) => {
                let end = self.offset.checked_add(self.len)?;
                packet.data().get(self.offset..end)
            }
            PacketPayload::Chain(_) => None,
        }
    }

    pub fn copy_into(&self, dst: &mut [u8]) -> usize {
        let len = self.len.min(dst.len());
        PacketPayloadView::new(&self.payload).copy_range(self.offset, &mut dst[..len])
    }

    pub fn eq_bytes(&self, bytes: &[u8]) -> bool {
        if self.len != bytes.len() {
            return false;
        }
        bytes.iter()
            .enumerate()
            .all(|(index, expected)| self.byte_at(index) == Some(*expected))
    }

    pub fn eq_ignore_ascii_case(&self, bytes: &[u8]) -> bool {
        if self.len != bytes.len() {
            return false;
        }
        bytes.iter().enumerate().all(|(index, expected)| {
            self.byte_at(index)
                .map(|actual| actual.eq_ignore_ascii_case(expected))
                .unwrap_or(false)
        })
    }

    pub fn contains_ascii_case(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        let Some(max_start) = self.len.checked_sub(needle.len()) else {
            return false;
        };
        (0..=max_start).any(|start| {
            needle.iter().enumerate().all(|(index, expected)| {
                self.byte_at(start + index)
                    .map(|actual| actual.eq_ignore_ascii_case(expected))
                    .unwrap_or(false)
            })
        })
    }

    pub fn find_bytes(&self, pattern: &[u8]) -> Option<usize> {
        self.find_bytes_from(pattern, 0)
    }

    pub fn find_bytes_from(&self, pattern: &[u8], start: usize) -> Option<usize> {
        if pattern.is_empty() {
            return (start <= self.len).then_some(start);
        }
        let max_start = self.len.checked_sub(pattern.len())?;
        if start > max_start {
            return None;
        }
        (start..=max_start).find(|candidate| {
            pattern.iter().enumerate().all(|(index, expected)| {
                self.byte_at(*candidate + index) == Some(*expected)
            })
        })
    }

    pub fn parse_ascii_usize(&self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        let mut value = 0usize;
        for index in 0..self.len {
            let digit = self.byte_at(index)?;
            if !digit.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?.checked_add((digit - b'0') as usize)?;
        }
        Some(value)
    }

    pub fn parse_ascii_hex_usize(&self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        let mut value = 0usize;
        for index in 0..self.len {
            let digit = self.byte_at(index)?;
            let nibble = match digit {
                b'0'..=b'9' => (digit - b'0') as usize,
                b'a'..=b'f' => (digit - b'a' + 10) as usize,
                b'A'..=b'F' => (digit - b'A' + 10) as usize,
                _ => return None,
            };
            value = value.checked_mul(16)?.checked_add(nibble)?;
        }
        Some(value)
    }

    pub fn trim_ascii_whitespace(&self) -> Self {
        let mut start = 0usize;
        let mut end = self.len;

        while start < end {
            let Some(byte) = self.byte_at(start) else {
                break;
            };
            if !byte.is_ascii_whitespace() {
                break;
            }
            start += 1;
        }

        while end > start {
            let Some(byte) = self.byte_at(end - 1) else {
                break;
            };
            if !byte.is_ascii_whitespace() {
                break;
            }
            end -= 1;
        }

        Self {
            payload: self.payload.clone(),
            offset: self.offset + start,
            len: end - start,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PayloadSequence {
    spans: Vec<PayloadSpan>,
    total_len: usize,
}

impl PayloadSequence {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, span: PayloadSpan) {
        self.total_len = self.total_len.saturating_add(span.total_len());
        self.spans.push(span);
    }

    pub fn spans(&self) -> &[PayloadSpan] {
        &self.spans
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    pub fn into_payload(self) -> Option<PacketPayload> {
        let mut combined = PacketPayload::default();
        for span in self.spans {
            append_payload(&mut combined, span.to_payload()?);
        }
        Some(combined)
    }
}

pub struct PacketPayloadBuilder {
    segments: Vec<PacketRef>,
}

impl PacketPayloadBuilder {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn push_bytes(&mut self, data: &[u8]) -> Option<()> {
        if data.is_empty() {
            return Some(());
        }
        let mut packet = alloc_packet_for_len(data.len())?;
        packet.data_mut()[..data.len()].copy_from_slice(data);
        self.segments.push(packet);
        Some(())
    }

    pub fn push_str(&mut self, data: &str) -> Option<()> {
        self.push_bytes(data.as_bytes())
    }

    pub fn push_payload(&mut self, payload: PacketPayload) {
        self.segments.extend(payload.into_segments());
    }

    pub fn build(self) -> PacketPayload {
        match self.segments.len() {
            0 => PacketPayload::default(),
            1 => PacketPayload::single(self.segments.into_iter().next().expect("single segment")),
            _ => PacketPayload::chain(kernel_api::resource::net::PacketChain::from_segments(
                self.segments,
            )),
        }
    }
}

pub fn append_payload(target: &mut PacketPayload, payload: PacketPayload) {
    if payload.is_empty() {
        return;
    }
    if target.is_empty() {
        *target = payload;
        return;
    }

    let mut segments = core::mem::take(target).into_segments();
    segments.extend(payload.into_segments());
    *target = if segments.len() == 1 {
        PacketPayload::single(segments.remove(0))
    } else {
        PacketPayload::chain(kernel_api::resource::net::PacketChain::from_segments(segments))
    };
}

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
