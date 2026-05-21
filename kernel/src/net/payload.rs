// ============================================================================
// kernel/src/net/payload.rs - Packet payload ownership model
// ============================================================================

use crate::net::l3::ipv4::IpProtocol;
use alloc::vec::Vec;
use kernel_api::resource::net::{
    PacketByteCount, PacketChain, PacketPayload, PacketPayloadFront, PacketRef, PacketWindowError,
};

#[derive(Debug, Clone, Copy)]
pub struct PayloadSpanRef<'a> {
    payload: &'a PacketPayload,
    offset: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadByteOffset(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadByteLen(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadRange {
    offset: PayloadByteOffset,
    len: PayloadByteLen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedPayloadBounds {
    offset: PayloadByteOffset,
    len: PayloadByteLen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutablePayloadBounds {
    offset: PayloadByteOffset,
    len: PayloadByteLen,
}

#[derive(Debug)]
pub struct FixedPayloadBytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedPayloadBytes<N> {
    pub const fn as_slice(&self) -> &[u8] {
        self.bytes.split_at(self.len).0
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl PayloadRange {
    pub fn checked(payload: &PacketPayload, offset: usize, len: usize) -> Option<Self> {
        if offset > payload.total_len() || len > payload.total_len().saturating_sub(offset) {
            return None;
        }
        Some(Self {
            offset: PayloadByteOffset(offset),
            len: PayloadByteLen(len),
        })
    }

    pub const fn from_span(span: PayloadSpanRef<'_>) -> Self {
        Self {
            offset: PayloadByteOffset(span.offset),
            len: PayloadByteLen(span.len),
        }
    }

    pub const fn offset(&self) -> usize {
        self.offset.get()
    }

    pub const fn total_len(&self) -> usize {
        self.len.get()
    }

    pub const fn checked_end_offset(&self) -> Option<usize> {
        self.offset.get().checked_add(self.len.get())
    }

    pub fn span<'a>(&self, payload: &'a PacketPayload) -> Option<PayloadSpanRef<'a>> {
        PayloadSpanRef::from_range(payload, *self)
    }
}

impl OwnedPayloadBounds {
    pub fn checked(payload: &PacketPayload, offset: usize, len: usize) -> Option<Self> {
        checked_payload_bounds(payload, offset, len).map(|(offset, len)| Self { offset, len })
    }

    pub const fn offset(self) -> usize {
        self.offset.get()
    }

    pub const fn total_len(self) -> usize {
        self.len.get()
    }

    pub fn take_from(self, payload: PacketPayload) -> Option<OwnedPayloadWindow> {
        checked_payload_bounds(&payload, self.offset(), self.total_len())?;
        Some(OwnedPayloadWindow {
            payload,
            range: self.into_range(),
        })
    }

    const fn into_range(self) -> PayloadRange {
        PayloadRange {
            offset: self.offset,
            len: self.len,
        }
    }
}

impl MutablePayloadBounds {
    pub fn checked(payload: &PacketPayload, offset: usize, len: usize) -> Option<Self> {
        checked_payload_bounds(payload, offset, len).map(|(offset, len)| Self { offset, len })
    }

    pub const fn offset(self) -> usize {
        self.offset.get()
    }

    pub const fn total_len(self) -> usize {
        self.len.get()
    }

    pub fn open<'a>(self, payload: &'a mut PacketPayload) -> Option<PayloadSpanMut<'a>> {
        checked_payload_bounds(payload, self.offset(), self.total_len())?;
        Some(PayloadSpanMut {
            payload,
            offset: self.offset(),
            len: self.total_len(),
        })
    }

    pub fn span<'a>(self, payload: &'a PacketPayload) -> Option<PayloadSpanRef<'a>> {
        checked_payload_bounds(payload, self.offset(), self.total_len())?;
        PayloadSpanRef::from_range(payload, self.into_range())
    }

    const fn into_range(self) -> PayloadRange {
        PayloadRange {
            offset: self.offset,
            len: self.len,
        }
    }
}

fn checked_payload_bounds(
    payload: &PacketPayload,
    offset: usize,
    len: usize,
) -> Option<(PayloadByteOffset, PayloadByteLen)> {
    if offset > payload.total_len() || len > payload.total_len().saturating_sub(offset) {
        return None;
    }
    Some((PayloadByteOffset(offset), PayloadByteLen(len)))
}

impl PayloadByteOffset {
    pub const ZERO: Self = Self(0);

    pub const fn get(self) -> usize {
        self.0
    }
}

impl PayloadByteLen {
    pub const ZERO: Self = Self(0);

    pub const fn get(self) -> usize {
        self.0
    }
}

impl<'a> PayloadSpanRef<'a> {
    pub fn from_payload(payload: &'a PacketPayload) -> Self {
        Self {
            payload,
            offset: 0,
            len: payload.total_len(),
        }
    }

    pub fn from_range(payload: &'a PacketPayload, range: PayloadRange) -> Option<Self> {
        PayloadRange::checked(payload, range.offset(), range.total_len())?;
        Some(Self {
            payload,
            offset: range.offset(),
            len: range.total_len(),
        })
    }

    pub const fn payload(&self) -> &'a PacketPayload {
        self.payload
    }

    pub const fn offset(&self) -> usize {
        self.offset
    }

    pub const fn total_len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn range(self) -> PayloadRange {
        PayloadRange {
            offset: PayloadByteOffset(self.offset),
            len: PayloadByteLen(self.len),
        }
    }

    pub fn subspan(self, offset: usize, len: usize) -> Option<Self> {
        if offset > self.len || len > self.len.saturating_sub(offset) {
            return None;
        }
        Self::from_range(
            self.payload,
            PayloadRange::checked(self.payload, self.offset.checked_add(offset)?, len)?,
        )
    }

    pub fn byte_at(&self, index: usize) -> Option<u8> {
        if index >= self.len {
            return None;
        }
        PacketPayloadView::new(self.payload)
            .read_array::<1>(self.offset + index)
            .map(|bytes| bytes[0])
    }

    pub fn read_array<const N: usize>(&self, index: usize) -> Option<[u8; N]> {
        if index.checked_add(N)? > self.len {
            return None;
        }
        PacketPayloadView::new(self.payload).read_array(self.offset + index)
    }

    pub fn read_fixed_bytes<const N: usize>(&self, len: usize) -> Option<FixedPayloadBytes<N>> {
        if len > self.len || len > N {
            return None;
        }
        PacketPayloadView::new(self.payload).read_fixed_bytes(self.offset, len)
    }

    pub fn read_u8(&self, index: usize) -> Option<u8> {
        self.read_array::<1>(index).map(|bytes| bytes[0])
    }

    pub fn read_u16_be(&self, index: usize) -> Option<u16> {
        self.read_array::<2>(index).map(u16::from_be_bytes)
    }

    pub fn read_u24_be(&self, index: usize) -> Option<u32> {
        self.read_array::<3>(index)
            .map(|bytes| ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32)
    }

    pub fn read_u32_be(&self, index: usize) -> Option<u32> {
        self.read_array::<4>(index).map(u32::from_be_bytes)
    }

    pub fn for_each_chunk(&self, mut f: impl FnMut(&[u8])) {
        let span_start = self.offset;
        let span_end = self.offset.saturating_add(self.len);
        let mut cursor = 0usize;

        PacketPayloadView::new(self.payload).for_each_chunk(|chunk| {
            let chunk_start = cursor;
            let chunk_end = cursor.saturating_add(chunk.len());
            cursor = chunk_end;

            if chunk_end <= span_start || chunk_start >= span_end {
                return;
            }

            let local_start = span_start.saturating_sub(chunk_start);
            let local_end = chunk.len().min(span_end.saturating_sub(chunk_start));
            if local_start < local_end {
                f(&chunk[local_start..local_end]);
            }
        });
    }

    pub fn eq_bytes(&self, bytes: &[u8]) -> bool {
        if self.len != bytes.len() {
            return false;
        }
        bytes
            .iter()
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
            pattern
                .iter()
                .enumerate()
                .all(|(index, expected)| self.byte_at(*candidate + index) == Some(*expected))
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
            value = value
                .checked_mul(10)?
                .checked_add((digit - b'0') as usize)?;
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

    pub fn trim_ascii_whitespace(self) -> Option<Self> {
        let mut start = 0usize;
        let mut end = self.len;

        while start < end {
            let byte = self.byte_at(start)?;
            if !byte.is_ascii_whitespace() {
                break;
            }
            start += 1;
        }

        while end > start {
            let byte = self.byte_at(end - 1)?;
            if !byte.is_ascii_whitespace() {
                break;
            }
            end -= 1;
        }

        Self::from_range(
            self.payload,
            PayloadRange::checked(self.payload, self.offset.checked_add(start)?, end - start)?,
        )
    }

    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        prefix
            .iter()
            .enumerate()
            .all(|(index, expected)| self.byte_at(index) == Some(*expected))
    }

    pub fn ends_with(&self, suffix: &[u8]) -> bool {
        let Some(start) = self.len.checked_sub(suffix.len()) else {
            return false;
        };
        suffix
            .iter()
            .enumerate()
            .all(|(index, expected)| self.byte_at(start + index) == Some(*expected))
    }

    pub fn cursor(&self) -> PacketPayloadCursor<'a> {
        PacketPayloadCursor {
            view: PacketPayloadView::new(self.payload),
            offset: self.offset,
            end: self.offset.saturating_add(self.len),
        }
    }
}

pub struct OwnedPayloadWindow {
    payload: PacketPayload,
    range: PayloadRange,
}

pub type PayloadFront = PacketPayloadFront;

pub struct GeneratedPacketWriter {
    packet: PacketRef,
    offset: usize,
}

impl OwnedPayloadWindow {
    pub fn whole(payload: PacketPayload) -> Self {
        let range = PayloadRange {
            offset: PayloadByteOffset::ZERO,
            len: PayloadByteLen(payload.total_len()),
        };
        Self { payload, range }
    }

    pub fn span(&self) -> PayloadSpanRef<'_> {
        PayloadSpanRef::from_range(&self.payload, self.range)
            .expect("OwnedPayloadWindow bounds are validated at construction")
    }

    pub fn into_original_payload(self) -> PacketPayload {
        self.payload
    }

    pub fn into_payload(self) -> Result<PacketPayload, PacketWindowError> {
        let offset = self.range.offset();
        let len = self.range.total_len();
        if len == 0 {
            return Ok(PacketPayload::default());
        }

        let payload = if offset == 0 {
            self.payload
        } else {
            let prefix_len = PacketByteCount::new(offset).ok_or(PacketWindowError::Empty)?;
            match self.payload.take_front(prefix_len)? {
                PacketPayloadFront::Whole(_) => return Err(PacketWindowError::OutOfBounds),
                PacketPayloadFront::Prefix { remainder, .. } => remainder,
            }
        };

        if payload.total_len() == len {
            return Ok(payload);
        }

        let front_len = PacketByteCount::new(len).ok_or(PacketWindowError::Empty)?;
        match payload.take_front(front_len)? {
            PacketPayloadFront::Whole(payload) => Ok(payload),
            PacketPayloadFront::Prefix { front, .. } => Ok(front),
        }
    }
}

impl GeneratedPacketWriter {
    pub fn new(len: usize, headroom: usize) -> Option<Self> {
        Some(Self {
            packet: alloc_packet_with_headroom(len, headroom)?,
            offset: 0,
        })
    }

    pub fn write_u8(&mut self, value: u8) -> Option<()> {
        self.write_generated_bytes(&[value])
    }

    pub fn write_u16_be(&mut self, value: u16) -> Option<()> {
        self.write_generated_bytes(&value.to_be_bytes())
    }

    pub fn write_u24_be(&mut self, value: u32) -> Option<()> {
        self.write_generated_bytes(&[
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ])
    }

    pub fn write_u32_be(&mut self, value: u32) -> Option<()> {
        self.write_generated_bytes(&value.to_be_bytes())
    }

    pub fn write_generated_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.offset.checked_add(bytes.len())?;
        let data = self.packet.data_mut();
        if end > data.len() {
            return None;
        }
        data[self.offset..end].copy_from_slice(bytes);
        self.offset = end;
        Some(())
    }

    pub fn finish(self) -> Option<PacketPayload> {
        (self.offset == self.packet.len()).then(|| PacketPayload::single(self.packet))
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
        PacketPayload::chain(kernel_api::resource::net::PacketChain::from_segments(
            segments,
        ))
    };
}

pub fn packet_payload_from_segments(mut segments: Vec<PacketRef>) -> PacketPayload {
    match segments.len() {
        0 => PacketPayload::default(),
        1 => PacketPayload::single(segments.remove(0)),
        _ => PacketPayload::chain(PacketChain::from_segments(segments)),
    }
}

pub struct PacketPayloadView<'a> {
    payload: &'a PacketPayload,
}

pub struct PayloadSpanMut<'a> {
    payload: &'a mut PacketPayload,
    offset: usize,
    len: usize,
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

    pub fn read_array<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        if offset.checked_add(N)? > self.total_len() {
            return None;
        }

        let mut out = [0u8; N];
        let mut payload_cursor = 0usize;
        let mut copied = 0usize;

        self.for_each_chunk(|chunk| {
            if copied == N {
                return;
            }

            let chunk_start = payload_cursor;
            let chunk_end = payload_cursor.saturating_add(chunk.len());
            payload_cursor = chunk_end;

            if chunk_end <= offset {
                return;
            }

            let local_start = offset.saturating_sub(chunk_start);
            let available = chunk.len().saturating_sub(local_start);
            let take = available.min(N.saturating_sub(copied));
            if take == 0 {
                return;
            }

            out[copied..copied + take].copy_from_slice(&chunk[local_start..local_start + take]);
            copied += take;
        });

        (copied == N).then_some(out)
    }

    pub fn read_fixed_bytes<const N: usize>(
        &self,
        offset: usize,
        len: usize,
    ) -> Option<FixedPayloadBytes<N>> {
        if len > N || offset.checked_add(len)? > self.total_len() {
            return None;
        }

        let mut bytes = [0u8; N];
        let mut payload_cursor = 0usize;
        let mut copied = 0usize;

        self.for_each_chunk(|chunk| {
            if copied == len {
                return;
            }

            let chunk_start = payload_cursor;
            let chunk_end = payload_cursor.saturating_add(chunk.len());
            payload_cursor = chunk_end;

            if chunk_end <= offset {
                return;
            }

            let local_start = offset.saturating_sub(chunk_start);
            let available = chunk.len().saturating_sub(local_start);
            let take = available.min(len.saturating_sub(copied));
            if take == 0 {
                return;
            }

            bytes[copied..copied + take].copy_from_slice(&chunk[local_start..local_start + take]);
            copied += take;
        });

        (copied == len).then_some(FixedPayloadBytes { bytes, len })
    }

    pub fn read_u8(&self, offset: usize) -> Option<u8> {
        self.read_array::<1>(offset).map(|bytes| bytes[0])
    }

    pub fn read_u16_be(&self, offset: usize) -> Option<u16> {
        self.read_array::<2>(offset).map(u16::from_be_bytes)
    }

    pub fn read_u24_be(&self, offset: usize) -> Option<u32> {
        self.read_array::<3>(offset)
            .map(|bytes| ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32)
    }

    pub fn read_u32_be(&self, offset: usize) -> Option<u32> {
        self.read_array::<4>(offset).map(u32::from_be_bytes)
    }

    pub fn cursor(&self) -> PacketPayloadCursor<'_> {
        PacketPayloadCursor {
            view: PacketPayloadView::new(self.payload),
            offset: 0,
            end: self.total_len(),
        }
    }
}

impl<'a> PayloadSpanMut<'a> {
    pub fn whole(payload: &'a mut PacketPayload) -> Self {
        let len = payload.total_len();
        Self {
            payload,
            offset: 0,
            len,
        }
    }

    pub fn for_each_chunk_mut(&mut self, mut f: impl FnMut(&mut [u8])) {
        let span_start = self.offset;
        let span_end = self.offset + self.len;
        let mut cursor = 0usize;

        for segment in self.payload.segments_mut() {
            let segment_len = segment.len();
            let segment_start = cursor;
            let segment_end = cursor + segment_len;
            cursor = segment_end;

            if segment_end <= span_start || segment_start >= span_end {
                continue;
            }

            let local_start = span_start.saturating_sub(segment_start);
            let local_end = segment_len.min(span_end.saturating_sub(segment_start));
            if local_start < local_end {
                f(&mut segment.data_mut()[local_start..local_end]);
            }
        }
    }
}

pub struct PacketPayloadCursor<'a> {
    view: PacketPayloadView<'a>,
    offset: usize,
    end: usize,
}

impl<'a> PacketPayloadCursor<'a> {
    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.offset)
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

    pub fn read_u24_be(&mut self) -> Option<u32> {
        self.read_array::<3>()
            .map(|bytes| ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32)
    }

    pub fn take_span(&mut self, len: usize) -> Option<PayloadSpanRef<'a>> {
        if len > self.remaining() {
            return None;
        }
        let span = PayloadSpanRef::from_range(
            self.view.payload(),
            PayloadRange::checked(self.view.payload(), self.offset, len)?,
        )?;
        self.offset += len;
        Some(span)
    }

    pub fn remaining_span(&self) -> Option<PayloadSpanRef<'a>> {
        PayloadSpanRef::from_range(
            self.view.payload(),
            PayloadRange::checked(self.view.payload(), self.offset, self.remaining())?,
        )
    }
}

pub fn alloc_packet_with_headroom(len: usize, headroom: usize) -> Option<PacketRef> {
    let visible_len = PacketByteCount::new(len)?;
    if let Some(mut packet) = crate::net::datapath::mempool::alloc_packet() {
        let available_headroom = packet.headroom();
        let capacity = packet.capacity().saturating_sub(available_headroom);
        if headroom <= available_headroom && len <= capacity {
            if !packet.set_len(visible_len) {
                return None;
            }
            return Some(packet);
        }
    }

    let dma_len = len.checked_add(headroom)?;
    let dma_buf = crate::io::dma::TypedDmaSlice::<crate::io::dma::CpuOwned>::new(dma_len)?;
    let mut packet =
        crate::net::datapath::mempool::packet_ref_from_dma_slice_with_headroom(dma_buf, headroom)?;
    if !packet.set_len(visible_len) {
        return None;
    }
    Some(packet)
}

pub fn ipv6_transport_payload(payload: &PacketPayload) -> Option<(IpProtocol, PayloadSpanRef<'_>)> {
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
    PayloadRange::checked(payload, offset, transport_len)
        .and_then(|range| PayloadSpanRef::from_range(payload, range))
        .map(|transport| (next_header, transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    #[test]
    fn payload_range_checked_end_rejects_overflow() {
        let range = PayloadRange {
            offset: PayloadByteOffset(usize::MAX),
            len: PayloadByteLen(1),
        };

        assert_eq!(range.checked_end_offset(), None);
    }

    #[test]
    fn trim_ascii_whitespace_rejects_invalid_span_instead_of_widening() {
        let payload = PacketPayload::default();
        let span = PayloadSpanRef {
            payload: &payload,
            offset: usize::MAX,
            len: 1,
        };

        assert!(span.trim_ascii_whitespace().is_none());
    }

    #[test]
    fn alloc_packet_with_large_headroom_preserves_requested_headroom() {
        let requested_headroom = DEFAULT_PACKET_HEADROOM.saturating_mul(2);
        let packet =
            alloc_packet_with_headroom(128, requested_headroom).expect("packet allocation");

        assert!(packet.headroom() >= requested_headroom);
        assert_eq!(packet.len(), 128);
    }

    #[test]
    fn alloc_packet_with_headroom_rejects_length_overflow() {
        assert!(alloc_packet_with_headroom(usize::MAX, 1).is_none());
    }

    #[test]
    fn payload_bound_window_rejects_out_of_bounds_request() {
        let payload = PacketPayload::single(test_packet_with_contents(b"abcd"));

        let bounds = OwnedPayloadBounds::checked(&payload, 4, 0).expect("empty tail bounds");
        assert!(bounds.take_from(payload).is_some());
        let payload = PacketPayload::single(test_packet_with_contents(b"abcd"));
        assert!(PayloadRange::checked(&payload, 5, 0).is_none());
        let payload = PacketPayload::single(test_packet_with_contents(b"abcd"));
        assert!(PayloadRange::checked(&payload, 3, 2).is_none());
    }

    fn test_packet_with_contents(bytes: &[u8]) -> PacketRef {
        let mut packet =
            alloc_packet_with_headroom(bytes.len(), DEFAULT_PACKET_HEADROOM).expect("packet");
        packet.data_mut().copy_from_slice(bytes);
        packet
    }

    fn assert_payload_bytes(payload: &PacketPayload, expected: &[u8]) {
        assert!(PayloadSpanRef::from_payload(payload).eq_bytes(expected));
    }

    #[test]
    fn packet_payload_take_front_splits_single_packet() {
        let payload = PacketPayload::single(test_packet_with_contents(b"abcdef"));
        let len = PacketByteCount::new(3).expect("non-empty prefix");

        let (front, remainder) = match payload.take_front(len).expect("single split") {
            PacketPayloadFront::Prefix { front, remainder } => (front, remainder),
            PacketPayloadFront::Whole(_) => panic!("partial split must produce prefix"),
        };

        assert_payload_bytes(&front, b"abc");
        assert_payload_bytes(&remainder, b"def");
    }

    #[test]
    fn packet_payload_take_front_splits_on_chain_boundary() {
        let payload = PacketPayload::chain(PacketChain::from_segments(alloc::vec![
            test_packet_with_contents(b"abc"),
            test_packet_with_contents(b"def"),
        ]));
        let len = PacketByteCount::new(3).expect("non-empty prefix");

        let (front, remainder) = match payload.take_front(len).expect("chain boundary split") {
            PacketPayloadFront::Prefix { front, remainder } => (front, remainder),
            PacketPayloadFront::Whole(_) => panic!("partial split must produce prefix"),
        };

        assert_payload_bytes(&front, b"abc");
        assert_payload_bytes(&remainder, b"def");
    }

    #[test]
    fn packet_payload_take_front_splits_inside_chain_segment() {
        let payload = PacketPayload::chain(PacketChain::from_segments(alloc::vec![
            test_packet_with_contents(b"abc"),
            test_packet_with_contents(b"defgh"),
        ]));
        let len = PacketByteCount::new(5).expect("non-empty prefix");

        let (front, remainder) = match payload.take_front(len).expect("middle segment split") {
            PacketPayloadFront::Prefix { front, remainder } => (front, remainder),
            PacketPayloadFront::Whole(_) => panic!("partial split must produce prefix"),
        };

        assert_payload_bytes(&front, b"abcde");
        assert_payload_bytes(&remainder, b"fgh");
    }

    #[test]
    fn owned_payload_window_takes_bounds_from_same_payload() {
        let source = PacketPayload::single(test_packet_with_contents(b"abcdef"));

        let bounds = OwnedPayloadBounds::checked(&source, 3, 3).expect("same-payload bounds");
        let taken = bounds
            .take_from(source)
            .expect("same-payload owned bounds")
            .into_payload()
            .expect("same-payload bounds are valid");

        assert_payload_bytes(&taken, b"def");
    }

    #[test]
    fn payload_span_mut_mutates_only_checked_range() {
        let mut payload = PacketPayload::chain(PacketChain::from_segments(alloc::vec![
            test_packet_with_contents(b"abcd"),
            test_packet_with_contents(b"efgh"),
        ]));
        let bounds = MutablePayloadBounds::checked(&payload, 2, 4).expect("cross-segment bounds");
        let mut span = bounds.open(&mut payload).expect("mutable span");

        span.for_each_chunk_mut(|chunk| {
            for byte in chunk {
                *byte = byte.to_ascii_uppercase();
            }
        });

        assert_payload_bytes(&payload, b"abCDEFgh");
    }

    #[test]
    fn owned_payload_window_rejects_bounds_against_target_payload() {
        let shorter_payload = PacketPayload::single(test_packet_with_contents(b"xy"));

        assert!(
            PayloadRange::checked(&shorter_payload, 3, 3).is_none(),
            "bounds are validated against the consumed payload"
        );
    }
}
