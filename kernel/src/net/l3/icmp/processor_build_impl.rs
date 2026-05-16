// ============================================================================
// kernel/src/net/l3/icmp/processor_build_impl.rs - L3 / ICMP / 構築処理
// ============================================================================

use super::*;
use crate::net::payload::{PacketPayloadView, append_payload, move_payload_window_owned};
use kernel_api::resource::net::PacketPayload;

fn packet_payload_checksum(view: &PacketPayloadView<'_>, initial: u32) -> u16 {
    let mut sum = initial;
    let mut trailing = None;

    view.for_each_chunk(|chunk| {
        let mut index = 0usize;
        if let Some(prev) = trailing.take() {
            if let Some((&first, rest)) = chunk.split_first() {
                sum = sum.saturating_add(u16::from_be_bytes([prev, first]) as u32);
                index = 1;
                if rest.is_empty() {
                    return;
                }
            } else {
                trailing = Some(prev);
                return;
            }
        }

        while index + 1 < chunk.len() {
            sum = sum.saturating_add(u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32);
            index += 2;
        }
        if index < chunk.len() {
            trailing = Some(chunk[index]);
        }
    });

    if let Some(last) = trailing {
        sum = sum.saturating_add(u16::from_be_bytes([last, 0]) as u32);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl IcmpProcessor {
    fn build_error_payload(
        icmp_type: IcmpType,
        code: u8,
        rest_of_header: [u8; 4],
        original_packet: PacketPayload,
    ) -> Option<PacketPayload> {
        let quote_len = original_packet.total_len().min(544);
        let mut packet = crate::net::payload::alloc_packet_with_headroom(
            IcmpHeader::SIZE + 4,
            kernel_api::resource::net::DEFAULT_PACKET_HEADROOM,
        )?;
        let data = packet.data_mut();
        data[0] = u8::from(icmp_type);
        data[1] = code;
        data[2] = 0;
        data[3] = 0;
        data[4..8].copy_from_slice(&rest_of_header);
        if !packet.set_len(IcmpHeader::SIZE + 4) {
            return None;
        }

        let mut message = PacketPayload::single(packet);
        if quote_len != 0 {
            append_payload(
                &mut message,
                move_payload_window_owned(original_packet, 0, quote_len)?,
            );
        }

        let checksum = packet_payload_checksum(&PacketPayloadView::new(&message), 0);
        if let Some(first) = message.segments_mut().first_mut() {
            first.data_mut()[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        Some(message)
    }

    /// Build a destination unreachable payload (RFC 792 / RFC 1191).
    pub fn build_dest_unreachable_payload(
        code: DestUnreachCode,
        next_hop_mtu: Option<u16>,
        original_packet: PacketPayload,
    ) -> Option<PacketPayload> {
        let mut rest = [0u8; 4];
        if code == DestUnreachCode::FragmentationNeeded {
            if let Some(mtu) = next_hop_mtu {
                rest[2..4].copy_from_slice(&mtu.to_be_bytes());
            }
        }
        Self::build_error_payload(
            IcmpType::DestinationUnreachable,
            code as u8,
            rest,
            original_packet,
        )
    }

    /// Build a time exceeded payload.
    pub fn build_time_exceeded_payload(
        code: TimeExceededCode,
        original_packet: PacketPayload,
    ) -> Option<PacketPayload> {
        Self::build_error_payload(IcmpType::TimeExceeded, code as u8, [0; 4], original_packet)
    }

    /// Build a parameter problem payload (RFC 792).
    pub fn build_parameter_problem_payload(
        pointer: u8,
        original_packet: PacketPayload,
    ) -> Option<PacketPayload> {
        Self::build_error_payload(
            IcmpType::ParameterProblem,
            0,
            [pointer, 0, 0, 0],
            original_packet,
        )
    }

    /// Build a timestamp reply packet (RFC 792)
    pub fn build_timestamp_reply(
        buffer: &mut [u8],
        identifier: u16,
        sequence: u16,
        originate_ts: u32,
        receive_ts: u32,
        transmit_ts: u32,
    ) -> Option<usize> {
        let total_len = 20;
        if buffer.len() < total_len {
            return None;
        }

        buffer[0] = u8::from(IcmpType::TimestampReply);
        buffer[1] = 0;
        buffer[2..4].copy_from_slice(&[0, 0]);
        buffer[4..6].copy_from_slice(&identifier.to_be_bytes());
        buffer[6..8].copy_from_slice(&sequence.to_be_bytes());
        buffer[8..12].copy_from_slice(&originate_ts.to_be_bytes());
        buffer[12..16].copy_from_slice(&receive_ts.to_be_bytes());
        buffer[16..20].copy_from_slice(&transmit_ts.to_be_bytes());

        let checksum = data_checksum(&buffer[..total_len], 0);
        buffer[2..4].copy_from_slice(&checksum.to_be_bytes());

        Some(total_len)
    }
}
