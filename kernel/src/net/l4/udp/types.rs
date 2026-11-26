// ============================================================================
// kernel/src/net/l4/udp/types.rs - L4 / UDP / 型定義
// ============================================================================

use super::*;
use crate::net::l4::socket::find_udp_by_port_in;
use crate::net::runtime::NetRuntimeHandle;

/// Validates received UDP datagrams and transfers their payload to a socket.
pub struct UdpProcessor;

/// Result of UDP processing
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UdpResult {
    /// No socket for this port
    NoEndpoint,
    /// Checksum error
    ChecksumError,
    /// Invalid packet
    Invalid,
}

impl UdpProcessor {
    fn payload_span_checksum(span: crate::net::payload::PayloadSpanRef<'_>, initial: u32) -> u16 {
        let mut sum = initial;
        let mut trailing = None;

        span.for_each_chunk(|chunk| {
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

            // LOOP_PROOF: mode=bounded; reason=index advances by two through the finite UDP payload chunk and leaves at most one trailing byte.;
            while index + 1 < chunk.len() {
                sum =
                    sum.saturating_add(u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32);
                index += 2;
            }
            if index < chunk.len() {
                trailing = Some(chunk[index]);
            }
        });

        if let Some(last) = trailing {
            sum = sum.saturating_add(u16::from_be_bytes([last, 0]) as u32);
        }

        // LOOP_PROOF: mode=condition; reason=Carry folding reduces the high half of this 32-bit checksum until the accumulator fits in 16 bits.;
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    pub fn process_window_on(
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        packet: OwnedPayloadWindow,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        let segment = packet.span();
        let Some(header) = segment.read_array::<8>(0) else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=segment.total_len()).contains(&length)
            || length != segment.total_len()
        {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum != 0 {
            let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, length as u16);
            let Some(checksum_span) = segment.subspan(0, length) else {
                return Err((UdpResult::Invalid, packet.into_original_payload()));
            };
            if Self::payload_span_checksum(checksum_span, pseudo) != 0 {
                return Err((UdpResult::ChecksumError, packet.into_original_payload()));
            }
        }

        let src = crate::net::l4::EndpointAddr::new(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let Some(endpoint) = find_udp_by_port_in(runtime, dst_port, if_id) else {
            return Err((UdpResult::NoEndpoint, packet.into_original_payload()));
        };

        let udp_segment = match packet.into_payload() {
            Ok(payload) => payload,
            Err(error) => {
                return Err((UdpResult::Invalid, error.into_owner()));
            }
        };
        let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
            &udp_segment,
            UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            return Err((UdpResult::Invalid, udp_segment));
        };
        let window = bounds
            .take_from(udp_segment)
            .expect("UDP bounds were checked against the same payload");
        let udp_payload = match window.into_payload() {
            Ok(payload) => payload,
            Err(error) => {
                return Err((UdpResult::Invalid, error.into_owner()));
            }
        };

        endpoint
            .deliver_udp_payload(if_id, src, ttl, udp_payload)
            .map_err(|(_, payload)| (UdpResult::Invalid, payload))
    }

    pub fn process_window_v6_on(
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        packet: OwnedPayloadWindow,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        let segment = packet.span();
        let Some(header) = segment.read_array::<8>(0) else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=segment.total_len()).contains(&length)
            || length != segment.total_len()
        {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum == 0 {
            return Err((UdpResult::ChecksumError, packet.into_original_payload()));
        }

        let pseudo = ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Udp, length as u32);
        let Some(checksum_span) = segment.subspan(0, length) else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        if Self::payload_span_checksum(checksum_span, pseudo) != 0 {
            return Err((UdpResult::ChecksumError, packet.into_original_payload()));
        }

        let src = crate::net::l4::EndpointAddr::new_v6(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let Some(endpoint) = find_udp_by_port_in(runtime, dst_port, if_id) else {
            return Err((UdpResult::NoEndpoint, packet.into_original_payload()));
        };

        let udp_segment = match packet.into_payload() {
            Ok(payload) => payload,
            Err(error) => {
                return Err((UdpResult::Invalid, error.into_owner()));
            }
        };
        let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
            &udp_segment,
            UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            return Err((UdpResult::Invalid, udp_segment));
        };
        let window = bounds
            .take_from(udp_segment)
            .expect("UDP bounds were checked against the same payload");
        let udp_payload = match window.into_payload() {
            Ok(payload) => payload,
            Err(error) => {
                return Err((UdpResult::Invalid, error.into_owner()));
            }
        };

        endpoint
            .deliver_udp_payload(if_id, src, ttl, udp_payload)
            .map_err(|(_, payload)| (UdpResult::Invalid, payload))
    }
}
