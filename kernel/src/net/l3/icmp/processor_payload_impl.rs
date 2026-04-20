// ============================================================================
// kernel/src/net/l3/icmp/processor_payload_impl.rs - L3 / ICMP / ペイロード処理
// ============================================================================

use super::*;
use crate::net::payload::PacketPayloadView;

fn payload_checksum(view: &PacketPayloadView<'_>, initial: u32) -> u16 {
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

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum as u16
}

impl IcmpProcessor {
    pub fn process_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        current_time: u64,
    ) -> IcmpResult {
        if !self.check_ingress_rate_limit(current_time) {
            return IcmpResult::Ignored;
        }

        let view = PacketPayloadView::new(payload);
        if view.total_len() < IcmpHeader::SIZE {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        }

        if payload_checksum(&view, 0) != 0 {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        }

        let Some(header) = view.read_array::<4>(0) else {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        };
        let icmp_type = IcmpType::from(header[0]);
        let code = header[1];

        match icmp_type {
            IcmpType::EchoRequest => self.process_payload_echo_request(&view, src_ip, dst_ip),
            IcmpType::EchoReply => self.process_payload_echo_reply(&view),
            IcmpType::DestinationUnreachable
            | IcmpType::SourceQuench
            | IcmpType::TimeExceeded
            | IcmpType::ParameterProblem => self.process_payload_error(icmp_type, code),
            IcmpType::Redirect => self.process_payload_redirect(&view, code),
            IcmpType::TimestampRequest => self.process_payload_timestamp_request(&view, src_ip),
            IcmpType::TimestampReply => IcmpResult::Ignored,
            _ => IcmpResult::Ignored,
        }
    }

    fn process_payload_echo_request(
        &mut self,
        view: &PacketPayloadView<'_>,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
    ) -> IcmpResult {
        self.stats.echo_requests_rx += 1;
        if dst_ip.is_broadcast() || dst_ip.is_multicast() {
            return IcmpResult::Ignored;
        }

        let Some(echo) = view.read_array::<8>(0) else {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        };

        IcmpResult::SendEchoReply {
            src_ip,
            identifier: u16::from_be_bytes([echo[4], echo[5]]),
            sequence: u16::from_be_bytes([echo[6], echo[7]]),
            data_offset: IcmpEchoHeader::SIZE,
            data_len: view.total_len().saturating_sub(IcmpEchoHeader::SIZE),
        }
    }

    fn process_payload_echo_reply(&mut self, view: &PacketPayloadView<'_>) -> IcmpResult {
        self.stats.echo_replies_rx += 1;

        let Some(echo) = view.read_array::<8>(0) else {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        };

        IcmpResult::EchoReplyReceived {
            identifier: u16::from_be_bytes([echo[4], echo[5]]),
            sequence: u16::from_be_bytes([echo[6], echo[7]]),
        }
    }

    fn process_payload_error(&mut self, icmp_type: IcmpType, code: u8) -> IcmpResult {
        self.stats.errors_rx += 1;
        IcmpResult::Error { icmp_type, code }
    }

    fn process_payload_redirect(&mut self, view: &PacketPayloadView<'_>, code: u8) -> IcmpResult {
        self.stats.errors_rx += 1;

        let Some(bytes) = view.read_array::<28>(0) else {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        };

        IcmpResult::Redirect {
            code: RedirectCode::from(code),
            gateway: Ipv4Address::from_octets(bytes[4], bytes[5], bytes[6], bytes[7]),
            destination: Ipv4Address::from_octets(bytes[24], bytes[25], bytes[26], bytes[27]),
        }
    }

    fn process_payload_timestamp_request(
        &mut self,
        view: &PacketPayloadView<'_>,
        src_ip: Ipv4Address,
    ) -> IcmpResult {
        let Some(bytes) = view.read_array::<20>(0) else {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        };

        let now_ms = crate::task::current_tick() as u32;
        let ts_val = now_ms | 0x80000000;
        self.stats.echo_requests_rx += 1;

        IcmpResult::SendTimestampReply {
            src_ip,
            identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence: u16::from_be_bytes([bytes[6], bytes[7]]),
            originate_ts: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            receive_ts: ts_val,
            transmit_ts: ts_val,
        }
    }
}
