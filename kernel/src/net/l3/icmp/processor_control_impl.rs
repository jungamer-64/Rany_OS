// ============================================================================
// kernel/src/net/l3/icmp/processor_control_impl.rs - L3 / ICMP / 制御処理
// ============================================================================

use super::*;

impl IcmpProcessor {
    /// Process an ICMP Redirect packet.
    pub(super) fn process_redirect(
        &mut self,
        packet: &IcmpPacket<'_>,
        _src_ip: Ipv4Address,
    ) -> IcmpResult {
        // SECURITY: ICMP Redirect は危険なため制限する。
        // Even if we don't apply them here, we extract information for the stack to decide.
        let payload = packet.payload();
        if payload.len() >= 4 {
            let gateway = Ipv4Address::from_octets(payload[0], payload[1], payload[2], payload[3]);
            // The destination address is in the quoted packet in the payload after byte 4
            if payload.len() >= 4 + 20 {
                let dest_ip = Ipv4Address::from_octets(
                    payload[4 + 16],
                    payload[4 + 17],
                    payload[4 + 18],
                    payload[4 + 19],
                );
                return IcmpResult::Redirect {
                    code: RedirectCode::from(packet.code()),
                    gateway,
                    destination: dest_ip,
                };
            }
        }

        // Malformed or too short Redirect payload
        self.stats.invalid += 1;
        IcmpResult::Invalid
    }

    /// Process an ICMP Timestamp Request packet.
    pub(super) fn process_timestamp_request(
        &mut self,
        packet: &IcmpPacket<'_>,
        src_ip: Ipv4Address,
    ) -> IcmpResult {
        let payload = packet.payload();
        if payload.len() >= 12 {
            let identifier = u16::from_be_bytes([payload[0], payload[1]]);
            let sequence = u16::from_be_bytes([payload[2], payload[3]]);
            let originate_ts = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

            // RFC 792: Time is milliseconds since midnight UT.
            let now_ms = crate::task::current_tick() as u32;
            let ts_val = now_ms | 0x80000000; // High bit set to indicate non-UT

            IcmpResult::SendTimestampReply {
                src_ip,
                identifier,
                sequence,
                originate_ts,
                receive_ts: ts_val,
                transmit_ts: ts_val,
            }
        } else {
            IcmpResult::Invalid
        }
    }
}
