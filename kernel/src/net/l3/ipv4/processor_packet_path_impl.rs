// ============================================================================
// kernel/src/net/l3/ipv4/processor_packet_path_impl.rs - L3 / IPv4 / パケット経路処理
// ============================================================================

use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::payload::{PacketPayloadBuilder, PacketPayloadView, move_payload_window_owned};
use kernel_api::resource::net::PacketPayload;

impl Ipv4Processor {
    pub(crate) fn process_fragment_owned_packet(
        &mut self,
        packet_ref: PacketRef,
        current_time: u64,
    ) -> Ipv4ProcessResult<'static> {
        let original = PacketPayload::single(packet_ref);
        let (total_len, header_len, header_copy, header, protocol) = {
            let view = PacketPayloadView::new(&original);
            let total_len = view.total_len();
            if total_len < 20 {
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Error;
            }

            let Some(fixed) = view.read_array::<20>(0) else {
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Error;
            };

            let ihl_words = (fixed[0] & 0x0f) as usize;
            let header_len = ihl_words.saturating_mul(4);
            if header_len < 20 || total_len < header_len {
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Error;
            }
            let Some(header_prefix) = view.read_fixed_bytes::<60>(0, header_len) else {
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Error;
            };
            let header_bytes = header_prefix.as_slice();

            let packet = match Ipv4Packet::parse(header_bytes) {
                Some(packet) => packet,
                None => {
                    self.stats.rx_errors += 1;
                    return Ipv4ProcessResult::Error;
                }
            };

            if !packet.verify_checksum() {
                self.stats.checksum_errors += 1;
                return Ipv4ProcessResult::Error;
            }

            let dst = packet.destination();
            if !self.is_for_us(&dst) {
                self.stats.rx_dropped += 1;
                return Ipv4ProcessResult::Dropped;
            }

            self.stats.rx_packets += 1;

            let src = packet.source();
            if self.should_drop_src_dst_pair(src, dst) || self.should_drop_martian_source(src) {
                return Ipv4ProcessResult::Dropped;
            }

            if self.should_drop_forbidden_options(header_bytes, header_len) {
                return Ipv4ProcessResult::Dropped;
            }

            let mut header_copy = [0u8; 60];
            header_copy[..header_len].copy_from_slice(header_bytes);

            (
                total_len,
                header_len,
                header_copy,
                *packet.header(),
                packet.protocol(),
            )
        };
        if protocol == IpProtocol::Tcp || protocol == IpProtocol::Udp {
            let fragment_offset = header.fragment_offset();
            let payload_len = total_len.saturating_sub(header_len);
            let min_len = if protocol == IpProtocol::Tcp { 20 } else { 8 };

            if fragment_offset == 0 && payload_len < min_len {
                log::warn!(
                    "[NET-IPV4] Dropping tiny fragment (FO=0, protocol={:?}, len={}) - RFC 1858 violation",
                    protocol,
                    payload_len
                );
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Dropped;
            }

            if fragment_offset == 1 && protocol == IpProtocol::Tcp {
                log::warn!("[NET-IPV4] Dropping suspicious fragment (FO=1) - RFC 1858 violation");
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Dropped;
            }
        }

        let mut header_builder = PacketPayloadBuilder::new();
        if header_builder
            .append_generated_bytes(&header_copy[..header_len])
            .is_none()
        {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        }
        let header_packet = header_builder.build();
        let Some(payload_packet) =
            move_payload_window_owned(original, header_len, total_len.saturating_sub(header_len))
        else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };

        let (reassembled, expired) =
            self.reassembler
                .process_fragment(&header, header_packet, payload_packet, current_time);

        if let Some(data) = reassembled {
            Ipv4ProcessResult::Reassembled(data)
        } else if let Some((src, header_data)) = expired.into_iter().next() {
            Ipv4ProcessResult::ReassemblyTimeout(src, header_data)
        } else {
            Ipv4ProcessResult::FragmentPending
        }
    }

    pub(super) fn process_fragment_packet<'a>(
        &mut self,
        packet: &Ipv4Packet<'a>,
        data: &'a [u8],
        _packet_ref: Option<&PacketRef>,
        current_time: u64,
    ) -> Ipv4ProcessResult<'a> {
        let header = packet.header();
        let protocol = packet.protocol();
        if protocol == IpProtocol::Tcp || protocol == IpProtocol::Udp {
            let fragment_offset = header.fragment_offset();
            let payload_len = packet.payload().len();
            let min_len = if protocol == IpProtocol::Tcp { 20 } else { 8 };

            if fragment_offset == 0 && payload_len < min_len {
                log::warn!(
                    "[NET-IPV4] Dropping tiny fragment (FO=0, protocol={:?}, len={}) - RFC 1858 violation",
                    protocol,
                    payload_len
                );
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Dropped;
            }

            if fragment_offset == 1 && protocol == IpProtocol::Tcp {
                log::warn!("[NET-IPV4] Dropping suspicious fragment (FO=1) - RFC 1858 violation");
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Dropped;
            }
        }

        let _ = (packet, data, current_time);
        self.stats.rx_errors += 1;
        Ipv4ProcessResult::Error
    }

    pub(super) fn process_non_fragment_packet<'a>(
        &self,
        packet: &Ipv4Packet<'a>,
        data: &'a [u8],
        src: Ipv4Address,
        dst: Ipv4Address,
        _packet_ref: Option<&PacketRef>,
    ) -> Ipv4ProcessResult<'a> {
        // Non-fragmented packet - process normally
        let payload = packet.payload();

        match packet.protocol() {
            IpProtocol::Icmp => Ipv4ProcessResult::Icmp(payload, src, dst, packet.ttl(), data),
            IpProtocol::Igmp => Ipv4ProcessResult::Igmp(payload, src, packet.ttl(), data),
            IpProtocol::Tcp => Ipv4ProcessResult::Tcp(payload, src, dst, data),
            IpProtocol::Udp => Ipv4ProcessResult::Udp(payload, src, dst, data),
            p => Ipv4ProcessResult::UnknownProtocol(p.into(), src, dst),
        }
    }
}
