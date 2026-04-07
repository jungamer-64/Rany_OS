use super::*;
use crate::net::datapath::mempool::PacketRef;

impl Ipv4Processor {
    pub(super) fn process_fragment_packet<'a>(
        &mut self,
        packet: &Ipv4Packet<'a>,
        data: &'a [u8],
        packet_ref: Option<PacketRef>,
        current_time: u64,
    ) -> Ipv4ProcessResult<'a> {
        let header = packet.header();

        // Security: RFC 1858 Tiny Fragment Filtering
        // If FO=0 and protocol is TCP or UDP, the fragment MUST be large enough
        // to contain the entire transport header (20 bytes for TCP, 8 for UDP).
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

            if fragment_offset == 1 {
                log::warn!("[NET-IPV4] Dropping suspicious fragment (FO=1) - RFC 1858 violation");
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Dropped;
            }
        }

        let header_len = header.header_len();
        let header_data = &data[..header_len];
        let payload = packet.payload();
        let payload_packet = packet_ref.as_ref().map(|ip_packet| {
            let mut payload_packet = ip_packet.clone();
            payload_packet.advance(header_len);
            payload_packet.set_len(payload.len());
            payload_packet
        });

        let (reassembled, expired) = self.reassembler.process_fragment(
            header,
            header_data,
            payload,
            payload_packet,
            current_time,
        );

        if let Some(data) = reassembled {
            // Reassembly complete - return the reassembled packet
            Ipv4ProcessResult::Reassembled(data)
        } else if let Some((src, header_data)) = expired.into_iter().next() {
            // Return the first expired buffer for ICMP processing
            Ipv4ProcessResult::ReassemblyTimeout(src, header_data)
        } else {
            // Still waiting for more fragments
            Ipv4ProcessResult::FragmentPending
        }
    }

    pub(super) fn process_non_fragment_packet<'a>(
        &self,
        packet: &Ipv4Packet<'a>,
        data: &'a [u8],
        src: Ipv4Address,
        dst: Ipv4Address,
    ) -> Ipv4ProcessResult<'a> {
        // Non-fragmented packet - process normally
        let payload = packet.payload();

        match packet.protocol() {
            IpProtocol::Icmp => Ipv4ProcessResult::Icmp(payload, src, dst, packet.ttl(), data),
            IpProtocol::Igmp => Ipv4ProcessResult::Igmp(payload, src, packet.ttl(), data),
            IpProtocol::Tcp => Ipv4ProcessResult::Tcp(payload, src, dst, data),
            IpProtocol::Udp => Ipv4ProcessResult::Udp(payload, src, dst, data),
            p => Ipv4ProcessResult::UnknownProtocol(p.into(), src, dst, data),
        }
    }
}
