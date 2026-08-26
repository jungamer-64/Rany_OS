// ============================================================================
// kernel/src/net/l3/ipv4/processor_packet_path_impl.rs - L3 / IPv4 / パケット経路処理
// ============================================================================

use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::payload::GeneratedPacketWriter;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

impl Ipv4Processor {
    pub(crate) fn process_fragment_owned_packet(
        &mut self,
        packet_ref: PacketRef,
        current_time: u64,
    ) -> Ipv4ProcessResult {
        let (total_len, header_len, header_copy, header, protocol) = {
            let data = packet_ref.data();
            let packet = match Ipv4Packet::parse(data) {
                Some(packet) => packet,
                None => {
                    self.stats.rx_errors += 1;
                    return Ipv4ProcessResult::Error;
                }
            };
            let total_len = packet.header().total_length() as usize;
            let header_len = packet.header().header_len();
            let header_bytes = &data[..header_len];

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
        let Ok(original) = PacketPayload::try_single(packet_ref) else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
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

        let Some(mut header_writer) =
            GeneratedPacketWriter::new(header_len, DEFAULT_PACKET_HEADROOM)
        else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };
        if header_writer
            .write_generated_bytes(&header_copy[..header_len])
            .is_none()
        {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        }
        let Some(header_packet) = header_writer.finish() else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };
        let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
            &original,
            header_len,
            total_len.saturating_sub(header_len),
        ) else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };
        let Some(payload_packet) = bounds
            .take_from(original)
            .and_then(|window| window.into_payload().ok())
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
}
