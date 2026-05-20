// ============================================================================
// kernel/src/net/l3/ipv4/processor_packet_path_impl.rs - L3 / IPv4 / パケット経路処理
// ============================================================================

use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView, PayloadWindow};
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

impl Ipv4Processor {
    pub(crate) fn process_fragment_owned_packet(
        &mut self,
        packet_ref: PacketRef,
        current_time: u64,
    ) -> Ipv4ProcessResult {
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

        let Some(mut header_writer) =
            GeneratedPacketWriter::new(header_len, DEFAULT_PACKET_HEADROOM)
        else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };
        if header_writer
            .write_bytes(&header_copy[..header_len])
            .is_none()
        {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        }
        let Some(header_packet) = header_writer.finish() else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };
        let Some(window) = PayloadWindow::within_payload(
            &original,
            header_len,
            total_len.saturating_sub(header_len),
        ) else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };
        let Ok(payload_packet) =
            crate::net::payload::OwnedPayloadWindow::take_payload(original, window)
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
