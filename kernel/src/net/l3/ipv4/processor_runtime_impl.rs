// ============================================================================
// kernel/src/net/l3/ipv4/processor_runtime_impl.rs - L3 / IPv4 / ランタイム処理
// ============================================================================

use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::payload::{OwnedPayloadWindow, VerifiedPayloadWindow};
use kernel_api::resource::net::PacketPayload;

struct Ipv4NonFragmentIngress {
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: IpProtocol,
    ttl: u8,
    payload_offset: usize,
    payload_len: usize,
}

impl Ipv4Processor {
    pub fn process_owned_packet(
        &mut self,
        packet_ref: PacketRef,
        current_time: u64,
    ) -> Ipv4ProcessResult {
        let current_time = Self::normalize_time(current_time);

        let ingress = {
            let data = packet_ref.data();
            let packet = match Ipv4Packet::parse(data) {
                Some(p) => p,
                None => {
                    self.stats.rx_errors += 1;
                    return Ipv4ProcessResult::Error;
                }
            };

            // Verify checksum
            if !packet.verify_checksum() {
                self.stats.checksum_errors += 1;
                return Ipv4ProcessResult::Error;
            }

            // Check destination
            let dst = packet.destination();
            if !self.is_for_us(&dst) {
                self.stats.rx_dropped += 1;
                return Ipv4ProcessResult::Dropped;
            }

            self.stats.rx_packets += 1;

            let src = packet.source();

            if self.should_drop_src_dst_pair(src, dst) {
                return Ipv4ProcessResult::Dropped;
            }

            if self.should_drop_martian_source(src) {
                return Ipv4ProcessResult::Dropped;
            }

            let header_len = packet.header().header_len();
            if self.should_drop_forbidden_options(data, header_len) {
                return Ipv4ProcessResult::Dropped;
            }

            if packet.header().more_fragments() || packet.header().fragment_offset() != 0 {
                return self.process_fragment_owned_packet(packet_ref, current_time);
            }

            Ipv4NonFragmentIngress {
                src,
                dst,
                protocol: packet.protocol(),
                ttl: packet.ttl(),
                payload_offset: header_len,
                payload_len: packet.payload().len(),
            }
        };

        let original = PacketPayload::single(packet_ref);
        let Some(window) = VerifiedPayloadWindow::for_payload(
            &original,
            ingress.payload_offset,
            ingress.payload_len,
        ) else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };
        let Some(packet) = OwnedPayloadWindow::new(original, window) else {
            self.stats.rx_errors += 1;
            return Ipv4ProcessResult::Error;
        };

        match ingress.protocol {
            IpProtocol::Icmp => {
                Ipv4ProcessResult::Icmp(packet, ingress.src, ingress.dst, ingress.ttl)
            }
            IpProtocol::Igmp => Ipv4ProcessResult::Igmp(packet, ingress.src, ingress.ttl),
            IpProtocol::Tcp => Ipv4ProcessResult::Tcp(packet, ingress.src, ingress.dst),
            IpProtocol::Udp => {
                Ipv4ProcessResult::Udp(packet, ingress.src, ingress.dst, ingress.ttl)
            }
            p => Ipv4ProcessResult::UnknownProtocol(
                p.into(),
                ingress.src,
                ingress.dst,
                packet.into_original_payload(),
            ),
        }
    }

    #[inline]
    fn normalize_time(current_time: u64) -> u64 {
        // SECURITY: fragment timeout 処理のため valid timestamp を保証する。
        // If 0 is provided, fall back to the system uptime.
        if current_time == 0 {
            crate::time::get_uptime_ms()
        } else {
            current_time
        }
    }

    /// Check if a packet is for us
    pub(super) fn is_for_us(&self, addr: &Ipv4Address) -> bool {
        // DHCP取得フェーズ（ローカルIP未設定=0.0.0.0）では、
        // サーバが提案IPアドレス宛にOFFER/ACKをユニキャスト送信するため
        // 全てのIPv4パケットを受理する。DHCPリース取得後は通常フィルタに戻る。
        if self.config.address.is_any() {
            return true;
        }
        *addr == self.config.address
            || addr.is_broadcast()
            || *addr == self.config.broadcast_address()
            || addr.is_multicast() // Allow multicast for group processing
    }
}
