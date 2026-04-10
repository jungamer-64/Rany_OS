use super::*;
use crate::net::datapath::mempool::PacketRef;

impl Ipv4Processor {
    pub fn process_with_time_and_packet<'a>(
        &mut self,
        data: &'a [u8],
        packet_ref: Option<PacketRef>,
        current_time: u64,
    ) -> Ipv4ProcessResult<'a> {
        let current_time = Self::normalize_time(current_time);

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

        if self.should_drop_forbidden_options(data, packet.header().header_len()) {
            return Ipv4ProcessResult::Dropped;
        }

        if packet.header().more_fragments() || packet.header().fragment_offset() != 0 {
            return self.process_fragment_packet(&packet, data, packet_ref, current_time);
        }

        self.process_non_fragment_packet(&packet, data, src, dst, packet_ref.as_ref())
    }

    #[inline]
    fn normalize_time(current_time: u64) -> u64 {
        // Security: Ensure we have a valid timestamp for fragment timeout handling.
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
