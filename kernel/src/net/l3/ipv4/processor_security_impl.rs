use super::*;

impl Ipv4Processor {
    pub(super) fn should_drop_src_dst_pair(&mut self, src: Ipv4Address, dst: Ipv4Address) -> bool {
        // Security: Land Attack prevention (src == dst)
        // Discard packets where source and destination addresses are the same.
        if src == dst && !src.is_any() && !src.is_loopback() {
            self.stats.rx_dropped += 1;
            log::warn!(
                "[NET-IPV4] Dropping packet with src == dst (Land Attack) from {}",
                src
            );
            return true;
        }

        false
    }

    pub(super) fn should_drop_martian_source(&mut self, src: Ipv4Address) -> bool {
        // Security: Prevent Source IP spoofing (Martian packets)
        // RFC 1812: Source IP must not be a multicast or broadcast address.
        // RFC 6890: Filter other reserved/special-purpose ranges.
        if src.is_broadcast() || src.is_multicast() || src.is_martian() {
            // Special exception: 0.0.0.0 is allowed as source for DHCP DISCOVER/REQUEST
            if !src.is_any() {
                self.stats.rx_dropped += 1;
                log::warn!("[NET-IPV4] Dropping Martian packet with source {}", src);
                return true;
            }
        }

        false
    }

    pub(super) fn should_drop_forbidden_options(&mut self, data: &[u8], header_len: usize) -> bool {
        // Security: IPv4 Options Filtering
        // RFC 7126: Source routing (LSRR/SSRR) is a major security risk and should be dropped.
        if header_len <= 20 {
            return false;
        }

        let options = &data[20..header_len];
        let mut i = 0usize;

        while i < options.len() {
            let opt_type = options[i];
            if opt_type == 0 {
                break;
            }
            if opt_type == 1 {
                i += 1;
                continue;
            }

            // 131: LSRR (Loose Source and Record Route)
            // 137: SSRR (Strict Source and Record Route)
            if opt_type == 131 || opt_type == 137 {
                log::warn!(
                    "[NET-IPV4] Dropping packet with Source Route option ({})",
                    opt_type
                );
                self.stats.rx_dropped += 1;
                return true;
            }

            if i + 1 >= options.len() {
                break;
            }

            let opt_len = options[i + 1] as usize;
            if opt_len < 2 {
                break;
            }

            i += opt_len;
        }

        false
    }
}
