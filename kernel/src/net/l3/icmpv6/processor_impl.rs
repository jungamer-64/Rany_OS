use super::*;

impl Icmpv6Processor {
    /// Create a new ICMPv6 processor
    pub fn new(echo_enabled: bool) -> Self {
        Self {
            echo_enabled,
            stats: Icmpv6Stats::default(),
            last_token_time: AtomicU64::new(0),
            tx_tokens: AtomicU32::new(20),  // Initial burst capacity
            rx_tokens: AtomicU32::new(100), // Ingress limit is more generous
        }
    }

    /// Update token buckets
    fn update_tokens(&self, current_time: u64) {
        let last_time = self.last_token_time.load(Ordering::Relaxed);
        let elapsed = current_time.saturating_sub(last_time);
        let new_tokens = (elapsed / 50) as u32;

        if new_tokens > 0 {
            // Egress: 20 pkts/sec, max 50
            let old_tx = self.tx_tokens.load(Ordering::Relaxed);
            self.tx_tokens
                .store((old_tx + new_tokens).min(50), Ordering::Relaxed);

            // Ingress: 100 pkts/sec, max 200
            let old_rx = self.rx_tokens.load(Ordering::Relaxed);
            self.rx_tokens
                .store((old_rx + (new_tokens * 5)).min(200), Ordering::Relaxed);

            self.last_token_time.store(current_time, Ordering::Relaxed);
        }
    }

    /// Check if an outgoing message is allowed by the rate limiter
    pub fn check_tx_rate_limit(&self, current_time: u64) -> bool {
        self.update_tokens(current_time);

        let current_tokens = self.tx_tokens.load(Ordering::Relaxed);
        if current_tokens == 0 {
            self.stats
                .dropped_rate_limit
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.tx_tokens.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Check if an incoming message is allowed by the rate limiter
    pub fn check_rx_rate_limit(&self, current_time: u64) -> bool {
        self.update_tokens(current_time);

        let current_tokens = self.rx_tokens.load(Ordering::Relaxed);
        if current_tokens == 0 {
            return false;
        }

        self.rx_tokens.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Get stats reference
    #[inline]
    pub fn stats(&self) -> &Icmpv6Stats {
        &self.stats
    }

    pub fn process_payload(
        &self,
        payload: PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: crate::net::l2::ethernet::MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) -> Icmpv6Result {
        if payload.total_len() < ICMPV6_HEADER_SIZE {
            return Icmpv6Result::Error;
        }

        self.stats.rx_messages.fetch_add(1, Ordering::Relaxed);

        if !self.check_rx_rate_limit(current_time) {
            return Icmpv6Result::Dropped;
        }

        if !self.verify_checksum_payload(&payload, &src, &dst) {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return Icmpv6Result::Dropped;
        }

        let view = PacketPayloadView::new(&payload);
        let Some(header) = view.read_array::<2>(0) else {
            return Icmpv6Result::Error;
        };
        let msg_type = Icmpv6Type::from(header[0]);
        let code = header[1];

        match msg_type {
            Icmpv6Type::RouterSolicitation
            | Icmpv6Type::RouterAdvertisement
            | Icmpv6Type::NeighborSolicitation
            | Icmpv6Type::NeighborAdvertisement => {
                self.stats.rx_ndp.fetch_add(1, Ordering::Relaxed);
                Icmpv6Result::NdpMessage {
                    msg_type,
                    data: payload,
                    src,
                    dst,
                    src_mac,
                    hop_limit,
                }
            }
            Icmpv6Type::Redirect => {
                self.stats.rx_ndp.fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "ICMPv6: Ignoring Redirect from {} (Security: disabled by default)",
                    src
                );
                Icmpv6Result::Dropped
            }
            _ => self.dispatch_message_payload(&view, msg_type, code, src, dst, src_mac, hop_limit),
        }
    }

    fn verify_checksum_payload(
        &self,
        payload: &PacketPayload,
        src: &Ipv6Address,
        dst: &Ipv6Address,
    ) -> bool {
        let view = PacketPayloadView::new(payload);
        let pseudo =
            ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, view.total_len() as u32);
        payload_checksum(&view, pseudo) == 0
    }

    fn dispatch_message_payload(
        &self,
        view: &PacketPayloadView<'_>,
        msg_type: Icmpv6Type,
        code: u8,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: crate::net::l2::ethernet::MacAddress,
        hop_limit: u8,
    ) -> Icmpv6Result {
        let _ = hop_limit;
        match msg_type {
            Icmpv6Type::EchoRequest => {
                self.stats.rx_echo_requests.fetch_add(1, Ordering::Relaxed);
                self.handle_echo_request_payload(view, src, dst)
            }
            Icmpv6Type::EchoReply => {
                self.stats.rx_echo_replies.fetch_add(1, Ordering::Relaxed);
                self.handle_echo_reply_payload(view, src)
            }
            Icmpv6Type::DestinationUnreachable => {
                self.handle_quoted_error_payload(view, |code, _arg, src, dst, packet| {
                    Icmpv6Result::DestinationUnreachable {
                        code,
                        quoted_src: src,
                        quoted_dst: dst,
                        quoted_packet: packet,
                    }
                })
            }
            Icmpv6Type::PacketTooBig => self.handle_packet_too_big_payload(view),
            Icmpv6Type::TimeExceeded => {
                self.handle_quoted_error_payload(view, |code, arg, src, dst, packet| {
                    let _ = arg;
                    Icmpv6Result::TimeExceeded {
                        code,
                        quoted_src: src,
                        quoted_dst: dst,
                        quoted_packet: packet,
                    }
                })
            }
            Icmpv6Type::ParameterProblem => {
                self.handle_quoted_error_payload(view, |code, arg, src, dst, packet| {
                    Icmpv6Result::ParameterProblem {
                        code,
                        pointer: arg,
                        quoted_src: src,
                        quoted_dst: dst,
                        quoted_packet: packet,
                    }
                })
            }
            Icmpv6Type::Redirect => {
                self.stats.rx_ndp.fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "ICMPv6: Ignoring Redirect from {} (Security: disabled by default)",
                    src
                );
                Icmpv6Result::Dropped
            }
            Icmpv6Type::RouterSolicitation
            | Icmpv6Type::RouterAdvertisement
            | Icmpv6Type::NeighborSolicitation
            | Icmpv6Type::NeighborAdvertisement => {
                self.stats.rx_ndp.fetch_add(1, Ordering::Relaxed);
                Icmpv6Result::NdpMessage {
                    msg_type,
                    data: view.payload().clone(),
                    src,
                    dst,
                    src_mac,
                    hop_limit,
                }
            }
            _ => {
                log::debug!("ICMPv6: Unknown type {} code {}", u8::from(msg_type), code);
                Icmpv6Result::Dropped
            }
        }
    }

    /// Handle Echo Request → produce Echo Reply
    fn handle_echo_request_payload(
        &self,
        view: &PacketPayloadView<'_>,
        src: Ipv6Address,
        dst: Ipv6Address,
    ) -> Icmpv6Result {
        if !self.echo_enabled {
            return Icmpv6Result::Dropped;
        }

        // Security: RFC 4443 Section 2.4(e) - MUST NOT respond to multicast
        if dst.is_multicast() {
            return Icmpv6Result::Dropped;
        }

        if view.total_len() < ICMPV6_ECHO_HEADER_SIZE {
            return Icmpv6Result::Error;
        }

        let Some(identifier_bytes) = view.read_array::<2>(4) else {
            return Icmpv6Result::Error;
        };
        let Some(sequence_bytes) = view.read_array::<2>(6) else {
            return Icmpv6Result::Error;
        };
        let identifier = u16::from_be_bytes(identifier_bytes);
        let sequence = u16::from_be_bytes(sequence_bytes);

        // Security: Limit Echo payload size to prevent memory exhaustion.
        // 1232 bytes is the max payload that fits in a minimum IPv6 MTU (1280).
        let max_payload = 1232;
        let echo_data_len = (view.total_len() - ICMPV6_ECHO_HEADER_SIZE).min(max_payload);
        let Some(echo_data) = payload_range(view.payload(), ICMPV6_ECHO_HEADER_SIZE, echo_data_len)
        else {
            return Icmpv6Result::Error;
        };

        Icmpv6Result::SendEchoReply {
            dst: src, // reply goes back to sender
            identifier,
            sequence,
            data: echo_data,
        }
    }

    /// Handle Echo Reply (response to our ping)
    fn handle_echo_reply_payload(
        &self,
        view: &PacketPayloadView<'_>,
        src: Ipv6Address,
    ) -> Icmpv6Result {
        if view.total_len() < ICMPV6_ECHO_HEADER_SIZE {
            return Icmpv6Result::Error;
        }

        let Some(identifier_bytes) = view.read_array::<2>(4) else {
            return Icmpv6Result::Error;
        };
        let Some(sequence_bytes) = view.read_array::<2>(6) else {
            return Icmpv6Result::Error;
        };
        let identifier = u16::from_be_bytes(identifier_bytes);
        let sequence = u16::from_be_bytes(sequence_bytes);

        Icmpv6Result::EchoReplyReceived {
            src,
            identifier,
            sequence,
        }
    }

    /// Helper to extract info from quoted packets in ICMPv6 error messages (RFC 4443)
    fn handle_quoted_error_payload<F>(&self, view: &PacketPayloadView<'_>, f: F) -> Icmpv6Result
    where
        F: FnOnce(u8, u32, Ipv6Address, Ipv6Address, PacketPayload) -> Icmpv6Result,
    {
        if view.total_len() < 8 {
            return Icmpv6Result::Error;
        }

        let Some(code) = view.read_array::<1>(1).map(|bytes| bytes[0]) else {
            return Icmpv6Result::Error;
        };
        let Some(arg_bytes) = view.read_array::<4>(4) else {
            return Icmpv6Result::Error;
        };
        let arg = u32::from_be_bytes(arg_bytes);

        // Invoking packet starts at offset 8.
        // IPv6 fixed header: source at +8, dest at +24.
        // So total offsets: source at 16, dest at 32.
        if view.total_len() >= 48 {
            let Some(src_arr) = view.read_array::<16>(16) else {
                return Icmpv6Result::Error;
            };
            let Some(dst_arr) = view.read_array::<16>(32) else {
                return Icmpv6Result::Error;
            };
            let quoted_src = Ipv6Address::new(src_arr);
            let quoted_dst = Ipv6Address::new(dst_arr);

            // Quoted portion starts after the ICMPv6 header (offset 8)
            let quoted_len = view.total_len() - 8;
            let Some(quoted_packet) = payload_range(view.payload(), 8, quoted_len) else {
                return Icmpv6Result::Error;
            };

            f(code, arg, quoted_src, quoted_dst, quoted_packet)
        } else {
            Icmpv6Result::Dropped
        }
    }

    /// Handle Packet Too Big (Path MTU Discovery)
    fn handle_packet_too_big_payload(&self, view: &PacketPayloadView<'_>) -> Icmpv6Result {
        self.handle_quoted_error_payload(view, |_, mtu, src, dst, packet| {
            Icmpv6Result::PacketTooBig {
                quoted_src: src,
                dst,
                mtu,
                quoted_packet: packet,
            }
        })
    }
}

impl Default for Icmpv6Processor {
    fn default() -> Self {
        Self::new(true)
    }
}
