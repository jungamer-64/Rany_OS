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
    /// Create a new ICMP processor
    pub fn new(_local_ip: Ipv4Address) -> Self {
        IcmpProcessor {
            _local_ip,
            stats: IcmpStats::default(),
            per_ip_rate_limits: alloc::collections::BTreeMap::new(),
            global_last_time: 0,
            global_tokens: 100,  // Egress (sending) tokens
            ingress_tokens: 200, // Ingress (receiving) tokens
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }

    /// Update token buckets
    fn update_tokens(&mut self, current_time: u64) {
        let elapsed_global = current_time.saturating_sub(self.global_last_time);
        if elapsed_global >= 10 {
            let new_global_tokens = (elapsed_global / 10) as u32;
            // Egress: 100 pkts/sec, max 100
            self.global_tokens = (self.global_tokens + new_global_tokens).min(100);
            // Ingress: 200 pkts/sec, max 400
            self.ingress_tokens = (self.ingress_tokens + (new_global_tokens * 2)).min(400);
            self.global_last_time = current_time;
        }
    }

    /// Check rate limit for a given IP (Token Bucket) - Egress (Sending)
    /// Returns true if allowed, false if dropped.
    pub fn check_rate_limit(&mut self, ip: Ipv4Address, current_time: u64) -> bool {
        self.update_tokens(current_time);

        if self.global_tokens == 0 {
            return false;
        }

        // Per-IP rate limit: Add 1 token per 100ms, max 20 tokens per IP.
        const MAX_RATE_LIMIT_ENTRIES: usize = 1024;
        // ... (rest of logic)

        // If entry doesn't exist and map is full, we need to evict.
        // We check this before taking the entry to avoid borrow checker issues.
        if !self.per_ip_rate_limits.contains_key(&ip)
            && self.per_ip_rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES
        {
            if let Some(&first_key) = self.per_ip_rate_limits.keys().next() {
                self.per_ip_rate_limits.remove(&first_key);
            }
        }

        let (last_time, tokens) = self
            .per_ip_rate_limits
            .entry(ip)
            .or_insert((current_time, 10));
        let elapsed = current_time.saturating_sub(*last_time);
        if elapsed >= 100 {
            let new_tokens = (elapsed / 100) as u32;
            *tokens = (*tokens + new_tokens).min(20);
            *last_time = current_time;
        }

        if *tokens == 0 {
            return false;
        }

        *tokens -= 1;
        self.global_tokens -= 1;
        true
    }

    /// Check rate limit for an incoming packet
    pub fn check_ingress_rate_limit(&mut self, current_time: u64) -> bool {
        self.update_tokens(current_time);

        if self.ingress_tokens == 0 {
            return false;
        }

        self.ingress_tokens -= 1;
        true
    }

    /// Process an incoming ICMP packet
    pub fn process(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        current_time: u64,
    ) -> IcmpResult {
        // Security: Check ingress rate limit BEFORE expensive operations
        if !self.check_ingress_rate_limit(current_time) {
            return IcmpResult::Ignored;
        }

        let packet = match IcmpPacket::parse(data) {
            Some(p) => p,
            None => {
                self.stats.invalid += 1;
                return IcmpResult::Invalid;
            }
        };

        // Verify checksum
        if !packet.verify_checksum() {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        }

        match packet.icmp_type() {
            IcmpType::EchoRequest => {
                self.stats.echo_requests_rx += 1;

                // Security: RFC 1122 Section 3.2.2.6 - Do not respond to broadcast/multicast ICMP Echo Requests.
                if dst_ip.is_broadcast() || dst_ip.is_multicast() {
                    return IcmpResult::Ignored;
                }

                if let Some(echo) = packet.as_echo() {
                    IcmpResult::SendEchoReply {
                        src_ip,
                        identifier: echo.identifier(),
                        sequence: echo.sequence(),
                        data_offset: IcmpEchoHeader::SIZE,
                        data_len: echo.data().len(),
                    }
                } else {
                    IcmpResult::Invalid
                }
            }
            IcmpType::EchoReply => {
                self.stats.echo_replies_rx += 1;

                if let Some(echo) = packet.as_echo() {
                    IcmpResult::EchoReplyReceived {
                        identifier: echo.identifier(),
                        sequence: echo.sequence(),
                    }
                } else {
                    IcmpResult::Invalid
                }
            }
            IcmpType::DestinationUnreachable
            | IcmpType::SourceQuench
            | IcmpType::TimeExceeded
            | IcmpType::ParameterProblem => {
                self.stats.errors_rx += 1;
                IcmpResult::Error {
                    icmp_type: packet.icmp_type(),
                    code: packet.code(),
                }
            }
            IcmpType::Redirect => {
                self.stats.errors_rx += 1;
                self.process_redirect(&packet, src_ip)
            }
            IcmpType::TimestampRequest => self.process_timestamp_request(&packet, src_ip),
            IcmpType::TimestampReply => IcmpResult::Ignored,
            _ => IcmpResult::Ignored,
        }
    }

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
            IcmpType::EchoRequest => {
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
            IcmpType::EchoReply => {
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
            IcmpType::DestinationUnreachable
            | IcmpType::SourceQuench
            | IcmpType::TimeExceeded
            | IcmpType::ParameterProblem => {
                self.stats.errors_rx += 1;
                IcmpResult::Error { icmp_type, code }
            }
            IcmpType::Redirect => {
                self.stats.errors_rx += 1;
                let Some(bytes) = view.read_array::<28>(0) else {
                    self.stats.invalid += 1;
                    return IcmpResult::Invalid;
                };
                IcmpResult::Redirect {
                    code: RedirectCode::from(code),
                    gateway: Ipv4Address::from_octets(bytes[4], bytes[5], bytes[6], bytes[7]),
                    destination: Ipv4Address::from_octets(
                        bytes[24], bytes[25], bytes[26], bytes[27],
                    ),
                }
            }
            IcmpType::TimestampRequest => {
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
            IcmpType::TimestampReply => IcmpResult::Ignored,
            _ => IcmpResult::Ignored,
        }
    }

    /// Build an echo reply packet
    pub fn build_echo_reply(
        buffer: &mut [u8],
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
    ) -> Option<usize> {
        let mut builder = IcmpEchoBuilder::new(buffer)?;
        builder
            .build_reply(identifier, sequence)
            .write_data(echo_data);
        Some(builder.finalize())
    }

    /// Build an echo request packet
    pub fn build_echo_request(
        buffer: &mut [u8],
        identifier: u16,
        sequence: u16,
        data: &[u8],
    ) -> Option<usize> {
        let mut builder = IcmpEchoBuilder::new(buffer)?;
        builder.build_request(identifier, sequence).write_data(data);
        Some(builder.finalize())
    }

    /// Build a destination unreachable packet (RFC 792 / RFC 1191)
    pub fn build_dest_unreachable(
        buffer: &mut [u8],
        code: DestUnreachCode,
        next_hop_mtu: Option<u16>,
        original_packet: &[u8],
    ) -> Option<usize> {
        if buffer.len() < IcmpHeader::SIZE + 4 + 28 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder
            .set_type(IcmpType::DestinationUnreachable)
            .set_code(code as u8);

        // Bytes 4-7 of ICMP: 4 bytes unused, but for Code 4 (Fragmentation Needed)
        // the last 2 bytes (bytes 6-7) contain the Next-Hop MTU (RFC 1191).
        let payload = builder.payload_mut();
        payload[0..4].copy_from_slice(&[0, 0, 0, 0]); // Default to zero

        if code == DestUnreachCode::FragmentationNeeded {
            if let Some(mtu) = next_hop_mtu {
                payload[2..4].copy_from_slice(&mtu.to_be_bytes());
            }
        }

        // RFC 1122 / RFC 1812: Include the full IP header + at least 8 octets of the data.
        // MUST NOT exceed 576 bytes total (IP header 20 + ICMP header 8 + payload 4 + copy_len <= 576 -> copy_len <= 544).
        let copy_len = original_packet.len().min(payload.len() - 4).min(544);
        payload[4..4 + copy_len].copy_from_slice(&original_packet[..copy_len]);

        builder.set_payload_len(4 + copy_len);
        Some(builder.finalize())
    }

    /// Build a time exceeded packet
    pub fn build_time_exceeded(
        buffer: &mut [u8],
        code: TimeExceededCode,
        original_packet: &[u8],
    ) -> Option<usize> {
        if buffer.len() < IcmpHeader::SIZE + 4 + 28 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder
            .set_type(IcmpType::TimeExceeded)
            .set_code(code as u8);

        let payload = builder.payload_mut();
        payload[0..4].copy_from_slice(&[0, 0, 0, 0]); // Unused

        // RFC 1122 / RFC 1812: MUST NOT exceed 576 bytes total.
        let copy_len = original_packet.len().min(payload.len() - 4).min(544);
        payload[4..4 + copy_len].copy_from_slice(&original_packet[..copy_len]);

        builder.set_payload_len(4 + copy_len);
        Some(builder.finalize())
    }

    /// Build a parameter problem packet (RFC 792)
    pub fn build_parameter_problem(
        buffer: &mut [u8],
        pointer: u8,
        original_packet: &[u8],
    ) -> Option<usize> {
        if buffer.len() < IcmpHeader::SIZE + 4 + 28 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder.set_type(IcmpType::ParameterProblem).set_code(0);

        let payload = builder.payload_mut();
        payload[0] = pointer; // Pointer to the byte in the original header where the error was detected
        payload[1..4].copy_from_slice(&[0, 0, 0]); // Unused

        // RFC 1122 / RFC 1812: MUST NOT exceed 576 bytes total.
        let copy_len = original_packet.len().min(payload.len() - 4).min(544);
        payload[4..4 + copy_len].copy_from_slice(&original_packet[..copy_len]);

        builder.set_payload_len(4 + copy_len);
        Some(builder.finalize())
    }

    /// Build a timestamp reply packet (RFC 792)
    pub fn build_timestamp_reply(
        buffer: &mut [u8],
        identifier: u16,
        sequence: u16,
        originate_ts: u32,
        receive_ts: u32,
        transmit_ts: u32,
    ) -> Option<usize> {
        let total_len = 20;
        if buffer.len() < total_len {
            return None;
        }

        buffer[0] = u8::from(IcmpType::TimestampReply);
        buffer[1] = 0;
        buffer[2..4].copy_from_slice(&[0, 0]);
        buffer[4..6].copy_from_slice(&identifier.to_be_bytes());
        buffer[6..8].copy_from_slice(&sequence.to_be_bytes());
        buffer[8..12].copy_from_slice(&originate_ts.to_be_bytes());
        buffer[12..16].copy_from_slice(&receive_ts.to_be_bytes());
        buffer[16..20].copy_from_slice(&transmit_ts.to_be_bytes());

        let checksum = data_checksum(&buffer[..total_len], 0);
        buffer[2..4].copy_from_slice(&checksum.to_be_bytes());

        Some(total_len)
    }

    /// Process an ICMP Redirect packet.
    pub(super) fn process_redirect(
        &mut self,
        packet: &IcmpPacket<'_>,
        _src_ip: Ipv4Address,
    ) -> IcmpResult {
        // Security: ICMP Redirects are dangerous.
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
