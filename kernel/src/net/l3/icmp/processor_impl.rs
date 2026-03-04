use super::*;


impl IcmpProcessor {
    /// Create a new ICMP processor
    pub fn new(local_ip: Ipv4Address) -> Self {
        IcmpProcessor {
            _local_ip: local_ip,
            stats: IcmpStats::default(),
            per_ip_rate_limits: alloc::collections::BTreeMap::new(),
            global_last_time: 0,
            global_tokens: 100, // Max 100 tokens globally
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }

    /// Check rate limit for a given IP (Token Bucket)
    /// Returns true if allowed, false if dropped.
    pub(crate) fn check_rate_limit(&mut self, src_ip: Ipv4Address, current_time: u64) -> bool {
        // Global rate limit: Add 1 token per 10ms (100 pkts/sec), max 100 tokens.
        let elapsed_global = current_time.saturating_sub(self.global_last_time);
        let new_global_tokens = (elapsed_global / 10) as u32;
        if new_global_tokens > 0 {
            self.global_tokens = (self.global_tokens + new_global_tokens).min(100);
            self.global_last_time = current_time;
        }

        if self.global_tokens == 0 {
            return false;
        }

        // Add 1 token per 100ms, max 20 tokens per IP.
        // Security: Limit map size to prevent memory DoS.
        const MAX_RATE_LIMIT_ENTRIES: usize = 1024;
        
        if self.per_ip_rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES && !self.per_ip_rate_limits.contains_key(&src_ip) {
            // Evict oldest entry to prevent DoS
            let oldest = self.per_ip_rate_limits.iter()
                .min_by_key(|(_, (last_time, _))| *last_time)
                .map(|(&ip, _)| ip);
            if let Some(oldest_ip) = oldest {
                self.per_ip_rate_limits.remove(&oldest_ip);
            } else {
                return false;
            }
        }

        let (last_time, tokens) = self.per_ip_rate_limits.entry(src_ip).or_insert((current_time, 10));
        let elapsed = current_time.saturating_sub(*last_time);
        let new_tokens = (elapsed / 100) as u32;
        if new_tokens > 0 {
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

    /// Process an incoming ICMP packet
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, current_time: u64) -> IcmpResult {
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
                // This prevents being used in Smurf amplification attacks.
                if dst_ip.is_broadcast() || dst_ip.is_multicast() {
                    return IcmpResult::Ignored;
                }

                if !self.check_rate_limit(src_ip, current_time) {
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
                self.process_redirect(&packet)
            }
            IcmpType::TimestampRequest => {
                if !self.check_rate_limit(src_ip, current_time) {
                    return IcmpResult::Ignored;
                }
                self.process_timestamp_request(&packet, src_ip)
            }
            IcmpType::TimestampReply => {
                // Just acknowledge receipt
                IcmpResult::Ignored
            }
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

    /// Build a destination unreachable packet
    pub fn build_dest_unreachable(
        buffer: &mut [u8],
        code: DestUnreachCode,
        original_packet: &[u8],
    ) -> Option<usize> {
        if buffer.len() < IcmpHeader::SIZE + 4 + 28 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder
            .set_type(IcmpType::DestinationUnreachable)
            .set_code(code as u8);

        // 4 bytes unused, then original IP header + at least 8 bytes of data (RFC 1122)
        let payload = builder.payload_mut();
        payload[0..4].copy_from_slice(&[0, 0, 0, 0]); // Unused

        // RFC 1122: Include the full IP header + at least 8 octets of the data.
        // RFC 1812: SHOULD include as much of the original datagram as possible,
        // up to a total ICMP length of 576 bytes.
        let _header_len = if !original_packet.is_empty() {
            ((original_packet[0] & 0x0F) as usize) * 4
        } else {
            20
        };
        // We include as much of the original packet as will fit in our buffer.
        let copy_len = original_packet.len().min(payload.len() - 4);
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

        // RFC 1122: Include the full IP header + at least 8 octets of the data.
        // RFC 1812: SHOULD include as much of the original datagram as possible.
        let _header_len = if !original_packet.is_empty() {
            ((original_packet[0] & 0x0F) as usize) * 4
        } else {
            20
        };
        let copy_len = original_packet.len().min(payload.len() - 4);
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
        builder
            .set_type(IcmpType::ParameterProblem)
            .set_code(0);

        let payload = builder.payload_mut();
        payload[0] = pointer; // Pointer to the byte in the original header where the error was detected
        payload[1..4].copy_from_slice(&[0, 0, 0]); // Unused

        // RFC 1122: Include the full IP header + at least 8 octets of the data.
        // RFC 1812: SHOULD include as much of the original datagram as possible.
        let _header_len = if !original_packet.is_empty() {
            ((original_packet[0] & 0x0F) as usize) * 4
        } else {
            20
        };
        let copy_len = original_packet.len().min(payload.len() - 4);
        payload[4..4 + copy_len].copy_from_slice(&original_packet[..copy_len]);

        builder.set_payload_len(4 + copy_len);
        Some(builder.finalize())
    }

    /// Build a timestamp reply packet (RFC 792)
    ///
    /// Timestamp reply format (20 bytes total):
    /// Type(1) Code(1) Checksum(2) Identifier(2) Sequence(2)
    /// Originate Timestamp(4) Receive Timestamp(4) Transmit Timestamp(4)
    pub fn build_timestamp_reply(
        buffer: &mut [u8],
        identifier: u16,
        sequence: u16,
        originate_ts: u32,
        receive_ts: u32,
        transmit_ts: u32,
    ) -> Option<usize> {
        // Timestamp reply: 8 bytes header + 12 bytes timestamps
        let total_len = 20;
        if buffer.len() < total_len {
            return None;
        }

        // Type = 14 (Timestamp Reply), Code = 0
        buffer[0] = u8::from(IcmpType::TimestampReply);
        buffer[1] = 0;
        // Checksum placeholder
        buffer[2..4].copy_from_slice(&[0, 0]);
        // Identifier and Sequence
        buffer[4..6].copy_from_slice(&identifier.to_be_bytes());
        buffer[6..8].copy_from_slice(&sequence.to_be_bytes());
        // Originate Timestamp (copied from request)
        buffer[8..12].copy_from_slice(&originate_ts.to_be_bytes());
        // Receive Timestamp
        buffer[12..16].copy_from_slice(&receive_ts.to_be_bytes());
        // Transmit Timestamp
        buffer[16..20].copy_from_slice(&transmit_ts.to_be_bytes());

        // Calculate checksum
        let checksum = data_checksum(&buffer[..total_len], 0);
        buffer[2..4].copy_from_slice(&checksum.to_be_bytes());

        Some(total_len)
    }

    /// Process an ICMP Redirect packet.
    pub(super) fn process_redirect(&self, _packet: &IcmpPacket<'_>) -> IcmpResult {
        // Security: ICMP Redirects are dangerous and can be used for MitM attacks.
        // We ignore them by default unless the system is specifically configured to
        // trust them and they come from the current gateway.
        log::warn!("[NET] ICMP: Ignoring Redirect message (Security: disabled by default)");
        IcmpResult::Ignored
    }

    /// Process an ICMP Timestamp Request packet.
    pub(super) fn process_timestamp_request(&mut self, packet: &IcmpPacket<'_>, src_ip: Ipv4Address) -> IcmpResult {
        let payload = packet.payload();
        if payload.len() >= 12 {
            let identifier = u16::from_be_bytes([payload[0], payload[1]]);
            let sequence = u16::from_be_bytes([payload[2], payload[3]]);
            let originate_ts = u32::from_be_bytes([
                payload[4], payload[5], payload[6], payload[7],
            ]);
            IcmpResult::SendTimestampReply {
                src_ip,
                identifier,
                sequence,
                originate_ts,
            }
        } else {
            IcmpResult::Invalid
        }
    }
}


