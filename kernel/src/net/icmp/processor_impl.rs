use super::*;


impl IcmpProcessor {
    /// Create a new ICMP processor
    pub fn new(local_ip: Ipv4Address) -> Self {
        IcmpProcessor {
            _local_ip: local_ip,
            stats: IcmpStats::default(),
            per_ip_rate_limits: alloc::collections::BTreeMap::new(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }

    /// Process an incoming ICMP packet
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address, current_time: u64) -> IcmpResult {
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

                // Rate limiting (Per-IP Token Bucket)
                // Add 1 token per 100ms, max 20 tokens.
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
                        return IcmpResult::Ignored;
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
                    return IcmpResult::Ignored;
                }
                *tokens -= 1;

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
        if buffer.len() < IcmpHeader::SIZE + 4 + 8 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder
            .set_type(IcmpType::DestinationUnreachable)
            .set_code(code as u8);

        // 4 bytes unused, then original IP header + 8 bytes
        let payload = builder.payload_mut();
        payload[0..4].copy_from_slice(&[0, 0, 0, 0]); // Unused

        let copy_len = original_packet.len().min(payload.len() - 4).min(28);
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
        if buffer.len() < IcmpHeader::SIZE + 4 + 8 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder
            .set_type(IcmpType::TimeExceeded)
            .set_code(code as u8);

        let payload = builder.payload_mut();
        payload[0..4].copy_from_slice(&[0, 0, 0, 0]); // Unused

        let copy_len = original_packet.len().min(payload.len() - 4).min(28);
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

#[cfg(any(test, feature = "qemu-test-export"))]
#[path = "tests.rs"]
pub mod tests;

