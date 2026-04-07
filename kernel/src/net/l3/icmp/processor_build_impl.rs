use super::*;

impl IcmpProcessor {
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
}
