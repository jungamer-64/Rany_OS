use super::*;

impl Icmpv6Builder {
    /// Build an ICMPv6 Echo Reply
    ///
    /// Returns the complete ICMPv6 message with correct checksum
    pub fn build_echo_reply(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        identifier: u16,
        sequence: u16,
        payload: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        Self::build_echo(
            src,
            dst,
            Icmpv6Type::EchoReply,
            identifier,
            sequence,
            payload,
        )
    }

    /// Build an ICMPv6 Echo Request
    ///
    /// Returns the complete ICMPv6 message with correct checksum
    pub fn build_echo_request(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        identifier: u16,
        sequence: u16,
        payload: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        Self::build_echo(
            src,
            dst,
            Icmpv6Type::EchoRequest,
            identifier,
            sequence,
            payload,
        )
    }

    /// Build ICMPv6 Echo message (shared by Request and Reply)
    fn build_echo(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        msg_type: Icmpv6Type,
        identifier: u16,
        sequence: u16,
        payload: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        let payload_len = payload.total_len();
        let total_len = ICMPV6_ECHO_HEADER_SIZE + payload_len;
        let mut packet = alloc_packet_with_headroom(total_len, 0)?;
        let message = &mut packet.data_mut()[..total_len];

        message[0] = u8::from(msg_type);
        message[1] = 0;
        message[2] = 0;
        message[3] = 0;
        message[4..6].copy_from_slice(&identifier.to_be_bytes());
        message[6..8].copy_from_slice(&sequence.to_be_bytes());
        if payload_len > 0
            && payload.copy_all_into(&mut message[ICMPV6_ECHO_HEADER_SIZE..]) != payload_len
        {
            return None;
        }

        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(message, pseudo);
        message[2..4].copy_from_slice(&cksum.to_be_bytes());

        Some(PacketPayload::single(packet))
    }

    /// Build a Packet Too Big message (RFC 4443 Section 3.2)
    pub fn build_packet_too_big(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        mtu: u32,
        trigger_packet: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        Self::build_error(src, dst, Icmpv6Type::PacketTooBig, 0, mtu, trigger_packet)
    }

    /// Build a Destination Unreachable message
    pub fn build_dest_unreachable(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        code: u8,
        trigger_packet: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        Self::build_error(
            src,
            dst,
            Icmpv6Type::DestinationUnreachable,
            code,
            0,
            trigger_packet,
        )
    }

    /// Build a Time Exceeded message
    pub fn build_time_exceeded(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        code: u8,
        trigger_packet: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        Self::build_error(src, dst, Icmpv6Type::TimeExceeded, code, 0, trigger_packet)
    }

    /// Build a Parameter Problem message
    pub fn build_parameter_problem(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        code: u8,
        pointer: u32,
        trigger_packet: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        Self::build_error(
            src,
            dst,
            Icmpv6Type::ParameterProblem,
            code,
            pointer,
            trigger_packet,
        )
    }

    /// Internal helper to build ICMPv6 error messages
    fn build_error(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        msg_type: Icmpv6Type,
        code: u8,
        arg: u32,
        trigger_packet: &PacketPayloadView<'_>,
    ) -> Option<PacketPayload> {
        // ICMPv6 header (4) + arg/unused (4) + as much of trigger as fits
        // stay under minimum MTU of 1280 (RFC 4443)
        let max_trigger = 1232.min(trigger_packet.total_len());
        let total_len = 8 + max_trigger;
        let mut packet = alloc_packet_with_headroom(total_len, 0)?;
        let message = &mut packet.data_mut()[..total_len];

        message[0] = u8::from(msg_type);
        message[1] = code;
        // Checksum placeholder
        // Bytes 4-7 = argument (e.g. pointer for parameter problem)
        let arg_bytes = arg.to_be_bytes();
        message[4..8].copy_from_slice(&arg_bytes);

        // Trigger packet
        if max_trigger > 0
            && trigger_packet.copy_all_into(&mut message[8..8 + max_trigger]) != max_trigger
        {
            return None;
        }

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(message, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        message[2] = cksum_bytes[0];
        message[3] = cksum_bytes[1];

        Some(PacketPayload::single(packet))
    }
}
