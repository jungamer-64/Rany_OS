// ============================================================================
// kernel/src/net/l4/tcp/segment.rs - TCPセグメントビルダー
// ============================================================================
//! # TCPセグメントビルダー
//!
//! TcpSegmentBuilder - パケット構築

use super::tcb::tcp_flags;
use crate::net::l4::types::{EndpointAddr, EndpointError};
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketByteCount, PacketPayload};

#[inline]
fn endpoint_ipv4_pair(local: EndpointAddr, remote: EndpointAddr) -> Option<([u8; 4], [u8; 4])> {
    Some((local.as_ipv4()?, remote.as_ipv4()?))
}

#[inline]
fn endpoint_is_native_v6_pair(local: EndpointAddr, remote: EndpointAddr) -> bool {
    local.is_ipv6() && remote.is_ipv6() && local.as_ipv4().is_none() && remote.as_ipv4().is_none()
}

/// TCPセグメントビルダー
pub struct TcpSegmentBuilder {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    data: TcpSegmentPayload,
    /// TCPオプション
    options: [u8; 40],
    options_len: usize,
    /// Urgent pointer
    urgent_ptr: u16,
}

enum TcpSegmentPayload {
    Empty,
    Packet(PacketPayload),
}

impl TcpSegmentBuilder {
    /// 新規作成
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num: 0,
            ack_num: 0,
            flags: 0,
            window: 65535,
            data: TcpSegmentPayload::Empty,
            options: [0; 40],
            options_len: 0,
            urgent_ptr: 0,
        }
    }

    /// シーケンス番号設定
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq_num = seq;
        self
    }

    /// ACK番号設定
    pub fn ack(mut self, ack: u32) -> Self {
        self.ack_num = ack;
        self
    }

    /// SYNフラグ追加
    pub fn syn(mut self) -> Self {
        self.flags |= tcp_flags::SYN;
        self
    }

    /// ACKフラグ追加
    pub fn ack_flag(mut self) -> Self {
        self.flags |= tcp_flags::ACK;
        self
    }

    /// FINフラグ追加
    pub fn fin(mut self) -> Self {
        self.flags |= tcp_flags::FIN;
        self
    }

    /// RSTフラグ追加
    pub fn rst(mut self) -> Self {
        self.flags |= tcp_flags::RST;
        self
    }

    /// PSHフラグ追加
    pub fn psh(mut self) -> Self {
        self.flags |= tcp_flags::PSH;
        self
    }

    /// Window設定
    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    /// パケットデータ設定（zero-copy）
    pub fn payload_packet(mut self, payload: PacketPayload) -> Self {
        self.data = TcpSegmentPayload::Packet(payload);
        self
    }

    /// TCPオプション追加 (MSS等)
    pub fn option(mut self, kind: u8, data: &[u8]) -> Self {
        let option_len = 2 + data.len();
        if self.options_len + option_len <= self.options.len() {
            self.options[self.options_len] = kind;
            self.options[self.options_len + 1] = option_len as u8;
            self.options[self.options_len + 2..self.options_len + option_len].copy_from_slice(data);
            self.options_len += option_len;
        }
        self
    }

    pub fn mss(self, mss: u16) -> Self {
        self.option(2, &mss.to_be_bytes())
    }

    pub fn window_scale(self, scale: u8) -> Self {
        self.option(3, &[scale])
    }

    pub fn sack_permitted(self) -> Self {
        self.option(4, &[])
    }

    pub fn timestamp(self, ts_val: u32, ts_ecr: u32) -> Self {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&ts_val.to_be_bytes());
        data[4..8].copy_from_slice(&ts_ecr.to_be_bytes());
        self.option(8, &data)
    }

    pub fn nop(mut self) -> Self {
        if self.options_len < self.options.len() {
            self.options[self.options_len] = 1;
            self.options_len += 1;
        }
        self
    }

    /// SYN用の標準オプションを構築
    pub fn syn_options(
        self,
        mss: u16,
        window_scale: Option<u8>,
        sack_permitted: bool,
        ts_val: Option<u32>,
    ) -> Self {
        let mut builder = self.mss(mss);
        if let Some(scale) = window_scale {
            builder = builder.window_scale(scale);
        }
        if sack_permitted {
            builder = builder.sack_permitted();
        }
        if let Some(val) = ts_val {
            builder = builder.timestamp(val, 0);
        }
        builder
    }

    fn pad_options(&mut self) {
        let remainder = self.options_len % 4;
        if remainder != 0 {
            let padding = 4 - remainder;
            for _ in 0..padding {
                if self.options_len >= self.options.len() {
                    break;
                }
                self.options[self.options_len] = 0;
                self.options_len += 1;
            }
        }
    }

    pub fn build_packet(mut self) -> Result<PacketPayload, EndpointError> {
        self.pad_options();
        let options_len = self.options_len.min(self.options.len());
        let header_len = 20 + options_len;
        let data_offset = (header_len / 4) as u8;

        let src_port = self.src_port;
        let dst_port = self.dst_port;
        let seq_num = self.seq_num;
        let ack_num = self.ack_num;
        let flags = self.flags;
        let window = self.window;
        let urgent_ptr = self.urgent_ptr;
        let options = self.options;
        let segment_payload = core::mem::replace(&mut self.data, TcpSegmentPayload::Empty);

        let write_header = |segment: &mut [u8]| {
            debug_assert!(segment.len() >= header_len);
            segment[0..2].copy_from_slice(&src_port.to_be_bytes());
            segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
            segment[4..8].copy_from_slice(&seq_num.to_be_bytes());
            segment[8..12].copy_from_slice(&ack_num.to_be_bytes());
            let data_off_flags = ((data_offset as u16) << 12) | (flags as u16);
            segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
            segment[14..16].copy_from_slice(&window.to_be_bytes());
            segment[16..18].copy_from_slice(&0u16.to_be_bytes());
            segment[18..20].copy_from_slice(&urgent_ptr.to_be_bytes());
            if options_len != 0 {
                segment[20..20 + options_len].copy_from_slice(&options[..options_len]);
            }
        };

        match segment_payload {
            TcpSegmentPayload::Empty => {
                let mut packet = crate::net::payload::alloc_packet_with_headroom(
                    header_len,
                    DEFAULT_PACKET_HEADROOM,
                )
                .ok_or(EndpointError::ResourceExhausted)?;
                write_header(packet.data_mut());
                PacketPayload::try_single(packet).map_err(|_| EndpointError::ResourceExhausted)
            }
            TcpSegmentPayload::Packet(mut payload) => {
                if let Ok(header) = payload.try_prepend_in_place(
                    PacketByteCount::new(header_len).expect("TCP header length is non-zero"),
                ) {
                    write_header(header);
                    Ok(payload)
                } else {
                    let mut header_packet = crate::net::payload::alloc_packet_with_headroom(
                        header_len,
                        DEFAULT_PACKET_HEADROOM,
                    )
                    .ok_or(EndpointError::ResourceExhausted)?;
                    write_header(header_packet.data_mut());
                    payload
                        .try_prepend(header_packet)
                        .map_err(|_| EndpointError::ResourceExhausted)
                }
            }
        }
    }

    pub fn build_checked_packet(
        self,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> Result<PacketPayload, EndpointError> {
        let mut payload = self.build_packet()?;
        if let Some((src_v4, dst_v4)) = endpoint_ipv4_pair(local, remote) {
            Self::calculate_checksum(&mut payload, src_v4, dst_v4);
            return Ok(payload);
        }
        if endpoint_is_native_v6_pair(local, remote) {
            Self::calculate_checksum_v6(
                &mut payload,
                crate::net::l3::ipv6::Ipv6Address::new(local.as_ipv6()),
                crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6()),
            );
            return Ok(payload);
        }
        log::warn!(
            "[NET][endpoint] mixed TCP address family rejected: {} -> {}",
            local,
            remote
        );
        Err(EndpointError::InvalidArgument)
    }

    pub fn calculate_checksum(payload: &mut PacketPayload, src_ip: [u8; 4], dst_ip: [u8; 4]) {
        if payload.total_len() < 20 {
            return;
        }
        if let Some(data) = payload.chunks_mut().next()
            && data.len() >= 20
        {
            data[16] = 0;
            data[17] = 0;
        }
        use crate::net::l3::ipv4::{IpProtocol, Ipv4Address, pseudo_header_checksum};
        let src = Ipv4Address::new(src_ip);
        let dst = Ipv4Address::new(dst_ip);
        let pseudo = pseudo_header_checksum(src, dst, IpProtocol::Tcp, payload.total_len() as u16);
        let mut sum = pseudo;
        let mut byte_idx = 0;
        let mut prev_byte = 0u8;
        for chunk in payload.segments() {
            for &b in chunk.data() {
                if byte_idx % 2 == 0 {
                    prev_byte = b;
                } else {
                    sum += u16::from_be_bytes([prev_byte, b]) as u32;
                }
                byte_idx += 1;
            }
        }
        if byte_idx % 2 != 0 {
            sum += u16::from_be_bytes([prev_byte, 0]) as u32;
        }
        // LOOP_PROOF: mode=condition; reason=Carry folding reduces the high half of this 32-bit checksum until the accumulator fits in 16 bits.;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        if let Some(data) = payload.chunks_mut().next()
            && data.len() >= 20
        {
            data[16..18].copy_from_slice(&checksum.to_be_bytes());
        }
    }

    pub fn calculate_checksum_v6(
        payload: &mut PacketPayload,
        src_ip: crate::net::l3::ipv6::Ipv6Address,
        dst_ip: crate::net::l3::ipv6::Ipv6Address,
    ) {
        if payload.total_len() < 20 {
            return;
        }
        if let Some(data) = payload.chunks_mut().next()
            && data.len() >= 20
        {
            data[16] = 0;
            data[17] = 0;
        }
        use crate::net::l3::ipv4::IpProtocol;
        use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;
        let pseudo = ipv6_pseudo_header_checksum(
            &src_ip,
            &dst_ip,
            IpProtocol::Tcp,
            payload.total_len() as u32,
        );
        let mut sum = pseudo;
        let mut byte_idx = 0;
        let mut prev_byte = 0u8;
        for chunk in payload.segments() {
            for &b in chunk.data() {
                if byte_idx % 2 == 0 {
                    prev_byte = b;
                } else {
                    sum += u16::from_be_bytes([prev_byte, b]) as u32;
                }
                byte_idx += 1;
            }
        }
        if byte_idx % 2 != 0 {
            sum += u16::from_be_bytes([prev_byte, 0]) as u32;
        }
        // LOOP_PROOF: mode=condition; reason=Carry folding reduces the high half of this 32-bit checksum until the accumulator fits in 16 bits.;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        if let Some(data) = payload.chunks_mut().next()
            && data.len() >= 20
        {
            data[16..18].copy_from_slice(&checksum.to_be_bytes());
        }
    }
}

/// Transfers a TCP packet to the runtime command queue. Acceptance transfers
/// ownership to the command consumer; it does not acknowledge device transmission.
///
/// # Errors
/// Returns the unchanged packet with `InvalidArgument` for mixed address families,
/// or `ResourceExhausted` when CPU command resources cannot accept the request.
/// A rejected request has not been published and its owner may retry it.
///
/// # Panics
/// The command queue must return the original request on rejection. A different
/// command variant indicates a violated queue ownership contract.
#[expect(
    clippy::result_large_err,
    reason = "Rejection must return the inline packet owner without allocating on the exhausted command path or copying its backing"
)]
pub fn send_tcp_segment_payload_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    if_id: crate::net::runtime::manager::NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    segment: PacketPayload,
    completion_id: Option<u64>,
) -> Result<(), (EndpointError, PacketPayload)> {
    use crate::net::runtime::command::{
        RawIpv4Transport, RawIpv6Transport, RawSendCommand, RuntimeCommand, TransportCommand,
        new_detached_command_channel_in, try_enqueue_command_in,
    };
    use crate::net::types::InterfaceScope;

    let command = if let Some((src, dst)) = endpoint_ipv4_pair(local, remote) {
        RawSendCommand::Ipv4 {
            scope: InterfaceScope::Pinned(if_id),
            dst,
            transport: RawIpv4Transport::Tcp { src },
            payload: segment,
            completion_id,
        }
    } else if endpoint_is_native_v6_pair(local, remote) {
        RawSendCommand::Ipv6 {
            scope: InterfaceScope::Pinned(if_id),
            dst: remote.as_ipv6(),
            transport: RawIpv6Transport::Tcp {
                src: local.as_ipv6(),
            },
            payload: segment,
            completion_id,
        }
    } else {
        return Err((EndpointError::InvalidArgument, segment));
    };
    let reply = new_detached_command_channel_in(runtime);
    match try_enqueue_command_in(
        runtime,
        RuntimeCommand::Transport(TransportCommand::RawSend { command, reply }),
    ) {
        Ok(()) => Ok(()),
        Err(RuntimeCommand::Transport(TransportCommand::RawSend { command, .. })) => {
            let payload = match command {
                RawSendCommand::Ipv4 { payload, .. } | RawSendCommand::Ipv6 { payload, .. } => {
                    payload
                }
            };
            Err((EndpointError::ResourceExhausted, payload))
        }
        Err(_) => unreachable!("network command rejection must return the original TCP request"),
    }
}
