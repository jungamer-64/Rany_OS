// ============================================================================
// kernel/src/net/l4/endpoint/segment.rs
// ============================================================================
//! # TCPセグメントビルダー
//!
//! TcpSegmentBuilder - パケット構築

use alloc::vec::Vec;

use super::tcb::tcp_flags;
use super::types::{EndpointAddr, EndpointError};
use crate::net::payload::{PacketPayloadBuilder, PacketPayloadView};
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload, PacketRef};

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
    options: Vec<u8>,
    /// Urgent pointer
    urgent_ptr: u16,
}

enum TcpSegmentPayload {
    Empty,
    Packet(PacketPayload),
}

impl TcpSegmentPayload {
    fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Packet(payload) => payload.total_len(),
        }
    }

    fn copy_into(&self, dst: &mut [u8]) {
        match self {
            Self::Empty => {}
            Self::Packet(payload) => {
                let view = PacketPayloadView::new(payload);
                let copied = view.copy_range(0, dst);
                debug_assert_eq!(copied, view.total_len());
            }
        }
    }
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
            options: Vec::new(),
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

    /// フラグ設定
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
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

    /// データ設定
    pub fn payload(mut self, data: &[u8]) -> Self {
        let mut builder = PacketPayloadBuilder::new();
        if builder.push_bytes(data).is_some() {
            self.data = TcpSegmentPayload::Packet(builder.build());
        }
        self
    }

    /// パケットデータ設定（zero-copy）
    pub fn payload_packet(mut self, payload: PacketPayload) -> Self {
        self.data = TcpSegmentPayload::Packet(payload);
        self
    }

    /// TCPオプション追加 (MSS等)
    pub fn option(mut self, kind: u8, data: &[u8]) -> Self {
        if self.options.len() + 2 + data.len() <= 40 {
            self.options.push(kind);
            self.options.push((2 + data.len()) as u8);
            self.options.extend_from_slice(data);
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
        if self.options.len() < 40 {
            self.options.push(1);
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
        let options_len = self.options.len();
        let remainder = options_len % 4;
        if remainder != 0 {
            let padding = 4 - remainder;
            for _ in 0..padding {
                self.options.push(0);
            }
        }
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn build(mut self) -> Vec<u8> {
        self.pad_options();
        if self.options.len() > 40 {
            self.options.truncate(40);
        }
        let options_len = self.options.len();
        let header_len = 20 + options_len;
        let data_offset = (header_len / 4) as u8;
        let total_len = header_len + self.data.len();
        let mut segment = alloc::vec![0u8; total_len];
        self.write_header_bytes(&mut segment, header_len, data_offset, options_len);
        if self.data.len() > 0 {
            self.data.copy_into(&mut segment[header_len..]);
        }
        segment
    }

    pub fn build_packet(mut self) -> Result<PacketPayload, EndpointError> {
        self.pad_options();
        if self.options.len() > 40 {
            self.options.truncate(40);
        }

        let options_len = self.options.len();
        let header_len = 20 + options_len;
        let data_offset = (header_len / 4) as u8;

        let src_port = self.src_port;
        let dst_port = self.dst_port;
        let seq_num = self.seq_num;
        let ack_num = self.ack_num;
        let flags = self.flags;
        let window = self.window;
        let urgent_ptr = self.urgent_ptr;
        let options = core::mem::take(&mut self.options);
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
            if !options.is_empty() {
                segment[20..20 + options_len].copy_from_slice(&options);
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
                Ok(PacketPayload::Single(packet))
            }
            TcpSegmentPayload::Packet(mut payload) => {
                let can_retreat = if let PacketPayload::Single(ref mut packet) = payload {
                    packet.retreat(header_len)
                } else {
                    false
                };

                if can_retreat {
                    if let PacketPayload::Single(ref mut packet) = payload {
                        write_header(packet.data_mut());
                    }
                    Ok(payload)
                } else {
                    let mut header_packet = crate::net::payload::alloc_packet_with_headroom(
                        header_len,
                        DEFAULT_PACKET_HEADROOM,
                    )
                    .ok_or(EndpointError::ResourceExhausted)?;
                    write_header(header_packet.data_mut());
                    Ok(payload.prepend(header_packet))
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

    fn write_header_bytes(
        &self,
        segment: &mut [u8],
        header_len: usize,
        data_offset: u8,
        options_len: usize,
    ) {
        debug_assert!(segment.len() >= header_len);
        segment[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        segment[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        segment[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        segment[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        let data_off_flags = ((data_offset as u16) << 12) | (self.flags as u16);
        segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
        segment[14..16].copy_from_slice(&self.window.to_be_bytes());
        segment[16..18].copy_from_slice(&0u16.to_be_bytes());
        segment[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        if !self.options.is_empty() {
            segment[20..20 + options_len].copy_from_slice(&self.options);
        }
    }

    pub fn calculate_checksum(payload: &mut PacketPayload, src_ip: [u8; 4], dst_ip: [u8; 4]) {
        if payload.total_len() < 20 {
            return;
        }
        if let Some(first) = payload.segments_mut().first_mut() {
            let data = first.data_mut();
            if data.len() >= 20 {
                data[16] = 0;
                data[17] = 0;
            }
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
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        if let Some(first) = payload.segments_mut().first_mut() {
            let data = first.data_mut();
            if data.len() >= 20 {
                data[16..18].copy_from_slice(&checksum.to_be_bytes());
            }
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
        if let Some(first) = payload.segments_mut().first_mut() {
            let data = first.data_mut();
            if data.len() >= 20 {
                data[16] = 0;
                data[17] = 0;
            }
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
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        if let Some(first) = payload.segments_mut().first_mut() {
            let data = first.data_mut();
            if data.len() >= 20 {
                data[16..18].copy_from_slice(&checksum.to_be_bytes());
            }
        }
    }

    pub fn calculate_checksum_bytes(segment: &mut [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
        if segment.len() < 20 {
            return;
        }
        segment[16] = 0;
        segment[17] = 0;
        use crate::net::l3::ipv4::{
            IpProtocol, Ipv4Address, data_checksum, pseudo_header_checksum,
        };
        let src = Ipv4Address::new(src_ip);
        let dst = Ipv4Address::new(dst_ip);
        let pseudo = pseudo_header_checksum(src, dst, IpProtocol::Tcp, segment.len() as u16);
        let checksum = data_checksum(segment, pseudo);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    }

    pub fn calculate_checksum_v6_bytes(
        segment: &mut [u8],
        src_ip: crate::net::l3::ipv6::Ipv6Address,
        dst_ip: crate::net::l3::ipv6::Ipv6Address,
    ) {
        if segment.len() < 20 {
            return;
        }
        segment[16] = 0;
        segment[17] = 0;
        use crate::net::l3::ipv4::{IpProtocol, data_checksum};
        use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;
        let pseudo =
            ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Tcp, segment.len() as u32);
        let checksum = data_checksum(segment, pseudo);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    }
}

pub fn send_tcp_segment_payload(
    local: EndpointAddr,
    remote: EndpointAddr,
    segment: PacketPayload,
) -> bool {
    let (scope, ingress_if) = super::tcb::tcb_table()
        .get(local, remote)
        .map(|tcb| (tcb.scope, tcb.ingress_if_id))
        .unwrap_or((crate::net::types::InterfaceScope::Any, None));
    let scoped_if = scope.as_if_id().or(ingress_if);
    let segment_len = segment.total_len();
    if let Some((src_v4, dst_v4)) = endpoint_ipv4_pair(local, remote) {
        let src_ip = crate::net::l3::ipv4::Ipv4Address::new(src_v4);
        let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4);

        // 非同期イベントキュー経由で送信（ロック競合回避）
        let ok = match scoped_if {
            Some(if_id) => crate::net::runtime::stack::enqueue_tcp_send_on_in(
                crate::net::runtime::default_runtime(),
                if_id,
                src_ip,
                dst_ip,
                segment,
            ),
            None => crate::net::runtime::stack::enqueue_tcp_send_in(
                crate::net::runtime::default_runtime(),
                src_ip,
                dst_ip,
                segment,
            ),
        };
        if ok {
            log::debug!(
                "TCP TX (async): {} -> {} ({} bytes)",
                local,
                remote,
                segment_len
            );
        } else {
            log::debug!("TCP TX enqueue failed: {} -> {}", local, remote);
        }
        return ok;
    }

    if endpoint_is_native_v6_pair(local, remote) {
        let src_v6 = crate::net::l3::ipv6::Ipv6Address::new(local.as_ipv6());
        let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6());
        let ok = match scoped_if {
            Some(if_id) => crate::net::runtime::stack::enqueue_tcp_v6_send_on_in(
                crate::net::runtime::default_runtime(),
                if_id,
                src_v6,
                dst_v6,
                segment,
            ),
            None => crate::net::runtime::stack::enqueue_tcp_v6_send_in(
                crate::net::runtime::default_runtime(),
                src_v6,
                dst_v6,
                segment,
            ),
        };
        if ok {
            log::debug!(
                "TCP TX (v6 async): [{}]:{} -> [{}]:{} ({} bytes)",
                src_v6,
                local.port(),
                dst_v6,
                remote.port(),
                segment_len
            );
        } else {
            log::debug!(
                "TCP TX enqueue failed (v6): [{}]:{} -> [{}]:{}",
                src_v6,
                local.port(),
                dst_v6,
                remote.port()
            );
        }
        return ok;
    }

    log::warn!(
        "[NET][endpoint] mixed TCP address family dropped: {} -> {}",
        local,
        remote
    );
    false
}

pub fn send_tcp_segment_packet(
    local: EndpointAddr,
    remote: EndpointAddr,
    segment: PacketRef,
) -> bool {
    send_tcp_segment_payload(local, remote, PacketPayload::single(segment))
}

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    fn test_payload_bytes(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
    }

    fn send_test_segment(local: EndpointAddr, remote: EndpointAddr, segment: Vec<u8>) -> bool {
        let Some(payload) = crate::net::payload::payload_from_bytes(&segment) else {
            return false;
        };
        send_tcp_segment_payload(local, remote, payload)
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_segment_builder() {
        // SYNセグメント構築
        let segment = TcpSegmentBuilder::new(12345, 80)
            .seq(1000)
            .syn()
            .window(65535)
            .build();

        // ヘッダサイズは20バイト（オプションなし）
        assert_eq!(segment.len(), 20);

        // ポート検証
        assert_eq!(u16::from_be_bytes([segment[0], segment[1]]), 12345);
        assert_eq!(u16::from_be_bytes([segment[2], segment[3]]), 80);

        // シーケンス番号検証
        assert_eq!(
            u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
            1000
        );

        // フラグ検証（SYN = 0x02）
        let data_offset_flags = u16::from_be_bytes([segment[12], segment[13]]);
        let flags = (data_offset_flags & 0x3F) as u8;
        assert_eq!(flags & tcp_flags::SYN, tcp_flags::SYN);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_segment_with_data() {
        let data = alloc::vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
        let segment = TcpSegmentBuilder::new(8080, 80)
            .seq(2000)
            .ack(3000)
            .ack_flag()
            .payload_packet(test_payload_bytes(&data))
            .build();

        // ヘッダ20バイト + データ5バイト
        assert_eq!(segment.len(), 25);

        // データ検証
        assert_eq!(&segment[20..], b"Hello");
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_segment_with_options() {
        // SYNセグメント with TCP options
        let segment = TcpSegmentBuilder::new(12345, 80)
            .seq(1000)
            .syn()
            .window(65535)
            .syn_options(1460, Some(7), true, None) // MSS=1460, WS=7, SACK
            .build();

        // ヘッダ20バイト + オプション12バイト = 32バイト (MSS:4, WS:3, SACK:2, NOP:3)
        assert_eq!(segment.len(), 32);

        // Data Offset = 8 (32バイト / 4 = 8)
        let data_offset_flags = u16::from_be_bytes([segment[12], segment[13]]);
        let data_offset = ((data_offset_flags >> 12) & 0xF) as u8;
        assert_eq!(data_offset, 8);

        // オプション検証
        // MSS (Kind=2, Length=4, Value=1460)
        assert_eq!(segment[20], 2); // Kind
        assert_eq!(segment[21], 4); // Length
        assert_eq!(u16::from_be_bytes([segment[22], segment[23]]), 1460); // MSS

        // Window Scale (Kind=3, Length=3, Shift=7)
        assert_eq!(segment[24], 3); // Kind
        assert_eq!(segment[25], 3); // Length
        assert_eq!(segment[26], 7); // Shift

        // SACK Permitted (Kind=4, Length=2)
        assert_eq!(segment[27], 4); // Kind
        assert_eq!(segment[28], 2); // Length

        // NOP padding (Kind=1) x 3
        assert_eq!(segment[29], 1); // NOP
        assert_eq!(segment[30], 1); // NOP
        assert_eq!(segment[31], 1); // NOP
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_message_length_field_for_checksum() {
        let mut segment = TcpSegmentBuilder::new(12345, 80)
            .seq(1)
            .ack(1)
            .ack_flag()
            .payload_packet(test_payload_bytes(b"abc"))
            .build();

        TcpSegmentBuilder::calculate_checksum(&mut segment, [192, 168, 1, 10], [192, 168, 1, 20]);

        let checksum = u16::from_be_bytes([segment[16], segment[17]]);
        assert_ne!(checksum, 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_checksum_v6() {
        let mut segment = TcpSegmentBuilder::new(1234, 80).seq(1).ack(0).build();
        TcpSegmentBuilder::calculate_checksum_v6(
            &mut segment,
            crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
            crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        );
        // Checksum field should be non-zero for valid segment
        assert!(segment[16] != 0 || segment[17] != 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_send_tcp_segment_rejects_mixed_family() {
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
        let segment = TcpSegmentBuilder::new(local.port(), remote.port())
            .syn()
            .build();

        assert!(!send_test_segment(local, remote, segment));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_send_tcp_segment_ipv4_no_panic_when_stack_unavailable() {
        let local = EndpointAddr::new([127, 0, 0, 1], 12346);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        let segment = TcpSegmentBuilder::new(local.port(), remote.port())
            .syn()
            .build();

        let _ = send_test_segment(local, remote, segment);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_send_tcp_segment_ipv6_no_panic_when_stack_unavailable() {
        let local =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12347);
        let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
        let segment = TcpSegmentBuilder::new(local.port(), remote.port())
            .syn()
            .build();

        let _ = send_test_segment(local, remote, segment);
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    fn test_payload_bytes(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
    }

    pub fn tcp_segment_builder_smoke() -> bool {
        let segment = TcpSegmentBuilder::new(12345, 80)
            .seq(1000)
            .syn()
            .window(65535)
            .build();

        if segment.len() != 20 {
            return false;
        }

        if u16::from_be_bytes([segment[0], segment[1]]) != 12345 {
            return false;
        }
        if u16::from_be_bytes([segment[2], segment[3]]) != 80 {
            return false;
        }
        if u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]) != 1000 {
            return false;
        }

        let data_offset_flags = u16::from_be_bytes([segment[12], segment[13]]);
        let flags = (data_offset_flags & 0x3F) as u8;
        (flags & tcp_flags::SYN) == tcp_flags::SYN
    }

    pub fn tcp_segment_with_data_smoke() -> bool {
        let data = alloc::vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let segment = TcpSegmentBuilder::new(8080, 80)
            .seq(2000)
            .ack(3000)
            .ack_flag()
            .payload_packet(test_payload_bytes(&data))
            .build();

        segment.len() == 25 && &segment[20..] == b"Hello"
    }

    pub fn tcp_segment_with_options_smoke() -> bool {
        let segment = TcpSegmentBuilder::new(12345, 80)
            .seq(1000)
            .syn()
            .window(65535)
            .syn_options(1460, Some(7), true, None)
            .build();

        if segment.len() != 32 {
            return false;
        }

        let data_offset_flags = u16::from_be_bytes([segment[12], segment[13]]);
        let data_offset = ((data_offset_flags >> 12) & 0xF) as u8;
        if data_offset != 8 {
            return false;
        }

        if segment[20] != 2 || segment[21] != 4 {
            return false;
        }
        if u16::from_be_bytes([segment[22], segment[23]]) != 1460 {
            return false;
        }
        if segment[24] != 3 || segment[25] != 3 || segment[26] != 7 {
            return false;
        }
        if segment[27] != 4 || segment[28] != 2 {
            return false;
        }

        segment[29] == 1 && segment[30] == 1 && segment[31] == 1
    }

    pub fn tcp_message_length_field_for_checksum_smoke() -> bool {
        let mut segment = TcpSegmentBuilder::new(12345, 80)
            .seq(1)
            .ack(1)
            .ack_flag()
            .payload_packet(test_payload_bytes(b"abc"))
            .build();

        TcpSegmentBuilder::calculate_checksum(&mut segment, [192, 168, 1, 10], [192, 168, 1, 20]);

        let checksum = u16::from_be_bytes([segment[16], segment[17]]);
        checksum != 0
    }
}
