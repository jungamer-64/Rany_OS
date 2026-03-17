// ============================================================================
// kernel/src/net/l4/endpoint/segment.rs
// ============================================================================
//! # TCPセグメントビルダー
//!
//! TcpSegmentBuilder - パケット構築

use alloc::vec::Vec;

use super::tcb::tcp_flags;
use super::types::EndpointAddr;

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
    data: Vec<u8>,
    /// TCPオプション
    options: Vec<u8>,
    /// Urgent pointer
    urgent_ptr: u16,
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
            data: Vec::new(),
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

    /// URGフラグ追加
    pub fn urg(mut self) -> Self {
        self.flags |= tcp_flags::URG;
        self
    }

    /// ECN-Echo flag (RFC 3168)
    pub fn ece(mut self) -> Self {
        self.flags |= tcp_flags::ECE;
        self
    }

    /// Congestion Window Reduced flag (RFC 3168)
    pub fn cwr(mut self) -> Self {
        self.flags |= tcp_flags::CWR;
        self
    }

    /// Urgent pointer設定
    /// Note: URGフラグも自動的に設定される
    pub fn urgent_pointer(mut self, ptr: u16) -> Self {
        if ptr > 0 {
            self.flags |= tcp_flags::URG;
        }
        self.urgent_ptr = ptr;
        self
    }

    /// ウィンドウサイズ設定
    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    /// データ設定
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// ペイロード設定（スライスから）
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    // ====================
    // TCPオプション追加メソッド
    // ====================

    /// MSS (Maximum Segment Size) オプション追加
    /// Kind=2, Length=4, MSS=value
    pub fn mss(mut self, mss: u16) -> Self {
        self.options.push(2); // Kind
        self.options.push(4); // Length
        self.options.extend_from_slice(&mss.to_be_bytes());
        self
    }

    /// Window Scale オプション追加
    /// Kind=3, Length=3, Shift=value
    pub fn window_scale(mut self, scale: u8) -> Self {
        self.options.push(3); // Kind
        self.options.push(3); // Length
        self.options.push(scale);
        self
    }

    /// SACK Permitted オプション追加
    /// Kind=4, Length=2
    pub fn sack_permitted(mut self) -> Self {
        self.options.push(4); // Kind
        self.options.push(2); // Length
        self
    }

    /// SACK ブロックオプション追加 (RFC 2018)
    /// Kind=5, Length=2+8*N, N個の (left_edge, right_edge) ペア
    pub fn sack_blocks(mut self, blocks: &[(u32, u32)]) -> Self {
        if blocks.is_empty() {
            return self;
        }
        let num = blocks.len().min(4); // 最大4ブロック
        let opt_len = 2 + num * 8; // Kind(1) + Length(1) + N*8
        self.options.push(5); // Kind = SACK
        self.options.push(opt_len as u8);
        for (left, right) in blocks.iter().take(num) {
            self.options.extend_from_slice(&left.to_be_bytes());
            self.options.extend_from_slice(&right.to_be_bytes());
        }
        self
    }

    /// Timestamp オプション追加
    /// Kind=8, Length=10, TSval=ts_val, TSecr=ts_ecr
    pub fn timestamp(mut self, ts_val: u32, ts_ecr: u32) -> Self {
        self.options.push(8); // Kind
        self.options.push(10); // Length
        self.options.extend_from_slice(&ts_val.to_be_bytes());
        self.options.extend_from_slice(&ts_ecr.to_be_bytes());
        self
    }

    /// NOP (No Operation) オプション追加 - パディング用
    pub fn nop(mut self) -> Self {
        self.options.push(1); // Kind=1 (NOP)
        self
    }

    /// SYN/SYN-ACK用の標準オプションセットを追加
    /// MSS + Window Scale (optional) + SACK Permitted (optional) + Timestamp (optional)
    pub fn syn_options(
        self,
        mss: u16,
        window_scale: Option<u8>,
        sack_permitted: bool,
        ts_val: Option<u32>,
    ) -> Self {
        let mut builder = self.mss(mss);

        if let Some(ws) = window_scale {
            builder = builder.window_scale(ws);
        }

        if sack_permitted {
            builder = builder.sack_permitted();
        }

        if let Some(val) = ts_val {
            builder = builder.timestamp(val, 0);
        }

        builder
    }
    /// オプション長をパディングして4バイト境界に揃える
    fn pad_options(&mut self) {
        // 20バイト + オプション長が4の倍数になるようパディング
        let options_len = self.options.len();
        let remainder = options_len % 4;
        if remainder != 0 {
            let padding = 4 - remainder;
            for _ in 0..padding {
                self.options.push(0); // End of Options (Kind=0) または NOP
            }
        }
    }

    /// TCPセグメントをバイト列に構築
    pub fn build(mut self) -> Vec<u8> {
        // オプションをパディング
        self.pad_options();

        // RFC 793: Maximum TCP header length is 60 bytes (20 bytes fixed + 40 bytes options)
        if self.options.len() > 40 {
            self.options.truncate(40);
        }

        let options_len = self.options.len();
        let header_len = 20 + options_len;
        let data_offset = (header_len / 4) as u8; // 4バイト単位
        let total_len = header_len + self.data.len();

        let mut segment = alloc::vec![0u8; total_len];

        // Source port (2 bytes)
        segment[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        // Destination port (2 bytes)
        segment[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        // Sequence number (4 bytes)
        segment[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        // ACK number (4 bytes)
        segment[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        // Data offset (4 bits) + Reserved (4 bits) + Flags (8 bits)
        let data_off_flags = ((data_offset as u16) << 12) | (self.flags as u16);
        segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
        // Window (2 bytes)
        segment[14..16].copy_from_slice(&self.window.to_be_bytes());
        // Checksum (2 bytes) - will be calculated later
        segment[16..18].copy_from_slice(&0u16.to_be_bytes());
        // Urgent pointer (2 bytes)
        segment[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());

        // Options
        if !self.options.is_empty() {
            segment[20..20 + options_len].copy_from_slice(&self.options);
        }

        // Data
        if !self.data.is_empty() {
            segment[header_len..].copy_from_slice(&self.data);
        }

        segment
    }

    /// チェックサム計算（疑似ヘッダ込み） — IPv4 用
    pub fn calculate_checksum(segment: &mut [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
        if segment.len() < 20 {
            return;
        }

        // チェックサムフィールドをゼロに
        segment[16] = 0;
        segment[17] = 0;

        use crate::net::l3::ipv4::{
            IpProtocol, Ipv4Address, data_checksum, pseudo_header_checksum,
        };
        let src = Ipv4Address::new(src_ip);
        let dst = Ipv4Address::new(dst_ip);
        let pseudo = pseudo_header_checksum(src, dst, IpProtocol::Tcp, segment.len() as u16);
        let checksum = data_checksum(segment, pseudo);

        // TCP checksums are allowed to be 0 (0xFFFF one's complement).
        // Only UDP requires replacing 0 with 0xFFFF.

        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    }

    /// TCPチェックサム計算（IPv6擬似ヘッダ）
    pub fn calculate_checksum_v6(
        segment: &mut [u8],
        src_ip: crate::net::l3::ipv6::Ipv6Address,
        dst_ip: crate::net::l3::ipv6::Ipv6Address,
    ) {
        if segment.len() < 20 {
            return;
        }

        // Ensure checksum field is zeroed
        segment[16] = 0;
        segment[17] = 0;

        use crate::net::l3::ipv4::IpProtocol;
        use crate::net::l3::ipv4::data_checksum;
        use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;

        let pseudo =
            ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Tcp, segment.len() as u32);
        let checksum = data_checksum(segment, pseudo);

        // TCP checksums are allowed to be 0 (0xFFFF one's complement).
        // Only UDP requires replacing 0 with 0xFFFF.

        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    }
}

/// TCPセグメント送信（IP層に渡す） — IPv4/IPv6 デュアルスタック対応
///
/// 非同期イベントキュー経由で送信。スタックロックを直接取得せず、
/// `network_event_task` が一括処理するため、async コンテキストからの
/// 呼び出しでデッドロックを回避する。
pub fn send_tcp_segment(local: EndpointAddr, remote: EndpointAddr, segment: Vec<u8>) -> bool {
    let (scope, ingress_if) = super::tcb::tcb_table()
        .get(local, remote)
        .map(|tcb| (tcb.scope, tcb.ingress_if_id))
        .unwrap_or((crate::net::types::InterfaceScope::Any, None));
    let scoped_if = scope.as_if_id().or(ingress_if);
    if let Some((src_v4, dst_v4)) = endpoint_ipv4_pair(local, remote) {
        let src_ip = crate::net::l3::ipv4::Ipv4Address::new(src_v4);
        let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4);
        let segment_len = segment.len();
        let Some(payload) = crate::net::payload::payload_from_bytes(&segment) else {
            log::debug!(
                "TCP TX enqueue failed: {} -> {} (packet alloc)",
                local,
                remote
            );
            return false;
        };

        // 非同期イベントキュー経由で送信（ロック競合回避）
        let ok = match scoped_if {
            Some(if_id) => {
                crate::net::runtime::stack::enqueue_tcp_send_on(if_id, src_ip, dst_ip, payload)
            }
            None => crate::net::runtime::stack::enqueue_tcp_send(src_ip, dst_ip, payload),
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
        let segment_len = segment.len();
        let Some(payload) = crate::net::payload::payload_from_bytes(&segment) else {
            log::debug!(
                "TCP TX enqueue failed (v6): [{}]:{} -> [{}]:{} (packet alloc)",
                src_v6,
                local.port(),
                dst_v6,
                remote.port()
            );
            return false;
        };
        let ok = match scoped_if {
            Some(if_id) => {
                crate::net::runtime::stack::enqueue_tcp_v6_send_on(if_id, src_v6, dst_v6, payload)
            }
            None => crate::net::runtime::stack::enqueue_tcp_v6_send(src_v6, dst_v6, payload),
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

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

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
            .data(data)
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
            .payload(b"abc")
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

        assert!(!send_tcp_segment(local, remote, segment));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_send_tcp_segment_ipv4_no_panic_when_stack_unavailable() {
        let local = EndpointAddr::new([127, 0, 0, 1], 12346);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        let segment = TcpSegmentBuilder::new(local.port(), remote.port())
            .syn()
            .build();

        let _ = send_tcp_segment(local, remote, segment);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_send_tcp_segment_ipv6_no_panic_when_stack_unavailable() {
        let local =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12347);
        let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
        let segment = TcpSegmentBuilder::new(local.port(), remote.port())
            .syn()
            .build();

        let _ = send_tcp_segment(local, remote, segment);
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

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
            .data(data)
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
            .payload(b"abc")
            .build();

        TcpSegmentBuilder::calculate_checksum(&mut segment, [192, 168, 1, 10], [192, 168, 1, 20]);

        let checksum = u16::from_be_bytes([segment[16], segment[17]]);
        checksum != 0
    }
}
