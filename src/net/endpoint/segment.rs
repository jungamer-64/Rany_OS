//! # TCPセグメントビルダー
//!
//! TcpSegmentBuilder - パケット構築

use alloc::vec::Vec;

use super::tcb::tcp_flags;
use super::types::SocketAddr;

/// TCPセグメントビルダー
pub struct TcpSegmentBuilder {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    data: Vec<u8>,
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

    /// TCPセグメントをバイト列に構築
    pub fn build(self) -> Vec<u8> {
        let data_offset = 5u8; // 20バイト（オプションなし）
        let header_len = (data_offset as usize) * 4;
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
        segment[18..20].copy_from_slice(&0u16.to_be_bytes());

        // Data
        if !self.data.is_empty() {
            segment[header_len..].copy_from_slice(&self.data);
        }

        segment
    }

    /// チェックサム計算（疑似ヘッダ込み）
    pub fn calculate_checksum(segment: &mut [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
        // チェックサムフィールドをゼロに
        segment[16] = 0;
        segment[17] = 0;

        // 疑似ヘッダ
        let mut sum: u32 = 0;

        // 送信元IP
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        // 宛先IP
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        // Protocol (TCP = 6) + TCPセグメント長
        sum += 6u32;
        sum += segment.len() as u32;

        // TCPセグメント本体
        let mut i = 0;
        while i + 1 < segment.len() {
            sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
            i += 2;
        }
        // 奇数長の場合
        if i < segment.len() {
            sum += (segment[i] as u32) << 8;
        }

        // 1の補数計算
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !sum as u16;

        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    }
}

/// TCPセグメント送信（IP層に渡す）
pub fn send_tcp_segment(local: SocketAddr, remote: SocketAddr, segment: Vec<u8>) {
    // IP層経由でパケット送信
    let src_ip = crate::net::ipv4::Ipv4Address::new(local.ip);
    let dst_ip = crate::net::ipv4::Ipv4Address::new(remote.ip);

    // NetworkStack経由で送信
    let stack = crate::net::stack::stack();
    if let Some(ref s) = *stack.lock() {
        if s.send_tcp(src_ip, dst_ip, &segment) {
            crate::serial_println!(
                "TCP TX: {:?}:{} -> {:?}:{} ({} bytes)",
                local.ip,
                local.port,
                remote.ip,
                remote.port,
                segment.len()
            );
        } else {
            crate::serial_println!(
                "TCP TX failed (ARP pending?): {:?}:{} -> {:?}:{}",
                local.ip,
                local.port,
                remote.ip,
                remote.port
            );
        }
    } else {
        crate::serial_println!("TCP TX: Network stack not initialized");
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_segment_builder() {
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

    #[test]
    fn test_tcp_segment_with_data() {
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
}
