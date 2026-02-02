// ============================================================================
// kernel/src/net/endpoint/segment.rs
// ============================================================================
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
    /// TCPオプション
    options: Vec<u8>,
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

    /// Timestamp オプション追加
    /// Kind=8, Length=10, TSval=ts_val, TSecr=ts_ecr
    pub fn timestamp(mut self, ts_val: u32, ts_ecr: u32) -> Self {
        self.options.push(8);  // Kind
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
    /// MSS + Window Scale + SACK Permitted + NOP (4バイト境界パディング)
    pub fn syn_options(self, mss: u16, window_scale: u8) -> Self {
        // MSS(4) + WS(3) + SACK(2) + NOP(1) = 10 bytes → 次の4バイト境界は12
        // 12バイトにするにはNOP 2個追加
        self.mss(mss)
            .window_scale(window_scale)
            .sack_permitted()
            .nop()
            .nop()
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
        segment[18..20].copy_from_slice(&0u16.to_be_bytes());

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
    match stack.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                if s.send_tcp(src_ip, dst_ip, &segment) {
                    log::info!(
                        "TCP TX: {:?}:{} -> {:?}:{} ({} bytes)",
                        local.ip,
                        local.port,
                        remote.ip,
                        remote.port,
                        segment.len()
                    );
                } else {
                    log::info!(
                        "TCP TX failed (ARP pending?): {:?}:{} -> {:?}:{}",
                        local.ip,
                        local.port,
                        remote.ip,
                        remote.port
                    );
                }
            } else {
                log::info!("TCP TX: Network stack not initialized");
            }
        }
        Err(_) => {
            log::error!("[NET] Stack poisoned - dropping TCP segment");
        }
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
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

    #[test_case]
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

    #[test_case]
    fn test_tcp_segment_with_options() {
        // SYNセグメント with TCP options
        let segment = TcpSegmentBuilder::new(12345, 80)
            .seq(1000)
            .syn()
            .window(65535)
            .syn_options(1460, 7) // MSS=1460, WS=7, SACK
            .build();

        // ヘッダ20バイト + オプション12バイト = 32バイト
        assert_eq!(segment.len(), 32);

        // Data Offset = 8 (32バイト / 4 = 8)
        let data_offset_flags = u16::from_be_bytes([segment[12], segment[13]]);
        let data_offset = ((data_offset_flags >> 12) & 0xF) as u8;
        assert_eq!(data_offset, 8);

        // オプション検証
        // MSS (Kind=2, Length=4, Value=1460)
        assert_eq!(segment[20], 2);  // Kind
        assert_eq!(segment[21], 4);  // Length
        assert_eq!(u16::from_be_bytes([segment[22], segment[23]]), 1460); // MSS

        // Window Scale (Kind=3, Length=3, Shift=7)
        assert_eq!(segment[24], 3);  // Kind
        assert_eq!(segment[25], 3);  // Length
        assert_eq!(segment[26], 7);  // Shift

        // SACK Permitted (Kind=4, Length=2)
        assert_eq!(segment[27], 4);  // Kind
        assert_eq!(segment[28], 2);  // Length

        // NOP padding (Kind=1)
        assert_eq!(segment[29], 1);  // NOP
        assert_eq!(segment[30], 1);  // NOP
    }

    #[test_case]
