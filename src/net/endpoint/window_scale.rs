//! # TCP Window Scaling - ウィンドウスケーリング
//!
//! RFC 1323 / RFC 7323 準拠実装
//! - Window Scale Option (WSopt)
//! - 最大1GBのウィンドウサイズをサポート

/// 最大ウィンドウスケール値 (2^14 = 16384 まで)
pub const MAX_WINDOW_SCALE: u8 = 14;

/// デフォルトウィンドウスケール値
pub const DEFAULT_WINDOW_SCALE: u8 = 7; // 2^7 = 128 -> 最大 8MB

/// Window Scaling オプション設定
#[derive(Debug, Clone, Copy)]
pub struct WindowScaleOption {
    /// ウィンドウスケーリングが有効か
    pub enabled: bool,
    /// 送信側スケール値 (相手が使う値、自分が送信するときのシフト量)
    pub snd_scale: u8,
    /// 受信側スケール値 (自分が使う値、相手が送信するときのシフト量)
    pub rcv_scale: u8,
}

impl WindowScaleOption {
    /// 新規作成（無効状態）
    pub const fn new() -> Self {
        Self {
            enabled: false,
            snd_scale: 0,
            rcv_scale: 0,
        }
    }

    /// 有効状態で作成
    pub const fn with_scale(rcv_scale: u8) -> Self {
        let scale = if rcv_scale > MAX_WINDOW_SCALE {
            MAX_WINDOW_SCALE
        } else {
            rcv_scale
        };
        Self {
            enabled: true,
            snd_scale: 0, // 相手からの応答で設定される
            rcv_scale: scale,
        }
    }

    /// デフォルト設定で有効化
    pub const fn default_enabled() -> Self {
        Self::with_scale(DEFAULT_WINDOW_SCALE)
    }

    /// 相手のスケール値を設定（SYN-ACK受信時）
    pub fn set_snd_scale(&mut self, scale: u8) {
        if self.enabled {
            self.snd_scale = scale.min(MAX_WINDOW_SCALE);
        }
    }

    /// 実際の送信ウィンドウサイズを計算
    #[inline]
    pub fn scale_snd_window(&self, advertised_window: u16) -> u32 {
        if self.enabled {
            (advertised_window as u32) << self.snd_scale
        } else {
            advertised_window as u32
        }
    }

    /// 実際の受信ウィンドウサイズを計算
    #[inline]
    pub fn scale_rcv_window(&self, advertised_window: u16) -> u32 {
        if self.enabled {
            (advertised_window as u32) << self.rcv_scale
        } else {
            advertised_window as u32
        }
    }

    /// 広告するウィンドウ値（16bit）を計算
    /// 実際のバッファサイズからスケールダウン
    #[inline]
    pub fn advertised_window(&self, actual_window: u32) -> u16 {
        if self.enabled && self.rcv_scale > 0 {
            let scaled = actual_window >> self.rcv_scale;
            scaled.min(65535) as u16
        } else {
            actual_window.min(65535) as u16
        }
    }
}

impl Default for WindowScaleOption {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP Option Kind values
pub mod tcp_option_kind {
    pub const END_OF_OPTIONS: u8 = 0;
    pub const NOP: u8 = 1;
    pub const MSS: u8 = 2;
    pub const WINDOW_SCALE: u8 = 3;
    pub const SACK_PERMITTED: u8 = 4;
    pub const SACK: u8 = 5;
    pub const TIMESTAMP: u8 = 8;
}

/// TCPオプションパーサー
pub struct TcpOptionParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TcpOptionParser<'a> {
    pub fn new(options: &'a [u8]) -> Self {
        Self {
            data: options,
            pos: 0,
        }
    }

    /// Window Scale オプションを探す
    pub fn find_window_scale(&mut self) -> Option<u8> {
        self.pos = 0;
        while self.pos < self.data.len() {
            let kind = self.data[self.pos];

            match kind {
                tcp_option_kind::END_OF_OPTIONS => break,
                tcp_option_kind::NOP => {
                    self.pos += 1;
                }
                tcp_option_kind::WINDOW_SCALE => {
                    // Kind(1) + Length(1) + ShiftCount(1) = 3 bytes
                    if self.pos + 3 <= self.data.len() && self.data[self.pos + 1] == 3 {
                        return Some(self.data[self.pos + 2]);
                    }
                    self.pos += 3;
                }
                _ => {
                    // 可変長オプション
                    if self.pos + 1 < self.data.len() {
                        let len = self.data[self.pos + 1] as usize;
                        if len < 2 || self.pos + len > self.data.len() {
                            break;
                        }
                        self.pos += len;
                    } else {
                        break;
                    }
                }
            }
        }
        None
    }

    /// MSS オプションを探す
    pub fn find_mss(&mut self) -> Option<u16> {
        self.pos = 0;
        while self.pos < self.data.len() {
            let kind = self.data[self.pos];

            match kind {
                tcp_option_kind::END_OF_OPTIONS => break,
                tcp_option_kind::NOP => {
                    self.pos += 1;
                }
                tcp_option_kind::MSS => {
                    // Kind(1) + Length(1) + MSS(2) = 4 bytes
                    if self.pos + 4 <= self.data.len() && self.data[self.pos + 1] == 4 {
                        let mss =
                            u16::from_be_bytes([self.data[self.pos + 2], self.data[self.pos + 3]]);
                        return Some(mss);
                    }
                    self.pos += 4;
                }
                _ => {
                    // 可変長オプション
                    if self.pos + 1 < self.data.len() {
                        let len = self.data[self.pos + 1] as usize;
                        if len < 2 || self.pos + len > self.data.len() {
                            break;
                        }
                        self.pos += len;
                    } else {
                        break;
                    }
                }
            }
        }
        None
    }
}

/// TCPオプションビルダー
pub struct TcpOptionBuilder {
    buffer: [u8; 40], // 最大オプションサイズ
    len: usize,
}

impl TcpOptionBuilder {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; 40],
            len: 0,
        }
    }

    /// MSS オプション追加
    pub fn add_mss(&mut self, mss: u16) -> &mut Self {
        if self.len + 4 <= 40 {
            self.buffer[self.len] = tcp_option_kind::MSS;
            self.buffer[self.len + 1] = 4; // length
            self.buffer[self.len + 2..self.len + 4].copy_from_slice(&mss.to_be_bytes());
            self.len += 4;
        }
        self
    }

    /// Window Scale オプション追加
    pub fn add_window_scale(&mut self, scale: u8) -> &mut Self {
        // NOP + WSopt for 4-byte alignment
        if self.len + 4 <= 40 {
            self.buffer[self.len] = tcp_option_kind::NOP;
            self.buffer[self.len + 1] = tcp_option_kind::WINDOW_SCALE;
            self.buffer[self.len + 2] = 3; // length
            self.buffer[self.len + 3] = scale.min(MAX_WINDOW_SCALE);
            self.len += 4;
        }
        self
    }

    /// SACK Permitted オプション追加
    pub fn add_sack_permitted(&mut self) -> &mut Self {
        if self.len + 2 <= 40 {
            self.buffer[self.len] = tcp_option_kind::SACK_PERMITTED;
            self.buffer[self.len + 1] = 2; // length
            self.len += 2;
        }
        self
    }

    /// End of Options + パディング
    pub fn finalize(&mut self) -> &[u8] {
        // 4バイト境界にパディング
        while self.len % 4 != 0 && self.len < 40 {
            self.buffer[self.len] = tcp_option_kind::NOP;
            self.len += 1;
        }
        &self.buffer[..self.len]
    }

    /// 現在の長さ
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for TcpOptionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_scale_disabled() {
        let ws = WindowScaleOption::new();
        assert!(!ws.enabled);
        assert_eq!(ws.scale_snd_window(65535), 65535);
        assert_eq!(ws.scale_rcv_window(65535), 65535);
    }

    #[test]
    fn test_window_scale_enabled() {
        let mut ws = WindowScaleOption::with_scale(7);
        assert!(ws.enabled);
        ws.set_snd_scale(7);

        // 128倍にスケール
        assert_eq!(ws.scale_snd_window(1000), 128000);
        assert_eq!(ws.scale_rcv_window(1000), 128000);
    }

    #[test]
    fn test_advertised_window() {
        let ws = WindowScaleOption::with_scale(7);

        // 128で割ってスケールダウン
        assert_eq!(ws.advertised_window(128000), 1000);

        // オーバーフロー防止
        assert_eq!(ws.advertised_window(u32::MAX), 65535);
    }

    #[test]
    fn test_option_builder() {
        let mut builder = TcpOptionBuilder::new();
        builder
            .add_mss(1460)
            .add_window_scale(7)
            .add_sack_permitted();

        let options = builder.finalize();
        assert!(!options.is_empty());
        assert_eq!(options.len() % 4, 0); // 4バイト境界
    }

    #[test]
    fn test_option_parser() {
        // MSS=1460, WSopt=7 のオプション
        let options = [
            2, 4, 0x05, 0xB4, // MSS = 1460
            1,    // NOP
            3, 3, 7, // Window Scale = 7
        ];

        let mut parser = TcpOptionParser::new(&options);
        assert_eq!(parser.find_mss(), Some(1460));
        assert_eq!(parser.find_window_scale(), Some(7));
    }
}
