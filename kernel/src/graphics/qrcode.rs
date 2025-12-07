// ============================================================================
// src/graphics/qrcode.rs - Simple QR Code Generator for no_std environment
// ============================================================================
//!
//! # 簡易QRコード生成器
//!
//! no_std環境で動作するシンプルなQRコード生成器。
//! バージョン1（21x21モジュール）のみをサポート。
//! エラー訂正レベルはL（7%）を使用。
//!
//! ## 制限事項
//! - バージョン1のみ（最大25文字の英数字）
//! - 英数字モードのみ
//! - エラー訂正レベルL固定

#![allow(dead_code)]

use super::{Color, Framebuffer, Rect};

/// QRコードのバージョン1のサイズ（21x21モジュール）
const QR_SIZE: usize = 21;

/// QRコードモジュールの状態
#[derive(Clone, Copy, PartialEq, Eq)]
enum Module {
    /// 未設定
    Unset,
    /// データ/機能パターンで黒
    Dark,
    /// データ/機能パターンで白
    Light,
}

impl Default for Module {
    fn default() -> Self {
        Module::Unset
    }
}

/// QRコードバッファ
pub struct QrCode {
    modules: [[Module; QR_SIZE]; QR_SIZE],
    size: usize,
}

impl QrCode {
    /// 新しいQRコードを生成
    pub fn new(data: &str) -> Option<Self> {
        // バージョン1の英数字モードでは25文字まで
        if data.len() > 25 {
            return None;
        }

        let mut qr = QrCode {
            modules: [[Module::Unset; QR_SIZE]; QR_SIZE],
            size: QR_SIZE,
        };

        // 機能パターンを配置
        qr.place_finder_patterns();
        qr.place_timing_patterns();
        qr.place_format_info();

        // データを符号化して配置
        if let Some(encoded) = encode_alphanumeric(data) {
            qr.place_data(&encoded);
        } else {
            // 符号化失敗時は空のQRコードを返す
            return None;
        }

        // マスクパターンを適用（パターン0: (i + j) mod 2 == 0）
        qr.apply_mask();

        Some(qr)
    }

    /// ファインダーパターンを配置（3つの位置検出パターン）
    fn place_finder_patterns(&mut self) {
        // 左上
        self.place_finder_pattern(0, 0);
        // 右上
        self.place_finder_pattern(QR_SIZE - 7, 0);
        // 左下
        self.place_finder_pattern(0, QR_SIZE - 7);

        // セパレータ（白い境界線）
        // 左上
        for i in 0..8 {
            if i < QR_SIZE {
                self.set_module(7, i, Module::Light);
                self.set_module(i, 7, Module::Light);
            }
        }
        // 右上
        for i in 0..8 {
            if QR_SIZE - 8 + i < QR_SIZE {
                self.set_module(QR_SIZE - 8, i, Module::Light);
            }
            self.set_module(QR_SIZE - 8 + i, 7, Module::Light);
        }
        // 左下
        for i in 0..8 {
            self.set_module(7, QR_SIZE - 8 + i, Module::Light);
            if QR_SIZE - 8 + i < QR_SIZE {
                self.set_module(i, QR_SIZE - 8, Module::Light);
            }
        }
    }

    /// 単一のファインダーパターンを配置
    fn place_finder_pattern(&mut self, x: usize, y: usize) {
        for dy in 0..7 {
            for dx in 0..7 {
                let is_border = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                let is_inner = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
                let module = if is_border || is_inner {
                    Module::Dark
                } else {
                    Module::Light
                };
                self.set_module(x + dx, y + dy, module);
            }
        }
    }

    /// タイミングパターンを配置
    fn place_timing_patterns(&mut self) {
        for i in 8..QR_SIZE - 8 {
            let module = if i % 2 == 0 {
                Module::Dark
            } else {
                Module::Light
            };
            self.set_module(i, 6, module);
            self.set_module(6, i, module);
        }
    }

    /// フォーマット情報を配置（エラー訂正L、マスク0）
    fn place_format_info(&mut self) {
        // フォーマット情報ビット（L-0マスク用、BCHエラー訂正込み）
        // Format info: 01 (L) + 000 (mask 0) = 01000
        // BCH encoded: 111011111000100
        let format_bits: u16 = 0b111011111000100;

        // 左上のフォーマット情報
        let positions_horizontal = [
            (0, 8),
            (1, 8),
            (2, 8),
            (3, 8),
            (4, 8),
            (5, 8),
            (7, 8),
            (8, 8),
            (8, 7),
            (8, 5),
            (8, 4),
            (8, 3),
            (8, 2),
            (8, 1),
            (8, 0),
        ];

        for (i, &(x, y)) in positions_horizontal.iter().enumerate() {
            let bit = ((format_bits >> (14 - i)) & 1) == 1;
            self.set_module(x, y, if bit { Module::Dark } else { Module::Light });
        }

        // 右上と左下のフォーマット情報
        // 右上（水平）
        for i in 0..8 {
            let bit = ((format_bits >> (14 - i)) & 1) == 1;
            self.set_module(QR_SIZE - 1 - i, 8, if bit { Module::Dark } else { Module::Light });
        }

        // 左下（垂直）
        for i in 0..7 {
            let bit = ((format_bits >> (6 - i)) & 1) == 1;
            self.set_module(8, QR_SIZE - 1 - i, if bit { Module::Dark } else { Module::Light });
        }

        // ダークモジュール（固定位置）
        self.set_module(8, QR_SIZE - 8, Module::Dark);
    }

    /// データを配置
    fn place_data(&mut self, data: &[u8]) {
        let mut data_idx = 0;
        let mut bit_idx = 0;

        // 右から左へ、2列ずつスキャン
        let mut x = QR_SIZE - 1;

        while x > 0 {
            // タイミングパターンの列（6）をスキップ
            if x == 6 {
                x -= 1;
                continue;
            }

            // 上下方向を交互に
            let upward = ((QR_SIZE - 1 - x) / 2) % 2 == 0;

            for y_offset in 0..QR_SIZE {
                let y = if upward {
                    QR_SIZE - 1 - y_offset
                } else {
                    y_offset
                };

                // 2列分（右と左）
                for dx in 0..2 {
                    let col = if dx == 0 { x } else { x - 1 };

                    if self.modules[y][col] == Module::Unset {
                        let bit = if data_idx < data.len() {
                            ((data[data_idx] >> (7 - bit_idx)) & 1) == 1
                        } else {
                            false // パディング
                        };

                        self.modules[y][col] = if bit { Module::Dark } else { Module::Light };

                        bit_idx += 1;
                        if bit_idx >= 8 {
                            bit_idx = 0;
                            data_idx += 1;
                        }
                    }
                }
            }

            x = x.saturating_sub(2);
        }
    }

    /// マスクパターンを適用
    fn apply_mask(&mut self) {
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                // 機能パターン以外にマスクを適用
                if self.is_data_module(x, y) {
                    // マスクパターン0: (row + column) mod 2 == 0
                    if (x + y) % 2 == 0 {
                        self.modules[y][x] = match self.modules[y][x] {
                            Module::Dark => Module::Light,
                            Module::Light => Module::Dark,
                            Module::Unset => Module::Unset,
                        };
                    }
                }
            }
        }
    }

    /// データモジュールかどうか（機能パターンでない）
    fn is_data_module(&self, x: usize, y: usize) -> bool {
        // ファインダーパターン + セパレータ
        if x <= 8 && y <= 8 {
            return false;
        }
        if x >= QR_SIZE - 8 && y <= 8 {
            return false;
        }
        if x <= 8 && y >= QR_SIZE - 8 {
            return false;
        }

        // タイミングパターン
        if x == 6 || y == 6 {
            return false;
        }

        true
    }

    /// モジュールを設定
    fn set_module(&mut self, x: usize, y: usize, module: Module) {
        if x < QR_SIZE && y < QR_SIZE {
            self.modules[y][x] = module;
        }
    }

    /// モジュールが黒かどうか
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        if x < QR_SIZE && y < QR_SIZE {
            self.modules[y][x] == Module::Dark
        } else {
            false
        }
    }

    /// QRコードのサイズを取得
    pub fn size(&self) -> usize {
        self.size
    }

    /// フレームバッファにQRコードを描画
    pub fn draw(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        module_size: u32,
        dark_color: Color,
        light_color: Color,
    ) {
        // クワイエットゾーン（白い枠）を含めて描画
        let quiet_zone = 2;
        let total_size = (self.size + quiet_zone * 2) as u32 * module_size;

        // 背景（ライトカラー）
        fb.fill_rect(
            Rect::new(x, y, total_size, total_size),
            light_color,
        );

        // モジュールを描画
        for row in 0..self.size {
            for col in 0..self.size {
                if self.is_dark(col, row) {
                    let px = x + ((quiet_zone + col) as u32 * module_size) as i32;
                    let py = y + ((quiet_zone + row) as u32 * module_size) as i32;
                    fb.fill_rect(
                        Rect::new(px, py, module_size, module_size),
                        dark_color,
                    );
                }
            }
        }
    }
}

/// 英数字をQRコード用にエンコード
fn encode_alphanumeric(data: &str) -> Option<[u8; 26]> {
    let mut result = [0u8; 26];
    let mut bit_buffer: u32 = 0;
    let mut bit_count: usize = 0;
    let mut byte_idx: usize = 0;

    // モード指示子（英数字: 0010）
    bit_buffer = 0b0010;
    bit_count = 4;

    // 文字数指示子（バージョン1では9ビット）
    let char_count = data.len() as u32;
    bit_buffer = (bit_buffer << 9) | (char_count & 0x1FF);
    bit_count += 9;

    // 英数字データをエンコード
    let chars: alloc::vec::Vec<u8> = data
        .chars()
        .filter_map(|c| alphanumeric_value(c))
        .collect();

    if chars.len() != data.len() {
        return None; // 無効な文字が含まれている
    }

    // 2文字ずつエンコード
    let mut i = 0;
    while i < chars.len() {
        if i + 1 < chars.len() {
            // 2文字: 45 * first + second = 11ビット
            let value = (chars[i] as u32) * 45 + (chars[i + 1] as u32);
            bit_buffer = (bit_buffer << 11) | (value & 0x7FF);
            bit_count += 11;
            i += 2;
        } else {
            // 1文字: 6ビット
            let value = chars[i] as u32;
            bit_buffer = (bit_buffer << 6) | (value & 0x3F);
            bit_count += 6;
            i += 1;
        }

        // バイトに書き出し
        while bit_count >= 8 && byte_idx < result.len() {
            bit_count -= 8;
            result[byte_idx] = ((bit_buffer >> bit_count) & 0xFF) as u8;
            byte_idx += 1;
        }
    }

    // 終端パターン（0000、最大4ビット）
    let terminator_bits = core::cmp::min(4, 26 * 8 - (byte_idx * 8 + bit_count));
    bit_buffer <<= terminator_bits;
    bit_count += terminator_bits;

    // 残りのビットを書き出し
    while bit_count >= 8 && byte_idx < result.len() {
        bit_count -= 8;
        result[byte_idx] = ((bit_buffer >> bit_count) & 0xFF) as u8;
        byte_idx += 1;
    }

    // 最後の部分ビットがあればパディング
    if bit_count > 0 && byte_idx < result.len() {
        result[byte_idx] = ((bit_buffer << (8 - bit_count)) & 0xFF) as u8;
        byte_idx += 1;
    }

    // パディングバイト（0xEC, 0x11を交互）
    let mut pad_byte = 0xEC_u8;
    while byte_idx < 19 {
        // バージョン1-Lのデータ容量は19バイト
        result[byte_idx] = pad_byte;
        byte_idx += 1;
        pad_byte = if pad_byte == 0xEC { 0x11 } else { 0xEC };
    }

    // エラー訂正コードワードを追加（簡易版：固定パターン）
    // 実際のReed-Solomon符号化は複雑なため、デモ用に固定値を使用
    let ec_codewords = calculate_ec_codewords(&result[..19]);
    for (i, &ec) in ec_codewords.iter().enumerate() {
        if byte_idx + i < result.len() {
            result[byte_idx + i] = ec;
        }
    }

    Some(result)
}

/// 英数字の値を取得
fn alphanumeric_value(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'A'..='Z' => Some(c as u8 - b'A' + 10),
        ' ' => Some(36),
        '$' => Some(37),
        '%' => Some(38),
        '*' => Some(39),
        '+' => Some(40),
        '-' => Some(41),
        '.' => Some(42),
        '/' => Some(43),
        ':' => Some(44),
        // 小文字を大文字として扱う
        'a'..='z' => Some(c as u8 - b'a' + 10),
        _ => None,
    }
}

/// エラー訂正コードワードを計算（簡易版）
/// 
/// 注: これは完全なReed-Solomon実装ではなく、
/// デモンストレーション用の簡易実装です。
fn calculate_ec_codewords(data: &[u8]) -> [u8; 7] {
    // バージョン1-Lでは7個のエラー訂正コードワード
    let mut ec = [0u8; 7];

    // 簡易的なチェックサム生成（実際のRSではない）
    // 実運用では適切なGalois Field算術が必要
    for (i, byte) in data.iter().enumerate() {
        ec[i % 7] ^= byte;
        ec[(i + 1) % 7] ^= byte.rotate_left(1);
        ec[(i + 2) % 7] ^= byte.rotate_right(1);
    }

    // 追加の混合
    for i in 0..7 {
        ec[i] = ec[i].wrapping_add((i as u8).wrapping_mul(17));
    }

    ec
}

/// エラー情報からQRコードを生成するヘルパー
pub fn generate_error_qr(error_code: &str) -> Option<QrCode> {
    // エラーコードをQRコードに変換
    // 最大25文字に制限
    let truncated = if error_code.len() > 25 {
        &error_code[..25]
    } else {
        error_code
    };

    QrCode::new(truncated)
}
