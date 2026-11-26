//! RSS のフローハッシュ。

/// ネットワークフロー用CPU親和性マネージャ
pub struct FlowAffinity;

impl FlowAffinity {
    /// 5タプルからフローハッシュを計算（改良版 Toeplitz ハッシュ）
    ///
    /// Microsoft RSS 標準鍵を使用した Toeplitz ハッシュにより、
    /// フロー分散の均一性を改善し、特定CPUコアへの偏りを低減する。
    pub fn hash_5tuple(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> u32 {
        // Microsoft RSS 標準ハッシュキー (40バイト — 先頭13バイトで十分)
        static RSS_KEY: [u8; 40] = [
            0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
            0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
            0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        ];

        // 入力を12バイト（src_ip:4 + dst_ip:4 + src_port:2 + dst_port:2）に
        // パックしてから Toeplitz ハッシュを計算
        let mut input = [0u8; 13];
        input[0..4].copy_from_slice(&src_ip.to_be_bytes());
        input[4..8].copy_from_slice(&dst_ip.to_be_bytes());
        input[8..10].copy_from_slice(&src_port.to_be_bytes());
        input[10..12].copy_from_slice(&dst_port.to_be_bytes());
        input[12] = protocol;

        toeplitz_hash(&input, &RSS_KEY)
    }
}

/// Toeplitz ハッシュ計算
///
/// NIC RSS と互換性のある Toeplitz ハッシュ関数。
/// `key` は少なくとも `input.len() + 4` バイトの長さが必要。
fn toeplitz_hash(input: &[u8], key: &[u8]) -> u32 {
    let mut result: u32 = 0;

    // key の最初の4バイトを初期値として32ビットに展開
    let mut k: u32 = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);

    for (i, &byte) in input.iter().enumerate() {
        // key から次のバイトを取得して k をシフト
        let next_key_byte = if i + 4 < key.len() { key[i + 4] } else { 0 };

        for bit in (0..8).rev() {
            if byte & (1 << bit) != 0 {
                result ^= k;
            }
            // k を1ビット左シフトし、next_key_byte の対応ビットを右端に入れる
            k = (k << 1) | ((next_key_byte as u32 >> bit) & 1);
        }
    }

    result
}
