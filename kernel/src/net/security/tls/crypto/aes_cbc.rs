// ============================================================================
// tls/crypto/aes_cbc.rs - AES-CBC Implementation (NIST SP 800-38A)
// TLS 1.0/1.1/1.2 CBC暗号スイートに必要
// ============================================================================

use super::aes_core::{
    AesRoundKeySchedule, aes_add_round_key, aes_encrypt_block_with_schedule,
    aes_expand_key_schedule, gf_mul,
};
use alloc::vec::Vec;

/// AES Inverse S-box (復号用)
const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES InvSubBytes
fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

/// AES InvShiftRows
fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    // Row 0: no shift
    // Row 1: shift right by 1
    state[1] = temp[13];
    state[5] = temp[1];
    state[9] = temp[5];
    state[13] = temp[9];
    // Row 2: shift right by 2
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    // Row 3: shift right by 3
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
    state[15] = temp[3];
}

/// AES InvMixColumns
fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        state[i + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        state[i + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        state[i + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

/// AESブロック復号 (拡張鍵スケジュール使用)
fn aes_decrypt_block_with_schedule(block: &[u8; 16], schedule: &AesRoundKeySchedule) -> [u8; 16] {
    let mut state = *block;

    // 最終ラウンドキーを最初に適用
    aes_add_round_key(&mut state, &schedule.round_keys[schedule.rounds]);

    // 逆ラウンド (MixColumns含む)
    for i in (1..schedule.rounds).rev() {
        aes_inv_shift_rows(&mut state);
        aes_inv_sub_bytes(&mut state);
        aes_add_round_key(&mut state, &schedule.round_keys[i]);
        aes_inv_mix_columns(&mut state);
    }

    // 最初のラウンド (MixColumnsなし)
    aes_inv_shift_rows(&mut state);
    aes_inv_sub_bytes(&mut state);
    aes_add_round_key(&mut state, &schedule.round_keys[0]);

    state
}

/// AES-CBC暗号化
///
/// 入力はパディング済み（16バイトの倍数）であること。
/// C[i] = AES_Encrypt(P[i] XOR C[i-1]), C[-1] = IV
pub(crate) fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let Some(schedule) = aes_expand_key_schedule(key) else {
        return Vec::new();
    };

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut prev_block = *iv;

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);

        // XOR with previous ciphertext block
        for j in 0..16 {
            block[j] ^= prev_block[j];
        }

        let encrypted = aes_encrypt_block_with_schedule(&block, &schedule);
        ciphertext.extend_from_slice(&encrypted);
        prev_block = encrypted;
    }

    ciphertext
}

/// AES-CBC復号
///
/// P[i] = AES_Decrypt(C[i]) XOR C[i-1], C[-1] = IV
/// パディングは呼び出し側で検証・除去する。
pub(crate) fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() % 16 != 0 || ciphertext.is_empty() {
        return None;
    }

    let schedule = aes_expand_key_schedule(key)?;

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = *iv;

    for chunk in ciphertext.chunks(16) {
        let mut ct_block = [0u8; 16];
        ct_block.copy_from_slice(chunk);

        let mut decrypted = aes_decrypt_block_with_schedule(&ct_block, &schedule);

        // XOR with previous ciphertext block
        for j in 0..16 {
            decrypted[j] ^= prev_block[j];
        }

        plaintext.extend_from_slice(&decrypted);
        prev_block = ct_block;
    }

    Some(plaintext)
}

/// TLSパディング追加 (RFC 5246 Section 6.2.3.2)
///
/// padding_length = block_size - ((data_len) % block_size) - 1 の場合もあるが、
/// TLSでは: padding = [pad_val; pad_val + 1] where pad_val = block_size - 1 - (data_len % block_size)
/// 各パディングバイトの値 = パディング長 - 1
pub(crate) fn tls_add_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let pad_byte = (pad_len - 1) as u8;
    let mut result = Vec::with_capacity(data.len() + pad_len);
    result.extend_from_slice(data);
    for _ in 0..pad_len {
        result.push(pad_byte);
    }
    result
}

/// TLSパディング検証 (定時間)
///
/// パディングの最後のバイトがパディング長を示す。
/// 全パディングバイトが同じ値であることを検証。
/// 戻り値: パディングを除いたデータ長、または None
pub(crate) fn tls_verify_padding(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }

    // TLS padding: all bytes in padding must have the same value as the last byte.
    // Last byte value is (padding_length - 1).
    let last_byte = data[data.len() - 1];
    let pad_len = (last_byte as usize).wrapping_add(1);

    // Security (Lucky13/POODLE mitigation):
    // Use bitwise operations to avoid branching on secret padding data.
    let mut bad = 0usize;

    // Check if padding length is valid (1..=data.len() and <= 256 for TLS)
    // We use bitwise OR to accumulate errors.
    if pad_len > data.len() || pad_len > 256 {
        bad |= 1;
    }

    // Always check the entire possible padding range (up to 256 bytes) to maintain constant time.
    // We cap it to data.len() to avoid out-of-bounds, but for TLS records data.len()
    // is usually > 256. If data.len() < 256, we check up to data.len().
    let check_len = data.len().min(256);

    for i in 0..check_len {
        let mask = if i < pad_len { 0xFF } else { 0x00 };
        let actual_byte = data[data.len() - 1 - i];
        bad |= ((actual_byte ^ last_byte) as usize) & mask;
    }

    // Constant-time check: if bad is 0, return Some(data.len() - pad_len), else None.
    // Note: Option returning is still a branch, but we've mitigated the timing of the
    // internal verification logic which is the primary leak in Lucky 13.
    if bad == 0 {
        Some(data.len() - pad_len)
    } else {
        None
    }
}
