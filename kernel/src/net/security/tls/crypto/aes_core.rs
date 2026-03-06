// ============================================================================
// tls/crypto/aes_core.rs - AES Core Primitives (AES-128/AES-256)
// ============================================================================
// AES暗号プリミティブ。全関数が直接呼び出されるわけではないが、
// AES-CBC/AES-GCM等のモード実装で必要となるビルディングブロック。

use alloc::vec::Vec;

/// AES-128 Sbox
pub(crate) const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES Rcon (round constants)
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128キー展開 (Legacy — テスト用途)
///
/// NOTE: 新規コードでは `aes_expand_key_schedule()` を使用してください。
/// この関数はAES-128のみ対応しています。AES-128/256の両方に対応する
/// 統合実装は `aes_expand_key_schedule()` です。
pub(crate) fn aes_key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut round_keys = [[0u8; 16]; 11];
    round_keys[0].copy_from_slice(key);

    for i in 1..11 {
        // 前のラウンドキーをコピーして借用問題を回避
        let prev = round_keys[i - 1];
        let mut temp = [prev[12], prev[13], prev[14], prev[15]];

        // RotWord
        temp.rotate_left(1);

        // SubWord
        for b in &mut temp {
            *b = AES_SBOX[*b as usize];
        }

        // XOR with Rcon
        temp[0] ^= RCON[i - 1];

        for j in 0..4 {
            for k in 0..4 {
                round_keys[i][j * 4 + k] = if j == 0 {
                    prev[k] ^ temp[k]
                } else {
                    prev[j * 4 + k] ^ round_keys[i][(j - 1) * 4 + k]
                };
            }
        }
    }

    round_keys
}

/// GF(2^8) での乗算 (AES 用)
///
/// 以前の実装は分岐を伴っておりタイミング攻撃に対して脆弱でした。
/// この実装はビットマスクを使用し、入力データに依存しない一定の時間で実行されます。
pub(crate) fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        // bの最下位ビットが1ならaを加算(XOR)
        let mask = 0u8.wrapping_sub(b & 1);
        result ^= a & mask;

        // aを2倍し、溢れたら多項式 0x1b で減算(XOR)
        let high_bit_mask = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & high_bit_mask);

        b >>= 1;
    }
    result
}

/// AES SubBytes
fn aes_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

/// AES ShiftRows
fn aes_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    // Row 0: no shift
    // Row 1: shift left by 1
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];
    // Row 2: shift left by 2
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    // Row 3: shift left by 3
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

/// AES MixColumns
fn aes_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[i + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

/// AES AddRoundKey
pub(crate) fn aes_add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(round_key.iter()) {
        *s ^= *k;
    }
}

/// AES-128 ブロック暗号化
pub(crate) fn aes_encrypt_block(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *block;

    // Initial round
    aes_add_round_key(&mut state, &round_keys[0]);

    // Main rounds
    for i in 1..10 {
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, &round_keys[i]);
    }

    // Final round (no MixColumns)
    aes_sub_bytes(&mut state);
    aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, &round_keys[10]);

    state
}

/// Expanded AES key schedule supporting AES-128/AES-256.
#[derive(Clone, Copy)]
pub(crate) struct AesRoundKeySchedule {
    /// Round keys (maximum needed by AES-256 = 15 keys)
    pub(crate) round_keys: [[u8; 16]; 15],
    /// Number of rounds (10 for AES-128, 14 for AES-256)
    pub(crate) rounds: usize,
}

/// Apply RotWord + SubWord to a 4-byte AES temp word.
fn rotate_sub_word(temp: &mut [u8; 4]) {
    temp.rotate_left(1);
    for b in temp.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

/// Apply SubWord only (AES-256 extra step).
fn sub_word(temp: &mut [u8; 4]) {
    for b in temp.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

/// Expand raw 4-byte words from the AES key.
fn expand_aes_words(key: &[u8], nk: usize, total_words: usize) -> [[u8; 4]; 60] {
    let mut words = [[0u8; 4]; 60];
    for i in 0..nk {
        let base = i * 4;
        words[i].copy_from_slice(&key[base..base + 4]);
    }
    for i in nk..total_words {
        let mut temp = words[i - 1];
        if i % nk == 0 {
            rotate_sub_word(&mut temp);
            temp[0] ^= RCON[(i / nk) - 1];
        } else if nk > 6 && i % nk == 4 {
            sub_word(&mut temp);
        }
        for j in 0..4 {
            words[i][j] = words[i - nk][j] ^ temp[j];
        }
    }
    words
}

/// Pack expanded words into round key arrays.
fn words_to_round_keys(words: &[[u8; 4]; 60], nr: usize) -> [[u8; 16]; 15] {
    let mut round_keys = [[0u8; 16]; 15];
    for round in 0..=nr {
        for word_idx in 0..4 {
            let word = words[round * 4 + word_idx];
            let start = word_idx * 4;
            round_keys[round][start..start + 4].copy_from_slice(&word);
        }
    }
    round_keys
}

/// Expand AES key schedule for AES-128 (16-byte key) or AES-256 (32-byte key).
pub(crate) fn aes_expand_key_schedule(key: &[u8]) -> Option<AesRoundKeySchedule> {
    let nk = match key.len() {
        16 => 4, // AES-128
        32 => 8, // AES-256
        _ => return None,
    };

    let nr = nk + 6;
    let total_words = 4 * (nr + 1);
    let words = expand_aes_words(key, nk, total_words);
    let round_keys = words_to_round_keys(&words, nr);

    Some(AesRoundKeySchedule {
        round_keys,
        rounds: nr,
    })
}

/// Encrypt one AES block using a pre-expanded key schedule.
pub(crate) fn aes_encrypt_block_with_schedule(
    block: &[u8; 16],
    schedule: &AesRoundKeySchedule,
) -> [u8; 16] {
    let mut state = *block;

    aes_add_round_key(&mut state, &schedule.round_keys[0]);

    for i in 1..schedule.rounds {
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, &schedule.round_keys[i]);
    }

    aes_sub_bytes(&mut state);
    aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, &schedule.round_keys[schedule.rounds]);

    state
}

/// AES-CTR with pre-expanded schedule.
pub(crate) fn aes_ctr_with_schedule(
    schedule: &AesRoundKeySchedule,
    nonce: &[u8],
    data: &[u8],
    initial_counter: u32,
) -> Vec<u8> {
    if nonce.len() != 12 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(data.len());
    let mut counter_block = [0u8; 16];
    counter_block[0..12].copy_from_slice(nonce);

    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        let counter = (chunk_idx as u32)
            .wrapping_add(initial_counter)
            .to_be_bytes();
        counter_block[12..16].copy_from_slice(&counter);

        let keystream = aes_encrypt_block_with_schedule(&counter_block, schedule);

        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }
    }

    result
}

/// AES-CTR with pre-expanded schedule (In-place, no allocation).
pub(crate) fn aes_ctr_with_schedule_in_place(
    schedule: &AesRoundKeySchedule,
    nonce: &[u8],
    initial_counter: u32,
    data: &mut [u8],
) {
    if nonce.len() != 12 {
        return;
    }

    let mut counter_block = [0u8; 16];
    counter_block[0..12].copy_from_slice(nonce);

    for (chunk_idx, chunk) in data.chunks_mut(16).enumerate() {
        let counter = (chunk_idx as u32)
            .wrapping_add(initial_counter)
            .to_be_bytes();
        counter_block[12..16].copy_from_slice(&counter);

        let keystream = aes_encrypt_block_with_schedule(&counter_block, schedule);

        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
    }
}

/// AES-CTR モードでの暗号化/復号
pub(crate) fn aes_ctr(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let Some(schedule) = aes_expand_key_schedule(key) else {
        return Vec::new();
    };
    aes_ctr_with_schedule(&schedule, nonce, data, 1)
}
