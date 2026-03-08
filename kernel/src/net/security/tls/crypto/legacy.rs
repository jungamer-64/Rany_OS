// tls/crypto/legacy.rs - Legacy Hash (MD5, SHA-1), HMAC, and TLS 1.0 PRF

use super::hmac::hmac_sha256;
use crate::net::security::tls::TlsVersion;
use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// MD5 Implementation (RFC 1321)
// TLS 1.0/1.1 PRF のデュアルハッシュ方式に必要
// ============================================================================

/// MD5 output size in bytes
const MD5_OUTPUT_SIZE: usize = 16;

/// MD5 block size in bytes
const MD5_BLOCK_SIZE: usize = 64;

/// MD5 initial hash values (RFC 1321 Section 3.3)
const MD5_INIT: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// MD5 per-round shift amounts (RFC 1321 Section 3.4)
const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// MD5 T[i] = floor(2^32 * abs(sin(i+1))) constants
const MD5_T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// MD5ハッシュ計算 (ストリーミング対応)
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: MD5_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        // バッファに残りがあれば先に埋める
        if self.buffer_len > 0 {
            let remaining = 64 - self.buffer_len;
            let copy_len = remaining.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            offset = copy_len;

            if self.buffer_len == 64 {
                let block = self.buffer;
                md5_compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        // 64バイトブロックを直接処理
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            md5_compress(&mut self.state, &block);
            offset += 64;
        }

        // 残りをバッファに保存
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        // MD5パディング: 1ビット + ゼロ + 64ビットリトルエンディアン長
        let bit_len = self.total_len * 8;
        let mut padding = [0u8; 72]; // 最大パディングサイズ
        padding[0] = 0x80;

        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        self.update(&padding[..pad_len]);

        // 長さをリトルエンディアンで追加
        let len_bytes = bit_len.to_le_bytes();
        self.update(&len_bytes);

        // 結果をリトルエンディアンで出力
        let mut result = [0u8; 16];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        result
    }
}

/// MD5圧縮関数 (RFC 1321 Section 3.4)
fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]) {
    // ブロックを16個のリトルエンディアンu32に変換
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | ((!b) & d), i),
            16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | (!d)), (7 * i) % 16),
        };

        let temp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(MD5_T[i])
                .wrapping_add(m[g])
                .rotate_left(MD5_S[i]),
        );
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// MD5ワンショット計算
pub fn md5_compute(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize()
}

// ============================================================================
// SHA-1 Implementation (FIPS 180-4)
// TLS 1.0/1.1 PRF および レガシー署名検証に必要
// ============================================================================

/// SHA-1 output size in bytes
const SHA1_OUTPUT_SIZE: usize = 20;

/// SHA-1 block size in bytes
const SHA1_BLOCK_SIZE: usize = 64;

/// SHA-1 initial hash values (FIPS 180-4 Section 5.3.1)
const SHA1_INIT: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// SHA-1ハッシュ計算 (ストリーミング対応)
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: SHA1_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        if self.buffer_len > 0 {
            let remaining = 64 - self.buffer_len;
            let copy_len = remaining.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            offset = copy_len;

            if self.buffer_len == 64 {
                let block = self.buffer;
                sha1_compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            sha1_compress(&mut self.state, &block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len * 8;
        let mut padding = [0u8; 72];
        padding[0] = 0x80;

        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        self.update(&padding[..pad_len]);

        // SHA-1はビッグエンディアンの長さ
        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);

        let mut result = [0u8; 20];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }
}

/// SHA-1圧縮関数 (FIPS 180-4 Section 6.1.2)
fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];

    // メッセージスケジュール: W[0..15] はブロックから直接
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    // W[16..79] = (W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16]) <<< 1
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdcu32),
            _ => (b ^ c ^ d, 0xca62c1d6u32),
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// SHA-1ワンショット計算
pub fn sha1_compute(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

// ============================================================================
// HMAC-MD5 / HMAC-SHA1 (RFC 2104)
// TLS 1.0/1.1 PRF および CBC MAC に必要
// ============================================================================

/// HMAC-MD5 (RFC 2104)
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; MD5_OUTPUT_SIZE] {
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > MD5_BLOCK_SIZE {
        hashed_key = md5_compute(key);
        &hashed_key
    } else {
        key
    };

    let mut ipad = [0x36u8; MD5_BLOCK_SIZE];
    let mut opad = [0x5cu8; MD5_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    let mut inner = Md5::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Md5::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// HMAC-SHA1 (RFC 2104)
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_OUTPUT_SIZE] {
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > SHA1_BLOCK_SIZE {
        hashed_key = sha1_compute(key);
        &hashed_key
    } else {
        key
    };

    let mut ipad = [0x36u8; SHA1_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA1_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ============================================================================
// TLS 1.0/1.1 PRF (RFC 2246 Section 5, RFC 4346 Section 5)
// デュアルハッシュ方式: P_MD5 XOR P_SHA-1
// ============================================================================

/// P_MD5 expansion
fn p_md5(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_md5(secret, seed); // A(1)
    let mut offset = 0;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while offset < output.len() {
        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let block = hmac_md5(secret, &a_seed);
        let copy_len = (output.len() - offset).min(MD5_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;

        a = hmac_md5(secret, &a);
    }
}

/// P_SHA1 expansion
fn p_sha1(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_sha1(secret, seed); // A(1)
    let mut offset = 0;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while offset < output.len() {
        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let block = hmac_sha1(secret, &a_seed);
        let copy_len = (output.len() - offset).min(SHA1_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;

        a = hmac_sha1(secret, &a);
    }
}

/// TLS 1.0/1.1 PRF (RFC 2246 Section 5)
///
/// PRF(secret, label, seed) = P_MD5(S1, label+seed) XOR P_SHA-1(S2, label+seed)
/// S1 = secret[..L_S], S2 = secret[L_S..]
/// L_S = ceil(secret.len() / 2)
pub fn tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    // secret を前半・後半に分割 (奇数長は中央バイト共有)
    let half = (secret.len() + 1) / 2;
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];

    let mut md5_output = vec![0u8; output.len()];
    let mut sha1_output = vec![0u8; output.len()];

    p_md5(s1, &combined_seed, &mut md5_output);
    p_sha1(s2, &combined_seed, &mut sha1_output);

    // XOR して最終結果
    for i in 0..output.len() {
        output[i] = md5_output[i] ^ sha1_output[i];
    }
}

// ============================================================================
// TLS MAC computation (RFC 5246 Section 6.2.3.1)
// CBC暗号スイートのMAC-then-Encrypt用
// ============================================================================

/// TLS MAC計算
///
/// MAC = HMAC(mac_key, seq_num(8) || type(1) || version(2) || length(2) || fragment)
pub(crate) fn compute_tls_mac(
    mac_key: &[u8],
    seq_num: u64,
    content_type: u8,
    version: TlsVersion,
    fragment: &[u8],
    use_sha1: bool,
) -> Vec<u8> {
    let mut mac_input = Vec::with_capacity(13 + fragment.len());
    mac_input.extend_from_slice(&seq_num.to_be_bytes());
    mac_input.push(content_type);
    let ver_bytes = version.to_bytes();
    mac_input.push(ver_bytes[0]);
    mac_input.push(ver_bytes[1]);
    mac_input.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(fragment);

    if use_sha1 {
        hmac_sha1(mac_key, &mac_input).to_vec()
    } else {
        hmac_sha256(mac_key, &mac_input).to_vec()
    }
}
