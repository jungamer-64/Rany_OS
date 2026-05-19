// ============================================================================
// kernel/src/net/security/rsa/mod.rs - RSA PKCS#1 v1.5 Signature Verification
// ============================================================================
//!
//! # RSA PKCS#1 v1.5 署名検証
//!
//! TLS証明書チェーンの署名検証に使用するRSA PKCS#1 v1.5実装。
//! カスタム多倍長整数 (`BigUint`) によるモジュラ冪乗を基盤とし、
//! SHA-256/SHA-384ダイジェストの署名検証をサポートする。
//!
//! ## 機能
//! - **BigUint**: 最大8192ビット（128リム）のリトルエンディアン多倍長整数
//! - **モジュラ冪乗**: 二乗累乗法（MSBからスキャン）
//! - **PKCS#1 v1.5検証**: RFC 8017 Section 8.2.2 準拠
//!
//! ## セキュリティ特性
//! - 署名検証のみ（秘密鍵操作なし）
//! - DigestInfo DERプレフィックスの厳密照合
//! - パディング構造 0x00 0x01 [0xFF...] 0x00 の完全検証

// Building block: RSA implementation

use core::cmp::Ordering;

// ============================================================================
// Multi-Precision Integer (BigUint)
// =====================================

/// 多倍長符号なし整数の最大リム数
///
/// 128リム × 64ビット = 8192ビット。
/// RSA-4096の演算（(n-1)*(n-1)など）を安全に処理するために十分なサイズを確保。
mod pss_verify;
pub use pss_verify::*;
const MAX_LIMBS: usize = 128;
pub const RSA_MAX_BYTES: usize = MAX_LIMBS * 8;

/// 多倍長符号なし整数（リトルエンディアン u64 リム表現）
#[derive(Clone, Copy)]
pub struct BigUint {
    limbs: [u64; MAX_LIMBS],
    len: usize,
}

impl BigUint {
    /// ゼロ値を生成
    pub fn zero() -> Self {
        Self {
            limbs: [0u64; MAX_LIMBS],
            len: 0,
        }
    }

    /// 1を生成
    pub fn one() -> Self {
        let mut limbs = [0u64; MAX_LIMBS];
        limbs[0] = 1;
        Self { limbs, len: 1 }
    }

    /// ビッグエンディアンバイト列から生成
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let significant = &bytes[start..];

        if significant.is_empty() {
            return Self::zero();
        }

        let mut limbs = [0u64; MAX_LIMBS];
        let byte_count = significant.len();
        let limb_count = (byte_count + 7) / 8;

        if limb_count > MAX_LIMBS {
            // セキュリティ: 過大な入力によるパニックを避け、ゼロを返す（またはエラーハンドリングすべきだがシグネチャ上はゼロ）
            return Self::zero();
        }

        for (i, &byte) in significant.iter().rev().enumerate() {
            let limb_idx = i / 8;
            let byte_pos = i % 8;
            limbs[limb_idx] |= (byte as u64) << (byte_pos * 8);
        }

        Self {
            limbs,
            len: limb_count,
        }
    }

    pub fn encoded_len(&self) -> usize {
        if self.is_zero() {
            1
        } else {
            self.bit_len().div_ceil(8)
        }
    }

    /// ビッグエンディアンバイト列を caller-owned buffer に書き込む
    pub fn write_be_bytes(&self, out: &mut [u8]) -> Option<usize> {
        let byte_count = self.encoded_len();
        if out.len() < byte_count {
            return None;
        }
        out[..byte_count].fill(0);
        for i in 0..byte_count {
            let limb_idx = i / 8;
            let byte_pos = i % 8;
            out[byte_count - 1 - i] = (self.limbs[limb_idx] >> (byte_pos * 8)) as u8;
        }
        Some(byte_count)
    }

    /// 指定バイト長にゼロパディングしたビッグエンディアン表現を書き込む
    pub fn write_be_bytes_padded(&self, out: &mut [u8]) {
        out.fill(0);
        for i in 0..out.len() {
            let limb_idx = i / 8;
            let byte_pos = i % 8;
            if limb_idx >= self.len {
                break;
            }
            out[out.len() - 1 - i] = (self.limbs[limb_idx] >> (byte_pos * 8)) as u8;
        }
    }

    /// ゼロ判定
    pub fn is_zero(&self) -> bool {
        for i in 0..self.len {
            if self.limbs[i] != 0 {
                return false;
            }
        }
        true
    }

    /// ビット長
    pub fn bit_len(&self) -> usize {
        for i in (0..self.len).rev() {
            if self.limbs[i] != 0 {
                return i * 64 + (64 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// 有効リム数を再計算
    fn normalize(&mut self) {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.len > 0 && self.limbs[self.len - 1] == 0 {
            self.len -= 1;
        }
    }

    /// 加算
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        let max_len = self.len.max(other.len);
        let mut carry: u64 = 0;

        for i in 0..max_len {
            let a = if i < self.len { self.limbs[i] } else { 0 };
            let b = if i < other.len { other.limbs[i] } else { 0 };
            let sum = (a as u128) + (b as u128) + (carry as u128);
            result.limbs[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }

        result.len = max_len;
        if carry != 0 && result.len < MAX_LIMBS {
            result.limbs[result.len] = carry;
            result.len += 1;
        }

        result
    }

    /// 減算 (self >= other 前提)
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        let mut borrow: u64 = 0;

        let max_len = self.len.max(other.len);
        for i in 0..max_len {
            let a = if i < self.len { self.limbs[i] } else { 0 };
            let b = if i < other.len { other.limbs[i] } else { 0 };
            let diff = (a as u128)
                .wrapping_sub(b as u128)
                .wrapping_sub(borrow as u128);
            result.limbs[i] = diff as u64;
            borrow = if diff >> 127 != 0 { 1 } else { 0 };
        }

        result.len = max_len;
        result.normalize();
        result
    }

    /// 乗算
    pub fn mul(&self, other: &Self) -> Self {
        let mut product = [0u64; MAX_LIMBS];
        let mut result_len = 0;

        for i in 0..self.len {
            if self.limbs[i] == 0 {
                continue;
            }
            let mut carry: u64 = 0;
            for j in 0..other.len {
                let pos = i + j;
                if pos >= MAX_LIMBS {
                    break;
                }
                let wide = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (product[pos] as u128)
                    + (carry as u128);
                product[pos] = wide as u64;
                carry = (wide >> 64) as u64;
                result_len = result_len.max(pos + 1);
            }
            let final_pos = i + other.len;
            if carry != 0 && final_pos < MAX_LIMBS {
                let wide = (product[final_pos] as u128) + (carry as u128);
                product[final_pos] = wide as u64;
                // wide >> 64 should be 0 since carry was u64 and product[pos] was u64
                result_len = result_len.max(final_pos + 1);
            }
        }

        let mut result = Self::zero();
        result.limbs = product;
        result.len = result_len;
        result.normalize();
        result
    }

    /// 1ビット左シフト
    fn shl1(&self) -> Self {
        let mut result = Self::zero();
        let mut carry: u64 = 0;

        for i in 0..self.len {
            let new_carry = self.limbs[i] >> 63;
            result.limbs[i] = (self.limbs[i] << 1) | carry;
            carry = new_carry;
        }

        result.len = self.len;
        if carry != 0 && result.len < MAX_LIMBS {
            result.limbs[result.len] = carry;
            result.len += 1;
        }

        result
    }

    /// 除算と剰余
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        if divisor.is_zero() {
            return (Self::zero(), Self::zero());
        }

        if self.cmp_internal(divisor) == Ordering::Less {
            return (Self::zero(), *self);
        }

        let mut quotient = Self::zero();
        let mut remainder = Self::zero();
        let total_bits = self.bit_len();

        for bit_idx in (0..total_bits).rev() {
            remainder = remainder.shl1();
            let limb_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if (self.limbs[limb_idx] >> bit_pos) & 1 == 1 {
                remainder.limbs[0] |= 1;
                if remainder.len == 0 {
                    remainder.len = 1;
                }
            }

            if remainder.cmp_internal(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                let q_limb = bit_idx / 64;
                let q_bit = bit_idx % 64;
                quotient.limbs[q_limb] |= 1u64 << q_bit;
                if q_limb >= quotient.len {
                    quotient.len = q_limb + 1;
                }
            }
        }

        quotient.normalize();
        remainder.normalize();
        (quotient, remainder)
    }

    pub fn rem(&self, modulus: &Self) -> Self {
        let (_, r) = self.div_rem(modulus);
        r
    }

    /// モジュラ冪乗
    pub fn mod_exp(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        if exp.is_zero() {
            return Self::one().rem(modulus);
        }

        let mut result = Self::one();
        let base = self.rem(modulus);
        let exp_bits = exp.bit_len();

        for bit_idx in (0..exp_bits).rev() {
            result = result.mul(&result).rem(modulus);
            let limb_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if (exp.limbs[limb_idx] >> bit_pos) & 1 == 1 {
                result = result.mul(&base).rem(modulus);
            }
        }
        result
    }

    fn cmp_internal(&self, other: &Self) -> Ordering {
        let max_len = self.len.max(other.len);
        for i in (0..max_len).rev() {
            let a = if i < self.len { self.limbs[i] } else { 0 };
            let b = if i < other.len { other.limbs[i] } else { 0 };
            match a.cmp(&b) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_internal(other) == Ordering::Equal
    }
}
impl Eq for BigUint {}
impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp_internal(other))
    }
}
impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_internal(other)
    }
}

impl core::fmt::Debug for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BigUint({} bits)", self.bit_len())
    }
}

// ============================================================================
// Hash Algorithm
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

#[derive(Debug)]
pub struct RsaPublicKey<'a> {
    pub modulus: &'a [u8],
    pub exponent: &'a [u8],
}

// DigestInfo DER Prefixes
const DIGEST_INFO_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384_PREFIX: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512_PREFIX: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaError {
    InvalidSignatureLength,
    InvalidSignatureValue,
    InvalidPadding,
    DigestInfoMismatch,
    DigestMismatch,
    ModulusTooSmall,
    EntropyUnavailable,
}

fn find_pkcs1_separator(em: &[u8]) -> Result<usize, RsaError> {
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return Err(RsaError::InvalidPadding);
    }
    let mut separator_pos = None;
    for i in 2..em.len() {
        if em[i] == 0x00 {
            separator_pos = Some(i);
            break;
        }
        if em[i] != 0xFF {
            return Err(RsaError::InvalidPadding);
        }
    }
    let sep = separator_pos.ok_or(RsaError::InvalidPadding)?;
    if sep < 10 {
        return Err(RsaError::InvalidPadding);
    } // PS must be at least 8 bytes
    Ok(sep)
}

fn verify_digest_info(
    t_data: &[u8],
    prefix: &[u8],
    digest: &[u8],
    t_len: usize,
) -> Result<(), RsaError> {
    if t_data.len() != t_len || !bytes_eq(&t_data[..prefix.len()], prefix) {
        return Err(RsaError::DigestInfoMismatch);
    }
    let extracted = &t_data[prefix.len()..];
    if extracted.len() != digest.len() {
        return Err(RsaError::DigestMismatch);
    }
    let mut diff = 0u8;
    for i in 0..digest.len() {
        diff |= extracted[i] ^ digest[i];
    }
    if diff != 0 {
        Err(RsaError::DigestMismatch)
    } else {
        Ok(())
    }
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |=
            unsafe { core::ptr::read_volatile(&a[i]) } ^ unsafe { core::ptr::read_volatile(&b[i]) };
    }
    (unsafe { core::ptr::read_volatile(&diff) }) == 0
}

pub fn rsa_pkcs1_verify(
    key: &RsaPublicKey,
    hash_alg: HashAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaError> {
    let k = key.modulus.len();
    // SECURITY: large allocation による DoS を防ぐため modulus size を制限する。
    if k > 1024 {
        return Err(RsaError::ModulusTooSmall); // Or a new error variant
    }

    let n = BigUint::from_be_bytes(key.modulus);
    let e = BigUint::from_be_bytes(key.exponent);
    let prefix = match hash_alg {
        HashAlgorithm::Sha256 => &DIGEST_INFO_SHA256_PREFIX[..],
        HashAlgorithm::Sha384 => &DIGEST_INFO_SHA384_PREFIX[..],
        HashAlgorithm::Sha512 => &DIGEST_INFO_SHA512_PREFIX[..],
    };
    let t_len = prefix.len() + hash_alg.digest_len();
    if k < t_len + 11 || signature.len() != k {
        return Err(RsaError::ModulusTooSmall);
    }
    let s = BigUint::from_be_bytes(signature);
    if s >= n {
        return Err(RsaError::InvalidSignatureValue);
    }
    let m = s.mod_exp(&e, &n);
    let mut em = [0u8; RSA_MAX_BYTES];
    let em = &mut em[..k];
    m.write_be_bytes_padded(em);
    let em = &em[..];
    let sep = find_pkcs1_separator(&em)?;
    verify_digest_info(&em[sep + 1..], prefix, digest, t_len)
}

pub fn rsa_pkcs1_encrypt_into(
    key: &RsaPublicKey,
    message: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<usize, RsaError> {
    let k = key.modulus.len();
    // SECURITY: large allocation による DoS を防ぐため modulus size を制限する。
    if k > RSA_MAX_BYTES || ciphertext_out.len() < k {
        return Err(RsaError::ModulusTooSmall);
    }

    if message.len() > k.saturating_sub(11) {
        return Err(RsaError::ModulusTooSmall);
    }
    let ps_len = k - 3 - message.len();
    let mut em = [0u8; RSA_MAX_BYTES];
    let em = &mut em[..k];
    em[0] = 0x00;
    em[1] = 0x02;
    let mut offset = 2usize;
    let mut ps_remaining = ps_len;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while ps_remaining > 0 {
        let random_bytes = crate::net::security::tls::crypto::generate_random()
            .map_err(|_| RsaError::EntropyUnavailable)?;
        for &b in &random_bytes {
            if b != 0 {
                em[offset] = b;
                offset += 1;
                ps_remaining -= 1;
                if ps_remaining == 0 {
                    break;
                }
            }
        }
    }
    em[offset] = 0x00;
    offset += 1;
    em[offset..offset + message.len()].copy_from_slice(message);
    let n = BigUint::from_be_bytes(key.modulus);
    let e = BigUint::from_be_bytes(key.exponent);
    let m = BigUint::from_be_bytes(em);
    if m >= n {
        return Err(RsaError::InvalidSignatureValue);
    }
    let c = m.mod_exp(&e, &n);
    c.write_be_bytes_padded(&mut ciphertext_out[..k]);
    Ok(k)
}

fn find_pss_padding_separator(db: &[u8]) -> Result<usize, RsaError> {
    for (i, &b) in db.iter().enumerate() {
        if b == 0x01 {
            return Ok(i + 1);
        }
        if b != 0x00 {
            return Err(RsaError::InvalidPadding);
        }
    }
    Err(RsaError::InvalidPadding)
}

fn unmask_db(
    masked_db: &[u8],
    h: &[u8],
    db_len: usize,
    hash_alg: HashAlgorithm,
    em_len: usize,
    k: usize,
) -> [u8; RSA_MAX_BYTES] {
    let mut db_mask = [0u8; RSA_MAX_BYTES];
    mgf1_into(h, &mut db_mask[..db_len], hash_alg);
    let mut db = [0u8; RSA_MAX_BYTES];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }
    let top_bits = 8 * em_len - (k * 8 - 1).min(8 * em_len);
    if top_bits < 8 && db_len != 0 {
        db[0] &= 0xFF >> top_bits;
    }
    db
}

fn constant_time_hash_eq(a: &[u8], b: &[u8]) -> Result<(), RsaError> {
    if a.len() != b.len() {
        return Err(RsaError::DigestMismatch);
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        // SECURITY: read_volatile により、この loop が early-exit comparison へ
        // 最適化されて timing side-channel を生むことを防ぐ。
        diff |=
            unsafe { core::ptr::read_volatile(&a[i]) } ^ unsafe { core::ptr::read_volatile(&b[i]) };
    }
    if unsafe { core::ptr::read_volatile(&diff) } != 0 {
        Err(RsaError::DigestMismatch)
    } else {
        Ok(())
    }
}
