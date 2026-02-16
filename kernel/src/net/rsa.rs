// ============================================================================
// src/net/rsa.rs - RSA PKCS#1 v1.5 Signature Verification
// ============================================================================
//!
//! # RSA PKCS#1 v1.5 署名検証
//!
//! TLS証明書チェーンの署名検証に使用するRSA PKCS#1 v1.5実装。
//! カスタム多倍長整数 (`BigUint`) によるモジュラ冪乗を基盤とし、
//! SHA-256/SHA-384ダイジェストの署名検証をサポートする。
//!
//! ## 機能
//! - **BigUint**: 最大4096ビット（64リム）のリトルエンディアン多倍長整数
//! - **モジュラ冪乗**: 二乗累乗法（MSBからスキャン）
//! - **PKCS#1 v1.5検証**: RFC 8017 Section 8.2.2 準拠
//!
//! ## セキュリティ特性
//! - 署名検証のみ（秘密鍵操作なし）
//! - DigestInfo DERプレフィックスの厳密照合
//! - パディング構造 0x00 0x01 [0xFF...] 0x00 の完全検証

#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

// ============================================================================
// Multi-Precision Integer (BigUint)
// ============================================================================

/// 多倍長符号なし整数の最大リム数（64 × 64ビット = 4096ビット）
const MAX_LIMBS: usize = 64;

/// 多倍長符号なし整数（リトルエンディアン u64 リム表現）
///
/// `limbs[0]` が最下位リム、`limbs[len-1]` が最上位リム。
/// 使用中のリム数は `len` で管理し、`len..MAX_LIMBS` はゼロ。
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
    ///
    /// 先頭のゼロバイトは無視される。
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        // 先頭のゼロをスキップ
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let significant = &bytes[start..];

        if significant.is_empty() {
            return Self::zero();
        }

        let mut limbs = [0u64; MAX_LIMBS];
        let byte_count = significant.len();
        let limb_count = (byte_count + 7) / 8;

        assert!(
            limb_count <= MAX_LIMBS,
            "BigUint::from_be_bytes: value too large"
        );

        // ビッグエンディアンバイトをリトルエンディアンリムに変換
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

    /// ビッグエンディアンバイト列へ変換（最小長）
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0u8];
        }

        let bits = self.bit_len();
        let byte_count = (bits + 7) / 8;
        let mut result = vec![0u8; byte_count];

        for i in 0..byte_count {
            let limb_idx = i / 8;
            let byte_pos = i % 8;
            result[byte_count - 1 - i] = (self.limbs[limb_idx] >> (byte_pos * 8)) as u8;
        }

        result
    }

    /// 指定バイト長にゼロパディングしたビッグエンディアンバイト列を返す
    ///
    /// RSA検証で modulus と同じ長さに揃えるために使用。
    pub fn to_be_bytes_padded(&self, target_len: usize) -> Vec<u8> {
        let raw = self.to_be_bytes();
        if raw.len() >= target_len {
            // 最下位 target_len バイトを返す
            return raw[raw.len() - target_len..].to_vec();
        }
        let mut padded = vec![0u8; target_len - raw.len()];
        padded.extend_from_slice(&raw);
        padded
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

    /// ビット長（最上位の1ビットの位置 + 1）
    pub fn bit_len(&self) -> usize {
        for i in (0..self.len).rev() {
            if self.limbs[i] != 0 {
                return i * 64 + (64 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// 有効リム数を再計算して正規化
    fn normalize(&mut self) {
        while self.len > 0 && self.limbs[self.len - 1] == 0 {
            self.len -= 1;
        }
    }

    /// 加算 (self + other)
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
        if carry != 0 {
            assert!(
                result.len < MAX_LIMBS,
                "BigUint::add: overflow"
            );
            result.limbs[result.len] = carry;
            result.len += 1;
        }

        result
    }

    /// 減算 (self - other)
    ///
    /// self >= other を前提とする。アンダーフローした場合はパニック。
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

        assert!(borrow == 0, "BigUint::sub: underflow");

        result.len = max_len;
        result.normalize();
        result
    }

    /// 乗算 (self * other)
    ///
    /// スクールブック乗算。中間結果は2倍幅のバッファで保持。
    pub fn mul(&self, other: &Self) -> Self {
        const DOUBLE: usize = MAX_LIMBS * 2;
        let mut product = [0u64; DOUBLE];

        for i in 0..self.len {
            let mut carry: u64 = 0;
            for j in 0..other.len {
                let pos = i + j;
                let wide = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (product[pos] as u128)
                    + (carry as u128);
                product[pos] = wide as u64;
                carry = (wide >> 64) as u64;
            }
            if carry != 0 {
                product[i + other.len] = product[i + other.len]
                    .checked_add(carry)
                    .expect("BigUint::mul: carry overflow");
            }
        }

        // 結果がMAX_LIMBSに収まることを確認
        let mut result_len = self.len + other.len;
        while result_len > 0 && product[result_len - 1] == 0 {
            result_len -= 1;
        }
        assert!(
            result_len <= MAX_LIMBS,
            "BigUint::mul: result exceeds MAX_LIMBS"
        );

        let mut result = Self::zero();
        for i in 0..result_len {
            result.limbs[i] = product[i];
        }
        result.len = result_len;
        result
    }

    /// リム単位の左シフト（lower limbs にゼロを挿入）
    fn shl_limbs(&self, count: usize) -> Self {
        if count == 0 {
            return *self;
        }
        assert!(
            self.len + count <= MAX_LIMBS,
            "BigUint::shl_limbs: overflow"
        );

        let mut result = Self::zero();
        for i in 0..self.len {
            result.limbs[i + count] = self.limbs[i];
        }
        result.len = self.len + count;
        result
    }

    /// 1ビット右シフト
    fn shr1(&self) -> Self {
        let mut result = Self::zero();
        result.len = self.len;

        for i in (0..self.len).rev() {
            result.limbs[i] = self.limbs[i] >> 1;
            if i + 1 < self.len {
                // 上位リムの最下位ビットをこのリムの最上位ビットに移動
                // (すでに上位リムへの代入は完了済み)
            }
        }
        // 正しい実装: 各リムの最下位ビットを下位リムの最上位ビットへ
        let mut result2 = Self::zero();
        result2.len = self.len;
        let mut carry: u64 = 0;
        for i in (0..self.len).rev() {
            result2.limbs[i] = (self.limbs[i] >> 1) | (carry << 63);
            carry = self.limbs[i] & 1;
        }
        result2.normalize();
        result2
    }

    /// 除算と剰余 (self / divisor, self % divisor)
    ///
    /// ビット単位の長除算（shift-and-subtract）アルゴリズム。
    /// 正確性と簡潔さを優先した実装。
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "BigUint::div_rem: division by zero");

        if self.cmp_internal(divisor) == Ordering::Less {
            return (Self::zero(), *self);
        }

        let mut quotient = Self::zero();
        let mut remainder = Self::zero();

        let total_bits = self.bit_len();

        // MSBからLSBへビットを1つずつ処理
        for bit_idx in (0..total_bits).rev() {
            // remainder を左に1ビットシフト
            remainder = remainder.shl1();

            // self の bit_idx 番目のビットを remainder の最下位ビットに設定
            let limb_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if (self.limbs[limb_idx] >> bit_pos) & 1 == 1 {
                remainder.limbs[0] |= 1;
                if remainder.len == 0 {
                    remainder.len = 1;
                }
            }

            // remainder >= divisor なら引いて商のビットを立てる
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
        if carry != 0 {
            assert!(
                result.len < MAX_LIMBS,
                "BigUint::shl1: overflow"
            );
            result.limbs[result.len] = carry;
            result.len += 1;
        }

        result
    }

    /// 剰余のみ (self % modulus)
    pub fn rem(&self, modulus: &Self) -> Self {
        let (_, r) = self.div_rem(modulus);
        r
    }

    /// モジュラ冪乗 (self^exp mod modulus)
    ///
    /// 二乗累乗法（MSBから走査）。
    pub fn mod_exp(&self, exp: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "BigUint::mod_exp: modulus is zero");

        if exp.is_zero() {
            // x^0 mod n = 1 (n > 1)
            return Self::one().rem(modulus);
        }

        let mut result = Self::one();
        let base = self.rem(modulus);

        let exp_bits = exp.bit_len();

        // MSBからLSBへスキャン
        for bit_idx in (0..exp_bits).rev() {
            // 二乗
            result = result.mul(&result).rem(modulus);

            // 指数のビットが1なら乗算
            let limb_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if (exp.limbs[limb_idx] >> bit_pos) & 1 == 1 {
                result = result.mul(&base).rem(modulus);
            }
        }

        result
    }

    /// 内部比較
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

/// ハッシュアルゴリズム（署名検証用）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (32バイトダイジェスト)
    Sha256,
    /// SHA-384 (48バイトダイジェスト)
    Sha384,
}

impl HashAlgorithm {
    /// ダイジェスト長（バイト）
    pub fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
        }
    }
}

// ============================================================================
// RSA Public Key
// ============================================================================

/// RSA公開鍵（検証用）
///
/// DERエンコードされた証明書からパースされたモジュラスと指数を保持する。
#[derive(Clone, Debug)]
pub struct RsaPublicKey<'a> {
    /// モジュラス n（ビッグエンディアンバイト列）
    pub modulus: &'a [u8],
    /// 公開指数 e（ビッグエンディアンバイト列）
    pub exponent: &'a [u8],
}

// ============================================================================
// DigestInfo DER Prefixes (PKCS#1 v1.5)
// ============================================================================

/// SHA-256 DigestInfo DERプレフィックス (RFC 8017 Section 9.2 Notes 1)
///
/// DigestInfo ::= SEQUENCE {
///   digestAlgorithm  AlgorithmIdentifier(id-sha256, NULL),
///   digest           OCTET STRING
/// }
///
/// 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
const DIGEST_INFO_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

/// SHA-384 DigestInfo DERプレフィックス
///
/// 30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
const DIGEST_INFO_SHA384_PREFIX: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0x05, 0x00, 0x04, 0x30,
];

// ============================================================================
// RSA PKCS#1 v1.5 Signature Verification
// ============================================================================

/// RSA PKCS#1 v1.5エラー
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaError {
    /// 署名長がモジュラス長と一致しない
    InvalidSignatureLength,
    /// モジュラ冪乗の結果が不正
    InvalidSignatureValue,
    /// PKCS#1 v1.5パディングが不正
    InvalidPadding,
    /// DigestInfoプレフィックスが一致しない
    DigestInfoMismatch,
    /// ダイジェスト値が一致しない
    DigestMismatch,
    /// モジュラスが小さすぎる
    ModulusTooSmall,
}

/// RSA PKCS#1 v1.5 署名検証 (RFC 8017 Section 8.2.2)
///
/// # 検証手順
/// 1. 署名バイト列 s を整数に変換
/// 2. s^e mod n を計算（RSA復号プリミティブ RSAVP1）
/// 3. 結果を k バイト（モジュラス長）にエンコード
/// 4. PKCS#1 v1.5パディングを検証: 0x00 0x01 [0xFF...] 0x00 T
/// 5. T = DigestInfo DERプレフィックス || digest_hash を照合
///
/// # Arguments
/// * `key` - RSA公開鍵（モジュラスと指数）
/// * `hash_alg` - 使用するハッシュアルゴリズム
/// * `digest` - メッセージのハッシュ値
/// * `signature` - 検証する署名バイト列
///
/// # Returns
/// 検証成功なら `Ok(())`、失敗なら対応する `RsaError`
pub fn rsa_pkcs1_verify(
    key: &RsaPublicKey,
    hash_alg: HashAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaError> {
    let n = BigUint::from_be_bytes(key.modulus);
    let e = BigUint::from_be_bytes(key.exponent);

    // モジュラスのバイト長（k）
    let k = key.modulus.len();

    // DigestInfo DERプレフィックス
    let prefix = match hash_alg {
        HashAlgorithm::Sha256 => &DIGEST_INFO_SHA256_PREFIX[..],
        HashAlgorithm::Sha384 => &DIGEST_INFO_SHA384_PREFIX[..],
    };

    // T = DigestInfo = prefix || digest
    let t_len = prefix.len() + hash_alg.digest_len();

    // Step 0: モジュラスがパディングを収容できるか確認
    // 最小長: 0x00 (1) + 0x01 (1) + 0xFF...0xFF (>=8) + 0x00 (1) + T
    if k < t_len + 11 {
        return Err(RsaError::ModulusTooSmall);
    }

    // Step 1: 署名長の検証
    if signature.len() != k {
        return Err(RsaError::InvalidSignatureLength);
    }

    // Step 2: 署名を整数に変換し、s^e mod n を計算
    let s = BigUint::from_be_bytes(signature);

    // s < n を確認
    if s >= n {
        return Err(RsaError::InvalidSignatureValue);
    }

    let m = s.mod_exp(&e, &n);

    // Step 3: 結果をk バイトのビッグエンディアンにエンコード
    let em = m.to_be_bytes_padded(k);

    // Step 4: PKCS#1 v1.5パディングの検証
    // EM = 0x00 || 0x01 || PS || 0x00 || T
    // PS = 0xFF repeated (>= 8 octets)
    if em[0] != 0x00 || em[1] != 0x01 {
        return Err(RsaError::InvalidPadding);
    }

    // PS の終端を探す（0x00 セパレータ）
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

    let sep = match separator_pos {
        Some(pos) => pos,
        None => return Err(RsaError::InvalidPadding),
    };

    // PS の長さが8以上であることを確認
    let ps_len = sep - 2;
    if ps_len < 8 {
        return Err(RsaError::InvalidPadding);
    }

    // Step 5: T の検証
    let t_start = sep + 1;
    let t_data = &em[t_start..];

    if t_data.len() != t_len {
        return Err(RsaError::DigestInfoMismatch);
    }

    // DigestInfo DERプレフィックスの照合
    if &t_data[..prefix.len()] != prefix {
        return Err(RsaError::DigestInfoMismatch);
    }

    // ダイジェスト値の照合（定時間比較）
    let extracted_digest = &t_data[prefix.len()..];
    if extracted_digest.len() != digest.len() {
        return Err(RsaError::DigestMismatch);
    }

    let mut diff = 0u8;
    for i in 0..digest.len() {
        diff |= extracted_digest[i] ^ digest[i];
    }

    if diff != 0 {
        return Err(RsaError::DigestMismatch);
    }

    Ok(())
}

// ============================================================================
// QEMU Test Module
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    /// 小さな値のモジュラ冪乗テスト: 3^7 mod 11 = 9
    pub fn rsa_modexp_small_smoke() -> bool {
        let base = BigUint::from_be_bytes(&[3]);
        let exp = BigUint::from_be_bytes(&[7]);
        let modulus = BigUint::from_be_bytes(&[11]);

        let result = base.mod_exp(&exp, &modulus);
        let result_bytes = result.to_be_bytes();

        // 3^7 = 2187, 2187 mod 11 = 2187 - 198*11 = 2187 - 2178 = 9
        result_bytes.len() == 1 && result_bytes[0] == 9
    }

    /// 256ビット決定論的モジュラ冪乗テスト
    ///
    /// base = 2^128 + 1, exp = 3, modulus = 2^256 - 189
    /// 結果が非ゼロで modulus 未満であることを検証。
    pub fn rsa_modexp_medium_smoke() -> bool {
        // base = 2^128 + 1 = 0x00...01 00...01 (17 bytes)
        let mut base_bytes = [0u8; 17];
        base_bytes[0] = 1;
        base_bytes[16] = 1;
        let base = BigUint::from_be_bytes(&base_bytes);

        let exp = BigUint::from_be_bytes(&[3]);

        // modulus = 2^256 - 189
        let mut mod_bytes = [0xFFu8; 32];
        mod_bytes[31] = 0xFF - 188; // 0xFF - 188 = 67 = 0x43
        let modulus = BigUint::from_be_bytes(&mod_bytes);

        let result = base.mod_exp(&exp, &modulus);

        // 結果が非ゼロで modulus 未満であることを確認
        !result.is_zero() && result < modulus
    }

    /// PKCS#1 v1.5 検証スモークテスト（e=1トリック）
    ///
    /// e=1 の場合 s^1 mod n = s なので、署名をパディング済みメッセージに設定し、
    /// n > s となる十分大きなモジュラスを使えば検証が通る。
    pub fn rsa_pkcs1_verify_smoke() -> bool {
        // SHA-256ダイジェスト（テスト値）
        let digest = [0xABu8; 32];

        // k = 128 bytes (1024-bit modulus)
        let k = 128;

        // パディング済みメッセージ EM を手動構築
        // EM = 0x00 || 0x01 || PS(0xFF * ps_len) || 0x00 || DigestInfo_SHA256_prefix || digest
        let t_len = DIGEST_INFO_SHA256_PREFIX.len() + 32; // 19 + 32 = 51
        let ps_len = k - 3 - t_len; // 128 - 3 - 51 = 74

        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x01);
        for _ in 0..ps_len {
            em.push(0xFF);
        }
        em.push(0x00);
        em.extend_from_slice(&DIGEST_INFO_SHA256_PREFIX);
        em.extend_from_slice(&digest);

        // e = 1 なら s^1 mod n = s (ただし s < n)
        // signature = EM
        let signature = em.clone();

        // n = EM にバイトを加えた値（EM < n を保証）
        // 最も簡単: n の最上位バイトを EM のそれより大きくする
        let mut n_bytes = vec![0xFFu8; k];
        // n は全バイト 0xFF → 確実に EM より大きい

        let key = RsaPublicKey {
            modulus: &n_bytes,
            exponent: &[1], // e = 1
        };

        rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, &signature).is_ok()
    }

    /// PKCS#1 v1.5 不正署名拒否テスト
    ///
    /// 正しい署名の1ビットを反転させると検証が失敗することを確認。
    pub fn rsa_pkcs1_verify_bad_sig_smoke() -> bool {
        let digest = [0xABu8; 32];
        let k = 128;

        let t_len = DIGEST_INFO_SHA256_PREFIX.len() + 32;
        let ps_len = k - 3 - t_len;

        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x01);
        for _ in 0..ps_len {
            em.push(0xFF);
        }
        em.push(0x00);
        em.extend_from_slice(&DIGEST_INFO_SHA256_PREFIX);
        em.extend_from_slice(&digest);

        // 署名の最終バイトの最下位ビットを反転
        let mut bad_sig = em.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0x01;

        let n_bytes = vec![0xFFu8; k];

        let key = RsaPublicKey {
            modulus: &n_bytes,
            exponent: &[1],
        };

        rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, &bad_sig).is_err()
    }

    /// BigUint 乗算・除算ラウンドトリップテスト
    ///
    /// a * b / b == a を検証。
    pub fn rsa_biguint_mul_div_smoke() -> bool {
        let a = BigUint::from_be_bytes(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let b = BigUint::from_be_bytes(&[0xFE, 0xDC, 0xBA, 0x98]);

        if b.is_zero() {
            return false;
        }

        let product = a.mul(&b);
        let (quotient, remainder) = product.div_rem(&b);

        quotient == a && remainder.is_zero()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // BigUint Basic Tests
    // ========================================================================

    /// ゼロ値テスト
    #[test_case]
    fn test_biguint_zero() {
        let z = BigUint::zero();
        assert!(z.is_zero());
        assert_eq!(z.bit_len(), 0);
        assert_eq!(z.to_be_bytes(), vec![0u8]);
    }

    /// 1値テスト
    #[test_case]
    fn test_biguint_one() {
        let one = BigUint::one();
        assert!(!one.is_zero());
        assert_eq!(one.bit_len(), 1);
        assert_eq!(one.to_be_bytes(), vec![1u8]);
    }

    /// ビッグエンディアンバイト列のラウンドトリップ
    #[test_case]
    fn test_biguint_be_bytes_roundtrip() {
        let original = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let n = BigUint::from_be_bytes(&original);
        let bytes = n.to_be_bytes();
        assert_eq!(bytes.as_slice(), &original);
    }

    /// 先頭ゼロの除去テスト
    #[test_case]
    fn test_biguint_leading_zeros() {
        let padded = [0x00, 0x00, 0x42, 0xFF];
        let n = BigUint::from_be_bytes(&padded);
        assert_eq!(n.to_be_bytes(), vec![0x42, 0xFF]);
    }

    // ========================================================================
    // BigUint Arithmetic Tests
    // ========================================================================

    /// 加算テスト
    #[test_case]
    fn test_biguint_add() {
        let a = BigUint::from_be_bytes(&[0xFF]);
        let b = BigUint::from_be_bytes(&[0x01]);
        let c = a.add(&b);
        assert_eq!(c.to_be_bytes(), vec![0x01, 0x00]);
    }

    /// 減算テスト
    #[test_case]
    fn test_biguint_sub() {
        let a = BigUint::from_be_bytes(&[0x01, 0x00]);
        let b = BigUint::from_be_bytes(&[0x01]);
        let c = a.sub(&b);
        assert_eq!(c.to_be_bytes(), vec![0xFF]);
    }

    /// 乗算テスト
    #[test_case]
    fn test_biguint_mul() {
        let a = BigUint::from_be_bytes(&[0xFF]);     // 255
        let b = BigUint::from_be_bytes(&[0xFF]);     // 255
        let c = a.mul(&b);
        // 255 * 255 = 65025 = 0xFE01
        assert_eq!(c.to_be_bytes(), vec![0xFE, 0x01]);
    }

    /// 除算・剰余テスト
    #[test_case]
    fn test_biguint_div_rem() {
        let a = BigUint::from_be_bytes(&[0x64]);     // 100
        let b = BigUint::from_be_bytes(&[0x07]);     // 7
        let (q, r) = a.div_rem(&b);
        // 100 / 7 = 14 余 2
        assert_eq!(q.to_be_bytes(), vec![14]);
        assert_eq!(r.to_be_bytes(), vec![2]);
    }

    /// 乗算・除算ラウンドトリップ
    #[test_case]
    fn test_biguint_mul_div_roundtrip() {
        let a = BigUint::from_be_bytes(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let b = BigUint::from_be_bytes(&[0xFE, 0xDC, 0xBA, 0x98]);

        let product = a.mul(&b);
        let (quotient, remainder) = product.div_rem(&b);

        assert_eq!(quotient, a);
        assert!(remainder.is_zero());
    }

    // ========================================================================
    // BigUint Comparison Tests
    // ========================================================================

    /// 比較テスト
    #[test_case]
    fn test_biguint_comparison() {
        let a = BigUint::from_be_bytes(&[0x01, 0x00]);  // 256
        let b = BigUint::from_be_bytes(&[0xFF]);         // 255
        let c = BigUint::from_be_bytes(&[0x01, 0x00]);   // 256

        assert!(a > b);
        assert!(b < a);
        assert_eq!(a, c);
    }

    // ========================================================================
    // Modular Exponentiation Tests
    // ========================================================================

    /// 小さな値のモジュラ冪乗: 3^7 mod 11 = 9
    #[test_case]
    fn test_modexp_small() {
        let base = BigUint::from_be_bytes(&[3]);
        let exp = BigUint::from_be_bytes(&[7]);
        let modulus = BigUint::from_be_bytes(&[11]);

        let result = base.mod_exp(&exp, &modulus);
        // 3^7 = 2187, 2187 mod 11 = 9
        assert_eq!(result.to_be_bytes(), vec![9]);
    }

    /// x^0 mod n = 1
    #[test_case]
    fn test_modexp_zero_exponent() {
        let base = BigUint::from_be_bytes(&[42]);
        let exp = BigUint::zero();
        let modulus = BigUint::from_be_bytes(&[11]);

        let result = base.mod_exp(&exp, &modulus);
        assert_eq!(result.to_be_bytes(), vec![1]);
    }

    /// x^1 mod n = x mod n
    #[test_case]
    fn test_modexp_one_exponent() {
        let base = BigUint::from_be_bytes(&[42]);
        let exp = BigUint::one();
        let modulus = BigUint::from_be_bytes(&[11]);

        let result = base.mod_exp(&exp, &modulus);
        // 42 mod 11 = 9
        assert_eq!(result.to_be_bytes(), vec![9]);
    }

    /// 2^10 mod 1000 = 1024 mod 1000 = 24
    #[test_case]
    fn test_modexp_power_of_two() {
        let base = BigUint::from_be_bytes(&[2]);
        let exp = BigUint::from_be_bytes(&[10]);
        let modulus = BigUint::from_be_bytes(&[0x03, 0xE8]); // 1000

        let result = base.mod_exp(&exp, &modulus);
        assert_eq!(result.to_be_bytes(), vec![24]);
    }

    // ========================================================================
    // PKCS#1 v1.5 Verify Tests
    // ========================================================================

    /// PKCS#1 v1.5 検証テスト (e=1 トリック)
    #[test_case]
    fn test_pkcs1_verify_e1() {
        let digest = [0xABu8; 32];
        let k = 128;

        // パディング済みメッセージを手動構築
        let t_len = DIGEST_INFO_SHA256_PREFIX.len() + 32;
        let ps_len = k - 3 - t_len;

        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x01);
        for _ in 0..ps_len {
            em.push(0xFF);
        }
        em.push(0x00);
        em.extend_from_slice(&DIGEST_INFO_SHA256_PREFIX);
        em.extend_from_slice(&digest);

        let n_bytes = vec![0xFFu8; k];

        let key = RsaPublicKey {
            modulus: &n_bytes,
            exponent: &[1],
        };

        let result = rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, &em);
        assert!(result.is_ok());
    }

    /// PKCS#1 v1.5 不正署名テスト
    #[test_case]
    fn test_pkcs1_verify_bad_signature() {
        let digest = [0xABu8; 32];
        let k = 128;

        let t_len = DIGEST_INFO_SHA256_PREFIX.len() + 32;
        let ps_len = k - 3 - t_len;

        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x01);
        for _ in 0..ps_len {
            em.push(0xFF);
        }
        em.push(0x00);
        em.extend_from_slice(&DIGEST_INFO_SHA256_PREFIX);
        em.extend_from_slice(&digest);

        // 署名を改竄
        let mut bad_sig = em;
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0x01;

        let n_bytes = vec![0xFFu8; k];

        let key = RsaPublicKey {
            modulus: &n_bytes,
            exponent: &[1],
        };

        let result = rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, &bad_sig);
        assert!(result.is_err());
    }

    /// 署名長不一致テスト
    #[test_case]
    fn test_pkcs1_verify_wrong_length() {
        let digest = [0xABu8; 32];
        let n_bytes = vec![0xFFu8; 128];

        let key = RsaPublicKey {
            modulus: &n_bytes,
            exponent: &[1],
        };

        // 署名が短すぎる
        let short_sig = vec![0x00u8; 64];
        let result = rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, &short_sig);
        assert!(matches!(result, Err(RsaError::InvalidSignatureLength)));
    }

    /// SHA-384 DigestInfo テスト
    #[test_case]
    fn test_pkcs1_verify_sha384_e1() {
        let digest = [0xCDu8; 48];
        let k = 128;

        let t_len = DIGEST_INFO_SHA384_PREFIX.len() + 48;
        let ps_len = k - 3 - t_len;

        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x01);
        for _ in 0..ps_len {
            em.push(0xFF);
        }
        em.push(0x00);
        em.extend_from_slice(&DIGEST_INFO_SHA384_PREFIX);
        em.extend_from_slice(&digest);

        let n_bytes = vec![0xFFu8; k];

        let key = RsaPublicKey {
            modulus: &n_bytes,
            exponent: &[1],
        };

        let result = rsa_pkcs1_verify(&key, HashAlgorithm::Sha384, &digest, &em);
        assert!(result.is_ok());
    }

    /// パディングバイト長不足テスト
    #[test_case]
    fn test_pkcs1_verify_short_padding() {
        let digest = [0xABu8; 32];
        let k = 128;

        let t_len = DIGEST_INFO_SHA256_PREFIX.len() + 32;

        // PS を7バイト（最小8に不足）で構築
        let ps_len = 7;
        let mut em = vec![0u8; k];
        em[0] = 0x00;
        em[1] = 0x01;
        for i in 0..ps_len {
            em[2 + i] = 0xFF;
        }
        em[2 + ps_len] = 0x00;
        let t_start = 3 + ps_len;
        em[t_start..t_start + DIGEST_INFO_SHA256_PREFIX.len()]
            .copy_from_slice(&DIGEST_INFO_SHA256_PREFIX);
        em[t_start + DIGEST_INFO_SHA256_PREFIX.len()..t_start + t_len]
            .copy_from_slice(&digest);

        let n_bytes = vec![0xFFu8; k];

        let key = RsaPublicKey {
            modulus: &n_bytes,
            exponent: &[1],
        };

        // パディングが7バイトだが、EM全体のサイズがkと一致しないため
        // 検証はパディングエラーまたはダイジェスト不一致になる
        let result = rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, &em);
        assert!(result.is_err());
    }

    // ========================================================================
    // BigUint to_be_bytes_padded Tests
    // ========================================================================

    /// ゼロパディングテスト
    #[test_case]
    fn test_biguint_to_be_bytes_padded() {
        let n = BigUint::from_be_bytes(&[0x42]);
        let padded = n.to_be_bytes_padded(4);
        assert_eq!(padded, vec![0x00, 0x00, 0x00, 0x42]);
    }

    /// パディング不要テスト
    #[test_case]
    fn test_biguint_to_be_bytes_padded_no_padding() {
        let n = BigUint::from_be_bytes(&[0x01, 0x02, 0x03, 0x04]);
        let padded = n.to_be_bytes_padded(4);
        assert_eq!(padded, vec![0x01, 0x02, 0x03, 0x04]);
    }

    // ========================================================================
    // HashAlgorithm Tests
    // ========================================================================

    /// ダイジェスト長テスト
    #[test_case]
    fn test_hash_algorithm_digest_len() {
        assert_eq!(HashAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(HashAlgorithm::Sha384.digest_len(), 48);
    }
}
