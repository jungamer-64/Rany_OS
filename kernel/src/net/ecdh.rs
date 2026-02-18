// ============================================================================
// src/net/ecdh.rs - ECDH Key Exchange
// ============================================================================
//!
//! # ECDH鍵交換
//!
//! `ed25519-compact` クレートの `x25519` モジュールを活用した
//! 楕円曲線ディフィー・ヘルマン（ECDH）鍵交換実装。
//!
//! ## サポートグループ
//! - **X25519** (RFC 7748) — `ed25519-compact::x25519` によるMontgomery Ladder
//! - **secp256r1 (P-256)** (FIPS 186-4) — NIST P-256曲線によるECDH
//!
//! ## セキュリティ特性
//! - 定時間実行（タイミング攻撃耐性）
//! - 弱い鍵の自動検出・拒否
//! - 秘密データの自動ワイプ（`DHOutput::Drop`）

#![allow(dead_code)]

use alloc::vec::Vec;
use ed25519_compact::x25519::{PublicKey as X25519PublicKey, SecretKey as X25519SecretKey};

// ============================================================================
// P-256 (secp256r1) Software Implementation
// ============================================================================

/// P-256 (secp256r1) 楕円曲線の純ソフトウェア実装
///
/// FIPS 186-4準拠のNIST P-256曲線演算を提供する。
/// ヤコビアン座標によるポイント演算と、NIST高速リダクションによる
/// フィールド算術を実装している。
pub(crate) mod p384;
pub use self::p384::*;
mod p256_parsing;
pub use p256_parsing::*;

pub mod p256 {
    /// P-256素数体の元（リトルエンディアン4×u64リム表現）
    ///
    /// p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct P256FieldElement {
        pub limbs: [u64; 4],
    }

    // p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    const P: [u64; 4] = [
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ];

    // a = p - 3
    const A_LIMBS: [u64; 4] = [
        0xFFFFFFFFFFFFFFFC,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ];

    // b = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    const B_LIMBS: [u64; 4] = [
        0x3BCE3C3E27D2604B,
        0x651D06B0CC53B0F6,
        0xB3EBBD55769886BC,
        0x5AC635D8AA3A93E7,
    ];

    // Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    const GX_LIMBS: [u64; 4] = [
        0xF4A13945D898C296,
        0x77037D812DEB33A0,
        0xF8BCE6E563A440F2,
        0x6B17D1F2E12C4247,
    ];

    // Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    const GY_LIMBS: [u64; 4] = [
        0xCBB6406837BF51F5,
        0x2BCE33576B315ECE,
        0x8EE7EB4A7C0F9E16,
        0x4FE342E2FE1A7F9B,
    ];

    // n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    pub const N: [u64; 4] = [
        0xF3B9CAC2FC632551,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
    ];

    impl P256FieldElement {
        /// ゼロ元
        pub const ZERO: Self = Self { limbs: [0; 4] };

        /// 単位元（1）
        pub const ONE: Self = Self {
            limbs: [1, 0, 0, 0],
        };

        /// 定数リムから生成
        pub const fn from_limbs(limbs: [u64; 4]) -> Self {
            Self { limbs }
        }

        /// ゼロ判定
        pub fn is_zero(&self) -> bool {
            self.limbs[0] == 0 && self.limbs[1] == 0 && self.limbs[2] == 0 && self.limbs[3] == 0
        }

        /// フィールド加算 (mod p)
        ///
        /// リムごとの加算にキャリー伝播を適用し、結果がp以上の場合は
        /// pを条件付き減算して正規化する。
        pub fn add(&self, other: &Self) -> Self {
            let mut result = [0u64; 4];
            let mut carry: u64 = 0;

            for i in 0..4 {
                let sum = (self.limbs[i] as u128) + (other.limbs[i] as u128) + (carry as u128);
                result[i] = sum as u64;
                carry = (sum >> 64) as u64;
            }

            // 条件付きpの減算（結果がp以上の場合）
            let mut borrow: u64 = 0;
            let mut sub = [0u64; 4];
            for i in 0..4 {
                let diff = (result[i] as u128)
                    .wrapping_sub(P[i] as u128)
                    .wrapping_sub(borrow as u128);
                sub[i] = diff as u64;
                borrow = if diff >> 127 != 0 { 1 } else { 0 };
            }
            // carry > 0ならオーバーフローしたのでsub使用、borrow == 0なら >= pなのでsub使用
            let use_sub = carry > 0 || borrow == 0;
            if use_sub {
                Self { limbs: sub }
            } else {
                Self { limbs: result }
            }
        }

        /// フィールド減算 (mod p)
        ///
        /// リムごとの減算にボロー伝播を適用し、アンダーフローが発生した場合は
        /// pを条件付き加算して正規化する。
        pub fn sub(&self, other: &Self) -> Self {
            let mut result = [0u64; 4];
            let mut borrow: u64 = 0;

            for i in 0..4 {
                let diff = (self.limbs[i] as u128)
                    .wrapping_sub(other.limbs[i] as u128)
                    .wrapping_sub(borrow as u128);
                result[i] = diff as u64;
                borrow = if diff >> 127 != 0 { 1 } else { 0 };
            }

            // アンダーフローした場合はpを加算
            if borrow != 0 {
                let mut carry: u64 = 0;
                for i in 0..4 {
                    let sum = (result[i] as u128) + (P[i] as u128) + (carry as u128);
                    result[i] = sum as u64;
                    carry = (sum >> 64) as u64;
                }
            }

            Self { limbs: result }
        }

        /// フィールド乗算 (mod p)
        ///
        /// スクールブック4x4乗算でu128中間値を使い512ビット積を生成後、
        /// FIPS 186-4 Section D.2.3のNIST高速リダクションで縮約する。
        pub fn mul(&self, other: &Self) -> Self {
            // スクールブック乗算 → 8リムの積
            let mut product = [0u64; 8];
            for i in 0..4 {
                let mut carry: u64 = 0;
                for j in 0..4 {
                    let wide =
                        (self.limbs[i] as u128) * (other.limbs[j] as u128)
                        + (product[i + j] as u128)
                        + (carry as u128);
                    product[i + j] = wide as u64;
                    carry = (wide >> 64) as u64;
                }
                product[i + 4] = carry;
            }

            // NIST P-256高速リダクション (FIPS 186-4 D.2.3)
            nist_p256_reduce(&product)
        }

        /// フィールド二乗 (mod p)
        pub fn square(&self) -> Self {
            self.mul(self)
        }

        /// フィールド逆元 (mod p)
        ///
        /// フェルマーの小定理によるa^(p-2)を二乗と乗算の繰り返しで計算する。
        /// p-2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
        pub fn inv(&self) -> Self {
            // p - 2 をビット列として扱い、square-and-multiply
            // p - 2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
            let p_minus_2: [u64; 4] = [
                0xFFFFFFFFFFFFFFFD,
                0x00000000FFFFFFFF,
                0x0000000000000000,
                0xFFFFFFFF00000001,
            ];

            let mut result = Self::ONE;
            let mut base = *self;

            for i in 0..4 {
                let mut word = p_minus_2[i];
                for _ in 0..64 {
                    if word & 1 == 1 {
                        result = result.mul(&base);
                    }
                    base = base.square();
                    word >>= 1;
                }
            }

            result
        }

        /// ビッグエンディアン32バイトからフィールド要素を生成
        pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
            let mut limbs = [0u64; 4];
            // bytes[0..8] → 最上位リム (limbs[3])
            // bytes[8..16] → limbs[2]
            // bytes[16..24] → limbs[1]
            // bytes[24..32] → 最下位リム (limbs[0])
            for i in 0..4 {
                let offset = (3 - i) * 8;
                limbs[i] = u64::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ]);
            }
            Self { limbs }
        }

        /// ビッグエンディアン32バイトへエンコード
        pub fn to_be_bytes(&self) -> [u8; 32] {
            let mut out = [0u8; 32];
            for i in 0..4 {
                let offset = (3 - i) * 8;
                let bytes = self.limbs[i].to_be_bytes();
                out[offset..offset + 8].copy_from_slice(&bytes);
            }
            out
        }
    }

    /// i64アキュムレータから4個のu64リムへ変換（キャリー伝搬付き）
    fn carry_propagate_to_limbs(acc: &mut [i64; 8]) -> (P256FieldElement, i64) {
        let mut carry: i64 = 0;
        let mut words = [0u32; 8];
        for i in 0..8 {
            acc[i] += carry;
            carry = acc[i] >> 32;
            words[i] = (acc[i] & 0xFFFFFFFF) as u32;
        }

        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = (words[2 * i] as u64) | ((words[2 * i + 1] as u64) << 32);
        }

        (P256FieldElement { limbs }, carry)
    }

    /// キャリーと最終正規化を適用して result mod p を返す
    fn normalize_mod_p(mut result: P256FieldElement, carry: i64) -> P256FieldElement {
        if carry > 0 {
            for _ in 0..carry {
                result = result.sub(&P256FieldElement { limbs: P });
            }
        } else if carry < 0 {
            for _ in 0..(-carry) {
                result = result.add(&P256FieldElement { limbs: P });
            }
        }

        let mut borrow: u64 = 0;
        let mut sub = [0u64; 4];
        for i in 0..4 {
            let diff = (result.limbs[i] as u128)
                .wrapping_sub(P[i] as u128)
                .wrapping_sub(borrow as u128);
            sub[i] = diff as u64;
            borrow = if diff >> 127 != 0 { 1 } else { 0 };
        }
        if borrow == 0 {
            result = P256FieldElement { limbs: sub };
        }

        result
    }

    /// NIST P-256高速リダクション (FIPS 186-4 Section D.2.3)
    ///
    /// 512ビット積を16個のu32ワードに分解し、NISTの公式に従って
    /// s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9 (mod p) を計算する。
    fn nist_p256_reduce(product: &[u64; 8]) -> P256FieldElement {
        // 512ビット積を16個のu32ワード（リトルエンディアン）に分解
        let mut c = [0u32; 16];
        for i in 0..8 {
            c[2 * i] = product[i] as u32;
            c[2 * i + 1] = (product[i] >> 32) as u32;
        }

        // i64アキュムレータで各位置を計算
        // 結果は8個のu32ワード（256ビット）
        let mut acc = [0i64; 8];

        // s1 = [c0, c1, c2, c3, c4, c5, c6, c7]
        for i in 0..8 {
            acc[i] += c[i] as i64;
        }

        // s2 = [0, 0, 0, c11, c12, c13, c14, c15] (加算2回)
        acc[3] += 2 * (c[11] as i64);
        acc[4] += 2 * (c[12] as i64);
        acc[5] += 2 * (c[13] as i64);
        acc[6] += 2 * (c[14] as i64);
        acc[7] += 2 * (c[15] as i64);

        // s3 = [0, 0, 0, c12, c13, c14, c15, 0] (加算2回)
        acc[3] += 2 * (c[12] as i64);
        acc[4] += 2 * (c[13] as i64);
        acc[5] += 2 * (c[14] as i64);
        acc[6] += 2 * (c[15] as i64);

        // s4 = [c8, c9, c10, 0, 0, 0, c14, c15]
        acc[0] += c[8] as i64;
        acc[1] += c[9] as i64;
        acc[2] += c[10] as i64;
        acc[6] += c[14] as i64;
        acc[7] += c[15] as i64;

        // s5 = [c9, c10, c11, c13, c14, c15, c13, c8]
        acc[0] += c[9] as i64;
        acc[1] += c[10] as i64;
        acc[2] += c[11] as i64;
        acc[3] += c[13] as i64;
        acc[4] += c[14] as i64;
        acc[5] += c[15] as i64;
        acc[6] += c[13] as i64;
        acc[7] += c[8] as i64;

        // s6 = [c11, c12, c13, 0, 0, 0, c8, c10] (減算)
        acc[0] -= c[11] as i64;
        acc[1] -= c[12] as i64;
        acc[2] -= c[13] as i64;
        acc[6] -= c[8] as i64;
        acc[7] -= c[10] as i64;

        // s7 = [c12, c13, c14, c15, 0, 0, c9, c11] (減算)
        acc[0] -= c[12] as i64;
        acc[1] -= c[13] as i64;
        acc[2] -= c[14] as i64;
        acc[3] -= c[15] as i64;
        acc[6] -= c[9] as i64;
        acc[7] -= c[11] as i64;

        // s8 = [c13, c14, c15, c8, c9, c10, 0, c12] (減算)
        acc[0] -= c[13] as i64;
        acc[1] -= c[14] as i64;
        acc[2] -= c[15] as i64;
        acc[3] -= c[8] as i64;
        acc[4] -= c[9] as i64;
        acc[5] -= c[10] as i64;
        acc[7] -= c[12] as i64;

        // s9 = [c14, c15, 0, c9, c10, c11, 0, c13] (減算)
        acc[0] -= c[14] as i64;
        acc[1] -= c[15] as i64;
        acc[3] -= c[9] as i64;
        acc[4] -= c[10] as i64;
        acc[5] -= c[11] as i64;
        acc[7] -= c[13] as i64;

        // キャリー伝播と4個のu64リムへ変換
        let (result, carry) = carry_propagate_to_limbs(&mut acc);

        // 残りのキャリーとpによる正規化
        normalize_mod_p(result, carry)
    }

    // ========================================================================
    // P-256 ポイント演算（ヤコビアン座標）
    // ========================================================================

    /// P-256曲線上の点（ヤコビアン座標）
    ///
    /// アフィン座標 (x, y) は (X/Z^2, Y/Z^3) として表現される。
    /// 無限遠点（単位元）は Z = 0 で表す。
    #[derive(Clone, Copy, Debug)]
    pub struct P256Point {
        pub x: P256FieldElement,
        pub y: P256FieldElement,
        pub z: P256FieldElement,
    }

    impl P256Point {
        /// 無限遠点（単位元）
        pub fn identity() -> Self {
            Self {
                x: P256FieldElement::ONE,
                y: P256FieldElement::ONE,
                z: P256FieldElement::ZERO,
            }
        }

        /// ベースポイント（生成元）G
        pub fn generator() -> Self {
            Self {
                x: P256FieldElement::from_limbs(GX_LIMBS),
                y: P256FieldElement::from_limbs(GY_LIMBS),
                z: P256FieldElement::ONE,
            }
        }

        /// アフィン座標から生成
        pub fn from_affine(x: P256FieldElement, y: P256FieldElement) -> Self {
            Self {
                x,
                y,
                z: P256FieldElement::ONE,
            }
        }

        /// 無限遠点かどうか判定
        pub fn is_identity(&self) -> bool {
            self.z.is_zero()
        }

        /// アフィン座標 (x, y) を取得
        ///
        /// Z座標の逆元を計算し、X/Z^2とY/Z^3を返す。
        /// 無限遠点の場合はNoneを返す。
        pub fn to_affine(&self) -> Option<(P256FieldElement, P256FieldElement)> {
            if self.is_identity() {
                return None;
            }

            let z_inv = self.z.inv();
            let z_inv2 = z_inv.square();
            let z_inv3 = z_inv2.mul(&z_inv);

            let ax = self.x.mul(&z_inv2);
            let ay = self.y.mul(&z_inv3);

            Some((ax, ay))
        }

        /// 点の2倍算（ヤコビアン座標）
        ///
        /// a = p - 3のショートカットを使用:
        /// M = 3*(X + Z^2)*(X - Z^2) （3X^2 + aZ^4の代わりに）
        pub fn double(&self) -> Self {
            if self.is_identity() {
                return Self::identity();
            }

            let y_is_zero = self.y.is_zero();
            if y_is_zero {
                return Self::identity();
            }

            // a = p - 3 ショートカット: M = 3(X + Z²)(X - Z²)
            let z2 = self.z.square();
            let xpz2 = self.x.add(&z2);
            let xmz2 = self.x.sub(&z2);
            let m = xpz2.mul(&xmz2);
            // M = 3 * m
            let m = m.add(&m).add(&m);

            // S = 4 * X * Y²
            let y2 = self.y.square();
            let s = self.x.mul(&y2);
            let s = s.add(&s).add(&s).add(&s); // 4 * X * Y²

            // X' = M² - 2*S
            let m2 = m.square();
            let s2 = s.add(&s);
            let x3 = m2.sub(&s2);

            // Y' = M * (S - X') - 8*Y⁴
            let y4 = y2.square();
            let y4_8 = y4.add(&y4).add(&y4).add(&y4);
            let y4_8 = y4_8.add(&y4_8); // 8*Y⁴
            let y3 = m.mul(&s.sub(&x3)).sub(&y4_8);

            // Z' = 2*Y*Z
            let z3 = self.y.mul(&self.z);
            let z3 = z3.add(&z3);

            Self {
                x: x3,
                y: y3,
                z: z3,
            }
        }

        /// 点の加算（ヤコビアン座標）
        ///
        /// 標準的なヤコビアン加算を無限遠点の検査付きで実装する。
        pub fn add(&self, other: &Self) -> Self {
            if self.is_identity() {
                return *other;
            }
            if other.is_identity() {
                return *self;
            }

            let z1z1 = self.z.square();
            let z2z2 = other.z.square();

            let u1 = self.x.mul(&z2z2);
            let u2 = other.x.mul(&z1z1);

            let s1 = self.y.mul(&z2z2).mul(&other.z);
            let s2 = other.y.mul(&z1z1).mul(&self.z);

            let h = u2.sub(&u1);
            let r = s2.sub(&s1);

            // U1 == U2 の場合
            if h.is_zero() {
                if r.is_zero() {
                    // 同じ点 → 2倍算
                    return self.double();
                } else {
                    // 逆元 → 無限遠点
                    return Self::identity();
                }
            }

            let h2 = h.square();
            let h3 = h2.mul(&h);

            let u1h2 = u1.mul(&h2);

            // X3 = R² - H³ - 2*U1*H²
            let x3 = r.square().sub(&h3).sub(&u1h2.add(&u1h2));

            // Y3 = R*(U1*H² - X3) - S1*H³
            let y3 = r.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h3));

            // Z3 = H*Z1*Z2
            let z3 = h.mul(&self.z).mul(&other.z);

            Self {
                x: x3,
                y: y3,
                z: z3,
            }
        }

        /// スカラー倍算 [k]P
        ///
        /// 左からのdouble-and-addアルゴリズム。
        /// MSBからLSBに向かって各ビットを処理する。
        pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {
            let mut result = Self::identity();
            let mut found_one = false;

            // ビッグエンディアンバイト列のMSBから処理
            for &byte in scalar.iter() {
                for bit_pos in (0..8).rev() {
                    if found_one {
                        result = result.double();
                    }
                    if (byte >> bit_pos) & 1 == 1 {
                        found_one = true;
                        result = result.add(self);
                    }
                }
            }

            result
        }

        /// 曲線上の点かどうか検証
        ///
        /// y² = x³ + ax + b (mod p) を満たすか確認する。
        /// アフィン座標に変換後に検証を行う。
        pub fn is_on_curve(&self) -> bool {
            if self.is_identity() {
                return true;
            }

            let Some((x, y)) = self.to_affine() else {
                return false;
            };

            let a = P256FieldElement::from_limbs(A_LIMBS);
            let b = P256FieldElement::from_limbs(B_LIMBS);

            // y² = x³ + ax + b
            let y2 = y.square();
            let x3 = x.square().mul(&x);
            let ax = a.mul(&x);
            let rhs = x3.add(&ax).add(&b);

            y2 == rhs
        }
    }

    // p256_parsing モジュールの公開関数を p256 名前空間から再エクスポート
    pub use crate::net::ecdh::ecdsa_p256_verify;
    pub use crate::net::ecdh::parse_uncompressed_point;
    pub use crate::net::ecdh::encode_uncompressed_point;
    pub use crate::net::ecdh::EcdsaError;
    pub use crate::net::ecdh::scalar_is_valid;
    pub use crate::net::ecdh::scalar_base_mul;
    pub use crate::net::ecdh::scalar_mul_mod_n;
    pub use crate::net::ecdh::scalar_inv_mod_n;
}
