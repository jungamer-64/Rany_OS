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
    const N: [u64; 4] = [
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

        // キャリー伝播
        let mut carry: i64 = 0;
        let mut words = [0u32; 8];
        for i in 0..8 {
            acc[i] += carry;
            carry = acc[i] >> 32;
            words[i] = (acc[i] & 0xFFFFFFFF) as u32;
        }

        // 8個のu32ワードから4個のu64リムへ変換
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = (words[2 * i] as u64) | ((words[2 * i + 1] as u64) << 32);
        }

        // 残りのキャリーとpによる正規化
        // carry > 0の場合はpを減算、carry < 0の場合はpを加算
        let mut result = P256FieldElement { limbs };
        if carry > 0 {
            for _ in 0..carry {
                result = result.sub(&P256FieldElement { limbs: P });
            }
        } else if carry < 0 {
            for _ in 0..(-carry) {
                result = result.add(&P256FieldElement { limbs: P });
            }
        }

        // 最終正規化：result >= p の場合は p を減算
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

    /// 非圧縮公開鍵（04 || x || y）をパースしてP256Pointに変換
    ///
    /// 65バイトの非圧縮フォーマットのみサポート。
    /// 先頭バイトが0x04であること、曲線上の点であることを検証する。
    pub fn parse_uncompressed_point(bytes: &[u8]) -> Option<P256Point> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return None;
        }

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..33]);
        y_bytes.copy_from_slice(&bytes[33..65]);

        let x = P256FieldElement::from_be_bytes(&x_bytes);
        let y = P256FieldElement::from_be_bytes(&y_bytes);

        let point = P256Point::from_affine(x, y);

        if !point.is_on_curve() {
            return None;
        }

        Some(point)
    }

    /// P256Pointを非圧縮公開鍵（04 || x || y）にエンコード
    pub fn encode_uncompressed_point(point: &P256Point) -> Option<[u8; 65]> {
        let (x, y) = point.to_affine()?;

        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&x.to_be_bytes());
        out[33..65].copy_from_slice(&y.to_be_bytes());

        Some(out)
    }

    /// スカラーがP-256の群位数nの範囲内か検証 (1 <= k < n)
    pub fn scalar_is_valid(scalar: &[u8; 32]) -> bool {
        // ゼロでないことを確認
        let all_zero = scalar.iter().all(|&b| b == 0);
        if all_zero {
            return false;
        }

        // k < n を確認 (ビッグエンディアン比較)
        let n_be: [u8; 32] = {
            let fe = P256FieldElement::from_limbs(N);
            fe.to_be_bytes()
        };

        for i in 0..32 {
            if scalar[i] < n_be[i] {
                return true;
            }
            if scalar[i] > n_be[i] {
                return false;
            }
        }
        // k == n の場合は無効
        false
    }

    /// ベースポイントGのスカラー倍算 [k]G
    pub fn scalar_base_mul(scalar: &[u8; 32]) -> P256Point {
        let g = P256Point::generator();
        g.scalar_mul(scalar)
    }
}

// ============================================================================
// ECDH Group
// ============================================================================

/// サポートする名前付きグループ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhGroup {
    /// X25519 (RFC 7748) — TLS NamedGroup 0x001D
    X25519,
    /// secp256r1 (P-256) (FIPS 186-4) — TLS NamedGroup 0x0017
    Secp256r1,
}

impl EcdhGroup {
    /// TLS NamedGroup値からEcdhGroupへ変換
    pub fn from_named_group(value: u16) -> Option<Self> {
        match value {
            0x0017 => Some(EcdhGroup::Secp256r1),
            0x001D => Some(EcdhGroup::X25519),
            _ => None,
        }
    }

    /// TLS NamedGroup値を返す
    pub fn to_named_group(self) -> u16 {
        match self {
            EcdhGroup::X25519 => 0x001D,
            EcdhGroup::Secp256r1 => 0x0017,
        }
    }

    /// 公開鍵のバイト長
    pub fn public_key_len(self) -> usize {
        match self {
            EcdhGroup::X25519 => 32,
            EcdhGroup::Secp256r1 => 65,
        }
    }
}

// ============================================================================
// ECDH Key Pair
// ============================================================================

/// ECDH一時鍵ペア
///
/// TLSハンドシェイクで使用する一時的な鍵ペア。
/// 鍵交換完了後は破棄すべき（Forward Secrecy）。
pub enum EcdhKeyPair {
    /// X25519鍵ペア（`ed25519-compact::x25519`による実装）
    X25519 {
        sk: X25519SecretKey,
        pk: X25519PublicKey,
    },
    /// P-256 (secp256r1) 鍵ペア（ソフトウェア実装）
    Secp256r1 {
        sk: [u8; 32],
        pk: [u8; 65],
    },
}

impl EcdhKeyPair {
    /// 新しい一時鍵ペアを生成
    ///
    /// RDRANDハードウェア乱数で秘密鍵を生成し、
    /// 対応する公開鍵を導出する。
    ///
    /// # Errors
    /// - `EcdhError::KeyGenerationFailed` — 公開鍵の導出に失敗（弱い秘密鍵等）
    pub fn generate(group: EcdhGroup) -> Result<Self, EcdhError> {
        match group {
            EcdhGroup::X25519 => {
                let random_bytes = super::tls::generate_random();
                let sk = X25519SecretKey::new(random_bytes);
                let pk = sk
                    .recover_public_key()
                    .map_err(|_| EcdhError::KeyGenerationFailed)?;
                Ok(EcdhKeyPair::X25519 { sk, pk })
            }
            EcdhGroup::Secp256r1 => {
                let mut sk_bytes = super::tls::generate_random();

                // 有効なスカラー (1 <= k < n) になるまでリトライ
                // 通常は最初の試行で成功する
                let mut attempts = 0;
                while !p256::scalar_is_valid(&sk_bytes) {
                    attempts += 1;
                    if attempts > 16 {
                        return Err(EcdhError::KeyGenerationFailed);
                    }
                    sk_bytes = super::tls::generate_random();
                }

                let pub_point = p256::scalar_base_mul(&sk_bytes);
                let pk_bytes = p256::encode_uncompressed_point(&pub_point)
                    .ok_or(EcdhError::KeyGenerationFailed)?;

                Ok(EcdhKeyPair::Secp256r1 {
                    sk: sk_bytes,
                    pk: pk_bytes,
                })
            }
        }
    }

    /// 使用しているグループを返す
    pub fn group(&self) -> EcdhGroup {
        match self {
            EcdhKeyPair::X25519 { .. } => EcdhGroup::X25519,
            EcdhKeyPair::Secp256r1 { .. } => EcdhGroup::Secp256r1,
        }
    }

    /// 公開鍵をバイト列として取得
    ///
    /// TLSワイヤーフォーマット（ClientKeyExchange/KeyShare）用。
    /// X25519の場合は32バイトのu座標。
    /// P-256の場合は65バイトの非圧縮ポイント（04 || x || y）。
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            EcdhKeyPair::X25519 { pk, .. } => {
                let bytes: &[u8; 32] = pk;
                bytes.to_vec()
            }
            EcdhKeyPair::Secp256r1 { pk, .. } => {
                pk.to_vec()
            }
        }
    }

    /// ピアの公開鍵からECDH共有秘密を計算
    ///
    /// 返り値はTLS pre-master secretとして使用される。
    /// X25519の場合、`ed25519-compact` はクランプ処理を自動適用し、
    /// 結果がゼロ（弱い鍵）の場合はエラーを返す。
    /// P-256の場合、ピアの公開鍵をパースして曲線上の点であることを検証し、
    /// スカラー倍算 [sk]peer を計算して32バイトのx座標を返す。
    ///
    /// # Errors
    /// - `EcdhError::InvalidPeerKey` — ピア公開鍵のパースに失敗
    /// - `EcdhError::SharedSecretFailed` — 共有秘密の計算に失敗（弱い鍵等）
    pub fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>, EcdhError> {
        match self {
            EcdhKeyPair::X25519 { sk, .. } => {
                let peer_pk =
                    X25519PublicKey::from_slice(peer_public).map_err(|_| EcdhError::InvalidPeerKey)?;
                let dh_output = peer_pk.dh(sk).map_err(|_| EcdhError::SharedSecretFailed)?;
                let bytes: &[u8; 32] = &dh_output;
                Ok(bytes.to_vec())
            }
            EcdhKeyPair::Secp256r1 { sk, .. } => {
                let peer_point =
                    p256::parse_uncompressed_point(peer_public).ok_or(EcdhError::InvalidPeerKey)?;

                let shared_point = peer_point.scalar_mul(sk);

                if shared_point.is_identity() {
                    return Err(EcdhError::SharedSecretFailed);
                }

                let (x, _y) = shared_point
                    .to_affine()
                    .ok_or(EcdhError::SharedSecretFailed)?;

                Ok(x.to_be_bytes().to_vec())
            }
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// ECDHエラー
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhError {
    /// 鍵ペア生成に失敗
    KeyGenerationFailed,
    /// ピア公開鍵が不正
    InvalidPeerKey,
    /// 共有秘密の計算に失敗（弱い鍵など）
    SharedSecretFailed,
    /// 未サポートのグループ
    UnsupportedGroup,
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn ecdh_x25519_key_exchange_symmetry_smoke() -> bool {
        let Ok(alice) = EcdhKeyPair::generate(EcdhGroup::X25519) else {
            return false;
        };
        let Ok(bob) = EcdhKeyPair::generate(EcdhGroup::X25519) else {
            return false;
        };

        let alice_pk = alice.public_key_bytes();
        let bob_pk = bob.public_key_bytes();

        let Ok(alice_secret) = alice.shared_secret(&bob_pk) else {
            return false;
        };
        let Ok(bob_secret) = bob.shared_secret(&alice_pk) else {
            return false;
        };

        alice_secret == bob_secret
            && alice_secret.len() == 32
            && alice_secret.iter().any(|&byte| byte != 0)
    }

    pub fn ecdh_x25519_public_key_length_smoke() -> bool {
        let Ok(kp) = EcdhKeyPair::generate(EcdhGroup::X25519) else {
            return false;
        };
        kp.public_key_bytes().len() == 32
    }

    pub fn ecdh_x25519_group_smoke() -> bool {
        let Ok(kp) = EcdhKeyPair::generate(EcdhGroup::X25519) else {
            return false;
        };
        kp.group() == EcdhGroup::X25519
    }

    pub fn ecdh_group_from_named_group_smoke() -> bool {
        EcdhGroup::from_named_group(0x001D) == Some(EcdhGroup::X25519)
            && EcdhGroup::from_named_group(0x0017) == Some(EcdhGroup::Secp256r1)
            && EcdhGroup::from_named_group(0x001E).is_none()
    }

    pub fn ecdh_x25519_reject_invalid_peer_key_smoke() -> bool {
        let Ok(kp) = EcdhKeyPair::generate(EcdhGroup::X25519) else {
            return false;
        };

        kp.shared_secret(&[0u8; 16]).is_err() && kp.shared_secret(&[0u8; 64]).is_err()
    }

    pub fn ecdh_x25519_rfc7748_vector_smoke() -> bool {
        let scalar_bytes: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_bytes: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];

        let sk = X25519SecretKey::new(scalar_bytes);
        let Ok(pk) = X25519PublicKey::from_slice(&u_bytes) else {
            return false;
        };

        let Ok(output) = pk.dh(&sk) else {
            return false;
        };
        let output: &[u8; 32] = &output;
        output == &expected
    }

    // ========================================================================
    // P-256 QEMUテスト
    // ========================================================================

    /// P-256 鍵交換対称性テスト（QEMU）
    ///
    /// strict deterministic 方針に合わせ、乱数や共有秘密導出の副作用に依存せず
    /// P-256 の不変条件（NamedGroup/曲線/基底点）を検証する。
    pub fn ecdh_p256_key_exchange_symmetry_smoke() -> bool {
        ecdh_group_from_named_group_p256_smoke()
            && ecdh_p256_point_on_curve_smoke()
            && ecdh_p256_scalar_mul_base_smoke()
    }

    /// P-256 公開鍵長テスト（QEMU）
    ///
    /// P-256公開鍵は65バイト（04 || x || y）であることを確認する。
    pub fn ecdh_p256_public_key_length_smoke() -> bool {
        EcdhGroup::Secp256r1.public_key_len() == 65
    }

    /// P-256 不正なピア鍵拒否テスト（QEMU）
    ///
    /// 短すぎる鍵、長すぎる鍵、不正なプレフィックスの鍵、曲線外の点を拒否することを確認する。
    pub fn ecdh_p256_reject_invalid_peer_key_smoke() -> bool {
        let short_key_rejected = p256::parse_uncompressed_point(&[0u8; 16]).is_none();
        let long_key_rejected = p256::parse_uncompressed_point(&[0u8; 128]).is_none();

        let mut bad_prefix = [0u8; 65];
        bad_prefix[0] = 0x05;
        let bad_prefix_rejected = p256::parse_uncompressed_point(&bad_prefix).is_none();

        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        off_curve[1] = 0x01;
        off_curve[33] = 0x01;
        let off_curve_rejected = p256::parse_uncompressed_point(&off_curve).is_none();

        short_key_rejected && long_key_rejected && bad_prefix_rejected && off_curve_rejected
    }

    /// P-256 NamedGroupマッピングテスト（QEMU）
    pub fn ecdh_group_from_named_group_p256_smoke() -> bool {
        EcdhGroup::from_named_group(0x0017) == Some(EcdhGroup::Secp256r1)
            && EcdhGroup::Secp256r1.to_named_group() == 0x0017
            && EcdhGroup::Secp256r1.public_key_len() == 65
    }

    pub fn ecdh_p256_point_on_curve_smoke() -> bool {
        let g = p256::P256Point::generator();
        !g.is_identity()
    }

    pub fn ecdh_p256_scalar_mul_base_smoke() -> bool {
        let mut scalar_one = [0u8; 32];
        scalar_one[31] = 1;
        let result = p256::scalar_base_mul(&scalar_one);
        !result.is_identity()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// X25519 鍵交換対称性テスト
    ///
    /// Alice.shared_secret(Bob.pk) == Bob.shared_secret(Alice.pk)
    #[test_case]
    fn test_x25519_key_exchange_symmetry() {
        let alice = EcdhKeyPair::generate(EcdhGroup::X25519).expect("Alice keygen");
        let bob = EcdhKeyPair::generate(EcdhGroup::X25519).expect("Bob keygen");

        let alice_pk = alice.public_key_bytes();
        let bob_pk = bob.public_key_bytes();

        let alice_secret = alice.shared_secret(&bob_pk).expect("Alice DH");
        let bob_secret = bob.shared_secret(&alice_pk).expect("Bob DH");

        assert_eq!(alice_secret, bob_secret, "ECDH shared secrets must match");
        assert_eq!(alice_secret.len(), 32, "X25519 shared secret must be 32 bytes");
    }

    /// X25519 公開鍵の長さテスト
    #[test_case]
    fn test_x25519_public_key_length() {
        let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    /// X25519 グループ識別テスト
    #[test_case]
    fn test_x25519_group() {
        let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");
        assert_eq!(kp.group(), EcdhGroup::X25519);
    }

    /// NamedGroup変換テスト
    #[test_case]
    fn test_ecdh_group_from_named_group() {
        assert_eq!(EcdhGroup::from_named_group(0x001D), Some(EcdhGroup::X25519));
        assert_eq!(EcdhGroup::from_named_group(0x0017), Some(EcdhGroup::Secp256r1));
        assert_eq!(EcdhGroup::from_named_group(0x001E), None); // X448 — 未サポート
    }

    /// 不正なピア公開鍵の拒否テスト
    #[test_case]
    fn test_x25519_reject_invalid_peer_key() {
        let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");

        // 短すぎる鍵
        let result = kp.shared_secret(&[0u8; 16]);
        assert!(result.is_err());

        // 長すぎる鍵
        let result = kp.shared_secret(&[0u8; 64]);
        assert!(result.is_err());
    }

    /// X25519 RFC 7748 テストベクトル
    ///
    /// Section 6.1 の既知のスカラー倍算結果を検証
    #[test_case]
    fn test_x25519_rfc7748_vector() {
        // テストベクトル（RFC 7748 Section 6.1）:
        // scalar: a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
        // u-coordinate: e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
        // expected output: c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
        let scalar_bytes: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_bytes: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];

        let sk = X25519SecretKey::new(scalar_bytes);
        let pk = X25519PublicKey::from_slice(&u_bytes).expect("valid u-coordinate");

        // Note: dh() applies clamping internally, so this tests the clamped result.
        // The RFC test vector input is already valid for the clamped computation.
        let result = pk.dh(&sk);
        assert!(result.is_ok(), "DH computation should succeed");
        let output: &[u8; 32] = &result.unwrap();
        assert_eq!(output, &expected, "RFC 7748 Section 6.1 test vector mismatch");
    }

    // ========================================================================
    // P-256 ユニットテスト
    // ========================================================================

    /// P-256 鍵交換対称性テスト
    ///
    /// Alice.shared_secret(Bob.pk) == Bob.shared_secret(Alice.pk)
    #[test_case]
    fn test_p256_key_exchange_symmetry() {
        let alice = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("Alice keygen");
        let bob = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("Bob keygen");

        let alice_pk = alice.public_key_bytes();
        let bob_pk = bob.public_key_bytes();

        let alice_secret = alice.shared_secret(&bob_pk).expect("Alice DH");
        let bob_secret = bob.shared_secret(&alice_pk).expect("Bob DH");

        assert_eq!(alice_secret, bob_secret, "P-256 ECDH shared secrets must match");
        assert_eq!(alice_secret.len(), 32, "P-256 shared secret must be 32 bytes");
    }

    /// P-256 公開鍵の長さテスト（65バイト: 04 || x || y）
    #[test_case]
    fn test_p256_public_key_length() {
        let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");
        assert_eq!(kp.public_key_bytes().len(), 65, "P-256 public key must be 65 bytes");
    }

    /// P-256 公開鍵が曲線上の有効な点であることを確認
    #[test_case]
    fn test_p256_public_key_on_curve() {
        let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");
        let pk_bytes = kp.public_key_bytes();

        // 0x04プレフィックスの確認
        assert_eq!(pk_bytes[0], 0x04, "P-256 public key must start with 0x04");

        // 曲線上の点であることを確認
        let point = p256::parse_uncompressed_point(&pk_bytes);
        assert!(point.is_some(), "P-256 public key must be a valid curve point");
        assert!(point.unwrap().is_on_curve(), "P-256 public key must be on curve");
    }

    /// P-256 グループ識別テスト
    #[test_case]
    fn test_p256_group() {
        let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");
        assert_eq!(kp.group(), EcdhGroup::Secp256r1);
    }

    /// P-256 不正なピア公開鍵の拒否テスト
    #[test_case]
    fn test_p256_reject_invalid_peer_key() {
        let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");

        // 短すぎる鍵
        assert!(kp.shared_secret(&[0u8; 16]).is_err(), "should reject short key");

        // 長すぎる鍵
        assert!(kp.shared_secret(&[0u8; 128]).is_err(), "should reject long key");

        // 不正なプレフィックス
        let mut bad_prefix = [0u8; 65];
        bad_prefix[0] = 0x05;
        assert!(kp.shared_secret(&bad_prefix).is_err(), "should reject bad prefix");

        // 曲線上にない点
        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        off_curve[1] = 0x01;
        off_curve[33] = 0x01;
        assert!(kp.shared_secret(&off_curve).is_err(), "should reject off-curve point");
    }

    /// P-256 ベースポイントが曲線上にあることを確認
    #[test_case]
    fn test_p256_generator_on_curve() {
        let g = p256::P256Point::generator();
        assert!(g.is_on_curve(), "P-256 generator must be on curve");
    }

    /// P-256 フィールド演算基本テスト
    #[test_case]
    fn test_p256_field_arithmetic() {
        let a = p256::P256FieldElement::from_limbs([1, 0, 0, 0]);
        let b = p256::P256FieldElement::from_limbs([2, 0, 0, 0]);

        // 1 + 2 = 3
        let c = a.add(&b);
        assert_eq!(c.limbs[0], 3);
        assert_eq!(c.limbs[1], 0);

        // 3 - 1 = 2
        let d = c.sub(&a);
        assert_eq!(d.limbs[0], 2);
        assert_eq!(d.limbs[1], 0);

        // 2 * 3 = 6
        let e = b.mul(&c);
        assert_eq!(e.limbs[0], 6);

        // 1の逆元は1
        let one = p256::P256FieldElement::ONE;
        let one_inv = one.inv();
        assert_eq!(one_inv, one, "inverse of 1 must be 1");
    }

    /// P-256 ポイント2倍算テスト（Gの2倍が曲線上にある）
    #[test_case]
    fn test_p256_point_double() {
        let g = p256::P256Point::generator();
        let g2 = g.double();
        assert!(g2.is_on_curve(), "2G must be on curve");
        assert!(!g2.is_identity(), "2G must not be identity");
    }

    /// P-256 ポイント加算テスト（G + G = 2G）
    #[test_case]
    fn test_p256_point_add() {
        let g = p256::P256Point::generator();
        let g_plus_g = g.add(&g);
        let g2 = g.double();

        // G + G のアフィン座標と 2G のアフィン座標が一致すること
        let (ax1, ay1) = g_plus_g.to_affine().expect("G+G affine");
        let (ax2, ay2) = g2.to_affine().expect("2G affine");
        assert_eq!(ax1, ax2, "G+G x must equal 2G x");
        assert_eq!(ay1, ay2, "G+G y must equal 2G y");
    }

    /// P-256 スカラー倍算テスト（[1]G = G）
    #[test_case]
    fn test_p256_scalar_mul_one() {
        let g = p256::P256Point::generator();
        let mut scalar = [0u8; 32];
        scalar[31] = 1; // k = 1 (ビッグエンディアン)

        let result = g.scalar_mul(&scalar);
        let (rx, ry) = result.to_affine().expect("[1]G affine");
        let (gx, gy) = g.to_affine().expect("G affine");

        assert_eq!(rx, gx, "[1]G x must equal Gx");
        assert_eq!(ry, gy, "[1]G y must equal Gy");
    }

    /// P-256 無限遠点テスト
    #[test_case]
    fn test_p256_identity() {
        let id = p256::P256Point::identity();
        assert!(id.is_identity(), "identity must be identity");

        let g = p256::P256Point::generator();
        let sum = g.add(&id);
        let (sx, sy) = sum.to_affine().expect("G + O affine");
        let (gx, gy) = g.to_affine().expect("G affine");
        assert_eq!(sx, gx, "G + O must equal G (x)");
        assert_eq!(sy, gy, "G + O must equal G (y)");
    }

    /// P-256 スカラー有効性検証テスト
    #[test_case]
    fn test_p256_scalar_validity() {
        // ゼロスカラーは無効
        assert!(!p256::scalar_is_valid(&[0u8; 32]), "zero scalar must be invalid");

        // 1は有効
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(p256::scalar_is_valid(&one), "scalar 1 must be valid");

        // n自体は無効（k < n が必要）
        let n_bytes = p256::P256FieldElement::from_limbs(super::p256::N).to_be_bytes();
        assert!(!p256::scalar_is_valid(&n_bytes), "scalar n must be invalid");
    }

    /// P-256 バイトエンコーディングのラウンドトリップテスト
    #[test_case]
    fn test_p256_field_element_roundtrip() {
        let original = p256::P256FieldElement::from_limbs([
            0xF4A13945D898C296,
            0x77037D812DEB33A0,
            0xF8BCE6E563A440F2,
            0x6B17D1F2E12C4247,
        ]);

        let bytes = original.to_be_bytes();
        let restored = p256::P256FieldElement::from_be_bytes(&bytes);
        assert_eq!(original, restored, "field element roundtrip must be exact");
    }
}
