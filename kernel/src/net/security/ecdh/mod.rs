// ============================================================================
// kernel/src/net/security/ecdh/mod.rs - ECDH Key Exchange
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
pub(crate) use self::p384::*;
mod p256_parsing;
pub use p256_parsing::*;

pub mod p256 {
    /// P-256素数体の元（リトルエンディアン4×u64リム表現）
    ///
    /// p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    #[derive(Clone, Copy, Debug)]
    pub struct P256FieldElement {
        pub limbs: [u64; 4],
    }

    impl PartialEq for P256FieldElement {
        fn eq(&self, other: &Self) -> bool {
            self.equals(other)
        }
    }

    impl Eq for P256FieldElement {}

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
            self.is_zero_ct() != 0
        }

        /// 等価判定
        pub fn equals(&self, other: &Self) -> bool {
            self.equals_ct(other) != 0
        }

        /// 等価判定 (Constant-time version)
        /// 等しければ1、異なれば0を返す。
        pub fn equals_ct(&self, other: &Self) -> u8 {
            let diff = (self.limbs[0] ^ other.limbs[0])
                | (self.limbs[1] ^ other.limbs[1])
                | (self.limbs[2] ^ other.limbs[2])
                | (self.limbs[3] ^ other.limbs[3]);
            (((diff | 0u64.wrapping_sub(diff)) >> 63) ^ 1) as u8
        }

        /// ゼロ判定 (Constant-time version)
        /// ゼロなら1, ゼロ以外なら0を返す。
        pub fn is_zero_ct(&self) -> u8 {
            let or = self.limbs[0] | self.limbs[1] | self.limbs[2] | self.limbs[3];
            let is_zero = ((or | (0u64.wrapping_sub(or))) >> 63) ^ 1;
            is_zero as u8
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
                borrow = (diff >> 127) as u64;
            }

            // carry > 0 OR borrow == 0
            // carry is either 0 or 1. borrow is either 0 or 1.
            let use_sub = (carry as u8) | (1 - borrow as u8);

            let res_fe = Self { limbs: result };
            let sub_fe = Self { limbs: sub };
            Self::ct_select(&res_fe, &sub_fe, use_sub)
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
                borrow = (diff >> 127) as u64;
            }

            // アンダーフローした場合はpを加算 (定時間で計算)
            let mut added = [0u64; 4];
            let mut carry: u64 = 0;
            for i in 0..4 {
                let sum = (result[i] as u128) + (P[i] as u128) + (carry as u128);
                added[i] = sum as u64;
                carry = (sum >> 64) as u64;
            }

            let res_fe = Self { limbs: result };
            let added_fe = Self { limbs: added };
            Self::ct_select(&res_fe, &added_fe, borrow as u8)
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
                    let wide = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                        + (product[i + j] as u128)
                        + (carry as u128);
                    product[i + j] = wide as u64;
                    carry = (wide >> 64) as u64;
                }
                product[i + 4] = carry;
            }

            // NIST P-256高速リダクション (FIPS 186-4 D.2.3)
            reduce_mod_p256(&product)
        }

        /// フィールド二乗 (mod p)
        pub fn square(&self) -> Self {
            self.mul(self)
        }

        /// フィールド逆元 (mod p)
        ///
        /// フェルマーの小定理によるa^(p-2)を二乗と乗算の繰り返しで計算する。
        /// 定時間性を確保するため、ビットの値に関わらず常に乗算を行い、ct_selectで結果を選択する。
        pub fn inv(&self) -> Self {
            // p - 2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
            let p_minus_2: [u64; 4] = [
                0xFFFFFFFFFFFFFFFD,
                0x00000000FFFFFFFF,
                0x0000000000000000,
                0xFFFFFFFF00000001,
            ];

            let mut result = Self::ONE;
            let mut base = *self;

            // 固定回数 (4リム * 64ビット = 256回) のループ
            for i in 0..4 {
                let mut word = p_minus_2[i];
                for _ in 0..64 {
                    let bit = (word & 1) as u8;
                    let multiplied = result.mul(&base);

                    // result = (bit == 1) ? multiplied : result
                    result = Self::ct_select(&result, &multiplied, bit);

                    base = base.square();
                    word >>= 1;
                }
            }

            result
        }

        /// ビッグエンディアン32バイトからフィールド要素を生成。
        /// 範囲チェックを行い、p 以上の場合は None を返す。
        pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<Self> {
            let mut limbs = [0u64; 4];
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

            // 範囲チェック (val < p)
            let mut is_less = false;
            for i in (0..4).rev() {
                if limbs[i] < P[i] {
                    is_less = true;
                    break;
                }
                if limbs[i] > P[i] {
                    return None;
                }
            }
            if !is_less {
                // val == p
                return None;
            }

            Some(Self { limbs })
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

        /// Constant-time selection: returns `a` if `condition == 0`, `b` if `condition == 1`.
        /// `condition` MUST be 0 or 1.
        pub fn ct_select(a: &Self, b: &Self, condition: u8) -> Self {
            let mask = 0u64.wrapping_sub(condition as u64);
            let mut limbs = [0u64; 4];
            for i in 0..4 {
                limbs[i] = a.limbs[i] ^ ((a.limbs[i] ^ b.limbs[i]) & mask);
            }
            Self { limbs }
        }
    }

    /// BigUintベースのP-256剰余リダクション。
    ///
    /// P-256の高速リダクションは正しさの中核なので、壊れた特殊化を残さず
    /// 汎用多倍長整数で積を素数体へ戻す。
    fn reduce_mod_p256(product: &[u64; 8]) -> P256FieldElement {
        let mut be_bytes = [0u8; 64];
        for i in 0..8 {
            let bytes = product[7 - i].to_be_bytes();
            be_bytes[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        let prod_big = crate::net::security::rsa::BigUint::from_be_bytes(&be_bytes);

        let p_fe = P256FieldElement::from_limbs(P);
        let p_bytes = p_fe.to_be_bytes();
        let p_big = crate::net::security::rsa::BigUint::from_be_bytes(&p_bytes);

        let result = prod_big.rem(&p_big);
        let mut result_bytes = [0u8; 32];
        result.write_be_bytes_padded(&mut result_bytes);

        match P256FieldElement::from_be_bytes(&result_bytes) {
            Some(value) => value,
            None => unreachable!("P-256 modular reduction produced an out-of-field value"),
        }
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
            if self.z.equals(&P256FieldElement::ONE) {
                return Some((self.x, self.y));
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
            let is_id = self.is_identity();

            // a = p - 3 ショートカット: M = 3(X + Z²)(X - Z²)
            let z2 = self.z.square();
            let xpz2 = self.x.add(&z2);
            let xmz2 = self.x.sub(&z2);
            let m = xpz2.mul(&xmz2);
            // M = 3 * m
            let m = m.add(&m).add(&m);

            // S = 4 * X * Y²
            let y2 = self.y.square();
            let x_y2 = self.x.mul(&y2);
            let s = x_y2.add(&x_y2).add(&x_y2.add(&x_y2)); // (2*x_y2) + (2*x_y2) = 4*x_y2

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

            let res = Self {
                x: x3,
                y: y3,
                z: z3,
            };

            // If identity, stay identity. If Y is zero (vertical tangent), becomes identity.
            let y_is_zero = self.y.is_zero_ct();
            Self::ct_select(&res, &Self::identity(), is_id as u8 | y_is_zero)
        }

        /// 点の加算（ヤコビアン座標）
        ///
        /// 標準的なヤコビアン加算を無限遠点の検査付きで実装する。
        pub fn add(&self, other: &Self) -> Self {
            let is_self_id = self.is_identity() as u8;
            let is_other_id = other.is_identity() as u8;

            let z1z1 = self.z.square();
            let z2z2 = other.z.square();

            let u1 = self.x.mul(&z2z2);
            let u2 = other.x.mul(&z1z1);

            let s1 = self.y.mul(&z2z2).mul(&other.z);
            let s2 = other.y.mul(&z1z1).mul(&self.z);

            let h = u2.sub(&u1);
            let r = s2.sub(&s1);

            let h_is_zero = h.is_zero_ct();
            let r_is_zero = r.is_zero_ct();

            let h2 = h.square();
            let h3 = h2.mul(&h);

            let u1h2 = u1.mul(&h2);

            // X3 = R² - H³ - 2*U1*H²
            let x3 = r.square().sub(&h3).sub(&u1h2.add(&u1h2));

            // Y3 = R*(U1*H² - X3) - S1*H³
            let y3 = r.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h3));

            // Z3 = H*Z1*Z2
            let z3 = h.mul(&self.z).mul(&other.z);

            let res = Self {
                x: x3,
                y: y3,
                z: z3,
            };

            // U1 == U2 の場合
            let is_equal = h_is_zero & r_is_zero;
            let is_opposite = h_is_zero & (1 - r_is_zero);

            // 2倍算の結果（自己加算時）
            let doubled = self.double();

            let res = Self::ct_select(&res, &doubled, is_equal);
            let res = Self::ct_select(&res, &Self::identity(), is_opposite);

            // 単位元の処理
            let res = Self::ct_select(&res, other, is_self_id);
            let res = Self::ct_select(&res, self, is_other_id);
            res
        }

        /// Constant-time selection: returns `a` if `condition == 0`, `b` if `condition == 1`.
        pub fn ct_select(a: &Self, b: &Self, condition: u8) -> Self {
            Self {
                x: P256FieldElement::ct_select(&a.x, &b.x, condition),
                y: P256FieldElement::ct_select(&a.y, &b.y, condition),
                z: P256FieldElement::ct_select(&a.z, &b.z, condition),
            }
        }

        /// スカラー倍算 [k]P (Constant-time implementation)
        ///
        /// 全ての演算が定数時間で行われる add/double を使用し、
        /// スカラーの値に依存しない定時間で演算を行う。
        pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {
            let mut result = Self::identity();

            // 固定回数ループにより、タイミング漏洩を防止。
            // 全ての add と double が定数時間化されているため、このループも定数時間となる。
            for i in (0..256).rev() {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                let bit = (scalar[31 - byte_idx] >> bit_idx) & 1;

                result = result.double();
                let added = result.add(self);
                result = Self::ct_select(&result, &added, bit as u8);
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

            y2.equals(&rhs)
        }
    }

    // p256_parsing モジュールの公開関数を p256 名前空間から再エクスポート
    pub use crate::net::security::ecdh::ecdsa_p256_verify;
    pub use crate::net::security::ecdh::parse_uncompressed_point;
}
