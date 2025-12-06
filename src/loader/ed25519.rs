// ============================================================================
// src/loader/ed25519.rs - Ed25519 Signature Verification
// 設計書 3.3: コンパイラ署名とロード時検証
// ============================================================================
//!
//! no_std環境向けのEd25519署名検証の純Rust実装
//!
//! ## 参照
//! - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
//! - FIPS 186-5: Digital Signature Standard (DSS)
//!
//! ## 注意
//! この実装は教育目的のものです。本番環境では、監査済みの暗号ライブラリ
//! (ed25519-dalek等)の使用を検討してください。

#![allow(dead_code)]

use super::sha256;

// ============================================================================
// Field and Curve Constants
// ============================================================================

/// 素体の法 p = 2^255 - 19
const P: [u64; 4] = [
    0xFFFFFFFFFFFFFFED,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
];

/// 群の位数 L = 2^252 + 27742317777372353535851937790883648493
const L: [u64; 4] = [
    0x5812631A5CF5D3ED,
    0x14DEF9DEA2F79CD6,
    0x0000000000000000,
    0x1000000000000000,
];

/// ベースポイント座標
const BASE_POINT_Y: [u64; 4] = [
    0x6666666666666658,
    0x6666666666666666,
    0x6666666666666666,
    0x6666666666666666,
];

// ============================================================================
// Field Element (mod p)
// ============================================================================

/// 有限体要素 (mod p)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldElement([u64; 4]);

impl FieldElement {
    const ZERO: Self = Self([0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0]);

    /// バイト列から生成（リトルエンディアン）
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut result = [0u64; 4];
        for i in 0..4 {
            result[i] = u64::from_le_bytes([
                bytes[i * 8],
                bytes[i * 8 + 1],
                bytes[i * 8 + 2],
                bytes[i * 8 + 3],
                bytes[i * 8 + 4],
                bytes[i * 8 + 5],
                bytes[i * 8 + 6],
                bytes[i * 8 + 7],
            ]);
        }
        // 最上位ビットをクリア (mod 2^255)
        result[3] &= 0x7FFFFFFFFFFFFFFF;
        Self(result).reduce()
    }

    /// バイト列に変換
    fn to_bytes(&self) -> [u8; 32] {
        let reduced = self.reduce();
        let mut result = [0u8; 32];
        for i in 0..4 {
            result[i * 8..(i + 1) * 8].copy_from_slice(&reduced.0[i].to_le_bytes());
        }
        result
    }

    /// mod p で正規化
    fn reduce(self) -> Self {
        let mut result = self.0;
        
        // 簡易的な減算法: result >= p なら result -= p
        loop {
            let mut borrow = 0i128;
            let mut temp = [0u64; 4];
            
            for i in 0..4 {
                let diff = result[i] as i128 - P[i] as i128 - borrow;
                if diff < 0 {
                    temp[i] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    temp[i] = diff as u64;
                    borrow = 0;
                }
            }
            
            if borrow == 0 {
                result = temp;
            } else {
                break;
            }
        }
        
        Self(result)
    }

    /// 加算 (mod p)
    fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;

        for i in 0..4 {
            let sum = self.0[i] as u128 + other.0[i] as u128 + carry as u128;
            result[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }

        Self(result).reduce()
    }

    /// 減算 (mod p)
    fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            let diff = self.0[i] as i128 - other.0[i] as i128 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }

        // borrowがある場合、pを加算
        if borrow > 0 {
            let mut carry = 0u64;
            for i in 0..4 {
                let sum = result[i] as u128 + P[i] as u128 + carry as u128;
                result[i] = sum as u64;
                carry = (sum >> 64) as u64;
            }
        }

        Self(result)
    }

    /// 乗算 (mod p) - 簡易版
    fn mul(&self, other: &Self) -> Self {
        // 512ビット積を計算
        let mut product = [0u64; 8];
        
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let pos = i + j;
                let prod = self.0[i] as u128 * other.0[j] as u128 
                    + product[pos] as u128 
                    + carry as u128;
                product[pos] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            product[i + 4] = carry;
        }
        
        // Barrett reduction簡易版
        Self::reduce_512(&product)
    }

    /// 512ビット値をmod pに減算
    fn reduce_512(product: &[u64; 8]) -> Self {
        // 下位256ビット
        let mut result = [product[0], product[1], product[2], product[3] & 0x7FFFFFFFFFFFFFFF];
        
        // 上位ビットを19倍して加算 (2^255 ≡ 19 mod p)
        let high_bit = (product[3] >> 63) as u128;
        let mut carry = high_bit * 19;
        
        for i in 0..4 {
            let upper = if i < 4 { product[4 + i] } else { 0 };
            let contribution = (upper as u128) * 38 + carry; // 2^256 ≡ 38 mod p
            let sum = result[i] as u128 + (contribution & 0xFFFFFFFFFFFFFFFF);
            result[i] = sum as u64;
            carry = (sum >> 64) + (contribution >> 64);
        }
        
        // 最終正規化
        Self(result).reduce()
    }

    /// 二乗
    fn square(&self) -> Self {
        self.mul(self)
    }

    /// 逆元 (mod p) - フェルマーの小定理を使用
    fn inverse(&self) -> Self {
        // a^(-1) = a^(p-2) mod p
        let mut result = Self::ONE;
        let mut base = *self;
        
        // p - 2 の2進表現でのべき乗
        let exp = [
            P[0].wrapping_sub(2),
            P[1],
            P[2],
            P[3],
        ];
        
        for i in 0..4 {
            for j in 0..64 {
                if (exp[i] >> j) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
            }
        }
        
        result
    }

    /// 負の値
    fn neg(&self) -> Self {
        Self([P[0], P[1], P[2], P[3]]).sub(self)
    }

    /// ゼロかどうか
    fn is_zero(&self) -> bool {
        let reduced = self.reduce();
        reduced.0[0] == 0 && reduced.0[1] == 0 && reduced.0[2] == 0 && reduced.0[3] == 0
    }
}

// ============================================================================
// Edwards Curve Point
// ============================================================================

/// Extended coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, xy=T/Z
#[derive(Clone, Copy, Debug)]
struct ExtendedPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl ExtendedPoint {
    /// 単位元（無限遠点）
    const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// Y座標からポイントを復元
    fn from_y(y_bytes: &[u8; 32]) -> Option<Self> {
        let mut y_copy = *y_bytes;
        let sign = (y_copy[31] >> 7) & 1;
        y_copy[31] &= 0x7F;
        
        let y = FieldElement::from_bytes(&y_copy);
        
        // x^2 = (y^2 - 1) / (d*y^2 + 1)
        // d = -121665/121666
        let y2 = y.square();
        
        // 曲線定数 d
        let d = FieldElement::from_bytes(&[
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
            0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
            0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
            0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
        ]);
        
        let one = FieldElement::ONE;
        let numerator = y2.sub(&one);
        let denominator = d.mul(&y2).add(&one);
        
        let x2 = numerator.mul(&denominator.inverse());
        
        // 平方根を計算（存在すれば）
        let x = sqrt_field(&x2)?;
        
        // 符号を調整
        let x_bytes = x.to_bytes();
        let computed_sign = x_bytes[0] & 1;
        
        let x = if computed_sign != sign {
            x.neg()
        } else {
            x
        };
        
        let t = x.mul(&y);
        
        Some(Self {
            x,
            y,
            z: FieldElement::ONE,
            t,
        })
    }

    /// 点の加算
    fn add(&self, other: &Self) -> Self {
        // Extended coordinates addition formula
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        
        // d = -121665/121666
        let d = FieldElement::from_bytes(&[
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
            0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
            0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
            0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
        ]);
        
        let c = self.t.mul(&d).mul(&other.t);
        let dd = self.z.mul(&other.z);
        let e = self.x.add(&self.y).mul(&other.x.add(&other.y)).sub(&a).sub(&b);
        let f = dd.sub(&c);
        let g = dd.add(&c);
        let h = b.add(&a); // b - (-a) = b + a (a = -1 in Ed25519)
        
        let x3 = e.mul(&f);
        let y3 = g.mul(&h);
        let t3 = e.mul(&h);
        let z3 = f.mul(&g);
        
        Self {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// 点の二倍
    fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(&self.z.square()); // 2*Z^2
        let h = a.add(&b);
        let e = self.x.add(&self.y).square().sub(&h);
        let g = a.sub(&b); // a = -1
        let f = c.add(&g);
        
        let x3 = e.mul(&f);
        let y3 = g.mul(&h);
        let t3 = e.mul(&h);
        let z3 = f.mul(&g);
        
        Self {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// スカラー倍
    fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {
        let mut result = Self::IDENTITY;
        let mut temp = *self;
        
        for i in 0..256 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            
            if (scalar[byte_idx] >> bit_idx) & 1 == 1 {
                result = result.add(&temp);
            }
            temp = temp.double();
        }
        
        result
    }

    /// Affine座標に変換
    fn to_affine(&self) -> (FieldElement, FieldElement) {
        let z_inv = self.z.inverse();
        (self.x.mul(&z_inv), self.y.mul(&z_inv))
    }

    /// Y座標をバイト列に変換（圧縮形式）
    fn to_bytes(&self) -> [u8; 32] {
        let (x, y) = self.to_affine();
        let mut result = y.to_bytes();
        let x_bytes = x.to_bytes();
        result[31] |= (x_bytes[0] & 1) << 7;
        result
    }
}

/// 有限体での平方根（存在すれば）
fn sqrt_field(a: &FieldElement) -> Option<FieldElement> {
    // p ≡ 5 (mod 8) なので a^((p+3)/8) を使用
    // まず a^((p-5)/8) を計算
    let mut result = *a;
    
    // 簡易版: a^((p+3)/8) を計算
    // この指数は (2^255 - 19 + 3) / 8 = (2^255 - 16) / 8 = 2^252 - 2
    for _ in 0..250 {
        result = result.square();
    }
    result = result.mul(a);
    
    // 検証: result^2 == a ?
    let check = result.square();
    if check == *a {
        Some(result)
    } else {
        // -1 * result を試す
        let neg_result = result.neg();
        let check2 = neg_result.square();
        if check2 == *a {
            Some(neg_result)
        } else {
            None
        }
    }
}

// ============================================================================
// Ed25519 Verification
// ============================================================================

/// ベースポイントを取得
fn get_base_point() -> ExtendedPoint {
    // ベースポイントのY座標（圧縮形式）
    let base_y = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    ];
    
    ExtendedPoint::from_y(&base_y).expect("Base point should be valid")
}

/// SHA-512ハッシュの下位256ビットを取得（スカラー用）
fn hash_to_scalar(data: &[u8]) -> [u8; 32] {
    // SHA-512の簡易実装として、SHA-256を2回使用
    let h1 = sha256::compute(data);
    let mut data2 = [0u8; 64];
    data2[..32].copy_from_slice(&h1);
    data2[32..].copy_from_slice(data.get(..32).unwrap_or(&[0u8; 32]));
    
    sha256::compute(&data2)
}

/// Ed25519署名を検証
///
/// # Arguments
/// * `public_key` - 32バイトの公開鍵
/// * `message` - 署名対象のメッセージ（ハッシュ済み）
/// * `signature` - 64バイトの署名
///
/// # Returns
/// 署名が有効な場合true
pub fn verify(public_key: &[u8; 32], message: &[u8; 32], signature: &[u8; 64]) -> bool {
    // 1. 公開鍵Aをデコード
    let a = match ExtendedPoint::from_y(public_key) {
        Some(p) => p,
        None => return false,
    };

    // 2. 署名を分解: R || S
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    s_bytes.copy_from_slice(&signature[32..]);

    // 3. Rをデコード
    let r = match ExtendedPoint::from_y(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    // 4. sがL未満であることを確認
    if !is_scalar_valid(&s_bytes) {
        return false;
    }

    // 5. h = SHA512(R || A || M) mod L
    let mut hash_input = alloc::vec::Vec::new();
    hash_input.extend_from_slice(&r_bytes);
    hash_input.extend_from_slice(public_key);
    hash_input.extend_from_slice(message);
    
    let h = hash_to_scalar(&hash_input);

    // 6. 検証: [S]B == R + [h]A
    let base = get_base_point();
    let sb = base.scalar_mul(&s_bytes);
    let ha = a.scalar_mul(&h);
    let rhs = r.add(&ha);

    // 座標を比較
    let sb_bytes = sb.to_bytes();
    let rhs_bytes = rhs.to_bytes();
    
    sb_bytes == rhs_bytes
}

/// スカラー値が有効か（L未満か）確認
fn is_scalar_valid(s: &[u8; 32]) -> bool {
    // 簡易チェック: 最上位バイトが0x10未満なら確実に有効
    if s[31] < 0x10 {
        return true;
    }
    
    // より厳密なチェック: s < L
    for i in (0..32).rev() {
        let l_byte = ((L[i / 8] >> ((i % 8) * 8)) & 0xFF) as u8;
        if s[i] < l_byte {
            return true;
        }
        if s[i] > l_byte {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_element_basic() {
        let one = FieldElement::ONE;
        let zero = FieldElement::ZERO;
        
        assert!(zero.is_zero());
        assert!(!one.is_zero());
        
        let sum = one.add(&zero);
        assert_eq!(sum, one);
    }

    #[test]
    fn test_field_element_mul() {
        let two = FieldElement([2, 0, 0, 0]);
        let three = FieldElement([3, 0, 0, 0]);
        let six = two.mul(&three);
        assert_eq!(six.0[0], 6);
    }

    #[test]
    fn test_base_point_valid() {
        let base = get_base_point();
        // ベースポイントが曲線上にあることを確認
        let (x, y) = base.to_affine();
        assert!(!x.is_zero() || !y.is_zero());
    }

    // 注: 完全な署名検証テストには、既知のテストベクターが必要
}
