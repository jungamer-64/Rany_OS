use super::*;


// ============================================================================
// P-384 (secp384r1) Software Implementation
// ============================================================================

/// P-384 (secp384r1) 楕円曲線の純ソフトウェア実装
///
/// FIPS 186-4準拠のNIST P-384曲線演算を提供する。
/// ヤコビアン座標によるポイント演算とBigUintベースの
/// フィールド算術を実装している。
mod ecdh_group;
pub use ecdh_group::*;
#[allow(dead_code)]
pub mod p384 {
    use alloc::vec::Vec;

    /// P-384素数体の元（リトルエンディアン6×u64リム表現）
    ///
    /// p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct P384FieldElement {
        pub limbs: [u64; 6],
    }

    // p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    pub(super) const P: [u64; 6] = [
        0x00000000FFFFFFFF,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];

    // a = p - 3
    pub(super) const A_LIMBS: [u64; 6] = [
        0x00000000FFFFFFFC,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];

    // b (hex BE): B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
    pub(super) const B_LIMBS: [u64; 6] = [
        0x2A85C8EDD3EC2AEF,
        0xC656398D8A2ED19D,
        0x0314088F5013875A,
        0x181D9C6EFE814112,
        0x988E056BE3F82D19,
        0xB3312FA7E23EE7E4,
    ];

    // Gx (hex BE): AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    pub(super) const GX_LIMBS: [u64; 6] = [
        0x3A545E3872760AB7,
        0x5502F25DBF55296C,
        0x59F741E082542A38,
        0x6E1D3B628BA79B98,
        0x8EB1C71EF320AD74,
        0xAA87CA22BE8B0537,
    ];

    // Gy (hex BE): 3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
    pub(super) const GY_LIMBS: [u64; 6] = [
        0x7A431D7C90EA0E5F,
        0x0A60B1CE1D7E819D,
        0xE9DA3113B5F0B8C0,
        0xF8F41DBD289A147C,
        0x5D9E98BF9292DC29,
        0x3617DE4A96262C6F,
    ];

    // n (order, hex BE): FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    pub(super) const N: [u64; 6] = [
        0xECEC196ACCC52973,
        0x581A0DB248B0A77A,
        0xC7634D81F4372DDF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];

    impl P384FieldElement {
        /// ゼロ元
        pub const ZERO: Self = Self { limbs: [0; 6] };

        /// 単位元（1）
        pub const ONE: Self = Self {
            limbs: [1, 0, 0, 0, 0, 0],
        };

        /// 定数リムから生成
        pub const fn from_limbs(limbs: [u64; 6]) -> Self {
            Self { limbs }
        }

        /// ゼロ判定
        pub fn is_zero(&self) -> bool {
            self.limbs[0] == 0
                && self.limbs[1] == 0
                && self.limbs[2] == 0
                && self.limbs[3] == 0
                && self.limbs[4] == 0
                && self.limbs[5] == 0
        }

        /// フィールド加算 (mod p)
        pub fn add(&self, other: &Self) -> Self {
            let mut result = [0u64; 6];
            let mut carry: u64 = 0;

            for i in 0..6 {
                let sum = (self.limbs[i] as u128) + (other.limbs[i] as u128) + (carry as u128);
                result[i] = sum as u64;
                carry = (sum >> 64) as u64;
            }

            // 条件付きpの減算（結果がp以上の場合）
            let mut borrow: u64 = 0;
            let mut sub = [0u64; 6];
            for i in 0..6 {
                let diff = (result[i] as u128)
                    .wrapping_sub(P[i] as u128)
                    .wrapping_sub(borrow as u128);
                sub[i] = diff as u64;
                borrow = if diff >> 127 != 0 { 1 } else { 0 };
            }
            let use_sub = carry > 0 || borrow == 0;
            if use_sub {
                Self { limbs: sub }
            } else {
                Self { limbs: result }
            }
        }

        /// フィールド減算 (mod p)
        pub fn sub(&self, other: &Self) -> Self {
            let mut result = [0u64; 6];
            let mut borrow: u64 = 0;

            for i in 0..6 {
                let diff = (self.limbs[i] as u128)
                    .wrapping_sub(other.limbs[i] as u128)
                    .wrapping_sub(borrow as u128);
                result[i] = diff as u64;
                borrow = if diff >> 127 != 0 { 1 } else { 0 };
            }

            // アンダーフローした場合はpを加算
            if borrow != 0 {
                let mut carry: u64 = 0;
                for i in 0..6 {
                    let sum = (result[i] as u128) + (P[i] as u128) + (carry as u128);
                    result[i] = sum as u64;
                    carry = (sum >> 64) as u64;
                }
            }

            Self { limbs: result }
        }

        /// フィールド乗算 (mod p)
        ///
        /// スクールブック6x6乗算でu128中間値を使い768ビット積を生成後、
        /// BigUintベースの剰余演算で縮約する。
        pub fn mul(&self, other: &Self) -> Self {
            // スクールブック乗算 → 12リムの積
            let mut product = [0u64; 12];
            for i in 0..6 {
                let mut carry: u64 = 0;
                for j in 0..6 {
                    let wide = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                        + (product[i + j] as u128)
                        + (carry as u128);
                    product[i + j] = wide as u64;
                    carry = (wide >> 64) as u64;
                }
                product[i + 6] = carry;
            }

            reduce_mod_p384(&product)
        }

        /// フィールド二乗 (mod p)
        pub fn square(&self) -> Self {
            self.mul(self)
        }

        /// フィールド逆元 (mod p)
        ///
        /// フェルマーの小定理によるa^(p-2)を二乗と乗算の繰り返しで計算する。
        pub fn inv(&self) -> Self {
            let p_minus_2: [u64; 6] = [
                0x00000000FFFFFFFD,
                0xFFFFFFFF00000000,
                0xFFFFFFFFFFFFFFFE,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ];

            let mut result = Self::ONE;
            let mut base = *self;

            for i in 0..6 {
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

        /// フィールド否定 (mod p)
        ///
        /// 非ゼロならp - selfを返す。ゼロの場合はゼロを返す。
        pub fn negate(&self) -> Self {
            if self.is_zero() {
                return Self::ZERO;
            }
            let p_fe = Self::from_limbs(P);
            p_fe.sub(self)
        }

        /// ビッグエンディアン48バイトからフィールド要素を生成
        pub fn from_be_bytes(bytes: &[u8; 48]) -> Self {
            let mut limbs = [0u64; 6];
            // bytes[0..8] → 最上位リム (limbs[5])
            // bytes[8..16] → limbs[4]
            // ...
            // bytes[40..48] → 最下位リム (limbs[0])
            for i in 0..6 {
                let offset = (5 - i) * 8;
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

        /// ビッグエンディアン48バイトへエンコード
        pub fn to_be_bytes(&self) -> [u8; 48] {
            let mut out = [0u8; 48];
            for i in 0..6 {
                let offset = (5 - i) * 8;
                let bytes = self.limbs[i].to_be_bytes();
                out[offset..offset + 8].copy_from_slice(&bytes);
            }
            out
        }
    }

    /// BigUintベースのP-384剰余リダクション
    ///
    /// 768ビット積（12リム）をP-384素数で縮約する。
    pub(super) fn reduce_mod_p384(product: &[u64; 12]) -> P384FieldElement {
        // 12 u64リム（LE）をビッグエンディアンバイト列に変換
        let mut be_bytes = [0u8; 96];
        for i in 0..12 {
            let bytes = product[11 - i].to_be_bytes();
            be_bytes[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        let prod_big = crate::net::rsa::BigUint::from_be_bytes(&be_bytes);

        // PをBigUintに変換
        let p_fe = P384FieldElement::from_limbs(P);
        let p_bytes = p_fe.to_be_bytes();
        let p_big = crate::net::rsa::BigUint::from_be_bytes(&p_bytes);

        let result = prod_big.rem(&p_big);
        let result_bytes = result.to_be_bytes_padded(48);

        P384FieldElement::from_be_bytes(&{
            let mut arr = [0u8; 48];
            let len = result_bytes.len();
            if len >= 48 {
                arr.copy_from_slice(&result_bytes[len - 48..]);
            } else {
                arr[48 - len..].copy_from_slice(&result_bytes);
            }
            arr
        })
    }

    // ========================================================================
    // P-384 ポイント演算（ヤコビアン座標）
    // ========================================================================

    /// P-384曲線上の点（ヤコビアン座標）
    ///
    /// アフィン座標 (x, y) は (X/Z^2, Y/Z^3) として表現される。
    /// 無限遠点（単位元）は Z = 0 で表す。
    #[derive(Clone, Copy, Debug)]
    pub struct P384Point {
        pub x: P384FieldElement,
        pub y: P384FieldElement,
        pub z: P384FieldElement,
    }

    impl P384Point {
        /// 無限遠点（単位元）
        pub fn identity() -> Self {
            Self {
                x: P384FieldElement::ONE,
                y: P384FieldElement::ONE,
                z: P384FieldElement::ZERO,
            }
        }

        /// ベースポイント（生成元）G
        pub fn generator() -> Self {
            Self {
                x: P384FieldElement::from_limbs(GX_LIMBS),
                y: P384FieldElement::from_limbs(GY_LIMBS),
                z: P384FieldElement::ONE,
            }
        }

        /// アフィン座標から生成
        pub fn from_affine(x: P384FieldElement, y: P384FieldElement) -> Self {
            Self {
                x,
                y,
                z: P384FieldElement::ONE,
            }
        }

        /// 無限遠点かどうか判定
        pub fn is_identity(&self) -> bool {
            self.z.is_zero()
        }

        /// アフィン座標 (x, y) を取得
        pub fn to_affine(&self) -> Option<(P384FieldElement, P384FieldElement)> {
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
        /// M = 3*(X + Z^2)*(X - Z^2)
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
        pub fn scalar_mul(&self, scalar: &[u8; 48]) -> Self {
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
        pub fn is_on_curve(&self) -> bool {
            if self.is_identity() {
                return true;
            }

            let Some((x, y)) = self.to_affine() else {
                return false;
            };

            let a = P384FieldElement::from_limbs(A_LIMBS);
            let b = P384FieldElement::from_limbs(B_LIMBS);

            // y² = x³ + ax + b
            let y2 = y.square();
            let x3 = x.square().mul(&x);
            let ax = a.mul(&x);
            let rhs = x3.add(&ax).add(&b);

            y2 == rhs
        }
    }

    /// 非圧縮公開鍵（04 || x || y）をパースしてP384Pointに変換
    ///
    /// 97バイトの非圧縮フォーマットのみサポート。
    pub fn parse_uncompressed_point_384(bytes: &[u8]) -> Option<P384Point> {
        if bytes.len() != 97 || bytes[0] != 0x04 {
            return None;
        }

        let mut x_bytes = [0u8; 48];
        let mut y_bytes = [0u8; 48];
        x_bytes.copy_from_slice(&bytes[1..49]);
        y_bytes.copy_from_slice(&bytes[49..97]);

        let x = P384FieldElement::from_be_bytes(&x_bytes);
        let y = P384FieldElement::from_be_bytes(&y_bytes);

        let point = P384Point::from_affine(x, y);

        if !point.is_on_curve() {
            return None;
        }

        Some(point)
    }

    /// ベースポイントGのスカラー倍算 [k]G
    pub fn scalar_base_mul_384(scalar: &[u8; 48]) -> P384Point {
        let g = P384Point::generator();
        g.scalar_mul(scalar)
    }

    /// スカラーがP-384の群位数nの範囲内か検証 (1 <= k < n)
    pub fn scalar_is_valid_384(scalar: &[u8; 48]) -> bool {
        // ゼロでないことを確認
        let all_zero = scalar.iter().all(|&b| b == 0);
        if all_zero {
            return false;
        }

        // k < n を確認 (ビッグエンディアン比較)
        let n_be: [u8; 48] = {
            let fe = P384FieldElement::from_limbs(N);
            fe.to_be_bytes()
        };

        for i in 0..48 {
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

    // ========================================================================
    // P-384 スカラー（群位数 n）上の算術演算
    // ========================================================================

    /// P-384群位数 n 上での乗算: (a * b) mod n
    pub fn scalar_mul_mod_n_384(a: &[u8; 48], b: &[u8; 48]) -> [u8; 48] {
        let a_big = crate::net::rsa::BigUint::from_be_bytes(a);
        let b_big = crate::net::rsa::BigUint::from_be_bytes(b);

        // a * b
        let product = a_big.mul(&b_big);

        // mod n
        let n_fe = P384FieldElement::from_limbs(N);
        let n_bytes = n_fe.to_be_bytes();
        let n_big = crate::net::rsa::BigUint::from_be_bytes(&n_bytes);

        let rem = product.rem(&n_big);
        let rem_bytes = rem.to_be_bytes_padded(48);

        let mut out = [0u8; 48];
        let len = rem_bytes.len();
        if len >= 48 {
            out.copy_from_slice(&rem_bytes[len - 48..]);
        } else {
            out[48 - len..].copy_from_slice(&rem_bytes);
        }
        out
    }

    /// P-384群位数 n 上でのモジュラ逆元: a^{-1} mod n
    /// フェルマーの小定理: a^{-1} = a^{n-2} mod n
    pub fn scalar_inv_mod_n_384(a: &[u8; 48]) -> [u8; 48] {
        // n - 2 を BigUint 経由で計算
        let n_fe = P384FieldElement::from_limbs(N);
        let n_bytes = n_fe.to_be_bytes();
        let n_big = crate::net::rsa::BigUint::from_be_bytes(&n_bytes);
        let two_big = crate::net::rsa::BigUint::from_be_bytes(&[2]);
        let nm2 = n_big.sub(&two_big);
        let nm2_bytes = nm2.to_be_bytes();

        let mut exp = [0u8; 48];
        if nm2_bytes.len() <= 48 {
            let start = 48 - nm2_bytes.len();
            exp[start..].copy_from_slice(&nm2_bytes);
        }

        // a^(n-2) mod n をバイナリ法で計算
        scalar_pow_mod_n_384(a, &exp)
    }

    /// P-384群位数 n 上での冪乗: base^exp mod n
    pub(super) fn scalar_pow_mod_n_384(base: &[u8; 48], exp: &[u8; 48]) -> [u8; 48] {
        let mut result = [0u8; 48];
        result[47] = 1; // 1

        let base_copy = *base;

        // MSBからの二進法冪乗
        let mut started = false;
        for byte_idx in 0..48 {
            for bit_idx in (0..8).rev() {
                if started {
                    result = scalar_mul_mod_n_384(&result, &result);
                }
                if (exp[byte_idx] >> bit_idx) & 1 == 1 {
                    if started {
                        result = scalar_mul_mod_n_384(&result, &base_copy);
                    } else {
                        result = base_copy;
                        started = true;
                    }
                }
            }
        }
        result
    }

    // ========================================================================
    // ECDSA P-384 署名検証 (FIPS 186-4 Section 4.1.4)
    // ========================================================================

    /// DER INTEGERを48バイト固定長に正規化
    pub(super) fn normalize_integer_48(data: &[u8]) -> Result<[u8; 48], EcdsaError> {
        // 先頭の0x00を除去
        let mut stripped = data;
        while stripped.len() > 1 && stripped[0] == 0 {
            stripped = &stripped[1..];
        }

        if stripped.len() > 48 {
            return Err(EcdsaError::InvalidSignature);
        }

        let mut result = [0u8; 48];
        let start = 48 - stripped.len();
        result[start..].copy_from_slice(stripped);
        Ok(result)
    }

    /// DERエンコードされたECDSA署名をパース（P-384用）
    /// DER SEQUENCE ヘッダーをデコードし、(シーケンス長, データ開始位置)を返す
    pub(super) fn decode_der_sequence_header(der: &[u8]) -> Result<(usize, usize), EcdsaError> {
        if der.len() < 6 || der[0] != 0x30 {
            return Err(EcdsaError::InvalidSignature);
        }

        if der[1] & 0x80 == 0 {
            Ok((der[1] as usize, 2))
        } else if der[1] == 0x81 {
            if der.len() < 3 {
                return Err(EcdsaError::InvalidSignature);
            }
            Ok((der[2] as usize, 3))
        } else {
            Err(EcdsaError::InvalidSignature)
        }
    }

    /// DER INTEGERを読み取り、(データスライス, 次のオフセット)を返す
    pub(super) fn read_der_integer<'a>(der: &'a [u8], pos: usize) -> Result<(&'a [u8], usize), EcdsaError> {
        if pos >= der.len() || der[pos] != 0x02 {
            return Err(EcdsaError::InvalidSignature);
        }
        let len = der[pos + 1] as usize;
        let start = pos + 2;
        if start + len > der.len() {
            return Err(EcdsaError::InvalidSignature);
        }
        Ok((&der[start..start + len], start + len))
    }

    pub(super) fn parse_ecdsa_signature_der_384(der: &[u8]) -> Result<([u8; 48], [u8; 48]), EcdsaError> {
        let (seq_len, pos) = decode_der_sequence_header(der)?;

        if der.len() < pos + seq_len {
            return Err(EcdsaError::InvalidSignature);
        }

        let (r_data, next_pos) = read_der_integer(der, pos)?;
        let (s_data, _) = read_der_integer(der, next_pos)?;

        let r = normalize_integer_48(r_data)?;
        let s = normalize_integer_48(s_data)?;

        Ok((r, s))
    }

    /// Validate and parse ECDSA P-384 inputs (public key + DER signature).
    pub(super) fn validate_ecdsa_p384_inputs(
        public_key: &[u8],
        signature_der: &[u8],
    ) -> Result<(P384Point, [u8; 48], [u8; 48]), EcdsaError> {
        let q = parse_uncompressed_point_384(public_key).ok_or(EcdsaError::InvalidPublicKey)?;
        if !q.is_on_curve() || q.is_identity() {
            return Err(EcdsaError::InvalidPublicKey);
        }
        let (r_bytes, s_bytes) = parse_ecdsa_signature_der_384(signature_der)?;
        if !scalar_is_valid_384(&r_bytes) || !scalar_is_valid_384(&s_bytes) {
            return Err(EcdsaError::InvalidSignature);
        }
        Ok((q, r_bytes, s_bytes))
    }

    /// Constant-time comparison of a 48-byte array against a variable-length slice.
    pub(super) fn constant_time_eq_48(a: &[u8; 48], b: &[u8]) -> bool {
        let mut diff = 0u8;
        for i in 0..48 {
            if i < b.len() {
                diff |= a[i] ^ b[i];
            } else {
                diff |= a[i];
            }
        }
        diff == 0
    }

    /// ECDSA P-384 署名検証
    ///
    /// # Arguments
    /// * `public_key` - 非圧縮公開鍵 (97バイト: 04 || x || y)
    /// * `message_hash` - メッセージのSHA-384ハッシュ (48バイト)
    /// * `signature_der` - DERエンコードされたECDSA署名
    ///
    /// # Returns
    /// 検証成功なら `Ok(())`、失敗なら `Err`
    pub fn ecdsa_p384_verify(
        public_key: &[u8],
        message_hash: &[u8; 48],
        signature_der: &[u8],
    ) -> Result<(), EcdsaError> {
        let (q, r_bytes, s_bytes) = validate_ecdsa_p384_inputs(public_key, signature_der)?;

        // s_inv = s^{-1} mod n
        let s_inv = scalar_inv_mod_n_384(&s_bytes);

        // u1 = hash * s_inv mod n
        let u1 = scalar_mul_mod_n_384(message_hash, &s_inv);

        // u2 = r * s_inv mod n
        let u2 = scalar_mul_mod_n_384(&r_bytes, &s_inv);

        // R' = u1*G + u2*Q
        let u1g = scalar_base_mul_384(&u1);
        let u2q = q.scalar_mul(&u2);
        let r_point = u1g.add(&u2q);

        if r_point.is_identity() {
            return Err(EcdsaError::InvalidSignature);
        }

        // x座標を取得
        let (rx, _ry) = r_point
            .to_affine()
            .ok_or(EcdsaError::InvalidSignature)?;

        let rx_bytes = rx.to_be_bytes();

        // r' = x mod n
        let n_fe = P384FieldElement::from_limbs(N);
        let n_bytes = n_fe.to_be_bytes();
        let rx_big = crate::net::rsa::BigUint::from_be_bytes(&rx_bytes);
        let n_big = crate::net::rsa::BigUint::from_be_bytes(&n_bytes);
        let rx_mod_n = rx_big.rem(&n_big);
        let rx_mod_n_bytes = rx_mod_n.to_be_bytes_padded(48);

        // r == r' ?
        if !constant_time_eq_48(&r_bytes, &rx_mod_n_bytes) {
            return Err(EcdsaError::VerificationFailed);
        }

        Ok(())
    }

    /// ECDSA検証エラー
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EcdsaError {
        /// 公開鍵が不正
        InvalidPublicKey,
        /// 署名が不正（フォーマットエラーまたは範囲外）
        InvalidSignature,
        /// 署名検証失敗
        VerificationFailed,
    }
}
