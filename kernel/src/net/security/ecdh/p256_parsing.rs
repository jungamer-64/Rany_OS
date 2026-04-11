use super::p256::{N, P256FieldElement, P256Point};

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

    let x = P256FieldElement::from_be_bytes(&x_bytes)?;
    let y = P256FieldElement::from_be_bytes(&y_bytes)?;

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

// ========================================================================
// P-256 スカラー（群位数 n）上の算術演算
// ========================================================================

/// P-256群位数 n 上での加算: (a + b) mod n
pub fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // ビッグエンディアンでu64リム4個に変換
    let mut a_limbs = [0u64; 4];
    let mut b_limbs = [0u64; 4];
    for i in 0..4 {
        a_limbs[3 - i] = u64::from_be_bytes([
            a[i * 8],
            a[i * 8 + 1],
            a[i * 8 + 2],
            a[i * 8 + 3],
            a[i * 8 + 4],
            a[i * 8 + 5],
            a[i * 8 + 6],
            a[i * 8 + 7],
        ]);
        b_limbs[3 - i] = u64::from_be_bytes([
            b[i * 8],
            b[i * 8 + 1],
            b[i * 8 + 2],
            b[i * 8 + 3],
            b[i * 8 + 4],
            b[i * 8 + 5],
            b[i * 8 + 6],
            b[i * 8 + 7],
        ]);
    }

    // a + b (carry付き)
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let sum = (a_limbs[i] as u128) + (b_limbs[i] as u128) + (carry as u128);
        result[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }

    // mod n: result >= n ならnを減算
    let mut borrow = 0u64;
    let mut sub = [0u64; 4];
    for i in 0..4 {
        let diff = (result[i] as u128)
            .wrapping_sub(N[i] as u128)
            .wrapping_sub(borrow as u128);
        sub[i] = diff as u64;
        borrow = if diff >> 127 != 0 { 1 } else { 0 };
    }

    // carry > 0 or (carry==0 and borrow==0) → use sub
    let use_sub = carry > 0 || borrow == 0;
    let final_limbs = if use_sub { sub } else { result };

    // リトルエンディアンリムからビッグエンディアンバイト列に変換
    let mut out = [0u8; 32];
    for i in 0..4 {
        let bytes = final_limbs[3 - i].to_be_bytes();
        out[i * 8..i * 8 + 8].copy_from_slice(&bytes);
    }
    out
}

/// P-256群位数 n 上での乗算: (a * b) mod n
pub fn scalar_mul_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // ビッグエンディアンu64リム（リトルエンディアン順）に変換
    let mut a_limbs = [0u64; 4];
    let mut b_limbs = [0u64; 4];
    for i in 0..4 {
        a_limbs[3 - i] = u64::from_be_bytes([
            a[i * 8],
            a[i * 8 + 1],
            a[i * 8 + 2],
            a[i * 8 + 3],
            a[i * 8 + 4],
            a[i * 8 + 5],
            a[i * 8 + 6],
            a[i * 8 + 7],
        ]);
        b_limbs[3 - i] = u64::from_be_bytes([
            b[i * 8],
            b[i * 8 + 1],
            b[i * 8 + 2],
            b[i * 8 + 3],
            b[i * 8 + 4],
            b[i * 8 + 5],
            b[i * 8 + 6],
            b[i * 8 + 7],
        ]);
    }

    // 4×4リム乗算 → 8リム積
    let mut product = [0u128; 8];
    for i in 0..4 {
        for j in 0..4 {
            product[i + j] += (a_limbs[i] as u128) * (b_limbs[j] as u128);
        }
    }

    // キャリー伝播
    let mut prod64 = [0u64; 8];
    let mut carry = 0u128;
    for i in 0..8 {
        let val = product[i] + carry;
        prod64[i] = val as u64;
        carry = val >> 64;
    }

    // Barrett reduction mod n
    // 簡易実装: 繰り返し減算（最大512ビット / 256ビット）
    scalar_reduce_mod_n(&prod64)
}

/// 512ビット値を P-256 群位数 n で剰余演算
pub(crate) fn scalar_reduce_mod_n(val: &[u64; 8]) -> [u8; 32] {
    // 簡易実装: ロングディビジョンの代わりに
    // BigUint相当の処理を行う

    // val をビッグエンディアンのバイト列に変換
    let mut bytes = [0u8; 64];
    for i in 0..8 {
        let be = val[7 - i].to_be_bytes();
        bytes[i * 8..i * 8 + 8].copy_from_slice(&be);
    }

    // rsa::BigUint を使って mod n を計算
    let val_big = crate::net::security::rsa::BigUint::from_be_bytes(&bytes);
    let n_fe = P256FieldElement::from_limbs(N);
    let n_bytes = n_fe.to_be_bytes();
    let n_big = crate::net::security::rsa::BigUint::from_be_bytes(&n_bytes);

    let mut out = [0u8; 32];
    val_big.rem(&n_big).write_be_bytes_padded(&mut out);
    out
}

/// P-256群位数 n 上でのモジュラ逆元: a^{-1} mod n
/// フェルマーの小定理: a^{-1} = a^{n-2} mod n
pub fn scalar_inv_mod_n(a: &[u8; 32]) -> [u8; 32] {
    // n - 2 を計算
    let n_fe = P256FieldElement::from_limbs(N);
    let n_bytes = n_fe.to_be_bytes();
    let mut n_minus_2 = [0u8; 32];
    n_minus_2.copy_from_slice(&n_bytes);

    // n - 2 を BigUint 経由で計算
    let n_big = crate::net::security::rsa::BigUint::from_be_bytes(&n_bytes);
    let two_big = crate::net::security::rsa::BigUint::from_be_bytes(&[2]);
    let mut exp = [0u8; 32];
    n_big.sub(&two_big).write_be_bytes_padded(&mut exp);

    // a^(n-2) mod n をバイナリ法で計算
    scalar_pow_mod_n(a, &exp)
}

/// P-256群位数 n 上での冪乗: base^exp mod n (Constant-time implementation)
pub(crate) fn scalar_pow_mod_n(base: &[u8; 32], exp: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[31] = 1; // result = 1

    let base_copy = *base;

    // 固定回数 (256回) のループで定時間性を確保
    for i in (0..256).rev() {
        // result = result^2 mod n
        result = scalar_mul_mod_n(&result, &result);

        // bit = exp[i]
        let byte_idx = 31 - (i / 8);
        let bit_idx = i % 8;
        let bit = (exp[byte_idx] >> bit_idx) & 1;

        // temp = result * base mod n
        let multiplied = scalar_mul_mod_n(&result, &base_copy);

        // if bit == 1 { result = multiplied } (定時間選択)
        let mask = 0u8.wrapping_sub(bit as u8);
        for j in 0..32 {
            result[j] ^= (result[j] ^ multiplied[j]) & mask;
        }
    }
    result
}

// ========================================================================
// ECDSA P-256 署名検証 (FIPS 186-4 Section 4.1.4)
// ========================================================================

/// 検証ポイントのx座標をrと比較
pub(crate) fn verify_r_equals_x(r_bytes: &[u8; 32], r_point: &P256Point) -> Result<(), EcdsaError> {
    if r_point.is_identity() {
        return Err(EcdsaError::InvalidSignature);
    }

    // x座標を取得
    let (rx, _ry) = r_point.to_affine().ok_or(EcdsaError::InvalidSignature)?;

    let rx_bytes = rx.to_be_bytes();

    // r' = x mod n
    // (P-256では p > n なので x mod n が必要)
    let n_fe = P256FieldElement::from_limbs(N);
    let n_bytes = n_fe.to_be_bytes();
    let rx_big = crate::net::security::rsa::BigUint::from_be_bytes(&rx_bytes);
    let n_big = crate::net::security::rsa::BigUint::from_be_bytes(&n_bytes);
    let mut rx_mod_n_bytes = [0u8; 32];
    rx_big.rem(&n_big).write_be_bytes_padded(&mut rx_mod_n_bytes);

    // r == r' ?
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= r_bytes[i] ^ rx_mod_n_bytes[i];
    }

    if diff != 0 {
        return Err(EcdsaError::VerificationFailed);
    }

    Ok(())
}

/// ECDSA P-256 署名検証
///
/// # Arguments
/// * `public_key` - 非圧縮公開鍵 (65バイト: 04 || x || y)
/// * `message_hash` - メッセージのSHA-256ハッシュ (32バイト)
/// * `signature_der` - DERエンコードされたECDSA署名
///
/// # Returns
/// 検証成功なら `Ok(())`、失敗なら `Err`
pub fn ecdsa_p256_verify(
    public_key: &[u8],
    message_hash: &[u8; 32],
    signature_der: &[u8],
) -> Result<(), EcdsaError> {
    // 公開鍵をパース
    let q = parse_uncompressed_point(public_key).ok_or(EcdsaError::InvalidPublicKey)?;

    if !q.is_on_curve() || q.is_identity() {
        return Err(EcdsaError::InvalidPublicKey);
    }

    // 署名をDERからパース (r, s)
    let (r_bytes, s_bytes) = parse_ecdsa_signature_der(signature_der)?;

    // r, s が [1, n-1] の範囲内か確認
    if !scalar_is_valid(&r_bytes) || !scalar_is_valid(&s_bytes) {
        return Err(EcdsaError::InvalidSignature);
    }

    // s_inv = s^{-1} mod n
    let s_inv = scalar_inv_mod_n(&s_bytes);

    // u1 = hash * s_inv mod n
    let u1 = scalar_mul_mod_n(message_hash, &s_inv);

    // u2 = r * s_inv mod n
    let u2 = scalar_mul_mod_n(&r_bytes, &s_inv);

    // R' = u1*G + u2*Q
    let u1g = scalar_base_mul(&u1);
    let u2q = q.scalar_mul(&u2);
    let r_point = u1g.add(&u2q);

    verify_r_equals_x(&r_bytes, &r_point)
}

/// DER INTEGER フィールドを1つパースし、位置を進める
pub(crate) fn parse_der_integer<'a>(
    der: &'a [u8],
    pos: &mut usize,
) -> Result<&'a [u8], EcdsaError> {
    if *pos >= der.len() || der[*pos] != 0x02 {
        return Err(EcdsaError::InvalidSignature);
    }
    *pos += 1;
    let len = der[*pos] as usize;
    *pos += 1;
    if *pos + len > der.len() {
        return Err(EcdsaError::InvalidSignature);
    }
    let data = &der[*pos..*pos + len];
    *pos += len;
    Ok(data)
}

/// DERエンコードされたECDSA署名をパース
///
/// ECDSA-Sig-Value ::= SEQUENCE {
///   r INTEGER,
///   s INTEGER
/// }
/// Validate the DER SEQUENCE header for an ECDSA signature.
/// Returns the sequence body start position and length.
pub(crate) fn validate_der_sequence_header(der: &[u8]) -> Result<usize, EcdsaError> {
    if der.len() < 6 || der[0] != 0x30 {
        return Err(EcdsaError::InvalidSignature);
    }
    let seq_len = if der[1] & 0x80 == 0 {
        der[1] as usize
    } else {
        return Err(EcdsaError::InvalidSignature);
    };
    if der.len() < 2 + seq_len {
        return Err(EcdsaError::InvalidSignature);
    }
    Ok(seq_len)
}

pub(crate) fn parse_ecdsa_signature_der(der: &[u8]) -> Result<([u8; 32], [u8; 32]), EcdsaError> {
    let _seq_len = validate_der_sequence_header(der)?;

    let mut pos = 2;
    let r_data = parse_der_integer(der, &mut pos)?;
    let s_data = parse_der_integer(der, &mut pos)?;

    // r, s を32バイトに正規化（先頭0x00パディング除去、左パディング）
    let r = normalize_integer_32(r_data)?;
    let s = normalize_integer_32(s_data)?;

    Ok((r, s))
}

/// DER INTEGERを32バイト固定長に正規化
pub(crate) fn normalize_integer_32(data: &[u8]) -> Result<[u8; 32], EcdsaError> {
    // 先頭の0x00を除去
    let mut stripped = data;
    while stripped.len() > 1 && stripped[0] == 0 {
        stripped = &stripped[1..];
    }

    if stripped.len() > 32 {
        return Err(EcdsaError::InvalidSignature);
    }

    let mut result = [0u8; 32];
    let start = 32 - stripped.len();
    result[start..].copy_from_slice(stripped);
    Ok(result)
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
