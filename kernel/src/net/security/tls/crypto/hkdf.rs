// tls/crypto/hkdf.rs - HKDF and TLS 1.3 Key Schedule (RFC 5869 / RFC 8446)

use super::hmac::{
    SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, hmac_sha256, hmac_sha256_parts, hmac_sha384,
    hmac_sha384_parts,
};

// ============================================================================
// HKDF-SHA256 (RFC 5869)
// ============================================================================

/// HKDF-Extract (RFC 5869 Section 2.2)
///
/// PRK = HMAC-Hash(salt, IKM)
///
/// If salt is empty, a zero-filled key of HashLen bytes is used.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_OUTPUT_SIZE] {
    let effective_salt = if salt.is_empty() {
        &[0u8; SHA256_OUTPUT_SIZE] as &[u8]
    } else {
        salt
    };
    hmac_sha256(effective_salt, ikm)
}

/// HKDF-Expand (RFC 5869 Section 2.3)
///
/// OKM = T(1) || T(2) || ... || T(N)
/// T(0) = empty string
/// T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
///
/// # Panics
/// Panics if length > 255 * HashLen (8160 bytes for SHA-256)
pub fn hkdf_expand(prk: &[u8; SHA256_OUTPUT_SIZE], info: &[u8], output: &mut [u8]) {
    assert!(
        output.len() <= 255 * SHA256_OUTPUT_SIZE,
        "HKDF-Expand: requested length too large"
    );

    let n = output.len().div_ceil(SHA256_OUTPUT_SIZE);
    let mut offset = 0usize;
    let mut t_prev = [0u8; SHA256_OUTPUT_SIZE];

    for i in 1..=n {
        let counter = [i as u8];
        let t_i = if offset == 0 {
            hmac_sha256_parts(prk, &[info, &counter])
        } else {
            hmac_sha256_parts(prk, &[&t_prev, info, &counter])
        };

        let copy_len = (output.len() - offset).min(SHA256_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&t_i[..copy_len]);
        offset += copy_len;
        t_prev = t_i;
    }
}

/// HKDF-Expand-Label for TLS 1.3 (RFC 8446 Section 7.1)
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// where HkdfLabel = struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// }
pub fn hkdf_expand_label(
    secret: &[u8; SHA256_OUTPUT_SIZE],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) {
    let tls_label_prefix = b"tls13 ";
    let full_label_len = tls_label_prefix.len() + label.len();
    assert!(
        output.len() <= u16::MAX as usize,
        "HKDF label length too large"
    );
    assert!(
        full_label_len <= u8::MAX as usize,
        "HKDF label label too large"
    );
    assert!(
        context.len() <= u8::MAX as usize,
        "HKDF label context too large"
    );

    let mut hkdf_label = [0u8; 514];
    let mut offset = 0usize;
    hkdf_label[offset..offset + 2].copy_from_slice(&(output.len() as u16).to_be_bytes());
    offset += 2;
    hkdf_label[offset] = full_label_len as u8;
    offset += 1;
    hkdf_label[offset..offset + tls_label_prefix.len()].copy_from_slice(tls_label_prefix);
    offset += tls_label_prefix.len();
    hkdf_label[offset..offset + label.len()].copy_from_slice(label);
    offset += label.len();
    hkdf_label[offset] = context.len() as u8;
    offset += 1;
    hkdf_label[offset..offset + context.len()].copy_from_slice(context);
    offset += context.len();

    hkdf_expand(secret, &hkdf_label[..offset], output)
}

// ============================================================================
// TLS 1.3 Key Schedule (RFC 8446 Section 7.1)
// ============================================================================

/// Derive-Secret (RFC 8446 Section 7.1)
///
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
///
/// `transcript_hash` は Messages のSHA-256ハッシュ値。
pub fn tls13_derive_secret(
    secret: &[u8; SHA256_OUTPUT_SIZE],
    label: &[u8],
    transcript_hash: &[u8; SHA256_OUTPUT_SIZE],
) -> [u8; SHA256_OUTPUT_SIZE] {
    let mut output = [0u8; SHA256_OUTPUT_SIZE];
    hkdf_expand_label(secret, label, transcript_hash, &mut output);
    output
}

/// TLS 1.3 鍵スケジュール: Early Secret を導出
///
/// Early Secret = HKDF-Extract(salt=0, IKM=PSK)
/// PSKなしの場合 IKM = ゼロ（32バイト）
pub fn tls13_early_secret(psk: Option<&[u8]>) -> [u8; SHA256_OUTPUT_SIZE] {
    let ikm = psk.unwrap_or(&[0u8; SHA256_OUTPUT_SIZE]);
    hkdf_extract(&[0u8; SHA256_OUTPUT_SIZE], ikm)
}

/// TLS 1.3 鍵スケジュール: Handshake Secret を導出
///
/// ```text
/// Derive-Secret(Early_Secret, "derived", "")
///       |
///       v
/// (EC)DHE -> HKDF-Extract = Handshake Secret
/// ```
pub fn tls13_handshake_secret(
    early_secret: &[u8; SHA256_OUTPUT_SIZE],
    shared_secret: &[u8],
) -> [u8; SHA256_OUTPUT_SIZE] {
    use crate::crypto::sha256;
    let empty_hash = sha256::compute(&[]);
    let derived = tls13_derive_secret(early_secret, b"derived", &empty_hash);
    hkdf_extract(&derived, shared_secret)
}

/// TLS 1.3 鍵スケジュール: Master Secret を導出
///
/// ```text
/// Derive-Secret(Handshake_Secret, "derived", "")
///       |
///       v
///   0 -> HKDF-Extract = Master Secret
/// ```
pub fn tls13_master_secret(
    handshake_secret: &[u8; SHA256_OUTPUT_SIZE],
) -> [u8; SHA256_OUTPUT_SIZE] {
    use crate::crypto::sha256;
    let empty_hash = sha256::compute(&[]);
    let derived = tls13_derive_secret(handshake_secret, b"derived", &empty_hash);
    hkdf_extract(&derived, &[0u8; SHA256_OUTPUT_SIZE])
}

/// TLS 1.3: トラフィック鍵のペアを導出
///
/// traffic_key = HKDF-Expand-Label(Secret, "key", "", key_length)
/// traffic_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length=12)
pub fn tls13_derive_traffic_keys(
    secret: &[u8; SHA256_OUTPUT_SIZE],
    key_out: &mut [u8],
    iv_out: &mut [u8; 12],
) {
    hkdf_expand_label(secret, b"key", b"", key_out);
    hkdf_expand_label(secret, b"iv", b"", iv_out);
}

/// TLS 1.3: Finished鍵を導出
///
/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
pub fn tls13_finished_key(base_key: &[u8; SHA256_OUTPUT_SIZE]) -> [u8; SHA256_OUTPUT_SIZE] {
    let mut output = [0u8; SHA256_OUTPUT_SIZE];
    hkdf_expand_label(base_key, b"finished", b"", &mut output);
    output
}

/// TLS 1.3: Finished verify_data を計算
///
/// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
pub fn tls13_verify_data(
    finished_key: &[u8; SHA256_OUTPUT_SIZE],
    transcript_hash: &[u8; SHA256_OUTPUT_SIZE],
) -> [u8; SHA256_OUTPUT_SIZE] {
    hmac_sha256(finished_key, transcript_hash)
}

// ============================================================================
// HKDF-SHA384 (RFC 5869) — TLS_AES_256_GCM_SHA384 用
// ============================================================================

/// HKDF-Extract using SHA-384  (PRK = HMAC-SHA384(salt, IKM))
pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; SHA384_OUTPUT_SIZE] {
    let effective_salt = if salt.is_empty() {
        &[0u8; SHA384_OUTPUT_SIZE] as &[u8]
    } else {
        salt
    };
    hmac_sha384(effective_salt, ikm)
}

/// HKDF-Expand using SHA-384  (RFC 5869 Section 2.3)
pub fn hkdf_expand_sha384(prk: &[u8; SHA384_OUTPUT_SIZE], info: &[u8], output: &mut [u8]) {
    assert!(
        output.len() <= 255 * SHA384_OUTPUT_SIZE,
        "HKDF-Expand-SHA384: requested length too large"
    );

    let n = output.len().div_ceil(SHA384_OUTPUT_SIZE);
    let mut offset = 0usize;
    let mut t_prev = [0u8; SHA384_OUTPUT_SIZE];

    for i in 1..=n {
        let counter = [i as u8];
        let t_i = if offset == 0 {
            hmac_sha384_parts(prk, &[info, &counter])
        } else {
            hmac_sha384_parts(prk, &[&t_prev, info, &counter])
        };

        let copy_len = (output.len() - offset).min(SHA384_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&t_i[..copy_len]);
        offset += copy_len;
        t_prev = t_i;
    }
}

/// HKDF-Expand-Label for TLS 1.3 using SHA-384 (RFC 8446 Section 7.1)
pub fn hkdf_expand_label_sha384(
    secret: &[u8; SHA384_OUTPUT_SIZE],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) {
    let tls_label_prefix = b"tls13 ";
    let full_label_len = tls_label_prefix.len() + label.len();
    assert!(
        output.len() <= u16::MAX as usize,
        "HKDF label length too large"
    );
    assert!(
        full_label_len <= u8::MAX as usize,
        "HKDF label label too large"
    );
    assert!(
        context.len() <= u8::MAX as usize,
        "HKDF label context too large"
    );

    let mut hkdf_label = [0u8; 514];
    let mut offset = 0usize;
    hkdf_label[offset..offset + 2].copy_from_slice(&(output.len() as u16).to_be_bytes());
    offset += 2;
    hkdf_label[offset] = full_label_len as u8;
    offset += 1;
    hkdf_label[offset..offset + tls_label_prefix.len()].copy_from_slice(tls_label_prefix);
    offset += tls_label_prefix.len();
    hkdf_label[offset..offset + label.len()].copy_from_slice(label);
    offset += label.len();
    hkdf_label[offset] = context.len() as u8;
    offset += 1;
    hkdf_label[offset..offset + context.len()].copy_from_slice(context);
    offset += context.len();

    hkdf_expand_sha384(secret, &hkdf_label[..offset], output)
}

/// Derive-Secret using SHA-384 for TLS 1.3
pub fn tls13_derive_secret_sha384(
    secret: &[u8; SHA384_OUTPUT_SIZE],
    label: &[u8],
    transcript_hash: &[u8; SHA384_OUTPUT_SIZE],
) -> [u8; SHA384_OUTPUT_SIZE] {
    let mut output = [0u8; SHA384_OUTPUT_SIZE];
    hkdf_expand_label_sha384(secret, label, transcript_hash, &mut output);
    output
}

/// TLS 1.3 Early Secret using SHA-384
pub fn tls13_early_secret_sha384(psk: Option<&[u8]>) -> [u8; SHA384_OUTPUT_SIZE] {
    let ikm = psk.unwrap_or(&[0u8; SHA384_OUTPUT_SIZE]);
    hkdf_extract_sha384(&[0u8; SHA384_OUTPUT_SIZE], ikm)
}

/// TLS 1.3 Handshake Secret using SHA-384
pub fn tls13_handshake_secret_sha384(
    early_secret: &[u8; SHA384_OUTPUT_SIZE],
    shared_secret: &[u8],
) -> [u8; SHA384_OUTPUT_SIZE] {
    use crate::crypto::sha384;
    let empty_hash = sha384::compute(&[]);
    let derived = tls13_derive_secret_sha384(early_secret, b"derived", &empty_hash);
    hkdf_extract_sha384(&derived, shared_secret)
}

/// TLS 1.3 Master Secret using SHA-384
pub fn tls13_master_secret_sha384(
    handshake_secret: &[u8; SHA384_OUTPUT_SIZE],
) -> [u8; SHA384_OUTPUT_SIZE] {
    use crate::crypto::sha384;
    let empty_hash = sha384::compute(&[]);
    let derived = tls13_derive_secret_sha384(handshake_secret, b"derived", &empty_hash);
    hkdf_extract_sha384(&derived, &[0u8; SHA384_OUTPUT_SIZE])
}

/// TLS 1.3 トラフィック鍵導出 using SHA-384
pub fn tls13_derive_traffic_keys_sha384(
    secret: &[u8; SHA384_OUTPUT_SIZE],
    key_out: &mut [u8],
    iv_out: &mut [u8; 12],
) {
    hkdf_expand_label_sha384(secret, b"key", b"", key_out);
    hkdf_expand_label_sha384(secret, b"iv", b"", iv_out);
}

/// TLS 1.3 Finished鍵導出 using SHA-384
pub fn tls13_finished_key_sha384(base_key: &[u8; SHA384_OUTPUT_SIZE]) -> [u8; SHA384_OUTPUT_SIZE] {
    let mut output = [0u8; SHA384_OUTPUT_SIZE];
    hkdf_expand_label_sha384(base_key, b"finished", b"", &mut output);
    output
}

/// TLS 1.3 Finished verify_data using SHA-384
pub fn tls13_verify_data_sha384(
    finished_key: &[u8; SHA384_OUTPUT_SIZE],
    transcript_hash: &[u8; SHA384_OUTPUT_SIZE],
) -> [u8; SHA384_OUTPUT_SIZE] {
    hmac_sha384(finished_key, transcript_hash)
}
