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
