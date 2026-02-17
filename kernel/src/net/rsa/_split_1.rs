use super::*;


pub fn rsa_pss_verify(
    key: &RsaPublicKey,
    hash_alg: HashAlgorithm,
    message_hash: &[u8],
    signature: &[u8],
) -> Result<(), RsaError> {
    let k = key.modulus.len();
    let h_len = hash_alg.digest_len();

    if signature.len() != k {
        return Err(RsaError::InvalidSignatureLength);
    }

    // Step 1: RSAVP1 (s^e mod n)
    let n = BigUint::from_be_bytes(key.modulus);
    let e = BigUint::from_be_bytes(key.exponent);
    let s = BigUint::from_be_bytes(signature);

    if s >= n {
        return Err(RsaError::InvalidSignatureValue);
    }

    let m = s.mod_exp(&e, &n);
    let em = m.to_be_bytes_padded(k);

    // Step 2: EMSA-PSS-VERIFY
    let em_len = em.len();
    if em_len < h_len + 2 {
        return Err(RsaError::InvalidPadding);
    }
    if em[em_len - 1] != 0xBC {
        return Err(RsaError::InvalidPadding);
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + h_len];

    let db = unmask_db(masked_db, h, db_len, hash_alg, em_len, k);

    let salt_start = find_pss_padding_separator(&db)?;
    let salt = &db[salt_start..];

    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    let mut m_prime = Vec::with_capacity(8 + h_len + salt.len());
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(message_hash);
    m_prime.extend_from_slice(salt);

    let h_prime = hash_compute(hash_alg, &m_prime);

    constant_time_hash_eq(h, &h_prime)
}

/// MGF1 マスク生成関数 (RFC 8017 Appendix B.2.1)
pub(crate) fn mgf1(seed: &[u8], length: usize, hash_alg: HashAlgorithm) -> Vec<u8> {
    let h_len = hash_alg.digest_len();
    let mut output = Vec::with_capacity(length + h_len);
    let mut counter: u32 = 0;

    while output.len() < length {
        let mut input = Vec::with_capacity(seed.len() + 4);
        input.extend_from_slice(seed);
        input.extend_from_slice(&counter.to_be_bytes());

        let hash = hash_compute(hash_alg, &input);
        output.extend_from_slice(&hash);
        counter += 1;
    }

    output.truncate(length);
    output
}

/// ハッシュ計算ヘルパー
pub(crate) fn hash_compute(hash_alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match hash_alg {
        HashAlgorithm::Sha256 => crate::loader::sha256::compute(data).to_vec(),
        HashAlgorithm::Sha384 => crate::loader::sha384::compute(data).to_vec(),
    }
}

/// カーネル環境用 擬似ランダムバイト生成
///
/// TSC (Time Stamp Counter) をベースに簡易ランダム値を生成。
/// 暗号学的に安全ではないが、カーネル初期段階で使用可能。
pub(crate) fn pseudo_random_byte(extra_entropy: u64) -> u8 {
    // TSC (or fallback) で基本エントロピーを取得
    let tsc = read_tsc();
    let mixed = tsc
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
        .wrapping_add(extra_entropy.wrapping_mul(2862933555777941757));
    (mixed >> 33) as u8
}

/// TSCを読み取る（x86_64 RDTSC命令）
pub(crate) fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
        }
        ((hi as u64) << 32) | lo as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // フォールバック: 定数ベース
        0x123456789ABCDEF0u64.wrapping_add(extra_entropy)
    }
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
mod tests;
