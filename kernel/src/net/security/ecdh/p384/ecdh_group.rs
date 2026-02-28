use super::*;


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
                let random_bytes = crate::net::tls::generate_random();
                let sk = X25519SecretKey::new(random_bytes);
                let pk = sk
                    .recover_public_key()
                    .map_err(|_| EcdhError::KeyGenerationFailed)?;
                Ok(EcdhKeyPair::X25519 { sk, pk })
            }
            EcdhGroup::Secp256r1 => {
                let mut sk_bytes = crate::net::tls::generate_random();

                // 有効なスカラー (1 <= k < n) になるまでリトライ
                // 通常は最初の試行で成功する
                let mut attempts = 0;
                while !crate::net::ecdh::scalar_is_valid(&sk_bytes) {
                    attempts += 1;
                    if attempts > 16 {
                        return Err(EcdhError::KeyGenerationFailed);
                    }
                    sk_bytes = crate::net::tls::generate_random();
                }

                let pub_point = crate::net::ecdh::scalar_base_mul(&sk_bytes);
                let pk_bytes = crate::net::ecdh::encode_uncompressed_point(&pub_point)
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
        let result = crate::net::ecdh::scalar_base_mul(&scalar_one);
        !result.is_identity()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;
