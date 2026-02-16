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
//!
//! ## セキュリティ特性
//! - 定時間実行（タイミング攻撃耐性）
//! - 弱い鍵の自動検出・拒否
//! - 秘密データの自動ワイプ（`DHOutput::Drop`）

#![allow(dead_code)]

use alloc::vec::Vec;
use ed25519_compact::x25519::{
    PublicKey as X25519PublicKey, SecretKey as X25519SecretKey,
};

// ============================================================================
// ECDH Group
// ============================================================================

/// サポートする名前付きグループ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhGroup {
    /// X25519 (RFC 7748) — TLS NamedGroup 0x001D
    X25519,
    // 将来拡張: Secp256r1, X448, Secp384r1
}

impl EcdhGroup {
    /// TLS NamedGroup値からEcdhGroupへ変換
    pub fn from_named_group(value: u16) -> Option<Self> {
        match value {
            0x001D => Some(EcdhGroup::X25519),
            _ => None,
        }
    }

    /// TLS NamedGroup値を返す
    pub fn to_named_group(self) -> u16 {
        match self {
            EcdhGroup::X25519 => 0x001D,
        }
    }

    /// 公開鍵のバイト長
    pub fn public_key_len(self) -> usize {
        match self {
            EcdhGroup::X25519 => 32,
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
        }
    }

    /// 使用しているグループを返す
    pub fn group(&self) -> EcdhGroup {
        match self {
            EcdhKeyPair::X25519 { .. } => EcdhGroup::X25519,
        }
    }

    /// 公開鍵をバイト列として取得
    ///
    /// TLSワイヤーフォーマット（ClientKeyExchange/KeyShare）用。
    /// X25519の場合は32バイトのu座標。
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            EcdhKeyPair::X25519 { pk, .. } => {
                let bytes: &[u8; 32] = pk;
                bytes.to_vec()
            }
        }
    }

    /// ピアの公開鍵からECDH共有秘密を計算
    ///
    /// 返り値はTLS pre-master secretとして使用される。
    /// `ed25519-compact` はクランプ処理を自動適用し、
    /// 結果がゼロ（弱い鍵）の場合はエラーを返す。
    ///
    /// # Errors
    /// - `EcdhError::InvalidPeerKey` — ピア公開鍵のパースに失敗
    /// - `EcdhError::SharedSecretFailed` — 共有秘密の計算に失敗（弱い鍵等）
    pub fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>, EcdhError> {
        match self {
            EcdhKeyPair::X25519 { sk, .. } => {
                let peer_pk = X25519PublicKey::from_slice(peer_public)
                    .map_err(|_| EcdhError::InvalidPeerKey)?;
                let dh_output = peer_pk.dh(sk).map_err(|_| EcdhError::SharedSecretFailed)?;
                let bytes: &[u8; 32] = &dh_output;
                Ok(bytes.to_vec())
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// X25519 鍵交換対称性テスト
    ///
    /// Alice.shared_secret(Bob.pk) == Bob.shared_secret(Alice.pk)
    #[test]
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
    #[test]
    fn test_x25519_public_key_length() {
        let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    /// X25519 グループ識別テスト
    #[test]
    fn test_x25519_group() {
        let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");
        assert_eq!(kp.group(), EcdhGroup::X25519);
    }

    /// NamedGroup変換テスト
    #[test]
    fn test_ecdh_group_from_named_group() {
        assert_eq!(EcdhGroup::from_named_group(0x001D), Some(EcdhGroup::X25519));
        assert_eq!(EcdhGroup::from_named_group(0x0017), None); // SECP256R1 — 未サポート
        assert_eq!(EcdhGroup::from_named_group(0x001E), None); // X448 — 未サポート
    }

    /// 不正なピア公開鍵の拒否テスト
    #[test]
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
    #[test]
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
}
