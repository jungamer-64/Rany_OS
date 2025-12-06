// ============================================================================
// src/loader/ed25519.rs - Ed25519 Signature Verification
// 設計書 3.3: コンパイラ署名とロード時検証
// ============================================================================
//!
//! Ed25519署名検証（ed25519-dalekクレートのラッパー）
//!
//! ## 参照
//! - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
//! - FIPS 186-5: Digital Signature Standard (DSS)
//!
//! ## 実装
//! 監査済みの `ed25519-dalek` クレートを使用し、no_std環境で動作します。
//! このクレートは広く使用され、暗号セキュリティの専門家によるレビューを受けています。

use ed25519_dalek::{Signature, VerifyingKey, Verifier};

/// Ed25519署名を検証（pre-hashed message用）
///
/// 署名対象データがすでにハッシュ済みの場合に使用します。
/// 内部的には、ハッシュ値をそのままメッセージとして扱います。
///
/// # Arguments
/// * `public_key` - 32バイトの公開鍵
/// * `message` - 署名対象のメッセージ（ハッシュ済み32バイト）
/// * `signature` - 64バイトの署名
///
/// # Returns
/// 署名が有効な場合true
///
/// # Note
/// この関数はハッシュ済みメッセージを直接署名対象として検証します。
/// 通常のEd25519検証（メッセージを内部でハッシュする方式）には
/// `verify_message`関数を使用してください。
pub fn verify(public_key: &[u8; 32], message: &[u8; 32], signature: &[u8; 64]) -> bool {
    // ハッシュ済みメッセージをそのまま検証
    // 注：これはハッシュ済みデータをメッセージとして扱う
    verify_message(public_key, message, signature)
}

/// 公開鍵とメッセージから署名を検証（メッセージ全体を渡す場合）
///
/// 通常のEd25519検証。メッセージは内部でSHA-512でハッシュされる。
///
/// # Arguments
/// * `public_key` - 32バイトの公開鍵
/// * `message` - 署名対象のメッセージ
/// * `signature` - 64バイトの署名
///
/// # Returns
/// 署名が有効な場合true
pub fn verify_message(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    // 公開鍵をパース
    let verifying_key = match VerifyingKey::from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // 署名をパース
    let sig = Signature::from_bytes(signature);

    // 検証を実行
    verifying_key.verify(message, &sig).is_ok()
}

/// 公開鍵が有効な形式かどうかを確認
///
/// # Arguments
/// * `public_key` - 32バイトの公開鍵
///
/// # Returns
/// 公開鍵が有効な場合true
pub fn is_valid_public_key(public_key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_public_key() {
        // ゼロの公開鍵は無効
        let zero_key = [0u8; 32];
        assert!(!is_valid_public_key(&zero_key));
    }

    #[test]
    fn test_signature_format() {
        // 無効な署名でのverify呼び出しがpanicしないことを確認
        let dummy_key = [0u8; 32];
        let dummy_message = [0u8; 32];
        let dummy_sig = [0u8; 64];
        
        // panicせずにfalseを返すことを確認
        let result = verify(&dummy_key, &dummy_message, &dummy_sig);
        assert!(!result);
    }

    // RFC 8032のテストベクター（test vector 1）
    #[test]
    fn test_rfc8032_vector1() {
        // 秘密鍵（使用しない、参考用）: 
        // 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
        
        // 公開鍵
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
            0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        
        // メッセージ: 空
        let message: &[u8] = b"";
        
        // 署名
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        
        assert!(verify_message(&public_key, message, &signature));
    }
}
