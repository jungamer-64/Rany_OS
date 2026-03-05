// ============================================================================
// src/crypto/ed25519.rs - Ed25519 Signature Verification
// ============================================================================
//!
//! Ed25519署名検証（ed25519-compactクレートのラッパー）
//!
//! ## 参照
//! - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
//! - FIPS 186-5: Digital Signature Standard (DSS)
//!
//! ## 実装
//! `ed25519-compact` クレートを使用し、no_std環境で動作します。
//! このクレートはcurve25519-dalekに依存せず、軽量な実装を提供します。
#![allow(dead_code)]
#[allow(unused_imports)]
use ed25519_compact::{PublicKey, Signature};

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
#[allow(unused_variables)]
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
#[allow(unused_variables)]
pub fn verify_message(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    // 公開鍵をパース
    let pk = match PublicKey::from_slice(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // 署名をパース
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 検証を実行
    pk.verify(message, &sig).is_ok()
}

/// 公開鍵が有効な形式かどうかを確認
///
/// # Arguments
/// * `public_key` - 32バイトの公開鍵
///
/// # Returns
/// 公開鍵が有効な場合true
#[allow(unused_variables)]
pub fn is_valid_public_key(public_key: &[u8; 32]) -> bool {
    // Reject the all-zero representation (defensive check); some `from_bytes`
    // implementations may accept non-canonical or zero values.
    if public_key.iter().all(|&b| b == 0) {
        return false;
    }
    PublicKey::from_slice(public_key).is_ok()
}
