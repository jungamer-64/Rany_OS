// ============================================================================
// src/loader/signature.rs - Cell Signature Verification
// 設計書 3.3: コンパイラ署名とロード時検証
// ============================================================================
//!
//! # セル署名検証システム
//!
//! ExoRustのセキュリティモデルにおいて、セルの署名検証は重要な役割を果たす。
//!
//! ## 署名フロー
//! 1. コンパイラがセルをビルド時に署名を生成
//! 2. ローダーがセルをロード時に署名を検証
//! 3. 検証失敗時はロードを拒否
//!
//! ## セキュリティ考慮事項
//! - Ed25519署名による改竄検出
//! - 公開鍵ホワイトリストによる信頼チェーン
//! - 開発モードでも署名構造の検証は実行
#![allow(dead_code)]
#![allow(unexpected_cfgs)]

use super::LoadError;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// 署名セクションの名前（ELFセクション）
const SIGNATURE_SECTION_NAME: &[u8] = b".exorust_sig";

/// 署名のマジックナンバー
const SIGNATURE_MAGIC: [u8; 8] = *b"EXORSIG\0";

/// 署名バージョン
const SIGNATURE_VERSION: u32 = 1;

/// Ed25519署名サイズ
const ED25519_SIGNATURE_SIZE: usize = 64;

/// Ed25519公開鍵サイズ
const ED25519_PUBLIC_KEY_SIZE: usize = 32;

// ============================================================================
// 署名情報
// ============================================================================

/// セルの署名情報
#[derive(Debug, Clone)]
pub struct CellSignature {
    /// 署名バージョン
    pub version: u32,
    /// セルがunsafeコードを含むかどうか
    pub contains_unsafe: bool,
    /// セルがフレームワークAPIのみを使用しているか
    pub uses_framework_only: bool,
    /// コンパイラバージョン
    pub compiler_version: String,
    /// ビルドタイムスタンプ
    pub build_timestamp: u64,
    /// 署名ハッシュ（SHA-256）
    pub hash: [u8; 32],
    /// 署名データ（Ed25519）
    pub signature: Vec<u8>,
    /// 公開鍵
    pub public_key: [u8; 32],
}

impl Default for CellSignature {
    fn default() -> Self {
        Self {
            version: SIGNATURE_VERSION,
            contains_unsafe: false,
            uses_framework_only: true,
            compiler_version: String::new(),
            build_timestamp: 0,
            hash: [0; 32],
            signature: Vec::new(),
            public_key: [0; 32],
        }
    }
}

impl CellSignature {
    /// 署名が有効な形式かどうか（暗号検証の前のチェック）
    pub fn is_well_formed(&self) -> bool {
        self.version == SIGNATURE_VERSION
            && self.signature.len() == ED25519_SIGNATURE_SIZE
            && self.public_key != [0; 32]
    }

    /// 開発モード用の署名かどうか
    pub fn is_dev_signature(&self) -> bool {
        self.compiler_version == "dev" || self.signature.is_empty()
    }
}

// ============================================================================
// 署名ヘッダー（ELFセクション）
// ============================================================================

/// 署名ヘッダー（ELFセクション内のデータ構造）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SignatureHeader {
    /// マジックナンバー
    pub magic: [u8; 8],
    /// バージョン
    pub version: u32,
    /// フラグ
    pub flags: u32,
    /// コンパイラバージョン文字列のオフセット
    pub compiler_version_offset: u32,
    /// コンパイラバージョン文字列の長さ
    pub compiler_version_len: u32,
    /// ビルドタイムスタンプ
    pub build_timestamp: u64,
    /// コードハッシュ
    pub hash: [u8; 32],
    /// 公開鍵
    pub public_key: [u8; 32],
    /// 署名長
    pub signature_len: u32,
    /// 予約済み
    pub reserved: u32,
}

/// 署名フラグ
pub mod flags {
    /// unsafeコードを含む
    pub const CONTAINS_UNSAFE: u32 = 1 << 0;
    /// フレームワークAPIのみを使用
    pub const FRAMEWORK_ONLY: u32 = 1 << 1;
    /// デバッグビルド
    pub const DEBUG_BUILD: u32 = 1 << 2;
    /// 開発モードビルド（署名なし許可）
    pub const DEV_MODE: u32 = 1 << 3;
}

// ============================================================================
// 署名検証器
// ============================================================================

/// 署名検証エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    /// 署名形式が無効
    MalformedSignature,
    /// 公開鍵が信頼されていない
    UntrustedKey,
    /// 署名検証に失敗
    InvalidSignature,
    /// ハッシュが一致しない
    HashMismatch,
    /// バージョン不一致
    VersionMismatch,
}

/// 署名検証器
///
/// 信頼された公開鍵のリストを保持し、
/// セル署名を検証する。
pub struct SignatureVerifier {
    /// 信頼された公開鍵のリスト
    trusted_keys: Vec<[u8; ED25519_PUBLIC_KEY_SIZE]>,
    /// 開発モードを許可するか（デフォルト: false）
    allow_dev_mode: bool,
    /// 検証統計
    stats: VerifierStats,
}

/// 検証統計
#[derive(Debug, Default, Clone)]
pub struct VerifierStats {
    /// 検証試行回数
    pub verification_attempts: u64,
    /// 成功回数
    pub successful_verifications: u64,
    /// 失敗回数
    pub failed_verifications: u64,
    /// 開発モードでスキップした回数
    pub dev_mode_bypasses: u64,
}

impl SignatureVerifier {
    /// 新しい検証器を作成
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            allow_dev_mode: cfg!(not(feature = "require_signatures")),
            stats: VerifierStats::default(),
        }
    }

    /// 本番モードの検証器を作成（開発モード無効）
    pub fn production() -> Self {
        Self {
            trusted_keys: Vec::new(),
            allow_dev_mode: false,
            stats: VerifierStats::default(),
        }
    }

    /// 信頼された公開鍵を追加
    pub fn add_trusted_key(&mut self, key: [u8; ED25519_PUBLIC_KEY_SIZE]) {
        if !self.trusted_keys.contains(&key) {
            self.trusted_keys.push(key);
        }
    }

    /// 開発モードを許可/禁止
    pub fn set_dev_mode(&mut self, allow: bool) {
        self.allow_dev_mode = allow;
    }

    /// 公開鍵が信頼されているかチェック
    pub fn is_trusted_key(&self, key: &[u8; ED25519_PUBLIC_KEY_SIZE]) -> bool {
        self.trusted_keys.contains(key)
    }

    /// 署名を検証
    pub fn verify(
        &mut self,
        signature: &CellSignature,
        data: &[u8],
    ) -> Result<(), VerificationError> {
        self.stats.verification_attempts += 1;

        // 開発モードのバイパス（設定されている場合のみ）
        if self.allow_dev_mode && signature.is_dev_signature() {
            self.stats.dev_mode_bypasses += 1;
            self.stats.successful_verifications += 1;
            return Ok(());
        }

        // 1. 署名形式のチェック
        if !signature.is_well_formed() {
            self.stats.failed_verifications += 1;
            return Err(VerificationError::MalformedSignature);
        }

        // 2. 公開鍵の信頼チェック
        if !self.trusted_keys.is_empty() && !self.is_trusted_key(&signature.public_key) {
            self.stats.failed_verifications += 1;
            return Err(VerificationError::UntrustedKey);
        }

        // 3. ハッシュ検証
        let computed_hash = self.compute_hash(data);
        if computed_hash != signature.hash {
            self.stats.failed_verifications += 1;
            return Err(VerificationError::HashMismatch);
        }

        // 4. Ed25519署名検証
        if !self.verify_ed25519(&signature.public_key, &signature.hash, &signature.signature) {
            self.stats.failed_verifications += 1;
            return Err(VerificationError::InvalidSignature);
        }

        self.stats.successful_verifications += 1;
        Ok(())
    }

    /// SHA-256ハッシュを計算
    fn compute_hash(&self, data: &[u8]) -> [u8; 32] {
        // TODO: 実際のSHA-256実装
        // 現在は単純なチェックサム
        let mut hash = [0u8; 32];
        for (i, &byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        hash
    }

    /// Ed25519署名を検証
    ///
    /// TODO: 実際のEd25519実装（ed25519-dalek等）
    fn verify_ed25519(&self, public_key: &[u8; 32], message: &[u8; 32], signature: &[u8]) -> bool {
        // 実装予定: ed25519_verify(public_key, message, signature)
        // 現在はプレースホルダー

        // 基本的な形式チェック
        if signature.len() != ED25519_SIGNATURE_SIZE {
            return false;
        }

        // 公開鍵が空でないこと
        if public_key.iter().all(|&b| b == 0) {
            return false;
        }

        // メッセージが空でないこと
        if message.iter().all(|&b| b == 0) {
            return false;
        }

        // TODO: 実際のEd25519検証
        // 現在は形式チェックのみでパス
        true
    }

    /// 統計を取得
    pub fn stats(&self) -> &VerifierStats {
        &self.stats
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 署名抽出
// ============================================================================

/// ELFデータから署名を抽出
pub fn extract_signature(elf_data: &[u8]) -> Result<CellSignature, LoadError> {
    // ELFヘッダーを読み取り
    if elf_data.len() < 64 {
        return Err(LoadError::InvalidFormat("ELF too small".into()));
    }

    // 署名セクションを探す
    if let Some(sig_data) = find_signature_section(elf_data) {
        parse_signature_section(sig_data)
    } else {
        // 署名セクションが見つからない場合
        #[cfg(feature = "require_signatures")]
        {
            Err(LoadError::InvalidSignature)
        }

        #[cfg(not(feature = "require_signatures"))]
        {
            // 開発モード: 署名なしでもロードを許可（ただし制限付き）
            crate::log!("[SIGNATURE] Warning: Loading unsigned cell (dev mode)\n");
            Ok(CellSignature {
                version: SIGNATURE_VERSION,
                contains_unsafe: false,
                uses_framework_only: true,
                compiler_version: "dev".into(),
                build_timestamp: 0,
                hash: [0; 32],
                signature: Vec::new(),
                public_key: [0; 32],
            })
        }
    }
}

/// 署名セクションを検索
fn find_signature_section(elf_data: &[u8]) -> Option<&[u8]> {
    use super::elf::{Elf64Header, Elf64SectionHeader};
    use core::mem;

    if elf_data.len() < mem::size_of::<Elf64Header>() {
        return None;
    }

    let header: Elf64Header = unsafe { core::ptr::read(elf_data.as_ptr() as *const Elf64Header) };

    // ELFマジック検証
    if &header.e_ident[0..4] != b"\x7FELF" {
        return None;
    }

    // 文字列テーブルセクションを取得
    let shstrtab_offset =
        header.e_shoff as usize + (header.e_shstrndx as usize * header.e_shentsize as usize);

    if shstrtab_offset + mem::size_of::<Elf64SectionHeader>() > elf_data.len() {
        return None;
    }

    let shstrtab_sh: Elf64SectionHeader =
        unsafe { core::ptr::read(elf_data.as_ptr().add(shstrtab_offset) as *const _) };

    let shstrtab_start = shstrtab_sh.sh_offset as usize;
    let shstrtab_end = shstrtab_start + shstrtab_sh.sh_size as usize;

    if shstrtab_end > elf_data.len() {
        return None;
    }

    let shstrtab = &elf_data[shstrtab_start..shstrtab_end];

    // 全セクションを走査して署名セクションを探す
    for i in 0..header.e_shnum {
        let sh_offset = header.e_shoff as usize + (i as usize * header.e_shentsize as usize);

        if sh_offset + mem::size_of::<Elf64SectionHeader>() > elf_data.len() {
            continue;
        }

        let sh: Elf64SectionHeader =
            unsafe { core::ptr::read(elf_data.as_ptr().add(sh_offset) as *const _) };

        // セクション名を取得
        let name_offset = sh.sh_name as usize;
        if name_offset >= shstrtab.len() {
            continue;
        }

        // 名前を比較
        let name_end = shstrtab[name_offset..]
            .iter()
            .position(|&c| c == 0)
            .map(|p| name_offset + p)
            .unwrap_or(shstrtab.len());

        let section_name = &shstrtab[name_offset..name_end];

        if section_name == SIGNATURE_SECTION_NAME {
            let data_start = sh.sh_offset as usize;
            let data_end = data_start + sh.sh_size as usize;

            if data_end <= elf_data.len() {
                return Some(&elf_data[data_start..data_end]);
            }
        }
    }

    None
}

/// 署名セクションをパース
fn parse_signature_section(data: &[u8]) -> Result<CellSignature, LoadError> {
    use core::mem;

    if data.len() < mem::size_of::<SignatureHeader>() {
        return Err(LoadError::InvalidFormat(
            "Signature section too small".into(),
        ));
    }

    let header: SignatureHeader =
        unsafe { core::ptr::read(data.as_ptr() as *const SignatureHeader) };

    // マジックナンバーの検証
    if header.magic != SIGNATURE_MAGIC {
        return Err(LoadError::InvalidSignature);
    }

    // バージョンの検証
    if header.version != SIGNATURE_VERSION {
        return Err(LoadError::InvalidFormat(
            "Unsupported signature version".into(),
        ));
    }

    // コンパイラバージョンを読み取り
    let compiler_version =
        if header.compiler_version_len > 0 {
            let start = header.compiler_version_offset as usize;
            let end = start + header.compiler_version_len as usize;

            if end > data.len() {
                return Err(LoadError::InvalidFormat(
                    "Invalid compiler version offset".into(),
                ));
            }

            String::from(core::str::from_utf8(&data[start..end]).map_err(|_| {
                LoadError::InvalidFormat("Invalid UTF-8 in compiler version".into())
            })?)
        } else {
            String::new()
        };

    // 署名データを読み取り
    let sig_start = mem::size_of::<SignatureHeader>();
    let sig_end = sig_start + header.signature_len as usize;

    if sig_end > data.len() {
        return Err(LoadError::InvalidFormat("Invalid signature data".into()));
    }

    let signature = data[sig_start..sig_end].to_vec();

    Ok(CellSignature {
        version: header.version,
        contains_unsafe: (header.flags & flags::CONTAINS_UNSAFE) != 0,
        uses_framework_only: (header.flags & flags::FRAMEWORK_ONLY) != 0,
        compiler_version,
        build_timestamp: header.build_timestamp,
        hash: header.hash,
        signature,
        public_key: header.public_key,
    })
}

// ============================================================================
// グローバルAPI
// ============================================================================

use spin::Mutex;

/// グローバル検証器
static GLOBAL_VERIFIER: Mutex<Option<SignatureVerifier>> = Mutex::new(None);

/// グローバル検証器を初期化
pub fn init_verifier() {
    let mut verifier = GLOBAL_VERIFIER.lock();
    if verifier.is_none() {
        *verifier = Some(SignatureVerifier::new());
        crate::log!("[SIGNATURE] Signature verifier initialized\n");
    }
}

/// グローバル検証器を本番モードで初期化
pub fn init_verifier_production() {
    let mut verifier = GLOBAL_VERIFIER.lock();
    *verifier = Some(SignatureVerifier::production());
    crate::log!("[SIGNATURE] Signature verifier initialized (production mode)\n");
}

/// 信頼された公開鍵を追加
pub fn add_trusted_key(key: [u8; ED25519_PUBLIC_KEY_SIZE]) {
    let mut verifier = GLOBAL_VERIFIER.lock();
    if let Some(v) = verifier.as_mut() {
        v.add_trusted_key(key);
    }
}

/// 署名を検証（グローバル検証器を使用）
pub fn verify_signature(signature: &CellSignature, data: &[u8]) -> bool {
    let mut verifier_guard = GLOBAL_VERIFIER.lock();

    // 未初期化の場合は自動初期化
    if verifier_guard.is_none() {
        *verifier_guard = Some(SignatureVerifier::new());
    }

    if let Some(verifier) = verifier_guard.as_mut() {
        verifier.verify(signature, data).is_ok()
    } else {
        false
    }
}

/// セルの署名を検証
pub fn verify_cell(elf_data: &[u8]) -> Result<bool, LoadError> {
    let signature = extract_signature(elf_data)?;
    Ok(verify_signature(&signature, elf_data))
}

/// 検証統計を取得
pub fn get_verifier_stats() -> Option<VerifierStats> {
    GLOBAL_VERIFIER.lock().as_ref().map(|v| v.stats().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_signature() {
        let sig = CellSignature::default();
        assert_eq!(sig.version, SIGNATURE_VERSION);
        assert!(!sig.contains_unsafe);
        assert!(sig.uses_framework_only);
    }

    #[test]
    fn test_well_formed_signature() {
        let mut sig = CellSignature::default();
        // デフォルトは不完全
        assert!(!sig.is_well_formed());

        // 完全な署名
        sig.signature = vec![0u8; ED25519_SIGNATURE_SIZE];
        sig.public_key = [1u8; 32];
        assert!(sig.is_well_formed());
    }

    #[test]
    fn test_verifier_dev_mode() {
        let mut verifier = SignatureVerifier::new();
        verifier.set_dev_mode(true);

        let mut sig = CellSignature::default();
        sig.compiler_version = "dev".into();

        // 開発モードではバイパス
        assert!(verifier.verify(&sig, &[]).is_ok());
        assert_eq!(verifier.stats().dev_mode_bypasses, 1);
    }

    #[test]
    fn test_verifier_production_mode() {
        let mut verifier = SignatureVerifier::production();

        let mut sig = CellSignature::default();
        sig.compiler_version = "dev".into();

        // 本番モードでは不完全な署名は拒否
        assert_eq!(
            verifier.verify(&sig, &[]),
            Err(VerificationError::MalformedSignature)
        );
    }
}
