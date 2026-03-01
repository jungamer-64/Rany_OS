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
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
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

/// Built-in trusted key for production verification.
const BUILTIN_TRUSTED_KEY: [u8; ED25519_PUBLIC_KEY_SIZE] =
    *include_bytes!("../../../keys/kernel_pub.key");

/// Trusted key level used for signature-chain enforcement.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyLevel {
    Platform = 0,
    Kernel = 1,
    Driver = 2,
    Application = 3,
}

impl KeyLevel {
    #[inline]
    fn required_parent(self) -> Option<Self> {
        match self {
            Self::Platform => None,
            // Current deployment bootstraps kernel keys directly from built-in trust.
            Self::Kernel => None,
            Self::Driver => Some(Self::Kernel),
            Self::Application => Some(Self::Driver),
        }
    }
}

/// Logical key identifier used in trust-chain and revocation tracking.
pub type KeyId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedKeyRecord {
    key_id: KeyId,
    public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    level: KeyLevel,
    issuer: Option<KeyId>,
}

/// Revocation set for keys and signed cell hashes.
#[derive(Debug, Default, Clone)]
pub struct RevocationSet {
    revoked_key_ids: BTreeSet<KeyId>,
    revoked_cell_hashes: BTreeSet<[u8; 32]>,
}

impl RevocationSet {
    pub fn revoke_key(&mut self, key_id: KeyId) {
        self.revoked_key_ids.insert(key_id);
    }

    pub fn revoke_cell_hash(&mut self, hash: [u8; 32]) {
        self.revoked_cell_hashes.insert(hash);
    }

    #[inline]
    pub fn is_key_revoked(&self, key_id: KeyId) -> bool {
        self.revoked_key_ids.contains(&key_id)
    }

    #[inline]
    pub fn is_cell_hash_revoked(&self, hash: &[u8; 32]) -> bool {
        self.revoked_cell_hashes.contains(hash)
    }
}

#[inline]
fn key_id_from_public_key(key: &[u8; ED25519_PUBLIC_KEY_SIZE]) -> KeyId {
    let mut id = [0u8; 8];
    id.copy_from_slice(&key[..8]);
    u64::from_le_bytes(id)
}

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
    /// 失効済みの署名鍵
    RevokedKey,
    /// 失効済みのセルハッシュ
    RevokedCell,
    /// 信頼チェーン不整合
    InvalidTrustChain,
}

/// 署名検証器
///
/// 信頼された公開鍵のリストを保持し、
/// セル署名を検証する。
pub struct SignatureVerifier {
    /// 信頼された公開鍵（KeyId -> record）
    trusted_keys: BTreeMap<KeyId, TrustedKeyRecord>,
    /// 公開鍵からKeyIdを逆引きする索引
    key_index: BTreeMap<[u8; ED25519_PUBLIC_KEY_SIZE], KeyId>,
    /// 開発モードを許可するか（デフォルト: false）
    allow_dev_mode: bool,
    /// 失効リスト
    revocation_set: RevocationSet,
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
            trusted_keys: BTreeMap::new(),
            key_index: BTreeMap::new(),
            allow_dev_mode: false,
            revocation_set: RevocationSet::default(),
            stats: VerifierStats::default(),
        }
    }

    /// 本番モードの検証器を作成（開発モード無効）
    pub fn production() -> Self {
        Self {
            trusted_keys: BTreeMap::new(),
            key_index: BTreeMap::new(),
            allow_dev_mode: false,
            revocation_set: RevocationSet::default(),
            stats: VerifierStats::default(),
        }
    }

    /// 信頼された公開鍵を追加
    pub fn add_trusted_key(&mut self, key: [u8; ED25519_PUBLIC_KEY_SIZE]) {
        let _ = self.add_trusted_key_with_level(key, KeyLevel::Kernel, None);
    }

    /// 信頼された公開鍵をレベル付きで追加
    pub fn add_trusted_key_with_level(
        &mut self,
        key: [u8; ED25519_PUBLIC_KEY_SIZE],
        level: KeyLevel,
        issuer: Option<KeyId>,
    ) -> KeyId {
        let key_id = key_id_from_public_key(&key);
        let rec = TrustedKeyRecord {
            key_id,
            public_key: key,
            level,
            issuer,
        };
        self.trusted_keys.insert(key_id, rec);
        self.key_index.insert(key, key_id);
        key_id
    }

    /// 署名鍵を失効させる
    pub fn revoke_key(&mut self, key_id: KeyId) {
        self.revocation_set.revoke_key(key_id);
    }

    /// セルハッシュを失効させる
    pub fn revoke_cell_hash(&mut self, hash: [u8; 32]) {
        self.revocation_set.revoke_cell_hash(hash);
    }

    /// 開発モードを許可/禁止
    pub fn set_dev_mode(&mut self, allow: bool) {
        self.allow_dev_mode = allow;
    }

    /// 公開鍵が信頼されているかチェック
    pub fn is_trusted_key(&self, key: &[u8; ED25519_PUBLIC_KEY_SIZE]) -> bool {
        self.key_index.contains_key(key)
    }

    fn key_id_for_public_key(&self, key: &[u8; ED25519_PUBLIC_KEY_SIZE]) -> Option<KeyId> {
        self.key_index.get(key).copied()
    }

    fn verify_trust_chain(&self, key_id: KeyId, depth: usize) -> Result<(), VerificationError> {
        if depth > 8 {
            return Err(VerificationError::InvalidTrustChain);
        }
        let Some(record) = self.trusted_keys.get(&key_id) else {
            return Err(VerificationError::UntrustedKey);
        };
        if self.revocation_set.is_key_revoked(record.key_id) {
            return Err(VerificationError::RevokedKey);
        }
        match record.level.required_parent() {
            None => Ok(()),
            Some(expected_parent_level) => {
                let issuer_id = record.issuer.ok_or(VerificationError::InvalidTrustChain)?;
                let issuer = self
                    .trusted_keys
                    .get(&issuer_id)
                    .ok_or(VerificationError::InvalidTrustChain)?;
                if issuer.level != expected_parent_level {
                    return Err(VerificationError::InvalidTrustChain);
                }
                self.verify_trust_chain(issuer_id, depth + 1)
            }
        }
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

        if self.revocation_set.is_cell_hash_revoked(&signature.hash) {
            self.stats.failed_verifications += 1;
            return Err(VerificationError::RevokedCell);
        }

        // 2. 公開鍵の信頼チェック（trusted keyが必須）
        if self.trusted_keys.is_empty() {
            self.stats.failed_verifications += 1;
            return Err(VerificationError::UntrustedKey);
        }
        let Some(key_id) = self.key_id_for_public_key(&signature.public_key) else {
            self.stats.failed_verifications += 1;
            return Err(VerificationError::UntrustedKey);
        };
        if let Err(e) = self.verify_trust_chain(key_id, 0) {
            self.stats.failed_verifications += 1;
            return Err(e);
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
    ///
    /// 設計書 3.3: SHA-256によるコード完全性検証
    fn compute_hash(&self, data: &[u8]) -> [u8; 32] {
        super::sha256::compute(data)
    }

    /// Ed25519署名を検証
    ///
    /// 設計書 3.3: Ed25519による署名検証
    fn verify_ed25519(&self, public_key: &[u8; 32], message: &[u8; 32], signature: &[u8]) -> bool {
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

        // 署名配列に変換
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        // Ed25519検証を実行
        super::ed25519::verify(public_key, message, &sig_bytes)
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
        // 開発モード: 署名なしでもロードを許可（ただし制限付き）
        log::info!("[SIGNATURE] Warning: Loading unsigned cell (dev mode)\n");
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

/// ELFヘッダーからセクション名文字列テーブルを取得する
fn get_shstrtab<'a>(
    elf_data: &'a [u8],
    header: &super::elf::Elf64Header,
) -> Option<&'a [u8]> {
    use super::elf::Elf64SectionHeader;
    use core::mem;

    let shstrtab_offset =
        header.e_shoff as usize + (header.e_shstrndx as usize * header.e_shentsize as usize);

    if shstrtab_offset + mem::size_of::<Elf64SectionHeader>() > elf_data.len() {
        return None;
    }

    let shstrtab_sh: Elf64SectionHeader = crate::util::read_struct(elf_data, shstrtab_offset)?;

    let shstrtab_start = shstrtab_sh.sh_offset as usize;
    let shstrtab_end = shstrtab_start + shstrtab_sh.sh_size as usize;

    if shstrtab_end > elf_data.len() {
        return None;
    }

    Some(&elf_data[shstrtab_start..shstrtab_end])
}

/// セクション名文字列テーブルからセクション名を取得する
fn get_section_name<'a>(shstrtab: &'a [u8], name_offset: usize) -> Option<&'a [u8]> {
    if name_offset >= shstrtab.len() {
        return None;
    }
    let name_end = shstrtab[name_offset..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| name_offset + p)
        .unwrap_or(shstrtab.len());
    Some(&shstrtab[name_offset..name_end])
}

/// ELFヘッダーとshstrtabを検証・取得
fn validate_and_get_shstrtab<'a>(elf_data: &'a [u8]) -> Option<(super::elf::Elf64Header, &'a [u8])> {
    use super::elf::Elf64Header;
    use core::mem;

    if elf_data.len() < mem::size_of::<Elf64Header>() {
        return None;
    }

    let header: Elf64Header = crate::util::read_struct(elf_data, 0)?;

    if &header.e_ident[0..4] != b"\x7FELF" {
        return None;
    }

    let shstrtab = get_shstrtab(elf_data, &header)?;
    Some((header, shstrtab))
}

/// 署名セクションを検索
fn find_signature_section(elf_data: &[u8]) -> Option<&[u8]> {
    use super::elf::Elf64SectionHeader;
    use core::mem;

    let (header, shstrtab) = validate_and_get_shstrtab(elf_data)?;

    // 全セクションを走査して署名セクションを探す
    for i in 0..header.e_shnum {
        let sh_offset = header.e_shoff as usize + (i as usize * header.e_shentsize as usize);

        if sh_offset + mem::size_of::<Elf64SectionHeader>() > elf_data.len() {
            continue;
        }

        let sh: Elf64SectionHeader = crate::util::read_struct(elf_data, sh_offset)?;

        let section_name = get_section_name(shstrtab, sh.sh_name as usize)?;

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

fn read_compiler_version(data: &[u8], header: &SignatureHeader) -> Result<String, LoadError> {
    if header.compiler_version_len > 0 {
        let start = header.compiler_version_offset as usize;
        let end = start + header.compiler_version_len as usize;
        if end > data.len() {
            return Err(LoadError::InvalidFormat(
                "Invalid compiler version offset".into(),
            ));
        }
        Ok(String::from(core::str::from_utf8(&data[start..end]).map_err(|_| {
            LoadError::InvalidFormat("Invalid UTF-8 in compiler version".into())
        })?))
    } else {
        Ok(String::new())
    }
}

/// 署名セクションをパース
fn parse_signature_section(data: &[u8]) -> Result<CellSignature, LoadError> {
    use core::mem;

    if data.len() < mem::size_of::<SignatureHeader>() {
        return Err(LoadError::InvalidFormat(
            "Signature section too small".into(),
        ));
    }

    let header: SignatureHeader = crate::util::read_struct(data, 0)
        .ok_or_else(|| LoadError::InvalidFormat("Invalid signature header".into()))?;

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

    let compiler_version = read_compiler_version(data, &header)?;

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
        let mut v = SignatureVerifier::new();
        v.add_trusted_key(BUILTIN_TRUSTED_KEY);
        *verifier = Some(v);
        log::info!("[SIGNATURE] Signature verifier initialized\n");
    }
}

/// グローバル検証器を本番モードで初期化
pub fn init_verifier_production() {
    let mut verifier = GLOBAL_VERIFIER.lock();
    let mut v = SignatureVerifier::production();
    v.add_trusted_key(BUILTIN_TRUSTED_KEY);
    *verifier = Some(v);
    log::info!("[SIGNATURE] Signature verifier initialized (production mode)\n");
}

/// 信頼された公開鍵を追加
pub fn add_trusted_key(key: [u8; ED25519_PUBLIC_KEY_SIZE]) {
    let mut verifier = GLOBAL_VERIFIER.lock();
    if let Some(v) = verifier.as_mut() {
        v.add_trusted_key(key);
    }
}

/// 信頼された公開鍵をレベル付きで追加
pub fn add_trusted_key_with_level(
    key: [u8; ED25519_PUBLIC_KEY_SIZE],
    level: KeyLevel,
    issuer: Option<KeyId>,
) -> Option<KeyId> {
    let mut verifier = GLOBAL_VERIFIER.lock();
    verifier
        .as_mut()
        .map(|v| v.add_trusted_key_with_level(key, level, issuer))
}

/// 署名鍵を失効させる
pub fn revoke_key(key_id: KeyId) {
    let mut verifier = GLOBAL_VERIFIER.lock();
    if let Some(v) = verifier.as_mut() {
        v.revoke_key(key_id);
    }
}

/// セルハッシュを失効させる
pub fn revoke_cell_hash(hash: [u8; 32]) {
    let mut verifier = GLOBAL_VERIFIER.lock();
    if let Some(v) = verifier.as_mut() {
        v.revoke_cell_hash(hash);
    }
}

/// 署名を検証（グローバル検証器を使用）
pub fn verify_signature(signature: &CellSignature, data: &[u8]) -> bool {
    let mut verifier_guard = GLOBAL_VERIFIER.lock();

    // 未初期化の場合は自動初期化
    if verifier_guard.is_none() {
        let mut v = SignatureVerifier::production();
        v.add_trusted_key(BUILTIN_TRUSTED_KEY);
        #[cfg(any(feature = "qemu-test-export", debug_assertions))]
        {
            // デバッグビルドおよびQEMUテストでは署名なしセルのロードを許可
            v.set_dev_mode(true);
        }
        *verifier_guard = Some(v);
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

    fn fake_signature(public_key: [u8; 32]) -> CellSignature {
        CellSignature {
            version: SIGNATURE_VERSION,
            contains_unsafe: false,
            uses_framework_only: true,
            compiler_version: String::from("test"),
            build_timestamp: 0,
            hash: [1; 32],
            signature: alloc::vec![0u8; ED25519_SIGNATURE_SIZE],
            public_key,
        }
    }

    #[test_case]
    fn test_revoked_key_is_rejected_before_hash_check() {
        let mut verifier = SignatureVerifier::new();
        let key = [7u8; 32];
        let key_id = verifier.add_trusted_key_with_level(key, KeyLevel::Kernel, None);
        verifier.revoke_key(key_id);

        let sig = fake_signature(key);
        let err = verifier
            .verify(&sig, b"payload")
            .expect_err("revoked key must be rejected");
        assert_eq!(err, VerificationError::RevokedKey);
    }

    #[test_case]
    fn test_invalid_chain_without_kernel_issuer_is_rejected() {
        let mut verifier = SignatureVerifier::new();
        let driver_key = [9u8; 32];
        let _ = verifier.add_trusted_key_with_level(driver_key, KeyLevel::Driver, None);

        let sig = fake_signature(driver_key);
        let err = verifier
            .verify(&sig, b"payload")
            .expect_err("driver key without issuer must fail");
        assert_eq!(err, VerificationError::InvalidTrustChain);
    }
}
