// ============================================================================
// src/loader/signature.rs - Cell Signature Verification
// 設計書 3.3: コンパイラ署名とロード時検証
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use super::LoadError;

/// 署名セクションの名前（ELFセクション）
const SIGNATURE_SECTION_NAME: &[u8] = b".exorust_sig";

/// 署名のマジックナンバー
const SIGNATURE_MAGIC: [u8; 8] = *b"EXORSIG\0";

/// 署名バージョン
const SIGNATURE_VERSION: u32 = 1;

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
    /// 署名データ（Ed25519など）
    pub signature: Vec<u8>,
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
        }
    }
}

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
}

/// 署名検証器
pub struct SignatureVerifier {
    /// 信頼された公開鍵のリスト
    trusted_keys: Vec<[u8; 32]>,
}

impl SignatureVerifier {
    /// 新しい検証器を作成
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
        }
    }
    
    /// 信頼された公開鍵を追加
    pub fn add_trusted_key(&mut self, key: [u8; 32]) {
        self.trusted_keys.push(key);
    }
    
    /// 署名を検証
    pub fn verify(&self, signature: &CellSignature, _data: &[u8]) -> bool {
        // TODO: 実際の暗号検証を実装
        // Ed25519署名の検証など
        
        // 現在は単純なチェックのみ
        signature.version == SIGNATURE_VERSION && !signature.signature.is_empty()
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// ELFデータから署名を抽出
pub fn extract_signature(elf_data: &[u8]) -> Result<CellSignature, LoadError> {
    // ELFヘッダーを読み取り
    if elf_data.len() < 64 {
        return Err(LoadError::InvalidFormat("ELF too small".into()));
    }
    
    // シンプルな実装: 署名セクションを探す
    // 実際には完全なELFパーサーが必要
    
    // 署名が見つからない場合はデフォルト署名を返す（開発用）
    // 本番環境では InvalidSignature を返すべき
    
    #[cfg(feature = "require_signatures")]
    {
        // 署名セクションを探す
        if let Some(sig) = find_signature_section(elf_data) {
            parse_signature_section(sig)
        } else {
            Err(LoadError::InvalidSignature)
        }
    }
    
    #[cfg(not(feature = "require_signatures"))]
    {
        // 開発モード: 署名なしでもロードを許可
        // ただしunsafeは無効とマーク
        Ok(CellSignature {
            version: SIGNATURE_VERSION,
            contains_unsafe: false,
            uses_framework_only: true,
            compiler_version: "dev".into(),
            build_timestamp: 0,
            hash: [0; 32],
            signature: vec![1], // ダミー署名
        })
    }
}

/// 署名セクションを検索
#[allow(dead_code)]
fn find_signature_section(elf_data: &[u8]) -> Option<&[u8]> {
    use super::elf::{Elf64Header, Elf64SectionHeader};
    use core::mem;
    
    if elf_data.len() < mem::size_of::<Elf64Header>() {
        return None;
    }
    
    let header: Elf64Header = unsafe {
        core::ptr::read(elf_data.as_ptr() as *const Elf64Header)
    };
    
    // 文字列テーブルセクションを取得
    let shstrtab_offset = header.e_shoff as usize
        + (header.e_shstrndx as usize * header.e_shentsize as usize);
    
    if shstrtab_offset + mem::size_of::<Elf64SectionHeader>() > elf_data.len() {
        return None;
    }
    
    let shstrtab_sh: Elf64SectionHeader = unsafe {
        core::ptr::read(elf_data.as_ptr().add(shstrtab_offset) as *const _)
    };
    
    let shstrtab_start = shstrtab_sh.sh_offset as usize;
    let shstrtab_end = shstrtab_start + shstrtab_sh.sh_size as usize;
    
    if shstrtab_end > elf_data.len() {
        return None;
    }
    
    let shstrtab = &elf_data[shstrtab_start..shstrtab_end];
    
    // 全セクションを走査して署名セクションを探す
    for i in 0..header.e_shnum {
        let sh_offset = header.e_shoff as usize
            + (i as usize * header.e_shentsize as usize);
        
        if sh_offset + mem::size_of::<Elf64SectionHeader>() > elf_data.len() {
            continue;
        }
        
        let sh: Elf64SectionHeader = unsafe {
            core::ptr::read(elf_data.as_ptr().add(sh_offset) as *const _)
        };
        
        // セクション名を取得
        let name_offset = sh.sh_name as usize;
        if name_offset >= shstrtab.len() {
            continue;
        }
        
        // 名前を比較
        let name_end = shstrtab[name_offset..].iter()
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
#[allow(dead_code)]
fn parse_signature_section(data: &[u8]) -> Result<CellSignature, LoadError> {
    use core::mem;
    
    if data.len() < mem::size_of::<SignatureHeader>() {
        return Err(LoadError::InvalidFormat("Signature section too small".into()));
    }
    
    let header: SignatureHeader = unsafe {
        core::ptr::read(data.as_ptr() as *const SignatureHeader)
    };
    
    // マジックナンバーの検証
    if header.magic != SIGNATURE_MAGIC {
        return Err(LoadError::InvalidSignature);
    }
    
    // バージョンの検証
    if header.version != SIGNATURE_VERSION {
        return Err(LoadError::InvalidFormat("Unsupported signature version".into()));
    }
    
    // コンパイラバージョンを読み取り
    let compiler_version = if header.compiler_version_len > 0 {
        let start = header.compiler_version_offset as usize;
        let end = start + header.compiler_version_len as usize;
        
        if end > data.len() {
            return Err(LoadError::InvalidFormat("Invalid compiler version offset".into()));
        }
        
        core::str::from_utf8(&data[start..end])
            .map_err(|_| LoadError::InvalidFormat("Invalid UTF-8 in compiler version".into()))?
            .to_string()
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
    })
}

/// 署名を検証（グローバル検証器を使用）
pub fn verify_signature(signature: &CellSignature, data: &[u8]) -> bool {
    // 開発モード: 常にtrue
    #[cfg(not(feature = "require_signatures"))]
    {
        let _ = (signature, data);
        true
    }
    
    #[cfg(feature = "require_signatures")]
    {
        // 本番モード: 実際の検証
        static VERIFIER: spin::Once<SignatureVerifier> = spin::Once::new();
        let verifier = VERIFIER.call_once(SignatureVerifier::new);
        verifier.verify(signature, data)
    }
}

/// セルの署名を検証
pub fn verify_cell(elf_data: &[u8]) -> Result<bool, LoadError> {
    let signature = extract_signature(elf_data)?;
    Ok(verify_signature(&signature, elf_data))
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
    fn test_verifier() {
        let verifier = SignatureVerifier::new();
        let mut sig = CellSignature::default();
        sig.signature = vec![1, 2, 3]; // ダミー署名
        
        assert!(verifier.verify(&sig, &[]));
    }
}
