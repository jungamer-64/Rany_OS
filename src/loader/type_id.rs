// ============================================================================
// src/loader/type_id.rs - Type ID Check for ABI Compatibility
// 設計書 3.4: ABIの安定性とType ID Check
// ============================================================================
//!
//! # Type ID Check
//!
//! RustはABI（Application Binary Interface）が安定していないため、
//! 動的リンクには特別な注意が必要です。
//!
//! このモジュールは、型定義ハッシュによる互換性検証を提供します。
//!
//! ## 設計書 3.4 の実装
//!
//! 1. **コンパイル時ハッシュ生成**: 各セルのコンパイル時に、依存インターフェースの
//!    型定義ハッシュ値をメタデータとしてELFバイナリに埋め込みます。
//!
//! 2. **ロード時検証**: カーネルのローダーがセルをロードする際、
//!    依存インターフェースのハッシュ値を比較します。
//!
//! 3. **不一致時の拒否**: ハッシュ値が一致しない場合、セルのロードを拒否します。

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// 型のハッシュ値（64ビット）
pub type TypeHash = u64;

/// セマンティックバージョン
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl SemVer {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }
    
    /// メジャーバージョンの互換性チェック
    pub fn is_major_compatible(&self, other: &SemVer) -> bool {
        self.major == other.major
    }
    
    /// マイナーバージョンの後方互換性チェック
    pub fn is_backward_compatible(&self, other: &SemVer) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl core::fmt::Display for SemVer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// 型ID情報
#[derive(Debug, Clone)]
pub struct TypeIdInfo {
    /// 型の完全修飾名
    pub name: String,
    /// 型定義のハッシュ値
    pub hash: TypeHash,
    /// バージョン情報
    pub version: SemVer,
}

/// 【設計書 3.4】Type ID Hashトレイト
///
/// 構造体やトレイトに実装することで、ABI互換性を保証するための
/// ハッシュ値を提供します。
pub trait TypeIdHash {
    /// 型の一意なハッシュ値を返す
    ///
    /// このハッシュは、型の名前、フィールドの順序・型・オフセット、
    /// 関数の引数・戻り値の型などから計算されます。
    fn type_id_hash() -> TypeHash;
    
    /// 型の名前を返す
    fn type_name() -> &'static str;
    
    /// バージョン情報を返す
    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0) // デフォルトバージョン
    }
    
    /// TypeIdInfoを構築
    fn type_id_info() -> TypeIdInfo {
        TypeIdInfo {
            name: String::from(Self::type_name()),
            hash: Self::type_id_hash(),
            version: Self::type_version(),
        }
    }
}

/// コンパイル時定数ハッシュ関数（FNV-1a）
///
/// 型定義文字列からハッシュを計算します。
pub const fn const_hash(bytes: &[u8]) -> TypeHash {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    
    let mut hash = FNV_OFFSET_BASIS;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// インターフェース定義のレジストリ
///
/// カーネルが提供するインターフェースのハッシュ値を管理します。
pub struct InterfaceRegistry {
    /// インターフェース名 -> TypeIdInfo のマッピング
    interfaces: BTreeMap<String, TypeIdInfo>,
}

impl InterfaceRegistry {
    pub const fn new() -> Self {
        Self {
            interfaces: BTreeMap::new(),
        }
    }
    
    /// インターフェースを登録
    pub fn register<T: TypeIdHash>(&mut self) {
        let info = T::type_id_info();
        self.interfaces.insert(info.name.clone(), info);
    }
    
    /// インターフェースを手動登録（名前とハッシュを指定）
    pub fn register_manual(&mut self, name: String, hash: TypeHash, version: SemVer) {
        self.interfaces.insert(name.clone(), TypeIdInfo { name, hash, version });
    }
    
    /// インターフェースのハッシュを検証
    ///
    /// # Returns
    /// - `Ok(())`: ハッシュが一致
    /// - `Err(TypeIdError)`: ハッシュ不一致または未登録
    pub fn verify(&self, name: &str, expected_hash: TypeHash) -> Result<(), TypeIdError> {
        match self.interfaces.get(name) {
            Some(info) => {
                if info.hash == expected_hash {
                    Ok(())
                } else {
                    Err(TypeIdError::HashMismatch {
                        interface: String::from(name),
                        expected: expected_hash,
                        actual: info.hash,
                        version: info.version,
                    })
                }
            }
            None => Err(TypeIdError::InterfaceNotFound {
                interface: String::from(name),
            }),
        }
    }
    
    /// バージョン互換性も含めて検証
    pub fn verify_with_version(
        &self,
        name: &str,
        expected_hash: TypeHash,
        required_version: SemVer,
    ) -> Result<(), TypeIdError> {
        match self.interfaces.get(name) {
            Some(info) => {
                if info.hash != expected_hash {
                    return Err(TypeIdError::HashMismatch {
                        interface: String::from(name),
                        expected: expected_hash,
                        actual: info.hash,
                        version: info.version,
                    });
                }
                
                if !info.version.is_backward_compatible(&required_version) {
                    return Err(TypeIdError::VersionIncompatible {
                        interface: String::from(name),
                        required: required_version,
                        actual: info.version,
                    });
                }
                
                Ok(())
            }
            None => Err(TypeIdError::InterfaceNotFound {
                interface: String::from(name),
            }),
        }
    }
    
    /// 登録されているインターフェース数を取得
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }
    
    /// 登録されているインターフェースが空かどうか
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

/// Type ID検証エラー
#[derive(Debug, Clone)]
pub enum TypeIdError {
    /// ハッシュ不一致
    HashMismatch {
        interface: String,
        expected: TypeHash,
        actual: TypeHash,
        version: SemVer,
    },
    /// バージョン非互換
    VersionIncompatible {
        interface: String,
        required: SemVer,
        actual: SemVer,
    },
    /// インターフェースが見つからない
    InterfaceNotFound {
        interface: String,
    },
}

impl core::fmt::Display for TypeIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TypeIdError::HashMismatch { interface, expected, actual, version } => {
                write!(
                    f,
                    "ABI incompatibility for '{}' (v{}): expected hash {:#x}, got {:#x}",
                    interface, version, expected, actual
                )
            }
            TypeIdError::VersionIncompatible { interface, required, actual } => {
                write!(
                    f,
                    "Version incompatibility for '{}': required {}, got {}",
                    interface, required, actual
                )
            }
            TypeIdError::InterfaceNotFound { interface } => {
                write!(f, "Interface '{}' not found in registry", interface)
            }
        }
    }
}

/// セルの依存関係情報
#[derive(Debug, Clone)]
pub struct CellDependencies {
    /// セル名
    pub cell_name: String,
    /// セルバージョン
    pub cell_version: SemVer,
    /// 依存インターフェースのリスト
    pub dependencies: Vec<DependencyEntry>,
}

/// 依存関係エントリ
#[derive(Debug, Clone)]
pub struct DependencyEntry {
    /// インターフェース名
    pub interface: String,
    /// 要求するハッシュ値
    pub hash: TypeHash,
    /// 要求する最小バージョン
    pub min_version: SemVer,
}

/// ELFバイナリからType ID情報を抽出
///
/// セルのメタデータセクション（.rany_type_id）からハッシュ情報を読み取ります。
pub fn extract_type_ids(elf_data: &[u8]) -> Option<CellDependencies> {
    // ELFヘッダーの検証
    if elf_data.len() < 64 || &elf_data[0..4] != b"\x7fELF" {
        return None;
    }
    
    // セクションヘッダーテーブルを走査して .rany_type_id セクションを探す
    // 簡易実装：実際にはELFパーサーを使用
    
    // TODO: 実際のELFセクション解析を実装
    // 現在はプレースホルダー
    None
}

/// グローバルインターフェースレジストリ
static INTERFACE_REGISTRY: spin::Mutex<InterfaceRegistry> = 
    spin::Mutex::new(InterfaceRegistry::new());

/// カーネルインターフェースを登録
pub fn register_kernel_interface<T: TypeIdHash>() {
    INTERFACE_REGISTRY.lock().register::<T>();
}

/// カーネルインターフェースを手動登録
pub fn register_kernel_interface_manual(name: &str, hash: TypeHash, version: SemVer) {
    INTERFACE_REGISTRY.lock().register_manual(String::from(name), hash, version);
}

/// セルの依存関係を検証
pub fn verify_cell_dependencies(deps: &CellDependencies) -> Result<(), TypeIdError> {
    let registry = INTERFACE_REGISTRY.lock();
    
    for dep in &deps.dependencies {
        registry.verify_with_version(&dep.interface, dep.hash, dep.min_version)?;
    }
    
    Ok(())
}

// ============================================================================
// 標準カーネルインターフェースの定義
// ============================================================================

/// メモリアロケータインターフェース
pub struct MemoryAllocatorInterface;

impl TypeIdHash for MemoryAllocatorInterface {
    fn type_id_hash() -> TypeHash {
        const_hash(b"MemoryAllocatorInterface:v1:alloc(Layout)->*mut u8,dealloc(*mut u8,Layout)")
    }
    
    fn type_name() -> &'static str {
        "MemoryAllocatorInterface"
    }
    
    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
    }
}

/// タスクスケジューラインターフェース
pub struct TaskSchedulerInterface;

impl TypeIdHash for TaskSchedulerInterface {
    fn type_id_hash() -> TypeHash {
        const_hash(b"TaskSchedulerInterface:v1:spawn(Future)->TaskId,yield_now(),sleep(Duration)")
    }
    
    fn type_name() -> &'static str {
        "TaskSchedulerInterface"
    }
    
    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
    }
}

/// IPCインターフェース
pub struct IpcInterface;

impl TypeIdHash for IpcInterface {
    fn type_id_hash() -> TypeHash {
        const_hash(b"IpcInterface:v1:send(RRef<T>),recv()->RRef<T>,create_channel()->ChannelPair")
    }
    
    fn type_name() -> &'static str {
        "IpcInterface"
    }
    
    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
    }
}

/// カーネルインターフェースの初期化
pub fn init_kernel_interfaces() {
    let mut registry = INTERFACE_REGISTRY.lock();
    
    // 標準カーネルインターフェースを登録
    registry.register::<MemoryAllocatorInterface>();
    registry.register::<TaskSchedulerInterface>();
    registry.register::<IpcInterface>();
    
    crate::log!("[TypeID] Registered {} kernel interfaces\n", registry.len());
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_const_hash() {
        let hash1 = const_hash(b"test");
        let hash2 = const_hash(b"test");
        let hash3 = const_hash(b"different");
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_semver_compatibility() {
        let v1_0_0 = SemVer::new(1, 0, 0);
        let v1_1_0 = SemVer::new(1, 1, 0);
        let v2_0_0 = SemVer::new(2, 0, 0);
        
        assert!(v1_1_0.is_backward_compatible(&v1_0_0));
        assert!(!v1_0_0.is_backward_compatible(&v1_1_0));
        assert!(!v2_0_0.is_backward_compatible(&v1_0_0));
    }
}
