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
use crate::sync::PoisonLock;
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
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
        Self {
            major,
            minor,
            patch,
        }
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
    pub name: Cow<'static, str>,
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
            name: Cow::Borrowed(Self::type_name()),
            hash: Self::type_id_hash(),
            version: Self::type_version(),
        }
    }
}

/// コンパイル時定数ハッシュ関数（FNV-1a）
///
/// 型定義文字列からハッシュを計算します。
/// `crate::util::fnv1a_hash`のエイリアス。
#[inline]
pub const fn const_hash(bytes: &[u8]) -> TypeHash {
    crate::util::fnv1a_hash(bytes)
}

#[inline(never)]
fn str_eq_bytewise(lhs: &str, rhs: &str) -> bool {
    let lhs_bytes = lhs.as_bytes();
    let rhs_bytes = rhs.as_bytes();
    if lhs_bytes.len() != rhs_bytes.len() {
        return false;
    }

    let mut index = 0usize;
    while index < lhs_bytes.len() {
        if lhs_bytes[index] != rhs_bytes[index] {
            return false;
        }
        index += 1;
    }

    true
}

/// インターフェース定義のレジストリ
///
/// カーネルが提供するインターフェースのハッシュ値を管理します。
pub struct InterfaceRegistry {
    /// 登録済みインターフェース一覧（名前は一意）
    interfaces: Vec<TypeIdInfo>,
}

impl InterfaceRegistry {
    pub const fn new() -> Self {
        Self {
            interfaces: Vec::new(),
        }
    }

    /// インターフェースを登録
    pub fn register<T: TypeIdHash>(&mut self) {
        let info = T::type_id_info();
        self.register_manual(info.name, info.hash, info.version);
    }

    /// インターフェースを手動登録（名前とハッシュを指定）
    pub fn register_manual(&mut self, name: Cow<'static, str>, hash: TypeHash, version: SemVer) {
        for index in 0..self.interfaces.len() {
            if str_eq_bytewise(self.interfaces[index].name.as_ref(), name.as_ref()) {
                let existing = &mut self.interfaces[index];
                existing.hash = hash;
                existing.version = version;
                return;
            }
        }
        self.interfaces.push(TypeIdInfo {
            name,
            hash,
            version,
        });
    }

    /// 初期ブート時の再配置を避けるために、必要容量を先に確保する。
    pub fn reserve(&mut self, additional: usize) {
        self.interfaces.reserve(additional);
    }

    /// インターフェースのハッシュを検証
    ///
    /// # Returns
    /// - `Ok(())`: ハッシュが一致
    /// - `Err(TypeIdError)`: ハッシュ不一致または未登録
    pub fn verify(&self, name: &str, expected_hash: TypeHash) -> Result<(), TypeIdError> {
        match self
            .interfaces
            .iter()
            .find(|i| str_eq_bytewise(i.name.as_ref(), name))
        {
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
        match self
            .interfaces
            .iter()
            .find(|i| str_eq_bytewise(i.name.as_ref(), name))
        {
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
    InterfaceNotFound { interface: String },
}

impl core::fmt::Display for TypeIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TypeIdError::HashMismatch {
                interface,
                expected,
                actual,
                version,
            } => {
                write!(
                    f,
                    "ABI incompatibility for '{}' (v{}): expected hash {:#x}, got {:#x}",
                    interface, version, expected, actual
                )
            }
            TypeIdError::VersionIncompatible {
                interface,
                required,
                actual,
            } => {
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

/// ELFヘッダーとセクションテーブルを検証し、基本パラメータを返す
fn validate_elf_sections(elf_data: &[u8]) -> Option<(usize, usize, usize, usize)> {
    use crate::loader::elf::Elf64Header;

    if elf_data.len() < 64 || &elf_data[0..4] != b"\x7fELF" {
        return None;
    }

    let header = crate::util::get_ref::<Elf64Header>(elf_data, 0)?;

    let sh_offset = header.e_shoff as usize;
    let sh_entsize = header.e_shentsize as usize;
    let sh_num = header.e_shnum as usize;
    let shstrtab_idx = header.e_shstrndx as usize;

    if sh_offset == 0 || sh_num == 0 || shstrtab_idx >= sh_num {
        return None;
    }
    if sh_offset + sh_num * sh_entsize > elf_data.len() {
        return None;
    }

    Some((sh_offset, sh_entsize, sh_num, shstrtab_idx))
}

/// セクション名文字列テーブルの範囲を取得
fn get_shstrtab_range(
    elf_data: &[u8],
    sh_offset: usize,
    sh_entsize: usize,
    shstrtab_idx: usize,
) -> Option<(usize, usize)> {
    use crate::loader::elf::Elf64SectionHeader;

    let shstrtab_header_offset = sh_offset + shstrtab_idx * sh_entsize;
    let shstrtab_header =
        crate::util::get_ref::<Elf64SectionHeader>(elf_data, shstrtab_header_offset)?;
    let start = shstrtab_header.sh_offset as usize;
    let size = shstrtab_header.sh_size as usize;

    if start + size > elf_data.len() {
        return None;
    }

    Some((start, size))
}

/// shstrtabから名前付きセクションデータを検索
fn find_named_section_data<'a>(
    elf_data: &'a [u8],
    sh_offset: usize,
    sh_entsize: usize,
    sh_num: usize,
    shstrtab_start: usize,
    shstrtab_size: usize,
    target_name: &str,
) -> Option<&'a [u8]> {
    use crate::loader::elf::Elf64SectionHeader;

    for i in 0..sh_num {
        let sh_header_offset = sh_offset + i * sh_entsize;
        let section_header =
            crate::util::get_ref::<Elf64SectionHeader>(elf_data, sh_header_offset)?;

        let name_offset = section_header.sh_name as usize;
        if name_offset >= shstrtab_size {
            continue;
        }

        let name_start = shstrtab_start + name_offset;
        let mut name_end = name_start;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while name_end < elf_data.len() && elf_data[name_end] != 0 {
            name_end += 1;
        }

        let section_name = core::str::from_utf8(&elf_data[name_start..name_end]).ok()?;

        if section_name == target_name {
            let data_start = section_header.sh_offset as usize;
            let data_size = section_header.sh_size as usize;

            if data_start + data_size > elf_data.len() {
                return None;
            }

            return Some(&elf_data[data_start..data_start + data_size]);
        }
    }

    None
}

/// ELFバイナリからType ID情報を抽出
///
/// セルのメタデータセクション（.rany_type_id）からハッシュ情報を読み取ります。
pub fn extract_type_ids(elf_data: &[u8]) -> Option<CellDependencies> {
    let (sh_offset, sh_entsize, sh_num, shstrtab_idx) = validate_elf_sections(elf_data)?;
    let (shstrtab_start, shstrtab_size) =
        get_shstrtab_range(elf_data, sh_offset, sh_entsize, shstrtab_idx)?;

    let section_data = find_named_section_data(
        elf_data,
        sh_offset,
        sh_entsize,
        sh_num,
        shstrtab_start,
        shstrtab_size,
        ".rany_type_id",
    )?;

    parse_type_id_section(section_data)
}

/// .rany_type_id セクションの内容を解析
fn parse_type_id_section(data: &[u8]) -> Option<CellDependencies> {
    // セクションフォーマット:
    // - 4 bytes: magic ("RTID")
    // - 4 bytes: version
    // - 4 bytes: dependency count
    // - For each dependency:
    //   - 64 bytes: interface name (null-terminated)
    //   - 8 bytes: type hash
    //   - 2 bytes: major version
    //   - 2 bytes: minor version
    //   - 2 bytes: patch version

    if data.len() < 12 {
        return None;
    }

    // Magicチェック
    if &data[0..4] != b"RTID" {
        return None;
    }

    let _version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let dep_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

    let mut dependencies = Vec::new();
    let mut offset = 12;

    for _ in 0..dep_count {
        if offset + 78 > data.len() {
            break;
        }

        // インターフェース名
        let name_end = data[offset..offset + 64]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(64);
        let interface = core::str::from_utf8(&data[offset..offset + name_end])
            .ok()?
            .to_string();
        offset += 64;

        // ハッシュ（u64）
        let hash = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        // バージョン
        let major = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let minor = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let patch = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        offset += 6;

        dependencies.push(DependencyEntry {
            interface: String::from(interface),
            hash,
            min_version: SemVer {
                major,
                minor,
                patch,
            },
        });
    }

    Some(CellDependencies {
        cell_name: String::new(), // セクションには名前がないためデフォルト
        cell_version: SemVer::new(0, 0, 0),
        dependencies,
    })
}

/// グローバルインターフェースレジストリ
static INTERFACE_REGISTRY: PoisonLock<InterfaceRegistry> =
    PoisonLock::new(InterfaceRegistry::new());

/// カーネルインターフェースを登録
pub fn register_kernel_interface<T: TypeIdHash>() {
    INTERFACE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .register::<T>();
}

/// カーネルインターフェースを手動登録
pub fn register_kernel_interface_manual(name: &str, hash: TypeHash, version: SemVer) {
    INTERFACE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .register_manual(Cow::Owned(String::from(name)), hash, version);
}

/// 登録済みカーネルインターフェースを取得（シェル観測用）
pub fn get_kernel_interface(name: &str) -> Option<TypeIdInfo> {
    INTERFACE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .interfaces
        .iter()
        .find(|i| str_eq_bytewise(i.name.as_ref(), name))
        .cloned()
}

/// 登録済みカーネルインターフェースを列挙（シェル観測用）
pub fn list_kernel_interfaces() -> Vec<TypeIdInfo> {
    INTERFACE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .interfaces
        .clone()
}

/// セルの依存関係を検証
pub fn verify_cell_dependencies(deps: &CellDependencies) -> Result<(), TypeIdError> {
    let registry = INTERFACE_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());

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

pub struct KernelApiInterface;

impl TypeIdHash for KernelApiInterface {
    fn type_id_hash() -> TypeHash {
        const_hash(b"KernelApiInterface:v11:KernelApiV4+dma_lease+exchange_heap+ipc_raw+domain_id+net_packet")
    }

    fn type_name() -> &'static str {
        "KernelApiInterface"
    }

    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
    }
}

pub struct DriverExportsInterface;

impl TypeIdHash for DriverExportsInterface {
    fn type_id_hash() -> TypeHash {
        const_hash(b"DriverExportsInterface:v2:DriverExportsV1+state_hooks")
    }

    fn type_name() -> &'static str {
        "DriverExportsInterface"
    }

    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
    }
}

/// カーネルインターフェースの初期化
pub fn init_kernel_interfaces() {
    let mut registry = INTERFACE_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    registry.reserve(5);

    // 標準カーネルインターフェースを登録
    registry.register::<MemoryAllocatorInterface>();
    registry.register::<TaskSchedulerInterface>();
    registry.register::<IpcInterface>();
    registry.register::<KernelApiInterface>();
    registry.register::<DriverExportsInterface>();

    log::info!("[TypeID] Registered {} kernel interfaces\n", registry.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_get_and_list_kernel_interfaces() {
        let name = "TypeIdTestManualIface";
        let hash = 0x1234_5678_9abc_def0;
        let ver = SemVer::new(9, 1, 2);
        register_kernel_interface_manual(name, hash, ver);

        let got = get_kernel_interface(name).expect("interface should exist");
        assert_eq!(got.name, name);
        assert_eq!(got.hash, hash);
        assert_eq!(got.version, ver);

        let all = list_kernel_interfaces();
        assert!(all.iter().any(|i| i.name == name && i.hash == hash));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_verify_cell_dependencies_accepts_matching_hash() {
        let iface = "TypeIdVerifyMatchIface";
        let hash = 0xdead_beef_cafe_babe;
        let ver = SemVer::new(1, 2, 0);
        register_kernel_interface_manual(iface, hash, ver);

        let deps = CellDependencies {
            cell_name: String::from("test-cell"),
            cell_version: SemVer::new(1, 0, 0),
            dependencies: vec![DependencyEntry {
                interface: String::from(iface),
                hash,
                min_version: SemVer::new(1, 0, 0),
            }],
        };

        assert!(verify_cell_dependencies(&deps).is_ok());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_verify_cell_dependencies_rejects_hash_mismatch() {
        let iface = "TypeIdVerifyMismatchIface";
        let actual = 0x1111_2222_3333_4444;
        let required = 0x9999_aaaa_bbbb_cccc;
        register_kernel_interface_manual(iface, actual, SemVer::new(1, 0, 0));

        let deps = CellDependencies {
            cell_name: String::from("test-cell"),
            cell_version: SemVer::new(1, 0, 0),
            dependencies: vec![DependencyEntry {
                interface: String::from(iface),
                hash: required,
                min_version: SemVer::new(1, 0, 0),
            }],
        };

        let err = verify_cell_dependencies(&deps).expect_err("hash mismatch must be rejected");
        assert!(matches!(err, TypeIdError::HashMismatch { .. }));
    }
}
