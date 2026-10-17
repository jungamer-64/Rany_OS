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
    // LOOP_PROOF: mode=condition; reason=The byte index increases once per matched byte and a mismatch or the finite equal slice length ends comparison.;
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
#[derive(Default)]
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
    /// # Errors
    /// Reports an unregistered name or a provider fingerprint that differs from
    /// the importing artifact's expected hash. Verification does not register it.
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
    ///
    /// # Errors
    /// Requires both an exact fingerprint match and a provider version accepted
    /// by [`SemVer::is_backward_compatible`]; neither check replaces the other.
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

/// An ABI requirement borrowed from an immutable artifact, not cell identity.
#[derive(Debug, Clone)]
pub struct DependencyEntry<'a> {
    /// インターフェース名
    pub interface: &'a str,
    /// 要求するハッシュ値
    pub hash: TypeHash,
    /// 要求する最小バージョン
    pub min_version: SemVer,
}

/// Parsing never publishes a prefix of a malformed dependency list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyMetadataError {
    Sections(super::elf::SectionError),
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u32),
    InvalidName,
    OutOfMemory,
}

impl core::fmt::Display for DependencyMetadataError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sections(error) => error.fmt(f),
            Self::Truncated => f.write_str("truncated ABI dependency fragment"),
            Self::InvalidMagic => f.write_str("invalid ABI dependency magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported ABI dependency format {version}")
            }
            Self::InvalidName => f.write_str("ABI interface name is empty or is not UTF-8"),
            Self::OutOfMemory => f.write_str("cannot reserve ABI dependency records"),
        }
    }
}

/// Read every dependency fragment emitted into the ELF metadata section.
/// `None` means only that the section is absent; an empty declared list is `Some`.
/// Names borrow the artifact and no cell name/version is inferred from them.
///
/// # Errors
/// Malformed ELF sections, unsupported/truncated records, invalid names and
/// allocation failure are distinct from absence. No partial list escapes.
pub fn extract_type_ids<'a>(
    loader: &super::elf::ElfLoader<'a>,
) -> Result<Option<Vec<DependencyEntry<'a>>>, DependencyMetadataError> {
    loader
        .section_data(b".rany_type_id")
        .map_err(DependencyMetadataError::Sections)?
        .map(parse_type_id_section)
        .transpose()
}

fn parse_type_id_section(
    mut data: &[u8],
) -> Result<Vec<DependencyEntry<'_>>, DependencyMetadataError> {
    use kernel_api::type_metadata::{
        ENTRY_NAME_LEN, ENTRY_SIZE, FORMAT_VERSION, HEADER_SIZE, MAGIC,
    };
    if data.is_empty() {
        return Err(DependencyMetadataError::Truncated);
    }
    let mut dependencies = Vec::new();
    // LOOP_PROOF: mode=condition; reason=Each successful iteration consumes at least one header from the finite input slice and an empty remainder ends parsing.;
    while !data.is_empty() {
        let header = data
            .get(..HEADER_SIZE)
            .ok_or(DependencyMetadataError::Truncated)?;
        if header[..4] != MAGIC {
            return Err(DependencyMetadataError::InvalidMagic);
        }
        let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if version != FORMAT_VERSION {
            return Err(DependencyMetadataError::UnsupportedVersion(version));
        }
        let count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let end = count
            .checked_mul(ENTRY_SIZE)
            .and_then(|bytes| HEADER_SIZE.checked_add(bytes))
            .ok_or(DependencyMetadataError::Truncated)?;
        let entries = data
            .get(HEADER_SIZE..end)
            .ok_or(DependencyMetadataError::Truncated)?;
        dependencies
            .try_reserve(count)
            .map_err(|_| DependencyMetadataError::OutOfMemory)?;
        for entry in entries.as_chunks::<ENTRY_SIZE>().0 {
            let name = &entry[..ENTRY_NAME_LEN];
            let end = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(ENTRY_NAME_LEN);
            let interface = core::str::from_utf8(&name[..end])
                .map_err(|_| DependencyMetadataError::InvalidName)?;
            if interface.is_empty() {
                return Err(DependencyMetadataError::InvalidName);
            }
            dependencies.push(DependencyEntry {
                interface,
                hash: u64::from_le_bytes([
                    entry[64], entry[65], entry[66], entry[67], entry[68], entry[69], entry[70],
                    entry[71],
                ]),
                min_version: SemVer::new(
                    u16::from_le_bytes([entry[72], entry[73]]),
                    u16::from_le_bytes([entry[74], entry[75]]),
                    u16::from_le_bytes([entry[76], entry[77]]),
                ),
            });
        }
        data = &data[end..];
    }
    Ok(dependencies)
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

/// Verify all imported fingerprints and minimum versions against registered providers.
///
/// # Errors
/// Returns the first missing interface, hash mismatch or incompatible version.
pub fn verify_cell_dependencies(deps: &[DependencyEntry<'_>]) -> Result<(), TypeIdError> {
    let registry = INTERFACE_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());

    for dep in deps {
        registry.verify_with_version(dep.interface, dep.hash, dep.min_version)?;
    }

    Ok(())
}

// ============================================================================
// 標準カーネルインターフェースの定義
// ============================================================================

/// カーネルインターフェースの初期化
pub fn init_kernel_interfaces() {
    let mut registry = INTERFACE_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    use kernel_api::type_metadata::{
        DRIVER_EXPORTS_INTERFACE, IPC_INTERFACE, KERNEL_API_INTERFACE, MEMORY_ALLOCATOR_INTERFACE,
        TASK_SCHEDULER_INTERFACE,
    };
    let interfaces = [
        MEMORY_ALLOCATOR_INTERFACE,
        TASK_SCHEDULER_INTERFACE,
        IPC_INTERFACE,
        KERNEL_API_INTERFACE,
        DRIVER_EXPORTS_INTERFACE,
    ];
    registry.reserve(interfaces.len());
    for interface in interfaces {
        registry.register_manual(
            Cow::Borrowed(interface.name),
            interface.hash,
            SemVer::new(interface.major, interface.minor, interface.patch),
        );
    }

    log::info!("[TypeID] Registered {} kernel interfaces\n", registry.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependency_fragment(name: &[u8]) -> Vec<u8> {
        // Independent wire vector: RTID v1, one 78-byte record.
        let mut bytes = vec![0; 90];
        bytes[..12].copy_from_slice(b"RTID\x01\0\0\0\x01\0\0\0");
        bytes[12..12 + name.len()].copy_from_slice(name);
        bytes[76..84].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
        bytes[84..90].copy_from_slice(&[2, 0, 3, 0, 4, 0]);
        bytes
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn dependency_fragments_preserve_every_requirement() {
        let mut bytes = dependency_fragment(b"First");
        bytes.extend_from_slice(b"RTID\x01\0\0\0\0\0\0\0");
        bytes.extend_from_slice(&dependency_fragment(&[b'X'; 64]));
        let dependencies = parse_type_id_section(&bytes).expect("complete fragments");
        assert_eq!(dependencies.len(), 2);
        assert_eq!(dependencies[0].interface, "First");
        assert_eq!(dependencies[0].hash, 0x0123_4567_89ab_cdef);
        assert_eq!(dependencies[0].min_version, SemVer::new(2, 3, 4));
        assert_eq!(dependencies[1].interface.as_bytes(), &[b'X'; 64]);
        assert!(
            parse_type_id_section(b"RTID\x01\0\0\0\0\0\0\0")
                .unwrap()
                .is_empty()
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn dependency_fragments_reject_incomplete_lists_and_trailing_bytes() {
        let bytes = dependency_fragment(b"First");
        for size in [0, 11, 12, 89] {
            assert_eq!(
                parse_type_id_section(&bytes[..size]).unwrap_err(),
                DependencyMetadataError::Truncated
            );
        }
        let mut truncated = bytes.clone();
        truncated[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            parse_type_id_section(&truncated).unwrap_err(),
            DependencyMetadataError::Truncated
        );
        truncated[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            parse_type_id_section(&truncated).unwrap_err(),
            DependencyMetadataError::Truncated
        );
        let mut trailing = bytes;
        trailing.extend_from_slice(b"RTID\x01\0\0\0\x01\0\0\0");
        assert_eq!(
            parse_type_id_section(&trailing).unwrap_err(),
            DependencyMetadataError::Truncated
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn dependency_fragments_reject_unknown_formats_and_invalid_identity() {
        let mut bytes = dependency_fragment(b"First");
        bytes[0] = b'X';
        assert_eq!(
            parse_type_id_section(&bytes).unwrap_err(),
            DependencyMetadataError::InvalidMagic
        );
        bytes[0] = b'R';
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            parse_type_id_section(&bytes).unwrap_err(),
            DependencyMetadataError::UnsupportedVersion(2)
        );
        assert_eq!(
            parse_type_id_section(&dependency_fragment(b"")).unwrap_err(),
            DependencyMetadataError::InvalidName
        );
        assert_eq!(
            parse_type_id_section(&dependency_fragment(&[0xff])).unwrap_err(),
            DependencyMetadataError::InvalidName
        );
    }

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

        let deps = [DependencyEntry {
            interface: iface,
            hash,
            min_version: SemVer::new(1, 0, 0),
        }];

        assert!(verify_cell_dependencies(&deps).is_ok());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_verify_cell_dependencies_rejects_hash_mismatch() {
        let iface = "TypeIdVerifyMismatchIface";
        let actual = 0x1111_2222_3333_4444;
        let required = 0x9999_aaaa_bbbb_cccc;
        register_kernel_interface_manual(iface, actual, SemVer::new(1, 0, 0));

        let deps = [DependencyEntry {
            interface: iface,
            hash: required,
            min_version: SemVer::new(1, 0, 0),
        }];

        let err = verify_cell_dependencies(&deps).expect_err("hash mismatch must be rejected");
        assert!(matches!(err, TypeIdError::HashMismatch { .. }));
    }
}
