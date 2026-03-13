// ============================================================================
// src/loader/mod.rs - Cell (Module) Loader
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 3.3: コンパイラ署名とロード時検証
// 設計書 3.4: ABIの安定性とType ID Check
// ============================================================================
#![allow(dead_code)]

#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub mod boot_artifacts; // Boot artifact handoff からのセルロード
pub mod driver_pack;
pub mod elf;
pub mod live_update; // 新: ライブアップデート・Epoch-based Reclamation (設計書 3.5)
pub mod loop_proof;
pub mod signature;
pub mod staged_pci;
pub mod type_id;

mod cell_lookup;
#[allow(unused_imports)]
pub(crate) use cell_lookup::*;
#[allow(unused_imports)]
pub use elf::{CellInfo, ElfLoader, LoadedCell, LoadedInfo, Loader};
#[allow(unused_imports)]
pub use live_update::{
    CompletedUpdateOutcome, LiveUpdateError, LiveUpdateManager, LiveUpdateState,
    PendingUpdateStatus, RequestTracker, UpdateTransition, current_epoch, enter_critical_section,
    enter_quiescent_state, leave_critical_section, live_update_manager, poll_pending_updates,
    wait_for_quiescent_state,
};
#[allow(unused_imports)]
pub use signature::{
    CellSignature, KeyId, KeyLevel, RevocationSet, SignatureVerifier, add_trusted_key_with_level,
    revoke_cell_hash, revoke_key, verify_cell,
};

use crate::driver_registry::{
    DriverHandle, register_abi_driver_with_context, register_exports_driver_with_context,
};
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kernel_api::abi::driver::{
    DRIVER_ENTRY_SYMBOL, DRIVER_EXPORTS_SYMBOL, DriverContext as AbiDriverContext, DriverExportsV1,
};

#[inline]
pub(crate) fn str_eq(lhs: &str, rhs: &str) -> bool {
    let lhs_bytes = lhs.as_bytes();
    let rhs_bytes = rhs.as_bytes();
    if lhs_bytes.len() != rhs_bytes.len() {
        return false;
    }
    let mut idx = 0usize;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while idx < lhs_bytes.len() {
        if lhs_bytes[idx] != rhs_bytes[idx] {
            return false;
        }
        idx += 1;
    }
    true
}

/// セルの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellState {
    /// ロード待ち
    Pending,
    /// ロード中
    Loading,
    /// ロード完了、実行可能
    Loaded,
    /// 実行中
    Running,
    /// 停止
    Stopped,
    /// エラー
    Error,
}

/// モジュール統計情報
///
/// ロードされたモジュールのパフォーマンスとリソース使用状況を追跡
#[derive(Debug, Clone, Default)]
pub struct ModuleStats {
    /// ロード時刻（TSCタイムスタンプ）
    pub load_timestamp: u64,
    /// ロードにかかった時間（TSCサイクル）
    pub load_duration_cycles: u64,
    /// シンボル数
    pub symbol_count: usize,
    /// リロケーション適用数
    pub relocation_count: usize,
    /// メモリ使用量（バイト）
    pub memory_usage: usize,
    /// セグメント数
    pub segment_count: usize,
    /// ASLRオフセット
    pub aslr_offset: usize,
    /// W^X違反のチェック回数
    pub wx_check_count: usize,
}

/// ロードされたセルの管理情報
#[derive(Debug)]
pub struct CellRegistry {
    /// セルID -> セル情報のマッピング
    cells: BTreeMap<CellId, CellEntry>,
    /// シンボルテーブル（名前 -> アドレス）
    pub symbol_table: Vec<(String, usize)>,
    /// 次のセルID
    next_id: u64,
}

/// セルID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(u64);

impl CellId {
    pub const KERNEL: CellId = CellId(0);

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn from_u64(id: u64) -> Self {
        Self(id)
    }
}

/// セルエントリ
#[derive(Debug)]
pub struct CellEntry {
    /// セルID
    pub id: CellId,
    /// セル名
    pub name: String,
    /// 状態
    pub state: CellState,
    /// ロードされたアドレス範囲
    pub load_address: usize,
    pub load_size: usize,
    /// ヒープに実際に確保した先頭（ASLR補正前）
    pub allocation_base: usize,
    /// ヒープに実際に確保したサイズ（ASLRパディング込み）
    pub allocation_size: usize,
    /// エントリポイント
    pub entry_point: Option<usize>,
    /// エクスポートされたシンボル
    /// (名前, アドレス)
    pub exports: Vec<(String, usize)>,
    /// インポートしているシンボル（依存関係）
    pub imports: Vec<String>,
    /// 依存するセル
    pub dependencies: Vec<CellId>,
    /// Safe Rustのみかどうか
    pub is_safe: bool,
    /// 署名が検証済みかどうか
    pub signature_verified: bool,
    /// 要求ケイパビリティ（マニフェスト由来、0は未指定）
    pub required_caps: u64,
    /// 登録されたドライバ（このセルに依存するドライバ）
    pub registered_drivers: Vec<DriverHandle>,
    /// 割り当てられた Protection Key
    pub pkey: Option<u8>,
    /// モジュール統計情報
    pub stats: ModuleStats,
}

impl CellRegistry {
    pub const fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            symbol_table: Vec::new(),
            next_id: 1, // 0はカーネル用
        }
    }

    pub fn register_symbol(&mut self, symbol: String, addr: usize) {
        if self
            .symbol_table
            .iter()
            .any(|(name, _)| str_eq(name.as_str(), symbol.as_str()))
        {
            return;
        }
        self.symbol_table.push((symbol, addr));
    }

    fn unregister_symbol(&mut self, symbol: &str) {
        self.symbol_table
            .retain(|(name, _)| !str_eq(name.as_str(), symbol));
    }

    /// 新しいセルIDを生成
    pub fn allocate_id(&mut self) -> CellId {
        let id = CellId(self.next_id);
        self.next_id += 1;
        id
    }

    /// セルを登録
    pub fn register(&mut self, entry: CellEntry) {
        crate::io::log::early_print("[LDBG] registry.register: begin\n");
        let is_shadow_staging = entry.name.starts_with("update-")
            || self.cells.values().any(|cell| cell.name == entry.name);
        if is_shadow_staging {
            crate::io::log::early_print(
                "[LDBG] registry.register: staging duplicate-name, skip symtab\n",
            );
        }
        if !is_shadow_staging {
            for (_idx, (symbol, addr)) in entry.exports.iter().enumerate() {
                if (_idx & 0x3f) == 0 {
                    crate::io::log::early_print("[LDBG] registry.register: export idx=");
                    crate::io::log::early_print_hex(_idx as u64);
                    crate::io::log::early_print("\n");
                }
                self.register_symbol(symbol.clone(), *addr);
            }
        }
        crate::io::log::early_print("[LDBG] registry.register: exports done\n");
        self.cells.insert(entry.id, entry);
        crate::io::log::early_print("[LDBG] registry.register: cells.insert done\n");
    }

    /// セルを取得
    pub fn get(&self, id: CellId) -> Option<&CellEntry> {
        self.cells.get(&id)
    }

    /// セルを変更
    pub fn get_mut(&mut self, id: CellId) -> Option<&mut CellEntry> {
        self.cells.get_mut(&id)
    }

    /// シンボルを解決
    pub fn resolve_symbol(&self, name: &str) -> Option<usize> {
        if str_eq(name, kernel_api::abi::driver::KERNEL_API_SYMBOL) {
            return Some(crate::driver_registry::kernel_api_v3()
                as *const kernel_api::abi::driver::KernelApiV3
                as usize);
        }

        self.symbol_table
            .iter()
            .find_map(|(symbol, addr)| str_eq(symbol.as_str(), name).then_some(*addr))
    }

    /// セルをアンロード
    pub fn unload(&mut self, id: CellId) -> Option<CellEntry> {
        if let Some(entry) = self.cells.remove(&id) {
            let live_update_shadow_involved = entry.name.starts_with("update-")
                || self
                    .cells
                    .values()
                    .any(|cell| cell.name.starts_with("update-"));
            if live_update_shadow_involved {
                crate::io::log::early_print(
                    "[LDBG] registry.unload: live-update shadow involved, skip symtab remove\n",
                );
            } else {
                for (symbol, _) in &entry.exports {
                    self.unregister_symbol(symbol);
                }
            }
            Some(entry)
        } else {
            None
        }
    }

    /// 名前でセルを検索
    pub fn find_by_name(&self, name: &str) -> Option<&CellEntry> {
        self.cells.values().find(|c| str_eq(c.name.as_str(), name))
    }

    /// 全セルを列挙
    pub fn all_cells(&self) -> impl Iterator<Item = &CellEntry> {
        self.cells.values()
    }

    /// 特定の状態のセルを列挙
    pub fn cells_by_state(&self, state: CellState) -> impl Iterator<Item = &CellEntry> {
        self.cells.values().filter(move |c| c.state == state)
    }

    /// List all loaded cells (public API for shell)
    pub fn list(&self) -> Vec<ExoCellInfo> {
        self.cells
            .values()
            .map(|c| ExoCellInfo {
                id: c.id,
                name: c.name.clone(),
                base_address: c.load_address as u64,
                size: c.load_size,
                driver_count: c.registered_drivers.len(),
            })
            .collect()
    }
}

/// Public info about a cell for listing (Shell API)
#[derive(Debug, Clone)]
pub struct ExoCellInfo {
    pub id: CellId,
    pub name: String,
    pub base_address: u64,
    pub size: usize,
    pub driver_count: usize,
}

/// グローバルセルレジストリ
static CELL_REGISTRY: PoisonLock<CellRegistry> = PoisonLock::new(CellRegistry::new());

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    let mut registry = CELL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    *registry = CellRegistry::new();
}

/// セルレジストリにアクセス
pub fn with_registry<F, R>(f: F) -> R
where
    F: FnOnce(&CellRegistry) -> R,
{
    f(&CELL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()))
}

/// セルレジストリを変更
pub fn with_registry_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut CellRegistry) -> R,
{
    f(&mut CELL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()))
}

/// ロードエラー
#[derive(Debug, Clone)]
pub enum LoadError {
    /// ELFフォーマットが不正
    InvalidFormat(String),
    /// 署名が無効
    InvalidSignature,
    /// 依存関係が解決できない
    UnresolvedDependency(String),
    /// メモリ割り当て失敗
    OutOfMemory,
    /// unsafeコードが許可されていない
    UnsafeNotAllowed,
    /// すでにロード済み
    AlreadyLoaded,
    /// 【設計書 3.4】ABI非互換
    AbiIncompatible(String),
    /// ループ境界証明セクションが欠落
    LoopProofMissing,
    /// ループ境界証明セクションが不正
    LoopProofInvalid(String),
    /// セルが見つからない
    CellNotFound,
    /// リロケーション失敗
    RelocationFailed(String),
    /// セグメント権限エラー（W^X違反など）
    InvalidPermissions(String),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoadError::InvalidFormat(msg) => write!(f, "Invalid ELF format: {}", msg),
            LoadError::InvalidSignature => write!(f, "Invalid or missing signature"),
            LoadError::UnresolvedDependency(sym) => write!(f, "Unresolved dependency: {}", sym),
            LoadError::OutOfMemory => write!(f, "Out of memory"),
            LoadError::UnsafeNotAllowed => write!(f, "Unsafe code not allowed for this cell"),
            LoadError::AlreadyLoaded => write!(f, "Cell already loaded"),
            LoadError::AbiIncompatible(msg) => write!(f, "ABI incompatibility: {}", msg),
            LoadError::LoopProofMissing => {
                write!(f, "Loop proof metadata missing (.rany_loop_proof)")
            }
            LoadError::LoopProofInvalid(msg) => {
                write!(f, "Loop proof metadata invalid: {}", msg)
            }
            LoadError::CellNotFound => write!(f, "Cell not found"),
            LoadError::RelocationFailed(msg) => write!(f, "Relocation failed: {}", msg),
            LoadError::InvalidPermissions(msg) => write!(f, "Invalid permissions: {}", msg),
        }
    }
}

/// セルをロード（メインAPI）
pub fn load_cell(name: &str, elf_data: &[u8], allow_unsafe: bool) -> Result<CellId, LoadError> {
    // 1. 署名の検証
    let signature = signature::extract_signature(elf_data)?;
    if !signature::verify_signature(&signature, elf_data) {
        return Err(LoadError::InvalidSignature);
    }

    load_cell_with_flags(
        name,
        elf_data,
        allow_unsafe,
        signature.contains_unsafe,
        true,
        0,
    )
}

fn validate_driver_pack_manifest(
    manifest: &driver_pack::DriverManifestV1,
) -> Result<(), LoadError> {
    let driver_abi = manifest.driver_abi_version as u64;
    if driver_abi != kernel_api::abi::driver::DRIVER_ABI_VERSION {
        return Err(LoadError::AbiIncompatible(
            "Driver ABI version mismatch".into(),
        ));
    }

    if manifest.kernel_api_min_version > kernel_api::abi::driver::KERNEL_API_ABI_VERSION {
        return Err(LoadError::AbiIncompatible(
            "Kernel API ABI version too old".into(),
        ));
    }

    Ok(())
}

fn load_driver_pack_cell(
    name: &str,
    pack_data: &[u8],
    allow_unsafe: bool,
) -> Result<CellId, LoadError> {
    let pack = driver_pack::parse_driver_pack(pack_data)?;
    let signature_verified = driver_pack::verify_driver_pack(&pack)?;
    validate_driver_pack_manifest(&pack.manifest)?;

    let manifest_name = pack.manifest.name_str();
    let driver_name = if manifest_name.is_empty() {
        name
    } else {
        manifest_name
    };

    load_cell_with_flags(
        driver_name,
        pack.elf,
        allow_unsafe,
        pack.manifest.contains_unsafe(),
        signature_verified,
        pack.manifest.required_caps,
    )
}

/// Load a driver artifact as a Cell without registering the driver yet.
///
/// This preserves the DriverDomain lifecycle split between load and start while
/// still accepting packaged driver artifacts staged from boot artifacts or PCI
/// probing.
pub(crate) fn load_driver_artifact_cell(
    name: &str,
    data: &[u8],
    allow_unsafe: bool,
) -> Result<CellId, LoadError> {
    if driver_pack::is_driver_pack(data) {
        load_driver_pack_cell(name, data, allow_unsafe)
    } else {
        load_cell(name, data, allow_unsafe)
    }
}

/// Validate unsafe flags and type ID dependencies
fn validate_cell_requirements(
    name: &str,
    elf_data: &[u8],
    allow_unsafe: bool,
    contains_unsafe: bool,
) -> Result<(), LoadError> {
    if !allow_unsafe && contains_unsafe {
        return Err(LoadError::UnsafeNotAllowed);
    }
    crate::io::log::early_print("[LDBG] validate deps extract\n");
    if let Some(deps) = type_id::extract_type_ids(elf_data) {
        crate::io::log::early_print("[LDBG] validate deps verify\n");
        if let Err(e) = type_id::verify_cell_dependencies(&deps) {
            log::info!(
                "[Loader] Type ID verification failed for '{}': {}\n",
                name,
                e
            );
            return Err(LoadError::AbiIncompatible(alloc::format!("{}", e)));
        }
        crate::io::log::early_print("[LDBG] validate deps ok\n");
        crate::io::log::early_print("[LDBG] type_id log begin\n");
        log::info!(
            "[Loader] Type ID verified for '{}' ({})\n",
            name,
            deps.cell_version
        );
        crate::io::log::early_print("[LDBG] type_id log end\n");
    }

    crate::io::log::early_print("[LDBG] loop proof begin\n");
    match loop_proof::verify_loop_proof_metadata(elf_data) {
        Ok(meta) => {
            crate::io::log::early_print("[LDBG] loop proof ok\n");
            log::info!(
                "[Loader] Loop proof verified for '{}' (version={}, flags={})\n",
                name,
                meta.version,
                meta.policy_flags
            );
            crate::io::log::early_print("[LDBG] loop proof ok logged\n");
        }
        Err(loop_proof::LoopProofError::MissingSection) => {
            crate::io::log::early_print("[LDBG] loop proof missing\n");
            log::warn!(
                "[Loader] Missing loop proof metadata for '{}': {}\n",
                name,
                loop_proof::LOOP_PROOF_SECTION_NAME
            );
            return Err(LoadError::LoopProofMissing);
        }
        Err(e) => {
            crate::io::log::early_print("[LDBG] loop proof invalid\n");
            log::warn!(
                "[Loader] Invalid loop proof metadata for '{}': {}\n",
                name,
                e
            );
            return Err(LoadError::LoopProofInvalid(alloc::format!("{}", e)));
        }
    }
    crate::io::log::early_print("[LDBG] loop proof end\n");
    Ok(())
}

fn load_cell_with_flags(
    name: &str,
    elf_data: &[u8],
    allow_unsafe: bool,
    contains_unsafe: bool,
    signature_verified: bool,
    required_caps: u64,
) -> Result<CellId, LoadError> {
    validate_cell_requirements(name, elf_data, allow_unsafe, contains_unsafe)?;

    crate::io::log::early_print("[LDBG] new\n");
    let loader = elf::ElfLoader::new(elf_data)?;
    crate::io::log::early_print("[LDBG] parse\n");
    let cell_info = loader.parse()?;
    crate::io::log::early_print("[LDBG] parsed\n");

    for import in &cell_info.imports {
        if with_registry(|r| r.resolve_symbol(*import)).is_none() {
            return Err(LoadError::UnresolvedDependency((*import).to_string()));
        }
    }

    crate::io::log::early_print("[LDBG] load\n");
    let loaded = loader.load(&cell_info)?;

    let resolver = |s: &str| with_registry(|r| r.resolve_symbol(s));
    crate::io::log::early_print("[LDBG] relocate\n");
    loader.relocate(&loaded, resolver)?;

    crate::io::log::early_print("[LDBG] register\n");
    let id = with_registry_mut(|r| {
        crate::io::log::early_print("[LDBG] register: alloc_id\n");
        let id = r.allocate_id();
        crate::io::log::early_print("[LDBG] register: exports collect begin\n");
        let exports = cell_info
            .exports
            .iter()
            .map(|(n, v)| (n.to_string(), loaded.base_address + *v as usize))
            .collect();
        crate::io::log::early_print("[LDBG] register: exports collect done\n");
        crate::io::log::early_print("[LDBG] register: imports collect begin\n");
        let imports = cell_info.imports.iter().map(|s| s.to_string()).collect();
        crate::io::log::early_print("[LDBG] register: imports collect done\n");
        crate::io::log::early_print("[LDBG] register: entry build begin\n");
        let entry = CellEntry {
            id,
            name: name.into(),
            state: CellState::Loaded,
            load_address: loaded.base_address,
            load_size: loaded.size,
            allocation_base: loaded.allocation_base,
            allocation_size: loaded.allocation_size,
            entry_point: loaded.entry_point,
            exports,
            imports,
            dependencies: Vec::new(),
            is_safe: !contains_unsafe,
            signature_verified,
            required_caps,
            registered_drivers: Vec::new(),
            pkey: loaded.pkey,
            stats: ModuleStats {
                memory_usage: loaded.size,
                segment_count: cell_info.segments.len(),
                symbol_count: cell_info.exports.len(),
                ..Default::default()
            },
        };
        crate::io::log::early_print("[LDBG] register: entry build done\n");
        crate::io::log::early_print("[LDBG] register: registry insert begin\n");
        r.register(entry);
        crate::io::log::early_print("[LDBG] register: registry insert done\n");
        id
    });

    Ok(id)
}

/// Load a driver artifact and register it as an ABI driver with the DriverRegistry.
///
/// This is an internal primitive; normal standalone driver-cell activation
/// should flow through `driver_domain::lifecycle`.
pub(crate) fn load_driver(
    name: &str,
    elf_data: &[u8],
    allow_unsafe: bool,
) -> Result<DriverHandle, LoadError> {
    load_driver_with_context(name, elf_data, allow_unsafe, AbiDriverContext::new())
}

/// Load a driver artifact and register it as an ABI driver with a pre-populated
/// driver context.
pub(crate) fn load_driver_with_context(
    name: &str,
    elf_data: &[u8],
    allow_unsafe: bool,
    ctx: AbiDriverContext,
) -> Result<DriverHandle, LoadError> {
    let cell_id = load_cell(name, elf_data, allow_unsafe)?;
    register_driver_from_cell_with_context(cell_id, ctx)
}

/// Load a driver pack (manifest + ELF + signature).
pub(crate) fn load_driver_pack(
    name: &str,
    pack_data: &[u8],
    allow_unsafe: bool,
) -> Result<DriverHandle, LoadError> {
    load_driver_pack_with_context(name, pack_data, allow_unsafe, AbiDriverContext::new())
}

/// Load a driver pack (manifest + ELF + signature) with a pre-populated driver
/// context.
pub(crate) fn load_driver_pack_with_context(
    name: &str,
    pack_data: &[u8],
    allow_unsafe: bool,
    ctx: AbiDriverContext,
) -> Result<DriverHandle, LoadError> {
    let cell_id = load_driver_pack_cell(name, pack_data, allow_unsafe)?;
    register_driver_from_cell_with_context(cell_id, ctx)
}

/// Load a driver artifact: raw ELF or driver pack.
pub(crate) fn load_driver_artifact(
    name: &str,
    data: &[u8],
    allow_unsafe: bool,
) -> Result<DriverHandle, LoadError> {
    load_driver_artifact_with_context(name, data, allow_unsafe, AbiDriverContext::new())
}

/// Load a driver artifact: raw ELF or driver pack, preserving the supplied
/// driver context for probe/start callbacks.
pub(crate) fn load_driver_artifact_with_context(
    name: &str,
    data: &[u8],
    allow_unsafe: bool,
    ctx: AbiDriverContext,
) -> Result<DriverHandle, LoadError> {
    if driver_pack::is_driver_pack(data) {
        load_driver_pack_with_context(name, data, allow_unsafe, ctx)
    } else {
        load_driver_with_context(name, data, allow_unsafe, ctx)
    }
}

/// Record a driver handle in the cell's registry entry.
fn record_driver_handle(cell_id: CellId, handle: DriverHandle) {
    with_registry_mut(|r| {
        if let Some(entry) = r.get_mut(cell_id) {
            entry.registered_drivers.push(handle);
            log::info!(
                "[Loader] Driver registered: {:?} for cell {:?}\n",
                handle,
                cell_id.as_u64()
            );
        }
    });
}

pub(crate) fn register_driver_from_cell(cell_id: CellId) -> Result<DriverHandle, LoadError> {
    register_driver_from_cell_with_context(cell_id, AbiDriverContext::new())
}

pub(crate) fn register_driver_from_cell_with_context(
    cell_id: CellId,
    ctx: AbiDriverContext,
) -> Result<DriverHandle, LoadError> {
    crate::io::log::early_print("[LDR] regdrv: begin\n");
    let exports_addr = with_registry(|r| {
        let cell = r.get(cell_id)?;
        cell.exports
            .iter()
            .find(|(n, _)| str_eq(n.as_str(), DRIVER_EXPORTS_SYMBOL))
            .map(|(_, addr)| *addr)
    });

    if let Some(addr) = exports_addr {
        crate::io::log::early_print("[LDR] regdrv: exports path\n");
        let exports_ptr = addr as *const DriverExportsV1;
        match register_exports_driver_with_context(exports_ptr, ctx) {
            Ok(handle) => {
                crate::io::log::early_print("[LDR] regdrv: exports registered\n");
                record_driver_handle(cell_id, handle);
                return Ok(handle);
            }
            Err(_) => {
                with_registry_mut(|r| {
                    r.unload(cell_id);
                });
                return Err(LoadError::InvalidFormat(
                    "Failed to register DriverExports driver".into(),
                ));
            }
        }
    }

    let entry_addr = with_registry(|r| {
        let cell = r.get(cell_id)?;
        cell.exports
            .iter()
            .find(|(n, _)| str_eq(n.as_str(), DRIVER_ENTRY_SYMBOL))
            .map(|(_, addr)| *addr)
    });

    let entry_addr = match entry_addr {
        Some(a) => a,
        None => {
            with_registry_mut(|r| {
                r.unload(cell_id);
            });
            return Err(LoadError::InvalidFormat(
                "Driver entry symbol not found".into(),
            ));
        }
    };
    crate::io::log::early_print("[LDR] regdrv: abi path\n");

    let entry_fn: kernel_api::abi::driver::DriverEntryFn =
        unsafe { core::mem::transmute(entry_addr) };

    match register_abi_driver_with_context(entry_fn, ctx) {
        Ok(handle) => {
            crate::io::log::early_print("[LDR] regdrv: abi registered\n");
            record_driver_handle(cell_id, handle);
            Ok(handle)
        }
        Err(_) => {
            with_registry_mut(|r| {
                r.unload(cell_id);
            });
            Err(LoadError::InvalidFormat(
                "Failed to register ABI driver".into(),
            ))
        }
    }
}

/// セルをアンロード
pub fn unload_cell(id: CellId) -> Result<(), LoadError> {
    let has_dependents = with_registry(|r| r.all_cells().any(|c| c.dependencies.contains(&id)));
    let has_drivers = with_registry(|r| {
        r.get(id)
            .map(|c| !c.registered_drivers.is_empty())
            .unwrap_or(false)
    });

    if has_dependents {
        return Err(LoadError::UnresolvedDependency(
            "Cell has active dependents".into(),
        ));
    }
    if has_drivers {
        return Err(LoadError::UnresolvedDependency(
            "Cell has registered drivers".into(),
        ));
    }

    let (load_address, load_size, allocation_base, allocation_size, pkey_opt) =
        with_registry(|r| {
            r.get(id)
                .map(|c| {
                    (
                        c.load_address,
                        c.load_size,
                        c.allocation_base,
                        c.allocation_size,
                        c.pkey,
                    )
                })
                .ok_or(LoadError::CellNotFound)
        })?;

    let old_epoch = live_update::current_epoch();
    log::info!(
        "[Loader] Unloading cell {:?}, waiting for epoch {} quiescence\n",
        id.as_u64(),
        old_epoch
    );

    live_update::enter_quiescent_state();
    live_update::wait_for_quiescent_state(old_epoch);

    with_registry_mut(|r| {
        r.unload(id);
    });

    if let Some(_pk) = pkey_opt {
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        crate::security::mpk::free_protection_key(_pk);
    }

    let dealloc_base = if allocation_base != 0 {
        allocation_base
    } else {
        load_address
    };
    let dealloc_size = if allocation_size != 0 {
        allocation_size
    } else {
        load_size
    };

    if dealloc_base != 0 && dealloc_size > 0 {
        unsafe {
            use alloc::alloc::{Layout, dealloc};
            let layout = Layout::from_size_align_unchecked(dealloc_size, 4096);
            dealloc(dealloc_base as *mut u8, layout);
            log::debug!(
                "[Loader] Deallocated {} bytes at {:#x} for cell {:?} (runtime base {:#x})",
                dealloc_size,
                dealloc_base,
                id.as_u64(),
                load_address
            );
        }
    }

    Ok(())
}

/// Unload a registered driver by handle.
pub(crate) fn unload_driver(handle: DriverHandle) -> Result<(), LoadError> {
    match crate::driver_registry::unregister_driver(handle) {
        Ok(()) => {}
        Err(_) => {
            return Err(LoadError::InvalidFormat(
                "Failed to unregister driver".into(),
            ));
        }
    }

    let mut found = false;
    with_registry_mut(|r| {
        for entry in r.cells.values_mut() {
            if let Some(pos) = entry.registered_drivers.iter().position(|h| *h == handle) {
                entry.registered_drivers.remove(pos);
                found = true;
                log::info!(
                    "[Loader] Removed driver handle {:?} from cell {}\n",
                    handle,
                    entry.id.as_u64()
                );
                break;
            }
        }
    });

    if !found {
        return Err(LoadError::InvalidFormat(
            "Driver handle not found in any cell".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ELF_BYTES: &[u8] = b"\x7fELFdriver-pack-test";

    fn registry_snapshot() -> (usize, usize) {
        with_registry(|r| (r.all_cells().count(), r.symbol_table.len()))
    }

    fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn align_up(value: usize, align: usize) -> usize {
        (value + (align - 1)) & !(align - 1)
    }

    fn build_test_elf(loop_proof_section: Option<(&str, &[u8])>) -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 64;
        const SECTION_HEADER_SIZE: usize = 64;

        let mut shstrtab = Vec::new();
        shstrtab.push(0);
        let shstrtab_name_offset = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab");
        shstrtab.push(0);

        let (section_name, payload) = loop_proof_section.unwrap_or((".dummy", b"dummy"));
        let section_name_offset = shstrtab.len() as u32;
        shstrtab.extend_from_slice(section_name.as_bytes());
        shstrtab.push(0);

        let mut cursor = ELF_HEADER_SIZE;
        let payload_offset = align_up(cursor, 8);
        cursor = payload_offset + payload.len();
        let shstrtab_offset = align_up(cursor, 8);
        cursor = shstrtab_offset + shstrtab.len();
        let section_table_offset = align_up(cursor, 8);

        let section_count = 3usize;
        let total_size = section_table_offset + section_count * SECTION_HEADER_SIZE;
        let mut elf = vec![0u8; total_size];

        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELF64
        elf[5] = 1; // little-endian
        elf[6] = 1; // version
        write_u16(&mut elf, 0x10, 1); // ET_REL
        write_u16(&mut elf, 0x12, 0x3E); // x86_64
        write_u32(&mut elf, 0x14, 1); // EV_CURRENT
        write_u16(&mut elf, 0x34, ELF_HEADER_SIZE as u16);
        write_u64(&mut elf, 0x28, section_table_offset as u64);
        write_u16(&mut elf, 0x3A, SECTION_HEADER_SIZE as u16);
        write_u16(&mut elf, 0x3C, section_count as u16);
        write_u16(&mut elf, 0x3E, 1); // shstrtab index

        elf[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
        elf[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(&shstrtab);

        // Section #1: .shstrtab
        let sh1 = section_table_offset + SECTION_HEADER_SIZE;
        write_u32(&mut elf, sh1, shstrtab_name_offset);
        write_u32(&mut elf, sh1 + 0x04, 3); // SHT_STRTAB
        write_u64(&mut elf, sh1 + 0x18, shstrtab_offset as u64);
        write_u64(&mut elf, sh1 + 0x20, shstrtab.len() as u64);

        // Section #2: payload section
        let sh2 = section_table_offset + 2 * SECTION_HEADER_SIZE;
        write_u32(&mut elf, sh2, section_name_offset);
        write_u32(&mut elf, sh2 + 0x04, 1); // SHT_PROGBITS
        write_u64(&mut elf, sh2 + 0x18, payload_offset as u64);
        write_u64(&mut elf, sh2 + 0x20, payload.len() as u64);

        elf
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn load_driver_pack_rejects_too_new_kernel_api_version() {
        let pack = driver_pack::build_unsigned_driver_pack(
            "test_driver",
            TEST_ELF_BYTES,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION + 1,
        );
        let before = registry_snapshot();

        match load_driver_pack("test_driver", &pack, true) {
            Err(LoadError::AbiIncompatible(message)) => {
                assert!(str_eq(message.as_str(), "Kernel API ABI version too old"));
            }
            other => panic!("expected Kernel API ABI version rejection, got {:?}", other),
        }

        assert_eq!(registry_snapshot(), before);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn artifact_path_rejects_too_new_kernel_api_version() {
        let pack = driver_pack::build_unsigned_driver_pack(
            "test_driver",
            TEST_ELF_BYTES,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION + 1,
        );
        let before = registry_snapshot();

        match load_driver_artifact("test_driver", &pack, true) {
            Err(LoadError::AbiIncompatible(message)) => {
                assert!(str_eq(message.as_str(), "Kernel API ABI version too old"));
            }
            other => panic!("expected Kernel API ABI version rejection, got {:?}", other),
        }

        assert_eq!(registry_snapshot(), before);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn artifact_cell_path_rejects_too_new_kernel_api_version() {
        let pack = driver_pack::build_unsigned_driver_pack(
            "test_driver",
            TEST_ELF_BYTES,
            kernel_api::abi::driver::KERNEL_API_ABI_VERSION + 1,
        );
        let before = registry_snapshot();

        match load_driver_artifact_cell("test_driver", &pack, true) {
            Err(LoadError::AbiIncompatible(message)) => {
                assert!(str_eq(message.as_str(), "Kernel API ABI version too old"));
            }
            other => panic!("expected Kernel API ABI version rejection, got {:?}", other),
        }

        assert_eq!(registry_snapshot(), before);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn validate_requirements_rejects_missing_loop_proof_section() {
        let elf = build_test_elf(None);
        let err = validate_cell_requirements("test-cell", &elf, true, false)
            .expect_err("missing loop proof must be rejected");
        assert!(matches!(err, LoadError::LoopProofMissing));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn validate_requirements_rejects_invalid_loop_proof_section() {
        let bad = [b'R', b'L', b'X', b'P', 1, 0, 0, 0, 0, 0, 0, 0];
        let elf = build_test_elf(Some((loop_proof::LOOP_PROOF_SECTION_NAME, &bad)));
        let err = validate_cell_requirements("test-cell", &elf, true, false)
            .expect_err("invalid loop proof must be rejected");
        assert!(matches!(err, LoadError::LoopProofInvalid(_)));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn validate_requirements_accepts_valid_loop_proof_section() {
        let good = [b'R', b'L', b'O', b'P', 1, 0, 0, 0, 0, 0, 0, 0];
        let elf = build_test_elf(Some((loop_proof::LOOP_PROOF_SECTION_NAME, &good)));
        validate_cell_requirements("test-cell", &elf, true, false)
            .expect("valid loop proof should pass");
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn load_cell_with_flags_rejects_missing_loop_proof_section() {
        let elf = build_test_elf(None);
        let before = registry_snapshot();
        let err = load_cell_with_flags("test-cell", &elf, true, false, false, 0)
            .expect_err("cell load path must reject missing loop proof");
        assert!(matches!(err, LoadError::LoopProofMissing));
        assert_eq!(registry_snapshot(), before);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn load_cell_rejects_missing_signature_without_mutating_registry() {
        let elf = build_test_elf(Some((".exorust_sig", b"bad-signature")));
        let before = registry_snapshot();
        let err = load_cell("unsigned-cell", &elf, true)
            .expect_err("malformed signature section must be rejected before registration");
        assert!(matches!(err, LoadError::InvalidSignature));
        assert_eq!(registry_snapshot(), before);
    }
}
