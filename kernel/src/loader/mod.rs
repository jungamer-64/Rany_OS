// ============================================================================
// src/loader/mod.rs - Cell (Module) Loader
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 3.3: コンパイラ署名とロード時検証
// 設計書 3.4: ABIの安定性とType ID Check
// ============================================================================
#![allow(dead_code)]

pub mod ed25519;
pub mod elf;
pub mod driver_pack;
pub mod live_update; // 新: ライブアップデート・Epoch-based Reclamation (設計書 3.5)
pub mod sha256;
pub mod sha384;
pub mod sha512;
pub mod signature;
pub mod type_id;

mod cell_lookup;
pub use cell_lookup::*;
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

use crate::driver_registry::{DriverHandle, register_abi_driver, register_exports_driver};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kernel_api::driver_abi::{DriverExportsV1, DRIVER_ENTRY_SYMBOL, DRIVER_EXPORTS_SYMBOL};
use spin::Mutex;

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
    pub symbol_table: BTreeMap<String, usize>,
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
            symbol_table: BTreeMap::new(),
            next_id: 1, // 0はカーネル用
        }
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
        // Live-update shadow loads can register a second cell with the same logical
        // name before the swap commit. During this staging phase we don't need to
        // mutate the global symbol table yet; touching it has been a hot crash point
        // in the driver_cell runtime path, while per-cell exports remain available
        // via `entry.exports`.
        let is_shadow_staging =
            entry.name.starts_with("update-")
                || self.cells.values().any(|cell| cell.name == entry.name);
        if is_shadow_staging {
            crate::io::log::early_print("[LDBG] registry.register: staging duplicate-name, skip symtab\n");
        }
        // シンボルテーブルにエクスポートを追加
        if !is_shadow_staging {
            for (_idx, (symbol, addr)) in entry.exports.iter().enumerate() {
                if (_idx & 0x3f) == 0 {
                    crate::io::log::early_print("[LDBG] registry.register: export idx=");
                    crate::io::log::early_print_hex(_idx as u64);
                    crate::io::log::early_print("\n");
                }
                if self.symbol_table.contains_key(symbol.as_str()) {
                    continue;
                }
                self.symbol_table.insert(symbol.clone(), *addr);
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
        self.symbol_table.get(name).copied()
    }

    /// セルをアンロード
    pub fn unload(&mut self, id: CellId) -> Option<CellEntry> {
        if let Some(entry) = self.cells.remove(&id) {
            // シンボルテーブルからエクスポートを削除
            let live_update_shadow_involved = entry.name.starts_with("update-")
                || self.cells.values().any(|cell| cell.name.starts_with("update-"));
            if live_update_shadow_involved {
                crate::io::log::early_print(
                    "[LDBG] registry.unload: live-update shadow involved, skip symtab remove\n",
                );
            } else {
                for (symbol, _) in &entry.exports {
                    self.symbol_table.remove(symbol);
                }
            }
            Some(entry)
        } else {
            None
        }
    }

    /// 名前でセルを検索
    pub fn find_by_name(&self, name: &str) -> Option<&CellEntry> {
        self.cells.values().find(|c| c.name == name)
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
static CELL_REGISTRY: Mutex<CellRegistry> = Mutex::new(CellRegistry::new());

/// セルレジストリにアクセス
pub fn with_registry<F, R>(f: F) -> R
where
    F: FnOnce(&CellRegistry) -> R,
{
    f(&CELL_REGISTRY.lock())
}

/// セルレジストリを変更
pub fn with_registry_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut CellRegistry) -> R,
{
    f(&mut CELL_REGISTRY.lock())
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
            LoadError::CellNotFound => write!(f, "Cell not found"),
            LoadError::RelocationFailed(msg) => write!(f, "Relocation failed: {}", msg),
            LoadError::InvalidPermissions(msg) => write!(f, "Invalid permissions: {}", msg),
        }
    }
}

/// セルをロード（メインAPI）
///
/// # 設計書 3.3: ロード時検証
/// 1. ELFフォーマットの検証
/// 2. 署名の検証
/// 3. 依存関係の解決
/// 4. メモリへの配置
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
        log::info!(
            "[Loader] Type ID verified for '{}' ({})\n",
            name,
            deps.cell_version
        );
    }
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

    // 3. ELFをパース
    crate::io::log::early_print("[LDBG] new\n");
    let loader = elf::ElfLoader::new(elf_data)?;
    crate::io::log::early_print("[LDBG] parse\n");
    let cell_info = loader.parse()?;
    crate::io::log::early_print("[LDBG] parsed\n");

    // 4. 依存関係のチェック
    for import in &cell_info.imports {
        if with_registry(|r| r.resolve_symbol(*import)).is_none() {
            return Err(LoadError::UnresolvedDependency((*import).to_string()));
        }
    }

    // 5. メモリ割り当てとロード
    crate::io::log::early_print("[LDBG] load\n");
    let loaded = loader.load(&cell_info)?;

    // 6. リロケーション
    let resolver = |s: &str| with_registry(|r| r.resolve_symbol(s));
    crate::io::log::early_print("[LDBG] relocate\n");
    loader.relocate(&loaded, resolver)?;

    // 6. レジストリに登録
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
pub fn load_driver(
    name: &str,
    elf_data: &[u8],
    allow_unsafe: bool,
) -> Result<DriverHandle, LoadError> {
    // Load the cell first
    let cell_id = load_cell(name, elf_data, allow_unsafe)?;

    register_driver_from_cell(cell_id)
}

/// Load a driver pack (manifest + ELF + signature).
pub fn load_driver_pack(
    name: &str,
    pack_data: &[u8],
    allow_unsafe: bool,
) -> Result<DriverHandle, LoadError> {
    let pack = driver_pack::parse_driver_pack(pack_data)?;
    let signature_verified = driver_pack::verify_driver_pack(&pack)?;

    let driver_abi = pack.manifest.driver_abi_version as u64;
    if driver_abi != kernel_api::driver_abi::DRIVER_ABI_VERSION {
        return Err(LoadError::AbiIncompatible(
            "Driver ABI version mismatch".into(),
        ));
    }

    if pack.manifest.kernel_api_min_version > kernel_api::driver_abi::KERNEL_API_ABI_VERSION {
        return Err(LoadError::AbiIncompatible(
            "Kernel API ABI version too old".into(),
        ));
    }

    let manifest_name = pack.manifest.name_str();
    let driver_name = if manifest_name.is_empty() {
        name
    } else {
        manifest_name
    };

    let cell_id = load_cell_with_flags(
        driver_name,
        pack.elf,
        allow_unsafe,
        pack.manifest.contains_unsafe(),
        signature_verified,
        pack.manifest.required_caps,
    )?;

    register_driver_from_cell(cell_id)
}

/// Load a driver artifact: raw ELF or driver pack.
pub fn load_driver_artifact(
    name: &str,
    data: &[u8],
    allow_unsafe: bool,
) -> Result<DriverHandle, LoadError> {
    if driver_pack::is_driver_pack(data) {
        load_driver_pack(name, data, allow_unsafe)
    } else {
        load_driver(name, data, allow_unsafe)
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
    crate::io::log::early_print("[LDR] regdrv: begin\n");
    // Prefer DRIVER_EXPORTS when available
    let exports_addr = with_registry(|r| {
        let cell = r.get(cell_id)?;
        cell.exports
            .iter()
            .find(|(n, _)| n == DRIVER_EXPORTS_SYMBOL)
            .map(|(_, addr)| *addr)
    });

    if let Some(addr) = exports_addr {
        crate::io::log::early_print("[LDR] regdrv: exports path\n");
        let exports_ptr = addr as *const DriverExportsV1;
        match register_exports_driver(exports_ptr) {
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

    // Resolve driver entry symbol address from the specific cell
    let entry_addr = with_registry(|r| {
        let cell = r.get(cell_id)?;
        cell.exports
            .iter()
            .find(|(n, _)| n == DRIVER_ENTRY_SYMBOL)
            .map(|(_, addr)| *addr)
    });

    let entry_addr = match entry_addr {
        Some(a) => a,
        None => {
            // Unload cell if entry not found
            with_registry_mut(|r| {
                r.unload(cell_id);
            });
            return Err(LoadError::InvalidFormat(
                "Driver entry symbol not found".into(),
            ));
        }
    };
    crate::io::log::early_print("[LDR] regdrv: abi path\n");

    // Cast address to function pointer
    let entry_fn: kernel_api::driver_abi::DriverEntryFn =
        unsafe { core::mem::transmute(entry_addr) };

    // Register with driver registry
    match register_abi_driver(entry_fn) {
        Ok(handle) => {
            crate::io::log::early_print("[LDR] regdrv: abi registered\n");
            record_driver_handle(cell_id, handle);
            Ok(handle)
        }
        Err(_) => {
            // registration failed - unload cell to clean up
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
///
/// 設計書 3.5.3: Epoch-based Reclamation
/// - アンロード前にグローバルエポックをインクリメント
/// - 全コアがQuiescent Stateに到達するまで待機
/// - その後にメモリを安全に解放
pub fn unload_cell(id: CellId) -> Result<(), LoadError> {
    // 依存しているセルがないかチェック
    let has_dependents = with_registry(|r| r.all_cells().any(|c| c.dependencies.contains(&id)));
    // Check if this cell has any registered drivers
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

    // セルのメモリ情報と PKEY を取得（unload前に必要）
    let (load_address, load_size, pkey_opt) = with_registry(|r| {
        r.get(id)
            .map(|c| (c.load_address, c.load_size, c.pkey))
            .ok_or(LoadError::CellNotFound)
    })?;

    // Epoch-based Reclamation: グローバルエポックをインクリメント
    let old_epoch = live_update::current_epoch();
    log::info!(
        "[Loader] Unloading cell {:?}, waiting for epoch {} quiescence\n",
        id.as_u64(),
        old_epoch
    );

    // Unload runs outside the code being reclaimed; mark the current core as
    // quiescent before waiting so we don't self-deadlock if the caller forgot
    // to exit a live-update critical section.
    live_update::enter_quiescent_state();

    // 全コアがQuiescent Stateに到達するまで待機
    live_update::wait_for_quiescent_state(old_epoch);

    // レジストリから削除
    with_registry_mut(|r| {
        r.unload(id);
    });

    // Protection Key を解放（存在する場合）
    if let Some(_pk) = pkey_opt {
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        crate::security::mpk::free_protection_key(_pk);
    }

    // メモリ解放
    if load_address != 0 && load_size > 0 {
        unsafe {
            use alloc::alloc::{Layout, dealloc};
            // ELFローダーは4096バイトアライメントでメモリを割り当てている
            let layout = Layout::from_size_align_unchecked(load_size, 4096);
            dealloc(load_address as *mut u8, layout);
            log::debug!(
                "[Loader] Deallocated {} bytes at {:#x} for cell {:?}",
                load_size,
                load_address,
                id.as_u64()
            );
        }
    }

    Ok(())
}

/// Unload a registered driver by handle, unregistering from the DriverRegistry
/// and removing it from the cell's registered_drivers. This ensures the cell
/// can be unloaded safely by freeing the driver reference.
pub fn unload_driver(handle: DriverHandle) -> Result<(), LoadError> {
    // Unregister from driver registry first
    match crate::driver_registry::unregister_driver(handle) {
        Ok(()) => {}
        Err(_) => {
            return Err(LoadError::InvalidFormat(
                "Failed to unregister driver".into(),
            ));
        }
    }

    // Remove handle from cell entries
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
