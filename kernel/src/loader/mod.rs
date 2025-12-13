// ============================================================================
// src/loader/mod.rs - Cell (Module) Loader
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 3.3: コンパイラ署名とロード時検証
// 設計書 3.4: ABIの安定性とType ID Check
// ============================================================================
#![allow(dead_code)]

pub mod ed25519;
pub mod elf;
pub mod live_update; // 新: ライブアップデート・Epoch-based Reclamation (設計書 3.5)
pub mod sha256;
pub mod signature;
pub mod type_id;

#[allow(unused_imports)]
pub use elf::{CellInfo, ElfLoader, LoadedCell};
#[allow(unused_imports)]
pub use live_update::{
    LiveUpdateError, LiveUpdateManager, LiveUpdateState, RequestTracker, current_epoch,
    enter_critical_section, enter_quiescent_state, leave_critical_section, live_update_manager,
    wait_for_quiescent_state,
};
#[allow(unused_imports)]
pub use signature::{CellSignature, SignatureVerifier, verify_cell};

use crate::driver_registry::{DriverHandle, register_abi_driver};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use kernel_api::driver_abi::DRIVER_ENTRY_SYMBOL;
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
    /// 登録されたドライバ（このセルに依存するドライバ）
    pub registered_drivers: Vec<DriverHandle>,
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
        // シンボルテーブルにエクスポートを追加
        for (symbol, addr) in &entry.exports {
            self.symbol_table.insert(symbol.clone(), *addr);
        }
        self.cells.insert(entry.id, entry);
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
            for (symbol, _) in &entry.exports {
                self.symbol_table.remove(symbol);
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

    // unsafeが許可されていない場合のチェック
    if !allow_unsafe && signature.contains_unsafe {
        return Err(LoadError::UnsafeNotAllowed);
    }

    // 2. 【設計書 3.4】Type ID Check - ABI互換性の検証
    if let Some(deps) = type_id::extract_type_ids(elf_data) {
        if let Err(e) = type_id::verify_cell_dependencies(&deps) {
            crate::log!(
                "[Loader] Type ID verification failed for '{}': {}\n",
                name,
                e
            );
            return Err(LoadError::AbiIncompatible(alloc::format!("{}", e)));
        }
        crate::log!(
            "[Loader] Type ID verified for '{}' ({})\n",
            name,
            deps.cell_version
        );
    }

    // 3. ELFをパース
    let loader = elf::ElfLoader::new(elf_data)?;
    let cell_info = loader.parse()?;

    // 4. 依存関係のチェック
    for import in &cell_info.imports {
        if with_registry(|r| r.resolve_symbol(import)).is_none() {
            return Err(LoadError::UnresolvedDependency(import.clone()));
        }
    }

    // 5. メモリ割り当てとロード
    let loaded = loader.load(&cell_info)?;

    // 6. リロケーション
    loader.relocate(&loaded, |sym| with_registry(|r| r.resolve_symbol(sym)))?;

    // 6. レジストリに登録
    let id = with_registry_mut(|r| {
        let id = r.allocate_id();
        let entry = CellEntry {
            id,
            name: name.into(),
            state: CellState::Loaded,
            load_address: loaded.base_address,
            load_size: loaded.size,
            entry_point: loaded.entry_point,
            exports: cell_info
                .exports
                .iter()
                .map(|(n, v)| (n.clone(), loaded.base_address + *v as usize))
                .collect(),
            imports: cell_info.imports,
            dependencies: Vec::new(),
            is_safe: !signature.contains_unsafe,
            signature_verified: true,
            registered_drivers: Vec::new(),
        };
        r.register(entry);
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

    // Cast address to function pointer
    let entry_fn: kernel_api::driver_abi::DriverEntryFn =
        unsafe { core::mem::transmute(entry_addr) };

    // Register with driver registry
    match register_abi_driver(entry_fn) {
        Ok(handle) => {
            // record driver handle in the cell entry so the cell cannot be unloaded
            with_registry_mut(|r| {
                if let Some(entry) = r.get_mut(cell_id) {
                    entry.registered_drivers.push(handle);
                    crate::log!(
                        "[Loader] Driver registered: {:?} for cell {:?}\n",
                        handle,
                        cell_id.as_u64()
                    );
                }
            });
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

    // Epoch-based Reclamation: グローバルエポックをインクリメント
    let old_epoch = live_update::current_epoch();
    crate::log!(
        "[Loader] Unloading cell {:?}, waiting for epoch {} quiescence\n",
        id.as_u64(),
        old_epoch
    );

    // 全コアがQuiescent Stateに到達するまで待機
    live_update::wait_for_quiescent_state(old_epoch);

    // レジストリから削除
    with_registry_mut(|r| {
        r.unload(id);
    });

    // メモリ解放
    // Note: セルのロードアドレスとサイズから解放
    // 実装: CellEntryにload_addressとload_sizeがあるので
    // crate::allocator::deallocate(load_address, load_size)

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
                crate::log!(
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

/// Find the CellId that owns the given driver handle
pub fn find_cell_by_driver(handle: DriverHandle) -> Option<CellId> {
    with_registry(|r| {
        for entry in r.cells.values() {
            if entry.registered_drivers.contains(&handle) {
                return Some(entry.id);
            }
        }
        None
    })
}

/// カーネルセルを初期化（起動時に呼ばれる）
pub fn init_kernel_cell() {
    with_registry_mut(|r| {
        let entry = CellEntry {
            id: CellId::KERNEL,
            name: "kernel".into(),
            state: CellState::Running,
            load_address: 0,
            load_size: 0,
            entry_point: None,
            exports: Vec::new(),
            imports: Vec::new(),
            dependencies: Vec::new(),
            is_safe: false, // カーネルはunsafeを含む
            signature_verified: true,
            registered_drivers: Vec::new(),
        };
        r.register(entry);
    });
}
