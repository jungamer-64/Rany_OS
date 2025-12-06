// ============================================================================
// src/loader/mod.rs - Cell (Module) Loader
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 3.3: コンパイラ署名とロード時検証
// ============================================================================
#![allow(dead_code)]

pub mod elf;
pub mod signature;
pub mod sha256;
pub mod ed25519;

#[allow(unused_imports)]
pub use elf::{CellInfo, ElfLoader, LoadedCell};
#[allow(unused_imports)]
pub use signature::{CellSignature, SignatureVerifier, verify_cell};

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
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
    pub exports: Vec<String>,
    /// インポートしているシンボル（依存関係）
    pub imports: Vec<String>,
    /// 依存するセル
    pub dependencies: Vec<CellId>,
    /// Safe Rustのみかどうか
    pub is_safe: bool,
    /// 署名が検証済みかどうか
    pub signature_verified: bool,
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
        for symbol in &entry.exports {
            self.symbol_table.insert(symbol.clone(), entry.load_address);
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
            for symbol in &entry.exports {
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

    // 2. ELFをパース
    let loader = elf::ElfLoader::new(elf_data)?;
    let cell_info = loader.parse()?;

    // 3. 依存関係のチェック
    for import in &cell_info.imports {
        if with_registry(|r| r.resolve_symbol(import)).is_none() {
            return Err(LoadError::UnresolvedDependency(import.clone()));
        }
    }

    // 4. メモリ割り当てとロード
    let loaded = loader.load(&cell_info)?;

    // 5. リロケーション
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
            exports: cell_info.exports,
            imports: cell_info.imports,
            dependencies: Vec::new(),
            is_safe: !signature.contains_unsafe,
            signature_verified: true,
        };
        r.register(entry);
        id
    });

    Ok(id)
}

/// セルをアンロード
pub fn unload_cell(id: CellId) -> Result<(), LoadError> {
    // 依存しているセルがないかチェック
    let has_dependents = with_registry(|r| r.all_cells().any(|c| c.dependencies.contains(&id)));

    if has_dependents {
        return Err(LoadError::UnresolvedDependency(
            "Cell has active dependents".into(),
        ));
    }

    // レジストリから削除
    with_registry_mut(|r| {
        r.unload(id);
    });

    // TODO: メモリを解放

    Ok(())
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
        };
        r.register(entry);
    });
}
