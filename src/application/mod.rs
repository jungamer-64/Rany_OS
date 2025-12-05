// ============================================================================
// src/application/mod.rs - Application Runtime & Domain Management
// ============================================================================
//!
//! # Application Runtime for ExoRust
//!
//! ## 設計思想
//!
//! ExoRustにおける「アプリケーション」は、従来のOSにおける「ユーザープロセス」とは
//! 根本的に異なります。
//!
//! ### 従来OS vs ExoRust
//!
//! ```text
//! 従来OS (Linux等):
//!   - User Process: Ring 3で実行、カーネルとは隔離
//!   - 安全性: ハードウェア（ページテーブル、特権レベル）で保証
//!   - システムコール経由でのみカーネル機能にアクセス
//!
//! ExoRust (SPL):
//!   - Application: Ring 0で実行、カーネルと同じアドレス空間
//!   - 安全性: Rustコンパイラ（型システム、所有権）で保証
//!   - KAPI経由で直接カーネル関数を呼び出し
//! ```
//!
//! ## アプリケーションの定義
//!
//! アプリケーションは「ドメイン内で実行される非同期タスクの集合体」です：
//! - 独立した`Domain`内で実行
//! - カーネルから付与された`DomainCapabilities`のみ使用可能
//! - `Application`トレイトを実装
//!
//! ## このモジュールの役割
//!
//! 1. **Application Trait**: アプリケーションのエントリポイント定義
//! 2. **AppContext**: 実行時コンテキスト（権限トークン保持）
//! 3. **DomainManager**: アプリケーションのライフサイクル管理
//! 4. **SDK Functions**: アプリケーション開発者向けユーティリティ

#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

// サブモジュール
pub mod system_monitor;
pub mod terminal;
pub mod editor;

// Re-exports
pub use system_monitor::{SystemMonitor, ProcessEntry};
pub use editor::{Editor, TextBuffer, Cursor, Selection, SyntaxHighlighter, SpecialKey};
pub use terminal::{
    Terminal, Cell, TerminalLine, TerminalBuffer, 
    AnsiParser, ParseAction, SpecialKey,
    CommandHistory, LineEditor, Selection,
    TabCompleter, Clipboard, TerminalApp, CLIPBOARD,
};

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use crate::kapi;
use crate::security::static_capability::{
    DmaCapability, DomainCapabilities, FsCapability, IoCapability, IpcCapability, MemoryCapability,
    NetCapability, TaskCapability,
};

// ============================================================================
// Application トレイト
// ============================================================================

/// ExoRustアプリケーションのエントリポイント
///
/// 全てのアプリケーションはこのトレイトを実装する必要があります。
///
/// # 例
///
/// ```rust
/// struct MyApp;
///
/// impl Application for MyApp {
///     async fn on_start(&mut self, ctx: AppContext) {
///         println!("Hello from MyApp!");
///         
///         // ネットワーク権限があれば使用
///         if let Some(net_cap) = ctx.net() {
///             // ネットワーク操作
///         }
///         
///         // 非同期処理
///         sleep(1000).await;
///     }
/// }
/// ```
pub trait Application: Send + Sync {
    /// アプリケーションのメインエントリポイント
    ///
    /// # 引数
    /// - `ctx`: 実行コンテキスト（権限トークン含む）
    fn on_start(&mut self, ctx: AppContext) -> impl Future<Output = ()> + Send;

    /// 終了時のクリーンアップ（オプション）
    ///
    /// アプリケーション終了時に呼び出されます。
    /// デフォルトでは何もしません。
    fn on_stop(&mut self) {
        // デフォルト: 何もしない
    }

    /// アプリケーション名
    fn name(&self) -> &str {
        "unnamed"
    }
}

// ============================================================================
// AppContext - 実行時コンテキスト
// ============================================================================

/// アプリケーション実行コンテキスト
///
/// このコンテキストは、アプリケーション起動時にカーネルから渡されます。
/// アプリケーションは、このコンテキスト経由でのみKAPIにアクセスできます。
///
/// ## 権限アクセス
///
/// 各権限は`Option`型で提供され、`None`の場合はその機能を使用できません。
/// これにより、**コンパイル時に権限の有無が検証**されます。
pub struct AppContext {
    /// アプリケーションID
    pub app_id: u64,
    /// アプリケーション名
    pub name: String,
    /// ドメインID
    pub domain_id: u64,
    /// 権限トークン束
    capabilities: DomainCapabilities,
}

impl AppContext {
    /// 新しいコンテキストを作成（カーネル内部用）
    pub(crate) fn new(
        app_id: u64,
        name: String,
        domain_id: u64,
        capabilities: DomainCapabilities,
    ) -> Self {
        Self {
            app_id,
            name,
            domain_id,
            capabilities,
        }
    }

    // --- 権限アクセサ ---

    /// ネットワーク権限を取得
    ///
    /// # 戻り値
    /// - `Some(&NetCapability)`: ネットワークアクセス許可
    /// - `None`: ネットワークアクセス不許可
    #[inline]
    pub fn net(&self) -> Option<&NetCapability> {
        self.capabilities.net.as_ref()
    }

    /// ファイルシステム権限を取得
    #[inline]
    pub fn fs(&self) -> Option<&FsCapability> {
        self.capabilities.fs.as_ref()
    }

    /// I/O権限を取得
    #[inline]
    pub fn io(&self) -> Option<&IoCapability> {
        self.capabilities.io.as_ref()
    }

    /// タスク生成権限を取得
    #[inline]
    pub fn task(&self) -> Option<&TaskCapability> {
        self.capabilities.task.as_ref()
    }

    /// IPC権限を取得
    #[inline]
    pub fn ipc(&self) -> Option<&IpcCapability> {
        self.capabilities.ipc.as_ref()
    }

    /// DMA権限を取得
    #[inline]
    pub fn dma(&self) -> Option<&DmaCapability> {
        self.capabilities.dma.as_ref()
    }

    /// メモリ権限を取得
    #[inline]
    pub fn memory(&self) -> Option<&MemoryCapability> {
        self.capabilities.memory.as_ref()
    }

    /// 全権限へのアクセス
    pub fn capabilities(&self) -> &DomainCapabilities {
        &self.capabilities
    }
}

// ============================================================================
// SDK ヘルパー関数
// ============================================================================

/// コンソール出力（フォーマット付き）
///
/// # 例
/// ```rust
/// print(format_args!("Value: {}", 42));
/// ```
pub fn print(args: core::fmt::Arguments) {
    let s = format!("{}", args);
    kapi::sys_api::debug_print(&s);
}

/// println! マクロの内部実装
#[macro_export]
macro_rules! app_println {
    () => ($crate::application::print(format_args!("\n")));
    ($($arg:tt)*) => ({
        $crate::application::print(format_args!("{}\n", format_args!($($arg)*)));
    })
}

/// 非同期スリープ
///
/// 指定ミリ秒間、現在のタスクを一時停止します。
/// 他のタスクは実行を継続します（非ブロッキング）。
///
/// # 例
/// ```rust
/// sleep(500).await;  // 500ms待機
/// ```
pub async fn sleep(ms: u64) {
    kapi::task_api::sleep_ms(ms).await;
}

/// CPU譲渡
///
/// 他の実行可能タスクに制御を移します。
pub async fn yield_now() {
    kapi::task_api::yield_now().await;
}

/// 現在時刻を取得（ミリ秒）
///
/// 起動からの経過時間をミリ秒単位で返します。
pub fn now() -> u64 {
    kapi::sys_api::uptime_ms()
}

/// 高精度時刻を取得（ナノ秒）
pub fn now_nanos() -> u64 {
    kapi::sys_api::uptime_nanos()
}

// ============================================================================
// DomainManager - ドメインライフサイクル管理
// ============================================================================

use spin::Mutex;

/// ドメイン状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// 作成済み、未開始
    Created,
    /// 初期化中
    Initializing,
    /// 実行中
    Running,
    /// 停止中
    Stopping,
    /// 停止完了
    Stopped,
    /// 異常終了
    Crashed,
}

/// ドメイン情報
pub struct DomainInfo {
    pub id: u64,
    pub name: String,
    pub state: DomainState,
    pub app_id: u64,
}

/// ドメインマネージャ
///
/// アプリケーション（ドメイン）のライフサイクルを管理します。
pub struct DomainManager {
    /// 登録済みドメイン
    domains: Vec<DomainInfo>,
    /// 次のドメインID
    next_domain_id: u64,
    /// 次のアプリID
    next_app_id: u64,
}

impl DomainManager {
    /// 新しいマネージャを作成
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            next_domain_id: 1,
            next_app_id: 1,
        }
    }

    /// アプリケーションをロードして起動
    ///
    /// # 引数
    /// - `app`: アプリケーションインスタンス
    /// - `name`: アプリケーション名
    /// - `caps`: 付与する権限
    ///
    /// # 動作
    /// 1. 新しいドメインを作成
    /// 2. 権限を設定
    /// 3. バックグラウンドタスクとして起動
    pub fn load_and_start<A>(&mut self, app: A, name: String, caps: DomainCapabilities)
    where
        A: Application + 'static,
    {
        let domain_id = self.next_domain_id;
        self.next_domain_id += 1;

        let app_id = self.next_app_id;
        self.next_app_id += 1;

        // ドメイン情報を登録
        self.domains.push(DomainInfo {
            id: domain_id,
            name: name.clone(),
            state: DomainState::Created,
            app_id,
        });

        // コンテキストを作成
        let ctx = AppContext::new(app_id, name.clone(), domain_id, caps);

        // バックグラウンドタスクとして起動
        // Note: 実際の実装ではExecutorに登録
        let domain_name = name.clone();

        crate::log!(
            "[Domain:{}] Loading application '{}'\n",
            domain_id,
            domain_name
        );

        // 将来的にはタスクスポーンで実行
        // let future = async move {
        //     app.on_start(ctx).await;
        //     app.on_stop();
        // };
        // crate::task::spawn(future);
    }

    /// ドメイン数を取得
    pub fn count(&self) -> usize {
        self.domains.len()
    }

    /// 全ドメイン情報をイテレート
    pub fn iter(&self) -> impl Iterator<Item = &DomainInfo> {
        self.domains.iter()
    }

    /// 特定ドメインの状態を更新
    pub fn set_state(&mut self, domain_id: u64, state: DomainState) {
        if let Some(domain) = self.domains.iter_mut().find(|d| d.id == domain_id) {
            domain.state = state;
        }
    }
}

impl Default for DomainManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// グローバルインスタンス
// ============================================================================

/// グローバルドメインマネージャ
static DOMAIN_MANAGER: Mutex<Option<DomainManager>> = Mutex::new(None);

/// ドメインマネージャを初期化
pub fn init() {
    *DOMAIN_MANAGER.lock() = Some(DomainManager::new());
    crate::log!("[Application] Runtime initialized (SPL Domain Model)\n");
}

/// ドメインマネージャにアクセス
pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut DomainManager) -> R,
{
    DOMAIN_MANAGER.lock().as_mut().map(f)
}

/// アプリケーションを起動
pub fn start_application<A>(app: A, name: &str, caps: DomainCapabilities)
where
    A: Application + 'static,
{
    with_manager(|mgr| {
        mgr.load_and_start(app, String::from(name), caps);
    });
}

/// 登録ドメイン数を取得
pub fn domain_count() -> usize {
    DOMAIN_MANAGER
        .lock()
        .as_ref()
        .map(|m| m.count())
        .unwrap_or(0)
}

// ============================================================================
// サンプルアプリケーション
// ============================================================================

/// サンプルアプリケーション
///
/// ExoRustアプリケーションの書き方のデモンストレーション。
pub struct ExampleApp {
    counter: u32,
}

impl ExampleApp {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}

impl Default for ExampleApp {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for ExampleApp {
    fn name(&self) -> &str {
        "ExampleApp"
    }

    async fn on_start(&mut self, ctx: AppContext) {
        crate::log!(
            "[{}] Starting (app_id: {}, domain_id: {})\n",
            self.name(),
            ctx.app_id,
            ctx.domain_id
        );

        // 権限チェックのデモ
        if let Some(_net_cap) = ctx.net() {
            crate::log!("[{}] Network access: GRANTED\n", self.name());
            // ネットワーク操作が可能
            // let endpoint = kapi::net_api::create_endpoint(net_cap)?;
        } else {
            crate::log!("[{}] Network access: DENIED\n", self.name());
        }

        if let Some(_fs_cap) = ctx.fs() {
            crate::log!("[{}] Filesystem access: GRANTED\n", self.name());
        } else {
            crate::log!("[{}] Filesystem access: DENIED\n", self.name());
        }

        // 非同期ループのデモ
        for i in 0..3 {
            self.counter += 1;
            crate::log!(
                "[{}] Working... iteration {} (counter: {})\n",
                self.name(),
                i,
                self.counter
            );
            sleep(100).await;
        }

        crate::log!("[{}] Completed successfully\n", self.name());
    }

    fn on_stop(&mut self) {
        crate::log!(
            "[{}] Cleanup complete (final counter: {})\n",
            self.name(),
            self.counter
        );
    }
}

// ============================================================================
// 後方互換性
// ============================================================================

/// 後方互換性: 旧AppCapabilities
#[deprecated(note = "Use DomainCapabilities from security::static_capability")]
pub type AppCapabilities = DomainCapabilities;

/// 後方互換性: 旧AppHandle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppHandle(pub u64);

impl AppHandle {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn id(&self) -> u64 {
        self.0
    }
}

/// 後方互換性: 旧AppState
#[deprecated(note = "Use DomainState")]
pub type AppState = DomainState;

/// 後方互換性: アプリ数取得
pub fn app_count() -> usize {
    domain_count()
}
