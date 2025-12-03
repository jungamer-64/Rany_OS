// ============================================================================
// src/kapi/mod.rs - Kernel API Interface (Pure SPL Architecture)
// ============================================================================
//!
//! # Kernel API (KAPI) - SPL直接関数呼び出しインターフェース
//!
//! ## 設計思想
//!
//! ExoRustはSPL（Single Privilege Level）アーキテクチャを採用しており、
//! **従来のシステムコールは完全に存在しません**。
//!
//! ### 従来OS vs ExoRust
//!
//! ```text
//! 従来OS (Linux等):
//!   User Process → INT 0x80/SYSCALL → Context Switch → Dispatcher → Handler
//!   コスト: 数百～数千サイクル
//!
//! ExoRust (SPL):
//!   Application → CALL instruction → Kernel Function (直接)
//!   コスト: 数サイクル
//! ```
//!
//! ## 特徴
//!
//! - **ゼロオーバーヘッド**: SYSCALL/INT命令なし、通常の関数呼び出し(CALL)のみ
//! - **型安全性**: 整数ID分岐ではなく、Rustの型システムでAPI境界を保証
//! - **所有権ベース**: バッファコピーなし、所有権移動(Move)でデータ転送
//! - **静的ケイパビリティ**: 権限チェックはコンパイル時に解決、ランタイムコスト0
//! - **非同期ファースト**: 全I/O APIは`async fn`、ブロッキングなし
//!
//! ## 使用方法
//!
//! ```rust
//! // アプリケーションコード
//! async fn my_app(ctx: &AppContext) {
//!     // ネットワーク権限があれば使用可能
//!     if let Some(net_cap) = ctx.net() {
//!         let packet = kapi::net_api::recv_packet(net_cap, &mut endpoint).await?;
//!         // パケットの所有権を取得（ゼロコピー）
//!     }
//!     
//!     // タスク管理（権限不要のユーティリティ）
//!     kapi::task_api::yield_now().await;
//! }
//! ```

#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

// 静的ケイパビリティシステム
use crate::security::static_capability::{
    DmaCapability, FsCapability, IoCapability, IpcCapability, MemoryCapability, NetCapability,
    TaskCapability,
};

// ============================================================================
// KAPI エラー型
// ============================================================================

/// KAPI結果型
pub type KapiResult<T> = Result<T, KapiError>;

/// KAPIエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KapiError {
    /// 権限不足（静的チェックをすり抜けた場合のフォールバック）
    PermissionDenied,
    /// リソース枯渇
    ResourceExhausted,
    /// 無効なハンドル
    InvalidHandle,
    /// タイムアウト
    Timeout,
    /// リソースが見つからない
    NotFound,
    /// 既に存在する
    AlreadyExists,
    /// I/Oエラー
    IoError,
    /// 接続エラー
    ConnectionError,
    /// 内部エラー
    Internal(i32),
}

impl core::fmt::Display for KapiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::ResourceExhausted => write!(f, "Resource exhausted"),
            Self::InvalidHandle => write!(f, "Invalid handle"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::NotFound => write!(f, "Resource not found"),
            Self::AlreadyExists => write!(f, "Resource already exists"),
            Self::IoError => write!(f, "I/O error"),
            Self::ConnectionError => write!(f, "Connection error"),
            Self::Internal(code) => write!(f, "Internal error: {}", code),
        }
    }
}

// ============================================================================
// タスク管理 API
// ============================================================================

/// タスク管理API
///
/// CPUスケジューリングとタスクライフサイクル管理。
/// 基本操作（yield、sleep）は権限不要、タスク生成には`TaskCapability`が必要。
pub mod task_api {
    use super::*;

    /// CPUを自発的に譲る
    ///
    /// 現在のタスクを一時停止し、他の実行可能タスクに制御を移す。
    /// 権限不要 - 任意のタスクが呼び出し可能。
    ///
    /// # パフォーマンス
    /// - コスト: ~10 cycles（コンテキストスイッチなし、Executor内でのキュー操作のみ）
    #[inline(always)]
    pub async fn yield_now() {
        // 非同期yieldポイント
        YieldFuture::new().await
    }

    /// 指定時間スリープ
    ///
    /// # 引数
    /// - `ms`: スリープ時間（ミリ秒）
    ///
    /// # パフォーマンス
    /// - 非ブロッキング: 他タスクは実行継続
    #[inline(always)]
    pub async fn sleep_ms(ms: u64) {
        SleepFuture::new(ms).await
    }

    /// 新しい非同期タスクをスポーン
    ///
    /// # 引数
    /// - `_cap`: タスク生成権限（コンパイル時検証）
    /// - `future`: 実行するFuture
    ///
    /// # 戻り値
    /// - `TaskHandle`: 生成されたタスクのハンドル
    pub fn spawn<F>(_cap: &TaskCapability, future: F) -> KapiResult<TaskHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // 権限チェックは型システムが実施済み（_capの存在が証明）
        // ランタイムオーバーヘッドなしでタスク生成
        static NEXT_TASK_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

        let id = NEXT_TASK_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        // 実際のExecutorへの登録（将来実装）
        // crate::task::executor::spawn(future);

        Ok(TaskHandle { id })
    }

    /// 現在のタスクIDを取得
    #[inline(always)]
    pub fn current_task_id() -> u64 {
        // TODO: 実際のタスクID取得
        0
    }

    /// タスクハンドル
    #[derive(Debug, Clone, Copy)]
    pub struct TaskHandle {
        id: u64,
    }

    impl TaskHandle {
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    // --- 内部Future実装 ---

    struct YieldFuture {
        yielded: bool,
    }

    impl YieldFuture {
        fn new() -> Self {
            Self { yielded: false }
        }
    }

    impl Future for YieldFuture {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    struct SleepFuture {
        target_tick: u64,
        started: bool,
    }

    impl SleepFuture {
        fn new(ms: u64) -> Self {
            Self {
                target_tick: ms, // 簡易実装
                started: false,
            }
        }
    }

    impl Future for SleepFuture {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if !self.started {
                self.started = true;
                let current = crate::task::timer::current_tick();
                self.target_tick = current + self.target_tick;
            }

            let current = crate::task::timer::current_tick();
            if current >= self.target_tick {
                Poll::Ready(())
            } else {
                // Wakerをタイマーキューに登録（将来実装）
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

// ============================================================================
// メモリ管理 API
// ============================================================================

/// メモリ管理API
///
/// SPL環境では標準の`alloc`クレートが使用可能だが、
/// DMAバッファなど特殊なメモリ領域には専用APIが必要。
pub mod mem_api {
    use super::*;

    /// DMAバッファ
    pub struct DmaBuffer {
        phys_addr: u64,
        virt_addr: *mut u8,
        size: usize,
    }

    impl DmaBuffer {
        /// 物理アドレスを取得
        pub fn physical_address(&self) -> u64 {
            self.phys_addr
        }

        /// 仮想アドレスを取得
        pub fn as_ptr(&self) -> *mut u8 {
            self.virt_addr
        }

        /// サイズを取得
        pub fn size(&self) -> usize {
            self.size
        }

        /// スライスとしてアクセス
        pub fn as_slice(&self) -> &[u8] {
            unsafe { core::slice::from_raw_parts(self.virt_addr, self.size) }
        }

        /// 可変スライスとしてアクセス
        pub fn as_slice_mut(&mut self) -> &mut [u8] {
            unsafe { core::slice::from_raw_parts_mut(self.virt_addr, self.size) }
        }
    }

    /// DMAバッファを割り当て
    ///
    /// # 引数
    /// - `_cap`: DMA権限（コンパイル時検証）
    /// - `size`: 割り当てサイズ（バイト）
    ///
    /// # 戻り値
    /// 連続物理メモリを持つDMAバッファ
    pub fn alloc_dma(_cap: &DmaCapability, size: usize) -> KapiResult<DmaBuffer> {
        // 権限チェック済み（_capの存在が証明）
        // 実際のDMA割り当て（将来実装）

        // ダミー実装
        Ok(DmaBuffer {
            phys_addr: 0x1000_0000,
            virt_addr: core::ptr::null_mut(),
            size,
        })
    }

    /// I/Oポートからの読み取り
    #[inline(always)]
    pub fn port_read_u8(_cap: &IoCapability, port: u16) -> u8 {
        unsafe {
            let value: u8;
            core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
            value
        }
    }

    /// I/Oポートへの書き込み
    #[inline(always)]
    pub fn port_write_u8(_cap: &IoCapability, port: u16, value: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
        }
    }
}

// ============================================================================
// ネットワーク API (ゼロコピー)
// ============================================================================

/// ネットワークAPI
///
/// **ゼロコピー設計**: パケットデータはコピーされず、所有権が移動する。
///
/// ## 従来のソケットAPIとの違い
///
/// ```text
/// POSIX (コピーベース):
///   recv(fd, buf, len) → カーネルバッファからユーザーバッファへコピー
///
/// KAPI (所有権ベース):
///   recv_packet(cap, endpoint) → パケットの所有権を取得（コピーなし）
/// ```
pub mod net_api {
    use super::*;

    /// ネットワークパケット（所有権付き）
    ///
    /// パケットデータへの排他的アクセス権を表す。
    /// Drop時に自動的にmempoolに返却される。
    pub struct Packet {
        data: Vec<u8>,
        /// パケット受信元情報
        pub src_port: u16,
        pub dst_port: u16,
    }

    impl Packet {
        /// パケットデータを取得
        pub fn data(&self) -> &[u8] {
            &self.data
        }

        /// パケットデータを可変取得
        pub fn data_mut(&mut self) -> &mut Vec<u8> {
            &mut self.data
        }

        /// パケットサイズ
        pub fn len(&self) -> usize {
            self.data.len()
        }

        /// 空かどうか
        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        /// 新しいパケットを作成
        pub fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                src_port: 0,
                dst_port: 0,
            }
        }
    }

    /// TCPエンドポイント
    pub struct TcpEndpoint {
        id: u64,
        connected: bool,
    }

    impl TcpEndpoint {
        /// 新しいエンドポイントを作成
        pub fn new(id: u64) -> Self {
            Self {
                id,
                connected: false,
            }
        }

        /// 接続状態を取得
        pub fn is_connected(&self) -> bool {
            self.connected
        }
    }

    /// パケットを受信（所有権を取得）
    ///
    /// # 引数
    /// - `_cap`: ネットワーク権限
    /// - `endpoint`: 受信元エンドポイント
    ///
    /// # 戻り値
    /// 受信したパケットの所有権（ゼロコピー）
    pub async fn recv_packet(
        _cap: &NetCapability,
        endpoint: &mut TcpEndpoint,
    ) -> KapiResult<Packet> {
        // 権限チェック済み
        // 実際のネットワーク受信（将来実装）

        // 非同期待機をシミュレート
        task_api::yield_now().await;

        // ダミーパケット
        Ok(Packet::new(Vec::new()))
    }

    /// パケットを送信（所有権を放棄）
    ///
    /// # 引数
    /// - `_cap`: ネットワーク権限
    /// - `endpoint`: 送信先エンドポイント
    /// - `packet`: 送信するパケット（所有権移動）
    ///
    /// # 注意
    /// 送信後、`packet`は使用不可（所有権が移動）
    pub async fn send_packet(
        _cap: &NetCapability,
        endpoint: &mut TcpEndpoint,
        packet: Packet,
    ) -> KapiResult<()> {
        // パケットの所有権を受け取り、送信後に自動drop
        // ゼロコピー: データはmempoolに直接返却

        task_api::yield_now().await;

        // packetはここでdrop（mempoolに返却）
        drop(packet);
        Ok(())
    }

    /// TCPエンドポイントを作成
    pub fn create_endpoint(_cap: &NetCapability) -> KapiResult<TcpEndpoint> {
        static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

        let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(TcpEndpoint::new(id))
    }
}

// ============================================================================
// ファイルシステム API
// ============================================================================

/// ファイルシステムAPI
///
/// ## 設計哲学
///
/// ExoRustでは、fs_abstractionレイヤーはオプションです。
/// 高速パス（NVMeポーリング等）では直接デバイスアクセスを使用します。
pub mod fs_api {
    use super::*;

    /// ファイルオープンモード
    #[derive(Debug, Clone, Copy)]
    pub enum OpenMode {
        Read,
        Write,
        ReadWrite,
        Append,
        Create,
    }

    /// ファイルハンドル
    pub struct FileHandle {
        id: u64,
        mode: OpenMode,
    }

    impl FileHandle {
        /// ファイルから読み込み（所有権ベース）
        ///
        /// 従来: `read(fd, buf, len)` → bufにコピー
        /// KAPI: `read(len)` → データの所有権を返す
        pub async fn read_owned(&mut self, len: usize) -> KapiResult<Vec<u8>> {
            // 実際のファイル読み込み（将来実装）
            task_api::yield_now().await;
            Ok(Vec::with_capacity(len))
        }

        /// ファイルに書き込み
        pub async fn write(&mut self, data: &[u8]) -> KapiResult<usize> {
            task_api::yield_now().await;
            Ok(data.len())
        }
    }

    /// ファイルを開く
    ///
    /// # 引数
    /// - `_cap`: ファイルシステム権限
    /// - `path`: ファイルパス
    /// - `mode`: オープンモード
    pub async fn open(_cap: &FsCapability, path: &str, mode: OpenMode) -> KapiResult<FileHandle> {
        // 権限チェック済み
        static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

        let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        task_api::yield_now().await;

        Ok(FileHandle { id, mode })
    }
}

// ============================================================================
// システム情報 API
// ============================================================================

/// システム情報API
///
/// 権限不要の読み取り専用システム情報。
pub mod sys_api {
    use super::*;

    /// 起動からの経過時間（ナノ秒）
    #[inline(always)]
    pub fn uptime_nanos() -> u64 {
        let ticks = crate::task::timer::current_tick();
        ticks * 1_000_000 // 1ms = 1_000_000 ns
    }

    /// 起動からの経過時間（ミリ秒）
    #[inline(always)]
    pub fn uptime_ms() -> u64 {
        crate::task::timer::current_tick()
    }

    /// デバッグ出力
    ///
    /// 開発時のログ出力。本番環境では無効化推奨。
    pub fn debug_print(msg: &str) {
        crate::log!("{}", msg);
    }

    /// システム情報
    #[derive(Debug, Clone)]
    pub struct SystemInfo {
        pub total_memory: u64,
        pub free_memory: u64,
        pub uptime_ms: u64,
        pub cpu_count: u32,
    }

    /// システム情報を取得
    pub fn get_system_info() -> SystemInfo {
        SystemInfo {
            total_memory: 128 * 1024 * 1024, // 128MB（仮）
            free_memory: 64 * 1024 * 1024,   // 64MB（仮）
            uptime_ms: uptime_ms(),
            cpu_count: 1,
        }
    }
}

// ============================================================================
// IPC API
// ============================================================================

/// プロセス間通信API
///
/// ドメイン間の型安全な通信チャネル。
pub mod ipc_api {
    use super::*;

    /// IPCチャネルハンドル
    pub struct ChannelHandle {
        id: u64,
    }

    /// チャネルを作成
    pub fn create_channel(_cap: &IpcCapability) -> KapiResult<(ChannelHandle, ChannelHandle)> {
        static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

        let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        Ok((ChannelHandle { id }, ChannelHandle { id }))
    }
}

// ============================================================================
// 初期化
// ============================================================================

/// KAPIサブシステムを初期化
pub fn init() {
    crate::log!("[KAPI] Kernel API initialized (Pure SPL - No syscall dispatch)\n");
    crate::log!("[KAPI] API model: Direct function calls with static capabilities\n");
}

// ============================================================================
// 後方互換性（移行期間用）
// ============================================================================

/// 後方互換性: 旧SyscallErrorとの対応
#[deprecated(note = "Use KapiError instead")]
pub type SyscallError = KapiError;

/// 後方互換性: 旧SyscallResultとの対応
#[deprecated(note = "Use KapiResult instead")]
pub type SyscallResult<T> = KapiResult<T>;
