//! シグナル処理 (Signal Handling)
//!
//! ExoRust用のシグナルシステム実装
//! POSIX互換性は排除し、Rustらしいエラーハンドリングと統合

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

/// シグナル番号 (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Signal(u32);

impl Signal {
    // 基本シグナル
    pub const SIGKILL: Self = Self(9); // 強制終了
    pub const SIGTERM: Self = Self(15); // 終了要求
    pub const SIGSTOP: Self = Self(19); // 停止
    pub const SIGCONT: Self = Self(18); // 再開

    // 例外シグナル
    pub const SIGSEGV: Self = Self(11); // セグメンテーション違反
    pub const SIGBUS: Self = Self(7); // バスエラー
    pub const SIGILL: Self = Self(4); // 不正命令
    pub const SIGFPE: Self = Self(8); // 浮動小数点例外

    // I/Oシグナル
    pub const SIGIO: Self = Self(29); // I/O可能
    pub const SIGPIPE: Self = Self(13); // パイプ破損
    pub const SIGURG: Self = Self(23); // 緊急データ

    // タイマーシグナル
    pub const SIGALRM: Self = Self(14); // アラーム
    pub const SIGVTALRM: Self = Self(26); // 仮想タイマー
    pub const SIGPROF: Self = Self(27); // プロファイリング

    // ユーザー定義シグナル
    pub const SIGUSR1: Self = Self(10); // ユーザー定義1
    pub const SIGUSR2: Self = Self(12); // ユーザー定義2

    // 子プロセス
    pub const SIGCHLD: Self = Self(17); // 子プロセス状態変化

    // ExoRust固有シグナル
    pub const SIGWAKE: Self = Self(64); // ウェイクアップ
    pub const SIGDOMAIN: Self = Self(65); // ドメインイベント
    pub const SIGIPC: Self = Self(66); // IPC通知

    /// カスタムシグナルの最小番号
    pub const SIGRTMIN: Self = Self(32);
    /// カスタムシグナルの最大番号
    pub const SIGRTMAX: Self = Self(63);

    pub const fn new(num: u32) -> Self {
        Self(num)
    }

    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// リアルタイムシグナルかどうか
    pub fn is_realtime(&self) -> bool {
        self.0 >= Self::SIGRTMIN.0 && self.0 <= Self::SIGRTMAX.0
    }

    /// キャッチ不可能なシグナルかどうか
    pub fn is_uncatchable(&self) -> bool {
        *self == Self::SIGKILL || *self == Self::SIGSTOP
    }
}

/// シグナルアクション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// デフォルトアクション
    Default,
    /// 無視
    Ignore,
    /// ハンドラで処理
    Handle,
    /// 停止
    Stop,
    /// 終了
    Terminate,
    /// コアダンプ付き終了
    CoreDump,
    /// 再開
    Continue,
}

impl SignalAction {
    /// シグナルのデフォルトアクションを取得
    pub fn default_for(signal: Signal) -> Self {
        match signal {
            Signal::SIGKILL | Signal::SIGTERM => Self::Terminate,
            Signal::SIGSEGV | Signal::SIGBUS | Signal::SIGILL | Signal::SIGFPE => Self::CoreDump,
            Signal::SIGSTOP => Self::Stop,
            Signal::SIGCONT => Self::Continue,
            Signal::SIGCHLD | Signal::SIGURG => Self::Ignore,
            _ => Self::Terminate,
        }
    }
}

/// シグナル情報
#[derive(Debug, Clone)]
pub struct SignalInfo {
    /// シグナル番号
    pub signal: Signal,
    /// 送信元タスクID
    pub sender_pid: Option<u64>,
    /// 追加データ
    pub data: SignalData,
    /// タイムスタンプ
    pub timestamp: u64,
}

/// シグナルデータ
#[derive(Debug, Clone)]
pub enum SignalData {
    /// データなし
    None,
    /// 整数値
    Int(i64),
    /// ポインタ (アドレス)
    Ptr(usize),
    /// 子プロセス情報
    Child { pid: u64, status: i32 },
    /// エラー情報
    Error { errno: i32, addr: usize },
    /// カスタムデータ
    Custom(u64),
}

/// シグナルハンドラ
pub type SignalHandler = fn(SignalInfo);

/// シグナルマスク
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalMask {
    bits: u64,
}

impl SignalMask {
    pub const EMPTY: Self = Self { bits: 0 };
    pub const ALL: Self = Self { bits: !0 };

    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// シグナルを追加
    pub fn add(&mut self, signal: Signal) {
        if signal.as_u32() < 64 {
            self.bits |= 1 << signal.as_u32();
        }
    }

    /// シグナルを削除
    pub fn remove(&mut self, signal: Signal) {
        if signal.as_u32() < 64 {
            self.bits &= !(1 << signal.as_u32());
        }
    }

    /// シグナルが含まれているか
    pub fn contains(&self, signal: Signal) -> bool {
        if signal.as_u32() < 64 {
            (self.bits & (1 << signal.as_u32())) != 0
        } else {
            false
        }
    }

    /// マスクを結合
    pub fn union(&self, other: &Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// マスクの差分
    pub fn difference(&self, other: &Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }
}

/// シグナル設定
#[derive(Debug, Clone)]
pub struct SignalConfig {
    /// アクション
    pub action: SignalAction,
    /// ハンドラ (Handle時のみ有効)
    pub handler: Option<SignalHandler>,
    /// フラグ
    pub flags: SignalFlags,
    /// マスク (ハンドラ実行中にブロックするシグナル)
    pub mask: SignalMask,
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            action: SignalAction::Default,
            handler: None,
            flags: SignalFlags::default(),
            mask: SignalMask::EMPTY,
        }
    }
}

/// シグナルフラグ
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalFlags {
    /// シグナルを受信したらハンドラをリセット
    pub reset_on_handle: bool,
    /// 再スタート可能なシステムコール
    pub restart: bool,
    /// キュー可能
    pub queued: bool,
    /// 情報付き (SignalInfo)
    pub siginfo: bool,
}

/// シグナルキュー
pub struct SignalQueue {
    /// ペンディング中のシグナル
    pending: spin::Mutex<Vec<SignalInfo>>,
    /// ペンディングビットマップ (高速チェック用)
    pending_mask: AtomicU64,
    /// 最大キューサイズ
    max_size: usize,
}

impl SignalQueue {
    pub const DEFAULT_MAX_SIZE: usize = 128;

    pub const fn new() -> Self {
        Self {
            pending: spin::Mutex::new(Vec::new()),
            pending_mask: AtomicU64::new(0),
            max_size: Self::DEFAULT_MAX_SIZE,
        }
    }

    /// シグナルをキューに追加
    pub fn enqueue(&self, info: SignalInfo) -> Result<(), SignalError> {
        let mut pending = self.pending.lock();

        if pending.len() >= self.max_size {
            return Err(SignalError::QueueFull);
        }

        // ペンディングマスクを更新
        if info.signal.as_u32() < 64 {
            self.pending_mask
                .fetch_or(1 << info.signal.as_u32(), Ordering::Release);
        }

        pending.push(info);
        Ok(())
    }

    /// シグナルをデキュー (マスク外の最初のシグナル)
    pub fn dequeue(&self, mask: &SignalMask) -> Option<SignalInfo> {
        let mut pending = self.pending.lock();

        // マスクされていないシグナルを探す
        let idx = pending
            .iter()
            .position(|info| !mask.contains(info.signal))?;
        let info = pending.remove(idx);

        // 同じシグナルがまだあるかチェック
        let has_same = pending.iter().any(|i| i.signal == info.signal);
        if !has_same && info.signal.as_u32() < 64 {
            self.pending_mask
                .fetch_and(!(1 << info.signal.as_u32()), Ordering::Release);
        }

        Some(info)
    }

    /// 特定のシグナルがペンディング中か
    pub fn is_pending(&self, signal: Signal) -> bool {
        if signal.as_u32() < 64 {
            (self.pending_mask.load(Ordering::Acquire) & (1 << signal.as_u32())) != 0
        } else {
            let pending = self.pending.lock();
            pending.iter().any(|info| info.signal == signal)
        }
    }

    /// ペンディング中のシグナルがあるか
    pub fn has_pending(&self) -> bool {
        self.pending_mask.load(Ordering::Acquire) != 0
    }

    /// ペンディング中のシグナルマスクを取得
    pub fn pending_mask(&self) -> SignalMask {
        SignalMask {
            bits: self.pending_mask.load(Ordering::Acquire),
        }
    }

    /// キューをクリア
    pub fn clear(&self) {
        let mut pending = self.pending.lock();
        pending.clear();
        self.pending_mask.store(0, Ordering::Release);
    }
}

/// シグナルエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    /// 無効なシグナル番号
    InvalidSignal,
    /// キャッチ不可能なシグナル
    Uncatchable,
    /// キューがフル
    QueueFull,
    /// タスクが存在しない
    NoSuchTask,
    /// 権限エラー
    PermissionDenied,
    /// 割り込まれた
    Interrupted,
}

/// シグナルコンテキスト (タスクごとの状態)
pub struct SignalContext {
    /// シグナル設定
    configs: spin::RwLock<BTreeMap<Signal, SignalConfig>>,
    /// シグナルキュー
    queue: SignalQueue,
    /// ブロックマスク
    blocked: spin::Mutex<SignalMask>,
    /// 待機中のWaker
    wakers: spin::Mutex<Vec<Waker>>,
    /// 統計
    received_count: AtomicU64,
    handled_count: AtomicU64,
}

impl SignalContext {
    pub const fn new() -> Self {
        Self {
            configs: spin::RwLock::new(BTreeMap::new()),
            queue: SignalQueue::new(),
            blocked: spin::Mutex::new(SignalMask::EMPTY),
            wakers: spin::Mutex::new(Vec::new()),
            received_count: AtomicU64::new(0),
            handled_count: AtomicU64::new(0),
        }
    }

    /// シグナルアクションを設定
    pub fn set_action(
        &self,
        signal: Signal,
        action: SignalAction,
        handler: Option<SignalHandler>,
    ) -> Result<(), SignalError> {
        if signal.is_uncatchable() && action != SignalAction::Default {
            return Err(SignalError::Uncatchable);
        }

        let mut configs = self.configs.write();
        configs.insert(
            signal,
            SignalConfig {
                action,
                handler,
                flags: SignalFlags::default(),
                mask: SignalMask::EMPTY,
            },
        );

        Ok(())
    }

    /// シグナルアクションを取得
    pub fn get_action(&self, signal: Signal) -> SignalAction {
        let configs = self.configs.read();
        configs
            .get(&signal)
            .map(|c| c.action)
            .unwrap_or(SignalAction::default_for(signal))
    }

    /// シグナルを送信
    pub fn send(&self, info: SignalInfo) -> Result<(), SignalError> {
        self.received_count.fetch_add(1, Ordering::Relaxed);

        // キューに追加
        self.queue.enqueue(info)?;

        // 待機中のタスクを起床
        let mut wakers = self.wakers.lock();
        for waker in wakers.drain(..) {
            waker.wake();
        }

        Ok(())
    }

    /// シグナルを処理
    pub fn process(&self) -> Option<ProcessedSignal> {
        let blocked = self.blocked.lock();
        let info = self.queue.dequeue(&blocked)?;

        let configs = self.configs.read();
        let config = configs.get(&info.signal);

        let action = config
            .map(|c| c.action)
            .unwrap_or(SignalAction::default_for(info.signal));

        let handler = config.and_then(|c| c.handler);

        self.handled_count.fetch_add(1, Ordering::Relaxed);

        Some(ProcessedSignal {
            info,
            action,
            handler,
        })
    }

    /// ブロックマスクを設定
    pub fn set_blocked(&self, mask: SignalMask) {
        let mut blocked = self.blocked.lock();
        *blocked = mask;
    }

    /// ブロックマスクを取得
    pub fn get_blocked(&self) -> SignalMask {
        *self.blocked.lock()
    }

    /// シグナルをブロック
    pub fn block(&self, signal: Signal) {
        let mut blocked = self.blocked.lock();
        blocked.add(signal);
    }

    /// シグナルをアンブロック
    pub fn unblock(&self, signal: Signal) {
        let mut blocked = self.blocked.lock();
        blocked.remove(signal);
    }

    /// ペンディング中のシグナルがあるか
    pub fn has_pending(&self) -> bool {
        self.queue.has_pending()
    }

    /// 非同期シグナル待機
    pub fn wait(&self) -> SignalFuture<'_> {
        SignalFuture { ctx: self }
    }

    /// 統計
    pub fn stats(&self) -> (u64, u64) {
        (
            self.received_count.load(Ordering::Relaxed),
            self.handled_count.load(Ordering::Relaxed),
        )
    }
}

/// 処理済みシグナル
pub struct ProcessedSignal {
    pub info: SignalInfo,
    pub action: SignalAction,
    pub handler: Option<SignalHandler>,
}

/// シグナル待機Future
pub struct SignalFuture<'a> {
    ctx: &'a SignalContext,
}

impl<'a> Future for SignalFuture<'a> {
    type Output = SignalInfo;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let blocked = self.ctx.blocked.lock();

        if let Some(info) = self.ctx.queue.dequeue(&blocked) {
            Poll::Ready(info)
        } else {
            // Wakerを登録
            // will_wake() で既存のWakerと比較し、同じなら clone() を回避
            let mut wakers = self.ctx.wakers.lock();
            let new_waker = cx.waker();
            if !wakers.iter().any(|w| w.will_wake(new_waker)) {
                wakers.push(new_waker.clone());
            }
            Poll::Pending
        }
    }
}

/// タスクID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct TaskId(u64);

impl TaskId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// シグナルマネージャー
pub struct SignalManager {
    /// タスクごとのシグナルコンテキスト
    contexts: spin::RwLock<BTreeMap<TaskId, Arc<SignalContext>>>,
    /// 統計
    total_sent: AtomicU64,
}

impl SignalManager {
    pub const fn new() -> Self {
        Self {
            contexts: spin::RwLock::new(BTreeMap::new()),
            total_sent: AtomicU64::new(0),
        }
    }

    /// タスクのコンテキストを登録
    pub fn register(&self, task_id: TaskId) -> Arc<SignalContext> {
        let ctx = Arc::new(SignalContext::new());
        let mut contexts = self.contexts.write();
        contexts.insert(task_id, ctx.clone());
        ctx
    }

    /// タスクのコンテキストを解除
    pub fn unregister(&self, task_id: TaskId) {
        let mut contexts = self.contexts.write();
        contexts.remove(&task_id);
    }

    /// コンテキストを取得
    pub fn get(&self, task_id: TaskId) -> Option<Arc<SignalContext>> {
        let contexts = self.contexts.read();
        contexts.get(&task_id).cloned()
    }

    /// シグナルを送信
    pub fn send(&self, target: TaskId, signal: Signal) -> Result<(), SignalError> {
        self.send_with_data(target, signal, SignalData::None)
    }

    /// データ付きシグナルを送信
    pub fn send_with_data(
        &self,
        target: TaskId,
        signal: Signal,
        data: SignalData,
    ) -> Result<(), SignalError> {
        let contexts = self.contexts.read();
        let ctx = contexts.get(&target).ok_or(SignalError::NoSuchTask)?;

        let info = SignalInfo {
            signal,
            sender_pid: None, // TODO: 送信元PID
            data,
            timestamp: 0, // TODO: タイムスタンプ
        };

        ctx.send(info)?;
        self.total_sent.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// 全タスクにシグナルを送信
    pub fn broadcast(&self, signal: Signal) -> usize {
        let contexts = self.contexts.read();
        let mut count = 0;

        for (_, ctx) in contexts.iter() {
            let info = SignalInfo {
                signal,
                sender_pid: None,
                data: SignalData::None,
                timestamp: 0,
            };

            if ctx.send(info).is_ok() {
                count += 1;
            }
        }

        self.total_sent.fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    /// 統計
    pub fn total_sent(&self) -> u64 {
        self.total_sent.load(Ordering::Relaxed)
    }
}

/// グローバルシグナルマネージャー
static SIGNAL_MANAGER: SignalManager = SignalManager::new();

/// シグナルマネージャーを取得
pub fn signal_manager() -> &'static SignalManager {
    &SIGNAL_MANAGER
}

// --- 便利関数 ---

/// シグナルを送信 (kill() 相当)
pub fn kill(target: TaskId, signal: Signal) -> Result<(), SignalError> {
    SIGNAL_MANAGER.send(target, signal)
}

/// 自分自身にシグナルを送信 (raise() 相当)
pub fn raise(_signal: Signal) -> Result<(), SignalError> {
    // TODO: 現在のタスクID取得
    Err(SignalError::NoSuchTask)
}

/// シグナルハンドラを設定 (signal() 相当)
pub fn signal(task_id: TaskId, signal: Signal, handler: SignalHandler) -> Result<(), SignalError> {
    let ctx = SIGNAL_MANAGER.get(task_id).ok_or(SignalError::NoSuchTask)?;
    ctx.set_action(signal, SignalAction::Handle, Some(handler))
}

/// シグナルを無視 (SIG_IGN 相当)
pub fn sigignore(task_id: TaskId, signal: Signal) -> Result<(), SignalError> {
    let ctx = SIGNAL_MANAGER.get(task_id).ok_or(SignalError::NoSuchTask)?;
    ctx.set_action(signal, SignalAction::Ignore, None)
}

/// シグナルをデフォルトに戻す (SIG_DFL 相当)
pub fn sigdefault(task_id: TaskId, signal: Signal) -> Result<(), SignalError> {
    let ctx = SIGNAL_MANAGER.get(task_id).ok_or(SignalError::NoSuchTask)?;
    ctx.set_action(signal, SignalAction::Default, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_mask() {
        let mut mask = SignalMask::new();
        assert!(!mask.contains(Signal::SIGTERM));

        mask.add(Signal::SIGTERM);
        assert!(mask.contains(Signal::SIGTERM));

        mask.remove(Signal::SIGTERM);
        assert!(!mask.contains(Signal::SIGTERM));
    }

    #[test]
    fn test_signal_queue() {
        let queue = SignalQueue::new();

        let info = SignalInfo {
            signal: Signal::SIGTERM,
            sender_pid: None,
            data: SignalData::None,
            timestamp: 0,
        };

        queue.enqueue(info.clone()).unwrap();
        assert!(queue.is_pending(Signal::SIGTERM));

        let dequeued = queue.dequeue(&SignalMask::EMPTY).unwrap();
        assert_eq!(dequeued.signal, Signal::SIGTERM);
    }
}
