// ============================================================================
// src/shell/graphical/streams.rs - Event Streams for Graphical Shell
// ============================================================================
//!
//! # イベントストリーム
//!
//! グラフィカルシェルのイベント駆動アーキテクチャ用ストリーム抽象化。
//!
//! ## 設計思想
//! - ビジーウェイトから Waker 駆動への移行
//! - `select!` によるイベント合成を可能に
//! - C-state 対応の省電力化

use alloc::collections::VecDeque;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

// ============================================================================
// Command Queue Stream
// ============================================================================

/// 非同期コマンドリクエスト
pub struct CommandRequest {
    pub command: String,
    pub id: u64,
}

/// コマンドキューへのWaker通知機構
struct CommandQueueWaker {
    waker: Mutex<Option<Waker>>,
    has_pending: AtomicBool,
}

impl CommandQueueWaker {
    const fn new() -> Self {
        Self {
            waker: Mutex::new(None),
            has_pending: AtomicBool::new(false),
        }
    }

    /// Wakerを登録（コンシューマ側）
    fn register(&self, waker: &Waker) {
        let mut guard = self.waker.lock();
        if let Some(existing) = guard.as_ref() {
            if existing.will_wake(waker) {
                return;
            }
        }
        *guard = Some(waker.clone());
    }

    /// Wakeをトリガー（プロデューサ側）
    fn notify(&self) {
        self.has_pending.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    /// 保留中のWakeを処理
    fn take_pending(&self) -> bool {
        self.has_pending.swap(false, Ordering::Acquire)
    }
}

static COMMAND_QUEUE: Mutex<VecDeque<CommandRequest>> = Mutex::new(VecDeque::new());
static COMMAND_WAKER: CommandQueueWaker = CommandQueueWaker::new();
static NEXT_COMMAND_ID: AtomicU64 = AtomicU64::new(0);

/// コマンドをキューに追加（プロデューサAPI）
pub fn submit_command(command: String) -> u64 {
    let id = NEXT_COMMAND_ID.fetch_add(1, Ordering::SeqCst);
    COMMAND_QUEUE
        .lock()
        .push_back(CommandRequest { command, id });
    COMMAND_WAKER.notify();
    id
}

/// コマンドを非同期に取得（非ブロッキング）
pub fn try_recv_command() -> Option<CommandRequest> {
    COMMAND_QUEUE.lock().pop_front()
}

/// コマンドキューからの非同期ストリーム
pub struct CommandQueueStream {
    _marker: (),
}

impl CommandQueueStream {
    pub fn new() -> Self {
        Self { _marker: () }
    }
}

/// コマンド取得用Future
pub struct CommandQueueFuture;

impl Future for CommandQueueFuture {
    type Output = CommandRequest;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 保留中の通知を処理
        COMMAND_WAKER.take_pending();

        // キューをチェック
        if let Some(req) = COMMAND_QUEUE.lock().pop_front() {
            return Poll::Ready(req);
        }

        // Wakerを登録
        COMMAND_WAKER.register(cx.waker());

        // ダブルチェック
        if let Some(req) = COMMAND_QUEUE.lock().pop_front() {
            return Poll::Ready(req);
        }

        Poll::Pending
    }
}

impl CommandQueueStream {
    /// 次のコマンドを非同期で待機
    pub fn next(&mut self) -> CommandQueueFuture {
        CommandQueueFuture
    }
}

// ============================================================================
// Blink Timer Stream
// ============================================================================

/// カーソル点滅用タイマー
pub struct BlinkTimer {
    interval_ticks: u64,
    last_tick: u64,
}

impl BlinkTimer {
    /// 新規タイマー作成（interval_ms: 点滅間隔ミリ秒）
    pub fn new(interval_ms: u64) -> Self {
        // タイマーティックをミリ秒に換算（1ティック = 約1ms想定）
        Self {
            interval_ticks: interval_ms,
            last_tick: kernel_api::services::kernel()
                .gui()
                .map(|g| g.current_tick())
                .unwrap_or(0),
        }
    }

    /// 次のティックまで待機
    pub fn tick(&mut self) -> BlinkTimerFuture<'_> {
        BlinkTimerFuture { timer: self }
    }
}

pub struct BlinkTimerFuture<'a> {
    timer: &'a mut BlinkTimer,
}

impl<'a> Future for BlinkTimerFuture<'a> {
    type Output = u64;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let current = kernel_api::services::kernel()
            .gui()
            .map(|g| g.current_tick())
            .unwrap_or(0);
        let elapsed = current.saturating_sub(self.timer.last_tick);

        if elapsed >= self.timer.interval_ticks {
            self.timer.last_tick = current;
            Poll::Ready(current)
        } else {
            // TODO: タイマー割り込みと連携したWaker登録
            // 現時点では即座にPendingを返し、次のpollで再チェック
            Poll::Pending
        }
    }
}

// ============================================================================
// Result Queue (for command outputs)
// ============================================================================

/// コマンド実行結果
pub struct CommandResult {
    pub id: u64,
    pub output: String,
    pub is_error: bool,
    pub cwd: Option<String>,
}

static RESULT_QUEUE: Mutex<VecDeque<CommandResult>> = Mutex::new(VecDeque::new());

/// 結果をキューに追加
pub fn push_result(result: CommandResult) {
    RESULT_QUEUE.lock().push_back(result);
}

/// 結果をポーリング
pub fn poll_result() -> Option<CommandResult> {
    RESULT_QUEUE.lock().pop_front()
}

/// すべての結果を取得
pub fn drain_results() -> alloc::vec::Vec<CommandResult> {
    let mut results = alloc::vec::Vec::new();
    let mut queue = RESULT_QUEUE.lock();
    while let Some(r) = queue.pop_front() {
        results.push(r);
    }
    results
}
