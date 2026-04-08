// ============================================================================
// kernel/src/net/l4/endpoint/event_loop.rs
// ============================================================================
//! # Endpoint Event Loop
//!
//! endpoint 共通のイベント待機・バッチ処理タスクを提供する。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::event::{NetworkEvent, event_queue_in};
use super::handler::{EventHandleResult, NetworkEventHandler};
use super::tcb::tcb_table;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};

/// ネットワークイベント処理タスク（完全非同期版）
///
/// 【完全非同期化】イベントキュー経由でプロトコルスタックにアクセスする。
/// NETWORK_STACKのロック取得はこのタスク内でのみ行われ、
/// 他の全てのネットワーク操作はイベントキュー経由で非同期にオフロードされる。
///
/// ## ロック取得の設計方針
/// - スタックロックは1回のバッチ処理で取得し、バッチ内の全イベントを処理
/// - バッチサイズに上限を設け、長時間のロック保持によるスターベーションを防止
/// - バッチ間でロックを解放し、yield_now()で他のタスクに実行機会を与える
/// - ISR内でwake()を直接呼ばない（設計書準拠: 2段階Wake方式）
pub async fn network_event_task() {
    network_event_task_in(default_runtime()).await;
}

pub async fn network_event_task_in(runtime: NetRuntimeHandle) {
    log::info!(
        "[NET] network_event_task started on CPU {} (fully async)",
        crate::cpu::try_current_id().unwrap_or(0)
    );
    log::info!("[NET][boot] network_event_task stage: awaiting first event batch");
    super::event::mark_event_task_running_in(runtime);

    /// 1回のバッチで処理するイベントの最大数
    /// ロック保持時間を制限し、他タスクのスターベーションを防止
    const MAX_BATCH_SIZE: usize = 128;

    let handler = NetworkEventHandler::new();

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.
    loop {
        let event = event_queue_in(runtime).wait_for_events().await;

        if let Ok(mut stack_guard) = runtime.context().stack.lock() {
            if let Some(ref mut stack) = *stack_guard {
                let event_clone = event.clone();
                let result = handler.handle_event_with_stack_in(runtime, event, stack);
                process_handle_result(runtime, result, event_clone);

                let mut batch_count = 1usize;
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.
                while batch_count < MAX_BATCH_SIZE {
                    match event_queue_in(runtime).recv() {
                        Some(batch_event) => {
                            let batch_clone = batch_event.clone();
                            let result =
                                handler.handle_event_with_stack_in(runtime, batch_event, stack);
                            process_handle_result(runtime, result, batch_clone);
                            batch_count += 1;
                        }
                        None => break,
                    }
                }

                drop(stack_guard);

                if batch_count >= MAX_BATCH_SIZE {
                    crate::task::yield_now().await;
                }
                continue;
            }
        }

        let event_clone = event.clone();
        let result = handler.handle_event_in(runtime, event);
        process_handle_result(runtime, result, event_clone);

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.
        while let Some(batch_event) = event_queue_in(runtime).recv() {
            let batch_clone = batch_event.clone();
            let result = handler.handle_event_in(runtime, batch_event);
            process_handle_result(runtime, result, batch_clone);
        }
    }
}

/// イベント処理結果の共通対応
fn process_handle_result(
    runtime: NetRuntimeHandle,
    result: EventHandleResult,
    event_clone: NetworkEvent,
) {
    match result {
        EventHandleResult::Success | EventHandleResult::IngressPacket { .. } => {}
        EventHandleResult::SocketNotFound(fd) => {
            log::debug!("Network: Socket {} not found (already closed)", fd.raw());
        }
        EventHandleResult::ProtocolError(e) => {
            static PROTO_ERR_COUNT: AtomicU32 = AtomicU32::new(0);
            static PROTO_ERR_LAST_LOG: AtomicU64 = AtomicU64::new(0);
            let now = tcb_table().get_current_tick();
            let last = PROTO_ERR_LAST_LOG.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= 5000 {
                let suppressed = PROTO_ERR_COUNT.swap(0, Ordering::Relaxed);
                PROTO_ERR_LAST_LOG.store(now, Ordering::Relaxed);
                if suppressed > 0 {
                    log::info!(
                        "Network: Protocol error: {:?} (suppressed {} similar in last 5s)",
                        e,
                        suppressed
                    );
                } else {
                    log::info!("Network: Protocol error: {:?}", e);
                }
            } else {
                PROTO_ERR_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
        EventHandleResult::Retry => {
            if super::event::enqueue_event_in(runtime, event_clone).is_err() {
                log::warn!("Network: Event requeue failed due to full queue");
            }
        }
    }
}
