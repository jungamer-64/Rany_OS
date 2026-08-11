// ============================================================================
// kernel/src/net/runtime/command_loop.rs - Socket Event Loop
// ============================================================================
//! # Socket Event Loop
//!
//! endpoint 共通のイベント待機・バッチ処理タスクを提供する。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::command::command_queue_in;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};
use crate::net::runtime::transport::tcp_table_in;

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
pub(crate) async fn runtime_command_task_in(runtime: NetRuntimeHandle) {
    log::info!(
        "[NET] runtime_command_task started on CPU {} (fully async)",
        crate::cpu::try_current_id().unwrap_or(0)
    );
    log::info!("[NET][boot] runtime_command_task stage: awaiting first event batch");
    super::command::mark_command_task_running_in(runtime);

    /// 1回のバッチで処理するイベントの最大数
    /// ロック保持時間を制限し、他タスクのスターベーションを防止
    const MAX_BATCH_SIZE: usize = 128;

    let handler = RuntimeCommandHandler::new();

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.
    loop {
        let event = command_queue_in(runtime).wait_for_events().await;

        if let Ok(mut stack_guard) = crate::net::runtime::stack::stack_in(runtime).lock() {
            if let Some(ref mut stack) = *stack_guard {
                let result = handler.handle_event_with_stack_in(runtime, event, stack);
                process_handle_result(runtime, result);

                let mut batch_count = 1usize;
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.
                while batch_count < MAX_BATCH_SIZE {
                    match command_queue_in(runtime).recv() {
                        Some(batch_event) => {
                            let result =
                                handler.handle_event_with_stack_in(runtime, batch_event, stack);
                            process_handle_result(runtime, result);
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

        let result = handler.handle_event_in(runtime, event);
        process_handle_result(runtime, result);

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.
        while let Some(batch_event) = command_queue_in(runtime).recv() {
            let result = handler.handle_event_in(runtime, batch_event);
            process_handle_result(runtime, result);
        }
    }
}

/// イベント処理結果の共通対応
fn process_handle_result(runtime: NetRuntimeHandle, result: EventHandleResult) {
    match result {
        EventHandleResult::Success => {}
        EventHandleResult::SocketNotFound(fd) => {
            log::debug!("Network: Socket {} not found (already closed)", fd.raw());
        }
        EventHandleResult::ProtocolError(e) => {
            static PROTO_ERR_COUNT: AtomicU32 = AtomicU32::new(0);
            static PROTO_ERR_LAST_LOG: AtomicU64 = AtomicU64::new(0);
            let now = tcp_table_in(runtime).get_current_tick();
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
    }
}
