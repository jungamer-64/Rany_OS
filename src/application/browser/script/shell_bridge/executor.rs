// ============================================================================
// src/application/browser/script/shell_bridge/executor.rs - Async Executor
// ============================================================================
//!
//! 非同期実行エグゼキュータ

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::application::browser::script::ScriptResult;
use crate::application::browser::script::value::ScriptValue;

use super::types::{AsyncCommandFuture, TaskId};

// ============================================================================
// Async Executor
// ============================================================================

/// 非同期実行コンテキスト
pub struct AsyncExecutor {
    /// 実行中のタスク
    tasks: Vec<(TaskId, AsyncCommandFuture)>,
    /// 完了したタスクの結果
    completed: BTreeMap<TaskId, ScriptResult<ScriptValue>>,
}

impl AsyncExecutor {
    /// 新しいエグゼキュータを作成
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            completed: BTreeMap::new(),
        }
    }

    /// タスクを追加
    pub fn spawn(&mut self, task_id: TaskId, future: AsyncCommandFuture) {
        self.tasks.push((task_id, future));
    }

    /// 1ステップ実行（協調的マルチタスク）
    pub fn poll_once(&mut self) -> Vec<TaskId> {
        let mut completed_ids = Vec::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        
        let mut i = 0;
        while i < self.tasks.len() {
            let (task_id, future) = &mut self.tasks[i];
            
            match Pin::as_mut(future).poll(&mut cx) {
                Poll::Ready(result) => {
                    let id = *task_id;
                    self.completed.insert(id, result);
                    completed_ids.push(id);
                    let _ = self.tasks.swap_remove(i);
                    // Don't increment i, as swap_remove moved the last element here
                }
                Poll::Pending => {
                    i += 1;
                }
            }
        }
        
        completed_ids
    }

    /// 完了したタスクの結果を取得
    pub fn take_result(&mut self, task_id: TaskId) -> Option<ScriptResult<ScriptValue>> {
        self.completed.remove(&task_id)
    }

    /// 保留中のタスク数を取得
    pub fn pending_count(&self) -> usize {
        self.tasks.len()
    }

    /// すべてのタスクが完了したか
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

impl Default for AsyncExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// No-op Waker
// ============================================================================

/// No-op Wakerを作成（シンプルなポーリング用）
pub fn noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable};
    
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    
    // Safety: The waker does nothing, so it's safe to create
    unsafe { core::task::Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}
