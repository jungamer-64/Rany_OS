// ============================================================================
// src/io/nvme/scheduler.rs - NVMe IoScheduler Integration
// ============================================================================
//!
//! # NVMe IoScheduler統合
//!
//! NVMeドライバをIoSchedulerと連携させるアダプタ層。

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, IoError, IoRequestId, IoResult, ModeThresholds, PollHandler,
};

use super::global::with_driver;
use super::per_core::PerCoreNvmeQueue;

// ============================================================================
// Poll Handler
// ============================================================================

/// NVMe用PollHandlerラッパー
///
/// IoSchedulerとNvmePollingDriverを接続するアダプタ。
/// 特定のコアIDに紐付けられる。
pub struct NvmePollHandler {
    /// コアID
    core_id: u32,
    /// 名前空間ID
    nsid: u32,
    /// 保留中のI/OリクエストID → NVMeコマンドID
    pending: Mutex<BTreeMap<IoRequestId, u16>>,
}

impl NvmePollHandler {
    /// 新しいPollHandlerを作成
    pub fn new(core_id: u32, nsid: u32) -> Self {
        Self {
            core_id,
            nsid,
            pending: Mutex::new(BTreeMap::new()),
        }
    }

    /// I/OリクエストIDとNVMeコマンドIDを紐付け
    pub fn register_request(&self, io_id: IoRequestId, cid: u16) {
        self.pending.lock().insert(io_id, cid);
    }

    /// I/OリクエストIDからNVMeコマンドIDを取得
    pub fn get_cid(&self, io_id: &IoRequestId) -> Option<u16> {
        self.pending.lock().get(io_id).copied()
    }

    /// 完了したリクエストを削除
    pub fn remove_request(&self, io_id: &IoRequestId) -> Option<u16> {
        self.pending.lock().remove(io_id)
    }
}

impl PollHandler for NvmePollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();

        with_driver(|driver| {
            if let Some(queue) = driver.get_queue(self.core_id) {
                // SAFETY: poll は内部で適切に同期されている
                while let Some(cqe) = unsafe { queue.poll() } {
                    let cid = cqe.cid;

                    let pending = self.pending.lock();
                    if let Some((&io_id, _)) = pending.iter().find(|&(_, &c)| c == cid) {
                        let result = if cqe.is_success() {
                            IoResult::Success(512)
                        } else {
                            IoResult::Error(IoError::DeviceError)
                        };
                        results.push((io_id, result));
                    }
                }
            }
        });

        // 完了したリクエストを削除
        for (io_id, _) in &results {
            self.pending.lock().remove(io_id);
        }

        results
    }

    fn is_ready(&self) -> bool {
        with_driver(|d| d.is_active()).unwrap_or(false)
    }
}

// ============================================================================
// PollHandler Wrapper
// ============================================================================

/// PollHandlerトレイト実装のラッパー（Box化用）
struct NvmePollHandlerWrapper {
    inner: Arc<NvmePollHandler>,
}

impl PollHandler for NvmePollHandlerWrapper {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        self.inner.poll_completions()
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}

// ============================================================================
// Registration
// ============================================================================

/// NVMeドライバをIoSchedulerに登録
///
/// # Arguments
/// * `controller_id` - NVMeコントローラID
/// * `namespace_id` - 名前空間ID
/// * `num_cores` - ポーリングスレッド数
///
/// # Returns
/// 登録されたPollHandlerへの参照（各コア用）
pub fn register_with_io_scheduler(
    controller_id: u8,
    namespace_id: u32,
    num_cores: u32,
) -> Result<Vec<Arc<NvmePollHandler>>, &'static str> {
    use crate::io::io_scheduler::{hybrid_coordinator, io_scheduler};

    let scheduler = io_scheduler();
    let coordinator = hybrid_coordinator();

    let mut handlers = Vec::new();

    for core_id in 0..num_cores {
        let device_id = IoDeviceId::Nvme {
            controller: controller_id,
            namespace: namespace_id,
        };

        // デフォルトのモード閾値でデバイスを登録
        scheduler.register_device(device_id, ModeThresholds::default());

        // PollHandlerを作成して登録
        let handler = Arc::new(NvmePollHandler::new(core_id, namespace_id));
        coordinator.polling_executor().register_handler(
            device_id,
            Box::new(NvmePollHandlerWrapper {
                inner: handler.clone(),
            }),
        );

        handlers.push(handler);
    }

    Ok(handlers)
}
