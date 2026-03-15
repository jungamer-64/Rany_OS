// ============================================================================
// src/io/virtio/blk_scheduler.rs - VirtIO Block IoScheduler Integration
// ============================================================================
//!
//! # VirtIO Block IoScheduler統合
//!
//! VirtIO-BlkデバイスをIoSchedulerと連携させるアダプタ層。
//! AHCI (`ahci/poll_handler.rs`) および NVMe (`nvme/scheduler.rs`) の
//! パターンに倣い、DeviceOps + PollHandler + 登録関数を提供する。

#![allow(dead_code)]

extern crate alloc;

use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::io_scheduler::{
    DeviceId, DeviceOps, IoCommand, IoError, IoRequest, IoRequestId, IoResult, PollHandler,
    hybrid_coordinator, io_scheduler,
};

use super::blk::{BlockError, get_virtio_blk_device};

// ============================================================================
// Pending Request Tracking
// ============================================================================

/// io_scheduler 経由で投入されたリクエストの追跡情報
struct PendingBlkRequest {
    /// IoScheduler リクエストID
    io_id: IoRequestId,
    /// 投入先キューインデックス
    queue_idx: usize,
    /// VirtQueue ディスクリプタ head ID
    desc_id: u16,
    /// 期待される転送バイト数（IoResult::Success 用）
    bytes: usize,
}

// ============================================================================
// VirtIO Block PollHandler
// ============================================================================

/// VirtIO Block PollHandler 実装
///
/// VirtQueue の used ring をポーリングして完了を検出し、
/// `(IoRequestId, IoResult)` ペアに変換して IoScheduler に返す。
pub struct VirtioBlkPollHandler {
    /// デバイスインデックス（DeviceId::VirtioBlk { index } 用）
    device_index: u8,
    /// 保留中リクエスト: queue_idx -> { desc_id -> PendingBlkRequest }
    /// マルチキュー対応のためキューごとに分離してロック競合を回避する
    pending: Vec<PoisonLock<BTreeMap<u16, PendingBlkRequest>>>,
}

impl VirtioBlkPollHandler {
    /// 新しい VirtioBlkPollHandler を作成
    pub fn new(device_index: u8, queue_count: usize) -> Self {
        let mut pending = Vec::with_capacity(queue_count);
        for _ in 0..queue_count {
            pending.push(PoisonLock::new(BTreeMap::new()));
        }
        Self {
            device_index,
            pending,
        }
    }

    /// 生の完了をpendingマップとマッチしてIoResultを生成する
    fn match_raw_completions(
        &self,
        device: &super::blk::VirtioBlkDevice,
        raw_completions: &[(usize, u16, u32)],
    ) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();
        for &(queue_idx, desc_id, _len) in raw_completions {
            let mut pending_guard = if let Some(p) = self.pending.get(queue_idx) {
                p.lock().unwrap_or_else(|e| e.into_inner())
            } else {
                continue;
            };

            if let Some(req) = pending_guard.remove(&desc_id) {
                let status_ok = if let Some(queue_dma) = device.inflight_dma.get(queue_idx) {
                    if let Ok(mut dmas) = queue_dma.lock() {
                        dmas.get_mut(desc_id as usize)
                            .and_then(|slot| slot.take())
                            .map(|dma| dma.status() == virtio_driver::blk::VIRTIO_BLK_S_OK)
                            .unwrap_or(true)
                    } else {
                        true
                    }
                } else {
                    true
                };

                let result = if status_ok {
                    IoResult::Success(req.bytes)
                } else {
                    IoResult::Error(IoError::DeviceError)
                };

                if let Some(queue_arc) = device.queue(queue_idx) {
                    queue_arc
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .free_desc(desc_id);
                }

                results.push((req.io_id, result));
            }
        }
        results
    }

    /// リクエストを保留マップに追加（submit 成功後に呼ぶ）
    pub fn add_pending(&self, io_id: IoRequestId, queue_idx: usize, desc_id: u16, bytes: usize) {
        if let Some(pending_queue) = self.pending.get(queue_idx) {
            pending_queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    desc_id,
                    PendingBlkRequest {
                        io_id,
                        queue_idx,
                        desc_id,
                        bytes,
                    },
                );
        }
    }

    /// 保留リクエストを取り出して削除（割り込みハンドラから使用）
    ///
    /// 指定された (queue_idx, desc_id) に対応するリクエストがあれば
    /// `(IoRequestId, bytes)` を返し、pending から削除する。
    pub fn take_pending(&self, queue_idx: usize, desc_id: u16) -> Option<(IoRequestId, usize)> {
        self.pending
            .get(queue_idx)?
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&desc_id)
            .map(|req| (req.io_id, req.bytes))
    }
}

impl PollHandler for VirtioBlkPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let device = match get_virtio_blk_device_at_index(0) {
            Some(dev) => dev,
            None => return Vec::new(),
        };

        // Phase 1: 全キューの used ring から生の完了を収集
        // VirtQueue lock を最小限に保持
        let mut raw_completions: Vec<(usize, u16, u32)> = Vec::new();
        let queue_count = device.queue_count();
        for q_idx in 0..queue_count {
            if let Some(queue_arc) = device.queue(q_idx) {
                let mut queue_guard = queue_arc.lock().unwrap_or_else(|e| e.into_inner());
                queue_guard.poll_completions(|desc_id, len| {
                    raw_completions.push((q_idx, desc_id, len));
                });
            }
        }

        // Phase 2: pending マップとマッチし IoResult を生成
        self.match_raw_completions(&device, &raw_completions)
    }

    fn is_ready(&self) -> bool {
        get_virtio_blk_device_at_index(0)
            .map(|dev| dev.is_ready())
            .unwrap_or(false)
    }
}

// ============================================================================
// VirtIO Block DeviceOps
// ============================================================================

/// VirtIO Block DeviceOps 実装
///
/// IoCommand をVirtQueue投入に変換する。
/// `submit_read` / `submit_write` / `submit_flush` は既存の
/// VirtioBlkDevice メソッドを再利用する。
pub struct VirtioBlkOps {
    device_index: u8,
    handler: Arc<VirtioBlkPollHandler>,
}

impl VirtioBlkOps {
    pub fn new(device_index: u8, handler: Arc<VirtioBlkPollHandler>) -> Self {
        Self {
            device_index,
            handler,
        }
    }

    /// cpu_idx に基づいてキューを選択（マルチキュー対応）
    fn select_queue(queue_count: usize, cpu_idx: usize) -> usize {
        if queue_count == 0 {
            0
        } else {
            cpu_idx % queue_count
        }
    }

    /// BlockError → IoError 変換
    fn map_block_error(e: BlockError) -> IoError {
        match e {
            BlockError::QueueFull => IoError::NoResources,
            BlockError::NotReady => IoError::Busy,
            BlockError::Unsupported => IoError::NotSupported,
            BlockError::IoError => IoError::DeviceError,
            BlockError::InvalidParam => IoError::InvalidParameter,
        }
    }
    /// Validate block I/O parameters
    fn validate_block_params(blocks: u16, bytes: usize, buf_len: usize) -> Result<(), IoError> {
        if blocks == 0 {
            return Err(IoError::InvalidParameter);
        }
        if bytes > buf_len {
            return Err(IoError::InvalidParameter);
        }
        Ok(())
    }
}

impl DeviceOps for VirtioBlkOps {
    fn submit(&self, req: &IoRequest, cpu_idx: usize) -> Result<(), IoError> {
        let cmd = req.command.as_ref().ok_or(IoError::NotSupported)?;

        let device = get_virtio_blk_device_at_index(0).ok_or(IoError::NoResources)?;
        let queue_idx = Self::select_queue(device.queue_count(), cpu_idx);

        match cmd {
            IoCommand::BlockRead {
                lba,
                blocks,
                bytes,
                buf,
            }
            | IoCommand::BlockWrite {
                lba,
                blocks,
                bytes,
                buf,
            } => {
                Self::validate_block_params(*blocks, *bytes, buf.len)?;

                let is_read = matches!(cmd, IoCommand::BlockRead { .. });
                let desc_id = if is_read {
                    device.submit_read(*lba, buf.iova, *bytes as u32, queue_idx)
                } else {
                    device.submit_write(*lba, buf.iova, *bytes as u32, queue_idx)
                }
                .map_err(Self::map_block_error)?;

                self.handler.add_pending(req.id, queue_idx, desc_id, *bytes);
                Ok(())
            }
            IoCommand::Flush => {
                let desc_id = device
                    .submit_flush(queue_idx)
                    .map_err(Self::map_block_error)?;

                self.handler.add_pending(req.id, queue_idx, desc_id, 0);
                Ok(())
            }
            IoCommand::Discard { .. } => Err(IoError::NotSupported),
            IoCommand::Ioctl { .. } => Err(IoError::NotSupported),
        }
    }

    fn is_ready(&self) -> bool {
        get_virtio_blk_device_at_index(0)
            .map(|dev| dev.is_ready())
            .unwrap_or(false)
    }
}

// ============================================================================
// PollHandler Wrapper & Global Registry
// ============================================================================

/// Arc<VirtioBlkPollHandler> を Box<dyn PollHandler> に変換するラッパー
struct VirtioBlkPollHandlerWrapper {
    inner: Arc<VirtioBlkPollHandler>,
}

impl PollHandler for VirtioBlkPollHandlerWrapper {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        self.inner.poll_completions()
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}

/// グローバル PollHandler レジストリ (device_index -> handler)
static VIRTIO_BLK_POLL_HANDLERS: PoisonRwLock<BTreeMap<u8, Arc<VirtioBlkPollHandler>>> =
    PoisonRwLock::new(BTreeMap::new());

/// 指定デバイスの PollHandler を取得（割り込みハンドラから使用）
pub fn get_poll_handler(device_index: u8) -> Option<Arc<VirtioBlkPollHandler>> {
    VIRTIO_BLK_POLL_HANDLERS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&device_index)
        .cloned()
}

// ============================================================================
// Registration
// ============================================================================

/// VirtIO-Blk を IoScheduler に登録（依存注入版）
pub fn register_virtio_blk_with(
    scheduler: &Arc<crate::io::io_scheduler::IoScheduler>,
    coordinator: &Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    device_index: u8,
) {
    let device_id = DeviceId::VirtioBlk {
        index: device_index,
    };

    // 1. 共有 PollHandler を作成
    let device = get_virtio_blk_device_at_index(0)
        .expect("VirtIO-blk device must be initialized before registration");
    let queue_count = device.queue_count();
    let handler = Arc::new(VirtioBlkPollHandler::new(device_index, queue_count));

    // 2. PollingExecutor に PollHandler を登録
    coordinator.polling_executor().register_handler(
        device_id,
        Box::new(VirtioBlkPollHandlerWrapper {
            inner: handler.clone(),
        }),
    );

    // 3. グローバルレジストリに保存（割り込みハンドラからの参照用）
    VIRTIO_BLK_POLL_HANDLERS
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(device_index, handler.clone());

    // 4. DeviceOps を作成して登録
    let ops = Arc::new(VirtioBlkOps::new(device_index, handler));
    scheduler.register_device_ops(device_id, ops);

    log::info!(
        "[VIRTIO-BLK] Registered device {:?} with IoScheduler",
        device_id
    );
}

/// VirtIO-Blk を IoScheduler に登録（グローバルインスタンス使用の便利ラッパー）
pub fn register_virtio_blk_with_io_scheduler(device_index: u8) {
    register_virtio_blk_with(&io_scheduler(), &hybrid_coordinator(), device_index);
}
