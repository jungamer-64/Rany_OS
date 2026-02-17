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

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use crate::io::io_scheduler::{
    DeviceId, DeviceOps, IoCommand, IoError, IoRequest, IoRequestId, IoResult, PollHandler,
    hybrid_coordinator, io_scheduler,
};

use super::blk::{BlockError, VirtioBlkStatus, get_virtio_blk_device};

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
    /// 保留中リクエスト: (queue_idx, desc_id) -> PendingBlkRequest
    /// マルチキュー対応のためキーに queue_idx を含める
    pending: Mutex<BTreeMap<(usize, u16), PendingBlkRequest>>,
}

impl VirtioBlkPollHandler {
    /// 新しい VirtioBlkPollHandler を作成
    pub fn new(device_index: u8) -> Self {
        Self {
            device_index,
            pending: Mutex::new(BTreeMap::new()),
        }
    }

    /// 生の完了をpendingマップとマッチしてIoResultを生成する
    fn match_raw_completions(
        &self,
        device: &super::blk::VirtioBlkDevice,
        raw_completions: &[(usize, u16, u32)],
    ) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();
        let mut pending = self.pending.lock();
        for &(queue_idx, desc_id, _len) in raw_completions {
            let key = (queue_idx, desc_id);
            if let Some(req) = pending.remove(&key) {
                let status_ok = device
                    .inflight_dma
                    .lock()
                    .remove(&desc_id)
                    .map(|dma| dma.status() == VirtioBlkStatus::Ok as u8)
                    .unwrap_or(true);

                let result = if status_ok {
                    IoResult::Success(req.bytes)
                } else {
                    IoResult::Error(IoError::DeviceError)
                };

                if let Some(queue_arc) = device.queue(queue_idx) {
                    queue_arc.lock().free_desc(desc_id);
                }

                results.push((req.io_id, result));
            }
        }
        results
    }

    /// リクエストを保留マップに追加（submit 成功後に呼ぶ）
    pub fn add_pending(
        &self,
        io_id: IoRequestId,
        queue_idx: usize,
        desc_id: u16,
        bytes: usize,
    ) {
        self.pending.lock().insert(
            (queue_idx, desc_id),
            PendingBlkRequest {
                io_id,
                queue_idx,
                desc_id,
                bytes,
            },
        );
    }

    /// 保留リクエストを取り出して削除（割り込みハンドラから使用）
    ///
    /// 指定された (queue_idx, desc_id) に対応するリクエストがあれば
    /// `(IoRequestId, bytes)` を返し、pending から削除する。
    pub fn take_pending(&self, queue_idx: usize, desc_id: u16) -> Option<(IoRequestId, usize)> {
        self.pending
            .lock()
            .remove(&(queue_idx, desc_id))
            .map(|req| (req.io_id, req.bytes))
    }
}

impl PollHandler for VirtioBlkPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let device = match get_virtio_blk_device() {
            Some(dev) => dev,
            None => return Vec::new(),
        };

        // Phase 1: 全キューの used ring から生の完了を収集
        // VirtQueue lock を最小限に保持
        let mut raw_completions: Vec<(usize, u16, u32)> = Vec::new();
        let queue_count = device.queue_count();
        for q_idx in 0..queue_count {
            if let Some(queue_arc) = device.queue(q_idx) {
                let queue_guard = queue_arc.lock();
                while let Some((desc_id, len)) = queue_guard.poll_completions() {
                    raw_completions.push((q_idx, desc_id, len));
                }
            }
        }

        // Phase 2: pending マップとマッチし IoResult を生成
        self.match_raw_completions(&device, &raw_completions)
    }

    fn is_ready(&self) -> bool {
        get_virtio_blk_device()
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
            BlockError::ReadOnly => IoError::NotSupported,
            BlockError::InvalidSector => IoError::InvalidParameter,
            BlockError::InvalidBufferSize => IoError::InvalidParameter,
            BlockError::Unsupported => IoError::NotSupported,
            BlockError::IoError => IoError::DeviceError,
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

        let device = get_virtio_blk_device().ok_or(IoError::NoResources)?;
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

                self.handler
                    .add_pending(req.id, queue_idx, desc_id, *bytes);
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
        get_virtio_blk_device()
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
static VIRTIO_BLK_POLL_HANDLERS: RwLock<BTreeMap<u8, Arc<VirtioBlkPollHandler>>> =
    RwLock::new(BTreeMap::new());

/// 指定デバイスの PollHandler を取得（割り込みハンドラから使用）
pub fn get_poll_handler(device_index: u8) -> Option<Arc<VirtioBlkPollHandler>> {
    VIRTIO_BLK_POLL_HANDLERS
        .read()
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
    let handler = Arc::new(VirtioBlkPollHandler::new(device_index));

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
