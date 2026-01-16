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
use spin::{Mutex, RwLock};

use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DeviceOps, DmaBufHandle, IoCommand, IoError, IoOperationType,
    IoPayload, IoRequest, IoRequestId, IoResult, ModeThresholds, PollHandler,
};
use crate::io::nvme::SglDescriptor;

use super::global::with_driver;

// ============================================================================
// NVMe Device Operations (DeviceOps Implementation)
// ============================================================================

/// NVMeデバイス操作実装
///
/// DeviceOpsを実装し、IoSchedulerからの依存逆転を提供する。
/// IoSchedulerはNVMe固有コードを知らずに、このtrait経由でのみ対話する。
pub struct NvmeOps {
    controller_id: u8,
    namespace_id: u32,
}

impl NvmeOps {
    /// 新しいNvmeOpsを作成
    pub fn new(controller_id: u8, namespace_id: u32) -> Self {
        Self {
            controller_id,
            namespace_id,
        }
    }
}

impl DeviceOps for NvmeOps {
    fn submit(&self, req: &IoRequest) -> Result<(), IoError> {
        // 新API: IoCommand が設定されていれば使用
        if let Some(cmd) = &req.command {
            return self.submit_command(cmd, req.id);
        }
        // 後方互換: 旧IoPayload を使用
        submit_request(req)
    }

    fn is_ready(&self) -> bool {
        with_driver(|d| d.is_active()).unwrap_or(false)
    }
}

impl NvmeOps {
    /// IoCommand を NVMe 固有形式に変換して submit
    fn submit_command(&self, cmd: &IoCommand, id: IoRequestId) -> Result<(), IoError> {
        let core_id = crate::smp::current_cpu();
        // handler選択: CPU ID != queue index の場合のフォールバック
        let handler = handler_for_device(self.controller_id, self.namespace_id, core_id)
            .or_else(|| {
                // フォールバック: 任意のハンドラを使用
                let key = (self.controller_id, self.namespace_id);
                NVME_POLL_HANDLERS.read().get(&key).and_then(|list| {
                    let idx = (core_id as usize) % list.len().max(1);
                    list.get(idx).cloned()
                })
            })
            .ok_or(IoError::NoResources)?;

        // 重要: submit と poll_completions で同じ queue を使用
        // handler.core_id が poll する queue なので、submit もそこへ
        let submit_qid = handler.core_id;

        let (cid, bytes) = match cmd {
            IoCommand::BlockRead { lba, blocks, bytes, buf } => {
                // PRP 検証: 現在は単一ページ（4K境界内）のみサポート
                Self::validate_prp_buffer(buf)?;
                let prp1 = buf.iova;
                let prp2 = 0; // 単一ページの場合
                let cid = with_driver(|driver| unsafe {
                    driver.submit_read(submit_qid, self.namespace_id, *lba, *blocks, prp1, prp2)
                })
                .ok_or(IoError::NoResources)?
                .map_err(map_nvme_error)?;
                (cid, *bytes)
            }
            IoCommand::BlockWrite { lba, blocks, bytes, buf } => {
                Self::validate_prp_buffer(buf)?;
                let prp1 = buf.iova;
                let prp2 = 0;
                let cid = with_driver(|driver| unsafe {
                    driver.submit_write(submit_qid, self.namespace_id, *lba, *blocks, prp1, prp2)
                })
                .ok_or(IoError::NoResources)?
                .map_err(map_nvme_error)?;
                (cid, *bytes)
            }
            IoCommand::Flush => {
                let cid = with_driver(|driver| unsafe {
                    driver.submit_flush(submit_qid, self.namespace_id)
                })
                .ok_or(IoError::NoResources)?
                .map_err(map_nvme_error)?;
                (cid, 0)
            }
            IoCommand::Discard { .. } => {
                return Err(IoError::NotSupported);
            }
            IoCommand::Ioctl { .. } => {
                return Err(IoError::NotSupported);
            }
        };

        handler.register_request(id, cid, bytes);
        Ok(())
    }

    /// PRP バッファ検証（単一4Kページ境界チェック）
    ///
    /// 現在の実装は prp2=0 (単一PRP) のため、バッファは:
    /// - 4KB以下の長さ
    /// - 4KB境界を跨がない
    /// 必要があります。
    fn validate_prp_buffer(buf: &DmaBufHandle) -> Result<(), IoError> {
        const PAGE_SIZE: u64 = 4096;
        let page_mask = PAGE_SIZE - 1;

        // バッファが4KB以下かチェック
        if buf.len as u64 > PAGE_SIZE {
            log::warn!("[NVMe] Buffer too large for single PRP: {} bytes (max 4096)", buf.len);
            return Err(IoError::InvalidParameter);
        }

        // 4KB境界を跨がないかチェック
        let start_page = buf.iova & !page_mask;
        let end_addr = buf.iova.saturating_add(buf.len as u64).saturating_sub(1);
        let end_page = end_addr & !page_mask;

        if start_page != end_page {
            log::warn!("[NVMe] Buffer crosses page boundary: iova=0x{:x}, len={}", buf.iova, buf.len);
            return Err(IoError::InvalidParameter);
        }

        Ok(())
    }
}

// ============================================================================
// Poll Handler
// ============================================================================

type NvmeHandlerKey = (u8, u32);

struct PendingNvmeRequest {
    io_id: IoRequestId,
    bytes: usize,
}

static NVME_POLL_HANDLERS: RwLock<BTreeMap<NvmeHandlerKey, Vec<Arc<NvmePollHandler>>>> =
    RwLock::new(BTreeMap::new());

/// NVMe用PollHandlerラッパー
///
/// IoSchedulerとNvmePollingDriverを接続するアダプタ。
/// 特定のコアIDに紐付けられる。
pub struct NvmePollHandler {
    /// コアID
    core_id: u32,
    /// 名前空間ID
    nsid: u32,
    /// 保留中のNVMeコマンドID → I/Oリクエスト
    /// Vec を使用して O(1) アクセス（CID は通常 0-1023 の範囲）
    pending: Mutex<Vec<Option<PendingNvmeRequest>>>,
}

/// NVMe キューの最大コマンドID数（2^10 = 1024）
const NVME_MAX_CID: usize = 1024;

impl NvmePollHandler {
    /// 新しいPollHandlerを作成
    pub fn new(core_id: u32, nsid: u32) -> Self {
        let mut pending = Vec::with_capacity(NVME_MAX_CID);
        pending.resize_with(NVME_MAX_CID, || None);
        Self {
            core_id,
            nsid,
            pending: Mutex::new(pending),
        }
    }

    /// I/OリクエストIDとNVMeコマンドIDを紐付け
    pub fn register_request(&self, io_id: IoRequestId, cid: u16, bytes: usize) {
        let mut pending = self.pending.lock();
        if let Some(slot) = pending.get_mut(cid as usize) {
            *slot = Some(PendingNvmeRequest { io_id, bytes });
        } else {
            // CID が範囲外の場合は警告（通常発生しない）
            log::warn!("[NVMe] CID {} out of range for pending tracking", cid);
        }
    }
}

impl PollHandler for NvmePollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();

        with_driver(|driver| {
            if let Some(queue) = driver.get_queue(self.core_id) {
                let pending_requests = queue.get_pending_requests();
                // SAFETY: poll は内部で適切に同期されている
                unsafe {
                    while let Some(cqe) = queue.poll() {
                        let cid = cqe.cid;
                        let entry = self.pending.lock()
                            .get_mut(cid as usize)
                            .and_then(|slot| slot.take());

                        {
                            let mut pending = pending_requests.lock();
                            pending.complete(cid, cqe);
                            if entry.is_some() {
                                let _ = pending.take(cid);
                            }
                        }

                        if let Some(entry) = entry {
                            let result = if cqe.is_success() {
                                IoResult::Success(entry.bytes)
                            } else {
                                IoResult::Error(IoError::DeviceError)
                            };
                            results.push((entry.io_id, result));
                        }
                    }
                }
            }
        });

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

    fn affinity_cpu_index(&self) -> Option<usize> {
        // NVMe handler は特定の queue/CPU index に紐づく
        // core_id は登録時の CPU 番号 (0-based) を想定
        Some(self.inner.core_id as usize)
    }
}

// ============================================================================
// Registration
// ============================================================================

/// NVMeドライバを注入されたスケジューラに登録（依存注入版）
///
/// NVMeがglobalシングルトンを知らなくて済む形。
/// 呼び出し側（kernel init等）だけがglobalを知る。
///
/// # Arguments
/// * `scheduler` - IoSchedulerへのArc参照
/// * `coordinator` - HybridIoCoordinatorへのArc参照
/// * `controller_id` - NVMeコントローラID
/// * `namespace_id` - 名前空間ID
/// * `num_cores` - ポーリングスレッド数
pub fn register_with(
    scheduler: &Arc<crate::io::io_scheduler::IoScheduler>,
    coordinator: &Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    controller_id: u8,
    namespace_id: u32,
    num_cores: u32,
) -> Result<Vec<Arc<NvmePollHandler>>, &'static str> {
    let available = with_driver(|driver| driver.io_queue_count()).unwrap_or(0);
    if available == 0 {
        return Err("NVMe driver not initialized or no I/O queues");
    }
    let handler_count = num_cores.min(available as u32);

    let mut handlers = Vec::new();
    let device_id = IoDeviceId::Nvme {
        controller: controller_id,
        namespace: namespace_id,
    };

    // デフォルトのモード閾値でデバイスを登録
    scheduler.register_device(device_id, ModeThresholds::default());

    // DeviceOpsを登録（依存逆転）
    let nvme_ops = Arc::new(NvmeOps::new(controller_id, namespace_id));
    scheduler.register_device_ops(device_id, nvme_ops);

    for core_id in 0..handler_count {
        let handler = Arc::new(NvmePollHandler::new(core_id, namespace_id));
        coordinator.polling_executor().register_handler(
            device_id,
            Box::new(NvmePollHandlerWrapper {
                inner: handler.clone(),
            }),
        );
        handlers.push(handler);
    }

    NVME_POLL_HANDLERS
        .write()
        .insert((controller_id, namespace_id), handlers.clone());

    Ok(handlers)
}

/// NVMeドライバをIoSchedulerに登録（後方互換wrapper）
///
/// 内部でglobal singletonを使用。新規コードは `register_with()` を推奨。
pub fn register_with_io_scheduler(
    controller_id: u8,
    namespace_id: u32,
    num_cores: u32,
) -> Result<Vec<Arc<NvmePollHandler>>, &'static str> {
    use crate::io::io_scheduler::{hybrid_coordinator, io_scheduler};

    register_with(
        &io_scheduler(),
        &hybrid_coordinator(),
        controller_id,
        namespace_id,
        num_cores,
    )
}

pub(crate) fn submit_request(request: &IoRequest) -> Result<(), IoError> {
    let (controller_id, namespace_id) = match request.device {
        IoDeviceId::Nvme {
            controller,
            namespace,
        } => (controller, namespace),
        _ => return Err(IoError::InvalidParameter),
    };

    let core_id = crate::smp::current_cpu();
    let handler = handler_for_device(controller_id, namespace_id, core_id)
        .ok_or(IoError::NoResources)?;

    let (cid, bytes) = match (request.operation, &request.payload) {
        (IoOperationType::Read, IoPayload::NvmeRw(payload)) => {
            if payload.blocks == 0 {
                return Err(IoError::InvalidParameter);
            }
            let cid = with_driver(|driver| unsafe {
                driver.submit_read(
                    core_id,
                    namespace_id,
                    payload.lba,
                    payload.blocks,
                    payload.prp1,
                    payload.prp2,
                )
            })
            .ok_or(IoError::NoResources)?
            .map_err(map_nvme_error)?;
            (cid, payload.bytes)
        }
        (IoOperationType::Read, IoPayload::NvmeSgl(payload)) => {
            if payload.blocks == 0 {
                return Err(IoError::InvalidParameter);
            }
            let sgl = match payload.sgl.type_specific >> 4 {
                0x00 => SglDescriptor::data_block(payload.sgl.addr, payload.sgl.length),
                0x03 => SglDescriptor::last_segment(payload.sgl.addr, payload.sgl.length),
                _ => return Err(IoError::InvalidParameter),
            };
            let cid = with_driver(|driver| unsafe {
                driver.submit_read_sgl(
                    core_id,
                    namespace_id,
                    payload.lba,
                    payload.blocks,
                    sgl,
                )
            })
            .ok_or(IoError::NoResources)?
            .map_err(map_nvme_error)?;
            (cid, payload.bytes)
        }
        (IoOperationType::Write, IoPayload::NvmeRw(payload)) => {
            if payload.blocks == 0 {
                return Err(IoError::InvalidParameter);
            }
            let cid = with_driver(|driver| unsafe {
                driver.submit_write(
                    core_id,
                    namespace_id,
                    payload.lba,
                    payload.blocks,
                    payload.prp1,
                    payload.prp2,
                )
            })
            .ok_or(IoError::NoResources)?
            .map_err(map_nvme_error)?;
            (cid, payload.bytes)
        }
        (IoOperationType::Write, IoPayload::NvmeSgl(payload)) => {
            if payload.blocks == 0 {
                return Err(IoError::InvalidParameter);
            }
            let sgl = match payload.sgl.type_specific >> 4 {
                0x00 => SglDescriptor::data_block(payload.sgl.addr, payload.sgl.length),
                0x03 => SglDescriptor::last_segment(payload.sgl.addr, payload.sgl.length),
                _ => return Err(IoError::InvalidParameter),
            };
            let cid = with_driver(|driver| unsafe {
                driver.submit_write_sgl(
                    core_id,
                    namespace_id,
                    payload.lba,
                    payload.blocks,
                    sgl,
                )
            })
            .ok_or(IoError::NoResources)?
            .map_err(map_nvme_error)?;
            (cid, payload.bytes)
        }
        (IoOperationType::Flush, _) => {
            let cid = with_driver(|driver| unsafe { driver.submit_flush(core_id, namespace_id) })
                .ok_or(IoError::NoResources)?
                .map_err(map_nvme_error)?;
            (cid, 0)
        }
        (IoOperationType::Custom(_), IoPayload::NvmeDsm(payload)) => {
            let cid = with_driver(|driver| unsafe {
                driver.submit_dataset_management(core_id, namespace_id, payload.nr, payload.prp1)
            })
            .ok_or(IoError::NoResources)?
            .map_err(map_nvme_error)?;
            (cid, 0)
        }
        _ => return Err(IoError::NotSupported),
    };

    handler.register_request(request.id, cid, bytes);
    Ok(())
}

fn handler_for_device(
    controller_id: u8,
    namespace_id: u32,
    core_id: u32,
) -> Option<Arc<NvmePollHandler>> {
    let handlers = NVME_POLL_HANDLERS.read();
    handlers
        .get(&(controller_id, namespace_id))
        .and_then(|list| list.get(core_id as usize))
        .cloned()
}

fn map_nvme_error(err: &'static str) -> IoError {
    match err {
        "Queue full" => IoError::Busy,
        "Queue not found" | "Queue not initialized" => IoError::NoResources,
        _ => IoError::DeviceError,
    }
}
