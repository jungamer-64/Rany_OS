// ============================================================================
// src/io/nvme/scheduler.rs - NVMe IoScheduler Integration
// ============================================================================
//!
//! # NVMe IoScheduler統合
//!
//! NVMeドライバをIoSchedulerと連携させるアダプタ層。

#![allow(dead_code)]

use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DeviceOps, DmaBufHandle, IoCommand, IoError, IoRequest, IoRequestId,
    IoResult, ModeThresholds, PollHandler,
};

use super::global;

// ============================================================================
// NVMe Device Operations (DeviceOps Implementation)
// ============================================================================

/// NVMeデバイス操作実装
///
/// DeviceOpsを実装し、IoSchedulerからの依存逆転を提供する。
/// IoSchedulerはNVMe固有コードを知らずに、このtrait経由でのみ対話する。

/// NVMe ドライバ操作抽象化（依存注入用）
pub trait NvmeDriverOps: Send + Sync {
    unsafe fn submit_read(
        &self,
        qid: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Option<u16>;
    unsafe fn submit_write(
        &self,
        qid: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Option<u16>;
    unsafe fn submit_flush(&self, qid: u32, nsid: u32) -> Option<u16>;
    unsafe fn submit_dsm(&self, qid: u32, nsid: u32, prp1: u64, prp2: u64) -> Option<u16>;
    fn is_active(&self) -> bool;
}

/// グローバルドライバへのアダプタ
struct GlobalDriverAdapter;

impl NvmeDriverOps for GlobalDriverAdapter {
    unsafe fn submit_read(
        &self,
        qid: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Option<u16> {
        global::with_driver(|d| unsafe { d.submit_read(qid, nsid, lba, blocks, prp1, prp2).ok() })
            .flatten()
    }

    unsafe fn submit_write(
        &self,
        qid: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Option<u16> {
        global::with_driver(|d| unsafe { d.submit_write(qid, nsid, lba, blocks, prp1, prp2).ok() })
            .flatten()
    }

    unsafe fn submit_flush(&self, qid: u32, nsid: u32) -> Option<u16> {
        global::with_driver(|d| unsafe { d.submit_flush(qid, nsid).ok() }).flatten()
    }

    unsafe fn submit_dsm(&self, qid: u32, nsid: u32, prp1: u64, prp2: u64) -> Option<u16> {
        global::with_driver(|d| unsafe { d.submit_dsm(qid, nsid, prp1, prp2).ok() }).flatten()
    }

    fn is_active(&self) -> bool {
        global::with_driver(|d| d.is_active()).unwrap_or(false)
    }
}

/// NVMe 操作実装
pub struct NvmeOps {
    driver: Box<dyn NvmeDriverOps>,
    controller_id: u8,
    namespace_id: u32,
    handlers: Arc<Vec<Arc<NvmePollHandler>>>,
}

impl NvmeOps {
    pub fn new(
        driver: Box<dyn NvmeDriverOps>,
        controller_id: u8,
        namespace_id: u32,
        handlers: Arc<Vec<Arc<NvmePollHandler>>>,
    ) -> Self {
        Self {
            driver,
            controller_id,
            namespace_id,
            handlers,
        }
    }
}

impl DeviceOps for NvmeOps {
    fn submit(&self, req: &IoRequest, cpu_idx: usize) -> Result<(), IoError> {
        // Use new IoCommand API only
        if let Some(cmd) = &req.command {
            return self.submit_command(cmd, req.id, cpu_idx);
        }
        // Legacy payload support removed: require IoCommand
        Err(IoError::NotSupported)
    }

    fn is_ready(&self) -> bool {
        self.driver.is_active()
    }
}

impl NvmeOps {
    /// IoCommand を NVMe 固有形式に変換して submit
    fn submit_command(
        &self,
        cmd: &IoCommand,
        id: IoRequestId,
        cpu_idx: usize,
    ) -> Result<(), IoError> {
        let core_id = cpu_idx as u32;

        // 1. 指定されたCPUに関連付けられたハンドラを取得
        let handler = self
            .handlers
            .iter()
            .find(|h| h.core_id == core_id)
            .cloned()
            .or_else(|| {
                // フォールバック
                let idx = (core_id as usize) % self.handlers.len().max(1);
                self.handlers.get(idx).cloned()
            })
            .ok_or(IoError::NoResources)?;

        // submit と poll_completions で同じ queue を使用
        let submit_qid = handler.core_id;

        let (cid, bytes) = match cmd {
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
                let (prp1, prp2) = Self::validate_and_get_prps(buf)?;
                let is_read = matches!(cmd, IoCommand::BlockRead { .. });
                let cid = if is_read {
                    unsafe {
                        self.driver.submit_read(
                            submit_qid,
                            self.namespace_id,
                            *lba,
                            *blocks,
                            prp1,
                            prp2,
                        )
                    }
                } else {
                    unsafe {
                        self.driver.submit_write(
                            submit_qid,
                            self.namespace_id,
                            *lba,
                            *blocks,
                            prp1,
                            prp2,
                        )
                    }
                }
                .ok_or(IoError::NoResources)?;
                (cid, *bytes)
            }
            IoCommand::Flush => {
                let cid = unsafe { self.driver.submit_flush(submit_qid, self.namespace_id) }
                    .ok_or(IoError::NoResources)?;
                (cid, 0)
            }
            IoCommand::Discard { .. } => (0, 0),
            IoCommand::Ioctl { code, buf } => self.handle_ioctl_submit(submit_qid, *code, buf)?,
        };

        handler.register_request(id, cid, bytes);
        Ok(())
    }

    /// IoctlコマンドをNVMeに変換してsubmit
    fn handle_ioctl_submit(
        &self,
        qid: u32,
        code: u32,
        buf: &DmaBufHandle,
    ) -> Result<(u16, usize), IoError> {
        if code == 0x09 {
            let prp1 = buf.iova;
            let cid = unsafe { self.driver.submit_dsm(qid, self.namespace_id, prp1, 0) }
                .ok_or(IoError::NoResources)?;
            Ok((cid, 0))
        } else {
            Err(IoError::NotSupported)
        }
    }

    /// PRP バッファ検証と取得
    ///
    /// physically contiguous memory を想定し、1ページまたぎまで対応する。
    /// > 2ページは PRP List が必要なため未対応 (IoError::NotSupported)。
    fn validate_and_get_prps(buf: &DmaBufHandle) -> Result<(u64, u64), IoError> {
        const PAGE_SIZE: u64 = 4096;
        let page_mask = PAGE_SIZE - 1;

        if buf.len == 0 {
            return Err(IoError::InvalidParameter);
        }

        let start_page = buf.iova & !page_mask;
        let end_addr = buf.iova.saturating_add(buf.len as u64).saturating_sub(1);
        let end_page = end_addr & !page_mask;

        if start_page == end_page {
            // Fits in single page
            Ok((buf.iova, 0))
        } else if end_page == start_page + PAGE_SIZE {
            // Spans 2 pages. Since it's DmaBufHandle, we assume physical contiguity.
            // PRP2 is the start of the next page.
            let prp2 = start_page + PAGE_SIZE;
            Ok((buf.iova, prp2))
        } else {
            // Spans > 2 pages. Requires PRP List.
            log::warn!(
                "[NVMe] Buffer too large (> 2 pages) for inline PRP: {} bytes",
                buf.len
            );
            Err(IoError::NotSupported)
        }
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

static NVME_POLL_HANDLERS: PoisonRwLock<BTreeMap<NvmeHandlerKey, Vec<Arc<NvmePollHandler>>>> =
    PoisonRwLock::new(BTreeMap::new());

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
    pending: PoisonLock<Vec<Option<PendingNvmeRequest>>>,
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
            pending: PoisonLock::new(pending),
        }
    }

    /// I/OリクエストIDとNVMeコマンドIDを紐付け
    pub fn register_request(&self, io_id: IoRequestId, cid: u16, bytes: usize) {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
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

        global::with_driver(|driver| {
            if let Some(queue) = driver.get_queue(self.core_id) {
                let pending_requests = queue.get_pending_requests();
                // SAFETY: poll は内部で適切に同期されている
                unsafe {
                    while let Some(cqe) = queue.poll() {
                        let cid = cqe.cid;
                        let entry = self
                            .pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
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
        global::with_driver(|d| d.is_active()).unwrap_or(false)
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
// Registration Helper
// ============================================================================

/// NVMeデバイスをIoSchedulerに登録
///
/// ハンドラを作成し、IoSchedulerおよびIoCoordinatorに登録する。
pub fn register_with_io_scheduler(
    controller_id: u8,
    namespace_id: u32,
    num_cores: u32,
) -> Result<Vec<Arc<NvmePollHandler>>, &'static str> {
    // 1. 利用可能なキュー数を確認
    let available = global::with_driver(|driver| driver.io_queue_count()).unwrap_or(0);
    if available == 0 {
        return Err("NVMe driver not initialized or no I/O queues");
    }
    let handler_count = num_cores.min(available as u32);
    let mut handlers = Vec::new();

    // 2. Scheduler/Coordinator 取得
    let scheduler = crate::io::io_scheduler::io_scheduler();
    let coordinator = crate::io::io_scheduler::hybrid_coordinator();

    let device_id = IoDeviceId::Nvme {
        controller: controller_id,
        namespace: namespace_id,
    };

    // 3. DeviceOps生成 & 登録 (DI: driver adapter, handlers)
    // ハンドラ生成
    for core_id in 0..handler_count {
        let handler = Arc::new(NvmePollHandler::new(core_id, namespace_id));
        handlers.push(handler);
    }
    let handlers_arc = Arc::new(handlers.clone());

    // DeviceOps 登録
    scheduler.register_device(device_id, ModeThresholds::default());

    let driver = Box::new(GlobalDriverAdapter);
    let ops = Arc::new(NvmeOps::new(
        driver,
        controller_id,
        namespace_id,
        handlers_arc,
    ));
    scheduler.register_device_ops(device_id, ops);

    // 4. PollHandler登録
    for handler in handlers.iter() {
        coordinator.polling_executor().register_handler(
            device_id,
            Box::new(NvmePollHandlerWrapper {
                inner: handler.clone(),
            }),
        );
    }

    // 5. Global Registry 更新 (Fallback用)
    NVME_POLL_HANDLERS
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert((controller_id, namespace_id), handlers.clone());

    log::info!(
        "[NVMe] Registered device {:?} with IoScheduler ({} queues)",
        device_id,
        handler_count
    );

    Ok(handlers)
}

fn handler_for_device(
    controller_id: u8,
    namespace_id: u32,
    core_id: u32,
) -> Option<Arc<NvmePollHandler>> {
    let handlers = NVME_POLL_HANDLERS.read().unwrap_or_else(|e| e.into_inner());
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
