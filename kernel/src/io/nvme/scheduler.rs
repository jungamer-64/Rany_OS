// ============================================================================
// src/io/nvme/scheduler.rs - NVMe IoScheduler Integration
// ============================================================================
//!
//! # NVMe IoScheduler統合
//!
//! NVMeドライバをIoSchedulerと連携させるアダプタ層。
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DeviceOps, DmaBufHandle, IoCommand, IoError, IoRequest, IoRequestId,
    IoResult, ModeThresholds, PollAffinity, PollHandler,
};

use super::global;

fn queue_index_for_cpu(
    online: &crate::cpu::CpuSet,
    cpu_id: crate::cpu::CpuId,
    queue_count: usize,
) -> Option<usize> {
    if queue_count == 0 {
        return None;
    }
    online
        .iter()
        .position(|member| member == cpu_id)
        .map(|member_index| member_index % queue_count)
}

fn poll_cpu_for_queue(
    online: &crate::cpu::CpuSet,
    queue_id: u32,
) -> Option<crate::cpu::CpuId> {
    if online.is_empty() {
        return None;
    }
    online.member_at(queue_id as usize % online.len())
}

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
    namespace_id: u32,
    handlers: Arc<Vec<Arc<NvmePollHandler>>>,
}

impl NvmeOps {
    pub fn new(
        driver: Box<dyn NvmeDriverOps>,
        namespace_id: u32,
        handlers: Arc<Vec<Arc<NvmePollHandler>>>,
    ) -> Self {
        Self {
            driver,
            namespace_id,
            handlers,
        }
    }
}

impl DeviceOps for NvmeOps {
    fn submit(&self, req: &IoRequest, cpu_id: crate::cpu::CpuId) -> Result<(), IoError> {
        // Use new IoCommand API only
        if let Some(cmd) = &req.command {
            return self.submit_command(cmd, req.id, cpu_id);
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
        cpu_id: crate::cpu::CpuId,
    ) -> Result<(), IoError> {
        let online = crate::cpu::snapshot();
        let queue_index = queue_index_for_cpu(online.online(), cpu_id, self.handlers.len())
            .ok_or(IoError::NoResources)?;

        // Hardware queue identity is independent from sparse logical CPU ID.
        let handler = self
            .handlers
            .get(queue_index)
            .cloned()
            .ok_or(IoError::NoResources)?;

        // submit と poll_completions で同じ queue を使用
        let submit_qid = handler.queue_id;

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
    /// NVMe hardware I/O queue ID.
    queue_id: u32,
    /// 保留中のNVMeコマンドID → I/Oリクエスト
    /// Vec を使用して O(1) アクセス（CID は通常 0-1023 の範囲）
    pending: PoisonLock<Vec<Option<PendingNvmeRequest>>>,
}

/// NVMe キューの最大コマンドID数（2^10 = 1024）
const NVME_MAX_CID: usize = 1024;

impl NvmePollHandler {
    /// 新しいPollHandlerを作成
    pub fn new(queue_id: u32) -> Self {
        let mut pending = Vec::with_capacity(NVME_MAX_CID);
        pending.resize_with(NVME_MAX_CID, || None);
        Self {
            queue_id,
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
            if let Some(queue) = driver.get_queue(self.queue_id) {
                let pending_requests = queue.get_pending_requests();
                // SAFETY: poll は内部で適切に同期されている
                unsafe {
                    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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

    fn affinity(&self) -> PollAffinity {
        let snapshot = crate::cpu::snapshot();
        poll_cpu_for_queue(snapshot.online(), self.inner.queue_id)
            .map_or(PollAffinity::Unavailable, PollAffinity::Cpu)
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
    online: &crate::cpu::CpuSet,
) -> Result<Vec<Arc<NvmePollHandler>>, &'static str> {
    // 1. 利用可能なキュー数を確認
    let available = global::with_driver(|driver| driver.io_queue_count()).unwrap_or(0);
    if available == 0 {
        return Err("NVMe driver not initialized or no I/O queues");
    }
    let handler_count = online.len().min(usize::from(available));
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
    for queue_index in 0..handler_count {
        let queue_id = u32::try_from(queue_index).map_err(|_| "NVMe queue ID out of range")?;
        let handler = Arc::new(NvmePollHandler::new(queue_id));
        handlers.push(handler);
    }
    let handlers_arc = Arc::new(handlers.clone());

    // DeviceOps 登録
    scheduler.register_device(device_id, ModeThresholds::default());

    let driver = Box::new(GlobalDriverAdapter);
    let ops = Arc::new(NvmeOps::new(driver, namespace_id, handlers_arc));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(value: usize) -> crate::cpu::CpuId {
        crate::cpu::CpuId::try_from(value).unwrap()
    }

    #[test]
    fn sparse_cpu_members_select_hardware_queues_by_member_index() {
        let online = crate::cpu::CpuSet::from_ids(3, [cpu(0), cpu(2)]).unwrap();

        assert_eq!(queue_index_for_cpu(&online, cpu(0), 2), Some(0));
        assert_eq!(queue_index_for_cpu(&online, cpu(2), 2), Some(1));
        assert_eq!(queue_index_for_cpu(&online, cpu(1), 2), None);
        assert_eq!(queue_index_for_cpu(&online, cpu(2), 0), None);
        assert_eq!(poll_cpu_for_queue(&online, 0), Some(cpu(0)));
        assert_eq!(poll_cpu_for_queue(&online, 1), Some(cpu(2)));
        assert_eq!(poll_cpu_for_queue(&online, 2), Some(cpu(0)));
    }
}
