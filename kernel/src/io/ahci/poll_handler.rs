//! AHCI IoScheduler 統合
//!
//! PollHandler 実装と IoScheduler への登録

extern crate alloc;

use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::io::io_scheduler::{
    DeviceId, DeviceOps, DmaBufHandle, IoCommand, IoError, IoRequest, IoRequestId, IoResult,
    PollHandler, hybrid_coordinator, io_scheduler,
};

use super::controller::AhciController;
use super::types::{Lba, PX_CI, PX_TFD, PortNumber, SectorCount, SlotNumber};

/// AHCI PollHandler 実装
pub struct AhciPollHandler {
    /// コントローラへの参照
    controller: Arc<PoisonLock<AhciController>>,
    /// 保留中リクエスト (IoRequestId -> (PortNumber, SlotNumber))
    pending: PoisonLock<BTreeMap<IoRequestId, (PortNumber, SlotNumber)>>,
    /// 次のリクエストID
    next_request_id: AtomicU64,
}

impl AhciPollHandler {
    /// 新しい AhciPollHandler を作成
    pub fn new(controller: Arc<PoisonLock<AhciController>>) -> Self {
        Self {
            controller,
            pending: PoisonLock::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// 新しいリクエストIDを生成
    pub fn next_request_id(&self) -> IoRequestId {
        IoRequestId(self.next_request_id.fetch_add(1, Ordering::SeqCst))
    }

    /// リクエストを追加
    pub fn add_pending(&self, id: IoRequestId, port: PortNumber, slot: SlotNumber) {
        match self.pending.lock() {
            Ok(mut pending) => {
                pending.insert(id, (port, slot));
            }
            Err(poisoned) => {
                log::warn!("[AHCI] pending queue lock poisoned; recovering");
                let mut pending = poisoned.into_inner();
                pending.insert(id, (port, slot));
            }
        }
    }

    /// コマンド完了をチェック
    fn check_completion(&self, port: PortNumber, slot: SlotNumber) -> Option<bool> {
        let controller = self.controller.lock().unwrap_or_else(|e| e.into_inner());
        let ci = controller.read_port_reg(port, PX_CI);

        // スロットのコマンドが完了していれば CI ビットがクリアされる
        if (ci & (1 << slot.as_u8())) == 0 {
            // TFD でエラーチェック
            let tfd = controller.read_port_reg(port, PX_TFD);
            let error = (tfd & 0x01) != 0; // ERR ビット
            Some(!error)
        } else {
            None
        }
    }
}

impl PollHandler for AhciPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();
        let mut completed = Vec::new();

        {
            let pending = match self.pending.lock() {
                Ok(pending) => pending,
                Err(poisoned) => {
                    log::warn!("[AHCI] pending queue lock poisoned during poll; recovering");
                    poisoned.into_inner()
                }
            };
            for (&request_id, &(port, slot)) in pending.iter() {
                if let Some(success) = self.check_completion(port, slot) {
                    // On completion, call port.finish_transfer to clean up and get transferred bytes
                    let finish_res = {
                        let controller = self.controller.lock().unwrap_or_else(|e| e.into_inner());
                        controller.with_port(port, |port| port.finish_transfer(slot))
                    };

                    let result = if success {
                        match finish_res {
                            Some(Ok(bytes)) => IoResult::Success(bytes),
                            _ => IoResult::Error(IoError::DeviceError),
                        }
                    } else {
                        IoResult::Error(IoError::DeviceError)
                    };

                    results.push((request_id, result));
                    completed.push(request_id);
                }
            }
        }

        // 完了したリクエストを削除
        let mut pending = match self.pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => {
                log::warn!("[AHCI] pending queue lock poisoned during cleanup; recovering");
                poisoned.into_inner()
            }
        };
        for id in completed {
            pending.remove(&id);
        }

        results
    }

    fn is_ready(&self) -> bool {
        // コントローラがロックできれば準備完了
        true
    }
}

// ============================================================================
// AHCI DeviceOps Implementation
// ============================================================================

/// AHCIデバイス操作実装
pub struct AhciOps {
    controller: Arc<PoisonLock<AhciController>>,
    port: u8,
    handler: Option<Arc<AhciPollHandler>>,
}

impl AhciOps {
    pub fn new(
        controller: Arc<PoisonLock<AhciController>>,
        port: u8,
        handler: Option<Arc<AhciPollHandler>>,
    ) -> Self {
        Self {
            controller,
            port,
            handler,
        }
    }

    /// Submit a block read or write DMA command
    fn submit_block_io(
        &self,
        req_id: IoRequestId,
        lba: u64,
        blocks: u16,
        bytes: usize,
        buf: &DmaBufHandle,
        is_read: bool,
    ) -> Result<(), IoError> {
        if blocks == 0 || bytes > buf.len {
            return Err(IoError::InvalidParameter);
        }

        let port_num = PortNumber(self.port);

        let slot_opt = {
            let controller = self.controller.lock().unwrap_or_else(|e| e.into_inner());
            let res_opt = controller.with_port(port_num, |port| {
                if is_read {
                    port.start_read_dma(Lba(lba), SectorCount(blocks), buf.iova, bytes as u32)
                } else {
                    port.start_write_dma(Lba(lba), SectorCount(blocks), buf.iova, bytes as u32)
                }
            });
            match res_opt {
                Some(Ok(slot)) => Some(slot),
                _ => None,
            }
        };

        match slot_opt {
            Some(slot) => self.register_pending(req_id, slot),
            None => Err(IoError::NoResources),
        }
    }

    /// Register a pending I/O with the poll handler
    fn register_pending(&self, req_id: IoRequestId, slot: SlotNumber) -> Result<(), IoError> {
        if let Some(handler) = &self.handler {
            handler.add_pending(req_id, PortNumber(self.port), slot);
            Ok(())
        } else if let Some(h) = AHCI_POLL_HANDLERS.read().unwrap_or_else(|e| e.into_inner()).get(&self.port).cloned() {
            h.add_pending(req_id, PortNumber(self.port), slot);
            Ok(())
        } else {
            Err(IoError::NoResources)
        }
    }
}

impl DeviceOps for AhciOps {
    fn submit(&self, req: &IoRequest, _cpu_idx: usize) -> Result<(), IoError> {
        // IoCommand 対応
        if let Some(cmd) = &req.command {
            return match cmd {
                IoCommand::BlockRead {
                    lba,
                    blocks,
                    bytes,
                    buf,
                } => self.submit_block_io(req.id, *lba, *blocks, *bytes, buf, true),
                IoCommand::BlockWrite {
                    lba,
                    blocks,
                    bytes,
                    buf,
                } => self.submit_block_io(req.id, *lba, *blocks, *bytes, buf, false),
                IoCommand::Flush => Err(IoError::NotSupported),
                _ => Err(IoError::NotSupported),
            };
        }
        // 旧形式: 未サポート
        Err(IoError::NotSupported)
    }

    fn is_ready(&self) -> bool {
        true
    }
}

// ============================================================================
// AHCI PollHandler Registry
// ============================================================================

/// Global registry for AHCI poll handlers (port -> handler)
static AHCI_POLL_HANDLERS: PoisonRwLock<BTreeMap<u8, Arc<AhciPollHandler>>> =
    PoisonRwLock::new(BTreeMap::new());

// Wrapper to allow registering an Arc<AhciPollHandler> as a PollHandler trait object
struct AhciPollHandlerWrapper {
    inner: Arc<AhciPollHandler>,
}

impl PollHandler for AhciPollHandlerWrapper {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        self.inner.poll_completions()
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}

// ============================================================================
// Registration (Dependency Injection)
// ============================================================================

/// AHCI を IoScheduler に登録（依存注入版）
pub fn register_ahci_with(
    scheduler: &Arc<crate::io::io_scheduler::IoScheduler>,
    coordinator: &Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    controller: Arc<PoisonLock<AhciController>>,
    port_number: u8,
) {
    let device_id = DeviceId::Ahci { port: port_number };

    // DeviceOps を登録
    // Create and register a shared poll handler so submit() can add pending requests
    let handler = Arc::new(AhciPollHandler::new(controller.clone()));
    coordinator.polling_executor().register_handler(
        device_id,
        Box::new(AhciPollHandlerWrapper {
            inner: handler.clone(),
        }),
    );

    // Store in global registry for lookup
    AHCI_POLL_HANDLERS
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(port_number, handler.clone());

    let ahci_ops = Arc::new(AhciOps::new(controller.clone(), port_number, Some(handler)));
    scheduler.register_device_ops(device_id, ahci_ops);
}

/// AHCI を IoScheduler に登録（後方互換wrapper）
pub fn register_ahci_with_io_scheduler(controller: Arc<PoisonLock<AhciController>>, port_number: u8) {
    register_ahci_with(
        &io_scheduler(),
        &hybrid_coordinator(),
        controller,
        port_number,
    );
}
