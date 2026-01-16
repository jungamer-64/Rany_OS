//! AHCI IoScheduler 統合
//!
//! PollHandler 実装と IoScheduler への登録

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::io::io_scheduler::{
    DeviceId, DeviceOps, IoCommand, IoError, IoRequest, IoRequestId, IoResult, PollHandler,
    hybrid_coordinator, io_scheduler,
};

use super::controller::AhciController;
use super::types::{PX_CI, PX_TFD, PortNumber, SlotNumber};

/// AHCI PollHandler 実装
pub struct AhciPollHandler {
    /// コントローラへの参照
    controller: Arc<Mutex<AhciController>>,
    /// 保留中リクエスト (IoRequestId -> (PortNumber, SlotNumber))
    pending: Mutex<BTreeMap<IoRequestId, (PortNumber, SlotNumber)>>,
    /// 次のリクエストID
    next_request_id: AtomicU64,
}

impl AhciPollHandler {
    /// 新しい AhciPollHandler を作成
    pub fn new(controller: Arc<Mutex<AhciController>>) -> Self {
        Self {
            controller,
            pending: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// 新しいリクエストIDを生成
    pub fn next_request_id(&self) -> IoRequestId {
        IoRequestId(self.next_request_id.fetch_add(1, Ordering::SeqCst))
    }

    /// リクエストを追加
    pub fn add_pending(&self, id: IoRequestId, port: PortNumber, slot: SlotNumber) {
        self.pending.lock().insert(id, (port, slot));
    }

    /// コマンド完了をチェック
    fn check_completion(&self, port: PortNumber, slot: SlotNumber) -> Option<bool> {
        let controller = self.controller.lock();
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
            let pending = self.pending.lock();
            for (&request_id, &(port, slot)) in pending.iter() {
                if let Some(success) = self.check_completion(port, slot) {
                    let result = if success {
                        IoResult::Success(512) // 1セクタを仮定
                    } else {
                        IoResult::Error(IoError::DeviceError)
                    };
                    results.push((request_id, result));
                    completed.push(request_id);
                }
            }
        }

        // 完了したリクエストを削除
        let mut pending = self.pending.lock();
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
    controller: Arc<Mutex<AhciController>>,
    port: u8,
}

impl AhciOps {
    pub fn new(controller: Arc<Mutex<AhciController>>, port: u8) -> Self {
        Self { controller, port }
    }
}

impl DeviceOps for AhciOps {
    fn submit(&self, req: &IoRequest) -> Result<(), IoError> {
        // IoCommand 対応
        if let Some(cmd) = &req.command {
            return match cmd {
                IoCommand::BlockRead { lba, blocks, bytes, buf } => {
                    // TODO: FIS構築 + コマンド発行
                    Err(IoError::NotSupported) // 暫定
                }
                IoCommand::BlockWrite { .. } => Err(IoError::NotSupported),
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
// Registration (Dependency Injection)
// ============================================================================

/// AHCI を IoScheduler に登録（依存注入版）
pub fn register_ahci_with(
    scheduler: &Arc<crate::io::io_scheduler::IoScheduler>,
    coordinator: &Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    controller: Arc<Mutex<AhciController>>,
    port_number: u8,
) {
    let device_id = DeviceId::Ahci { port: port_number };

    // DeviceOps を登録
    let ahci_ops = Arc::new(AhciOps::new(controller.clone(), port_number));
    scheduler.register_device_ops(device_id, ahci_ops);

    // PollHandler を登録
    let handler = AhciPollHandler::new(controller);
    let handler: Box<dyn PollHandler + Send + Sync> = Box::new(handler);
    coordinator.polling_executor().register_handler(device_id, handler);
}

/// AHCI を IoScheduler に登録（後方互換wrapper）
pub fn register_ahci_with_io_scheduler(controller: Arc<Mutex<AhciController>>, port_number: u8) {
    register_ahci_with(
        &io_scheduler(),
        &hybrid_coordinator(),
        controller,
        port_number,
    );
}
