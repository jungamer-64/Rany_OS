// ============================================================================
// src/io/nvme/driver.rs - NVMe Driver Re-exports
// ============================================================================
//!
//! # NVMeドライバ再エクスポート
//!
//! driver.rsは分割されました。このファイルは後方互換性のための
//! 再エクスポートを提供します。
//!
//! ## 分割されたモジュール
//! - `queue`: SQ/CQ/QueuePairの低レベル実装
//! - `per_core`: コアごとのキュー管理
//! - `polling_driver`: メインポーリングドライバ
//! - `async_io`: 非同期I/Oサポート
//! - `error`: エラー型
//! - `global`: グローバルインスタンス
//! - `scheduler`: IoScheduler統合

#![allow(dead_code)]
#![allow(unused_imports)]

// ============================================================================
// Re-exports from queue.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::queue::CompletionQueue`,
// `nvme_driver::queue::QueuePair`, and `nvme_driver::queue::SubmissionQueue` directly.

// ============================================================================
// Re-exports from per_core.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::per_core::NvmeQueueStats` and
// `nvme_driver::per_core::PerCoreNvmeQueue` directly.

// ============================================================================
// Re-exports from polling_driver.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::polling_driver::NvmeDriverStats` and
// `nvme_driver::polling_driver::NvmePollingDriver` directly.

// ============================================================================
// Re-exports from async_io.rs
// ============================================================================
// Removed: compatibility re-export. Import async I/O types/functions directly from
// `nvme_driver::async_io` (e.g., `nvme_driver::async_io::AsyncIoRequest`).

// ============================================================================
// Re-exports from error.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::error::NvmeError` directly.

// ============================================================================
// Re-exports from global.rs
// ============================================================================
// Removed: compatibility re-export. Import global helpers from `nvme_driver::global` directly (e.g., `nvme_driver::global::init`).

// ============================================================================
// Re-exports from scheduler.rs
// ============================================================================
// Removed: compatibility re-export. Import `nvme_driver::scheduler::register_with_io_scheduler` or
// `nvme_driver::scheduler::NvmePollHandler` directly.

// ============================================================================
// Re-exports from commands.rs (for backward compatibility)
// ============================================================================
// Removed: compatibility re-export. Use `nvme_driver::commands::{NvmeCommand, NvmeCompletion}` directly.

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::commands::{NvmeCommand, NvmeCompletion};
    use super::async_io::{AsyncIoRequest, IoRequestState, PendingRequests};
    use super::super::controller::NvmeCapabilities;
    use super::super::defs::PrpList;

    #[test]
    fn test_nvme_command_read() {
        let cmd = NvmeCommand::read(1, 0, 8, 0x1000, 0);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 0);
        assert_eq!(cmd.cdw12, 7); // 8-1
    }

    #[test]
    fn test_nvme_command_write() {
        let cmd = NvmeCommand::write(1, 100, 16, 0x2000, 0);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 100);
        assert_eq!(cmd.cdw12, 15); // 16-1
    }

    #[test]
    fn test_nvme_command_create_cq() {
        let cmd = NvmeCommand::create_io_cq(1, 256, 0x10000, 0, false);
        assert_eq!(cmd.cdw10, (1 << 16) | 255);
        assert_eq!(cmd.cdw11, 0x01); // PC=1, IEN=0
    }

    #[test]
    fn test_nvme_command_create_sq() {
        let cmd = NvmeCommand::create_io_sq(1, 256, 0x20000, 1, 0);
        assert_eq!(cmd.cdw10, (1 << 16) | 255);
        assert_eq!(cmd.cdw11, (1 << 16) | 0x01); // CQID=1, PC=1
    }

    #[test]
    fn test_nvme_completion_status() {
        let mut cqe = NvmeCompletion::default();
        cqe.status = 0x0001; // Phase bit set, success
        assert!(cqe.phase());
        assert!(cqe.is_success());
    }

    #[test]
    fn test_nvme_completion_error() {
        let mut cqe = NvmeCompletion::default();
        cqe.status = 0x0103; // SC=1, SCT=0, Phase=1
        assert!(cqe.phase());
        assert!(!cqe.is_success());
        assert_eq!(cqe.status_code(), 1);
    }

    #[test]
    fn test_io_request_state() {
        let req = AsyncIoRequest::new(42, 1);
        assert_eq!(req.state, IoRequestState::Pending);
        assert!(!req.is_complete());
    }

    #[test]
    fn test_capabilities() {
        let cap = NvmeCapabilities::new(0x00FF_2003_0020_FFFF);
        assert_eq!(cap.mqes(), 0xFFFF);
        assert_eq!(cap.dstrd(), 2);
        assert_eq!(cap.doorbell_stride_bytes(), 16);
        assert_eq!(cap.max_queue_depth(), 0x10000);
    }

    #[test]
    fn test_prp_list() {
        let mut prp_list = PrpList::new();
        assert!(prp_list.is_empty());

        assert!(prp_list.add_entry(0x1000).is_ok());
        assert!(prp_list.add_entry(0x2000).is_ok());
        assert_eq!(prp_list.len(), 2);

        // Non-aligned address should fail
        assert!(prp_list.add_entry(0x1001).is_err());
    }

    #[test]
    fn test_pending_requests() {
        let mut pending = PendingRequests::new();

        assert!(pending.register(0, 1).is_ok());
        assert_eq!(pending.active_count(), 1);

        // Complete the request
        let cqe = NvmeCompletion {
            cid: 0,
            status: 0x0001, // success with phase
            ..Default::default()
        };
        assert!(pending.complete(0, cqe));

        // Take the completed request
        let req = pending.take(0);
        assert!(req.is_some());
        assert!(req.unwrap().is_complete());
        assert_eq!(pending.active_count(), 0);
    }
}
