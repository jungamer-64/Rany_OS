// ============================================================================
// src/io/nvme/driver.rs - NVMe Driver Re-exports (Minimal)
// ============================================================================
//!
//! # NVMeドライバ後方互換レイヤー
//!
//! このモジュールはテスト互換性のための最小限の再エクスポートを提供します。
//! 新しいコードは `nvme_driver` クレートまたは `crate::io::nvme` を直接使用してください。

#![allow(dead_code)]
#![allow(unused_imports)]

// Re-export from nvme_driver crate directly
pub use nvme_driver::queue::{CompletionQueue, QueuePair, SubmissionQueue};
pub use nvme_driver::per_core::{NvmeQueueStats, PerCoreNvmeQueue};
pub use nvme_driver::polling_driver::{NvmeDriverStats, NvmePollingDriver};
pub use nvme_driver::async_io::{ReadFuture, WriteFuture};
pub use nvme_driver::{AsyncIoRequest, IoRequestState, PendingRequests};
pub use nvme_driver::error::NvmeError;
pub use nvme_driver::global::{get_stats, init, poll, with_driver, with_driver_mut};

// Scheduler (kernel-local)
pub use super::scheduler::{NvmePollHandler, register_with_io_scheduler};

#[cfg(test)]
mod tests {
    use nvme_driver::controller::NvmeCapabilities;
    use nvme_driver::defs::PrpList;
    use nvme_driver::commands::{NvmeCommand, NvmeCompletion};
    use super::*;

    #[test_case]
    fn test_nvme_command_read() {
        let cmd = NvmeCommand::read(0, 1, 0, 8, 0, 0);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 0);
        assert_eq!(cmd.cdw12, 7);
    }

    #[test_case]
    fn test_nvme_command_write() {
        let cmd = NvmeCommand::write(0, 1, 100, 16, 0, 0);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 100);
        assert_eq!(cmd.cdw12, 15);
    }

    #[test_case]
    fn test_capabilities() {
        let cap = NvmeCapabilities::new(0x00FF_2003_0020_FFFF);
        assert_eq!(cap.mqes(), 0xFFFF);
        assert_eq!(cap.dstrd(), 2);
        assert_eq!(cap.doorbell_stride_bytes(), 16);
        assert_eq!(cap.max_queue_depth(), 0x10000);
    }

    #[test_case]
    fn test_prp_list() {
        let mut prp_list = PrpList::new();
        assert!(prp_list.is_empty());
        assert!(prp_list.add_entry(0x1000).is_ok());
        assert!(prp_list.add_entry(0x2000).is_ok());
        assert_eq!(prp_list.len(), 2);
        assert!(prp_list.add_entry(0x1001).is_err());
    }
}
