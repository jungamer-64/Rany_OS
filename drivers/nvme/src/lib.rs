// ============================================================================
// drivers/nvme/src/lib.rs - NVMe Driver
// ============================================================================
//!
//! # NVMe Driver
//!
//! NVMe仕様に基づく共通定義とドライバを提供。
//!
//! ## Core Modules (kernel-independent)
//! - `defs`: 共通定数・構造体定義
//! - `commands`: コマンド構造体
//! - `regs`: レジスタ定義
//! - `queue_types`: 型安全なキュー抽象化
//! - `identify`: Identify構造体
//! - `error`: エラー型
//!
//! ## Kernel-Dependent (excluded)
//! ## Kernel-Dependent (excluded)
//! - `polling_driver`
//! - `async_io`, `global`, `scheduler`, `driver`

#![no_std]
#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)] // Transitional: DMA and queue operations

extern crate alloc;

// Register Cell runtime stubs (allocator, panic handler) for standalone cdylib build
#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

// Core modules (no kernel deps)
pub mod commands;
pub mod defs;
pub mod error;
pub mod identify;
pub mod queue_types;
pub mod regs;

// Modules migrated from kernel
pub mod controller;
pub mod per_core;
pub mod queue;

// Modules migrated from kernel - now enabled
pub mod async_io;
pub mod driver_impl;
pub mod global;
pub mod polling_driver;
pub mod requests;
pub mod sync;

// pub mod scheduler; // Requires kernel io_scheduler - stays local to kernel
// pub mod driver; // Re-exports only - stays local to kernel

// Re-exports
pub use defs::{
    ADMIN_QUEUE_DEPTH, AdminOpcode, CACHE_LINE_SIZE, CONTROLLER_READY_TIMEOUT_MS, CQE_SIZE,
    DEFAULT_QUEUE_DEPTH, DOORBELL_BATCH_THRESHOLD, IoOpcode, MAX_QUEUE_DEPTH, MAX_TRANSFER_SIZE,
    NvmeError as DefsNvmeError, NvmeStatus, PAGE_SIZE, POLL_BATCH_SIZE, PrpEntry, PrpList,
    SECTOR_SIZE, SQE_SIZE, SglDescriptor, SglType,
};

pub use commands::{NvmeCommand, NvmeCompletion};

pub use regs::{
    CmbLocation, CmbSize, NvmeAdminQueueAttributes, NvmeCapabilities, NvmeControllerConfig,
    NvmeControllerStatus, cc_bits, csts_bits, offsets,
};

pub use identify::{
    IdentifyCns, IdentifyController, IdentifyNamespace, LbaFormat, PowerStateDescriptor,
    RelativePerformance,
};

pub use error::NvmeError;

// Async I/O exports
pub use async_io::{ReadFuture, WriteFuture};
pub use requests::{AsyncIoRequest, IoRequestState, PendingRequests};

// Global driver exports
pub use crate::global::{
    get_stats, init, poll as poll_global, poll_batch, with_driver, with_driver_mut,
};

// Polling driver exports
pub use polling_driver::{NvmeDriverStats, NvmePollingDriver};

#[cfg(test)]
mod qemu_tests {
    use crate::commands::{NvmeCommand, NvmeCompletion};
    use crate::controller::NvmeCapabilities;
    use crate::defs::{AdminOpcode, IoOpcode, PrpList};
    use crate::queue_types::{
        AdminCommandTrait, AdminQueue, IdentifyCommand, IoCommandTrait, IoQueue, QueueType,
        ReadCommand,
    };
    use crate::requests::{AsyncIoRequest, IoRequestState, PendingRequests};

    // ========================================================================
    // driver.rs tests (commands, completions, async_io, controller, defs)
    // ========================================================================

    pub fn command_read_smoke() -> bool {
        // NvmeCommand::read(cid, nsid, slba, nlb, prp1, prp2)
        // cdw12 = nlb (0-based), so pass 7 to get cdw12 == 7
        let cmd = NvmeCommand::read(1, 1, 0, 7, 0x1000, 0);
        cmd.nsid == 1 && cmd.cdw10 == 0 && cmd.cdw12 == 7
    }

    pub fn command_write_smoke() -> bool {
        // NvmeCommand::write(cid, nsid, slba, nlb, prp1, prp2)
        // cdw12 = nlb (0-based), so pass 15 to get cdw12 == 15
        let cmd = NvmeCommand::write(1, 1, 100, 15, 0x2000, 0);
        cmd.nsid == 1 && cmd.cdw10 == 100 && cmd.cdw12 == 15
    }

    pub fn command_create_cq_smoke() -> bool {
        // create_io_cq(cid, qid, queue_size, prp, irq_vector, irq_enabled)
        let cmd = NvmeCommand::create_io_cq(1, 1, 256, 0x10000, 0, false);
        cmd.cdw10 == ((1 << 16) | 255) && cmd.cdw11 == 0x01
    }

    pub fn command_create_sq_smoke() -> bool {
        // create_io_sq(cid, qid, queue_size, prp, cqid, priority)
        let cmd = NvmeCommand::create_io_sq(1, 1, 256, 0x20000, 1, 0);
        cmd.cdw10 == ((1 << 16) | 255) && cmd.cdw11 == ((1 << 16) | 0x01)
    }

    pub fn completion_status_smoke() -> bool {
        let mut cqe = NvmeCompletion::default();
        cqe.status = 0x0001; // Phase bit set, success
        cqe.phase() && cqe.is_success()
    }

    pub fn completion_error_smoke() -> bool {
        let mut cqe = NvmeCompletion::default();
        cqe.status = 0x0003; // Phase=1, SC=1
        cqe.phase() && !cqe.is_success() && cqe.sc() == 1
    }

    pub fn io_request_state_smoke() -> bool {
        let req = AsyncIoRequest::new(42, 1);
        req.state == IoRequestState::Pending && !req.is_complete()
    }

    pub fn capabilities_smoke() -> bool {
        // Value engineered so dstrd()=2 (bits 32-35 = 0x2)
        let cap = NvmeCapabilities::new(0x00FF_0002_0020_FFFF);
        if cap.mqes() != 0xFFFF {
            return false;
        }
        if cap.dstrd() != 2 {
            return false;
        }
        if cap.doorbell_stride_bytes() != 16 {
            return false;
        }
        cap.max_queue_depth() == 0x10000
    }

    pub fn prp_list_smoke() -> bool {
        let mut prp_list = PrpList::new();
        if !prp_list.is_empty() {
            return false;
        }
        if prp_list.add_entry(0x1000).is_err() {
            return false;
        }
        if prp_list.add_entry(0x2000).is_err() {
            return false;
        }
        if prp_list.len() != 2 {
            return false;
        }
        // Non-aligned address should fail
        prp_list.add_entry(0x1001).is_err()
    }

    pub fn pending_requests_smoke() -> bool {
        let mut pending = PendingRequests::new();

        if pending.register(0, 1).is_err() {
            return false;
        }
        if pending.active_count() != 1 {
            return false;
        }

        // Complete the request
        let cqe = NvmeCompletion {
            cid: 0,
            status: 0x0001, // success with phase
            ..Default::default()
        };
        if !pending.complete(0, cqe) {
            return false;
        }

        // Take the completed request
        let req = match pending.take(0) {
            Some(r) => r,
            None => return false,
        };
        if !req.is_complete() {
            return false;
        }
        pending.active_count() == 0
    }

    // ========================================================================
    // queue_types.rs tests
    // ========================================================================

    pub fn queue_type_traits_smoke() -> bool {
        AdminQueue::NAME == "Admin"
            && IoQueue::NAME == "I/O"
            && AdminQueue::MAX_DEPTH == 4096
            && IoQueue::MAX_DEPTH == 65535
    }

    pub fn identify_command_smoke() -> bool {
        let cmd = IdentifyCommand {
            cns: 1,
            prp1: 0x1000,
        };
        let nvme_cmd = cmd.to_nvme_command(42, 0);
        nvme_cmd.opcode() == AdminOpcode::Identify as u8
            && nvme_cmd.cid() == 42
            && nvme_cmd.cdw10 == 1
    }

    pub fn read_command_smoke() -> bool {
        let cmd = ReadCommand {
            slba: 0x12345678,
            nlb: 7,
            prp1: 0x2000,
            prp2: 0,
        };
        let nvme_cmd = cmd.to_nvme_command(100, 1);
        nvme_cmd.opcode() == IoOpcode::Read as u8 && nvme_cmd.nsid == 1
    }
}


#[cfg(test)]
mod qemu_smoke_tests {
    use super::qemu_tests;

    #[test]
    fn command_read_smoke() {
        assert!(qemu_tests::command_read_smoke());
    }

    #[test]
    fn command_write_smoke() {
        assert!(qemu_tests::command_write_smoke());
    }

    #[test]
    fn command_create_cq_smoke() {
        assert!(qemu_tests::command_create_cq_smoke());
    }

    #[test]
    fn command_create_sq_smoke() {
        assert!(qemu_tests::command_create_sq_smoke());
    }

    #[test]
    fn completion_status_smoke() {
        assert!(qemu_tests::completion_status_smoke());
    }

    #[test]
    fn completion_error_smoke() {
        assert!(qemu_tests::completion_error_smoke());
    }

    #[test]
    fn io_request_state_smoke() {
        assert!(qemu_tests::io_request_state_smoke());
    }

    #[test]
    fn capabilities_smoke() {
        assert!(qemu_tests::capabilities_smoke());
    }

    #[test]
    fn prp_list_smoke() {
        assert!(qemu_tests::prp_list_smoke());
    }

    #[test]
    fn pending_requests_smoke() {
        assert!(qemu_tests::pending_requests_smoke());
    }

    #[test]
    fn queue_type_traits_smoke() {
        assert!(qemu_tests::queue_type_traits_smoke());
    }

    #[test]
    fn identify_command_smoke() {
        assert!(qemu_tests::identify_command_smoke());
    }

    #[test]
    fn read_command_smoke() {
        assert!(qemu_tests::read_command_smoke());
    }
}
