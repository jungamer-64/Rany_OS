// ============================================================================
// src/fs/async_ops.rs - Async File Operations
// 設計書 6.3: ストレージと非同期ファイルシステム
// ============================================================================
//!
//! # 非同期ファイル操作
//!
//! NVMe SSDの性能を引き出すための完全非同期API。
//! 従来のブロックレイヤーやページキャッシュの概念を刷新。
//!
//! ## 設計原則
//! - NVMeポーリング: 各CPUコアごとにSubmission/Completion Queueペア
//! - ロックフリーでコマンド発行
//! - ファイルシステムをバイパスした直接ブロックアクセスAPI
//! - ページキャッシュはカーネルヒープ上のArc<Vec<u8>>として実装
use crate::sync::Mutex;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use x86_64::PhysAddr;

use kernel_api::dma::{CpuOwned as KapiCpuOwned, DmaSlice};

use super::cache::{PAGE_SIZE as CACHE_PAGE_SIZE, page_cache};
use super::fs_model::{
    FileAttr, FsError, FsResult, SeekFrom, read_inode_by_number, write_inode_by_number,
};

// NVme per-core API
use crate::io::dma::{
    DeviceDmaContext, DeviceDmaMapping, DmaDirection, DmaMemoryAttributes, DmaRegion,
};
use crate::io::io_scheduler::{
    CompletionHook, DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoPriority, IoResult,
};
use crate::io::nvme::dma::{NvmeDmaError, NvmeDmaRegion};
mod cleanup_helpers;

// re-export only the public types/functions kernel relies on instead of a wildcard
pub use cleanup_helpers::{
    AsyncFile,
    AsyncIoRequest,
    AsyncIoScheduler,
    AsyncIoType,
    DirectBlockHandle,
    IoSchedulerStats,
    async_io_scheduler,
    // helper APIs that are internal but still referenced by other parts of the crate
};

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
#[cfg(any(test, feature = "qemu-test-export"))]
pub use tests::*;
