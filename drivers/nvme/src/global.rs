// ============================================================================
// src/io/nvme/global.rs - NVMe Global Instance and API
// ============================================================================
//!
//! # NVMeグローバルインスタンス
//!
//! グローバルNVMeドライバインスタンスとアクセスAPI。

#![allow(dead_code)]

use spin::Mutex;

use super::commands::NvmeCompletion;
use super::polling_driver::{NvmeDriverStats, NvmePollingDriver};

// ============================================================================
// Global Instance
// ============================================================================

static NVME_DRIVER: Mutex<Option<NvmePollingDriver>> = Mutex::new(None);

/// NVMeドライバを初期化
pub fn init(bar0: u64, num_cores: u32) -> Result<(), &'static str> {
    let mut driver = NvmePollingDriver::new(bar0, num_cores);
    driver.init()?;
    *NVME_DRIVER.lock() = Some(driver);
    Ok(())
}

/// NVMeドライバにアクセス
pub fn with_driver<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&NvmePollingDriver) -> R,
{
    NVME_DRIVER.lock().as_ref().map(f)
}

/// NVMeドライバに可変アクセス
pub fn with_driver_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut NvmePollingDriver) -> R,
{
    NVME_DRIVER.lock().as_mut().map(f)
}

/// ポーリングを実行
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub unsafe fn poll(core_id: u32) -> usize {
    with_driver(|d| unsafe { d.poll_loop(core_id) }).unwrap_or(0)
}

/// バッチポーリングを実行
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub unsafe fn poll_batch(core_id: u32, completions: &mut [NvmeCompletion]) -> usize {
    with_driver(|d| unsafe { d.poll_batch(core_id, completions) }).unwrap_or(0)
}

/// 統計を取得
pub fn get_stats() -> Option<NvmeDriverStats> {
    with_driver(|d| d.collect_stats())
}
