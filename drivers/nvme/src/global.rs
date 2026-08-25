// ============================================================================
// src/io/nvme/global.rs - NVMe Global Instance and API
// ============================================================================
//!
//! # NVMeグローバルインスタンス
//!
//! グローバルNVMeドライバインスタンスとアクセスAPI。
use exorust_sync::PoisonLock;
use kernel_api::abi::driver::PackedPciLocation;

use super::commands::NvmeCompletion;
use super::polling_driver::{NvmeDriverStats, NvmePollingDriver};

// ============================================================================
// Global Instance
// ============================================================================

static NVME_DRIVER: PoisonLock<Option<NvmePollingDriver>> = PoisonLock::new(None);

/// NVMeドライバを初期化
///
/// `device_id` にIOMMU対応のパック済みデバイスIDを指定すると、
/// DMAバッファがデバイス固有のIOMMUドメインにマッピングされる。
/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub fn init(
    bar0: u64,
    io_queue_capacity: u32,
    device_id: PackedPciLocation,
) -> Result<(), &'static str> {
    let mut driver = NvmePollingDriver::new(bar0, io_queue_capacity, device_id);
    driver.init()?;
    *NVME_DRIVER.lock().unwrap_or_else(|e| e.into_inner()) = Some(driver);
    Ok(())
}

/// NVMeドライバにアクセス
pub fn with_driver<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&NvmePollingDriver) -> R,
{
    NVME_DRIVER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(f)
}

/// NVMeドライバに可変アクセス
pub fn with_driver_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut NvmePollingDriver) -> R,
{
    NVME_DRIVER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .map(f)
}

/// ポーリングを実行
///
/// # Safety
/// `queue_index` が初期化済み I/O queue を指すことを呼び出し側が保証。
pub unsafe fn poll(queue_index: u32) -> usize {
    with_driver(|d| unsafe { d.poll_loop(queue_index) }).unwrap_or(0)
}

/// バッチポーリングを実行
///
/// # Safety
/// `queue_index` が初期化済み I/O queue を指すことを呼び出し側が保証。
pub unsafe fn poll_batch(queue_index: u32, completions: &mut [NvmeCompletion]) -> usize {
    with_driver(|d| unsafe { d.poll_batch(queue_index, completions) }).unwrap_or(0)
}

/// 統計を取得
pub fn get_stats() -> Option<NvmeDriverStats> {
    with_driver(|d| d.collect_stats())
}
