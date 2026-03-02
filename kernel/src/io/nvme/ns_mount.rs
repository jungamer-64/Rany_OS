// ============================================================================
// src/io/nvme/ns_mount.rs - NVMe Namespace FS Mount Integration
// ============================================================================
//!
//! # NVMe Namespace FS マウント統合
//!
//! NVMe ドライバ検出後、NVMe Namespace FS をフォーマット・マウントする
//! カーネルレベルの統合コード。
//!
//! ## 使い方
//! ```ignore
//! // カーネル初期化フロー中:
//! if let Err(e) = crate::io::nvme::ns_mount::mount_nvme_ns_fs() {
//!     warn!("NVMe NS FS mount failed: {}", e);
//! }
//! ```

use alloc::sync::Arc;
use log::{info, warn};

use nvme_ns::fs::BlockIo;
use nvme_ns::NvmeNamespaceFs;

use super::block_io::NvmeBlockIoAdapter;

/// NVMe Namespace FS のマウント結果
static NVME_NS_FS: spin::Once<Arc<NvmeNamespaceFs>> = spin::Once::new();

/// マウント済みの NVMe NS FS を取得
pub fn nvme_ns_fs() -> Option<&'static Arc<NvmeNamespaceFs>> {
    NVME_NS_FS.get()
}

/// NVMe Namespace FS をマウント（既にフォーマット済みの場合）
///
/// フォーマット済みでなければ自動的にフォーマットを試みる。
pub fn mount_nvme_ns_fs() -> Result<(), &'static str> {
    // BlockIo アダプタの作成
    let adapter = NvmeBlockIoAdapter::from_driver()?;

    info!(
        target: "nvme_ns",
        "NVMe NS: block_size={}, total_blocks={}",
        adapter.block_size(),
        adapter.total_blocks()
    );

    let dev: Arc<dyn BlockIo> = Arc::new(adapter);

    // まずマウントを試みる
    match NvmeNamespaceFs::mount(Arc::clone(&dev)) {
        Ok(fs) => {
            info!(target: "nvme_ns", "NVMe Namespace FS mounted successfully");
            NVME_NS_FS.call_once(|| fs);
            Ok(())
        }
        Err(_) => {
            // マウント失敗 → フォーマットして再マウント
            info!(target: "nvme_ns", "No valid FS found, formatting...");
            NvmeNamespaceFs::mkfs(&*dev, 4, "ranyos")
                .map_err(|_| "mkfs failed")?;

            let fs = NvmeNamespaceFs::mount(dev)
                .map_err(|_| "mount after mkfs failed")?;

            info!(target: "nvme_ns", "NVMe Namespace FS formatted and mounted");
            NVME_NS_FS.call_once(|| fs);
            Ok(())
        }
    }
}

/// NVMe NS FS をアンマウントしてクリーンシャットダウン
pub fn unmount_nvme_ns_fs() {
    if let Some(fs) = NVME_NS_FS.get() {
        if let Err(e) = vfs::ExtendedFileSystem::unmount(fs.as_ref()) {
            warn!(target: "nvme_ns", "NVMe NS FS unmount error: {:?}", e);
        } else {
            info!(target: "nvme_ns", "NVMe Namespace FS unmounted cleanly");
        }
    }
}
