// ============================================================================
// src/io/nvme/block_io.rs - NVMe BlockIo Adapter for nvme_ns FS
// ============================================================================
//!
//! # NVMe BlockIo アダプタ
//!
//! NVMe ドライバの低レベル PRP/DMA ベース API を `nvme_ns::BlockIo` トレイトに
//! 適合させるアダプタ。同期ポーリングモードで単一ブロック I/O を実行する。
//!
//! ## フロー
//! 1. page-padded な NVMe DMA 領域を確保し、必要なら device-scoped IOMMU map を作成
//! 2. `prp1` / `prp2` を構築
//! 3. `NvmePollingDriver::submit_read/write()` でコマンド発行
//! 4. `poll_completion_by_cid()` でスピンポーリング待機
//! 5. 論理長ぶんだけデータコピーし、DMA/IOMMU/PRP リソースを解放

use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoResult, io_scheduler,
};
use crate::io::nvme::dma::{NvmeDmaError, NvmeDmaRegion};
use nvme_ns::NsError;
use nvme_ns::fs::BlockIo;

/// 最大ポーリング反復回数（タイムアウト）
const MAX_POLL_ITERATIONS: u32 = 10_000_000;

/// NVMe ドライバをラップして `BlockIo` を提供するアダプタ
pub struct NvmeBlockIoAdapter {
    /// NVMe 名前空間 ID
    nsid: u32,
    /// 論理ブロックサイズ（バイト）
    block_size: u32,
    /// 総ブロック数
    total_blocks: u64,
}

impl NvmeBlockIoAdapter {
    fn map_dma_error(err: NvmeDmaError) -> NsError {
        match err {
            NvmeDmaError::OutOfMemory => {
                NsError::Internal(alloc::string::String::from("DMA alloc failed"))
            }
            NvmeDmaError::InvalidLen => {
                NsError::Internal(alloc::string::String::from("invalid DMA length"))
            }
            NvmeDmaError::IommuDeviceMissing | NvmeDmaError::IommuMappingFailed => NsError::IoError,
        }
    }

    /// ドライバから名前空間情報を取得してアダプタを作成
    ///
    /// NVMe グローバルドライバが初期化済みであること。
    pub fn from_driver() -> Result<Self, &'static str> {
        let (nsid, block_size, total_blocks) =
            if let Some(info) = crate::runtime_bridge::standalone_nvme_namespace_info(1) {
                (info.namespace_id, info.block_size, info.total_blocks)
            } else {
                crate::io::nvme::with_driver(|d| {
                    let nsid = d.nsid;
                    (
                        nsid,
                        d.namespace_block_size(nsid),
                        d.namespace_total_blocks(),
                    )
                })
                .ok_or("NVMe driver not initialized")?
            };

        if block_size == 0 || total_blocks == 0 {
            return Err("NVMe namespace not configured");
        }

        Ok(Self {
            nsid,
            block_size,
            total_blocks,
        })
    }

    /// 手動でパラメータを指定して作成（テスト用）
    pub fn new(nsid: u32, block_size: u32, total_blocks: u64) -> Self {
        Self {
            nsid,
            block_size,
            total_blocks,
        }
    }

    /// 現在のCPUコアIDを取得
    #[inline]
    fn core_id() -> u32 {
        crate::smp::cpu_index() as u32
    }

    /// DMA バッファを確保、コマンド発行、完了待機の共通ロジック
    fn submit_and_poll(
        &self,
        lba: u64,
        is_write: bool,
        data: Option<&[u8]>,
        out: Option<&mut [u8]>,
    ) -> Result<(), NsError> {
        let bs = self.block_size as usize;
        let dma = if is_write {
            let src = data.unwrap_or(&[]);
            NvmeDmaRegion::for_write(
                bs,
                &src[..src.len().min(bs)],
                crate::io::nvme::iommu_device(),
            )
        } else {
            NvmeDmaRegion::for_read(bs, crate::io::nvme::iommu_device())
        }
        .map_err(Self::map_dma_error)?;

        let device = IoDeviceId::Nvme {
            controller: 0,
            namespace: self.nsid,
        };
        let command = if is_write {
            IoCommand::BlockWrite {
                lba,
                blocks: 1,
                bytes: bs,
                buf: DmaBufHandle {
                    iova: dma.prp1(),
                    len: dma.alloc_len(),
                },
            }
        } else {
            IoCommand::BlockRead {
                lba,
                blocks: 1,
                bytes: bs,
                buf: DmaBufHandle {
                    iova: dma.prp1(),
                    len: dma.alloc_len(),
                },
            }
        };
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
            device,
            command,
            crate::io::io_scheduler::IoPriority::High,
        );
        let request_id = future.request_id();

        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some(result) = io_scheduler().take_result(request_id) {
                if !matches!(result, IoResult::Success(_)) {
                    return Err(NsError::IoError);
                }
                if !is_write {
                    if let Some(dst) = out {
                        dma.copy_into(dst);
                    }
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(NsError::Internal(alloc::string::String::from(
            "NVMe timeout",
        )))
    }
}

impl BlockIo for NvmeBlockIoAdapter {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    fn read_block(&self, lba: u64, buf: &mut [u8]) -> Result<(), NsError> {
        if lba >= self.total_blocks {
            return Err(NsError::InvalidArgument);
        }
        self.submit_and_poll(lba, false, None, Some(buf))
    }

    fn write_block(&self, lba: u64, buf: &[u8]) -> Result<(), NsError> {
        if lba >= self.total_blocks {
            return Err(NsError::InvalidArgument);
        }
        self.submit_and_poll(lba, true, Some(buf), None)
    }

    fn flush(&self) -> Result<(), NsError> {
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
            IoDeviceId::Nvme {
                controller: 0,
                namespace: self.nsid,
            },
            IoCommand::Flush,
            crate::io::io_scheduler::IoPriority::High,
        );
        let request_id = future.request_id();

        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some(result) = io_scheduler().take_result(request_id) {
                if matches!(result, IoResult::Success(_)) {
                    return Ok(());
                }
                return Err(NsError::IoError);
            }
            core::hint::spin_loop();
        }

        Err(NsError::Internal(alloc::string::String::from(
            "flush timeout",
        )))
    }
}
