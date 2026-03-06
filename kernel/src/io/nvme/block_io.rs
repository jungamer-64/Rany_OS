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
//! 1. DMA バッファを割り当て (`kernel_api::services::kernel().alloc_dma()`)
//! 2. PRP1 として `device_address()` を設定
//! 3. `NvmePollingDriver::submit_read/write()` でコマンド発行
//! 4. `poll_completion_by_cid()` でスピンポーリング待機
//! 5. データコピー & DMA バッファ解放

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
    /// ドライバから名前空間情報を取得してアダプタを作成
    ///
    /// NVMe グローバルドライバが初期化済みであること。
    pub fn from_driver() -> Result<Self, &'static str> {
        let (nsid, block_size, total_blocks) = crate::io::nvme::with_driver(|d| {
            let nsid = d.nsid;
            (
                nsid,
                d.namespace_block_size(nsid),
                d.namespace_total_blocks(),
            )
        })
        .ok_or("NVMe driver not initialized")?;

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
        let kernel = kernel_api::services::kernel();

        // DMA バッファ割り当て
        let mut dma_buf = kernel
            .alloc_dma(bs)
            .map_err(|_| NsError::Internal(alloc::string::String::from("DMA alloc failed")))?;

        // 書き込み時: データを DMA バッファにコピー
        if is_write {
            if let Some(src) = data {
                let len = src.len().min(bs);
                unsafe {
                    let dst = dma_buf.as_slice_mut();
                    dst[..len].copy_from_slice(&src[..len]);
                    if len < bs {
                        // ゼロ埋め
                        for byte in &mut dst[len..] {
                            *byte = 0;
                        }
                    }
                }
            }
        }

        let prp1 = dma_buf.device_address();
        let core_id = Self::core_id();

        // コマンド発行
        let cid = crate::io::nvme::with_driver(|d| {
            if is_write {
                unsafe { d.submit_write(core_id, self.nsid, lba, 1, prp1, 0) }
            } else {
                unsafe { d.submit_read(core_id, self.nsid, lba, 1, prp1, 0) }
            }
        })
        .ok_or(NsError::IoError)?
        .map_err(|_| NsError::IoError)?;

        // 完了をポーリング
        let mut completed = false;
        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some(cqe) =
                crate::io::nvme::with_driver(|d| unsafe { d.poll_completion_by_cid(core_id, cid) })
                    .flatten()
            {
                if !cqe.is_success() {
                    kernel.free_dma(dma_buf);
                    return Err(NsError::IoError);
                }
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }

        if !completed {
            kernel.free_dma(dma_buf);
            return Err(NsError::Internal(alloc::string::String::from(
                "NVMe timeout",
            )));
        }

        // 読み取り時: DMA バッファからデータをコピー
        if !is_write {
            if let Some(dst) = out {
                let len = dst.len().min(bs);
                unsafe {
                    let src = dma_buf.as_slice();
                    dst[..len].copy_from_slice(&src[..len]);
                }
            }
        }

        kernel.free_dma(dma_buf);
        Ok(())
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
        let core_id = Self::core_id();

        let cid = crate::io::nvme::with_driver(|d| unsafe { d.submit_flush(core_id, self.nsid) })
            .ok_or(NsError::IoError)?
            .map_err(|_| NsError::IoError)?;

        for _ in 0..MAX_POLL_ITERATIONS {
            if let Some(cqe) =
                crate::io::nvme::with_driver(|d| unsafe { d.poll_completion_by_cid(core_id, cid) })
                    .flatten()
            {
                if cqe.is_success() {
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
