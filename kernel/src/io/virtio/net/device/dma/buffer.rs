use super::*;

use crate::io::dma::{CpuOwned, DeviceOwned, SliceDmaGuard, TypedDmaSlice};
use x86_64::PhysAddr;
use crate::io::dma::CoherentDmaBuffer;

// ============================================================================
// 型安全 DMA バッファ (VirtIO Network)
// ============================================================================

/// VirtIO ネットワーク最大フレームサイズ
pub(crate) const VIRTIO_NET_MTU: usize = 1514;

/// VirtIO ネットワーク受信用DMAバッファ
///
/// 型状態パターンで DMA 転送中の不正アクセスを防止
#[derive(Debug)]
pub struct VirtioNetRxDmaBuffer {
    /// CPU所有状態のバッファ
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    /// デバイス所有状態（転送中）+ Guard
    inflight: Option<(TypedDmaSlice<DeviceOwned>, SliceDmaGuard)>,
    /// アロケート済みバッファサイズ（4Kアライン）
    pub(crate) alloc_size: usize,
}

impl VirtioNetRxDmaBuffer {
    /// MTUサイズの受信バッファを作成
    pub fn new() -> Option<Self> {
        // VirtIO net header + MTU
        let size = core::mem::size_of::<VirtioNetHeader>() + VIRTIO_NET_MTU;
        let alloc_size = iommu_align_len(size)?;
        let buffer = TypedDmaSlice::new(alloc_size)?;

        Some(Self {
            buffer: Some(buffer),
            inflight: None,
            alloc_size,
        })
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.buffer
            .as_ref()
            .map(|b| b.phys_addr())
            .or_else(|| self.inflight.as_ref().map(|(b, _)| b.phys_addr()))
    }

    /// DMA転送を開始（VirtQueueへのバッファ追加時）
    pub fn start_receive(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in use")?;
        let phys = buffer.phys_addr().as_u64();
        let (dev, guard) = buffer.start_dma();
        self.inflight = Some((dev, guard));
        Ok(phys)
    }

    /// DMA転送完了（受信完了時）
    pub fn complete_receive(&mut self) -> Result<(), &'static str> {
        let (dev, guard) = self.inflight.take().ok_or("No receive in progress")?;
        self.buffer = Some(guard.complete(dev));
        Ok(())
    }

    /// 受信データを取得（完了後のみ）
    pub fn received_data(&self) -> Option<&[u8]> {
        self.buffer.as_ref().map(|b| {
            // Skip VirtIO net header
            let slice = b.as_slice();
            let header_size = core::mem::size_of::<VirtioNetHeader>();
            let end = header_size + VIRTIO_NET_MTU;
            &slice[header_size..end]
        })
    }

    /// Take ownership of the CPU-owned TypedDmaSlice when completed.
    /// This consumes the internal buffer and returns it, allowing the caller to
    /// take ownership and avoid copying (true zero-copy path).
    pub fn take_cpu_buffer(&mut self) -> Option<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>> {
        self.buffer.take()
    }

    /// バッファ全体のサイズ（4Kアライン済み）
    pub fn size(&self) -> usize {
        self.alloc_size
    }
}

impl Default for VirtioNetRxDmaBuffer {
    fn default() -> Self {
        Self::new().expect("Failed to allocate VirtIO net RX buffer")
    }
}

/// VirtIO ネットワーク送信用DMAバッファ
#[derive(Debug)]
pub struct VirtioNetTxDmaBuffer {
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    inflight: Option<(TypedDmaSlice<DeviceOwned>, SliceDmaGuard)>,
    data_len: usize,
    alloc_size: usize,
}

impl VirtioNetTxDmaBuffer {
    /// 送信データからバッファを作成
    pub fn with_data(data: &[u8]) -> Option<Self> {
        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let total_size = header_size + data.len();
        let alloc_size = iommu_align_len(total_size)?;

        let mut buffer = TypedDmaSlice::new(alloc_size)?;

        {
            let slice = buffer.as_mut_slice();
            // VirtIO net header をゼロクリア（初期化済み）
            // slice[..header_size] は既に 0
            // データをコピー
            let data_end = header_size + data.len();
            slice[header_size..data_end].copy_from_slice(data);
        }

        Some(Self {
            buffer: Some(buffer),
            inflight: None,
            data_len: data.len(),
            alloc_size,
        })
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.buffer
            .as_ref()
            .map(|b| b.phys_addr())
            .or_else(|| self.inflight.as_ref().map(|(b, _)| b.phys_addr()))
    }

    /// DMA転送を開始
    pub fn start_transmit(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in use")?;
        let phys = buffer.phys_addr().as_u64();
        let (dev, guard) = buffer.start_dma();
        self.inflight = Some((dev, guard));
        Ok(phys)
    }

    /// DMA転送完了
    pub fn complete_transmit(&mut self) -> Result<(), &'static str> {
        let (dev, guard) = self.inflight.take().ok_or("No transmit in progress")?;
        self.buffer = Some(guard.complete(dev));
        Ok(())
    }

    /// 送信データ長
    pub fn data_len(&self) -> usize {
        self.data_len
    }

    /// 合計バッファサイズ（4Kアライン済み）
    pub fn total_size(&self) -> usize {
        self.alloc_size
    }
}

/// コヒーレントDMAバッファを使用したVirtQueue
///
/// VirtQueueの記述子テーブル、Availableリング、Usedリングに使用
#[derive(Debug)]
pub struct VirtQueueDmaBuffers {
    /// 記述子テーブル
    pub desc_table: CoherentDmaBuffer,
    /// Available リング
    pub avail_ring: CoherentDmaBuffer,
    /// Used リング  
    pub used_ring: CoherentDmaBuffer,
}

impl VirtQueueDmaBuffers {
    /// VirtQueue用のDMAバッファセットを作成
    ///
    /// # Arguments
    /// * `queue_size` - キューサイズ（記述子数）
    pub fn new(queue_size: u16) -> Option<Self> {
        let desc_size = queue_size as usize * 16; // VirtqDesc は 16 バイト
        let avail_size = 6 + queue_size as usize * 2; // header + entries
        let used_size = 6 + queue_size as usize * 8; // header + entries

        let desc_table = CoherentDmaBuffer::new(desc_size, crate::io::dma::DmaMemoryAttributes::MMIO)?;
        let avail_ring = CoherentDmaBuffer::new(avail_size, crate::io::dma::DmaMemoryAttributes::MMIO)?;
        let used_ring = CoherentDmaBuffer::new(used_size, crate::io::dma::DmaMemoryAttributes::FROM_DEVICE)?;

        Some(Self {
            desc_table,
            avail_ring,
            used_ring,
        })
    }

    /// 記述子テーブルの物理アドレス
    pub fn desc_table_addr(&self) -> u64 {
        self.desc_table.phys_addr().as_u64()
    }

    /// Available リングの物理アドレス
    pub fn avail_ring_addr(&self) -> u64 {
        self.avail_ring.phys_addr().as_u64()
    }

    /// Used リングの物理アドレス
    pub fn used_ring_addr(&self) -> u64 {
        self.used_ring.phys_addr().as_u64()
    }
}
