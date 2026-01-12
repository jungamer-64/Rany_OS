//! AHCI DMA安全バッファ
//!
//! DMA転送中の不正アクセスを防止する型安全なバッファ

use x86_64::PhysAddr;

use crate::io::dma::{
    CoherentDmaBuffer, CpuOwned, DeviceOwned, DmaMemoryAttributes, SliceDmaGuard, TypedDmaSlice,
};

use super::types::SECTOR_SIZE;

/// DMA安全なセクタ読み取り用バッファ
///
/// TypedDmaSlice を使用して、DMA転送中の不正アクセスを防止する
pub struct AhciDmaReadBuffer {
    /// DMAバッファ (CPU所有状態)
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    /// 転送中バッファ (デバイス所有状態) + Guard
    inflight: Option<(TypedDmaSlice<DeviceOwned>, SliceDmaGuard)>,
    /// セクタ数
    sector_count: usize,
}

impl AhciDmaReadBuffer {
    /// 指定セクタ数用のバッファを作成
    pub fn new(sector_count: usize) -> Option<Self> {
        let size = sector_count * SECTOR_SIZE;
        let buffer = TypedDmaSlice::new(size)?;
        crate::io::log::early_print("[DMA] AHCI ReadBuffer alloc size=");
        crate::io::log::early_print_dec(size as u64);
        crate::io::log::early_print(" phys=");
        crate::io::log::early_print_hex(buffer.phys_addr().as_u64());
        crate::io::log::early_print("\n");

        Some(Self {
            buffer: Some(buffer),
            inflight: None,
            sector_count,
        })
    }

    /// 物理アドレスを取得（DMAエンジンに渡す用）
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.buffer
            .as_ref()
            .map(|b| b.phys_addr())
            .or_else(|| self.inflight.as_ref().map(|(b, _)| b.phys_addr()))
    }

    /// DMA転送を開始
    pub fn start_transfer(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in transfer")?;
        let phys = buffer.phys_addr().as_u64();
        // Diagnostic: log AHCI DMA start
        crate::io::log::early_print("[DMA] AHCI start_transfer phys=");
        crate::io::log::early_print_hex(phys);
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_dec(self.size() as u64);
        crate::io::log::early_print("\n");
        #[cfg(debug_assertions)]
        crate::memory::verify_buddy_integrity();
        let (dev, guard) = buffer.start_dma();
        self.inflight = Some((dev, guard));
        Ok(phys)
    }

    /// DMA転送完了
    pub fn complete_transfer(&mut self) -> Result<(), &'static str> {
        let (dev, guard) = self.inflight.take().ok_or("No transfer in progress")?;
        self.buffer = Some(guard.complete(dev));
        Ok(())
    }

    /// 読み取りデータを取得（CPU所有状態でのみ）
    pub fn data(&self) -> Option<&[u8]> {
        self.buffer.as_ref().map(|b| b.as_slice())
    }

    /// バッファサイズ
    pub fn size(&self) -> usize {
        self.sector_count * SECTOR_SIZE
    }
}

/// DMA安全なセクタ書き込み用バッファ
pub struct AhciDmaWriteBuffer {
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    inflight: Option<(TypedDmaSlice<DeviceOwned>, SliceDmaGuard)>,
    #[allow(dead_code)]
    sector_count: usize,
}

impl AhciDmaWriteBuffer {
    /// 書き込みデータでバッファを作成
    pub fn with_data(data: &[u8]) -> Option<Self> {
        let sector_count = (data.len() + SECTOR_SIZE - 1) / SECTOR_SIZE;
        let size = sector_count * SECTOR_SIZE;

        let mut buffer = TypedDmaSlice::new(size)?;
        crate::io::log::early_print("[DMA] AHCI WriteBuffer alloc size=");
        crate::io::log::early_print_dec(size as u64);
        crate::io::log::early_print(" phys=");
        crate::io::log::early_print_hex(buffer.phys_addr().as_u64());
        crate::io::log::early_print("\n");
        buffer.as_mut_slice()[..data.len()].copy_from_slice(data);

        Some(Self {
            buffer: Some(buffer),
            inflight: None,
            sector_count,
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
    pub fn start_transfer(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in transfer")?;
        let phys = buffer.phys_addr().as_u64();
        // Diagnostic: log AHCI DMA start
        crate::io::log::early_print("[DMA] AHCI start_transfer phys=");
        crate::io::log::early_print_hex(phys);
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_dec((self.sector_count * SECTOR_SIZE) as u64);
        crate::io::log::early_print("\n");
        #[cfg(debug_assertions)]
        crate::memory::verify_buddy_integrity();
        let (dev, guard) = buffer.start_dma();
        self.inflight = Some((dev, guard));
        Ok(phys)
    }

    /// DMA転送完了
    pub fn complete_transfer(&mut self) -> Result<(), &'static str> {
        let (dev, guard) = self.inflight.take().ok_or("No transfer in progress")?;
        self.buffer = Some(guard.complete(dev));
        Ok(())
    }
}

/// コヒーレントDMAバッファを使用したAHCI識別データ読み取り
///
/// キャッシュ一貫性を自動管理し、より安全なDMA転送を提供
pub struct AhciIdentifyBuffer {
    buffer: CoherentDmaBuffer,
}

impl AhciIdentifyBuffer {
    /// 識別データ用バッファ（512バイト）
    pub fn new() -> Option<Self> {
        let buffer = CoherentDmaBuffer::new(512, DmaMemoryAttributes::FROM_DEVICE)?;
        Some(Self { buffer })
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.buffer.phys_addr()
    }

    /// DMA転送準備
    pub fn prepare(&self) {
        // FROM_DEVICE なので prepare では何もしない
        // buffer.prepare_for_device() は書き込み転送用
    }

    /// DMA転送完了後のデータ取得
    pub fn finish_and_get_words(&self) -> [u16; 256] {
        self.buffer.finish_from_device();

        let mut words = [0u16; 256];
        // SAFETY: 転送完了後なので安全にアクセス可能
        let slice = unsafe { self.buffer.as_slice() };
        for (i, word) in words.iter_mut().enumerate() {
            let idx = i * 2;
            if idx + 1 < slice.len() {
                *word = u16::from_le_bytes([slice[idx], slice[idx + 1]]);
            }
        }
        words
    }
}

impl Default for AhciIdentifyBuffer {
    fn default() -> Self {
        Self::new().expect("Failed to allocate AHCI identify buffer")
    }
}
