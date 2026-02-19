use super::*;


// ============================================================================
// Statistics
// ============================================================================

/// VirtIO ネットワーク統計
#[derive(Debug, Clone)]
pub struct VirtioNetStats {
    pub tx_packets: u32,
    pub rx_packets: u32,
    pub tx_bytes: u32,
    pub rx_bytes: u32,
}

// ============================================================================
// Global Device Instance
// ============================================================================

use crate::io::virtio::transport::VirtioMmioTransport;

pub(crate) static VIRTIO_NET_DEVICE: Mutex<Option<VirtioNetDevice>> = Mutex::new(None);

/// VirtIO ネットワークデバイス（MMIO）を初期化
///
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net(base_addr: usize) -> Result<(), VirtioNetError> {
    // トランスポート作成（magic/version検証含む）
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new(Box::new(transport));
    device.init()?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// VirtIO ネットワークデバイス（MMIO）を初期化（IOMMUデバイスID付き）
///
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net_for_device(
    base_addr: usize,
    device: IommuDeviceId,
) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new_with_device(Box::new(transport), Some(device));
    device.init()?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI).
///
/// `iommu_device_id` must be provided when IOMMU is enabled (strict mode).
pub fn init_virtio_net_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new_with_device(transport, iommu_device_id);
    device.init()?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// VirtIO ネットワークデバイスにアクセス
pub fn with_virtio_net<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    VIRTIO_NET_DEVICE.lock().as_ref().map(f)
}

/// 割り込みハンドラ
pub fn handle_virtio_net_interrupt() {
    if let Some(ref mut device) = *VIRTIO_NET_DEVICE.lock() {
        // Read and ack interrupt status for diagnostics and clearing the device
        let status = device.transport.get_interrupt_status();
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] IRQ status read=0x{:x}\n", status));
        device.transport.ack_interrupt(status);

        // Now process completions
        device.handle_interrupt();
    }
}

#[cfg(test)]
#[path = "../../tests.rs"]
mod tests;

// ============================================================================
// IoScheduler Integration
// ============================================================================

/// VirtIO ネットワーク PollHandler 実装
pub struct VirtioNetPollHandler {
    /// デバイスへの参照
    device_lock: &'static Mutex<Option<VirtioNetDevice>>,
    /// 保留中リクエスト (IoRequestId -> buffer_index)
    pending_rx: Mutex<BTreeMap<IoRequestId, u16>>,
    pending_tx: Mutex<BTreeMap<IoRequestId, u16>>,
    /// 次のリクエストID
    next_request_id: AtomicU64,
}

impl VirtioNetPollHandler {
    /// 新しい VirtioNetPollHandler を作成
    pub fn new() -> Self {
        Self {
            device_lock: &VIRTIO_NET_DEVICE,
            pending_rx: Mutex::new(BTreeMap::new()),
            pending_tx: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// 新しいリクエストIDを生成
    pub fn next_request_id(&self) -> IoRequestId {
        IoRequestId(self.next_request_id.fetch_add(1, Ordering::SeqCst))
    }

    /// RX リクエストを追加
    pub fn add_pending_rx(&self, id: IoRequestId, buffer_idx: u16) {
        self.pending_rx.lock().insert(id, buffer_idx);
    }

    /// TX リクエストを追加
    pub fn add_pending_tx(&self, id: IoRequestId, buffer_idx: u16) {
        self.pending_tx.lock().insert(id, buffer_idx);
    }
}

impl PollHandler for VirtioNetPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();

        if let Some(ref device) = *self.device_lock.lock() {
            // RX 完了をチェック - rx_queue が存在するか確認
            if let Some(ref rx_queue) = device.rx_queue {
                let mut pending = self.pending_rx.lock();
                let mut completed = Vec::new();

                // 簡略化: キューにリクエストがあれば完了とみなす
                // 実際の実装では used ring のインデックスを追跡
                for (&id, &_buf_idx) in pending.iter() {
                    // rx_queue の状態をチェック
                    let _ = rx_queue; // 使用を示す
                    results.push((id, IoResult::Success(1514))); // MTU
                    completed.push(id);
                    break; // 1つずつ処理
                }

                for id in completed {
                    pending.remove(&id);
                }
            }

            // TX 完了をチェック
            if let Some(ref tx_queue) = device.tx_queue {
                let mut pending = self.pending_tx.lock();
                let mut completed = Vec::new();

                for (&id, &_buf_idx) in pending.iter() {
                    let _ = tx_queue;
                    results.push((id, IoResult::Success(0)));
                    completed.push(id);
                    break;
                }

                for id in completed {
                    pending.remove(&id);
                }
            }
        }

        results
    }

    fn is_ready(&self) -> bool {
        self.device_lock.lock().is_some()
    }
}

// SAFETY: VirtioNetPollHandler はスレッドセーフ
// - 内部の Mutex で安全に同期
unsafe impl Send for VirtioNetPollHandler {}
unsafe impl Sync for VirtioNetPollHandler {}

/// VirtIO ネットワークを IoScheduler に登録（依存注入版）
pub fn register_virtio_net_with(
    coordinator: &alloc::sync::Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    index: u8,
) {
    let handler = VirtioNetPollHandler::new();
    let handler: Box<dyn PollHandler + Send + Sync> = Box::new(handler);
    coordinator.polling_executor().register_handler(DeviceId::VirtioNet { index }, handler);
}

/// VirtIO ネットワークを IoScheduler に登録（後方互換wrapper）
pub fn register_virtio_net_with_io_scheduler(index: u8) {
    register_virtio_net_with(&hybrid_coordinator(), index);
}

// ============================================================================
// 型安全 DMA バッファ (VirtIO Network)
// ============================================================================

/// VirtIO ネットワーク最大フレームサイズ
pub(crate) const VIRTIO_NET_MTU: usize = 1514;

/// VirtIO ネットワーク受信用DMAバッファ
///
/// 型状態パターンで DMA 転送中の不正アクセスを防止
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

        let desc_table = CoherentDmaBuffer::new(desc_size, DmaMemoryAttributes::MMIO)?;
        let avail_ring = CoherentDmaBuffer::new(avail_size, DmaMemoryAttributes::MMIO)?;
        let used_ring = CoherentDmaBuffer::new(used_size, DmaMemoryAttributes::FROM_DEVICE)?;

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
