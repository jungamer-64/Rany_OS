use super::*;
use crate::io::virtio::virtqueue::{VringAvail, VringDesc, VringUsed};

mod dma;
pub use dma::*;
mod irq;
mod mac;
mod registry;
mod rx;
mod tx;
pub use registry::*;
impl Drop for NetVirtQueue {
    fn drop(&mut self) {
        if let Some(map) = self.iommu_map.take() {
            // Prefer DmaHandle unmap if available
            if let Some(handle) = map.handle {
                if let Err(err) = handle.unmap() {
                    log::warn!("[VIRTIO-NET] failed to unmap DMA handle: {:?}", err);
                }
            } else {
                let result = match map.device {
                    Some(device) => unmap_for_device(&device, map.iova, map.len as u64),
                    None => unmap_dma(map.iova, map.len as u64),
                };
                if let Err(err) = result {
                    log::warn!("[VIRTIO-NET] failed to unmap queue DMA: {:?}", err);
                }
            }
        }
    }
}

// ============================================================================
// VirtIO Net Device
// ============================================================================

/// In-flight entry for a zero-copy TX packet. Holds cleanup handles for unmapping when completed.
#[derive(Debug)]
pub(crate) struct TxPacketInflight {
    packet: crate::net::datapath::mempool::PacketRef,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
    dma_iova: Option<u64>,
    dma_len: usize,
    /// Bounce buffer from the pool, if used.
    pool_bounce_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
}

/// In-flight entry for a zero-copy RX PacketRef. Holds IOMMU mapping for cleanup on completion.
#[derive(Debug)]
pub(crate) struct RxPacketInflight {
    packet: crate::net::datapath::mempool::PacketRef,
    /// IOVA mapped through IOMMU for this buffer (None when IOMMU is inactive)
    iommu_iova: Option<u64>,
    /// Size of the IOMMU mapping
    iommu_map_len: u64,
}

/// In-flight entry for a VirtioNetRxDmaBuffer. Holds IOMMU mapping for cleanup on completion.
#[derive(Debug)]
pub(crate) struct RxVbufInflight {
    vbuf: VirtioNetRxDmaBuffer,
    /// IOVA mapped through IOMMU for this buffer (None when IOMMU is inactive)
    iommu_iova: Option<u64>,
    /// Size of the IOMMU mapping
    iommu_map_len: u64,
}

// Queue memory layout calculation result.
pub(crate) use virtio_driver::net::QueueMemoryLayout;

/// VirtIO ネットワークデバイス
#[derive(Debug)]
pub struct VirtioNetDevice {
    /// トランスポート層（MMIO/PCI共通インターフェース）
    pub(crate) transport: alloc::sync::Arc<dyn VirtioTransport>,
    /// Shared device core
    pub(crate) core: virtio_driver::net::device::VirtioNetDevice,
    /// VirtIO-Net device index (multi-NIC support)
    pub(crate) virtio_index: u8,
    /// Bound logical network interface id (assigned by NetworkManager)
    pub(crate) net_if_id: Option<crate::net::runtime::manager::NetIfId>,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// 受信キューリスト (各ペアにつき1つ、インデックス0,2,...)
    rx_queues: Vec<NetVirtQueue>,
    /// 送信キューリスト (各ペアにつき1つ、インデックス1,3,...)
    tx_queues: Vec<NetVirtQueue>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 統計: 送信パケット数
    tx_packets: AtomicU32,
    /// 統計: 受信パケット数
    rx_packets: AtomicU32,
    /// 統計: 送信バイト数
    tx_bytes: AtomicU32,
    /// 統計: 受信バイト数
    rx_bytes: AtomicU32,
    /// 受信用バッファマップ (キュー別, desc_idx -> RxVbufInflight)
    pub(crate) rx_buffers: Vec<Box<[core::sync::atomic::AtomicPtr<RxVbufInflight>]>>,
    /// 受信用バッファマップ (キュー別, desc_idx -> RxPacketInflight) - zero-copy posted buffers from mempool
    pub(crate) rx_packetrefs: Vec<Box<[core::sync::atomic::AtomicPtr<RxPacketInflight>]>>,
    /// 送信用 PacketRef インフライトマップ (キュー別, desc_idx -> TxPacketInflight)
    pub(crate) tx_packetrefs: Vec<Box<[core::sync::atomic::AtomicPtr<TxPacketInflight>]>>,
    /// 送信用インフライトバッファ (キュー別, desc_idx -> CoherentDmaBuffer)
    pub(crate) tx_inflight: Vec<Box<[core::sync::atomic::AtomicPtr<CoherentDmaBuffer>]>>,
    /// プール済み送信用バウンスバッフェ (Here we keep the lock as it's a global pool, not per-descriptor)
    tx_bounce_pool: IrqPoisonLock<Vec<CoherentDmaBuffer>>,
    /// プール済み受信用バウンスバッファ
    rx_bounce_pool: IrqPoisonLock<Vec<CoherentDmaBuffer>>,
}

impl VirtioNetDevice {
    /// 新しいデバイスを作成
    ///
    /// # Arguments
    /// * `transport` - 初期化済みの VirtioTransport 実装（MMIO または PCI）
    ///   トランスポートはmagic/version検証を通過している必要がある
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_index_and_device(0, transport, None)
    }

    /// 新しいデバイスを作成（IOMMUデバイスIDを指定）
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self::new_with_index_and_device(0, transport, iommu_device_id)
    }

    /// 新しいデバイスを作成（デバイス index 指定）
    pub fn new_at_index(index: u8, transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_index_and_device(index, transport, None)
    }

    /// 新しいデバイスを作成（デバイス index + IOMMUデバイスID指定）
    pub fn new_with_index_and_device(
        index: u8,
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            transport: alloc::sync::Arc::from(transport),
            core: virtio_driver::net::device::VirtioNetDevice::new(),
            virtio_index: index,
            net_if_id: None,
            iommu_device_id,
            rx_queues: Vec::new(),
            tx_queues: Vec::new(),
            initialized: AtomicBool::new(false),
            tx_packets: AtomicU32::new(0),
            rx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            rx_buffers: Vec::new(),
            rx_packetrefs: Vec::new(),
            tx_packetrefs: Vec::new(),
            tx_inflight: Vec::new(),
            tx_bounce_pool: IrqPoisonLock::new(Vec::new()),
            rx_bounce_pool: IrqPoisonLock::new(Vec::new()),
        }
    }

    /// Return first RX queue (index 0) if present.
    pub fn first_rx_queue(&self) -> Option<&NetVirtQueue> {
        self.rx_queues.get(0)
    }

    /// Return first TX queue (index 1) if present.
    pub fn first_tx_queue(&self) -> Option<&NetVirtQueue> {
        self.tx_queues.get(0)
    }

    /// Return the IOMMU device identifier, if assigned.
    ///
    /// Used by the bridge layer to allocate DMA buffers with correct IOMMU
    /// mappings when submitting TX via the IoScheduler path.
    pub fn iommu_device_id(&self) -> Option<IommuDeviceId> {
        self.iommu_device_id
    }

    /// Bind this VirtIO device to a logical network interface identifier.
    pub fn set_net_if_id(&mut self, if_id: crate::net::runtime::manager::NetIfId) {
        self.net_if_id = Some(if_id);
    }

    /// Return the logical network interface identifier, if assigned.
    pub fn net_if_id(&self) -> Option<crate::net::runtime::manager::NetIfId> {
        self.net_if_id
    }

    pub(crate) fn mut_transport(&mut self) -> &mut dyn VirtioTransport {
        alloc::sync::Arc::get_mut(&mut self.transport)
            .expect("Transport must not be shared during init")
    }

    /// Validate strict IOMMU policy for VirtIO-Net.
    ///
    /// In strict mode, when IOMMU translation is active, device-scoped mappings
    /// require a concrete device identifier.
    fn validate_iommu_device_requirement(
        iommu_enabled: bool,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Result<(), VirtioNetError> {
        if iommu_enabled && iommu_device_id.is_none() {
            log::error!(
                "[VIRTIO-NET] strict IOMMU mode requires iommu_device_id when IOMMU is enabled"
            );
            return Err(VirtioNetError::DeviceError);
        }
        Ok(())
    }

    /// デバイスを初期化
    pub fn init(&mut self) -> Result<(), VirtioNetError> {
        // 1. デバイスタイプ確認（トランスポートはすでにmagic/version検証済み）
        if self.transport.device_type() != VirtioDeviceType::Network {
            return Err(VirtioNetError::DeviceError);
        }

        // Strict policy: device-scoped DMA mapping requires device ID when IOMMU is active.
        Self::validate_iommu_device_requirement(is_iommu_enabled(), self.iommu_device_id)?;

        // 2-7. Perform common VirtIO initialization using shared core
        self.core.init(self.transport.as_ref())?;

        // 8. キューの設定
        if let Err(e) = self.setup_queues() {
            log::error!("[VIRTIO-NET] Failed to setup queues: {:?}", e);
            self.mut_transport()
                .set_status(status::VIRTIO_STATUS_FAILED);
            return Err(e);
        }

        // 9. DRIVER_OK を設定
        self.mut_transport().add_status(status::VIRTIO_STATUS_DRIVER_OK);

        // 10. DRIVER_OK後にRXキューを再通知（VirtIO spec準拠）
        for rxq in &self.rx_queues {
            rxq.notify(self.transport.as_ref());
        }

        // Initialize bounce buffer pools for IOMMU paths
        if let Err(e) = self.init_bounce_pools() {
            log::error!("[VIRTIO-NET] Failed to init bounce pools: {:?}", e);
            self.mut_transport()
                .set_status(status::VIRTIO_STATUS_FAILED);
            return Err(e);
        }

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// RXキューが空になっている場合にバッファを補充する（スタベーション回復）
    pub fn refill_rx_queues(&self) {
        for rx_queue in &self.rx_queues {
            let mut count = 0;
            let queue_size = rx_queue.inner().queue_size();
            // API drift fallback: post until the queue rejects new buffers.
            while count < queue_size {
                match self.try_post_rx_packet(rx_queue) {
                    Ok(true) => count += 1,
                    Ok(false) => break, // queue full or mempool empty
                    Err(_) => break,
                }
            }
            if count > 0 {
                log::info!(
                    "[VIRTIO-NET] Refilled {} RX buffers for queue {}",
                    count,
                    rx_queue.inner().queue_index()
                );
                rx_queue.notify(self.transport.as_ref());
            }
        }
    }

    fn init_bounce_pools(&self) -> Result<(), VirtioNetError> {
        // Pre-allocate 128 bounce buffers for TX and RX (4KB each)
        let pool_size = 128;
        let buffer_size = 4096;
        let mut tx_guard = self
            .tx_bounce_pool
            .lock()
            .map_err(|_| VirtioNetError::DeviceError)?;
        let mut rx_guard = self
            .rx_bounce_pool
            .lock()
            .map_err(|_| VirtioNetError::DeviceError)?;

        for _ in 0..pool_size {
            let tx_buf = match self.iommu_device_id {
                Some(dev) => {
                    CoherentDmaBuffer::new_for_device(buffer_size, DmaMemoryAttributes::MMIO, &dev)
                }
                None => CoherentDmaBuffer::new(buffer_size, DmaMemoryAttributes::MMIO),
            }
            .ok_or(VirtioNetError::DeviceError)?;
            tx_guard.push(tx_buf);

            let rx_buf = match self.iommu_device_id {
                Some(dev) => {
                    CoherentDmaBuffer::new_for_device(buffer_size, DmaMemoryAttributes::MMIO, &dev)
                }
                None => CoherentDmaBuffer::new(buffer_size, DmaMemoryAttributes::MMIO),
            }
            .ok_or(VirtioNetError::DeviceError)?;
            rx_guard.push(rx_buf);
        }
        Ok(())
    }

    pub(crate) fn get_tx_bounce_buffer(
        &self,
        size: usize,
    ) -> Result<crate::io::dma::CoherentDmaBuffer, VirtioNetError> {
        let mut guard = self
            .tx_bounce_pool
            .lock()
            .map_err(|_| VirtioNetError::DeviceError)?;
        if let Some(buf) = guard.pop() {
            if buf.size() >= size {
                return Ok(buf);
            }
            guard.push(buf);
        }
        let alloc_size = core::cmp::max(size, 4096);
        match self.iommu_device_id {
            Some(dev) => crate::io::dma::CoherentDmaBuffer::new_for_device(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
                &dev,
            ),
            None => crate::io::dma::CoherentDmaBuffer::new(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
            ),
        }
        .ok_or(VirtioNetError::DeviceError)
    }

    pub(crate) fn return_tx_bounce_buffer(&self, buffer: crate::io::dma::CoherentDmaBuffer) {
        if let Ok(mut guard) = self.tx_bounce_pool.lock() {
            guard.push(buffer);
        }
    }

    pub(crate) fn get_rx_bounce_buffer(
        &self,
        size: usize,
    ) -> Result<crate::io::dma::CoherentDmaBuffer, VirtioNetError> {
        let mut guard = self
            .rx_bounce_pool
            .lock()
            .map_err(|_| VirtioNetError::DeviceError)?;
        if let Some(buf) = guard.pop() {
            if buf.size() >= size {
                return Ok(buf);
            }
            guard.push(buf);
        }
        let alloc_size = core::cmp::max(size, 4096);
        match self.iommu_device_id {
            Some(dev) => crate::io::dma::CoherentDmaBuffer::new_for_device(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
                &dev,
            ),
            None => crate::io::dma::CoherentDmaBuffer::new(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
            ),
        }
        .ok_or(VirtioNetError::DeviceError)
    }

    pub(crate) fn return_rx_bounce_buffer(&self, buffer: crate::io::dma::CoherentDmaBuffer) {
        if let Ok(mut guard) = self.rx_bounce_pool.lock() {
            guard.push(buffer);
        }
    }

    /// VirtQueue を設定。`core.config.max_queues` に従いキューペアを並列構築する。
    pub(super) fn setup_queues(&mut self) -> Result<(), VirtioNetError> {
        let pair_count = self.core.get_pair_count();
        for i in 0..pair_count {
            let rx_index = (i * 2) as u16;
            let rxq = self.setup_single_queue(rx_index)?;
            self.rx_queues.push(rxq);

            let tx_index = rx_index + 1;
            let txq = self.setup_single_queue(tx_index)?;
            self.tx_queues.push(txq);
        }

        Ok(())
    }

    /// 単一のキューを設定
    pub(super) fn setup_single_queue(
        &mut self,
        queue_index: u16,
    ) -> Result<NetVirtQueue, VirtioNetError> {
        // キューを選択
        self.mut_transport().select_queue(queue_index);

        // 最大キューサイズを取得
        let max_size = self.transport.get_queue_max_size();
        if max_size == 0 {
            return Err(VirtioNetError::DeviceError);
        }

        // キューサイズを設定（最大256エントリに制限）
        let queue_size = self.core.calculate_queue_size(max_size);
        self.mut_transport().set_queue_size(queue_size);

        // Standardized layout calculation
        let layout = QueueMemoryLayout::calculate(queue_index, queue_size);

        // DMAバッファを割り当て
        let (buffer, _dma_len) = self.allocate_queue_dma(layout.total_size)?;

        let phys_base = buffer.device_addr();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(layout.desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(layout.used_offset) as *mut VringUsed };
        let notify_addr = self.mut_transport().get_notify_addr(queue_index);
        let notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        // IOMMU DMAマッピングを設定
        let (dma_base, iommu_map) = self.setup_iommu_dma_mapping(&buffer, layout.total_size, phys_base)?;

        let (tx_headers, tx_header_dma_base) = if (queue_index % 2) == 1 {
            let header_ptr = unsafe { ptr.add(layout.header_offset) as *mut VirtioNetHeader };
            let header_dma_base = dma_base + layout.header_offset as u64;
            (Some(header_ptr), Some(header_dma_base))
        } else {
            (None, None)
        };

        // 各リングを初期化
        // setup_queues handles the queue setup

        // デバイスにアドレスを設定
        let desc_addr = dma_base;
        let avail_addr = dma_base + layout.desc_size as u64;
        let used_addr = dma_base + layout.used_offset as u64;

        self.mut_transport().set_queue_desc_addr(desc_addr);
        self.mut_transport().set_queue_avail_addr(avail_addr);
        self.mut_transport().set_queue_used_addr(used_addr);

        // Create trackers for this queue
        if (queue_index % 2) == 0 {
            // RX queue
            let mut tracker_vec = Vec::with_capacity(queue_size as usize);
            for _ in 0..queue_size {
                tracker_vec.push(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()));
            }
            self.rx_buffers.push(tracker_vec.into_boxed_slice());

            let mut pr_vec = Vec::with_capacity(queue_size as usize);
            for _ in 0..queue_size {
                pr_vec.push(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()));
            }
            self.rx_packetrefs.push(pr_vec.into_boxed_slice());
        } else {
            // TX queue
            let mut tracker_vec = Vec::with_capacity(queue_size as usize);
            for _ in 0..queue_size {
                tracker_vec.push(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()));
            }
            self.tx_packetrefs.push(tracker_vec.into_boxed_slice());

            let mut inflight_vec = Vec::with_capacity(queue_size as usize);
            for _ in 0..queue_size {
                inflight_vec.push(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()));
            }
            self.tx_inflight.push(inflight_vec.into_boxed_slice());
        }

        let features = self.transport.get_device_features_low() as u64
            | ((self.transport.get_device_features_high() as u64) << 32);

        // キューを作成
        let queue = unsafe {
            NetVirtQueue::new(
                queue_index,
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                notify_addr,
                notify_is_32bit,
                iommu_map,
                tx_headers,
                tx_header_dma_base,
                features,
            )
        };

        // RXキューの場合は初期バッファを投稿
        if (queue_index % 2) == 0 {
            self.pre_allocate_rx_buffers_for_queue(&queue);
        }

        self.mut_transport().enable_queue();

        Ok(queue)
    }


    /// キュー用のDMAバッファを割り当てる
    pub(super) fn allocate_queue_dma(
        &self,
        total_size: usize,
    ) -> Result<(CoherentDmaBuffer, usize), VirtioNetError> {
        if is_iommu_required() && !is_iommu_enabled() {
            return Err(VirtioNetError::DeviceError);
        }

        if is_iommu_enabled() {
            let aligned_len = iommu_align_len(total_size).ok_or(VirtioNetError::DeviceError)?;
            let device_id = self.iommu_device_id.ok_or_else(|| {
                log::error!(
                    "[VIRTIO-NET] queue DMA allocation requires iommu_device_id when IOMMU is enabled"
                );
                VirtioNetError::DeviceError
            })?;
            let buffer = CoherentDmaBuffer::new_for_device(
                aligned_len,
                DmaMemoryAttributes::MMIO,
                &device_id,
            )
            .ok_or(VirtioNetError::DeviceError)?;
            if !buffer.is_iommu_mapped() {
                log::error!(
                    "[VIRTIO-NET] queue DMA buffer was not mapped for device; refusing phys fallback"
                );
                return Err(VirtioNetError::DeviceError);
            }
            Ok((buffer, aligned_len))
        } else {
            let buffer = CoherentDmaBuffer::new(total_size, DmaMemoryAttributes::MMIO)
                .ok_or(VirtioNetError::DeviceError)?;
            Ok((buffer, total_size))
        }
    }

    /// キューメモリのIOMMU DMAマッピングを設定する
    pub(super) fn setup_iommu_dma_mapping(
        &self,
        buffer: &CoherentDmaBuffer,
        _dma_len: usize,
        phys_base: u64,
    ) -> Result<(u64, Option<IommuMapping>), VirtioNetError> {
        if !is_iommu_enabled() {
            return Ok((phys_base, None));
        }

        if self.iommu_device_id.is_some() && !buffer.is_iommu_mapped() {
            log::error!(
                "[VIRTIO-NET] queue memory is not mapped for device DMA despite IOMMU being enabled"
            );
            return Err(VirtioNetError::DeviceError);
        }

        // Queue memory must be shared between CPU and device.
        // Use the same coherent buffer backing with device-visible address.
        Ok((buffer.device_addr(), None))
    }

    /// RXバッファ用のIOMMUマッピングを実行する
    ///
    /// Returns (dma_addr, iommu_iova, iommu_map_len).
    pub(super) fn map_buffer_for_rx(
        &self,
        phys: u64,
        buf_len: usize,
    ) -> Result<(u64, Option<u64>, u64), VirtioNetError> {
        if !is_iommu_enabled() {
            return Ok((phys, None, 0));
        }

        if let Some(ref device_id) = self.iommu_device_id {
            let map_size = iommu_align_len(buf_len).unwrap_or(buf_len) as u64;
            // Intel VT-d: R=0,W=1 is invalid (W is reserved when R=0)
            // RX buffers need R+W even though device only writes
            match unsafe {
                map_for_device_with_perms(device_id, PhysAddr::new(phys), map_size, true, true)
            } {
                Ok(iova) => Ok((iova, Some(iova), map_size)),
                Err(e) => {
                    log::warn!("[VIRTIO-NET] IOMMU map failed for RX buffer: {:?}", e);
                    Err(VirtioNetError::DeviceError)
                }
            }
        } else {
            Ok((phys, None, 0))
        }
    }

    /// PacketRefの割り当てとRXキューへのポストを試みる
    ///
    /// Returns: Ok(true) = posted successfully (continue to next),
    ///          Ok(false) = not posted (fall through to vbuf),
    ///          Err = skip this iteration (e.g. IOMMU failure)
    pub(super) fn try_post_rx_packet(&self, rxq: &NetVirtQueue) -> Result<bool, VirtioNetError> {
        // キューに空きディスクリプタがなければ、PacketRef割り当てを回避する
        if rxq.available_descriptors() == 0 {
            return Ok(false);
        }

        let packet = match crate::net::datapath::mempool::alloc_packet() {
            Some(p) => p,
            None => return Ok(false),
        };

        let phys = packet.phys_addr().as_u64();
        let buf_len = packet.capacity();

        let (dma_addr, iommu_iova, iommu_map_len) = self.map_buffer_for_rx(phys, buf_len)?;

        match rxq.add_rx_buffer_zero_copy(dma_addr, buf_len) {
            Ok(desc_idx) => {
                let q_idx = self
                    .rx_queues
                    .iter()
                    .position(|q| core::ptr::eq(q, rxq))
                    .unwrap_or(0);
                if let Some(tracker) = self.rx_packetrefs.get(q_idx) {
                    if let Some(slot) = tracker.get(desc_idx as usize) {
                        let entry = Box::new(RxPacketInflight {
                            packet,
                            iommu_iova,
                            iommu_map_len,
                        });
                        slot.store(Box::into_raw(entry), Ordering::Release);
                    }
                }
                Ok(true)
            }
            Err(e) => {
                if let (Some(iova), Some(device_id)) = (iommu_iova, &self.iommu_device_id) {
                    let _ = unmap_for_device(device_id, iova, iommu_map_len);
                }
                // QueueFullはリフィル時に正常に発生するため、traceレベルで記録
                log::trace!("[VIRTIO-NET] failed to post PacketRef rx buffer: {:?}", e);
                Ok(false)
            }
        }
    }

    /// VirtioNetRxDmaBufferの割り当てとRXキューへのポストを試みる
    ///
    /// Returns: Ok(true) = posted successfully,
    ///          Ok(false) = not posted (continue),
    ///          Err = no more buffers available (stop)
    pub(super) fn try_post_rx_vbuf(&self, rxq: &NetVirtQueue) -> Result<bool, VirtioNetError> {
        // キューに空きディスクリプタがなければ、バッファ割り当てを回避する
        if rxq.available_descriptors() == 0 {
            return Ok(false);
        }

        let mut vbuf = match VirtioNetRxDmaBuffer::new() {
            Some(v) => v,
            None => {
                log::warn!("[VIRTIO-NET] failed to allocate rx buffer");
                return Err(VirtioNetError::DeviceError);
            }
        };

        let phys = match vbuf.start_receive() {
            Ok(p) => p,
            Err(e) => {
                log::warn!("[VIRTIO-NET] failed to start rx buffer: {}", e);
                return Ok(false);
            }
        };
        let buf_len = vbuf.alloc_size;

        let (dma_addr, iommu_iova, iommu_map_len) = match self.map_buffer_for_rx(phys, buf_len) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        match rxq.add_rx_buffer_zero_copy(dma_addr, buf_len) {
            Ok(desc_idx) => {
                let q_idx = self
                    .rx_queues
                    .iter()
                    .position(|q| core::ptr::eq(q, rxq))
                    .unwrap_or(0);
                if let Some(tracker) = self.rx_buffers.get(q_idx) {
                    if let Some(slot) = tracker.get(desc_idx as usize) {
                        let entry = Box::new(RxVbufInflight {
                            vbuf,
                            iommu_iova,
                            iommu_map_len,
                        });
                        slot.store(Box::into_raw(entry), Ordering::Release);
                    }
                }
                Ok(true)
            }
            Err(e) => {
                if let (Some(iova), Some(device_id)) = (iommu_iova, &self.iommu_device_id) {
                    let _ = unmap_for_device(device_id, iova, iommu_map_len);
                }
                log::trace!("[VIRTIO-NET] failed to add rx buffer: {:?}", e);
                Ok(false)
            }
        }
    }

    /// RXキューにバッファを事前割り当てする（特定キュー版）
    pub(super) fn pre_allocate_rx_buffers_for_queue(&self, rxq: &NetVirtQueue) {
        let mut added = 0usize;
        for _ in 0..8 {
            match self.try_post_rx_packet(rxq) {
                Ok(true) => {
                    added += 1;
                    continue;
                }
                Ok(false) => {}
                Err(_) => {
                    continue;
                }
            }
            match self.try_post_rx_vbuf(rxq) {
                Ok(true) => {
                    added += 1;
                }
                Ok(false) => {}
                Err(_) => {
                    break;
                }
            }
        }
        log::info!("[VIRTIO-NET] posted {} initial RX buffers", added);
        // Notify the device that new RX buffers are available
        if added > 0 {
            rxq.notify(self.transport.as_ref());
        }
    }

    /// 登録済み全 RX キューにバッファを事前割り当てする
    pub(super) fn pre_allocate_rx_buffers(&self) {
        for rxq in &self.rx_queues {
            self.pre_allocate_rx_buffers_for_queue(rxq);
        }
    }

    /// デバイスに通知（キュー更新）
    pub fn notify(&mut self, queue_index: u16) {
        self.transport.notify_queue(queue_index);
    }

    /// Submit a transmit packet synchronously by copying into a coherent DMA buffer and
    /// adding it to the TX queue. The buffer is retained in `tx_inflight` until completion
    /// and freed in the interrupt handler.
    pub(super) fn process_post_notify_completions(&self) {
        // Use the normal completion path so descriptor chains are reclaimed via
        // `take_completion()` and TX rings do not leak into QueueFull.
        self.process_tx_completions();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_validate_iommu_device_requirement_rejects_missing_device_id_when_enabled() {
        let result = VirtioNetDevice::validate_iommu_device_requirement(true, None);
        assert_eq!(result, Err(VirtioNetError::DeviceError));
    }

    #[test_case]
    fn test_validate_iommu_device_requirement_accepts_device_id_when_enabled() {
        let device = IommuDeviceId::new(0, 0, 1, 0);
        let result = VirtioNetDevice::validate_iommu_device_requirement(true, Some(device));
        assert_eq!(result, Ok(()));
    }

    #[test_case]
    fn test_validate_iommu_device_requirement_accepts_missing_device_id_when_disabled() {
        let result = VirtioNetDevice::validate_iommu_device_requirement(false, None);
        assert_eq!(result, Ok(()));
    }
}
