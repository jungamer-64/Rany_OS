use super::*;


mod dma_helpers;
pub use dma_helpers::*;
mod tx_submit;
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

/// VirtIO ネットワークデバイス設定
#[derive(Debug, Clone)]
pub struct VirtioNetConfig {
    /// MACアドレス
    pub mac: [u8; 6],
    /// 最大キュー数
    pub max_queues: u16,
    /// MTU
    pub mtu: u16,
}

impl Default for VirtioNetConfig {
    fn default() -> Self {
        Self {
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // QEMU default
            max_queues: 1,
            mtu: 1500,
        }
    }
}

/// In-flight entry for a zero-copy TX packet. Holds cleanup handles for unmapping when completed.
pub(crate) struct TxPacketInflight {
    packet: crate::net::PacketRef,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
    dma_iova: Option<u64>,
    dma_len: usize,
}

/// In-flight entry for a zero-copy RX PacketRef. Holds IOMMU mapping for cleanup on completion.
pub(crate) struct RxPacketInflight {
    packet: crate::net::PacketRef,
    /// IOVA mapped through IOMMU for this buffer (None when IOMMU is inactive)
    iommu_iova: Option<u64>,
    /// Size of the IOMMU mapping
    iommu_map_len: u64,
}

/// In-flight entry for a VirtioNetRxDmaBuffer. Holds IOMMU mapping for cleanup on completion.
pub(crate) struct RxVbufInflight {
    vbuf: VirtioNetRxDmaBuffer,
    /// IOVA mapped through IOMMU for this buffer (None when IOMMU is inactive)
    iommu_iova: Option<u64>,
    /// Size of the IOMMU mapping
    iommu_map_len: u64,
}

/// Queue memory layout calculation result.
pub(crate) struct QueueMemoryLayout {
    desc_size: usize,
    avail_size: usize,
    used_size: usize,
    used_offset: usize,
    header_offset: usize,
    total_size: usize,
}

/// VirtIO ネットワークデバイス
pub struct VirtioNetDevice {
    /// トランスポート層（MMIO/PCI共通インターフェース）
    transport: Box<dyn VirtioTransport>,
    /// 設定
    config: VirtioNetConfig,
    /// VirtIO-Net device index (multi-NIC support)
    pub(crate) virtio_index: u8,
    /// Bound logical network interface id (assigned by NetworkManager)
    pub(crate) net_if_id: Option<crate::net::NetIfId>,
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
    /// 受信用バッファマップ (desc_idx -> RxVbufInflight)
    rx_buffers: Mutex<BTreeMap<u16, RxVbufInflight>>,
    /// 受信用バッファマップ (desc_idx -> RxPacketInflight) - zero-copy posted buffers from mempool
    rx_packetrefs: Mutex<BTreeMap<u16, RxPacketInflight>>,
    /// 送信用 PacketRef インフライトマップ (desc_idx -> TxPacketInflight)
    tx_packetrefs: Mutex<BTreeMap<u16, TxPacketInflight>>,
    /// 送信用インフライトバッファ (desc_idx -> CoherentDmaBuffer)
    tx_inflight: Mutex<BTreeMap<u16, CoherentDmaBuffer>>,
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
            transport,
            config: VirtioNetConfig {
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                max_queues: 1,
                mtu: 1500,
            },
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
            rx_buffers: Mutex::new(BTreeMap::new()),
            rx_packetrefs: Mutex::new(BTreeMap::new()),
            tx_packetrefs: Mutex::new(BTreeMap::new()),
            tx_inflight: Mutex::new(BTreeMap::new()),
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

    /// Bind this VirtIO device to a logical network interface identifier.
    pub fn set_net_if_id(&mut self, if_id: crate::net::NetIfId) {
        self.net_if_id = Some(if_id);
    }

    /// Return the logical network interface identifier, if assigned.
    pub fn net_if_id(&self) -> Option<crate::net::NetIfId> {
        self.net_if_id
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

        // 2. デバイスリセット
        self.transport.reset();

        // 3. ACKNOWLEDGE ステータスビットを設定
        self.transport.set_status(status::VIRTIO_STATUS_ACKNOWLEDGE);

        // 4. DRIVER ステータスビットを設定
        self.transport
            .set_status(status::VIRTIO_STATUS_ACKNOWLEDGE | status::VIRTIO_STATUS_DRIVER);

        // 5. Feature negotiation
        let device_features_low = self.transport.get_device_features_low();
        let device_features_high = self.transport.get_device_features_high();

        // 必要なフィーチャーのみを受け入れる
        let accepted_features_low = device_features_low
            & (features::VIRTIO_NET_F_MAC as u32 | features::VIRTIO_NET_F_CSUM as u32);
        let accepted_features_high = device_features_high;

        self.transport
            .set_driver_features_low(accepted_features_low);
        self.transport
            .set_driver_features_high(accepted_features_high);

        // 6. FEATURES_OK を設定
        self.transport.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE
                | status::VIRTIO_STATUS_DRIVER
                | status::VIRTIO_STATUS_FEATURES_OK,
        );

        // FEATURES_OK が設定されたか確認
        if (self.transport.get_status() & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.transport.set_status(status::VIRTIO_STATUS_FAILED);
            return Err(VirtioNetError::DeviceError);
        }

        // 7. MACアドレスを読み取り
        if (accepted_features_low & features::VIRTIO_NET_F_MAC as u32) != 0 {
            self.config.mac = read_mac_address(self.transport.as_ref());
        }

        // 8. キューの設定
        self.setup_queues()?;

        // 9. DRIVER_OK を設定
        self.transport.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE
                | status::VIRTIO_STATUS_DRIVER
                | status::VIRTIO_STATUS_FEATURES_OK
                | status::VIRTIO_STATUS_DRIVER_OK,
        );

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// VirtQueue を設定。`config.max_queues` に従いキューペアを並列構築する。
    pub(super) fn setup_queues(&mut self) -> Result<(), VirtioNetError> {
        // まずマルチキュー機能を読み取るため、config の max_queues を更新
        if (self.transport.get_device_features_low() & (features::VIRTIO_NET_F_MQ as u32)) != 0 {
            // Virtio ネットワーク設定空間 offset 8 に max_virtqueue_pairs がある
            let pairs = self.transport.read_config_u16(8);
            if pairs > 0 {
                self.config.max_queues = pairs;
            }
        }

        let pair_count = core::cmp::max(self.config.max_queues as usize, 1);
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
    pub(super) fn setup_single_queue(&mut self, queue_index: u16) -> Result<NetVirtQueue, VirtioNetError> {
        // キューを選択
        self.transport.select_queue(queue_index);

        // 最大キューサイズを取得
        let max_size = self.transport.get_queue_max_size();
        if max_size == 0 {
            return Err(VirtioNetError::DeviceError);
        }

        // キューサイズを設定（最大256エントリに制限）
        let queue_size = max_size.min(256);
        self.transport.set_queue_size(queue_size);

        // メモリレイアウトを計算
        let layout = Self::compute_queue_memory_layout(queue_index, queue_size);

        // DMAバッファを割り当て
        let (buffer, dma_len) = self.allocate_queue_dma(layout.total_size)?;

        let phys_base = buffer.phys_addr().as_u64();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(layout.desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(layout.used_offset) as *mut VringUsed };
        let notify_addr = self.transport.get_notify_addr(queue_index);
        let notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        // IOMMU DMAマッピングを設定
        let (dma_base, iommu_map) = self.setup_iommu_dma_mapping(&buffer, dma_len, phys_base)?;

        let (tx_headers, tx_header_dma_base) = if queue_index == 1 {
            let header_ptr = unsafe { ptr.add(layout.header_offset) as *mut VirtioNetHeader };
            let header_dma_base = dma_base + layout.header_offset as u64;
            (Some(SendPtr::new(header_ptr)), Some(header_dma_base))
        } else {
            (None, None)
        };

        // 各リングを初期化
        Self::init_ring_memory(desc_table, avail_ring, used_ring, queue_size, tx_headers);

        // デバイスにアドレスを設定
        let desc_addr = dma_base;
        let avail_addr = dma_base + layout.desc_size as u64;
        let used_addr = dma_base + layout.used_offset as u64;

        crate::io::log::early_print(&alloc::format!(
            "[EARLY][VIRTIO-NET] queue {}: dma_base=0x{:x} desc_size={} avail_size={} used_offset={} used_addr=0x{:x} used_size={}\n",
            queue_index,
            dma_base,
            layout.desc_size,
            layout.avail_size,
            layout.used_offset,
            used_addr,
            layout.used_size
        ));

        self.transport.set_queue_desc_addr(desc_addr);
        self.transport.set_queue_avail_addr(avail_addr);
        self.transport.set_queue_used_addr(used_addr);

        crate::io::log::early_print(&alloc::format!(
            "[EARLY][VIRTIO-NET] set_queue_desc_addr=0x{:x} avail_addr=0x{:x} used_addr=0x{:x}\n",
            desc_addr,
            avail_addr,
            used_addr
        ));

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
            )
        };

        // RXキューの場合は初期バッファを投稿
        if (queue_index % 2) == 0 {
            self.pre_allocate_rx_buffers_for_queue(&queue);
        }

        self.transport.enable_queue();

        Ok(queue)
    }

    /// キューのメモリレイアウトを計算する
    pub(super) fn compute_queue_memory_layout(queue_index: u16, queue_size: u16) -> QueueMemoryLayout {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize;
        let used_size = 6 + 8 * queue_size as usize;

        let used_align = core::mem::align_of::<VringUsed>();
        let used_offset = align_up(desc_size + avail_size, used_align);

        let header_align = core::mem::align_of::<VirtioNetHeader>();
        let header_stride = VirtioNetHeader::SIZE;
        let header_offset = align_up(used_offset + used_size, header_align);
        let header_size = header_stride * queue_size as usize;
        let total_size = if (queue_index % 2) == 1 {
            header_offset + header_size
        } else {
            used_offset + used_size
        };

        QueueMemoryLayout {
            desc_size,
            avail_size,
            used_size,
            used_offset,
            header_offset,
            total_size,
        }
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

    /// リングメモリを初期化する
    pub(super) fn init_ring_memory(
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        queue_size: u16,
        tx_headers: Option<SendPtr<VirtioNetHeader>>,
    ) {
        for i in 0..queue_size {
            unsafe {
                (*desc_table.add(i as usize)) = VringDesc::default();
            }
        }
        unsafe {
            (*avail_ring).flags = 0;
            (*avail_ring).idx = 0;
            (*used_ring).flags = 0;
            (*used_ring).idx = 0;
        }
        if let Some(header_ptr) = tx_headers {
            for i in 0..queue_size {
                unsafe {
                    *header_ptr.as_ptr().add(i as usize) = VirtioNetHeader::default();
                }
            }
        }
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
            match unsafe {
                map_for_device_with_perms(
                    device_id,
                    PhysAddr::new(phys),
                    map_size,
                    false,
                    true,
                )
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
    pub(super) fn try_post_rx_packet(
        &self,
        rxq: &NetVirtQueue,
    ) -> Result<bool, VirtioNetError> {
        let packet = match crate::net::mempool::alloc_packet() {
            Some(p) => p,
            None => return Ok(false),
        };

        let phys = packet.phys_addr().as_u64();
        let buf_len = packet.capacity();

        let (dma_addr, iommu_iova, iommu_map_len) = self.map_buffer_for_rx(phys, buf_len)?;

        match rxq.add_rx_buffer_zero_copy(dma_addr, buf_len) {
            Ok(desc_idx) => {
                log::info!(
                    "[VIRTIO-NET] posted RX PacketRef desc={} dma=0x{:x} len={}",
                    desc_idx,
                    dma_addr,
                    buf_len
                );
                self.rx_packetrefs.lock().insert(desc_idx, RxPacketInflight {
                    packet,
                    iommu_iova,
                    iommu_map_len,
                });
                Ok(true)
            }
            Err(e) => {
                if let (Some(iova), Some(device_id)) = (iommu_iova, &self.iommu_device_id) {
                    let _ = unmap_for_device(device_id, iova, iommu_map_len);
                }
                log::warn!("[VIRTIO-NET] failed to post PacketRef rx buffer: {:?}", e);
                Ok(false)
            }
        }
    }

    /// VirtioNetRxDmaBufferの割り当てとRXキューへのポストを試みる
    ///
    /// Returns: Ok(true) = posted successfully,
    ///          Ok(false) = not posted (continue),
    ///          Err = no more buffers available (stop)
    pub(super) fn try_post_rx_vbuf(
        &self,
        rxq: &NetVirtQueue,
    ) -> Result<bool, VirtioNetError> {
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
                log::info!(
                    "[VIRTIO-NET] posted RX desc={} dma=0x{:x} len={}",
                    desc_idx,
                    dma_addr,
                    buf_len
                );
                self.rx_buffers.lock().insert(desc_idx, RxVbufInflight {
                    vbuf,
                    iommu_iova,
                    iommu_map_len,
                });
                Ok(true)
            }
            Err(e) => {
                if let (Some(iova), Some(device_id)) = (iommu_iova, &self.iommu_device_id) {
                    let _ = unmap_for_device(device_id, iova, iommu_map_len);
                }
                log::warn!("[VIRTIO-NET] failed to add rx buffer: {:?}", e);
                Ok(false)
            }
        }
    }

    /// RXキューにバッファを事前割り当てする（特定キュー版）
    pub(super) fn pre_allocate_rx_buffers_for_queue(&self, rxq: &NetVirtQueue) {
        let mut added = 0usize;
        for _ in 0..8 {
            match self.try_post_rx_packet(rxq) {
                Ok(true) => { added += 1; continue; }
                Ok(false) => {}
                Err(_) => { continue; }
            }
            match self.try_post_rx_vbuf(rxq) {
                Ok(true) => { added += 1; }
                Ok(false) => {}
                Err(_) => { break; }
            }
        }
        log::info!("[VIRTIO-NET] posted {} initial RX buffers", added);
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
