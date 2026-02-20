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
use alloc::sync::Arc;
use spin::RwLock;

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

/// IoScheduler ioctl code for VirtIO-Net TX submit.
pub const VIRTIO_NET_IOCTL_TX: u32 = 0x1001;
/// IoScheduler ioctl code for VirtIO-Net RX submit.
pub const VIRTIO_NET_IOCTL_RX: u32 = 0x1002;

#[derive(Debug, Clone, Copy)]
struct PendingNetRequest {
    io_id: IoRequestId,
    requested_bytes: usize,
}

/// VirtIO ネットワーク PollHandler 実装
pub struct VirtioNetPollHandler {
    /// デバイスへの参照
    device_lock: &'static Mutex<Option<VirtioNetDevice>>,
    /// 保留中RXリクエスト (desc_id -> request)
    pending_rx: Mutex<BTreeMap<u16, PendingNetRequest>>,
    /// 保留中TXリクエスト (desc_id -> request)
    pending_tx: Mutex<BTreeMap<u16, PendingNetRequest>>,
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
    pub fn add_pending_rx(&self, id: IoRequestId, desc_id: u16, requested_bytes: usize) {
        self.pending_rx.lock().insert(
            desc_id,
            PendingNetRequest {
                io_id: id,
                requested_bytes,
            },
        );
    }

    /// TX リクエストを追加
    pub fn add_pending_tx(&self, id: IoRequestId, desc_id: u16, requested_bytes: usize) {
        self.pending_tx.lock().insert(
            desc_id,
            PendingNetRequest {
                io_id: id,
                requested_bytes,
            },
        );
    }

    /// IRQパス向けに pending RX を取り出して削除
    pub fn take_pending_rx(&self, desc_id: u16) -> Option<(IoRequestId, usize)> {
        self.pending_rx
            .lock()
            .remove(&desc_id)
            .map(|req| (req.io_id, req.requested_bytes))
    }

    /// IRQパス向けに pending TX を取り出して削除
    pub fn take_pending_tx(&self, desc_id: u16) -> Option<(IoRequestId, usize)> {
        self.pending_tx
            .lock()
            .remove(&desc_id)
            .map(|req| (req.io_id, req.requested_bytes))
    }

    fn match_rx_completion(
        &self,
        rx_queue: &NetVirtQueue,
        desc_id: u16,
        len: u32,
    ) -> Option<(IoRequestId, IoResult)> {
        let pending = self.pending_rx.lock().remove(&desc_id);
        let Some(req) = pending else {
            log::warn!(
                "[VIRTIO-NET] poll_completions: unmatched RX completion desc={}",
                desc_id
            );
            return None;
        };

        if rx_queue.take_completion(desc_id).is_none() {
            log::warn!(
                "[VIRTIO-NET] poll_completions: RX completion disappeared desc={}",
                desc_id
            );
        }

        let header_size = VirtioNetHeader::SIZE;
        let payload_len = (len as usize).saturating_sub(header_size);
        let payload_cap = req.requested_bytes.saturating_sub(header_size);
        let completed = core::cmp::min(payload_len, payload_cap);
        Some((req.io_id, IoResult::Success(completed)))
    }

    fn match_tx_completion(
        &self,
        tx_queue: &NetVirtQueue,
        desc_id: u16,
    ) -> Option<(IoRequestId, IoResult)> {
        let pending = self.pending_tx.lock().remove(&desc_id);
        let Some(req) = pending else {
            log::warn!(
                "[VIRTIO-NET] poll_completions: unmatched TX completion desc={}",
                desc_id
            );
            return None;
        };

        if tx_queue.take_completion(desc_id).is_none() {
            log::warn!(
                "[VIRTIO-NET] poll_completions: TX completion disappeared desc={}",
                desc_id
            );
        }

        Some((req.io_id, IoResult::Success(req.requested_bytes)))
    }

    #[cfg(test)]
    fn pending_rx_len(&self) -> usize {
        self.pending_rx.lock().len()
    }

    #[cfg(test)]
    fn pending_tx_len(&self) -> usize {
        self.pending_tx.lock().len()
    }
}

impl PollHandler for VirtioNetPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();

        if let Some(ref device) = *self.device_lock.lock() {
            if let Some(ref rx_queue) = device.rx_queue {
                for (desc_id, len) in rx_queue.process_used() {
                    if let Some(result) = self.match_rx_completion(rx_queue, desc_id, len) {
                        results.push(result);
                    }
                }
            }

            if let Some(ref tx_queue) = device.tx_queue {
                for (desc_id, _len) in tx_queue.process_used() {
                    if let Some(result) = self.match_tx_completion(tx_queue, desc_id) {
                        results.push(result);
                    }
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

fn map_virtio_net_error(err: VirtioNetError) -> crate::io::io_scheduler::IoError {
    match err {
        VirtioNetError::QueueFull => crate::io::io_scheduler::IoError::NoResources,
        VirtioNetError::BufferTooSmall => crate::io::io_scheduler::IoError::InvalidParameter,
        VirtioNetError::NotInitialized => crate::io::io_scheduler::IoError::NoResources,
        VirtioNetError::Timeout => crate::io::io_scheduler::IoError::Timeout,
        VirtioNetError::DeviceError => crate::io::io_scheduler::IoError::DeviceError,
    }
}

/// IoScheduler 向け VirtIO-Net DeviceOps 実装
pub struct VirtioNetOps {
    device_index: u8,
    handler: Arc<VirtioNetPollHandler>,
}

impl VirtioNetOps {
    pub fn new(device_index: u8, handler: Arc<VirtioNetPollHandler>) -> Self {
        Self {
            device_index,
            handler,
        }
    }

    fn submit_ioctl(
        &self,
        io_id: IoRequestId,
        code: u32,
        buf: crate::io::io_scheduler::DmaBufHandle,
    ) -> Result<(), crate::io::io_scheduler::IoError> {
        let _ = self.device_index;

        let device_guard = self.handler.device_lock.lock();
        let device = device_guard
            .as_ref()
            .ok_or(crate::io::io_scheduler::IoError::NoResources)?;

        match code {
            VIRTIO_NET_IOCTL_TX => {
                let tx_queue = device
                    .tx_queue
                    .as_ref()
                    .ok_or(crate::io::io_scheduler::IoError::NoResources)?;
                let desc_id = tx_queue
                    .add_tx_buffer_zero_copy(buf.iova, buf.len)
                    .map_err(map_virtio_net_error)?;
                self.handler.add_pending_tx(io_id, desc_id, buf.len);
                tx_queue.notify();
                Ok(())
            }
            VIRTIO_NET_IOCTL_RX => {
                if buf.len < VirtioNetHeader::SIZE {
                    return Err(crate::io::io_scheduler::IoError::InvalidParameter);
                }
                let rx_queue = device
                    .rx_queue
                    .as_ref()
                    .ok_or(crate::io::io_scheduler::IoError::NoResources)?;
                let desc_id = rx_queue
                    .add_rx_buffer_zero_copy(buf.iova, buf.len)
                    .map_err(map_virtio_net_error)?;
                self.handler.add_pending_rx(io_id, desc_id, buf.len);
                rx_queue.notify();
                Ok(())
            }
            _ => Err(crate::io::io_scheduler::IoError::NotSupported),
        }
    }
}

impl crate::io::io_scheduler::DeviceOps for VirtioNetOps {
    fn submit(
        &self,
        req: &crate::io::io_scheduler::IoRequest,
        _cpu_idx: usize,
    ) -> Result<(), crate::io::io_scheduler::IoError> {
        let cmd = req
            .command
            .as_ref()
            .ok_or(crate::io::io_scheduler::IoError::NotSupported)?;

        match cmd {
            crate::io::io_scheduler::IoCommand::Ioctl { code, buf } => {
                self.submit_ioctl(req.id, *code, *buf)
            }
            _ => Err(crate::io::io_scheduler::IoError::NotSupported),
        }
    }

    fn is_ready(&self) -> bool {
        self.handler.is_ready()
    }
}

struct VirtioNetPollHandlerWrapper {
    inner: Arc<VirtioNetPollHandler>,
}

impl PollHandler for VirtioNetPollHandlerWrapper {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        self.inner.poll_completions()
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}

/// グローバル PollHandler レジストリ (device_index -> handler)
static VIRTIO_NET_POLL_HANDLERS: RwLock<BTreeMap<u8, Arc<VirtioNetPollHandler>>> =
    RwLock::new(BTreeMap::new());

/// 指定デバイスの PollHandler を取得（IRQ完了連携で使用）
pub fn get_poll_handler(index: u8) -> Option<Arc<VirtioNetPollHandler>> {
    VIRTIO_NET_POLL_HANDLERS.read().get(&index).cloned()
}

#[cfg(test)]
pub(crate) fn clear_poll_handler_registry_for_tests() {
    VIRTIO_NET_POLL_HANDLERS.write().clear();
}

/// VirtIO ネットワークを IoScheduler に登録（依存注入版）
pub fn register_virtio_net_with(
    coordinator: &alloc::sync::Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    index: u8,
) {
    let device_id = DeviceId::VirtioNet { index };
    let handler = Arc::new(VirtioNetPollHandler::new());

    coordinator.polling_executor().register_handler(
        device_id,
        Box::new(VirtioNetPollHandlerWrapper {
            inner: handler.clone(),
        }),
    );

    VIRTIO_NET_POLL_HANDLERS.write().insert(index, handler.clone());

    crate::io::io_scheduler::io_scheduler()
        .register_device_ops(device_id, Arc::new(VirtioNetOps::new(index, handler)));
}

/// VirtIO ネットワークを IoScheduler に登録（後方互換wrapper）
pub fn register_virtio_net_with_io_scheduler(index: u8) {
    register_virtio_net_with(&hybrid_coordinator(), index);
}

#[cfg(test)]
mod io_scheduler_tests {
    use super::*;
    use crate::io::io_scheduler::{
        DeviceId, DeviceOps, DmaBufHandle, IoCommand, IoOperationType, IoPriority, IoRequest,
        IoRequestId, IoResult, IoState,
    };
    use crate::io::virtio::{TransportType, VirtioDeviceType, VirtioTransport};

    struct TestTransport;

    impl VirtioTransport for TestTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Network
        }
        fn get_status(&self) -> u8 {
            0
        }
        fn set_status(&mut self, _status: u8) {}
        fn get_device_features_low(&self) -> u32 {
            0
        }
        fn get_device_features_high(&self) -> u32 {
            0
        }
        fn set_driver_features_low(&mut self, _features: u32) {}
        fn set_driver_features_high(&mut self, _features: u32) {}
        fn get_num_queues(&self) -> u16 {
            2
        }
        fn select_queue(&mut self, _queue_index: u16) {}
        fn get_queue_max_size(&self) -> u16 {
            16
        }
        fn set_queue_size(&mut self, _size: u16) {}
        fn is_queue_ready(&self) -> bool {
            false
        }
        fn enable_queue(&mut self) {}
        fn disable_queue(&mut self) {}
        fn set_queue_desc_addr(&mut self, _addr: u64) {}
        fn set_queue_avail_addr(&mut self, _addr: u64) {}
        fn set_queue_used_addr(&mut self, _addr: u64) {}
        fn notify_queue(&mut self, _queue_index: u16) {}
        fn get_notify_addr(&mut self, _queue_index: u16) -> Option<u64> {
            None
        }
        fn get_interrupt_status(&self) -> u32 {
            0
        }
        fn ack_interrupt(&self, _status: u32) {}
        fn read_config_u8(&self, _offset: usize) -> u8 {
            0
        }
        fn read_config_u16(&self, _offset: usize) -> u16 {
            0
        }
        fn read_config_u32(&self, _offset: usize) -> u32 {
            0
        }
        fn write_config_u8(&mut self, _offset: usize, _value: u8) {}
        fn write_config_u16(&mut self, _offset: usize, _value: u16) {}
        fn write_config_u32(&mut self, _offset: usize, _value: u32) {}
        fn transport_type(&self) -> TransportType {
            TransportType::Mmio
        }
    }

    struct TestStateGuard {
        prev_device: Option<VirtioNetDevice>,
        prev_handlers: BTreeMap<u8, Arc<VirtioNetPollHandler>>,
    }

    impl TestStateGuard {
        fn new_with_device() -> Self {
            let prev_device = VIRTIO_NET_DEVICE.lock().take();
            let mut handlers = VIRTIO_NET_POLL_HANDLERS.write();
            let prev_handlers = core::mem::take(&mut *handlers);
            drop(handlers);

            let mut device = VirtioNetDevice::new(Box::new(TestTransport));
            assert!(device.init().is_ok());
            *VIRTIO_NET_DEVICE.lock() = Some(device);

            Self {
                prev_device,
                prev_handlers,
            }
        }
    }

    impl Drop for TestStateGuard {
        fn drop(&mut self) {
            *VIRTIO_NET_DEVICE.lock() = self.prev_device.take();
            *VIRTIO_NET_POLL_HANDLERS.write() = core::mem::take(&mut self.prev_handlers);
        }
    }

    fn build_ioctl_request(id: IoRequestId, code: u32, iova: u64, len: usize) -> IoRequest {
        IoRequest {
            id,
            device: DeviceId::VirtioNet { index: 0 },
            operation: IoOperationType::Ioctl,
            command: Some(IoCommand::Ioctl {
                code,
                buf: DmaBufHandle { iova, len },
            }),
            priority: IoPriority::Normal,
            state: IoState::Pending,
            submitted_at: 0,
            completed_at: None,
            waker: None,
            result: None,
            abandoned: false,
        }
    }

    #[test_case]
    fn test_poll_completions_empty_without_pending() {
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();
        assert!(handler.poll_completions().is_empty());
    }

    #[test_case]
    fn test_poll_completions_matches_tx_pending() {
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();
        let io_id = IoRequestId(1001);

        let desc_id = {
            let guard = VIRTIO_NET_DEVICE.lock();
            let device = guard.as_ref().expect("device");
            let tx_queue = device.tx_queue.as_ref().expect("tx queue");
            let desc_id = tx_queue
                .add_tx_buffer_zero_copy(0x4000, 64)
                .expect("tx submit");
            unsafe {
                let used = &mut *tx_queue.used_ring.as_ptr();
                let slot = (used.idx % tx_queue.size) as usize;
                used.ring[slot] = VringUsedElem {
                    id: desc_id as u32,
                    len: 64,
                };
                used.idx = used.idx.wrapping_add(1);
            }
            desc_id
        };

        handler.add_pending_tx(io_id, desc_id, 64);
        let results = handler.poll_completions();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, io_id);
        assert_eq!(results[0].1, IoResult::Success(64));

        let guard = VIRTIO_NET_DEVICE.lock();
        let device = guard.as_ref().expect("device");
        let tx_queue = device.tx_queue.as_ref().expect("tx queue");
        assert!(tx_queue.take_completion(desc_id).is_none());
    }

    #[test_case]
    fn test_poll_completions_matches_rx_pending_payload_len() {
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();
        let io_id = IoRequestId(1002);
        let total_buf_len = VirtioNetHeader::SIZE + 128;
        let used_len = (VirtioNetHeader::SIZE + 42) as u32;

        let desc_id = {
            let guard = VIRTIO_NET_DEVICE.lock();
            let device = guard.as_ref().expect("device");
            let rx_queue = device.rx_queue.as_ref().expect("rx queue");
            let desc_id = rx_queue
                .add_rx_buffer_zero_copy(0x5000, total_buf_len)
                .expect("rx submit");
            unsafe {
                let used = &mut *rx_queue.used_ring.as_ptr();
                let slot = (used.idx % rx_queue.size) as usize;
                used.ring[slot] = VringUsedElem {
                    id: desc_id as u32,
                    len: used_len,
                };
                used.idx = used.idx.wrapping_add(1);
            }
            desc_id
        };

        handler.add_pending_rx(io_id, desc_id, total_buf_len);
        let results = handler.poll_completions();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, io_id);
        assert_eq!(results[0].1, IoResult::Success(42));

        let guard = VIRTIO_NET_DEVICE.lock();
        let device = guard.as_ref().expect("device");
        let rx_queue = device.rx_queue.as_ref().expect("rx queue");
        assert!(rx_queue.take_completion(desc_id).is_none());
    }

    #[test_case]
    fn test_virtio_net_ops_rejects_unsupported_ioctl() {
        let _guard = TestStateGuard::new_with_device();
        let handler = Arc::new(VirtioNetPollHandler::new());
        let ops = VirtioNetOps::new(0, handler);
        let req = build_ioctl_request(IoRequestId(2001), 0xDEAD, 0x1000, 128);

        let err = ops.submit(&req, 0).expect_err("unsupported ioctl should fail");
        assert_eq!(err, crate::io::io_scheduler::IoError::NotSupported);
    }

    #[test_case]
    fn test_virtio_net_ops_submit_tracks_tx_and_rx_pending() {
        let _guard = TestStateGuard::new_with_device();
        let handler = Arc::new(VirtioNetPollHandler::new());
        let ops = VirtioNetOps::new(0, handler.clone());

        let tx_req = build_ioctl_request(IoRequestId(2002), VIRTIO_NET_IOCTL_TX, 0x6000, 96);
        assert!(ops.submit(&tx_req, 0).is_ok());
        assert_eq!(handler.pending_tx_len(), 1);
        assert!(handler
            .pending_tx
            .lock()
            .values()
            .any(|req| req.io_id == tx_req.id));

        let rx_len = VirtioNetHeader::SIZE + 96;
        let rx_req = build_ioctl_request(IoRequestId(2003), VIRTIO_NET_IOCTL_RX, 0x7000, rx_len);
        assert!(ops.submit(&rx_req, 0).is_ok());
        assert_eq!(handler.pending_rx_len(), 1);
        assert!(handler
            .pending_rx
            .lock()
            .values()
            .any(|req| req.io_id == rx_req.id));
    }
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
