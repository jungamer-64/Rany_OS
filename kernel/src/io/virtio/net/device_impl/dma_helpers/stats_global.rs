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

/// Primary (legacy) VirtIO-Net device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_NET_DEVICE: Mutex<Option<VirtioNetDevice>> = Mutex::new(None);
/// Additional VirtIO-Net devices (`index != 0`).
pub(crate) static VIRTIO_NET_DEVICES: RwLock<BTreeMap<u8, Arc<Mutex<VirtioNetDevice>>>> =
    RwLock::new(BTreeMap::new());

fn install_virtio_net_device(index: u8, device: VirtioNetDevice) {
    if index == 0 {
        *VIRTIO_NET_DEVICE.lock() = Some(device);
    } else {
        VIRTIO_NET_DEVICES
            .write()
            .insert(index, Arc::new(Mutex::new(device)));
    }
}

fn with_virtio_net_device_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    if index == 0 {
        return VIRTIO_NET_DEVICE.lock().as_ref().map(f);
    }

    let device = VIRTIO_NET_DEVICES.read().get(&index).cloned()?;
    let guard = device.lock();
    Some(f(&guard))
}

fn with_virtio_net_device_at_index_mut<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&mut VirtioNetDevice) -> R,
{
    if index == 0 {
        let mut guard = VIRTIO_NET_DEVICE.lock();
        return guard.as_mut().map(f);
    }

    let device = VIRTIO_NET_DEVICES.read().get(&index).cloned()?;
    let mut guard = device.lock();
    Some(f(&mut guard))
}

fn has_virtio_net_device(index: u8) -> bool {
    if index == 0 {
        return VIRTIO_NET_DEVICE.lock().is_some();
    }
    VIRTIO_NET_DEVICES.read().contains_key(&index)
}

fn collect_registered_virtio_net_indices() -> Vec<u8> {
    let mut indices = Vec::new();
    if VIRTIO_NET_DEVICE.lock().is_some() {
        indices.push(0);
    }
    indices.extend(VIRTIO_NET_DEVICES.read().keys().copied());
    indices
}

/// VirtIO ネットワークデバイス（MMIO）を index 指定で初期化
///
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net_at_index(index: u8, base_addr: usize) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new_at_index(index, Box::new(transport));
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

/// VirtIO ネットワークデバイス（MMIO）を初期化
///
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net(base_addr: usize) -> Result<(), VirtioNetError> {
    init_virtio_net_at_index(0, base_addr)
}

/// VirtIO ネットワークデバイス（MMIO）を index + IOMMUデバイスID指定で初期化
///
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net_for_device_at_index(
    index: u8,
    base_addr: usize,
    device: IommuDeviceId,
) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device =
        VirtioNetDevice::new_with_index_and_device(index, Box::new(transport), Some(device));
    device.init()?;
    install_virtio_net_device(index, device);
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
    init_virtio_net_for_device_at_index(0, base_addr, device)
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI).
///
/// `iommu_device_id` must be provided when IOMMU is enabled (strict mode).
pub fn init_virtio_net_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new_with_index_and_device(index, transport, iommu_device_id);
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI).
///
/// Compatibility wrapper for `index=0`.
pub fn init_virtio_net_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: Option<IommuDeviceId>,
) -> Result<(), VirtioNetError> {
    init_virtio_net_with_transport_at_index(0, transport, iommu_device_id)
}

/// VirtIO ネットワークデバイスに index 指定でアクセス
pub fn with_virtio_net_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    with_virtio_net_device_at_index(index, f)
}

/// Bind a VirtIO-Net device index to a logical network interface id.
///
/// Returns `true` if the device exists and was updated.
pub fn bind_virtio_net_interface(index: u8, if_id: crate::net::NetIfId) -> bool {
    with_virtio_net_device_at_index_mut(index, |device| {
        device.set_net_if_id(if_id);
    })
    .is_some()
}

/// 登録済み VirtIO-Net デバイスを列挙して処理する。
pub fn for_each_virtio_net<F>(mut f: F)
where
    F: FnMut(u8, &VirtioNetDevice),
{
    let indices = collect_registered_virtio_net_indices();
    for index in indices {
        let _ = with_virtio_net_device_at_index(index, |device| {
            f(index, device);
        });
    }
}

/// VirtIO ネットワークデバイスにアクセス
pub fn with_virtio_net<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    with_virtio_net_device_at_index(0, f)
}

/// 指定 index の VirtIO-Net 割り込みを処理する。
pub fn handle_virtio_net_interrupt_for_index(index: u8) {
    let _ = with_virtio_net_device_at_index(index, |device| {
        let status = device.transport.get_interrupt_status();
        crate::io::log::early_print(&alloc::format!(
            "[EARLY][VIRTIO-NET] IRQ status read index={} status=0x{:x}\n",
            index, status
        ));
        device.transport.ack_interrupt(status);
        device.handle_interrupt();
    });
}

/// 登録済みの全 VirtIO-Net デバイス割り込みを処理する（共有IRQ向け）。
pub fn handle_all_virtio_net_interrupts() {
    let indices = collect_registered_virtio_net_indices();
    for index in indices {
        handle_virtio_net_interrupt_for_index(index);
    }
}

/// 割り込みハンドラ
pub fn handle_virtio_net_interrupt() {
    handle_all_virtio_net_interrupts();
}

#[cfg(test)]
#[path = "../../tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn clear_virtio_net_devices_for_tests() {
    *VIRTIO_NET_DEVICE.lock() = None;
    VIRTIO_NET_DEVICES.write().clear();
}

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
    /// 対象 VirtIO-Net device index
    device_index: u8,
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
        Self::new_for_index(0)
    }

    /// 指定 index 用の VirtioNetPollHandler を作成
    pub fn new_for_index(device_index: u8) -> Self {
        Self {
            device_index,
            pending_rx: Mutex::new(BTreeMap::new()),
            pending_tx: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }

    fn with_device<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&VirtioNetDevice) -> R,
    {
        with_virtio_net_device_at_index(self.device_index, f)
    }

    fn is_device_ready(&self) -> bool {
        has_virtio_net_device(self.device_index)
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

    fn route_scheduler_rx_completion(
        &self,
        rx_queue: &NetVirtQueue,
        desc_id: u16,
    ) -> Option<(IoRequestId, IoResult)> {
        let pending = self.pending_rx.lock().remove(&desc_id);
        let Some(req) = pending else { return None };

        let completion_len = match rx_queue.take_completion(desc_id) {
            Some(completion_len) => completion_len,
            None => {
                log::warn!(
                    "[VIRTIO-NET] poll_completions: RX completion disappeared desc={}",
                    desc_id
                );
                return Some((
                    req.io_id,
                    IoResult::Error(crate::io::io_scheduler::IoError::DeviceError),
                ));
            }
        };

        let header_size = VirtioNetHeader::SIZE;
        let payload_len = (completion_len as usize).saturating_sub(header_size);
        let payload_cap = req.requested_bytes.saturating_sub(header_size);
        let completed = core::cmp::min(payload_len, payload_cap);
        Some((req.io_id, IoResult::Success(completed)))
    }

    fn route_scheduler_tx_completion(
        &self,
        tx_queue: &NetVirtQueue,
        desc_id: u16,
    ) -> Option<(IoRequestId, IoResult)> {
        let pending = self.pending_tx.lock().remove(&desc_id);
        let Some(req) = pending else { return None };

        if tx_queue.take_completion(desc_id).is_none() {
            log::warn!(
                "[VIRTIO-NET] poll_completions: TX completion disappeared desc={}",
                desc_id
            );
            return Some((
                req.io_id,
                IoResult::Error(crate::io::io_scheduler::IoError::DeviceError),
            ));
        }

        Some((req.io_id, IoResult::Success(req.requested_bytes)))
    }

    fn route_legacy_rx_completion(
        &self,
        device: &VirtioNetDevice,
        rx_queue: &NetVirtQueue,
        desc_id: u16,
        len: u32,
    ) -> bool {
        device.handle_legacy_rx_completion(rx_queue, desc_id, len)
    }

    fn route_legacy_tx_completion(
        &self,
        device: &VirtioNetDevice,
        tx_queue: &NetVirtQueue,
        desc_id: u16,
        len: u32,
    ) -> bool {
        device.handle_legacy_tx_completion(tx_queue, desc_id, len)
    }

    fn release_unknown_rx_completion(
        &self,
        device: &VirtioNetDevice,
        rx_queue: &NetVirtQueue,
        desc_id: u16,
    ) {
        device.release_unknown_rx_completion(rx_queue, desc_id);
    }

    fn release_unknown_tx_completion(
        &self,
        device: &VirtioNetDevice,
        tx_queue: &NetVirtQueue,
        desc_id: u16,
    ) {
        device.release_unknown_tx_completion(tx_queue, desc_id);
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
        self.with_device(|device| {
            let mut results = Vec::new();
            if let Some(rx_queue) = device.first_rx_queue() {
                for (desc_id, len) in rx_queue.process_used() {
                    device.rx_packets.fetch_add(1, Ordering::Relaxed);

                    if let Some(result) = self.route_scheduler_rx_completion(rx_queue, desc_id)
                    {
                        results.push(result);
                        continue;
                    }

                    if self.route_legacy_rx_completion(device, rx_queue, desc_id, len) {
                        continue;
                    }

                    self.release_unknown_rx_completion(device, rx_queue, desc_id);
                }
            }

            let mut tx_completed = false;
            if let Some(tx_queue) = device.first_tx_queue() {
                for (desc_id, len) in tx_queue.process_used() {
                    tx_completed = true;
                    device.tx_packets.fetch_add(1, Ordering::Relaxed);
                    device.tx_bytes.fetch_add(len, Ordering::Relaxed);

                    if let Some(result) = self.route_scheduler_tx_completion(tx_queue, desc_id) {
                        results.push(result);
                        continue;
                    }

                    if self.route_legacy_tx_completion(device, tx_queue, desc_id, len) {
                        continue;
                    }

                    self.release_unknown_tx_completion(device, tx_queue, desc_id);
                }
            }

            if tx_completed {
                crate::net::endpoint::event::send_event_ignore(
                    crate::net::endpoint::event::NetworkEvent::TxAvailable,
                );
            }
            results
        })
        .unwrap_or_default()
    }

    fn is_ready(&self) -> bool {
        self.is_device_ready()
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
        self.handler
            .with_device(|device| match code {
                VIRTIO_NET_IOCTL_TX => {
                    if device.virtio_index != self.device_index {
                        return Err(crate::io::io_scheduler::IoError::DeviceError);
                    }
                    let tx_queue = device
                        .first_tx_queue()
                        .ok_or(crate::io::io_scheduler::IoError::NoResources)?;
                    let desc_id = tx_queue
                        .add_tx_buffer_zero_copy(buf.iova, buf.len)
                        .map_err(map_virtio_net_error)?;
                    self.handler.add_pending_tx(io_id, desc_id, buf.len);
                    tx_queue.notify();
                    Ok(())
                }
                VIRTIO_NET_IOCTL_RX => {
                    if device.virtio_index != self.device_index {
                        return Err(crate::io::io_scheduler::IoError::DeviceError);
                    }
                    if buf.len < VirtioNetHeader::SIZE {
                        return Err(crate::io::io_scheduler::IoError::InvalidParameter);
                    }
                    let rx_queue = device
                        .first_rx_queue()
                        .ok_or(crate::io::io_scheduler::IoError::NoResources)?;
                    let desc_id = rx_queue
                        .add_rx_buffer_zero_copy(buf.iova, buf.len)
                        .map_err(map_virtio_net_error)?;
                    self.handler.add_pending_rx(io_id, desc_id, buf.len);
                    rx_queue.notify();
                    Ok(())
                }
                _ => Err(crate::io::io_scheduler::IoError::NotSupported),
            })
            .ok_or(crate::io::io_scheduler::IoError::NoResources)?
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

/// 指定デバイスの PollHandler を取得（IRQ完了連携で使用）。
///
/// - 未登録 index の場合は `None` を返す。
/// - 登録済み index の場合は、登録時と同一ハンドラ参照（`Arc` クローン）を返す。
pub fn get_poll_handler(index: u8) -> Option<Arc<VirtioNetPollHandler>> {
    VIRTIO_NET_POLL_HANDLERS.read().get(&index).cloned()
}

#[cfg(test)]
pub(crate) fn clear_poll_handler_registry_for_tests() {
    VIRTIO_NET_POLL_HANDLERS.write().clear();
}

/// VirtIO ネットワークを IoScheduler に登録（依存注入版）。
///
/// 同じ `index` の再登録は no-op で成功し、既存の PollHandler / DeviceOps を維持する。
pub fn register_virtio_net_with(
    coordinator: &alloc::sync::Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    index: u8,
) {
    let device_id = DeviceId::VirtioNet { index };

    if VIRTIO_NET_POLL_HANDLERS.read().contains_key(&index) {
        return;
    }

    let handler = Arc::new(VirtioNetPollHandler::new_for_index(index));
    {
        let mut handlers = VIRTIO_NET_POLL_HANDLERS.write();
        if handlers.contains_key(&index) {
            return;
        }
        handlers.insert(index, handler.clone());
    }

    coordinator.polling_executor().register_handler(
        device_id,
        Box::new(VirtioNetPollHandlerWrapper {
            inner: handler.clone(),
        }),
    );

    crate::io::io_scheduler::io_scheduler()
        .register_device_ops(device_id, Arc::new(VirtioNetOps::new(index, handler)));
}

/// VirtIO ネットワークを IoScheduler に opt-in 登録（後方互換 wrapper）。
///
/// `system_impl` からは自動呼び出しされないため、運用で有効化する場合は
/// 明示的にこの関数を呼ぶ。
///
/// # Examples
/// ```ignore
/// use crate::io::io_scheduler::{DeviceId, IoCommand, IoPriority, DmaBufHandle, hybrid_coordinator};
/// use crate::io::virtio::{
///     register_virtio_net_with_io_scheduler, VIRTIO_NET_IOCTL_RX, VIRTIO_NET_IOCTL_TX,
/// };
///
/// register_virtio_net_with_io_scheduler(0);
///
/// let _tx = hybrid_coordinator().submit_io_command(
///     DeviceId::VirtioNet { index: 0 },
///     IoCommand::Ioctl {
///         code: VIRTIO_NET_IOCTL_TX,
///         buf: DmaBufHandle { iova: 0x1000, len: 2048 },
///     },
///     IoPriority::Normal,
/// );
///
/// let _rx = hybrid_coordinator().submit_io_command(
///     DeviceId::VirtioNet { index: 0 },
///     IoCommand::Ioctl {
///         code: VIRTIO_NET_IOCTL_RX,
///         buf: DmaBufHandle { iova: 0x2000, len: 2048 },
///     },
///     IoPriority::Normal,
/// );
/// ```
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
        prev_devices: BTreeMap<u8, Arc<Mutex<VirtioNetDevice>>>,
        prev_handlers: BTreeMap<u8, Arc<VirtioNetPollHandler>>,
    }

    impl TestStateGuard {
        fn new_with_device() -> Self {
            let prev_device = VIRTIO_NET_DEVICE.lock().take();
            let mut devices = VIRTIO_NET_DEVICES.write();
            let prev_devices = core::mem::take(&mut *devices);
            drop(devices);
            let mut handlers = VIRTIO_NET_POLL_HANDLERS.write();
            let prev_handlers = core::mem::take(&mut *handlers);
            drop(handlers);

            let mut device = VirtioNetDevice::new(Box::new(TestTransport));
            assert!(device.init().is_ok());
            *VIRTIO_NET_DEVICE.lock() = Some(device);

            Self {
                prev_device,
                prev_devices,
                prev_handlers,
            }
        }
    }

    impl Drop for TestStateGuard {
        fn drop(&mut self) {
            *VIRTIO_NET_DEVICE.lock() = self.prev_device.take();
            *VIRTIO_NET_DEVICES.write() = core::mem::take(&mut self.prev_devices);
            *VIRTIO_NET_POLL_HANDLERS.write() = core::mem::take(&mut self.prev_handlers);
        }
    }

    fn install_test_device_at_index(index: u8) {
        let mut device = VirtioNetDevice::new_at_index(index, Box::new(TestTransport));
        assert!(device.init().is_ok());
        if index == 0 {
            *VIRTIO_NET_DEVICE.lock() = Some(device);
        } else {
            VIRTIO_NET_DEVICES
                .write()
                .insert(index, Arc::new(Mutex::new(device)));
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
    fn test_poll_handlers_do_not_cross_consume_between_indices() {
        let _guard = TestStateGuard::new_with_device();
        install_test_device_at_index(1);

        let handler0 = VirtioNetPollHandler::new_for_index(0);
        let handler1 = VirtioNetPollHandler::new_for_index(1);
        let io_id = IoRequestId(1101);

        let desc_id = {
            let device_lock = VIRTIO_NET_DEVICES
                .read()
                .get(&1)
                .cloned()
                .expect("device index 1");
            let guard = device_lock.lock();
            let device = &*guard;
            let tx_queue = device.first_tx_queue().expect("tx queue");
            let desc_id = tx_queue
                .add_tx_buffer_zero_copy(0x4100, 64)
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

        handler1.add_pending_tx(io_id, desc_id, 64);

        assert!(handler0.poll_completions().is_empty());

        let results = handler1.poll_completions();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, io_id);
        assert_eq!(results[0].1, IoResult::Success(64));
    }

    #[test_case]
    fn test_bind_virtio_net_interface_updates_device_binding() {
        let _guard = TestStateGuard::new_with_device();
        install_test_device_at_index(1);
        let if_id = crate::net::NetIfId(77);

        assert!(bind_virtio_net_interface(1, if_id));
        assert_eq!(
            with_virtio_net_at_index(1, |device| device.net_if_id()),
            Some(Some(if_id))
        );
        assert!(!bind_virtio_net_interface(42, if_id));
    }

    #[test_case]
    fn test_poll_completions_matches_tx_pending() {
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();
        let io_id = IoRequestId(1001);

        let desc_id = {
            let guard = VIRTIO_NET_DEVICE.lock();
            let device = guard.as_ref().expect("device");
            let tx_queue = device.first_tx_queue().expect("tx queue");
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
    fn test_poll_completions_routes_legacy_tx_without_result() {
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();

        let desc_id = {
            let guard = VIRTIO_NET_DEVICE.lock();
            let device = guard.as_ref().expect("device");
            let tx_queue = device.first_tx_queue().expect("tx queue");
            let desc_id = tx_queue
                .add_tx_buffer_zero_copy(0x4200, 64)
                .expect("tx submit");
            let inflight = CoherentDmaBuffer::new(64, DmaMemoryAttributes::MMIO)
                .expect("inflight buffer");
            device.tx_inflight.lock().insert(desc_id, inflight);
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

        let results = handler.poll_completions();
        assert!(results.is_empty());

        let guard = VIRTIO_NET_DEVICE.lock();
        let device = guard.as_ref().expect("device");
        assert!(!device.tx_inflight.lock().contains_key(&desc_id));
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
            let rx_queue = device.first_rx_queue().expect("rx queue");
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
        let rx_queue = device.first_rx_queue().expect("rx queue");
        assert!(rx_queue.take_completion(desc_id).is_none());
    }

    #[test_case]
    fn test_poll_completions_routes_legacy_rx_to_bridge() {
        let _ = crate::net::mempool::init_net_mempool(4);
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();
        let payload = b"poll-legacy-rx";
        let header_size = VirtioNetHeader::SIZE;
        let before = crate::net::driver_bridge::get_bridge_stats().rx_packets;

        let desc_id = {
            let guard = VIRTIO_NET_DEVICE.lock();
            let device = guard.as_ref().expect("device");
            let rx_queue = device.first_rx_queue().expect("rx queue");
            assert!(device.try_post_rx_packet(rx_queue).expect("post packet"));
            let desc_id = {
                let map = device.rx_packetrefs.lock();
                *map.keys().next().expect("posted PacketRef")
            };
            {
                let mut map = device.rx_packetrefs.lock();
                let inflight = map.get_mut(&desc_id).expect("inflight");
                let packet_data = inflight.packet.data_mut();
                packet_data[..header_size].fill(0);
                let start = header_size;
                packet_data[start..start + payload.len()].copy_from_slice(payload);
            }
            unsafe {
                let used = &mut *rx_queue.used_ring.as_ptr();
                let slot = (used.idx % rx_queue.size) as usize;
                used.ring[slot] = VringUsedElem {
                    id: desc_id as u32,
                    len: (header_size + payload.len()) as u32,
                };
                used.idx = used.idx.wrapping_add(1);
            }
            desc_id
        };

        let results = handler.poll_completions();
        assert!(results.is_empty());

        let after = crate::net::driver_bridge::get_bridge_stats().rx_packets;
        assert!(after >= before + 1, "bridge did not observe legacy RX packet");

        let guard = VIRTIO_NET_DEVICE.lock();
        let device = guard.as_ref().expect("device");
        assert!(!device.rx_packetrefs.lock().contains_key(&desc_id));
        let rx_queue = device.first_rx_queue().expect("rx queue");
        assert!(rx_queue.take_completion(desc_id).is_none());
    }

    #[test_case]
    fn test_poll_completions_releases_unknown_tx_completion() {
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();

        let desc_id = {
            let guard = VIRTIO_NET_DEVICE.lock();
            let device = guard.as_ref().expect("device");
            let tx_queue = device.first_tx_queue().expect("tx queue");
            let desc_id = tx_queue
                .add_tx_buffer_zero_copy(0x4600, 64)
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

        let results = handler.poll_completions();
        assert!(results.is_empty());

        let guard = VIRTIO_NET_DEVICE.lock();
        let device = guard.as_ref().expect("device");
        let tx_queue = device.tx_queue.as_ref().expect("tx queue");
        assert!(tx_queue.take_completion(desc_id).is_none());
    }

    #[test_case]
    fn test_poll_completions_releases_unknown_rx_completion() {
        let _guard = TestStateGuard::new_with_device();
        let handler = VirtioNetPollHandler::new();

        let desc_id = {
            let guard = VIRTIO_NET_DEVICE.lock();
            let device = guard.as_ref().expect("device");
            let rx_queue = device.first_rx_queue().expect("rx queue");
            let desc_id = rx_queue
                .add_rx_buffer_zero_copy(0x4800, VirtioNetHeader::SIZE + 64)
                .expect("rx submit");
            unsafe {
                let used = &mut *rx_queue.used_ring.as_ptr();
                let slot = (used.idx % rx_queue.size) as usize;
                used.ring[slot] = VringUsedElem {
                    id: desc_id as u32,
                    len: (VirtioNetHeader::SIZE + 16) as u32,
                };
                used.idx = used.idx.wrapping_add(1);
            }
            desc_id
        };

        let results = handler.poll_completions();
        assert!(results.is_empty());

        let guard = VIRTIO_NET_DEVICE.lock();
        let device = guard.as_ref().expect("device");
        let rx_queue = device.first_rx_queue().expect("rx queue");
        assert!(rx_queue.take_completion(desc_id).is_none());
    }

    #[test_case]
    fn test_register_virtio_net_with_is_idempotent() {
        crate::io::io_scheduler::init_io_scheduler();
        clear_poll_handler_registry_for_tests();

        let scheduler = Arc::new(crate::io::io_scheduler::IoScheduler::new());
        let coordinator = Arc::new(crate::io::io_scheduler::HybridIoCoordinator::new(scheduler));
        let index = 99u8;
        let device_id = DeviceId::VirtioNet { index };

        register_virtio_net_with(&coordinator, index);
        let first_handler = get_poll_handler(index).expect("first handler");
        let first_ops = crate::io::io_scheduler::io_scheduler()
            .get_device_ops(device_id)
            .expect("first device ops");

        register_virtio_net_with(&coordinator, index);
        let second_handler = get_poll_handler(index).expect("second handler");
        let second_ops = crate::io::io_scheduler::io_scheduler()
            .get_device_ops(device_id)
            .expect("second device ops");

        assert!(Arc::ptr_eq(&first_handler, &second_handler));
        assert!(Arc::ptr_eq(&first_ops, &second_ops));
        assert_eq!(VIRTIO_NET_POLL_HANDLERS.read().len(), 1);

        clear_poll_handler_registry_for_tests();
    }

    #[test_case]
    fn test_register_virtio_net_with_registers_distinct_indices() {
        crate::io::io_scheduler::init_io_scheduler();
        clear_poll_handler_registry_for_tests();

        let scheduler = Arc::new(crate::io::io_scheduler::IoScheduler::new());
        let coordinator = Arc::new(crate::io::io_scheduler::HybridIoCoordinator::new(scheduler));

        register_virtio_net_with(&coordinator, 0);
        register_virtio_net_with(&coordinator, 1);

        let handler0 = get_poll_handler(0).expect("handler0");
        let handler1 = get_poll_handler(1).expect("handler1");
        let ops0 = crate::io::io_scheduler::io_scheduler()
            .get_device_ops(DeviceId::VirtioNet { index: 0 })
            .expect("ops0");
        let ops1 = crate::io::io_scheduler::io_scheduler()
            .get_device_ops(DeviceId::VirtioNet { index: 1 })
            .expect("ops1");

        assert!(!Arc::ptr_eq(&handler0, &handler1));
        assert!(!Arc::ptr_eq(&ops0, &ops1));
        assert_eq!(VIRTIO_NET_POLL_HANDLERS.read().len(), 2);

        clear_poll_handler_registry_for_tests();
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
