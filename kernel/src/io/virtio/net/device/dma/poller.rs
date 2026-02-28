use super::*;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::collections::BTreeMap;
use spin::RwLock;

use crate::io::io_scheduler::{
    DeviceId, DeviceOps, IoRequestId, IoResult, PollHandler, hybrid_coordinator,
};

// ============================================================================
// IoScheduler Integration
// ============================================================================

/// IoScheduler ioctl code for VirtIO-Net TX submit.
pub const VIRTIO_NET_IOCTL_TX: u32 = 0x1001;
/// IoScheduler ioctl code for VirtIO-Net RX submit.
pub const VIRTIO_NET_IOCTL_RX: u32 = 0x1002;

#[derive(Debug, Clone, Copy)]
pub struct PendingNetRequest {
    pub io_id: IoRequestId,
    pub requested_bytes: usize,
}

/// VirtIO ネットワーク PollHandler 実装
pub struct VirtioNetPollHandler {
    /// 対象 VirtIO-Net device index
    pub device_index: u8,
    /// 保留中RXリクエスト (desc_id -> request)
    pub pending_rx: crate::sync::PoisonLock<BTreeMap<u16, PendingNetRequest>>,
    /// 保留中TXリクエスト (desc_id -> request)
    pub pending_tx: crate::sync::PoisonLock<BTreeMap<u16, PendingNetRequest>>,
    /// 次のリクエストID
    pub next_request_id: AtomicU64,
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
            pending_rx: crate::sync::PoisonLock::new(BTreeMap::new()),
            pending_tx: crate::sync::PoisonLock::new(BTreeMap::new()),
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
        self.pending_rx.lock().expect("lock poisoned").insert(
            desc_id,
            PendingNetRequest {
                io_id: id,
                requested_bytes,
            },
        );
    }

    /// TX リクエストを追加
    pub fn add_pending_tx(&self, id: IoRequestId, desc_id: u16, requested_bytes: usize) {
        self.pending_tx.lock().expect("lock poisoned").insert(
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
            .lock().expect("lock poisoned")
            .remove(&desc_id)
            .map(|req| (req.io_id, req.requested_bytes))
    }

    /// IRQパス向けに pending TX を取り出して削除
    pub fn take_pending_tx(&self, desc_id: u16) -> Option<(IoRequestId, usize)> {
        self.pending_tx
            .lock().expect("lock poisoned")
            .remove(&desc_id)
            .map(|req| (req.io_id, req.requested_bytes))
    }

    fn route_scheduler_rx_completion(
        &self,
        rx_queue: &NetVirtQueue,
        desc_id: u16,
    ) -> Option<(IoRequestId, IoResult)> {
        let pending = self.pending_rx.lock().expect("lock poisoned").remove(&desc_id);
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
        let pending = self.pending_tx.lock().expect("lock poisoned").remove(&desc_id);
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
        let q_idx = rx_queue
            .vq
            .lock()
            .expect("lock poisoned")
            .index() as usize;
        device.handle_legacy_rx_completion(rx_queue, q_idx, desc_id, len)
    }

    fn route_legacy_tx_completion(
        &self,
        device: &VirtioNetDevice,
        tx_queue: &NetVirtQueue,
        desc_id: u16,
        len: u32,
    ) -> bool {
        let q_idx = tx_queue
            .vq
            .lock()
            .expect("lock poisoned")
            .index() as usize;
        device.handle_legacy_tx_completion(tx_queue, q_idx, desc_id, len)
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
    pub fn pending_rx_len(&self) -> usize {
        self.pending_rx.lock().expect("lock poisoned").len()
    }

    #[cfg(test)]
    pub fn pending_tx_len(&self) -> usize {
        self.pending_tx.lock().expect("lock poisoned").len()
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
                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::TxAvailable,
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
                    tx_queue.notify(device.transport.as_ref());
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
                    rx_queue.notify(device.transport.as_ref());
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
pub static VIRTIO_NET_POLL_HANDLERS: RwLock<BTreeMap<u8, Arc<VirtioNetPollHandler>>> =
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
pub fn register_virtio_net_with_io_scheduler(index: u8) {
    register_virtio_net_with(&hybrid_coordinator(), index);
}
