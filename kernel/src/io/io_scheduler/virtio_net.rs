use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::io_scheduler::{
    DeviceId, DeviceOps, IoError, IoRequest, IoRequestId, IoResult, PollHandler,
    hybrid_coordinator, io_scheduler,
};

use virtio_driver::net::{
    NetCompletionKind, VirtioNetError, VirtioNetHeader, get_virtio_net_device_at_index,
    set_virtio_net_completion_handler,
};

pub const VIRTIO_NET_IOCTL_TX: u32 = 0x1001;
pub const VIRTIO_NET_IOCTL_RX: u32 = 0x1002;

#[derive(Debug, Clone, Copy)]
pub struct PendingNetRequest {
    pub io_id: IoRequestId,
    pub requested_bytes: usize,
}

pub struct VirtioNetPollHandler {
    device_index: u8,
    pending_rx: PoisonLock<BTreeMap<u16, PendingNetRequest>>,
    pending_tx: PoisonLock<BTreeMap<u16, PendingNetRequest>>,
}

impl VirtioNetPollHandler {
    pub fn new_for_index(device_index: u8) -> Self {
        Self {
            device_index,
            pending_rx: PoisonLock::new(BTreeMap::new()),
            pending_tx: PoisonLock::new(BTreeMap::new()),
        }
    }

    pub fn add_pending_rx(&self, id: IoRequestId, desc_id: u16, requested_bytes: usize) {
        self.pending_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                desc_id,
                PendingNetRequest {
                    io_id: id,
                    requested_bytes,
                },
            );
    }

    pub fn add_pending_tx(&self, id: IoRequestId, desc_id: u16, requested_bytes: usize) {
        self.pending_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                desc_id,
                PendingNetRequest {
                    io_id: id,
                    requested_bytes,
                },
            );
    }

    fn finish_rx(&self, desc_id: u16, completion_len: u32) -> Option<(IoRequestId, IoResult)> {
        let req = self
            .pending_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&desc_id)?;
        let payload_len = (completion_len as usize).saturating_sub(VirtioNetHeader::SIZE);
        let payload_cap = req.requested_bytes.saturating_sub(VirtioNetHeader::SIZE);
        let completed = core::cmp::min(payload_len, payload_cap);
        Some((req.io_id, IoResult::Success(completed)))
    }

    fn finish_tx(&self, desc_id: u16, requested_len: u32) -> Option<(IoRequestId, IoResult)> {
        let req = self
            .pending_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&desc_id)?;
        let bytes = if req.requested_bytes == 0 {
            requested_len as usize
        } else {
            req.requested_bytes
        };
        Some((req.io_id, IoResult::Success(bytes)))
    }
}

impl PollHandler for VirtioNetPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        if let Some(device) = get_virtio_net_device_at_index(self.device_index) {
            device.process_interrupt_deferred();
            device.refill_rx_queues();
        }
        Vec::new()
    }

    fn is_ready(&self) -> bool {
        get_virtio_net_device_at_index(self.device_index)
            .map(|device| device.is_ready())
            .unwrap_or(false)
    }
}

unsafe impl Send for VirtioNetPollHandler {}
unsafe impl Sync for VirtioNetPollHandler {}

fn map_virtio_net_error(err: VirtioNetError) -> IoError {
    match err {
        VirtioNetError::QueueFull => IoError::NoResources,
        VirtioNetError::BufferTooSmall => IoError::InvalidParameter,
        VirtioNetError::NotInitialized => IoError::NoResources,
        VirtioNetError::Timeout => IoError::Timeout,
        VirtioNetError::DeviceError => IoError::DeviceError,
    }
}

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
    ) -> Result<(), IoError> {
        let device =
            get_virtio_net_device_at_index(self.device_index).ok_or(IoError::NoResources)?;

        match code {
            VIRTIO_NET_IOCTL_TX => {
                let tx_queue = device.first_tx_queue().ok_or(IoError::NoResources)?;
                let desc_id = tx_queue
                    .add_tx_buffer_zero_copy(buf.iova, buf.len)
                    .map_err(map_virtio_net_error)?;
                self.handler.add_pending_tx(io_id, desc_id, buf.len);
                tx_queue.notify(device.transport());
                Ok(())
            }
            VIRTIO_NET_IOCTL_RX => {
                if buf.len < VirtioNetHeader::SIZE {
                    return Err(IoError::InvalidParameter);
                }
                let rx_queue = device.first_rx_queue().ok_or(IoError::NoResources)?;
                let desc_id = rx_queue
                    .add_rx_buffer_zero_copy(buf.iova, buf.len)
                    .map_err(map_virtio_net_error)?;
                self.handler.add_pending_rx(io_id, desc_id, buf.len);
                rx_queue.notify(device.transport());
                Ok(())
            }
            _ => Err(IoError::NotSupported),
        }
    }
}

impl DeviceOps for VirtioNetOps {
    fn submit(&self, req: &IoRequest, _cpu_idx: usize) -> Result<(), IoError> {
        let cmd = req.command.as_ref().ok_or(IoError::NotSupported)?;
        match cmd {
            crate::io::io_scheduler::IoCommand::Ioctl { code, buf } => {
                self.submit_ioctl(req.id, *code, *buf)
            }
            _ => Err(IoError::NotSupported),
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

pub static VIRTIO_NET_POLL_HANDLERS: PoisonRwLock<BTreeMap<u8, Arc<VirtioNetPollHandler>>> =
    PoisonRwLock::new(BTreeMap::new());

pub fn get_poll_handler(index: u8) -> Option<Arc<VirtioNetPollHandler>> {
    VIRTIO_NET_POLL_HANDLERS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .cloned()
}

fn handle_scheduler_completion(index: u8, kind: NetCompletionKind, desc_id: u16, len: u32) -> bool {
    let Some(handler) = get_poll_handler(index) else {
        return false;
    };

    let result = match kind {
        NetCompletionKind::Rx => handler.finish_rx(desc_id, len),
        NetCompletionKind::Tx => handler.finish_tx(desc_id, len),
    };
    let Some((io_id, io_result)) = result else {
        return false;
    };

    hybrid_coordinator()
        .interrupt_bridge()
        .handle_interrupt(DeviceId::VirtioNet { index }, &[(io_id, io_result)]);
    true
}

pub fn register_virtio_net_with(
    scheduler: &Arc<crate::io::io_scheduler::IoScheduler>,
    coordinator: &Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    index: u8,
) {
    if VIRTIO_NET_POLL_HANDLERS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&index)
    {
        return;
    }

    let handler = Arc::new(VirtioNetPollHandler::new_for_index(index));
    {
        let mut handlers = VIRTIO_NET_POLL_HANDLERS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if handlers.contains_key(&index) {
            return;
        }
        handlers.insert(index, handler.clone());
    }

    coordinator.polling_executor().register_handler(
        DeviceId::VirtioNet { index },
        Box::new(VirtioNetPollHandlerWrapper {
            inner: handler.clone(),
        }),
    );

    let _ = set_virtio_net_completion_handler(index, Some(handle_scheduler_completion));

    scheduler.register_device_ops(
        DeviceId::VirtioNet { index },
        Arc::new(VirtioNetOps::new(index, handler)),
    );
}

pub fn register_virtio_net_with_io_scheduler(index: u8) {
    register_virtio_net_with(&io_scheduler(), &hybrid_coordinator(), index);
}
