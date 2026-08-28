extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::domain::DomainId;
use crate::driver_domain::driver_domain_manager;
use crate::driver_registry::DriverHandle;
use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DeviceOps, IoCommand, IoError, IoRequest, IoRequestId, IoResult,
    PollHandler, hybrid_coordinator, io_scheduler,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::net::runtime::device::{self as net_device_runtime};
use crate::net::runtime::manager::NetIfId;
use crate::sync::{PoisonLock, PoisonRwLock};
#[cfg(test)]
use kernel_api::abi::driver::AbiNetPortOps;
use kernel_api::abi::driver::{
    AbiBlockCommandKind, AbiBlockDeviceInfo, AbiBlockDeviceRegistration, AbiBlockTransport,
    AbiError as AbiErrorCode, AbiIoCompletion, AbiNetDriverEvent, AbiNetDriverEventKind,
    AbiNetPortInfo, AbiNetPortRegistration, AbiNetPortRuntime, AbiNetPortStats, AbiNetRxMeta,
    AbiNetTxMeta, AbiNetTxSegment, AbiNetTxSubmission, AbiNvmeNamespaceInfo,
    AbiNvmeNamespaceRegistration, AbiRxLease, AbiRxWritableRegion, AbiTxDeviceOutcome,
};
use kernel_api::resource::net::PacketByteCount;
use kernel_api::service::netdev::{
    MacAddress, NetDeviceInfo, NetDevicePort, NetDriverEvent, NetPortId, NetPortRegistration,
    NetPortRuntimeHandle, NetPortStats, NetRxFrameLayout, NetRxMeta, NetTxMeta, PrimaryPortPolicy,
    RxBuffer, TxLeaseId, TxSubmission,
};
use kernel_api::service::storage::{StorageDeviceInfo, StorageTransport};
use x86_64::PhysAddr;

const STORAGE_FLAG_ACTIVE: u32 = 1 << 0;

pub mod direct_block;
pub mod dma;
pub mod fs;
pub mod ipc;
pub mod net;
pub mod nvme;
pub mod storage;

pub(crate) use dma::DmaCleanupStats;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnerCleanupStats {
    pub(crate) files: usize,
    pub(crate) channels: usize,
    pub(crate) dma: DmaCleanupStats,
    pub(crate) direct_blocks: usize,
    pub(crate) block_devices: usize,
    pub(crate) nvme_namespaces: usize,
    pub(crate) net_ports: usize,
}

fn map_io_status(status: i32) -> IoResult {
    match AbiErrorCode::from_raw(status) {
        AbiErrorCode::Success => IoResult::Success(0),
        AbiErrorCode::Timeout => IoResult::Error(IoError::Timeout),
        AbiErrorCode::DeviceBusy => IoResult::Error(IoError::Busy),
        AbiErrorCode::InvalidParam => IoResult::Error(IoError::InvalidParameter),
        AbiErrorCode::NotSupported => IoResult::Error(IoError::NotSupported),
        _ => IoResult::Error(IoError::DeviceError),
    }
}

fn map_storage_transport(raw: u32) -> StorageTransport {
    match raw {
        x if x == AbiBlockTransport::Nvme as u32 => StorageTransport::Nvme,
        x if x == AbiBlockTransport::Ahci as u32 => StorageTransport::Ahci,
        _ => StorageTransport::Other,
    }
}

#[derive(Clone, Copy)]
struct BlockDeviceAdapter {
    registration: AbiBlockDeviceRegistration,
}

impl DeviceOps for BlockDeviceAdapter {
    fn submit(&self, req: &IoRequest, _cpu_id: crate::cpu::CpuId) -> Result<(), IoError> {
        let Some(command) = req.command.as_ref() else {
            return Err(IoError::NotSupported);
        };

        let (kind, lba, blocks, bytes, iova) = match command {
            IoCommand::BlockRead {
                lba,
                blocks,
                bytes,
                buf,
            } => (
                AbiBlockCommandKind::Read as u32,
                *lba,
                *blocks as u32,
                *bytes,
                buf.iova,
            ),
            IoCommand::BlockWrite {
                lba,
                blocks,
                bytes,
                buf,
            } => (
                AbiBlockCommandKind::Write as u32,
                *lba,
                *blocks as u32,
                *bytes,
                buf.iova,
            ),
            IoCommand::Flush => (AbiBlockCommandKind::Flush as u32, 0, 0, 0, 0),
            IoCommand::Discard { lba, blocks } => (
                AbiBlockCommandKind::Discard as u32,
                *lba,
                *blocks as u32,
                0,
                0,
            ),
            IoCommand::Ioctl { .. } => return Err(IoError::NotSupported),
        };

        let status = (self.registration.submit)(
            self.registration.opaque,
            req.id.0,
            kind,
            lba,
            blocks,
            bytes,
            iova,
        );
        match AbiErrorCode::from_raw(status) {
            AbiErrorCode::Success => Ok(()),
            AbiErrorCode::Timeout => Err(IoError::Timeout),
            AbiErrorCode::DeviceBusy => Err(IoError::Busy),
            AbiErrorCode::InvalidParam => Err(IoError::InvalidParameter),
            AbiErrorCode::NotSupported => Err(IoError::NotSupported),
            _ => Err(IoError::DeviceError),
        }
    }

    fn is_ready(&self) -> bool {
        (self.registration.is_ready)(self.registration.opaque)
    }
}

impl PollHandler for BlockDeviceAdapter {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut completions = [AbiIoCompletion::default(); 32];
        let mut written = 0usize;
        let status = (self.registration.poll)(
            self.registration.opaque,
            completions.as_mut_ptr(),
            completions.len(),
            &mut written,
        );
        if !AbiErrorCode::from_raw(status).is_success() {
            return Vec::new();
        }

        completions[..written.min(completions.len())]
            .iter()
            .map(|entry| {
                let result = match AbiErrorCode::from_raw(entry.status) {
                    AbiErrorCode::Success => IoResult::Success(entry.bytes),
                    other => match map_io_status(other as i32) {
                        IoResult::Success(_) => IoResult::Success(entry.bytes),
                        error => error,
                    },
                };
                (IoRequestId(entry.request_id), result)
            })
            .collect()
    }

    fn is_ready(&self) -> bool {
        (self.registration.is_ready)(self.registration.opaque)
    }
}

struct BlockDeviceEntry {
    owner: DomainId,
    info: AbiBlockDeviceInfo,
    scheduler_device: IoDeviceId,
}

struct BlockBridgeRegistry {
    entries: PoisonRwLock<BTreeMap<u64, BlockDeviceEntry>>,
    next_handle: AtomicU64,
}

impl BlockBridgeRegistry {
    const fn new() -> Self {
        Self {
            entries: PoisonRwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        owner: DomainId,
        registration: &AbiBlockDeviceRegistration,
    ) -> Result<u64, AbiErrorCode> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let scheduler_device = IoDeviceId::RegisteredBlock { handle };

        {
            let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
            if entries
                .values()
                .any(|entry| entry.scheduler_device == scheduler_device)
            {
                return Err(AbiErrorCode::DeviceBusy);
            }
        }

        let adapter = BlockDeviceAdapter {
            registration: *registration,
        };
        io_scheduler().register_device(scheduler_device, Default::default());
        io_scheduler().register_device_ops(scheduler_device, Arc::new(adapter));
        hybrid_coordinator()
            .polling_executor()
            .register_handler(scheduler_device, Box::new(adapter));

        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                handle,
                BlockDeviceEntry {
                    owner,
                    info: registration.info,
                    scheduler_device,
                },
            );
        Ok(handle)
    }

    fn unregister(&self, owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
        let entry = {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = entries.get(&handle) else {
                return Err(AbiErrorCode::DeviceNotFound);
            };
            if entry.owner != owner {
                return Err(AbiErrorCode::PermissionDenied);
            }
            entries.remove(&handle)
        };

        if let Some(entry) = entry {
            io_scheduler().unregister_device(entry.scheduler_device);
            hybrid_coordinator()
                .polling_executor()
                .unregister_handler(entry.scheduler_device);
        }
        Ok(())
    }

    fn cleanup_owner(&self, owner: DomainId) -> usize {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for &handle in &handles {
            let _ = self.unregister(owner, handle);
        }
        handles.len()
    }

    fn storage_devices(&self) -> Vec<StorageDeviceInfo> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|entry| StorageDeviceInfo {
                device_id: entry.info.device_id,
                namespace_id: entry.info.namespace_id,
                block_size: entry.info.block_size,
                max_transfer_blocks: entry.info.max_transfer_blocks,
                transport: map_storage_transport(entry.info.transport),
                flags: entry.info.flags | STORAGE_FLAG_ACTIVE,
            })
            .collect()
    }
}

struct NvmeNamespaceEntry {
    owner: DomainId,
    info: AbiNvmeNamespaceInfo,
}

struct NvmeNamespaceRegistry {
    entries: PoisonRwLock<BTreeMap<u64, NvmeNamespaceEntry>>,
    next_handle: AtomicU64,
}

impl NvmeNamespaceRegistry {
    const fn new() -> Self {
        Self {
            entries: PoisonRwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        owner: DomainId,
        registration: &AbiNvmeNamespaceRegistration,
    ) -> Result<u64, AbiErrorCode> {
        {
            let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
            if entries
                .values()
                .any(|entry| entry.info.namespace_id == registration.info.namespace_id)
            {
                return Err(AbiErrorCode::DeviceBusy);
            }
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                handle,
                NvmeNamespaceEntry {
                    owner,
                    info: registration.info,
                },
            );
        Ok(handle)
    }

    fn unregister(&self, owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get(&handle) else {
            return Err(AbiErrorCode::DeviceNotFound);
        };
        if entry.owner != owner {
            return Err(AbiErrorCode::PermissionDenied);
        }
        entries.remove(&handle);
        Ok(())
    }

    fn cleanup_owner(&self, owner: DomainId) -> usize {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for &handle in &handles {
            let _ = self.unregister(owner, handle);
        }
        handles.len()
    }

    pub fn lookup(namespace_id: u32) -> Option<AbiNvmeNamespaceInfo> {
        NVME_NAMESPACES
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|entry| entry.info.namespace_id == namespace_id)
            .map(|entry| entry.info)
    }
}

fn leak_driver_name(info: &AbiNetPortInfo) -> &'static str {
    if info.name_ptr.is_null() || info.name_len == 0 {
        return "standalone-netdev";
    }
    let bytes = unsafe { core::slice::from_raw_parts(info.name_ptr, info.name_len) };
    let owned = alloc::string::String::from_utf8_lossy(bytes).into_owned();
    Box::leak(owned.into_boxed_str())
}

struct NetRuntimeState {
    runtime: NetPortRuntimeHandle,
    table: AbiNetPortRuntime,
    rx_leases: PoisonLock<RxLeaseTable>,
    dma_mappings: Arc<NetPacketDmaMappings>,
}

const NET_PACKET_DMA_PAGE_SIZE: u64 = crate::mm::types::PAGE_SIZE_4K as u64;

#[derive(Clone, Copy)]
struct NetPacketDmaPage {
    physical_base: u64,
    device_base: u64,
}

struct NetPacketDmaMappings {
    device: IommuDeviceId,
    pages: PoisonLock<Vec<NetPacketDmaPage>>,
}

impl NetPacketDmaMappings {
    fn new(device: IommuDeviceId) -> Self {
        Self {
            device,
            pages: PoisonLock::new(Vec::new()),
        }
    }

    fn map_region(&self, physical_addr: u64, len: usize) -> Result<u64, &'static str> {
        let len = u64::try_from(len).map_err(|_| "network DMA length does not fit u64")?;
        if physical_addr == 0 || len == 0 {
            return Err("network DMA region is empty");
        }
        let physical_end = physical_addr
            .checked_add(len - 1)
            .ok_or("network DMA region overflow")?;
        let physical_base = physical_addr & !(NET_PACKET_DMA_PAGE_SIZE - 1);
        if physical_end >= physical_base + NET_PACKET_DMA_PAGE_SIZE {
            return Err("network packet segment crosses a DMA page");
        }
        if !crate::io::iommu::api::is_iommu_enabled() {
            return Ok(physical_addr);
        }

        let offset = physical_addr - physical_base;
        let mut pages = self.pages.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(mapping) = pages
            .iter()
            .find(|mapping| mapping.physical_base == physical_base)
        {
            return mapping
                .device_base
                .checked_add(offset)
                .ok_or("network DMA device address overflow");
        }

        pages
            .try_reserve(1)
            .map_err(|_| "network DMA mapping registry allocation failed")?;
        // SAFETY: packet-pool buffers own this aligned physical page for the
        // lifetime of the port mapping cache. The device mapping is revoked
        // only after the port has quiesced DMA.
        let device_base = unsafe {
            crate::io::iommu::api::map_for_device_with_perms(
                &self.device,
                PhysAddr::new(physical_base),
                NET_PACKET_DMA_PAGE_SIZE,
                true,
                true,
            )
        }
        .map_err(|_| "network packet page IOMMU mapping failed")?;
        pages.push(NetPacketDmaPage {
            physical_base,
            device_base,
        });
        device_base
            .checked_add(offset)
            .ok_or("network DMA device address overflow")
    }

    fn revoke_all(&self) -> Result<(), &'static str> {
        let mut pages = self.pages.lock().unwrap_or_else(|error| error.into_inner());
        let mut failed = false;
        let mut index = pages.len();
        while index != 0 {
            index -= 1;
            let mapping = pages[index];
            if crate::io::iommu::api::unmap_for_device(
                &self.device,
                mapping.device_base,
                NET_PACKET_DMA_PAGE_SIZE,
            )
            .is_ok()
            {
                pages.swap_remove(index);
            } else {
                failed = true;
            }
        }
        if failed {
            Err("network packet IOMMU mappings could not be revoked")
        } else {
            Ok(())
        }
    }
}

impl Drop for NetPacketDmaMappings {
    fn drop(&mut self) {
        let _ = self.revoke_all();
    }
}

const ABI_RX_LEASE_INDEX_BITS: u32 = 16;
const ABI_RX_LEASE_INDEX_MASK: u64 = (1_u64 << ABI_RX_LEASE_INDEX_BITS) - 1;
const ABI_RX_LEASE_GENERATION_MASK: u64 = (1_u64 << (64 - ABI_RX_LEASE_INDEX_BITS)) - 1;
const ABI_RX_LEASE_SLOT_LIMIT: usize = u16::MAX as usize;

struct RxLeaseSlot {
    generation: u64,
    buffer: Option<RxBuffer>,
}

#[derive(Default)]
struct RxLeaseTable {
    slots: Vec<RxLeaseSlot>,
    free: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RxLeaseAdmissionError {
    Exhausted,
    Allocation,
}

impl RxLeaseTable {
    fn admit(&mut self, buffer: RxBuffer) -> Result<NonZeroU64, RxLeaseAdmissionError> {
        let index = if let Some(index) = self.free.pop() {
            usize::from(index)
        } else {
            if self.slots.len() == ABI_RX_LEASE_SLOT_LIMIT {
                return Err(RxLeaseAdmissionError::Exhausted);
            }
            self.slots
                .try_reserve(1)
                .map_err(|_| RxLeaseAdmissionError::Allocation)?;
            self.free
                .try_reserve(1)
                .map_err(|_| RxLeaseAdmissionError::Allocation)?;
            let index = self.slots.len();
            self.slots.push(RxLeaseSlot {
                generation: 0,
                buffer: None,
            });
            index
        };

        let slot = &mut self.slots[index];
        debug_assert!(slot.buffer.is_none());
        slot.generation = slot.generation.wrapping_add(1) & ABI_RX_LEASE_GENERATION_MASK;
        if slot.generation == 0 {
            slot.generation = 1;
        }
        slot.buffer = Some(buffer);
        let raw = (slot.generation << ABI_RX_LEASE_INDEX_BITS) | ((index as u64) + 1);
        Ok(NonZeroU64::new(raw).expect("RX lease generation and index are non-zero"))
    }

    fn claim(&mut self, lease_id: NonZeroU64) -> Option<RxBuffer> {
        let raw = lease_id.get();
        let encoded_index = raw & ABI_RX_LEASE_INDEX_MASK;
        if encoded_index == 0 {
            return None;
        }
        let index = usize::try_from(encoded_index - 1).ok()?;
        let generation = raw >> ABI_RX_LEASE_INDEX_BITS;
        let slot = self.slots.get_mut(index)?;
        if slot.generation != generation {
            return None;
        }
        let free_index = u16::try_from(index).ok()?;
        let buffer = slot.buffer.take()?;
        self.free.push(free_index);
        Some(buffer)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetRuntimeStateCookie(NonZeroUsize);

impl NetRuntimeStateCookie {
    fn from_state(state: &mut NetRuntimeState) -> Self {
        let raw = state as *mut NetRuntimeState as usize;
        let Some(raw) = NonZeroUsize::new(raw) else {
            unreachable!("boxed runtime state addresses are non-null");
        };
        Self(raw)
    }

    fn from_raw(raw: u64) -> Option<Self> {
        let raw = usize::try_from(raw).ok()?;
        NonZeroUsize::new(raw).map(Self)
    }

    fn as_raw(self) -> u64 {
        self.0.get() as u64
    }

    fn with_state<R>(self, f: impl FnOnce(&NetRuntimeState) -> R) -> R {
        let ptr = self.0.get() as *const NetRuntimeState;
        // SAFETY: NetRuntimeStateCookie values are created from the Box stored
        // in NetdevPortAdapter::runtime_state during start(). The box keeps the
        // pointee stable until the driver is stopped and the runtime table is no
        // longer a valid callback target.
        unsafe { f(&*ptr) }
    }
}

extern "C" fn runtime_lease_rx_buffer(runtime_cookie: u64, out_lease: *mut AbiRxLease) -> i32 {
    if out_lease.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(|state| {
        let Some(buffer) = state.runtime.lease_rx_buffer() else {
            return AbiErrorCode::OutOfMemory as i32;
        };
        let writable = buffer.writable_region();
        let device_addr = match state
            .dma_mappings
            .map_region(buffer.physical_addr(), writable.writable_len())
        {
            Ok(device_addr) => device_addr,
            Err(_) => return AbiErrorCode::IoError as i32,
        };
        let region = AbiRxWritableRegion {
            cpu_ptr: writable.cpu_ptr(),
            device_addr,
            writable_len: writable.writable_len(),
        };
        let lease_id = match state
            .rx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .admit(buffer)
        {
            Ok(lease_id) => lease_id,
            Err(RxLeaseAdmissionError::Exhausted) => return AbiErrorCode::DeviceBusy as i32,
            Err(RxLeaseAdmissionError::Allocation) => return AbiErrorCode::OutOfMemory as i32,
        };
        let Some(lease) = AbiRxLease::new(lease_id, region) else {
            let _ = state
                .rx_leases
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .claim(lease_id);
            return AbiErrorCode::InvalidParam as i32;
        };
        unsafe {
            *out_lease = lease;
        }
        AbiErrorCode::Success as i32
    })
}

extern "C" fn runtime_release_rx_buffer(runtime_cookie: u64, lease: *mut AbiRxLease) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease) = (unsafe { AbiRxLease::take(lease) }) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease_id) = lease.lease_id() else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(|state| {
        match state
            .rx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .claim(lease_id)
        {
            Some(_) => AbiErrorCode::Success as i32,
            None => AbiErrorCode::InvalidParam as i32,
        }
    })
}

extern "C" fn runtime_submit_rx_buffer(
    runtime_cookie: u64,
    lease: *mut AbiRxLease,
    meta: AbiNetRxMeta,
) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease) = (unsafe { AbiRxLease::take(lease) }) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease_id) = lease.lease_id() else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(buffer) = cookie.with_state(|state| {
        state
            .rx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .claim(lease_id)
    }) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let layout = meta.layout();
    if !layout.is_valid() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let Some(frame_len) = PacketByteCount::new(layout.frame_len()) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(rx_layout) =
        NetRxFrameLayout::new(frame_len, layout.header_len(), layout.payload_len())
    else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let rx_meta = NetRxMeta::new(meta.queue_index(), rx_layout, meta.flags());
    let received = match buffer.complete(rx_meta) {
        Ok(received) => received,
        Err(_) => return AbiErrorCode::InvalidParam as i32,
    };
    cookie.with_state(|state| match state.runtime.submit_rx(received) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    })
}

extern "C" fn runtime_schedule_event(runtime_cookie: u64, event: AbiNetDriverEvent) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let translated = match event.kind {
        x if x == AbiNetDriverEventKind::Interrupt as u32 => NetDriverEvent::Interrupt,
        x if x == AbiNetDriverEventKind::QueueWake as u32 => NetDriverEvent::QueueWake {
            queue_index: event.queue_index,
        },
        _ => NetDriverEvent::Poll,
    };
    cookie.with_state(|state| match state.runtime.schedule_event(translated) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    })
}

extern "C" fn runtime_complete_tx_lease(
    runtime_cookie: u64,
    lease_id: u64,
    outcome: AbiTxDeviceOutcome,
) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease_id) = TxLeaseId::new(lease_id) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(outcome) = outcome.into_outcome() else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(
        |state| match state.runtime.complete_tx_lease(lease_id, outcome) {
            Ok(()) => AbiErrorCode::Success as i32,
            Err(_) => AbiErrorCode::DeviceNotFound as i32,
        },
    )
}

extern "C" fn runtime_update_link(runtime_cookie: u64, up: bool) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(|state| match state.runtime.update_link(up) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    })
}

extern "C" fn runtime_log(runtime_cookie: u64, level: u32, msg_ptr: *const u8, msg_len: usize) {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return;
    };
    if msg_ptr.is_null() || msg_len == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
    if let Ok(message) = core::str::from_utf8(slice) {
        cookie.with_state(|state| {
            state.runtime.log(
                match level {
                    0 => kernel_api::service::netdev::NetLogLevel::Error,
                    1 => kernel_api::service::netdev::NetLogLevel::Warn,
                    3 => kernel_api::service::netdev::NetLogLevel::Debug,
                    4 => kernel_api::service::netdev::NetLogLevel::Trace,
                    _ => kernel_api::service::netdev::NetLogLevel::Info,
                },
                message,
            )
        });
    }
}

struct NetdevPortAdapter {
    registration: AbiNetPortRegistration,
    driver_name: &'static str,
    runtime_state: PoisonLock<Option<Box<NetRuntimeState>>>,
    max_tx_segments: NonZeroU16,
    tx_abi_scratch: PoisonLock<Vec<AbiNetTxSegment>>,
    dma_mappings: Arc<NetPacketDmaMappings>,
}

unsafe impl Send for NetdevPortAdapter {}
unsafe impl Sync for NetdevPortAdapter {}

impl NetdevPortAdapter {
    fn new(
        registration: &AbiNetPortRegistration,
        driver_name: &'static str,
        dma_device: IommuDeviceId,
    ) -> Result<Self, AbiErrorCode> {
        let Some(max_tx_segments) = NonZeroU16::new(registration.info.max_tx_segments) else {
            return Err(AbiErrorCode::InvalidParam);
        };
        let mut tx_abi_scratch = Vec::new();
        tx_abi_scratch
            .try_reserve_exact(usize::from(max_tx_segments.get()))
            .map_err(|_| AbiErrorCode::OutOfMemory)?;
        Ok(Self {
            registration: *registration,
            driver_name,
            runtime_state: PoisonLock::new(None),
            max_tx_segments,
            tx_abi_scratch: PoisonLock::new(tx_abi_scratch),
            dma_mappings: Arc::new(NetPacketDmaMappings::new(dma_device)),
        })
    }
}

impl NetDevicePort for NetdevPortAdapter {
    fn info(&self) -> NetDeviceInfo {
        let info = self.registration.info;
        NetDeviceInfo {
            port_id: NetPortId::new(info.port_id),
            if_id: None,
            driver_name: self.driver_name,
            queue_pairs: info.queue_pairs,
            max_tx_segments: self.max_tx_segments,
            mtu: info.mtu,
            mac: MacAddress(info.mac),
            flags: info.flags,
        }
    }

    fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
        let mut state = Box::new(NetRuntimeState {
            runtime,
            table: AbiNetPortRuntime::new(
                0,
                runtime_lease_rx_buffer,
                runtime_release_rx_buffer,
                runtime_submit_rx_buffer,
                runtime_complete_tx_lease,
                runtime_schedule_event,
                runtime_update_link,
                runtime_log,
            ),
            rx_leases: PoisonLock::new(RxLeaseTable::default()),
            dma_mappings: Arc::clone(&self.dma_mappings),
        });
        state.table.runtime_cookie = NetRuntimeStateCookie::from_state(&mut state).as_raw();
        let table_ptr = &state.table as *const AbiNetPortRuntime;
        let status = (self.registration.start)(self.registration.opaque, table_ptr);
        if !AbiErrorCode::from_raw(status).is_success() {
            return Err("standalone netdev start failed");
        }
        *self.runtime_state.lock().unwrap_or_else(|e| e.into_inner()) = Some(state);
        Ok(())
    }

    fn bind(&self, if_id: u16) -> Result<(), &'static str> {
        let status = (self.registration.bind)(self.registration.opaque, if_id);
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev bind failed")
        }
    }

    fn submit_tx_chain(
        &self,
        submission: TxSubmission<'_>,
        meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        let mut abi_segments = self
            .tx_abi_scratch
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        abi_segments.clear();
        if submission.segments().len() > abi_segments.capacity() {
            return Err("standalone netdev TX segment limit exceeded");
        }
        for segment in submission.segments() {
            let device_addr = self
                .dma_mappings
                .map_region(segment.physical_addr().get(), segment.len().get())?;
            abi_segments.push(
                AbiNetTxSegment::from_checked_parts(segment.cpu_ptr(), device_addr, segment.len())
                    .expect("NetTxSegment already validates ABI descriptor invariants"),
            );
        }
        let abi_submission = AbiNetTxSubmission::new(submission.lease_id(), &abi_segments)
            .ok_or("standalone netdev empty tx submission")?;
        let abi_meta = AbiNetTxMeta {
            queue_index: meta.queue_index.unwrap_or(0),
            has_queue_index: meta.queue_index.is_some(),
            has_vlan_tag: meta.vlan_tag.is_some(),
            reserved0: 0,
            flags: meta.flags,
            vlan_tag: meta.vlan_tag.unwrap_or(0),
            reserved1: 0,
        };
        let status = (self.registration.submit_tx_chain)(
            self.registration.opaque,
            &abi_submission,
            abi_meta,
        );
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev tx failed")
        }
    }

    fn set_interrupts_enabled(&self, enabled: bool) -> Result<(), &'static str> {
        let status = (self.registration.set_interrupts_enabled)(self.registration.opaque, enabled);
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev interrupt toggle failed")
        }
    }

    fn poll(&self, if_id: u16) -> Result<(), &'static str> {
        let status = (self.registration.poll)(self.registration.opaque, if_id);
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev poll failed")
        }
    }

    fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
        let abi_event = match event {
            NetDriverEvent::Interrupt => AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::Interrupt as u32,
                queue_index: 0,
                _padding: 0,
            },
            NetDriverEvent::QueueWake { queue_index } => AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::QueueWake as u32,
                queue_index,
                _padding: 0,
            },
            NetDriverEvent::Poll => AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::Poll as u32,
                queue_index: 0,
                _padding: 0,
            },
        };
        let status = (self.registration.handle_event)(self.registration.opaque, if_id, abi_event);
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev event failed")
        }
    }

    fn stats(&self) -> NetPortStats {
        let mut stats = AbiNetPortStats::default();
        let status = (self.registration.stats)(self.registration.opaque, &mut stats);
        if !AbiErrorCode::from_raw(status).is_success() {
            return NetPortStats::default();
        }
        NetPortStats {
            tx_packets: stats.tx_packets,
            rx_packets: stats.rx_packets,
            tx_errors: stats.tx_errors,
            rx_errors: stats.rx_errors,
            initialized: stats.initialized,
        }
    }

    fn stop(&self) -> Result<(), &'static str> {
        let status = (self.registration.stop)(self.registration.opaque);
        if !AbiErrorCode::from_raw(status).is_success() {
            return Err("standalone netdev could not prove DMA quiescence");
        }
        self.dma_mappings.revoke_all()?;
        let _ = self
            .runtime_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Ok(())
    }
}

struct NetdevPortEntry {
    owner: DomainId,
    if_id: NetIfId,
}

struct NetdevBridgeRegistry {
    entries: PoisonRwLock<BTreeMap<u64, NetdevPortEntry>>,
    next_handle: AtomicU64,
}

impl NetdevBridgeRegistry {
    const fn new() -> Self {
        Self {
            entries: PoisonRwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        owner: DomainId,
        dma_device: IommuDeviceId,
        registration: &AbiNetPortRegistration,
    ) -> Result<u64, AbiErrorCode> {
        let name = leak_driver_name(&registration.info);
        let adapter: Box<dyn NetDevicePort> =
            Box::new(NetdevPortAdapter::new(registration, name, dma_device)?);
        let info = adapter.info();
        let runtime = crate::net::runtime::default_runtime();
        let if_id = net_device_runtime::register_port_in(
            runtime,
            NetPortRegistration::new(info, adapter, PrimaryPortPolicy::Auto),
        )
        .map_err(|_| AbiErrorCode::IoError)?;
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handle, NetdevPortEntry { owner, if_id });
        Ok(handle)
    }

    fn unregister(&self, owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
        let entry = {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = entries.get(&handle) else {
                return Err(AbiErrorCode::DeviceNotFound);
            };
            if entry.owner != owner {
                return Err(AbiErrorCode::PermissionDenied);
            }
            entries.remove(&handle)
        };
        if let Some(entry) = entry {
            match net_device_runtime::unregister_port_in(
                crate::net::runtime::default_runtime(),
                entry.if_id,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(AbiErrorCode::DeviceNotFound),
                Err(_) => return Err(AbiErrorCode::IoError),
            }
        }
        Ok(())
    }

    fn cleanup_owner(&self, owner: DomainId) -> usize {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for &handle in &handles {
            let _ = self.unregister(owner, handle);
        }
        handles.len()
    }
}

static BLOCK_DEVICES: BlockBridgeRegistry = BlockBridgeRegistry::new();
static NVME_NAMESPACES: NvmeNamespaceRegistry = NvmeNamespaceRegistry::new();
static NETDEV_PORTS: NetdevBridgeRegistry = NetdevBridgeRegistry::new();

pub(crate) fn cleanup_owner_domain(owner: DomainId) -> OwnerCleanupStats {
    OwnerCleanupStats {
        files: fs::cleanup_owner(owner.as_u64()),
        channels: ipc::cleanup_owner(owner.as_u64()),
        dma: dma::cleanup_owner(owner),
        direct_blocks: direct_block::cleanup_owner(owner.as_u64()),
        block_devices: storage::cleanup_owner(owner),
        nvme_namespaces: nvme::cleanup_owner(owner),
        net_ports: net::cleanup_owner(owner),
    }
}

pub fn cleanup_for_driver_handle(handle: DriverHandle) {
    let Some(cell_id) = driver_domain_manager().find_by_driver_handle(handle) else {
        return;
    };
    if let Ok(Some(domain_id)) = driver_domain_manager().with_cell(cell_id, |cell| cell.domain_id) {
        let _ = cleanup_owner_domain(domain_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainId;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    extern "C" fn test_block_submit(
        _opaque: u64,
        _request_id: u64,
        _command: u32,
        _lba: u64,
        _blocks: u32,
        _bytes: usize,
        _iova: u64,
    ) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_block_poll(
        _opaque: u64,
        _out: *mut AbiIoCompletion,
        _capacity: usize,
        written: *mut usize,
    ) -> i32 {
        unsafe {
            *written = 0;
        }
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_block_ready(_opaque: u64) -> bool {
        true
    }

    static TEST_NET_INTERRUPT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TEST_NET_INTERRUPTS_ENABLED: AtomicBool = AtomicBool::new(true);

    extern "C" fn test_net_start(_opaque: u64, _runtime: *const AbiNetPortRuntime) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_bind(_opaque: u64, _if_id: u16) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_submit_tx(
        _opaque: u64,
        submission: *const AbiNetTxSubmission,
        _meta: AbiNetTxMeta,
    ) -> i32 {
        if submission.is_null() {
            return AbiErrorCode::InvalidParam as i32;
        }
        let submission = unsafe { &*submission };
        let Some(_segments) = submission.segments() else {
            return AbiErrorCode::InvalidParam as i32;
        };
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_poll(_opaque: u64, _if_id: u16) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_handle_event(
        _opaque: u64,
        _if_id: u16,
        _event: AbiNetDriverEvent,
    ) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_stats(_opaque: u64, out: *mut AbiNetPortStats) -> i32 {
        if out.is_null() {
            return AbiErrorCode::InvalidParam as i32;
        }
        unsafe {
            *out = AbiNetPortStats::default();
        }
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_stop(_opaque: u64) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_set_interrupts_enabled(_opaque: u64, enabled: bool) -> i32 {
        TEST_NET_INTERRUPT_CALLS.fetch_add(1, Ordering::Relaxed);
        TEST_NET_INTERRUPTS_ENABLED.store(enabled, Ordering::Release);
        AbiErrorCode::Success as i32
    }

    fn test_net_info(port_index: u16) -> AbiNetPortInfo {
        AbiNetPortInfo {
            port_id: 0x9000 + port_index as u64,
            queue_pairs: 1,
            reserved_queue: 0,
            mtu: 1500,
            flags: 0,
            mac: [0x02, 0, 0, 0, 0, port_index as u8],
            reserved0: [0; 2],
            name_ptr: core::ptr::null(),
            name_len: 0,
        }
    }

    fn test_net_registration(port_index: u16) -> AbiNetPortRegistration {
        AbiNetPortRegistration::new(
            test_net_info(port_index),
            0,
            AbiNetPortOps {
                start: test_net_start,
                bind: test_net_bind,
                submit_tx_chain: test_net_submit_tx,
                poll: test_net_poll,
                handle_event: test_net_handle_event,
                stats: test_net_stats,
                stop: test_net_stop,
                set_interrupts_enabled: test_net_set_interrupts_enabled,
            },
        )
    }

    fn test_block_registration(device_id: u64, namespace_id: u32) -> AbiBlockDeviceRegistration {
        AbiBlockDeviceRegistration::new(
            AbiBlockDeviceInfo {
                device_id,
                namespace_id,
                block_size: 512,
                max_transfer_blocks: 128,
                transport: AbiBlockTransport::Nvme as u32,
                flags: 0,
                controller_id: 0,
                port_id: 0,
            },
            0,
            test_block_submit,
            test_block_poll,
            test_block_ready,
        )
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn block_registry_rejects_duplicate_scheduler_device_and_cleans_owner() {
        let registry = BlockBridgeRegistry::new();
        let owner_a = DomainId::new(11);
        let owner_b = DomainId::new(12);

        let first = registry
            .register(owner_a, &test_block_registration(0x100, 1))
            .expect("first block registration");
        let duplicate = registry.register(owner_b, &test_block_registration(0x101, 1));
        assert_eq!(duplicate, Err(AbiErrorCode::DeviceBusy));

        let devices = registry.storage_devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].namespace_id, 1);
        assert_eq!(devices[0].transport, StorageTransport::Nvme);

        registry.cleanup_owner(owner_a);
        assert!(registry.storage_devices().is_empty());
        assert_eq!(
            registry.unregister(owner_a, first),
            Err(AbiErrorCode::DeviceNotFound)
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn nvme_namespace_registry_enforces_unique_namespace_and_owner() {
        let registry = NvmeNamespaceRegistry::new();
        let owner_a = DomainId::new(21);
        let owner_b = DomainId::new(22);
        let registration = AbiNvmeNamespaceRegistration::new(AbiNvmeNamespaceInfo {
            device_id: 0x200,
            namespace_id: 7,
            block_size: 4096,
            max_transfer_blocks: 256,
            max_sgl_entries: 32,
            total_blocks: 4096,
            controller_id: 0,
            flags: 0,
        });

        let handle = registry
            .register(owner_a, &registration)
            .expect("namespace registration");
        assert_eq!(
            registry.register(owner_b, &registration),
            Err(AbiErrorCode::DeviceBusy)
        );
        assert_eq!(
            registry.unregister(owner_b, handle),
            Err(AbiErrorCode::PermissionDenied)
        );
        registry.cleanup_owner(owner_a);
        assert!(
            registry
                .entries
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn netdev_adapter_v3_invokes_interrupt_toggle_callback() {
        TEST_NET_INTERRUPT_CALLS.store(0, Ordering::Relaxed);
        TEST_NET_INTERRUPTS_ENABLED.store(true, Ordering::Release);

        let registration = test_net_registration(2);
        let adapter = NetdevPortAdapter::new(
            &registration,
            "test-net",
            IommuDeviceId {
                segment: 0,
                bus: 0,
                device: 2,
                function: 0,
            },
        )
        .expect("v3 adapter");

        assert_eq!(adapter.set_interrupts_enabled(false), Ok(()));
        assert_eq!(TEST_NET_INTERRUPT_CALLS.load(Ordering::Relaxed), 1);
        assert!(!TEST_NET_INTERRUPTS_ENABLED.load(Ordering::Acquire));
    }
}
