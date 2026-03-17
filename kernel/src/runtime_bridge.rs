extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::domain_system::DomainId;
use crate::driver_domain::driver_domain_manager;
use crate::driver_registry::DriverHandle;
use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, DeviceOps, IoCommand, IoError, IoRequest, IoRequestId, IoResult,
    PollHandler, hybrid_coordinator, io_scheduler,
};
use crate::net::runtime::device::{self as net_device_runtime, NetDeviceKey};
use crate::net::runtime::manager::NetIfId;
use crate::sync::{PoisonLock, PoisonRwLock};
use kernel_api::abi::driver::{
    AbiAudioControllerRegistration, AbiAudioDeviceInfo, AbiBlockCommandKind, AbiBlockDeviceInfo,
    AbiBlockDeviceRegistration, AbiBlockTransport, AbiError as AbiErrorCode, AbiIoCompletion,
    AbiNetDriverEvent, AbiNetDriverEventKind, AbiNetPortInfo, AbiNetPortKind,
    AbiNetPortRegistrationV3, AbiNetPortRuntimeV2, AbiNetPortStats, AbiNetRxMeta, AbiNetTxMeta,
    AbiNvmeNamespaceInfo, AbiNvmeNamespaceRegistration, AbiPacketRefRaw,
};
use kernel_api::service::audio::AudioDeviceInfo;
use kernel_api::service::netdev::{
    MacAddress, NetDeviceInfo, NetDevicePort, NetDriverEvent, NetPortKind, NetPortRuntime,
    NetPortStats, NetRxMeta, NetTxMeta,
};
use kernel_api::service::storage::{StorageDeviceInfo, StorageTransport};

const STORAGE_FLAG_ACTIVE: u32 = 1 << 0;

fn current_driver_domain() -> Result<DomainId, AbiErrorCode> {
    let domain = crate::task::context::current_subject().domain;
    if domain == DomainId::KERNEL {
        return Err(AbiErrorCode::PermissionDenied);
    }
    if driver_domain_manager().find_by_domain(domain).is_none() {
        return Err(AbiErrorCode::PermissionDenied);
    }
    Ok(domain)
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

fn block_scheduler_device(info: &AbiBlockDeviceInfo, handle: u64) -> IoDeviceId {
    match info.transport {
        x if x == AbiBlockTransport::Nvme as u32 => IoDeviceId::Nvme {
            controller: info.controller_id as u8,
            namespace: info.namespace_id,
        },
        x if x == AbiBlockTransport::Ahci as u32 => IoDeviceId::Ahci {
            port: info.port_id as u8,
        },
        _ => IoDeviceId::Custom(handle as u32),
    }
}

#[derive(Clone, Copy)]
struct BlockDeviceAdapter {
    registration: AbiBlockDeviceRegistration,
}

impl DeviceOps for BlockDeviceAdapter {
    fn submit(&self, req: &IoRequest, _cpu_idx: usize) -> Result<(), IoError> {
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
        let scheduler_device = block_scheduler_device(&registration.info, handle);

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

    fn cleanup_owner(&self, owner: DomainId) {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for handle in handles {
            let _ = self.unregister(owner, handle);
        }
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

    fn cleanup_owner(&self, owner: DomainId) {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for handle in handles {
            let _ = self.unregister(owner, handle);
        }
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
    runtime: Arc<dyn NetPortRuntime>,
    table: AbiNetPortRuntimeV2,
}

extern "C" fn runtime_alloc_packet(runtime_cookie: u64, out_packet: *mut AbiPacketRefRaw) -> i32 {
    if out_packet.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let state = unsafe { &*(runtime_cookie as usize as *const NetRuntimeState) };
    let Some(packet) = state.runtime.alloc_packet() else {
        return AbiErrorCode::OutOfMemory as i32;
    };
    unsafe {
        *out_packet = AbiPacketRefRaw::from_packet(packet);
    }
    AbiErrorCode::Success as i32
}

extern "C" fn runtime_submit_rx_packet(
    runtime_cookie: u64,
    packet: *mut AbiPacketRefRaw,
    meta: AbiNetRxMeta,
) -> i32 {
    let Some(packet) = AbiPacketRefRaw::take(packet) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let state = unsafe { &*(runtime_cookie as usize as *const NetRuntimeState) };
    let rx_meta = NetRxMeta {
        queue_index: meta.queue_index,
        header_len: meta.header_len,
        payload_len: meta.payload_len,
        flags: meta.flags,
    };
    match state.runtime.submit_rx(packet.into_packet(), rx_meta) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    }
}

extern "C" fn runtime_schedule_event(runtime_cookie: u64, event: AbiNetDriverEvent) -> i32 {
    let state = unsafe { &*(runtime_cookie as usize as *const NetRuntimeState) };
    let translated = match event.kind {
        x if x == AbiNetDriverEventKind::Interrupt as u32 => NetDriverEvent::Interrupt,
        x if x == AbiNetDriverEventKind::QueueWake as u32 => NetDriverEvent::QueueWake {
            queue_index: event.queue_index,
        },
        _ => NetDriverEvent::Poll,
    };
    match state.runtime.schedule_event(translated) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    }
}

extern "C" fn runtime_update_link(runtime_cookie: u64, up: bool) -> i32 {
    let state = unsafe { &*(runtime_cookie as usize as *const NetRuntimeState) };
    match state.runtime.update_link(up) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    }
}

extern "C" fn runtime_log(runtime_cookie: u64, level: u32, msg_ptr: *const u8, msg_len: usize) {
    let state = unsafe { &*(runtime_cookie as usize as *const NetRuntimeState) };
    if msg_ptr.is_null() || msg_len == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
    if let Ok(message) = core::str::from_utf8(slice) {
        state.runtime.log(
            match level {
                0 => kernel_api::service::netdev::NetLogLevel::Error,
                1 => kernel_api::service::netdev::NetLogLevel::Warn,
                3 => kernel_api::service::netdev::NetLogLevel::Debug,
                4 => kernel_api::service::netdev::NetLogLevel::Trace,
                _ => kernel_api::service::netdev::NetLogLevel::Info,
            },
            message,
        );
    }
}

struct NetdevPortAdapter {
    registration: AbiNetPortRegistrationV3,
    driver_name: &'static str,
    runtime_state: PoisonLock<Option<Box<NetRuntimeState>>>,
}

unsafe impl Send for NetdevPortAdapter {}
unsafe impl Sync for NetdevPortAdapter {}

impl NetdevPortAdapter {
    fn new(
        registration: &AbiNetPortRegistrationV3,
        driver_name: &'static str,
    ) -> Result<Self, AbiErrorCode> {
        Ok(Self {
            registration: *registration,
            driver_name,
            runtime_state: PoisonLock::new(None),
        })
    }
}

impl NetDevicePort for NetdevPortAdapter {
    fn info(&self) -> NetDeviceInfo {
        let info = self.registration.info;
        NetDeviceInfo {
            port_id: info.port_id,
            if_id: None,
            kind: match info.kind {
                x if x == AbiNetPortKind::Virtio as u32 => NetPortKind::Virtio,
                x if x == AbiNetPortKind::Mlx5 as u32 => NetPortKind::Mlx5,
                _ => NetPortKind::Other,
            },
            driver_name: self.driver_name,
            queue_pairs: info.queue_pairs,
            mtu: info.mtu,
            mac: MacAddress(info.mac),
            flags: info.flags,
        }
    }

    fn start(&self, runtime: Arc<dyn NetPortRuntime>) -> Result<(), &'static str> {
        let mut state = Box::new(NetRuntimeState {
            runtime,
            table: AbiNetPortRuntimeV2::new(
                0,
                runtime_alloc_packet,
                runtime_submit_rx_packet,
                runtime_schedule_event,
                runtime_update_link,
                runtime_log,
            ),
        });
        let cookie = (&mut *state) as *mut NetRuntimeState as usize as u64;
        state.table.runtime_cookie = cookie;
        let table_ptr = &state.table as *const AbiNetPortRuntimeV2;
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

    fn submit_tx(
        &self,
        packet: kernel_api::resource::net::PacketRef,
        meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        let mut packet = AbiPacketRefRaw::from_packet(packet);
        let abi_meta = AbiNetTxMeta {
            queue_index: meta.queue_index.unwrap_or(0),
            has_queue_index: meta.queue_index.is_some(),
            has_vlan_tag: meta.vlan_tag.is_some(),
            _padding0: 0,
            flags: meta.flags,
            vlan_tag: meta.vlan_tag.unwrap_or(0),
            _padding1: 0,
        };
        let status =
            (self.registration.submit_tx_packet)(self.registration.opaque, &mut packet, abi_meta);
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

    fn stop(&self) {
        (self.registration.stop)(self.registration.opaque);
        let _ = self
            .runtime_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
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
        registration: &AbiNetPortRegistrationV3,
    ) -> Result<u64, AbiErrorCode> {
        let key = match registration.info.kind {
            x if x == AbiNetPortKind::Virtio as u32 => {
                NetDeviceKey::Virtio(registration.info.port_index as u8)
            }
            x if x == AbiNetPortKind::Mlx5 as u32 => {
                NetDeviceKey::Mlx5(registration.info.port_index as u8)
            }
            _ => return Err(AbiErrorCode::NotSupported),
        };
        let name = leak_driver_name(&registration.info);
        let adapter: Arc<dyn NetDevicePort> = Arc::new(NetdevPortAdapter::new(registration, name)?);
        let if_id = net_device_runtime::register_port_with_default_config(key, adapter, true)
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
            let _ = net_device_runtime::unregister_port(entry.if_id);
        }
        Ok(())
    }

    fn cleanup_owner(&self, owner: DomainId) {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for handle in handles {
            let _ = self.unregister(owner, handle);
        }
    }
}

struct AudioControllerEntry {
    owner: DomainId,
    registration: AbiAudioControllerRegistration,
}

struct AudioBridgeRegistry {
    entries: PoisonRwLock<BTreeMap<u64, AudioControllerEntry>>,
    next_handle: AtomicU64,
}

impl AudioBridgeRegistry {
    const fn new() -> Self {
        Self {
            entries: PoisonRwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        owner: DomainId,
        registration: &AbiAudioControllerRegistration,
    ) -> Result<u64, AbiErrorCode> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                handle,
                AudioControllerEntry {
                    owner,
                    registration: *registration,
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

    fn cleanup_owner(&self, owner: DomainId) {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for handle in handles {
            let _ = self.unregister(owner, handle);
        }
    }

    fn devices(&self) -> Vec<AudioDeviceInfo> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let mut devices = Vec::new();
        for entry in entries.values() {
            if !(entry.registration.is_initialized)(entry.registration.opaque) {
                continue;
            }
            let count = (entry.registration.device_count)(entry.registration.opaque);
            for index in 0..count {
                let mut info = AbiAudioDeviceInfo::default();
                let status =
                    (entry.registration.device_info)(entry.registration.opaque, index, &mut info);
                if !AbiErrorCode::from_raw(status).is_success() {
                    continue;
                }
                devices.push(AudioDeviceInfo {
                    device_id: info.device_id,
                    output_channels: info.output_channels,
                    input_channels: info.input_channels,
                    sample_rate_hz: info.sample_rate_hz,
                    flags: info.flags,
                });
            }
        }
        devices
    }
}

static BLOCK_DEVICES: BlockBridgeRegistry = BlockBridgeRegistry::new();
static NVME_NAMESPACES: NvmeNamespaceRegistry = NvmeNamespaceRegistry::new();
static NETDEV_PORTS: NetdevBridgeRegistry = NetdevBridgeRegistry::new();
static AUDIO_CONTROLLERS: AudioBridgeRegistry = AudioBridgeRegistry::new();

pub fn register_block_device(
    registration: &AbiBlockDeviceRegistration,
) -> Result<u64, AbiErrorCode> {
    let owner = current_driver_domain()?;
    BLOCK_DEVICES.register(owner, registration)
}

pub fn unregister_block_device(handle: u64) -> Result<(), AbiErrorCode> {
    let owner = current_driver_domain()?;
    BLOCK_DEVICES.unregister(owner, handle)
}

pub fn register_nvme_namespace(
    registration: &AbiNvmeNamespaceRegistration,
) -> Result<u64, AbiErrorCode> {
    let owner = current_driver_domain()?;
    NVME_NAMESPACES.register(owner, registration)
}

pub fn unregister_nvme_namespace(handle: u64) -> Result<(), AbiErrorCode> {
    let owner = current_driver_domain()?;
    NVME_NAMESPACES.unregister(owner, handle)
}

pub fn register_netdev_port(registration: &AbiNetPortRegistrationV3) -> Result<u64, AbiErrorCode> {
    let owner = current_driver_domain()?;
    NETDEV_PORTS.register(owner, registration)
}

pub fn unregister_netdev_port(handle: u64) -> Result<(), AbiErrorCode> {
    let owner = current_driver_domain()?;
    NETDEV_PORTS.unregister(owner, handle)
}

pub fn register_audio_controller(
    registration: &AbiAudioControllerRegistration,
) -> Result<u64, AbiErrorCode> {
    let owner = current_driver_domain()?;
    AUDIO_CONTROLLERS.register(owner, registration)
}

pub fn unregister_audio_controller(handle: u64) -> Result<(), AbiErrorCode> {
    let owner = current_driver_domain()?;
    AUDIO_CONTROLLERS.unregister(owner, handle)
}

pub fn cleanup_owner_domain(owner: DomainId) {
    BLOCK_DEVICES.cleanup_owner(owner);
    NVME_NAMESPACES.cleanup_owner(owner);
    NETDEV_PORTS.cleanup_owner(owner);
    AUDIO_CONTROLLERS.cleanup_owner(owner);
}

pub fn cleanup_for_driver_handle(handle: DriverHandle) {
    let Some(cell_id) = driver_domain_manager().find_by_driver_handle(handle) else {
        return;
    };
    if let Ok(Some(domain_id)) = driver_domain_manager().with_cell(cell_id, |cell| cell.domain_id) {
        cleanup_owner_domain(domain_id);
    }
}

pub fn standalone_storage_devices() -> Vec<StorageDeviceInfo> {
    BLOCK_DEVICES.storage_devices()
}

pub fn standalone_audio_devices() -> Vec<AudioDeviceInfo> {
    AUDIO_CONTROLLERS.devices()
}

pub fn standalone_nvme_namespace_info(namespace_id: u32) -> Option<AbiNvmeNamespaceInfo> {
    NvmeNamespaceRegistry::lookup(namespace_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_system::DomainId;
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

    extern "C" fn test_audio_initialized(_opaque: u64) -> bool {
        true
    }

    extern "C" fn test_audio_device_count(_opaque: u64) -> u32 {
        1
    }

    extern "C" fn test_audio_device_info(
        _opaque: u64,
        index: u32,
        out: *mut AbiAudioDeviceInfo,
    ) -> i32 {
        if index != 0 || out.is_null() {
            return AbiErrorCode::DeviceNotFound as i32;
        }
        unsafe {
            *out = AbiAudioDeviceInfo {
                device_id: 0xfeed,
                output_channels: 2,
                input_channels: 1,
                _padding0: 0,
                sample_rate_hz: 48_000,
                flags: 7,
            };
        }
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_audio_enable_irq(_opaque: u64) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_audio_disable_irq(_opaque: u64) -> i32 {
        AbiErrorCode::Success as i32
    }

    static TEST_NET_INTERRUPT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TEST_NET_INTERRUPTS_ENABLED: AtomicBool = AtomicBool::new(true);

    extern "C" fn test_net_start(_opaque: u64, _runtime: *const AbiNetPortRuntimeV2) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_bind(_opaque: u64, _if_id: u16) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_submit_tx(
        _opaque: u64,
        packet: *mut AbiPacketRefRaw,
        _meta: AbiNetTxMeta,
    ) -> i32 {
        let _ = AbiPacketRefRaw::take(packet);
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

    extern "C" fn test_net_stop(_opaque: u64) {}

    extern "C" fn test_net_set_interrupts_enabled(_opaque: u64, enabled: bool) -> i32 {
        TEST_NET_INTERRUPT_CALLS.fetch_add(1, Ordering::Relaxed);
        TEST_NET_INTERRUPTS_ENABLED.store(enabled, Ordering::Release);
        AbiErrorCode::Success as i32
    }

    fn test_net_info(kind: AbiNetPortKind, port_index: u16) -> AbiNetPortInfo {
        AbiNetPortInfo {
            port_id: 0x9000 + port_index as u64,
            kind: kind as u32,
            queue_pairs: 1,
            port_index,
            mtu: 1500,
            flags: 0,
            mac: [0x02, 0, 0, 0, 0, port_index as u8],
            _padding0: [0; 2],
            name_ptr: core::ptr::null(),
            name_len: 0,
        }
    }

    fn test_net_registration(port_index: u16) -> AbiNetPortRegistrationV3 {
        AbiNetPortRegistrationV3::new(
            test_net_info(AbiNetPortKind::Virtio, port_index),
            0,
            test_net_start,
            test_net_bind,
            test_net_submit_tx,
            test_net_poll,
            test_net_handle_event,
            test_net_stats,
            test_net_stop,
            test_net_set_interrupts_enabled,
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
    fn audio_registry_surfaces_devices_and_cleans_owner() {
        let registry = AudioBridgeRegistry::new();
        let owner = DomainId::new(31);
        let registration = AbiAudioControllerRegistration::new(
            0,
            42,
            test_audio_initialized,
            test_audio_device_count,
            test_audio_device_info,
            test_audio_enable_irq,
            test_audio_disable_irq,
        );

        let handle = registry
            .register(owner, &registration)
            .expect("audio registration");
        let devices = registry.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, 0xfeed);
        assert_eq!(devices[0].sample_rate_hz, 48_000);

        assert_eq!(
            registry.unregister(DomainId::new(32), handle),
            Err(AbiErrorCode::PermissionDenied)
        );
        registry.cleanup_owner(owner);
        assert!(registry.devices().is_empty());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn netdev_adapter_v3_invokes_interrupt_toggle_callback() {
        TEST_NET_INTERRUPT_CALLS.store(0, Ordering::Relaxed);
        TEST_NET_INTERRUPTS_ENABLED.store(true, Ordering::Release);

        let registration = test_net_registration(2);
        let adapter = NetdevPortAdapter::new(&registration, "test-net").expect("v3 adapter");

        assert_eq!(adapter.set_interrupts_enabled(false), Ok(()));
        assert_eq!(TEST_NET_INTERRUPT_CALLS.load(Ordering::Relaxed), 1);
        assert!(!TEST_NET_INTERRUPTS_ENABLED.load(Ordering::Acquire));
    }
}
