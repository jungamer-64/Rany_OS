extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp;
use core::slice;
use kernel_api::abi::driver::{
    AbiBlockCommandKind, AbiBlockDeviceInfo, AbiBlockDeviceRegistration, AbiBlockTransport,
    AbiError, AbiIoCompletion, AbiMmioHandle, AbiNetDriverEvent, AbiNetDriverEventKind,
    AbiNetPortInfo, AbiNetPortOpsV5, AbiNetPortRegistrationV5, AbiNetPortRuntimeV3,
    AbiNetPortStats, AbiNetRxMeta, AbiNetTxMeta, AbiNetTxSubmissionV4, AbiPacketRefRaw,
    DRIVER_ABI_VERSION, DriverCapabilities, DriverContext, DriverVTable, DriverVTableFns,
    PackedPciLocation, pack_version,
};
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::driver::DriverType;
use kernel_api::netdev::{
    NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP, NetDevicePort, NetTxMeta,
    NetTxSegment, TxSubmission,
};
use kernel_api::resource::net::PacketRef;
use kernel_api::service::kernel;
use spin::Mutex;

use crate::blk::{get_virtio_blk_device_at_index, init_virtio_blk_with_transport_at_index};
use crate::defs::VirtioDeviceType;
use crate::net::{
    NetDmaDirection, NetDmaMappingToken, NetDmaPurpose, NetRuntime, VirtioNetDriverAdapter,
    VirtioNetError, get_virtio_net_device_at_index, handle_virtio_net_interrupt_for_index,
    init_virtio_net_with_transport_at_index,
};
use crate::transport::{VirtioMmioTransport, VirtioPciTransport, VirtioTransport};

const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;
const PCI_CAP_PTR: u8 = 0x34;
const PCI_CAP_VENDOR_SPECIFIC: u8 = 0x09;
const PCI_BAR0: u8 = 0x10;
const PCI_BAR_MAP_SIZE: usize = 0x20_000;
const PORT_INDEX: u8 = 0;
const BLOCK_DEVICE_ID: u64 = 0x0001_0000_0000_0000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum VirtioStandaloneKind {
    Net,
    Block,
    Unsupported,
}

struct MappedBar {
    bar: u8,
    handle: AbiMmioHandle,
}

struct StandaloneNetRuntime {
    pci_locator: PackedPciLocation,
    runtime: Mutex<Option<AbiNetPortRuntimeV3>>,
}

impl StandaloneNetRuntime {
    const fn new(pci_locator: PackedPciLocation) -> Self {
        Self {
            pci_locator,
            runtime: Mutex::new(None),
        }
    }

    fn install_runtime(&self, runtime: AbiNetPortRuntimeV3) {
        *self.runtime.lock() = Some(runtime);
    }

    fn runtime(&self) -> Option<AbiNetPortRuntimeV3> {
        *self.runtime.lock()
    }
}

struct VirtioStandaloneState {
    kind: VirtioStandaloneKind,
    mapped_bars: Vec<MappedBar>,
    net_runtime: Option<Arc<StandaloneNetRuntime>>,
    netdev_handle: Option<u64>,
    block_handle: Option<u64>,
    block_pending: BTreeMap<u16, u64>,
}

static VIRTIO_STANDALONE_STATE: Mutex<Option<VirtioStandaloneState>> = Mutex::new(None);

fn kernel_api() -> &'static kernel_api::abi::driver::KernelApiV4 {
    kernel::abi()
}

fn kind_for_device(device_id: u16) -> VirtioStandaloneKind {
    match device_id {
        0x1000 | 0x1041 => VirtioStandaloneKind::Net,
        0x1001 | 0x1042 => VirtioStandaloneKind::Block,
        _ => VirtioStandaloneKind::Unsupported,
    }
}

fn device_type_for_id(device_id: u16) -> VirtioDeviceType {
    match device_id {
        0x1000 | 0x1041 => VirtioDeviceType::Network,
        0x1001 | 0x1042 => VirtioDeviceType::Block,
        0x1003 | 0x1043 => VirtioDeviceType::Console,
        0x1005 | 0x1045 => VirtioDeviceType::Balloon,
        0x1050 => VirtioDeviceType::Gpu,
        0x1052 => VirtioDeviceType::Input,
        _ => VirtioDeviceType::Unknown,
    }
}

fn config_addr(locator: PackedPciLocation, offset: u8) -> u32 {
    0x8000_0000
        | ((locator.bus() as u32) << 16)
        | ((locator.device() as u32) << 11)
        | ((locator.function() as u32) << 8)
        | ((offset as u32) & 0xFC)
}

fn pci_read32(locator: PackedPciLocation, offset: u8) -> u32 {
    hal::port_io::outl(PCI_CONFIG_ADDR, config_addr(locator, offset));
    hal::port_io::inl(PCI_CONFIG_DATA)
}

fn pci_read8(locator: PackedPciLocation, offset: u8) -> u8 {
    let shift = ((offset & 3) as u32) * 8;
    ((pci_read32(locator, offset) >> shift) & 0xFF) as u8
}

fn pci_bar_phys(locator: PackedPciLocation, bar: u8) -> Option<u64> {
    if bar >= 6 {
        return None;
    }
    let offset = PCI_BAR0 + bar.saturating_mul(4);
    let raw = pci_read32(locator, offset);
    if raw & 1 != 0 {
        return None;
    }
    let low = (raw & 0xFFFF_FFF0) as u64;
    let bar_type = (raw >> 1) & 0x3;
    if bar_type == 0x2 && bar + 1 < 6 {
        Some(low | ((pci_read32(locator, offset + 4) as u64) << 32))
    } else {
        Some(low)
    }
}

#[derive(Clone, Copy)]
struct PciCap {
    bar: u8,
    offset: u32,
}

#[derive(Default)]
struct PciCaps {
    common: Option<PciCap>,
    notify: Option<PciCap>,
    isr: Option<PciCap>,
    device: Option<PciCap>,
    notify_multiplier: u32,
}

fn pci_read_cap_u32(locator: PackedPciLocation, cap: u8, rel: u8) -> u32 {
    pci_read32(locator, cap.wrapping_add(rel))
}

fn parse_pci_caps(locator: PackedPciLocation) -> PciCaps {
    let mut caps = PciCaps {
        notify_multiplier: 1,
        ..PciCaps::default()
    };
    let mut cap = pci_read8(locator, PCI_CAP_PTR) & 0xFC;
    let mut visited = 0u8;
    while cap != 0 && visited < 48 {
        visited = visited.wrapping_add(1);
        let cap_id = pci_read8(locator, cap);
        let next = pci_read8(locator, cap.wrapping_add(1)) & 0xFC;
        if cap_id == PCI_CAP_VENDOR_SPECIFIC {
            let cfg_type = pci_read8(locator, cap.wrapping_add(3));
            let bar = pci_read8(locator, cap.wrapping_add(4));
            let offset = pci_read_cap_u32(locator, cap, 8);
            let pci_cap = PciCap { bar, offset };
            match cfg_type {
                1 => caps.common = Some(pci_cap),
                2 => {
                    caps.notify = Some(pci_cap);
                    caps.notify_multiplier = pci_read_cap_u32(locator, cap, 16);
                }
                3 => caps.isr = Some(pci_cap),
                4 => caps.device = Some(pci_cap),
                _ => {}
            }
        }
        cap = next;
    }
    caps
}

fn map_bar(
    mapped_bars: &mut Vec<MappedBar>,
    locator: PackedPciLocation,
    bar: u8,
) -> Option<AbiMmioHandle> {
    if let Some(mapped) = mapped_bars.iter().find(|mapped| mapped.bar == bar) {
        return Some(mapped.handle);
    }

    let phys_base = pci_bar_phys(locator, bar)?;
    let mut handle = AbiMmioHandle::default();
    let status = (kernel_api().map_mmio)(phys_base, PCI_BAR_MAP_SIZE, &mut handle);
    if status != 0 {
        return None;
    }
    mapped_bars.push(MappedBar { bar, handle });
    Some(handle)
}

fn cap_addr(
    mapped_bars: &mut Vec<MappedBar>,
    locator: PackedPciLocation,
    cap: Option<PciCap>,
) -> Option<usize> {
    let cap = cap?;
    let mapped = map_bar(mapped_bars, locator, cap.bar)?;
    Some((mapped.base + cap.offset as u64) as usize)
}

fn pci_transport(
    ctx: &DriverContext,
    mapped_bars: &mut Vec<MappedBar>,
) -> Option<Box<dyn VirtioTransport>> {
    let locator = ctx.pci_location();
    let caps = parse_pci_caps(locator);
    let common = cap_addr(mapped_bars, locator, caps.common)?;
    let notify = cap_addr(mapped_bars, locator, caps.notify)?;
    let isr = cap_addr(mapped_bars, locator, caps.isr).unwrap_or(0);
    let device = cap_addr(mapped_bars, locator, caps.device)?;
    let transport = unsafe {
        VirtioPciTransport::new(
            common,
            notify,
            caps.notify_multiplier,
            isr,
            device,
            device_type_for_id(ctx.device_id),
        )
        .ok()?
    };
    Some(Box::new(transport))
}

fn transport_for_context(
    ctx: &DriverContext,
    mapped_bars: &mut Vec<MappedBar>,
) -> Option<Box<dyn VirtioTransport>> {
    pci_transport(ctx, mapped_bars).or_else(|| {
        let transport = unsafe { VirtioMmioTransport::new(ctx.device_address as usize).ok()? };
        Some(Box::new(transport))
    })
}

impl NetRuntime for StandaloneNetRuntime {
    fn alloc_dma(
        &self,
        size: usize,
        _purpose: NetDmaPurpose,
    ) -> Result<DmaSlice<CpuOwned>, VirtioNetError> {
        kernel::instance()
            .alloc_dma_for_device(size, self.pci_locator)
            .map_err(|_| VirtioNetError::DeviceError)
    }

    fn alloc_packet(&self) -> Option<PacketRef> {
        let runtime = self.runtime()?;
        let mut raw = AbiPacketRefRaw::default();
        if (runtime.alloc_packet)(runtime.runtime_cookie, &mut raw) != 0 || raw.is_null() {
            None
        } else {
            Some(raw.into_packet())
        }
    }

    fn map_packet(
        &self,
        packet: &PacketRef,
        _direction: NetDmaDirection,
    ) -> Result<NetDmaMappingToken, VirtioNetError> {
        Ok(NetDmaMappingToken::direct(packet.device_address()))
    }

    fn release_dma_mapping(&self, _mapping: NetDmaMappingToken) {}

    fn receive_packet(
        &self,
        queue_index: u16,
        packet: PacketRef,
        header_len: usize,
        payload_len: usize,
    ) {
        let Some(runtime) = self.runtime() else {
            return;
        };
        let mut raw = AbiPacketRefRaw::from_packet(packet);
        let meta = AbiNetRxMeta {
            queue_index,
            header_len: header_len as u16,
            payload_len: payload_len as u16,
            flags: 0,
        };
        let _ = (runtime.submit_rx_packet)(runtime.runtime_cookie, &mut raw, meta);
    }

    fn transmit_complete(&self, _queue_index: u16, lease_id: u64) {
        if let Some(runtime) = self.runtime() {
            let _ = (runtime.complete_tx_lease)(runtime.runtime_cookie, lease_id, 0);
        }
    }

    fn schedule_wake(&self, queue_index: u16) {
        if let Some(runtime) = self.runtime() {
            let event = AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::QueueWake as u32,
                queue_index,
                _padding: 0,
            };
            let _ = (runtime.schedule_event)(runtime.runtime_cookie, event);
        }
    }

    fn log(&self, level: log::Level, msg: core::fmt::Arguments) {
        if let Some(runtime) = self.runtime() {
            let msg = alloc::format!("{}", msg);
            (runtime.log)(
                runtime.runtime_cookie,
                level as u32,
                msg.as_ptr(),
                msg.len(),
            );
        }
    }
}

extern "C" fn netdev_start(_opaque: u64, runtime: *const AbiNetPortRuntimeV3) -> i32 {
    if runtime.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let guard = VIRTIO_STANDALONE_STATE.lock();
    let Some(state) = guard.as_ref() else {
        return AbiError::NotInitialized as i32;
    };
    let Some(net_runtime) = state.net_runtime.as_ref() else {
        return AbiError::NotSupported as i32;
    };
    net_runtime.install_runtime(unsafe { *runtime });
    if let Some(device) = get_virtio_net_device_at_index(PORT_INDEX) {
        device.refill_rx_queues();
    }
    AbiError::Success as i32
}

extern "C" fn netdev_bind(_opaque: u64, if_id: u16) -> i32 {
    if let Some(device) = get_virtio_net_device_at_index(PORT_INDEX) {
        device.set_net_if_id(if_id);
        AbiError::Success as i32
    } else {
        AbiError::NotInitialized as i32
    }
}

extern "C" fn netdev_submit_tx_chain(
    _opaque: u64,
    submission: *const AbiNetTxSubmissionV4,
    meta: AbiNetTxMeta,
) -> i32 {
    if submission.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let submission = unsafe { &*submission };
    let abi_segments = if submission.segments_ptr.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(submission.segments_ptr, submission.segments_len) }
    };
    let mut segments = Vec::with_capacity(abi_segments.len());
    for segment in abi_segments {
        segments.push(NetTxSegment {
            cpu_ptr: segment.cpu_ptr as usize,
            device_addr: segment.device_addr,
            len: segment.len,
        });
    }
    let tx = TxSubmission::new(submission.lease_id, &segments);
    let tx_meta = NetTxMeta {
        queue_index: meta.has_queue_index.then_some(meta.queue_index),
        flags: meta.flags,
        vlan_tag: meta.has_vlan_tag.then_some(meta.vlan_tag),
        completion_id: None,
        completion_policy: Default::default(),
    };
    let Some(device) = get_virtio_net_device_at_index(PORT_INDEX) else {
        return AbiError::NotInitialized as i32;
    };
    match device.enqueue_send_submission(tx, tx_meta) {
        Ok(()) => AbiError::Success as i32,
        Err(_) => AbiError::DeviceBusy as i32,
    }
}

extern "C" fn netdev_poll(_opaque: u64, _if_id: u16) -> i32 {
    if let Some(device) = get_virtio_net_device_at_index(PORT_INDEX) {
        device.process_interrupt_deferred();
        device.refill_rx_queues();
        AbiError::Success as i32
    } else {
        AbiError::NotInitialized as i32
    }
}

extern "C" fn netdev_handle_event(opaque: u64, if_id: u16, _event: AbiNetDriverEvent) -> i32 {
    netdev_poll(opaque, if_id)
}

extern "C" fn netdev_stats(_opaque: u64, out: *mut AbiNetPortStats) -> i32 {
    if out.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let Some(device) = get_virtio_net_device_at_index(PORT_INDEX) else {
        return AbiError::NotInitialized as i32;
    };
    let stats = device.net_port_stats();
    unsafe {
        *out = AbiNetPortStats {
            tx_packets: stats.tx_packets,
            rx_packets: stats.rx_packets,
            tx_errors: stats.tx_errors,
            rx_errors: stats.rx_errors,
            initialized: stats.initialized,
            reserved: [0; 7],
        };
    }
    AbiError::Success as i32
}

extern "C" fn netdev_stop(_opaque: u64) {
    if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_ref()
        && let Some(runtime) = state.net_runtime.as_ref()
    {
        runtime.install_runtime(AbiNetPortRuntimeV3::new(
            0,
            empty_alloc_packet,
            empty_submit_rx_packet,
            empty_complete_tx_lease,
            empty_schedule_event,
            empty_update_link,
            empty_log,
        ));
    }
}

extern "C" fn netdev_set_interrupts_enabled(_opaque: u64, enabled: bool) -> i32 {
    if let Some(device) = get_virtio_net_device_at_index(PORT_INDEX) {
        device.set_interrupts_enabled_all(enabled);
        AbiError::Success as i32
    } else {
        AbiError::NotInitialized as i32
    }
}

extern "C" fn empty_alloc_packet(_cookie: u64, _out: *mut AbiPacketRefRaw) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_submit_rx_packet(
    _cookie: u64,
    _packet: *mut AbiPacketRefRaw,
    _meta: AbiNetRxMeta,
) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_complete_tx_lease(_cookie: u64, _lease_id: u64, _status: i32) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_schedule_event(_cookie: u64, _event: AbiNetDriverEvent) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_update_link(_cookie: u64, _up: bool) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_log(_cookie: u64, _level: u32, _msg: *const u8, _len: usize) {}

fn netdev_registration() -> AbiNetPortRegistrationV5 {
    let adapter = VirtioNetDriverAdapter::new(PORT_INDEX);
    let info = adapter.info();
    AbiNetPortRegistrationV5::new(
        AbiNetPortInfo {
            port_id: info.port_id.as_u64(),
            queue_pairs: cmp::max(1, info.queue_pairs),
            reserved_queue: 0,
            mtu: info.mtu,
            flags: info.flags | NETDEV_FLAG_ADMIN_UP | NETDEV_FLAG_HEALTHY | NETDEV_FLAG_LINK_UP,
            mac: *info.mac.as_bytes(),
            reserved0: [0; 2],
            name_ptr: virtio_net_name().as_ptr(),
            name_len: virtio_net_name().len(),
        },
        0,
        AbiNetPortOpsV5 {
            start: netdev_start,
            bind: netdev_bind,
            submit_tx_chain: netdev_submit_tx_chain,
            poll: netdev_poll,
            handle_event: netdev_handle_event,
            stats: netdev_stats,
            stop: netdev_stop,
            set_interrupts_enabled: netdev_set_interrupts_enabled,
        },
    )
}

extern "C" fn block_submit(
    _opaque: u64,
    request_id: u64,
    command: u32,
    lba: u64,
    _blocks: u32,
    bytes: usize,
    iova: u64,
) -> i32 {
    let Some(device) = get_virtio_blk_device_at_index(PORT_INDEX) else {
        return AbiError::NotInitialized as i32;
    };
    let result = match command {
        x if x == AbiBlockCommandKind::Read as u32 => {
            device.submit_read(lba, iova, bytes as u32, 0)
        }
        x if x == AbiBlockCommandKind::Write as u32 => {
            device.submit_write(lba, iova, bytes as u32, 0)
        }
        x if x == AbiBlockCommandKind::Flush as u32 => device.submit_flush(0),
        _ => return AbiError::NotSupported as i32,
    };
    match result {
        Ok(desc) => {
            if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_mut() {
                state.block_pending.insert(desc, request_id);
            }
            AbiError::Success as i32
        }
        Err(_) => AbiError::IoError as i32,
    }
}

extern "C" fn block_poll(
    _opaque: u64,
    out: *mut AbiIoCompletion,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let Some(device) = get_virtio_blk_device_at_index(PORT_INDEX) else {
        return AbiError::NotInitialized as i32;
    };
    let mut completions: Vec<(u16, usize, bool)> = Vec::new();
    device.drain_completions_with(|_queue, desc, len, ok| {
        completions.push((desc, len as usize, ok));
    });
    let mut emitted = 0usize;
    let mut state_guard = VIRTIO_STANDALONE_STATE.lock();
    let Some(state) = state_guard.as_mut() else {
        unsafe { *written = 0 };
        return AbiError::NotInitialized as i32;
    };
    for (desc, bytes, ok) in completions {
        if emitted >= capacity {
            break;
        }
        let Some(request_id) = state.block_pending.remove(&desc) else {
            continue;
        };
        if !out.is_null() {
            unsafe {
                *out.add(emitted) = AbiIoCompletion {
                    request_id,
                    status: if ok { 0 } else { AbiError::IoError as i32 },
                    bytes,
                };
            }
        }
        emitted += 1;
    }
    unsafe { *written = emitted };
    AbiError::Success as i32
}

extern "C" fn block_is_ready(_opaque: u64) -> bool {
    get_virtio_blk_device_at_index(PORT_INDEX)
        .map(|device| device.is_ready())
        .unwrap_or(false)
}

fn block_registration() -> Option<AbiBlockDeviceRegistration> {
    let device = get_virtio_blk_device_at_index(PORT_INDEX)?;
    let cfg = device.config();
    Some(AbiBlockDeviceRegistration::new(
        AbiBlockDeviceInfo {
            device_id: BLOCK_DEVICE_ID,
            namespace_id: 0,
            block_size: cfg.block_size,
            max_transfer_blocks: 0,
            transport: AbiBlockTransport::Other as u32,
            flags: 0,
            controller_id: 0,
            port_id: 0,
        },
        0,
        block_submit,
        block_poll,
        block_is_ready,
    ))
}

extern "C" fn virtio_probe(ctx: *mut DriverContext) -> i32 {
    if ctx.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let ctx = unsafe { &mut *ctx };
    let kind = kind_for_device(ctx.device_id);
    if kind == VirtioStandaloneKind::Unsupported {
        return AbiError::NotSupported as i32;
    }

    let mut mapped_bars = Vec::new();
    let Some(transport) = transport_for_context(ctx, &mut mapped_bars) else {
        return AbiError::DeviceNotFound as i32;
    };
    let pci_locator = ctx.pci_location();

    let result = match kind {
        VirtioStandaloneKind::Net => {
            let runtime = Arc::new(StandaloneNetRuntime::new(pci_locator));
            let init = unsafe {
                init_virtio_net_with_transport_at_index(PORT_INDEX, transport, runtime.clone())
            };
            init.map(|_| Some(runtime)).map_err(|_| ())
        }
        VirtioStandaloneKind::Block => {
            let init = unsafe {
                init_virtio_blk_with_transport_at_index(PORT_INDEX, transport, pci_locator)
            };
            init.map(|_| None).map_err(|_| ())
        }
        VirtioStandaloneKind::Unsupported => Err(()),
    };

    let net_runtime = match result {
        Ok(runtime) => runtime,
        Err(()) => {
            for mapped in &mapped_bars {
                let _ = (kernel_api().unmap_mmio)(&mapped.handle);
            }
            return AbiError::IoError as i32;
        }
    };

    *VIRTIO_STANDALONE_STATE.lock() = Some(VirtioStandaloneState {
        kind,
        mapped_bars,
        net_runtime,
        netdev_handle: None,
        block_handle: None,
        block_pending: BTreeMap::new(),
    });
    AbiError::Success as i32
}

extern "C" fn virtio_start(_ctx: *mut DriverContext) -> i32 {
    let mut guard = VIRTIO_STANDALONE_STATE.lock();
    let Some(state) = guard.as_mut() else {
        return AbiError::NotInitialized as i32;
    };
    match state.kind {
        VirtioStandaloneKind::Net => {
            if state.netdev_handle.is_some() {
                return AbiError::Success as i32;
            }
            let registration = netdev_registration();
            let mut handle = 0u64;
            let status = (kernel_api().register_netdev_port)(&registration, &mut handle);
            if status == 0 {
                state.netdev_handle = Some(handle);
            }
            status
        }
        VirtioStandaloneKind::Block => {
            if state.block_handle.is_some() {
                return AbiError::Success as i32;
            }
            let Some(registration) = block_registration() else {
                return AbiError::NotInitialized as i32;
            };
            let mut handle = 0u64;
            let status = (kernel_api().register_block_device)(&registration, &mut handle);
            if status == 0 {
                state.block_handle = Some(handle);
            }
            status
        }
        VirtioStandaloneKind::Unsupported => AbiError::NotSupported as i32,
    }
}

extern "C" fn virtio_stop(_ctx: *mut DriverContext) -> i32 {
    let mut guard = VIRTIO_STANDALONE_STATE.lock();
    let Some(state) = guard.as_mut() else {
        return AbiError::Success as i32;
    };
    if let Some(handle) = state.netdev_handle.take() {
        let _ = (kernel_api().unregister_netdev_port)(handle);
    }
    if let Some(handle) = state.block_handle.take() {
        let _ = (kernel_api().unregister_block_device)(handle);
    }
    AbiError::Success as i32
}

extern "C" fn virtio_remove(ctx: *mut DriverContext) -> i32 {
    let _ = virtio_stop(ctx);
    if let Some(state) = VIRTIO_STANDALONE_STATE.lock().take() {
        for mapped in &state.mapped_bars {
            let _ = (kernel_api().unmap_mmio)(&mapped.handle);
        }
    }
    AbiError::Success as i32
}

extern "C" fn virtio_handle_irq(_ctx: *mut DriverContext) -> bool {
    let guard = VIRTIO_STANDALONE_STATE.lock();
    let Some(state) = guard.as_ref() else {
        return false;
    };
    match state.kind {
        VirtioStandaloneKind::Net => {
            handle_virtio_net_interrupt_for_index(PORT_INDEX);
            true
        }
        VirtioStandaloneKind::Block => {
            crate::blk::handle_virtio_blk_interrupt_for_index(PORT_INDEX);
            true
        }
        VirtioStandaloneKind::Unsupported => false,
    }
}

fn virtio_driver_name() -> &'static [u8] {
    b"virtio\0"
}

fn virtio_net_name() -> &'static [u8] {
    b"virtio-net"
}

extern "C" fn virtio_name() -> *const u8 {
    virtio_driver_name().as_ptr()
}

extern "C" fn virtio_name_len() -> usize {
    virtio_driver_name().len() - 1
}

extern "C" fn virtio_driver_type() -> u32 {
    DriverType::Other as u32
}

extern "C" fn virtio_version() -> u64 {
    pack_version(0, 1, 0)
}

extern "C" fn virtio_request_capabilities(caps: *mut DriverCapabilities) {
    if caps.is_null() {
        return;
    }
    unsafe {
        (*caps).needs_dma = true;
        (*caps).needs_irq = true;
        (*caps).needs_mmio = true;
        (*caps).needs_io_ports = true;
    }
}

pub fn standalone_driver_vtable() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        DriverVTableFns {
            probe: virtio_probe,
            start: virtio_start,
            stop: virtio_stop,
            remove: virtio_remove,
            name: virtio_name,
            name_len: virtio_name_len,
            driver_type: virtio_driver_type,
            version: virtio_version,
            request_capabilities: Some(virtio_request_capabilities),
            handle_irq: Some(virtio_handle_irq),
        },
    );
    &VTABLE
}

#[cfg(feature = "export_driver_entry")]
#[unsafe(export_name = "_exorust_driver_entry")]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    standalone_driver_vtable()
}
