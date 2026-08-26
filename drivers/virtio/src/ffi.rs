extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_api::abi::driver::{
    AbiBlockCommandKind, AbiBlockDeviceInfo, AbiBlockDeviceRegistration, AbiBlockTransport,
    AbiError, AbiIoCompletion, AbiMmioHandle, AbiNetDriverEvent, AbiNetDriverEventKind,
    AbiNetPortInfo, AbiNetPortOps, AbiNetPortRegistration, AbiNetPortRuntime, AbiNetPortStats,
    AbiNetRxFrameLayout, AbiNetRxMeta, AbiNetTxMeta, AbiNetTxSubmission, AbiRxLease,
    AbiRxLeaseGuard, AbiTxDeviceOutcome, DRIVER_ABI_VERSION, DriverCapabilities, DriverContext,
    DriverVTable, DriverVTableFns, PackedPciLocation, pack_version,
};
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::driver::DriverType;
use kernel_api::netdev::{NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_HEALTHY, NetPortId, TxLeaseId};
use kernel_api::service::kernel;
use spin::Mutex;

use crate::blk::{get_virtio_blk_device_at_index, init_virtio_blk_with_transport_at_index};
use crate::defs::VirtioDeviceType;
use crate::net::{
    NetDmaPurpose, NetRuntime, RxDmaLease, VirtioNetError, handle_virtio_net_interrupt_for_index,
    init_virtio_net_with_transport_at_index, with_virtio_net_at_index,
};
use crate::transport::{VirtioMmioTransport, VirtioPciTransport, VirtioTransport};

const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;
const PCI_CAP_PTR: u8 = 0x34;
const PCI_CAP_VENDOR_SPECIFIC: u8 = 0x09;
const PCI_BAR0: u8 = 0x10;
const PCI_BAR_MAP_SIZE: usize = 0x20_000;
const PORT_INDEX: u8 = 0;
const NET_PORT_ID: u64 = 0x0001_0000 | PORT_INDEX as u64;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum StandaloneRegistration {
    Idle,
    Registering,
    Registered(u64),
    Unregistering(u64),
}

struct StandaloneNetRuntime {
    pci_locator: PackedPciLocation,
    runtime: Mutex<Option<AbiNetPortRuntime>>,
}

#[derive(Clone, Copy)]
struct StandaloneNetRuntimeHandle(core::ptr::NonNull<StandaloneNetRuntime>);

unsafe impl Send for StandaloneNetRuntimeHandle {}

impl StandaloneNetRuntimeHandle {
    fn new(runtime: &StandaloneNetRuntime) -> Self {
        Self(core::ptr::NonNull::from(runtime))
    }

    fn install_runtime(self, runtime: AbiNetPortRuntime) {
        unsafe { self.0.as_ref() }.install_runtime(runtime);
    }
}

impl StandaloneNetRuntime {
    const fn new(pci_locator: PackedPciLocation) -> Self {
        Self {
            pci_locator,
            runtime: Mutex::new(None),
        }
    }

    fn install_runtime(&self, runtime: AbiNetPortRuntime) {
        *self.runtime.lock() = Some(runtime);
    }

    fn runtime(&self) -> Option<AbiNetPortRuntime> {
        *self.runtime.lock()
    }
}

struct VirtioStandaloneState {
    kind: VirtioStandaloneKind,
    pci_locator: PackedPciLocation,
    mapped_bars: Vec<MappedBar>,
    net_runtime: Option<StandaloneNetRuntimeHandle>,
    interrupt: StandaloneInterrupt,
    registration: StandaloneRegistration,
    block_pending: BTreeMap<u16, u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StandaloneInterrupt {
    None,
    Bound { vector: u32 },
    Unbound,
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
            .map_err(|err| {
                let message = alloc::format!(
                    "virtio-net DMA allocation failed: size={size} device={:?} error={err:?}",
                    self.pci_locator
                );
                (kernel_api().log)(log::Level::Error as u32, message.as_ptr(), message.len());
                VirtioNetError::DeviceError
            })
    }

    fn lease_rx_buffer(&self) -> Option<RxDmaLease> {
        let runtime = self.runtime()?;
        AbiRxLeaseGuard::acquire(runtime)
            .ok()
            .map(RxDmaLease::from_abi)
    }

    fn receive_packet(
        &self,
        queue_index: u16,
        buffer: RxDmaLease,
        header_len: usize,
        payload_len: usize,
        flags: u32,
    ) {
        let Some(layout) =
            AbiNetRxFrameLayout::new(header_len + payload_len, header_len, payload_len)
        else {
            return;
        };
        let meta = AbiNetRxMeta::new(queue_index, layout, flags);
        let _ = buffer.submit(meta);
    }

    fn transmit_complete(&self, _queue_index: u16, lease_id: TxLeaseId) {
        if let Some(runtime) = self.runtime() {
            let _ = (runtime.complete_tx_lease)(
                runtime.runtime_cookie,
                lease_id.get(),
                AbiTxDeviceOutcome::TRANSMITTED,
            );
        }
    }

    fn schedule_interrupt(&self) {
        if let Some(runtime) = self.runtime() {
            let event = AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::Interrupt as u32,
                queue_index: 0,
                _padding: 0,
            };
            let _ = (runtime.schedule_event)(runtime.runtime_cookie, event);
        }
    }

    fn update_link(&self, up: bool) {
        if let Some(runtime) = self.runtime() {
            let _ = (runtime.update_link)(runtime.runtime_cookie, up);
        }
    }

    fn log(&self, level: log::Level, msg: core::fmt::Arguments) {
        let msg = alloc::format!("{}", msg);
        if let Some(runtime) = self.runtime() {
            (runtime.log)(
                runtime.runtime_cookie,
                level as u32,
                msg.as_ptr(),
                msg.len(),
            );
        } else {
            (kernel_api().log)(level as u32, msg.as_ptr(), msg.len());
        }
    }
}

extern "C" fn netdev_start(_opaque: u64, runtime: *const AbiNetPortRuntime) -> i32 {
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
    (*net_runtime).install_runtime(unsafe { *runtime });
    let _ = with_virtio_net_at_index(PORT_INDEX, |device| {
        device.publish_link_state();
        device.refill_rx_queues();
    });
    AbiError::Success as i32
}

extern "C" fn netdev_bind(_opaque: u64, if_id: u16) -> i32 {
    if with_virtio_net_at_index(PORT_INDEX, |device| {
        device.set_net_if_id(if_id);
    })
    .is_some()
    {
        AbiError::Success as i32
    } else {
        AbiError::NotInitialized as i32
    }
}

extern "C" fn netdev_submit_tx_chain(
    _opaque: u64,
    submission: *const AbiNetTxSubmission,
    _meta: AbiNetTxMeta,
) -> i32 {
    if submission.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let submission = unsafe { &*submission };
    let Some(abi_segments) = submission.segments() else {
        return AbiError::InvalidParam as i32;
    };
    let Some(lease_id) = submission.lease_id() else {
        return AbiError::InvalidParam as i32;
    };
    with_virtio_net_at_index(PORT_INDEX, |device| {
        match device.enqueue_send_segments(
            lease_id,
            abi_segments.count(),
            abi_segments
                .iter()
                .map(|segment| (segment.device_addr(), segment.len())),
        ) {
            Ok(()) => AbiError::Success as i32,
            Err(_) => AbiError::DeviceBusy as i32,
        }
    })
    .unwrap_or(AbiError::NotInitialized as i32)
}

extern "C" fn netdev_poll(_opaque: u64, _if_id: u16) -> i32 {
    if with_virtio_net_at_index(PORT_INDEX, |device| {
        device.process_interrupt_deferred();
        device.refill_rx_queues();
    })
    .is_some()
    {
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
    with_virtio_net_at_index(PORT_INDEX, |device| {
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
    })
    .unwrap_or(AbiError::NotInitialized as i32)
}

extern "C" fn netdev_stop(_opaque: u64) -> i32 {
    if with_virtio_net_at_index(PORT_INDEX, |device| device.quiesce()).is_none() {
        return AbiError::NotInitialized as i32;
    }
    if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_ref()
        && let Some(runtime) = state.net_runtime.as_ref()
    {
        (*runtime).install_runtime(AbiNetPortRuntime::new(
            0,
            empty_lease_rx_buffer,
            empty_release_rx_buffer,
            empty_submit_rx_buffer,
            empty_complete_tx_lease,
            empty_schedule_event,
            empty_update_link,
            empty_log,
        ));
    }
    AbiError::Success as i32
}

extern "C" fn netdev_set_interrupts_enabled(_opaque: u64, enabled: bool) -> i32 {
    if with_virtio_net_at_index(PORT_INDEX, |device| {
        device.set_interrupts_enabled_all(enabled);
    })
    .is_some()
    {
        AbiError::Success as i32
    } else {
        AbiError::NotInitialized as i32
    }
}

extern "C" fn empty_lease_rx_buffer(_cookie: u64, _out: *mut AbiRxLease) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_release_rx_buffer(_cookie: u64, _lease: *mut AbiRxLease) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_submit_rx_buffer(
    _cookie: u64,
    _lease: *mut AbiRxLease,
    _meta: AbiNetRxMeta,
) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_complete_tx_lease(
    _cookie: u64,
    _lease_id: u64,
    _outcome: AbiTxDeviceOutcome,
) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_schedule_event(_cookie: u64, _event: AbiNetDriverEvent) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_update_link(_cookie: u64, _up: bool) -> i32 {
    AbiError::NotInitialized as i32
}

extern "C" fn empty_log(_cookie: u64, _level: u32, _msg: *const u8, _len: usize) {}

fn netdev_registration() -> Option<AbiNetPortRegistration> {
    let info = with_virtio_net_at_index(PORT_INDEX, |device| {
        device.info_snapshot(NetPortId::new(NET_PORT_ID))
    })?;
    Some(AbiNetPortRegistration::new(
        AbiNetPortInfo {
            port_id: info.port_id.as_u64(),
            queue_pairs: info.queue_pairs.max(1),
            max_tx_segments: info.max_tx_segments.get(),
            mtu: info.mtu,
            flags: info.flags | NETDEV_FLAG_ADMIN_UP | NETDEV_FLAG_HEALTHY,
            mac: *info.mac.as_bytes(),
            reserved0: [0; 2],
            name_ptr: virtio_net_name().as_ptr(),
            name_len: virtio_net_name().len(),
        },
        0,
        AbiNetPortOps {
            start: netdev_start,
            bind: netdev_bind,
            submit_tx_chain: netdev_submit_tx_chain,
            poll: netdev_poll,
            handle_event: netdev_handle_event,
            stats: netdev_stats,
            stop: netdev_stop,
            set_interrupts_enabled: netdev_set_interrupts_enabled,
        },
    ))
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
    let interrupt = if kind == VirtioStandaloneKind::Net && transport.supports_msix() {
        let Some(vector) = kernel::instance()
            .enable_msix(pci_locator, 1)
            .ok()
            .and_then(|vectors| vectors.into_iter().next())
        else {
            for mapped in &mapped_bars {
                let _ = (kernel_api().unmap_mmio)(&mapped.handle);
            }
            return AbiError::IoError as i32;
        };
        let bind_status = (kernel_api().irq_bind)(vector.vector, 0);
        if !AbiError::from_raw(bind_status).is_success() {
            let _ = kernel::instance().disable_msix(pci_locator);
            for mapped in &mapped_bars {
                let _ = (kernel_api().unmap_mmio)(&mapped.handle);
            }
            return bind_status;
        }
        Some((vector.vector, vector.table_index))
    } else {
        None
    };

    let result = match kind {
        VirtioStandaloneKind::Net => {
            let runtime = Arc::new(StandaloneNetRuntime::new(pci_locator));
            let runtime_handle = StandaloneNetRuntimeHandle::new(runtime.as_ref());
            let init = unsafe {
                init_virtio_net_with_transport_at_index(
                    PORT_INDEX,
                    transport,
                    runtime,
                    interrupt.map(|(_, table_index)| table_index),
                )
            };
            init.map(|_| Some(runtime_handle)).map_err(|_| ())
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
            if let Some((vector, _)) = interrupt {
                let _ = (kernel_api().irq_unbind)(vector);
                let _ = kernel::instance().disable_msix(pci_locator);
            }
            for mapped in &mapped_bars {
                let _ = (kernel_api().unmap_mmio)(&mapped.handle);
            }
            return AbiError::IoError as i32;
        }
    };

    *VIRTIO_STANDALONE_STATE.lock() = Some(VirtioStandaloneState {
        kind,
        pci_locator,
        mapped_bars,
        net_runtime,
        interrupt: interrupt.map_or(StandaloneInterrupt::None, |(vector, _)| {
            StandaloneInterrupt::Bound { vector }
        }),
        registration: StandaloneRegistration::Idle,
        block_pending: BTreeMap::new(),
    });
    AbiError::Success as i32
}

extern "C" fn virtio_start(_ctx: *mut DriverContext) -> i32 {
    let kind = {
        let mut guard = VIRTIO_STANDALONE_STATE.lock();
        let Some(state) = guard.as_mut() else {
            return AbiError::NotInitialized as i32;
        };
        match state.registration {
            StandaloneRegistration::Registered(_) => return AbiError::Success as i32,
            StandaloneRegistration::Registering | StandaloneRegistration::Unregistering(_) => {
                return AbiError::DeviceBusy as i32;
            }
            StandaloneRegistration::Idle => {
                state.registration = StandaloneRegistration::Registering;
                state.kind
            }
        }
    };

    let mut handle = 0u64;
    let status = match kind {
        VirtioStandaloneKind::Net => {
            let Some(registration) = netdev_registration() else {
                if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_mut() {
                    state.registration = StandaloneRegistration::Idle;
                }
                return AbiError::NotInitialized as i32;
            };
            (kernel_api().register_netdev_port)(&registration, &mut handle)
        }
        VirtioStandaloneKind::Block => {
            let Some(registration) = block_registration() else {
                if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_mut() {
                    state.registration = StandaloneRegistration::Idle;
                }
                return AbiError::NotInitialized as i32;
            };
            (kernel_api().register_block_device)(&registration, &mut handle)
        }
        VirtioStandaloneKind::Unsupported => AbiError::NotSupported as i32,
    };

    let mut orphaned_registration = None;
    {
        let mut guard = VIRTIO_STANDALONE_STATE.lock();
        if let Some(state) = guard.as_mut()
            && state.kind == kind
            && state.registration == StandaloneRegistration::Registering
        {
            state.registration = if status == AbiError::Success as i32 {
                StandaloneRegistration::Registered(handle)
            } else {
                StandaloneRegistration::Idle
            };
        } else if status == AbiError::Success as i32 {
            orphaned_registration = Some((kind, handle));
        }
    }

    if let Some((kind, handle)) = orphaned_registration {
        match kind {
            VirtioStandaloneKind::Net => {
                let _ = (kernel_api().unregister_netdev_port)(handle);
            }
            VirtioStandaloneKind::Block => {
                let _ = (kernel_api().unregister_block_device)(handle);
            }
            VirtioStandaloneKind::Unsupported => {}
        }
        return AbiError::NotInitialized as i32;
    }

    status
}

extern "C" fn virtio_stop(_ctx: *mut DriverContext) -> i32 {
    let registration = {
        let mut guard = VIRTIO_STANDALONE_STATE.lock();
        let Some(state) = guard.as_mut() else {
            return AbiError::Success as i32;
        };
        match state.registration {
            StandaloneRegistration::Idle => None,
            StandaloneRegistration::Registering | StandaloneRegistration::Unregistering(_) => {
                return AbiError::DeviceBusy as i32;
            }
            StandaloneRegistration::Registered(handle) => {
                state.registration = StandaloneRegistration::Unregistering(handle);
                Some((state.kind, handle))
            }
        }
    };

    if let Some((kind, handle)) = registration {
        let status = match kind {
            VirtioStandaloneKind::Net => (kernel_api().unregister_netdev_port)(handle),
            VirtioStandaloneKind::Block => (kernel_api().unregister_block_device)(handle),
            VirtioStandaloneKind::Unsupported => AbiError::NotSupported as i32,
        };

        if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_mut()
            && state.kind == kind
            && state.registration == StandaloneRegistration::Unregistering(handle)
        {
            state.registration = if AbiError::from_raw(status).is_success() {
                StandaloneRegistration::Idle
            } else {
                StandaloneRegistration::Registered(handle)
            };
        }
        if !AbiError::from_raw(status).is_success() {
            return status;
        }
    }

    release_standalone_interrupt()
}

fn release_standalone_interrupt() -> i32 {
    loop {
        let action = {
            let guard = VIRTIO_STANDALONE_STATE.lock();
            let Some(state) = guard.as_ref() else {
                return AbiError::Success as i32;
            };
            (state.pci_locator, state.interrupt)
        };
        match action.1 {
            StandaloneInterrupt::None => return AbiError::Success as i32,
            StandaloneInterrupt::Bound { vector } => {
                let status = (kernel_api().irq_unbind)(vector);
                if !AbiError::from_raw(status).is_success() {
                    return status;
                }
                if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_mut()
                    && state.interrupt == action.1
                {
                    state.interrupt = StandaloneInterrupt::Unbound;
                }
            }
            StandaloneInterrupt::Unbound => {
                if kernel::instance().disable_msix(action.0).is_err() {
                    return AbiError::IoError as i32;
                }
                if let Some(state) = VIRTIO_STANDALONE_STATE.lock().as_mut()
                    && state.interrupt == StandaloneInterrupt::Unbound
                {
                    state.interrupt = StandaloneInterrupt::None;
                }
            }
        }
    }
}

extern "C" fn virtio_remove(ctx: *mut DriverContext) -> i32 {
    let status = virtio_stop(ctx);
    if status != AbiError::Success as i32 {
        return status;
    }
    if let Some(state) = VIRTIO_STANDALONE_STATE.lock().take() {
        for mapped in &state.mapped_bars {
            let _ = (kernel_api().unmap_mmio)(&mapped.handle);
        }
    }
    AbiError::Success as i32
}

extern "C" fn virtio_handle_irq(_ctx: *mut DriverContext) -> bool {
    let kind = VIRTIO_STANDALONE_STATE
        .lock()
        .as_ref()
        .map(|state| state.kind);
    let Some(kind) = kind else {
        return false;
    };
    match kind {
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
