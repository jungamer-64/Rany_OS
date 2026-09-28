// ============================================================================
// drivers/mlx5/src/ffi.rs - ABI-Stable Driver Export
// ============================================================================
//!
//! FFI adapter for the NVIDIA/Mellanox ConnectX Family (mlx5) driver.
//!
//! Exports a C-compatible `DriverVTable` for dynamic loading.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp;
use core::sync::atomic::{AtomicU32, Ordering};
#[cfg(test)]
use kernel_api::abi::driver::{
    AbiBlockDeviceRegistration, AbiDmaAllocation, AbiDmaRequest, AbiDmaResponse, AbiDmaStatus,
    AbiNvmeNamespaceRegistration,
};
use kernel_api::abi::driver::{
    AbiError, AbiMmioHandle, AbiNetDriverEvent, AbiNetDriverEventKind, AbiNetPortInfo,
    AbiNetPortOps, AbiNetPortRegistration, AbiNetPortRuntime, AbiNetPortStats, AbiNetRxFrameLayout,
    AbiNetRxMeta, AbiNetTxMeta, AbiNetTxSubmission, AbiRxLeaseGuard, AbiTxDeviceOutcome,
    DriverContext, KernelApiV4, PackedPciLocation,
};
use kernel_api::driver::{AsyncDriver, DriverFuture, DriverType, DriverVersion};
use kernel_api::service::netdev::{NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP, TxLeaseId};
use spin::Mutex;

use crate::bootstrap::{
    Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan, Mlx5DmaRegion, Mlx5PciIdentity,
    Mlx5QueueDmaRegion, Mlx5QueueProfile,
};
use crate::defs::{CqeOpcode, MLX5_WQ_DEPTH};
use crate::device::Mlx5Device;
use crate::error::Mlx5Error;
use crate::wq::TxOptions;

// ============================================================================
// External Kernel API Access
// ============================================================================

#[inline]
fn kernel_api() -> &'static KernelApiV4 {
    kernel_api::service::kernel::abi()
}

#[cfg(test)]
extern "C" fn test_kernel_log(_level: u32, _msg_ptr: *const u8, _msg_len: usize) {}

#[cfg(test)]
unsafe extern "C" fn test_kernel_dma_allocate(
    _size: usize,
    _device_id: u64,
    _direction: u8,
    _out: *mut AbiDmaAllocation,
) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
unsafe extern "C" fn test_kernel_dma_command(
    _lease_id: u64,
    _request: *const AbiDmaRequest,
    _out: *mut AbiDmaResponse,
) -> i32 {
    AbiDmaStatus::NotSupported as i32
}

#[cfg(test)]
unsafe extern "C" fn test_kernel_dma_read(
    _lease_id: u64,
    _context: *mut u8,
    _visitor: unsafe extern "C" fn(*mut u8, *const u8, usize),
) -> i32 {
    AbiDmaStatus::NotSupported as i32
}

#[cfg(test)]
unsafe extern "C" fn test_kernel_dma_write(
    _lease_id: u64,
    _context: *mut u8,
    _visitor: unsafe extern "C" fn(*mut u8, *mut u8, usize),
) -> i32 {
    AbiDmaStatus::NotSupported as i32
}

#[cfg(test)]
extern "C" fn test_kernel_map_mmio(_paddr: u64, _size: usize, _out: *mut AbiMmioHandle) -> i32 {
    -1
}

#[cfg(test)]
extern "C" fn test_kernel_unmap_mmio(_handle: *const AbiMmioHandle) -> i32 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_port_read_u8(_port: u16) -> u8 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_port_write_u8(_port: u16, _value: u8) {}

#[cfg(test)]
extern "C" fn test_kernel_irq_bind(_irq: u32, _cookie: u64) -> i32 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_irq_unbind(_irq: u32) -> i32 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_register_block_device(
    _reg: *const AbiBlockDeviceRegistration,
    _out: *mut u64,
) -> i32 {
    -1
}

#[cfg(test)]
extern "C" fn test_kernel_unregister_block_device(_handle: u64) -> i32 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_register_nvme_namespace(
    _reg: *const AbiNvmeNamespaceRegistration,
    _out: *mut u64,
) -> i32 {
    -1
}

#[cfg(test)]
extern "C" fn test_kernel_unregister_nvme_namespace(_handle: u64) -> i32 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_register_netdev_port(
    _reg: *const AbiNetPortRegistration,
    _out: *mut u64,
) -> i32 {
    -1
}

#[cfg(test)]
extern "C" fn test_kernel_unregister_netdev_port(_handle: u64) -> i32 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_current_domain_id() -> u64 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_exchange_alloc_raw(
    _size: usize,
    _align: usize,
    _out_ptr: *mut *mut u8,
    _out_owner: *mut u64,
) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
extern "C" fn test_kernel_exchange_dealloc_raw(
    _ptr: *mut u8,
    _owner: u64,
    _size: usize,
    _align: usize,
) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
extern "C" fn test_kernel_exchange_transfer_raw(
    _ptr: *mut u8,
    _from_owner: u64,
    _to_owner: u64,
) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
extern "C" fn test_kernel_ipc_create_channel_raw(
    _out_sender: *mut u64,
    _out_receiver: *mut u64,
) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
extern "C" fn test_kernel_ipc_close_raw(_handle: u64) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
extern "C" fn test_kernel_ipc_send_raw(
    _handle: u64,
    _raw: *const kernel_api::abi::driver::AbiRRefRaw,
) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
extern "C" fn test_kernel_ipc_recv_raw(
    _handle: u64,
    _out_raw: *mut kernel_api::abi::driver::AbiRRefRaw,
) -> i32 {
    AbiError::NotSupported as i32
}

#[cfg(test)]
#[unsafe(no_mangle)]
pub static __exorust_kernel_api_v4: KernelApiV4 = KernelApiV4 {
    abi_version: kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
    abi_size: core::mem::size_of::<KernelApiV4>() as u64,
    log: test_kernel_log,
    dma_allocate: test_kernel_dma_allocate,
    dma_command: test_kernel_dma_command,
    dma_read: test_kernel_dma_read,
    dma_write: test_kernel_dma_write,
    map_mmio: test_kernel_map_mmio,
    unmap_mmio: test_kernel_unmap_mmio,
    port_read_u8: test_kernel_port_read_u8,
    port_write_u8: test_kernel_port_write_u8,
    irq_bind: test_kernel_irq_bind,
    irq_unbind: test_kernel_irq_unbind,
    heap_alloc: None,
    heap_dealloc: None,
    panic_abort: None,
    current_domain_id: test_kernel_current_domain_id,
    exchange_alloc_raw: test_kernel_exchange_alloc_raw,
    exchange_dealloc_raw: test_kernel_exchange_dealloc_raw,
    exchange_transfer_raw: test_kernel_exchange_transfer_raw,
    ipc_create_channel_raw: test_kernel_ipc_create_channel_raw,
    ipc_close_raw: test_kernel_ipc_close_raw,
    ipc_send_raw: test_kernel_ipc_send_raw,
    ipc_recv_raw: test_kernel_ipc_recv_raw,
    register_block_device: test_kernel_register_block_device,
    unregister_block_device: test_kernel_unregister_block_device,
    register_nvme_namespace: test_kernel_register_nvme_namespace,
    unregister_nvme_namespace: test_kernel_unregister_nvme_namespace,
    register_netdev_port: test_kernel_register_netdev_port,
    unregister_netdev_port: test_kernel_unregister_netdev_port,
    reserved: [0; 2],
    enable_msix_raw: None,
    disable_msix_raw: None,
};

// ============================================================================
// DMA Resource Management
// ============================================================================

// ============================================================================
// Driver State
// ============================================================================

const MLX5_POLL_BATCH: u32 = 64;
const MLX5_POLL_INTERVAL_MS: u64 = 1;
const MLX5_DMA_MIN_IOVA: u64 = 0x100000;
const MLX5_DMA_LOW_IOVA_MAX_RETRIES: u32 = 64;

struct Mlx5StandaloneState {
    lifecycle: Mlx5Lifecycle,
    device: Mlx5Device,
    dma: Mlx5DmaResources,
    mmio: AbiMmioHandle,
    registration_handle: Option<u64>,
    runtime: Option<AbiNetPortRuntime>,
    poll_generation: u64,
    next_sq: AtomicU32,
    last_link_up: bool,
    tx_packets: u64,
    rx_packets: u64,
    tx_errors: u64,
    rx_errors: u64,
    tx_slots: Vec<Vec<Option<TxLeaseId>>>,
    rx_slots: Vec<Vec<Option<AbiRxLeaseGuard>>>,
}

enum Mlx5Lifecycle {
    Running,
    StartupFailed(Mlx5Error),
    DeviceStopped,
    MmioUnmapUnknown(i32),
}

// The finalizing future owns the resource state outside this lock. The slot
// retains its claim so another probe cannot reacquire the same function.
enum Mlx5Slot {
    Vacant,
    Live(Mlx5StandaloneState),
    Finalizing,
}

static MLX5_STANDALONE_STATE: Mutex<Mlx5Slot> = Mutex::new(Mlx5Slot::Vacant);

fn fallback_mac() -> [u8; 6] {
    [0x02, 0x00, 0x5E, 0x00, 0x53, 0x01]
}

fn reported_mac(device: &Mlx5Device) -> [u8; 6] {
    let mac = device
        .port(0)
        .map(|port| port.mac_bytes())
        .unwrap_or_else(fallback_mac);
    if mac == [0; 6] { fallback_mac() } else { mac }
}

fn port_flags(device: &Mlx5Device) -> u32 {
    if device
        .port(0)
        .map(|port| port.is_link_up())
        .unwrap_or(false)
    {
        NETDEV_FLAG_HEALTHY | NETDEV_FLAG_LINK_UP
    } else {
        NETDEV_FLAG_HEALTHY
    }
}

fn init_slot_ring<T>() -> Vec<Option<T>> {
    let mut ring = Vec::with_capacity(MLX5_WQ_DEPTH as usize);
    ring.resize_with(MLX5_WQ_DEPTH as usize, || None);
    ring
}

fn lease_runtime_rx_buffer(runtime: AbiNetPortRuntime) -> Result<AbiRxLeaseGuard, AbiError> {
    AbiRxLeaseGuard::acquire(runtime)
}

fn schedule_runtime_poll_locked(state: &Mlx5StandaloneState) {
    let Some(runtime) = state.runtime else {
        return;
    };
    let _ = (runtime.schedule_event)(
        runtime.runtime_cookie,
        AbiNetDriverEvent {
            kind: AbiNetDriverEventKind::Poll as u32,
            queue_index: 0,
            _padding: 0,
        },
    );
}

fn refill_rx_ring(state: &mut Mlx5StandaloneState) -> Result<(), AbiError> {
    let Some(runtime) = state.runtime else {
        return Err(AbiError::NotInitialized);
    };

    for rq_index in 0..state.rx_slots.len() {
        for slot in 0..MLX5_WQ_DEPTH as usize {
            if state.rx_slots[rq_index][slot].is_some() {
                continue;
            }
            let buffer = lease_runtime_rx_buffer(runtime)?;
            let region = buffer.writable_region();
            let device_addr = region.device_addr;
            let virt_addr = region.cpu_ptr as u64;
            let size = u32::try_from(region.writable_len).map_err(|_| AbiError::InvalidParam)?;
            match unsafe {
                state
                    .device
                    .post_receive(rq_index, device_addr, virt_addr, size)
            } {
                Ok(_) => state.rx_slots[rq_index][slot] = Some(buffer),
                Err(err) => {
                    log::warn!(
                        target: "mlx5",
                        "RX prefill stopped at rq={} slot={} with {:?}",
                        rq_index,
                        slot,
                        err
                    );
                    break;
                }
            }
        }
    }

    Ok(())
}

fn replenish_rx_slot(
    state: &mut Mlx5StandaloneState,
    runtime: AbiNetPortRuntime,
    rq_index: usize,
    slot: usize,
) {
    let Ok(buffer) = lease_runtime_rx_buffer(runtime) else {
        state.rx_errors = state.rx_errors.saturating_add(1);
        return;
    };
    let region = buffer.writable_region();
    let Ok(len) = u32::try_from(region.writable_len) else {
        state.rx_errors = state.rx_errors.saturating_add(1);
        return;
    };
    match unsafe {
        state
            .device
            .post_receive(rq_index, region.device_addr, region.cpu_ptr as u64, len)
    } {
        Ok(_) => state.rx_slots[rq_index][slot] = Some(buffer),
        Err(err) => {
            state.rx_errors = state.rx_errors.saturating_add(1);
            log::warn!(
                target: "mlx5",
                "RX repost failed at rq={} slot={} with {:?}",
                rq_index,
                slot,
                err
            );
        }
    }
}

fn poll_rx_locked(state: &mut Mlx5StandaloneState) {
    let Some(runtime) = state.runtime else {
        return;
    };

    for rq_index in 0..state.rx_slots.len() {
        let Some(rx_cq_index) = state.device.rx_cq_index_for_rq(rq_index) else {
            continue;
        };

        let cqes = unsafe { state.device.poll_cq(rx_cq_index, MLX5_POLL_BATCH) };
        for cqe in cqes {
            let Some(rx_info) =
                state
                    .device
                    .process_rx_completion(rq_index, cqe.wqe_counter, cqe.l3_ok, cqe.l4_ok)
            else {
                state.rx_errors = state.rx_errors.saturating_add(1);
                continue;
            };
            let slot = rx_info.slot_index as usize;

            let Some(buffer) = state.rx_slots[rq_index][slot].take() else {
                state.rx_errors = state.rx_errors.saturating_add(1);
                continue;
            };

            if matches!(cqe.opcode, CqeOpcode::ReqErr | CqeOpcode::RespErr) {
                state.rx_errors = state.rx_errors.saturating_add(1);
                replenish_rx_slot(state, runtime, rq_index, slot);
                continue;
            }

            let region = buffer.writable_region();
            let byte_count = cqe.byte_count as usize;
            if byte_count > region.writable_len {
                state.rx_errors = state.rx_errors.saturating_add(1);
                replenish_rx_slot(state, runtime, rq_index, slot);
                continue;
            }
            let Some(rx_layout) = AbiNetRxFrameLayout::whole_payload(byte_count) else {
                state.rx_errors = state.rx_errors.saturating_add(1);
                replenish_rx_slot(state, runtime, rq_index, slot);
                continue;
            };
            let status = buffer.submit(AbiNetRxMeta::new(rq_index as u16, rx_layout, 0));
            if status.is_success() {
                state.rx_packets = state.rx_packets.saturating_add(1);
            } else {
                state.rx_errors = state.rx_errors.saturating_add(1);
            }

            replenish_rx_slot(state, runtime, rq_index, slot);
        }
    }
}
fn poll_tx_locked(state: &mut Mlx5StandaloneState) {
    for sq_index in 0..state.tx_slots.len() {
        let Some(tx_cq_index) = state.device.tx_cq_index_for_sq(sq_index) else {
            continue;
        };

        let cqes = unsafe { state.device.poll_cq(tx_cq_index, MLX5_POLL_BATCH) };
        for cqe in cqes {
            let slot = (cqe.wqe_counter as usize) % (MLX5_WQ_DEPTH as usize);
            let _ = state
                .device
                .process_tx_completions(sq_index, cqe.wqe_counter);
            if let Some(lease_id) = state.tx_slots[sq_index][slot].take() {
                if let Some(runtime) = state.runtime {
                    let outcome = if matches!(cqe.opcode, CqeOpcode::ReqErr | CqeOpcode::RespErr) {
                        AbiTxDeviceOutcome::NOT_TRANSMITTED
                    } else {
                        AbiTxDeviceOutcome::TRANSMITTED
                    };
                    let _ = (runtime.complete_tx_lease)(
                        runtime.runtime_cookie,
                        lease_id.get(),
                        outcome,
                    );
                }
            }
            if matches!(cqe.opcode, CqeOpcode::ReqErr | CqeOpcode::RespErr) {
                state.tx_errors = state.tx_errors.saturating_add(1);
            }
        }
    }
}

fn poll_device_locked(state: &mut Mlx5StandaloneState) {
    let _ = unsafe { state.device.process_events() };
    poll_rx_locked(state);
    poll_tx_locked(state);

    let link_up = state
        .device
        .port(0)
        .map(|port| port.is_link_up())
        .unwrap_or(false);
    if link_up != state.last_link_up {
        if let Some(runtime) = state.runtime {
            let _ = (runtime.update_link)(runtime.runtime_cookie, link_up);
        }
        state.last_link_up = link_up;
    }
}

/// Failure retains the device, page capabilities, DMA resources and mapping.
/// An uncertain unmap is terminal for ordinary retry: no further register I/O
/// may use that address until the framework reconciles the mapping outcome.
#[expect(
    clippy::result_large_err,
    reason = "failed teardown returns the inline resource owner without allocating after hardware effects"
)]
fn destroy_state(
    mut state: Mlx5StandaloneState,
) -> Result<(), (kernel_api::error::KapiError, Mlx5StandaloneState)> {
    match state.lifecycle {
        Mlx5Lifecycle::MmioUnmapUnknown(status) => {
            return Err((kernel_api::error::KapiError::Internal(status), state));
        }
        Mlx5Lifecycle::Running | Mlx5Lifecycle::StartupFailed(_) => {
            // SAFETY: the retained state owns the startup resources and mapping;
            // registration/runtime admission was closed before reaching here.
            if let Err(cause) = unsafe { state.device.teardown_full() } {
                log::warn!(target: "mlx5", "Teardown retained resources: {:?}", cause);
                return Err((map_driver_error(cause), state));
            }
            state.lifecycle = Mlx5Lifecycle::DeviceStopped;
        }
        Mlx5Lifecycle::DeviceStopped => {}
    }
    let status = (kernel_api().unmap_mmio)(&state.mmio);
    if status != 0 {
        state.lifecycle = Mlx5Lifecycle::MmioUnmapUnknown(status);
        return Err((kernel_api::error::KapiError::Internal(status), state));
    }
    Ok(())
}

async fn mlx5_poll_kicker(generation: u64) {
    loop {
        let should_continue = {
            let guard = MLX5_STANDALONE_STATE.lock();
            match &*guard {
                Mlx5Slot::Live(state)
                    if state.poll_generation == generation && state.runtime.is_some() =>
                {
                    schedule_runtime_poll_locked(state);
                    true
                }
                _ => false,
            }
        };

        if !should_continue {
            break;
        }

        kernel_api::service::time::sleep_ms(MLX5_POLL_INTERVAL_MS).await;
    }
}

extern "C" fn mlx5_netdev_start(_opaque: u64, runtime: *const AbiNetPortRuntime) -> i32 {
    if runtime.is_null() {
        return AbiError::InvalidParam as i32;
    }

    let generation = {
        let mut guard = MLX5_STANDALONE_STATE.lock();
        let Mlx5Slot::Live(state) = &mut *guard else {
            return AbiError::NotInitialized as i32;
        };
        if !matches!(state.lifecycle, Mlx5Lifecycle::Running) {
            return AbiError::IoError as i32;
        }
        state.runtime = Some(unsafe { *runtime });
        if refill_rx_ring(state).is_err() {
            state.runtime = None;
            return AbiError::OutOfMemory as i32;
        }
        state.poll_generation = state.poll_generation.wrapping_add(1);
        if let Some(runtime) = state.runtime {
            let _ = (runtime.update_link)(runtime.runtime_cookie, state.last_link_up);
        }
        state.poll_generation
    };

    match kernel_api::service::kernel::instance().spawn_task(Box::pin(mlx5_poll_kicker(generation)))
    {
        Ok(_) => AbiError::Success as i32,
        Err(_) => {
            let mut guard = MLX5_STANDALONE_STATE.lock();
            if let Mlx5Slot::Live(state) = &mut *guard {
                if state.poll_generation == generation {
                    state.runtime = None;
                    state.poll_generation = state.poll_generation.wrapping_add(1);
                }
            }
            AbiError::IoError as i32
        }
    }
}

extern "C" fn mlx5_netdev_bind(_opaque: u64, _if_id: u16) -> i32 {
    AbiError::Success as i32
}

extern "C" fn mlx5_netdev_submit_tx_chain(
    _opaque: u64,
    submission: *const AbiNetTxSubmission,
    meta: AbiNetTxMeta,
) -> i32 {
    if submission.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let submission = unsafe { &*submission };
    let Some(segments) = submission.segments() else {
        return AbiError::InvalidParam as i32;
    };
    let mut guard = MLX5_STANDALONE_STATE.lock();
    let Mlx5Slot::Live(state) = &mut *guard else {
        return AbiError::NotInitialized as i32;
    };
    if !matches!(state.lifecycle, Mlx5Lifecycle::Running) {
        return AbiError::IoError as i32;
    }
    if !state.device.is_active() {
        return AbiError::NotInitialized as i32;
    }

    let data_len: usize = segments.iter().map(|segment| segment.len().get()).sum();
    if data_len == 0 {
        return AbiError::InvalidParam as i32;
    }

    if state
        .device
        .port(0)
        .map(|port| port.min_wqe_inline_mode())
        .unwrap_or(0)
        != 0
    {
        return AbiError::NotSupported as i32;
    }
    let Ok(total_len) = u32::try_from(data_len) else {
        return AbiError::InvalidParam as i32;
    };
    let sq_count = state.tx_slots.len().max(1) as u32;
    let sq_index = if meta.has_queue_index {
        (meta.queue_index as u32 % sq_count) as usize
    } else {
        (state.next_sq.fetch_add(1, Ordering::Relaxed) % sq_count) as usize
    };

    let mut options = TxOptions::default();
    if meta.has_vlan_tag {
        options.vlan_tag = meta.vlan_tag;
    }

    let mut dma_segments = [crate::wq::DmaSegment {
        device_addr: 0,
        virt_addr: 0,
        len: 0,
    }; 2];
    let mut dma_segment_count = 0usize;
    for segment in segments.iter() {
        if dma_segment_count == dma_segments.len() {
            return AbiError::InvalidParam as i32;
        }
        let segment_len = segment.len().get();
        let Ok(len) = u32::try_from(segment_len) else {
            return AbiError::InvalidParam as i32;
        };
        dma_segments[dma_segment_count] = crate::wq::DmaSegment {
            device_addr: segment.device_addr(),
            virt_addr: segment.cpu_ptr() as u64,
            len,
        };
        dma_segment_count += 1;
    }
    if dma_segment_count == 0 {
        return AbiError::InvalidParam as i32;
    }

    match unsafe {
        state.device.transmit_segments(
            sq_index,
            &dma_segments[..dma_segment_count],
            total_len,
            options,
        )
    } {
        Ok(wqe_idx) => {
            let slot = (wqe_idx as usize) % (MLX5_WQ_DEPTH as usize);
            let Some(lease_id) = submission.lease_id() else {
                return AbiError::InvalidParam as i32;
            };
            state.tx_slots[sq_index][slot] = Some(lease_id);
            state.tx_packets = state.tx_packets.saturating_add(1);
            schedule_runtime_poll_locked(state);
            AbiError::Success as i32
        }
        Err(err) => {
            state.tx_errors = state.tx_errors.saturating_add(1);
            log::warn!(target: "mlx5", "TX submit failed: {:?}", err);
            AbiError::IoError as i32
        }
    }
}

extern "C" fn mlx5_netdev_poll(_opaque: u64, _if_id: u16) -> i32 {
    let mut guard = MLX5_STANDALONE_STATE.lock();
    let Mlx5Slot::Live(state) = &mut *guard else {
        return AbiError::NotInitialized as i32;
    };
    if !matches!(state.lifecycle, Mlx5Lifecycle::Running) {
        return AbiError::IoError as i32;
    }
    poll_device_locked(state);
    AbiError::Success as i32
}

extern "C" fn mlx5_netdev_handle_event(
    _opaque: u64,
    _if_id: u16,
    _event: AbiNetDriverEvent,
) -> i32 {
    mlx5_netdev_poll(0, 0)
}

extern "C" fn mlx5_netdev_stats(_opaque: u64, out: *mut AbiNetPortStats) -> i32 {
    if out.is_null() {
        return AbiError::InvalidParam as i32;
    }

    let guard = MLX5_STANDALONE_STATE.lock();
    let Mlx5Slot::Live(state) = &*guard else {
        return AbiError::NotInitialized as i32;
    };

    unsafe {
        *out = AbiNetPortStats {
            tx_packets: state.tx_packets,
            rx_packets: state.rx_packets,
            tx_errors: state.tx_errors,
            rx_errors: state.rx_errors,
            initialized: state.device.is_active(),
            reserved: [0; 7],
        };
    }
    AbiError::Success as i32
}

extern "C" fn mlx5_netdev_stop(_opaque: u64) -> i32 {
    let mut guard = MLX5_STANDALONE_STATE.lock();
    if let Mlx5Slot::Live(state) = &mut *guard {
        if state.device.is_active() && unsafe { state.device.disable_hca_hw() }.is_err() {
            return AbiError::IoError as i32;
        }
        for queue in &mut state.rx_slots {
            for buffer in queue {
                let _ = buffer.take();
            }
        }
        for queue in &mut state.tx_slots {
            for lease in queue {
                let _ = lease.take();
            }
        }
        state.runtime = None;
        state.poll_generation = state.poll_generation.wrapping_add(1);
    }
    AbiError::Success as i32
}

extern "C" fn mlx5_netdev_set_interrupts_enabled(_opaque: u64, _enabled: bool) -> i32 {
    AbiError::Success as i32
}

fn netdev_registration(state: &Mlx5StandaloneState) -> AbiNetPortRegistration {
    AbiNetPortRegistration::new(
        AbiNetPortInfo {
            port_id: 0x0002_0000,
            queue_pairs: cmp::max(state.device.num_rqs(), state.device.num_sqs()) as u16,
            max_tx_segments: 2,
            mtu: state.device.port(0).map(|port| port.mtu()).unwrap_or(1500),
            flags: port_flags(&state.device),
            mac: reported_mac(&state.device),
            reserved0: [0; 2],
            name_ptr: mlx5_driver_name().as_ptr(),
            name_len: mlx5_driver_name().len(),
        },
        0,
        AbiNetPortOps {
            start: mlx5_netdev_start,
            bind: mlx5_netdev_bind,
            submit_tx_chain: mlx5_netdev_submit_tx_chain,
            poll: mlx5_netdev_poll,
            handle_event: mlx5_netdev_handle_event,
            stats: mlx5_netdev_stats,
            stop: mlx5_netdev_stop,
            set_interrupts_enabled: mlx5_netdev_set_interrupts_enabled,
        },
    )
}

// ============================================================================
// Driver Probe/Remove Functions
// ============================================================================

pub struct Mlx5AsyncDriver;

impl Mlx5AsyncDriver {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for Mlx5AsyncDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncDriver for Mlx5AsyncDriver {
    fn name(&self) -> &str {
        mlx5_driver_name()
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(
        &mut self,
        ctx: &mut DriverContext,
    ) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        let bar0_phys = ctx.device_address;
        let device_id = ctx.device_id;
        let pci_locator = ctx.pci_location();
        Box::pin(async move {
            if !matches!(*MLX5_STANDALONE_STATE.lock(), Mlx5Slot::Vacant) {
                return Err(kernel_api::error::KapiError::AlreadyExists);
            }

            let config = Mlx5BootstrapConfig {
                queue_profile: Mlx5QueueProfile::default(),
                mkey_params: crate::resources::MkeyParams::default(),
                pci_identity: Mlx5PciIdentity {
                    segment: pci_locator.segment(),
                    bus: pci_locator.bus(),
                    device: pci_locator.device(),
                    function: pci_locator.function(),
                },
                is_vf: crate::defs::ConnectXVariant::is_vf_device_id(device_id),
            };
            let plan = Mlx5BootstrapPlan::new(&config);

            let mut mmio = AbiMmioHandle::default();
            let bar0_size = 0x1000000;
            let res = (kernel_api().map_mmio)(bar0_phys, bar0_size, &mut mmio);
            if res != 0 {
                log::error!(target: "mlx5", "Failed to map BAR0: {}", res);
                return Err(kernel_api::error::KapiError::IoError);
            }

            let dma = match Mlx5DmaResources::allocate(&plan, pci_locator) {
                Ok(dma) => dma,
                Err(_) => {
                    let _ = (kernel_api().unmap_mmio)(&mmio);
                    return Err(kernel_api::error::KapiError::OutOfMemory);
                }
            };

            let mut device = Mlx5Device::new(mmio.base, device_id);
            let allocated = dma.to_allocated_resources();

            log::info!(
                target: "mlx5",
                "CMD DMA IOVA: cmdq={:#x} in_mbox={:#x} out_mbox={:#x}",
                dma.cmdq.device_address(),
                dma.cmd_in_mbox.device_address(),
                dma.cmd_out_mbox.device_address(),
            );

            if let Err(err) = unsafe { device.bootstrap(&config, &allocated) } {
                log::error!(target: "mlx5", "Initialization failed: {:?}", err);
                // The failed/uncertain start keeps the function claimed and
                // retains firmware pages, DMA resources and the live mapping.
                *MLX5_STANDALONE_STATE.lock() = Mlx5Slot::Live(Mlx5StandaloneState {
                    lifecycle: Mlx5Lifecycle::StartupFailed(err),
                    device,
                    dma,
                    mmio,
                    registration_handle: None,
                    runtime: None,
                    poll_generation: 0,
                    next_sq: AtomicU32::new(0),
                    last_link_up: false,
                    tx_packets: 0,
                    rx_packets: 0,
                    tx_errors: 0,
                    rx_errors: 0,
                    tx_slots: Vec::new(),
                    rx_slots: Vec::new(),
                });
                return Err(map_driver_error(err));
            }

            let _ = unsafe { device.refresh_port_runtime_state(0) };

            let mut tx_slots = Vec::with_capacity(device.num_sqs());
            tx_slots.resize_with(device.num_sqs(), init_slot_ring::<TxLeaseId>);
            let mut rx_slots = Vec::with_capacity(device.num_rqs());
            rx_slots.resize_with(device.num_rqs(), init_slot_ring::<AbiRxLeaseGuard>);

            let last_link_up = device
                .port(0)
                .map(|port| port.is_link_up())
                .unwrap_or(false);
            let state = Mlx5StandaloneState {
                lifecycle: Mlx5Lifecycle::Running,
                device,
                dma,
                mmio,
                registration_handle: None,
                runtime: None,
                poll_generation: 0,
                next_sq: AtomicU32::new(0),
                last_link_up,
                tx_packets: 0,
                rx_packets: 0,
                tx_errors: 0,
                rx_errors: 0,
                tx_slots,
                rx_slots,
            };
            *MLX5_STANDALONE_STATE.lock() = Mlx5Slot::Live(state);
            Ok(())
        })
    }

    fn start(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        Box::pin(async move {
            let registration = {
                let guard = MLX5_STANDALONE_STATE.lock();
                let Mlx5Slot::Live(state) = &*guard else {
                    return Err(kernel_api::error::KapiError::NotFound);
                };
                if state.registration_handle.is_some() {
                    return Ok(());
                }
                if let Mlx5Lifecycle::StartupFailed(cause) = state.lifecycle {
                    return Err(map_driver_error(cause));
                }
                if !matches!(state.lifecycle, Mlx5Lifecycle::Running) {
                    return Err(kernel_api::error::KapiError::IoError);
                }
                netdev_registration(state)
            };

            let handle =
                kernel_api::service::kernel::instance().register_netdev_port(&registration)?;
            let mut guard = MLX5_STANDALONE_STATE.lock();
            let Mlx5Slot::Live(state) = &mut *guard else {
                let _ = kernel_api::service::kernel::instance().unregister_netdev_port(handle);
                return Err(kernel_api::error::KapiError::NotFound);
            };
            state.registration_handle = Some(handle);
            Ok(())
        })
    }

    fn stop(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        Box::pin(async move {
            let handle = {
                let guard = MLX5_STANDALONE_STATE.lock();
                match &*guard {
                    Mlx5Slot::Live(state) => state.registration_handle,
                    _ => None,
                }
            };
            if let Some(handle) = handle {
                kernel_api::service::kernel::instance().unregister_netdev_port(handle)?;
            }
            let mut state = {
                let mut guard = MLX5_STANDALONE_STATE.lock();
                match core::mem::replace(&mut *guard, Mlx5Slot::Finalizing) {
                    Mlx5Slot::Live(state) => state,
                    Mlx5Slot::Vacant => {
                        *guard = Mlx5Slot::Vacant;
                        return Ok(());
                    }
                    Mlx5Slot::Finalizing => {
                        return Err(kernel_api::error::KapiError::AlreadyExists);
                    }
                }
            };
            state.registration_handle = None;
            state.runtime = None;
            match destroy_state(state) {
                Ok(()) => {
                    *MLX5_STANDALONE_STATE.lock() = Mlx5Slot::Vacant;
                    Ok(())
                }
                Err((cause, state)) => {
                    *MLX5_STANDALONE_STATE.lock() = Mlx5Slot::Live(state);
                    Err(cause)
                }
            }
        })
    }

    fn remove(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        self.stop()
    }
}

fn map_driver_error(err: Mlx5Error) -> kernel_api::error::KapiError {
    match err {
        Mlx5Error::PageAllocation(cause) => cause,
        Mlx5Error::NotSupported => kernel_api::error::KapiError::NotSupported,
        Mlx5Error::NoResources | Mlx5Error::DmaAllocFailed => {
            kernel_api::error::KapiError::OutOfMemory
        }
        Mlx5Error::DeviceNotFound => kernel_api::error::KapiError::NotFound,
        _ => kernel_api::error::KapiError::IoError,
    }
}

pub fn mlx5_driver_name() -> &'static str {
    "mlx5"
}
