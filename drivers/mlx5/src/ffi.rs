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
use exorust_sync::Mutex;
#[cfg(test)]
use kernel_api::abi::driver::{
    AbiBlockDeviceRegistration, AbiDmaAllocation, AbiDmaRequest, AbiDmaResponse, AbiDmaStatus,
    AbiMmioGrant, AbiNvmeNamespaceRegistration, KernelApiV4,
};
use kernel_api::abi::driver::{
    AbiError, AbiNetDriverEvent, AbiNetDriverEventKind, AbiNetPortInfo, AbiNetPortOps,
    AbiNetPortRegistration, AbiNetPortRuntime, AbiNetPortStats, AbiNetRxFrameLayout, AbiNetRxMeta,
    AbiNetTxMeta, AbiNetTxSubmission, AbiRxLeaseGuard, AbiTxDeviceOutcome, DriverContext,
};
use kernel_api::driver::{AsyncDriver, DriverType, DriverVersion};
use kernel_api::service::netdev::{NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP, TxLeaseId};

use crate::bootstrap::{
    BootstrapAllocationCause, BootstrapDmaInventory, BootstrapDmaPlan, BootstrapRetirementFailure,
    Mlx5BootstrapConfig, Mlx5PciIdentity, Mlx5QueueProfile,
};
use crate::defs::{CqeOpcode, MLX5_WQ_DEPTH};
use crate::device::Mlx5Device;
use crate::error::Mlx5Error;
use crate::wq::TxOptions;

// ============================================================================
// External Kernel API Access
// ============================================================================

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
unsafe extern "C" fn test_kernel_mmio_acquire(
    _device: u64,
    _bar: u8,
    _aperture: u8,
    _offset: usize,
    _length: usize,
    _out: *mut AbiMmioGrant,
) -> i32 {
    kernel_api::mmio::MmioAcquireError::Unavailable.into_abi()
}

#[cfg(test)]
unsafe extern "C" fn test_kernel_mmio_release(_identity: u64) {}

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
    task_waker_abi: kernel_api::abi::driver::TASK_WAKER_ABI,
    log: test_kernel_log,
    spawn: test_kernel_spawn,
    timer_register: test_kernel_timer_register,
    time_snapshot: test_kernel_time_snapshot,
    timer_statistics: test_kernel_timer_statistics,
    current_tick: test_kernel_current_tick,
    current_task_id: test_kernel_current_domain_id,
    dma_allocate: test_kernel_dma_allocate,
    dma_command: test_kernel_dma_command,
    dma_read: test_kernel_dma_read,
    dma_write: test_kernel_dma_write,
    mmio_acquire: test_kernel_mmio_acquire,
    mmio_release: test_kernel_mmio_release,
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

#[cfg(test)]
unsafe extern "C" fn test_kernel_spawn(
    future: *mut kernel_api::abi::driver::AbiTaskFuture,
    _options: *const kernel_api::abi::driver::AbiTaskOptions,
) -> kernel_api::abi::driver::AbiTaskSpawnResult {
    // SAFETY: the fixture receives the importer's uniquely borrowed capsule.
    drop(unsafe { (&mut *future).take() });
    kernel_api::abi::driver::AbiTaskSpawnResult::from_result(Err(
        kernel_api::resource::task::SpawnError::SchedulerUnavailable,
    ))
}

#[cfg(test)]
unsafe extern "C" fn test_kernel_timer_register(
    _schedule: *const kernel_api::abi::driver::AbiTimerSchedule,
) -> kernel_api::abi::driver::AbiTimerAdmission {
    kernel_api::abi::driver::AbiTimerAdmission::from_result(Err(
        kernel_api::service::time::TimerError::ServiceUnavailable,
    ))
}

#[cfg(test)]
extern "C" fn test_kernel_time_snapshot() -> kernel_api::abi::driver::AbiTimeSnapshot {
    kernel_api::abi::driver::AbiTimeSnapshot {
        available: 0,
        tick_ms: 0,
        uptime_ns: 0,
        unix_seconds: 0,
        unix_ms: 0,
    }
}

#[cfg(test)]
extern "C" fn test_kernel_current_tick() -> u64 {
    0
}

#[cfg(test)]
extern "C" fn test_kernel_timer_statistics() -> kernel_api::abi::driver::AbiTimerStatistics {
    kernel_api::abi::driver::AbiTimerStatistics {
        active_timers: 0,
        total_fired: 0,
        notifications: 0,
        due_timers: 0,
    }
}

// ============================================================================
// Unpublished DMA retirement
// ============================================================================

// ============================================================================
// Driver State
// ============================================================================

const MLX5_POLL_BATCH: u32 = 64;
const MLX5_POLL_INTERVAL_MS: u64 = 1;
enum BootstrapDmaRetention {
    Unpublished(BootstrapDmaInventory),
    UnmapFailed(BootstrapRetirementFailure),
    Released,
}

/// Does not retry uncertain release or restore CPU access. Reset reconciliation
/// owns that separate transition; a repeated stop must retain this quarantine.
fn retire_bootstrap_dma(
    retention: &mut BootstrapDmaRetention,
) -> Result<(), kernel_api::error::KapiError> {
    let inventory = match core::mem::replace(retention, BootstrapDmaRetention::Released) {
        BootstrapDmaRetention::Unpublished(inventory) => inventory,
        BootstrapDmaRetention::UnmapFailed(failure) => {
            log::warn!(target: "mlx5", "DMA quarantine retained: {:?}, released={} retained={}",
                failure.cause(), failure.released_count(), failure.retained_count());
            *retention = BootstrapDmaRetention::UnmapFailed(failure);
            return Err(kernel_api::error::KapiError::IoError);
        }
        BootstrapDmaRetention::Released => return Ok(()),
    };
    if let Err(failure) = inventory.close() {
        log::warn!(target: "mlx5", "DMA close retained: {:?}, released={} retained={}",
            failure.cause(), failure.released_count(), failure.retained_count());
        *retention = BootstrapDmaRetention::UnmapFailed(failure);
        return Err(kernel_api::error::KapiError::IoError);
    }
    Ok(())
}

/// Allocation failed before command/ring publication. This claim retains the
/// original acquisition cause and every successfully acquired DMA capability.
struct Mlx5AcquisitionFailure {
    cause: BootstrapAllocationCause,
    dma: BootstrapDmaRetention,
    device: Option<Mlx5Device>,
}

impl Mlx5AcquisitionFailure {
    fn close(&mut self) -> Result<(), kernel_api::error::KapiError> {
        log::warn!(target: "mlx5", "Retiring failed acquisition: {:?}", self.cause);
        retire_bootstrap_dma(&mut self.dma)?;
        // No hardware publication occurred; DMA retirement precedes release
        // of the device's retained register owner.
        drop(self.device.take());
        Ok(())
    }
}

struct Mlx5StandaloneState {
    lifecycle: Mlx5Lifecycle,
    device: Mlx5Device,
    dma: BootstrapDmaRetention,
    registration_handle: Option<u64>,
    runtime: Option<AbiNetPortRuntime>,
    poll_generation: u64,
    poll_task: Option<kernel_api::resource::task::TaskId>,
    poll_failure: Option<kernel_api::service::time::TimerError>,
    next_sq: AtomicU32,
    last_link_up: bool,
    tx_packets: u64,
    rx_packets: u64,
    tx_errors: u64,
    rx_errors: u64,
    tx_slots: Vec<Vec<Option<TxLeaseRecord>>>,
    rx_slots: Vec<Vec<Option<AbiRxLeaseGuard>>>,
}

enum Mlx5Lifecycle {
    Running,
    StartupFailed(Mlx5Error),
    /// New packet operations are rejected while the retained owner finalizes.
    StopRequested,
    DeviceStopped,
}

// The finalizing future owns the resource state outside this lock. The slot
// retains its claim so another probe cannot reacquire the same function.
enum Mlx5Slot {
    Vacant,
    Live(Mlx5StandaloneState),
    AcquisitionFailed(Mlx5AcquisitionFailure),
    Finalizing,
}

struct TxLeaseRecord {
    lease: TxLeaseId,
    counter: u16,
    completion: Option<AbiTxDeviceOutcome>,
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
                Ok(posted) => state.rx_slots[rq_index][posted.slot as usize] = Some(buffer),
                Err(crate::error::WorkSubmissionError::OutcomeUnknown { slot, cause, .. }) => {
                    state.rx_slots[rq_index][slot as usize] = Some(buffer);
                    state.device.state = crate::device::DeviceState::Error;
                    log::error!(target: "mlx5", "RX publication uncertain; retaining slot {slot}: {cause:?}");
                    return Err(AbiError::IoError);
                }
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
        Ok(posted) => state.rx_slots[rq_index][posted.slot as usize] = Some(buffer),
        Err(crate::error::WorkSubmissionError::OutcomeUnknown { slot, cause, .. }) => {
            state.rx_slots[rq_index][slot as usize] = Some(buffer);
            state.device.state = crate::device::DeviceState::Error;
            log::error!(target: "mlx5", "RX publication uncertain; retaining slot {slot}: {cause:?}");
        }
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

        let batch = state.device.poll_cq(rx_cq_index, MLX5_POLL_BATCH);
        if let Err(cause) = batch.completion {
            log::error!(target: "mlx5", "RX completion polling failed; consumed entries remain valid: {cause:?}");
        }
        let cqes = batch.entries;
        for cqe in cqes {
            let Ok(rx_info) = state
                .device
                .process_rx_completion(rq_index, rx_cq_index, &cqe)
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
/// Completion delivery can fail after hardware completion. Retain the exact
/// outcome and lease until the runtime acknowledges it, independently of CQ RAM.
fn deliver_tx_completions(state: &mut Mlx5StandaloneState) -> Result<(), AbiError> {
    let Some(runtime) = state.runtime else {
        return if state.tx_slots.iter().flatten().any(|slot| slot.is_some()) {
            Err(AbiError::NotInitialized)
        } else {
            Ok(())
        };
    };
    for queue in &mut state.tx_slots {
        for slot in queue {
            let Some(record) = slot.as_ref() else {
                continue;
            };
            let Some(outcome) = record.completion else {
                continue;
            };
            let result = AbiError::from_raw((runtime.complete_tx_lease)(
                runtime.runtime_cookie,
                record.lease.get(),
                outcome,
            ));
            if !result.is_success() {
                return Err(result);
            }
            *slot = None;
        }
    }
    Ok(())
}

fn poll_tx_locked(state: &mut Mlx5StandaloneState) {
    if let Err(cause) = deliver_tx_completions(state) {
        log::error!(target: "mlx5", "TX completion delivery retained: {cause:?}");
        return;
    }
    for sq_index in 0..state.tx_slots.len() {
        let Some(cq_index) = state.device.tx_cq_index_for_sq(sq_index) else {
            continue;
        };
        let batch = state.device.poll_cq(cq_index, MLX5_POLL_BATCH);
        if let Err(cause) = batch.completion {
            log::error!(target: "mlx5", "TX polling failed; processing consumed prefix: {cause:?}");
        }
        for cqe in batch.entries {
            let slot = cqe.wqe_counter as usize % state.tx_slots[sq_index].len();
            if state.tx_slots[sq_index][slot]
                .as_ref()
                .map(|record| record.counter)
                != Some(cqe.wqe_counter)
            {
                state.device.state = crate::device::DeviceState::Error;
                state.tx_errors = state.tx_errors.saturating_add(1);
                continue;
            }
            if let Err(cause) = state.device.process_tx_completion(sq_index, cq_index, &cqe) {
                state.device.state = crate::device::DeviceState::Error;
                log::error!(target: "mlx5", "TX completion mismatch; packet retained: {cause:?}");
                continue;
            }
            let record = state.tx_slots[sq_index][slot]
                .as_mut()
                .expect("verified lease/counter relation");
            record.completion = Some(if cqe.opcode == CqeOpcode::ReqErr {
                state.tx_errors = state.tx_errors.saturating_add(1);
                AbiTxDeviceOutcome::NOT_TRANSMITTED
            } else {
                AbiTxDeviceOutcome::TRANSMITTED
            });
        }
    }
    if let Err(cause) = deliver_tx_completions(state) {
        log::error!(target: "mlx5", "TX completion delivery retained: {cause:?}");
    }
}

fn poll_device_locked(state: &mut Mlx5StandaloneState) {
    if let Err(cause) = state.device.process_events() {
        log::error!(target: "mlx5", "event processing failed; resources retained: {cause:?}");
    }
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
/// Device/DMA retirement finishes before the last derived MMIO owner retires.
#[expect(
    clippy::result_large_err,
    reason = "failed teardown returns the inline resource owner without allocating after hardware effects"
)]
fn destroy_state(
    mut state: Mlx5StandaloneState,
) -> Result<(), (kernel_api::error::KapiError, Mlx5StandaloneState)> {
    match state.lifecycle {
        Mlx5Lifecycle::Running | Mlx5Lifecycle::StartupFailed(_) | Mlx5Lifecycle::StopRequested => {
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
    if let Err(cause) = retire_bootstrap_dma(&mut state.dma) {
        return Err((cause, state));
    }
    Ok(())
}

async fn mlx5_poll_kicker(generation: u64) {
    // LOOP_PROOF: mode=event; reason=Each generation-owned device poll awaits a timer outside the slot lock and exits on generation retirement, shutdown, or timer failure.;
    loop {
        let should_continue = {
            let guard = MLX5_STANDALONE_STATE.lock();
            match &*guard {
                Mlx5Slot::Live(state)
                    if state.poll_generation == generation
                        && state.runtime.is_some()
                        && matches!(state.lifecycle, Mlx5Lifecycle::Running) =>
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

        if let Err(cause) = kernel_api::service::time::sleep_ms(MLX5_POLL_INTERVAL_MS).await {
            let mut guard = MLX5_STANDALONE_STATE.lock();
            if let Mlx5Slot::Live(state) = &mut *guard
                && state.poll_generation == generation
            {
                state.poll_failure = Some(cause);
                state.poll_task = None;
                state.lifecycle = Mlx5Lifecycle::StopRequested;
            }
            log::error!("MLX5 poll timer failed; owned device requires shutdown: {cause}");
            return;
        }
    }
}

extern "C" fn mlx5_netdev_start(_opaque: u64, runtime: *const AbiNetPortRuntime) -> i32 {
    if runtime.is_null() {
        return AbiError::InvalidParam as i32;
    }
    let mut guard = MLX5_STANDALONE_STATE.lock();
    let Mlx5Slot::Live(state) = &mut *guard else {
        return AbiError::NotInitialized as i32;
    };
    if !matches!(state.lifecycle, Mlx5Lifecycle::Running) || state.runtime.is_some() {
        return AbiError::DeviceBusy as i32;
    }
    let Some(generation) = state.poll_generation.checked_add(1) else {
        return AbiError::DeviceBusy as i32;
    };
    let worker = match Box::try_new(mlx5_poll_kicker(generation)) {
        Ok(worker) => Box::into_pin(worker),
        Err(_) => return AbiError::OutOfMemory as i32,
    };
    // SAFETY: the ABI caller retains a live callback table through successful
    // stop, including incomplete startup. The state keeps its copied binding.
    state.runtime = Some(unsafe { *runtime });
    state.poll_generation = generation;
    // The guard prevents the admitted worker from observing partial startup.
    // No receive descriptor has been published if task admission fails.
    match kernel_api::service::kernel::instance()
        .spawn(worker, kernel_api::resource::task::TaskOptions::any())
    {
        Ok(task) => state.poll_task = Some(task),
        Err(cause) => {
            state.runtime = None;
            log::error!(target: "mlx5", "Poll worker admission failed before RX publication: {cause}");
            return match cause {
                kernel_api::resource::task::SpawnError::PhysicalMemoryExhausted => {
                    AbiError::OutOfMemory
                }
                kernel_api::resource::task::SpawnError::TaskSlotsExhausted
                | kernel_api::resource::task::SpawnError::TaskIdentityExhausted => {
                    AbiError::DeviceBusy
                }
                kernel_api::resource::task::SpawnError::MappingFailed(_) => AbiError::IoError,
                _ => AbiError::NotInitialized,
            } as i32;
        }
    }
    if let Err(cause) = refill_rx_ring(state) {
        // The worker and any posted prefix remain owned. Shutdown must retain
        // the runtime binding until those packet/command leases can retire.
        state.lifecycle = Mlx5Lifecycle::StopRequested;
        log::error!(target: "mlx5", "RX startup incomplete; retained for shutdown: {cause:?}");
        return AbiError::IoError as i32;
    }
    if let Some(runtime) = state.runtime {
        let status = AbiError::from_raw((runtime.update_link)(
            runtime.runtime_cookie,
            state.last_link_up,
        ));
        if !status.is_success() {
            state.lifecycle = Mlx5Lifecycle::StopRequested;
            return status as i32;
        }
    }
    AbiError::Success as i32
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

    let Some(lease_id) = submission.lease_id() else {
        return AbiError::InvalidParam as i32;
    };
    if state.tx_slots[sq_index].iter().any(|slot| {
        slot.as_ref()
            .is_some_and(|record| record.completion.is_some())
    }) {
        return AbiError::IoError as i32;
    }
    // SAFETY: the submission's lease retains each DMA segment through matching
    // CQ completion or acknowledged queue destruction, including unknown post.
    let result = unsafe {
        state.device.transmit_segments(
            sq_index,
            &dma_segments[..dma_segment_count],
            total_len,
            options,
        )
    };
    let counter = match result {
        Ok(counter) => counter,
        Err(crate::error::WorkSubmissionError::NotPublished(cause)) => {
            state.tx_errors = state.tx_errors.saturating_add(1);
            log::warn!(target: "mlx5", "TX was not published: {cause:?}");
            return AbiError::IoError as i32;
        }
        Err(crate::error::WorkSubmissionError::OutcomeUnknown { counter, cause, .. }) => {
            // ABI success transfers the submission owner even when transport
            // outcome is uncertain; returning rejection would release live DMA.
            state.device.state = crate::device::DeviceState::Error;
            log::error!(target: "mlx5", "TX publication uncertain; retaining counter {counter}: {cause:?}");
            counter
        }
    };
    let slot = counter as usize % state.tx_slots[sq_index].len();
    assert!(
        state.tx_slots[sq_index][slot].is_none(),
        "active counter owns its unique submission slot"
    );
    state.tx_slots[sq_index][slot] = Some(TxLeaseRecord {
        lease: lease_id,
        counter,
        completion: None,
    });
    state.tx_packets = state.tx_packets.saturating_add(1);
    schedule_runtime_poll_locked(state);
    AbiError::Success as i32
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

/// A failed finalization retains the complete owner, including callbacks and
/// packet leases. No runtime is destroyed merely because poll admission stops.
extern "C" fn mlx5_netdev_stop(_opaque: u64) -> i32 {
    let mut state = {
        let mut guard = MLX5_STANDALONE_STATE.lock();
        match core::mem::replace(&mut *guard, Mlx5Slot::Finalizing) {
            Mlx5Slot::Live(mut state) => {
                state.lifecycle = Mlx5Lifecycle::StopRequested;
                state
            }
            slot @ Mlx5Slot::Finalizing => {
                *guard = slot;
                return AbiError::DeviceBusy as i32;
            }
            slot @ (Mlx5Slot::Vacant | Mlx5Slot::AcquisitionFailed(_)) => {
                *guard = slot;
                return AbiError::Success as i32;
            }
        }
    };
    // SAFETY: Finalizing excludes new TX/RX/poll callbacks. This local owner
    // retains all queue, command, packet and MMIO resources on every outcome.
    let result = unsafe { state.device.teardown_full() };
    let status = match result {
        Err(Mlx5Error::CommandTransportBusy) => AbiError::DeviceBusy,
        Err(cause) => {
            log::warn!(target: "mlx5", "Shutdown incomplete; owner retained: {cause}");
            AbiError::IoError
        }
        Ok(()) => {
            // Packet leases need their own completion/return acknowledgement.
            // Empty rings authorize runtime detachment; a count is never DMA
            // quiescence evidence for a non-empty ring.
            let packets_remain = state.tx_slots.iter().flatten().any(Option::is_some)
                || state.rx_slots.iter().flatten().any(Option::is_some);
            if packets_remain {
                AbiError::DeviceBusy
            } else {
                state.lifecycle = Mlx5Lifecycle::DeviceStopped;
                state.runtime = None;
                AbiError::Success
            }
        }
    };
    *MLX5_STANDALONE_STATE.lock() = Mlx5Slot::Live(state);
    status as i32
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
    ) -> impl core::future::Future<Output = kernel_api::error::KapiResult<()>> + Send {
        let device_id = ctx.device_id;
        let pci_locator = ctx.pci_location();
        async move {
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
            let plan = BootstrapDmaPlan::new(config.queue_profile).map_err(|cause| {
                log::error!(target: "mlx5", "Unsupported bootstrap allocation profile: {:?}", cause);
                kernel_api::error::KapiError::NotSupported
            })?;

            let request = kernel_api::mmio::PciMmioRequest::whole_bar(pci_locator, 0)
                .map_err(|_| kernel_api::error::KapiError::InvalidHandle)?;
            let mapping = kernel_api::service::kernel::instance()
                .acquire_pci_mmio(request)
                .map_err(kernel_api::error::KapiError::Mmio)?;
            let mut device = Mlx5Device::new(mapping, device_id).map_err(|(mapping, cause)| {
                log::error!(target: "mlx5", "Device acquisition failed: {:?}", cause);
                drop(mapping);
                map_driver_error(cause)
            })?;

            let mut dma = match BootstrapDmaInventory::allocate(&plan, |request| {
                kernel_api::service::kernel::instance().alloc_dma_for_device(request, pci_locator)
            }) {
                Ok(dma) => dma,
                Err(failure) => {
                    let (cause, inventory) = failure.into_parts();
                    let result = match &cause {
                        BootstrapAllocationCause::Metadata(_) => {
                            kernel_api::error::KapiError::OutOfMemory
                        }
                        BootstrapAllocationCause::Allocation { cause, .. } => *cause,
                        BootstrapAllocationCause::AuthorityViolation { .. } => {
                            kernel_api::error::KapiError::Internal(-1)
                        }
                    };
                    *MLX5_STANDALONE_STATE.lock() =
                        Mlx5Slot::AcquisitionFailed(Mlx5AcquisitionFailure {
                            cause,
                            dma: BootstrapDmaRetention::Unpublished(inventory),
                            device: Some(device),
                        });
                    return Err(result);
                }
            };

            if let Err(err) = device.bootstrap(&config, &mut dma) {
                log::error!(target: "mlx5", "Initialization failed: {:?}", err);
                // The failed/uncertain start keeps the function claimed and
                // retains firmware pages, DMA resources and the live mapping.
                *MLX5_STANDALONE_STATE.lock() = Mlx5Slot::Live(Mlx5StandaloneState {
                    lifecycle: Mlx5Lifecycle::StartupFailed(err),
                    device,
                    dma: BootstrapDmaRetention::Unpublished(dma),
                    registration_handle: None,
                    runtime: None,
                    poll_generation: 0,
                    poll_task: None,
                    poll_failure: None,
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
            tx_slots.resize_with(device.num_sqs(), init_slot_ring::<TxLeaseRecord>);
            let mut rx_slots = Vec::with_capacity(device.num_rqs());
            rx_slots.resize_with(device.num_rqs(), init_slot_ring::<AbiRxLeaseGuard>);

            let last_link_up = device
                .port(0)
                .map(|port| port.is_link_up())
                .unwrap_or(false);
            let state = Mlx5StandaloneState {
                lifecycle: Mlx5Lifecycle::Running,
                device,
                dma: BootstrapDmaRetention::Unpublished(dma),
                registration_handle: None,
                runtime: None,
                poll_generation: 0,
                poll_task: None,
                poll_failure: None,
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
        }
    }

    async fn start(&mut self) -> kernel_api::error::KapiResult<()> {
        let registration = {
            let guard = MLX5_STANDALONE_STATE.lock();
            let Mlx5Slot::Live(state) = &*guard else {
                return Err(kernel_api::error::KapiError::NotFound);
            };
            if let Some(handle) = state.registration_handle {
                return if matches!(state.lifecycle, Mlx5Lifecycle::Running)
                    && state.runtime.is_some()
                {
                    Ok(())
                } else {
                    Err(kernel_api::error::KapiError::NetRegistrationRetained { handle })
                };
            }
            if let Mlx5Lifecycle::StartupFailed(cause) = state.lifecycle {
                return Err(map_driver_error(cause));
            }
            if !matches!(state.lifecycle, Mlx5Lifecycle::Running) {
                return Err(kernel_api::error::KapiError::IoError);
            }
            netdev_registration(state)
        };

        let outcome = kernel_api::service::kernel::instance().register_netdev_port(&registration);
        let (handle, failure) = match outcome {
            Ok(handle) => (handle, None),
            Err(cause @ kernel_api::error::KapiError::NetRegistrationRetained { handle }) => {
                (handle, Some(cause))
            }
            Err(cause) => return Err(cause),
        };
        let mut guard = MLX5_STANDALONE_STATE.lock();
        let Mlx5Slot::Live(state) = &mut *guard else {
            drop(guard);
            return match kernel_api::service::kernel::instance().unregister_netdev_port(handle) {
                Ok(()) => Err(kernel_api::error::KapiError::NotFound),
                Err(_) => Err(kernel_api::error::KapiError::NetRegistrationRetained { handle }),
            };
        };
        state.registration_handle = Some(handle);
        match failure {
            Some(cause) => Err(cause),
            None => Ok(()),
        }
    }

    async fn stop(&mut self) -> kernel_api::error::KapiResult<()> {
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
        let result = {
            let mut guard = MLX5_STANDALONE_STATE.lock();
            match core::mem::replace(&mut *guard, Mlx5Slot::Finalizing) {
                Mlx5Slot::Live(mut state) => {
                    drop(guard);
                    state.registration_handle = None;
                    destroy_state(state).map_err(|(cause, state)| (cause, Mlx5Slot::Live(state)))
                }
                Mlx5Slot::AcquisitionFailed(mut state) => {
                    drop(guard);
                    state
                        .close()
                        .map_err(|cause| (cause, Mlx5Slot::AcquisitionFailed(state)))
                }
                Mlx5Slot::Vacant => {
                    *guard = Mlx5Slot::Vacant;
                    return Ok(());
                }
                Mlx5Slot::Finalizing => {
                    return Err(kernel_api::error::KapiError::AlreadyExists);
                }
            }
        };
        match result {
            Ok(()) => {
                *MLX5_STANDALONE_STATE.lock() = Mlx5Slot::Vacant;
                Ok(())
            }
            Err((cause, slot)) => {
                *MLX5_STANDALONE_STATE.lock() = slot;
                Err(cause)
            }
        }
    }

    fn remove(
        &mut self,
    ) -> impl core::future::Future<Output = kernel_api::error::KapiResult<()>> + Send {
        self.stop()
    }
}

fn map_driver_error(err: Mlx5Error) -> kernel_api::error::KapiError {
    match err {
        Mlx5Error::PageAllocation(cause) => cause,
        Mlx5Error::CommandTransportBusy => kernel_api::error::KapiError::Busy,
        Mlx5Error::OutOfMemory => kernel_api::error::KapiError::OutOfMemory,
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
