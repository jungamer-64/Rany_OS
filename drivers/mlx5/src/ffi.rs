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
use kernel_api::abi::driver::AbiDmaSlice;
#[cfg(test)]
use kernel_api::abi::driver::{AbiBlockDeviceRegistration, AbiNvmeNamespaceRegistration};
use kernel_api::abi::driver::{
    AbiError, AbiMmioHandle, AbiNetDriverEvent, AbiNetDriverEventKind, AbiNetPortInfo,
    AbiNetPortOps, AbiNetPortRegistration, AbiNetPortRuntime, AbiNetPortStats, AbiNetRxFrameLayout,
    AbiNetRxMeta, AbiNetTxMeta, AbiNetTxSubmission, AbiPacketRefRaw, DriverContext, KernelApiV4,
    PackedPciLocation,
};
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::driver::{AsyncDriver, DriverFuture, DriverType, DriverVersion};
use kernel_api::resource::net::PacketByteCount;
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
extern "C" fn test_kernel_alloc_dma_for_device_raw(
    _size: usize,
    _device_id: u64,
    _align: usize,
    _out: *mut AbiDmaSlice,
) -> i32 {
    -1
}

#[cfg(test)]
extern "C" fn test_kernel_release_dma_raw(_dma_handle_id: u64) -> i32 {
    0
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
    alloc_dma_for_device_raw: test_kernel_alloc_dma_for_device_raw,
    release_dma_raw: test_kernel_release_dma_raw,
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

struct DmaSlot {
    buffer: Option<DmaSlice<CpuOwned>>,
    virt_addr: u64,
    device_addr: u64,
    size: usize,
}

// SAFETY: DmaSlot is only exposed through the mlx5 driver's internal state,
// and safe APIs never provide shared mutable access to the backing DMA memory.
unsafe impl Sync for DmaSlot {}

impl DmaSlot {
    fn alloc(
        size: usize,
        pci_locator: PackedPciLocation,
        label: &'static str,
    ) -> Result<Self, i32> {
        let mut low_iova_retries = 0u32;
        loop {
            match kernel_api::service::kernel::instance().alloc_dma_for_device(size, pci_locator) {
                Ok(buf) => {
                    let device_addr = buf.device_address();
                    let virt_addr = buf.as_ptr() as u64;
                    let allocated_size = buf.size();

                    // Skip anything below 1MB to avoid legacy/IOMMU reservation conflicts
                    if device_addr < MLX5_DMA_MIN_IOVA {
                        low_iova_retries = low_iova_retries.saturating_add(1);
                        if low_iova_retries == 1 || low_iova_retries % 8 == 0 {
                            log::warn!(
                                target: "mlx5",
                                "DMA allocated at low IOVA {:#x} for {}, retry {}/{}",
                                device_addr,
                                label,
                                low_iova_retries,
                                MLX5_DMA_LOW_IOVA_MAX_RETRIES
                            );
                        }
                        drop(buf);

                        if low_iova_retries >= MLX5_DMA_LOW_IOVA_MAX_RETRIES {
                            log::error!(
                                target: "mlx5",
                                "DMA allocation failed for {}: allocator returned only low IOVA (<{:#x}) for {} attempts",
                                label,
                                MLX5_DMA_MIN_IOVA,
                                MLX5_DMA_LOW_IOVA_MAX_RETRIES
                            );
                            return Err(-1);
                        }

                        continue;
                    }

                    log::info!(
                        target: "mlx5",
                        "DMA allocated for {}: device={:#x} size={:#x}",
                        label, device_addr, allocated_size
                    );
                    return Ok(Self {
                        buffer: Some(buf),
                        virt_addr,
                        device_addr,
                        size: allocated_size,
                    });
                }
                Err(e) => {
                    log::error!(target: "mlx5", "DMA allocation failed for {}: {:?}", label, e);
                    return Err(-1);
                }
            }
        }
    }

    fn as_ptr_u64(&self) -> u64 {
        self.virt_addr
    }

    fn device_address(&self) -> u64 {
        self.device_addr
    }

    fn as_region(&self) -> Mlx5DmaRegion {
        Mlx5DmaRegion::new(self.as_ptr_u64(), self.device_address(), self.size)
    }

    fn free(&mut self) {
        let _ = self.buffer.take();
    }
}

struct Mlx5DmaResources {
    cmdq: DmaSlot,
    cmd_in_mbox: DmaSlot,
    cmd_out_mbox: DmaSlot,
    fw_pages: Vec<DmaSlot>,
    eqs: Vec<DmaSlot>,
    tx_cqs: Vec<DmaSlot>,
    tx_cq_dbs: Vec<DmaSlot>,
    rx_cqs: Vec<DmaSlot>,
    rx_cq_dbs: Vec<DmaSlot>,
    sqs: Vec<DmaSlot>,
    sq_dbs: Vec<DmaSlot>,
    rqs: Vec<DmaSlot>,
    rq_dbs: Vec<DmaSlot>,
    rmps: Vec<DmaSlot>,
    rmp_dbs: Vec<DmaSlot>,
}

impl Mlx5DmaResources {
    fn allocate(plan: &Mlx5BootstrapPlan, pci_locator: PackedPciLocation) -> Result<Self, i32> {
        let profile = plan.queue_profile();

        let mut fw_pages = Vec::with_capacity(plan.fw_boot_page_count());
        for _ in 0..plan.fw_boot_page_count() {
            fw_pages.push(DmaSlot::alloc(plan.fw_page_size(), pci_locator, "fw_page")?);
        }

        let mut eqs = Vec::with_capacity(profile.eq_count);
        let mut tx_cqs = Vec::with_capacity(profile.tx_queue_count);
        let mut tx_cq_dbs = Vec::with_capacity(profile.tx_queue_count);
        let mut rx_cqs = Vec::with_capacity(profile.rx_queue_count);
        let mut rx_cq_dbs = Vec::with_capacity(profile.rx_queue_count);
        let mut sqs = Vec::with_capacity(profile.tx_queue_count);
        let mut sq_dbs = Vec::with_capacity(profile.tx_queue_count);
        let mut rqs = Vec::with_capacity(profile.rx_queue_count);
        let mut rq_dbs = Vec::with_capacity(profile.rx_queue_count);
        let mut rmps = Vec::with_capacity(profile.rx_queue_count);
        let mut rmp_dbs = Vec::with_capacity(profile.rx_queue_count);

        for _ in 0..profile.eq_count {
            eqs.push(DmaSlot::alloc(plan.eq_size(), pci_locator, "eq")?);
        }
        for _ in 0..profile.tx_queue_count {
            tx_cqs.push(DmaSlot::alloc(plan.cq_size(), pci_locator, "tx_cq")?);
            tx_cq_dbs.push(DmaSlot::alloc(
                plan.db_record_size(),
                pci_locator,
                "tx_cq_db",
            )?);
            sqs.push(DmaSlot::alloc(plan.sq_size(), pci_locator, "sq")?);
            sq_dbs.push(DmaSlot::alloc(plan.db_record_size(), pci_locator, "sq_db")?);
        }
        for _ in 0..profile.rx_queue_count {
            rx_cqs.push(DmaSlot::alloc(plan.cq_size(), pci_locator, "rx_cq")?);
            rx_cq_dbs.push(DmaSlot::alloc(
                plan.db_record_size(),
                pci_locator,
                "rx_cq_db",
            )?);
            rqs.push(DmaSlot::alloc(plan.rq_size(), pci_locator, "rq")?);
            rq_dbs.push(DmaSlot::alloc(plan.db_record_size(), pci_locator, "rq_db")?);
            rmps.push(DmaSlot::alloc(plan.rmp_size(), pci_locator, "rmp")?);
            rmp_dbs.push(DmaSlot::alloc(
                plan.db_record_size(),
                pci_locator,
                "rmp_db",
            )?);
        }

        Ok(Self {
            cmdq: DmaSlot::alloc(plan.command_queue_size(), pci_locator, "cmdq")?,
            cmd_in_mbox: DmaSlot::alloc(plan.command_mailbox_size(), pci_locator, "cmd_in_mbox")?,
            cmd_out_mbox: DmaSlot::alloc(plan.command_mailbox_size(), pci_locator, "cmd_out_mbox")?,
            fw_pages,
            eqs,
            tx_cqs,
            tx_cq_dbs,
            rx_cqs,
            rx_cq_dbs,
            sqs,
            sq_dbs,
            rqs,
            rq_dbs,
            rmps,
            rmp_dbs,
        })
    }

    fn to_allocated_resources(&self) -> Mlx5AllocatedResources {
        Mlx5AllocatedResources {
            cmdq: self.cmdq.as_region(),
            cmd_in_mbox: self.cmd_in_mbox.as_region(),
            cmd_out_mbox: self.cmd_out_mbox.as_region(),
            fw_pages: self.fw_pages.iter().map(DmaSlot::as_region).collect(),
            eqs: self.eqs.iter().map(DmaSlot::as_region).collect(),
            tx_cqs: self
                .tx_cqs
                .iter()
                .zip(self.tx_cq_dbs.iter())
                .map(|(queue, doorbell)| Mlx5QueueDmaRegion {
                    entries: queue.as_region(),
                    doorbell: doorbell.as_region(),
                })
                .collect(),
            rx_cqs: self
                .rx_cqs
                .iter()
                .zip(self.rx_cq_dbs.iter())
                .map(|(queue, doorbell)| Mlx5QueueDmaRegion {
                    entries: queue.as_region(),
                    doorbell: doorbell.as_region(),
                })
                .collect(),
            sqs: self
                .sqs
                .iter()
                .zip(self.sq_dbs.iter())
                .map(|(queue, doorbell)| Mlx5QueueDmaRegion {
                    entries: queue.as_region(),
                    doorbell: doorbell.as_region(),
                })
                .collect(),
            rqs: self
                .rqs
                .iter()
                .zip(self.rq_dbs.iter())
                .map(|(queue, doorbell)| Mlx5QueueDmaRegion {
                    entries: queue.as_region(),
                    doorbell: doorbell.as_region(),
                })
                .collect(),
            rmps: self
                .rmps
                .iter()
                .zip(self.rmp_dbs.iter())
                .map(|(queue, doorbell)| Mlx5QueueDmaRegion {
                    entries: queue.as_region(),
                    doorbell: doorbell.as_region(),
                })
                .collect(),
        }
    }
}

impl Drop for Mlx5DmaResources {
    fn drop(&mut self) {
        self.fw_pages.clear();
        self.rmp_dbs.clear();
        self.rmps.clear();
        self.rq_dbs.clear();
        self.rqs.clear();
        self.sq_dbs.clear();
        self.sqs.clear();
        self.rx_cq_dbs.clear();
        self.rx_cqs.clear();
        self.tx_cq_dbs.clear();
        self.tx_cqs.clear();
        self.eqs.clear();
        self.cmd_out_mbox.free();
        self.cmd_in_mbox.free();
        self.cmdq.free();
    }
}

// ============================================================================
// Driver State
// ============================================================================

const MLX5_POLL_BATCH: u32 = 64;
const MLX5_POLL_INTERVAL_MS: u64 = 1;
const MLX5_DMA_MIN_IOVA: u64 = 0x100000;
const MLX5_DMA_LOW_IOVA_MAX_RETRIES: u32 = 64;

struct Mlx5StandaloneState {
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
    rx_slots: Vec<Vec<Option<AbiPacketRefRaw>>>,
}

static MLX5_STANDALONE_STATE: Mutex<Option<Mlx5StandaloneState>> = Mutex::new(None);

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

fn allocate_runtime_packet(runtime: AbiNetPortRuntime) -> Result<AbiPacketRefRaw, AbiError> {
    let mut packet = AbiPacketRefRaw::default();
    let status = (runtime.alloc_packet)(runtime.runtime_cookie, &mut packet);
    let status = AbiError::from_raw(status);
    if status.is_success() && !packet.is_null() {
        Ok(packet)
    } else if status.is_success() {
        Err(AbiError::OutOfMemory)
    } else {
        Err(status)
    }
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

fn set_abi_packet_len(packet: &mut AbiPacketRefRaw, len: usize) -> Result<(), AbiError> {
    let Some(len) = PacketByteCount::new(len) else {
        return Err(AbiError::InvalidParam);
    };
    if packet.set_len(len) {
        Ok(())
    } else {
        Err(AbiError::InvalidParam)
    }
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
            let mut packet = allocate_runtime_packet(runtime)?;
            let buffer_size = packet.capacity().saturating_sub(packet.headroom());
            if buffer_size == 0 {
                return Err(AbiError::OutOfMemory);
            }
            set_abi_packet_len(&mut packet, buffer_size)?;
            let device_addr = packet.device_address();
            let virt_addr = packet.data_mut().as_ptr() as u64;
            let size = buffer_size as u32;
            match unsafe {
                state
                    .device
                    .post_receive(rq_index, device_addr, virt_addr, size)
            } {
                Ok(_) => state.rx_slots[rq_index][slot] = Some(packet),
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

            let Some(mut packet) = state.rx_slots[rq_index][slot].take() else {
                state.rx_errors = state.rx_errors.saturating_add(1);
                continue;
            };

            if matches!(cqe.opcode, CqeOpcode::ReqErr | CqeOpcode::RespErr) {
                state.rx_errors = state.rx_errors.saturating_add(1);
                if let Ok(mut replacement) = allocate_runtime_packet(runtime) {
                    let len = replacement
                        .capacity()
                        .saturating_sub(replacement.headroom());
                    if set_abi_packet_len(&mut replacement, len).is_ok() {
                        let _ = unsafe {
                            state.device.post_receive(
                                rq_index,
                                replacement.device_address(),
                                replacement.data_mut().as_ptr() as u64,
                                len as u32,
                            )
                        };
                        state.rx_slots[rq_index][slot] = Some(replacement);
                    } else {
                        state.rx_errors = state.rx_errors.saturating_add(1);
                    }
                }
                continue;
            }

            let byte_count = cmp::min(
                cqe.byte_count as usize,
                packet.capacity().saturating_sub(packet.headroom()),
            );
            if set_abi_packet_len(&mut packet, byte_count).is_err() {
                state.rx_errors = state.rx_errors.saturating_add(1);
                continue;
            }
            let Some(rx_layout) = AbiNetRxFrameLayout::whole_payload(byte_count) else {
                state.rx_errors = state.rx_errors.saturating_add(1);
                continue;
            };
            let status = (runtime.submit_rx_packet)(
                runtime.runtime_cookie,
                &mut packet,
                AbiNetRxMeta::new(rq_index as u16, rx_layout, 0),
            );
            if AbiError::from_raw(status).is_success() {
                state.rx_packets = state.rx_packets.saturating_add(1);
            } else {
                state.rx_errors = state.rx_errors.saturating_add(1);
            }

            match allocate_runtime_packet(runtime) {
                Ok(mut replacement) => {
                    let len = replacement
                        .capacity()
                        .saturating_sub(replacement.headroom());
                    if set_abi_packet_len(&mut replacement, len).is_err() {
                        state.rx_errors = state.rx_errors.saturating_add(1);
                        continue;
                    }
                    match unsafe {
                        state.device.post_receive(
                            rq_index,
                            replacement.device_address(),
                            replacement.data_mut().as_ptr() as u64,
                            len as u32,
                        )
                    } {
                        Ok(_) => state.rx_slots[rq_index][slot] = Some(replacement),
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
                Err(_) => state.rx_errors = state.rx_errors.saturating_add(1),
            }
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
                    let status = if matches!(cqe.opcode, CqeOpcode::ReqErr | CqeOpcode::RespErr) {
                        AbiError::IoError as i32
                    } else {
                        AbiError::Success as i32
                    };
                    let _ = (runtime.complete_tx_lease)(runtime.runtime_cookie, lease_id, status);
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

fn destroy_state(mut state: Mlx5StandaloneState) {
    unsafe {
        if let Err(err) = state.device.teardown_full() {
            log::warn!(target: "mlx5", "Teardown error: {:?}", err);
        }
    }
    let _ = (kernel_api().unmap_mmio)(&state.mmio);
    let _ = state.registration_handle.take();
    let _ = state.runtime.take();
    drop(state.dma);
}

async fn mlx5_poll_kicker(generation: u64) {
    loop {
        let should_continue = {
            let guard = MLX5_STANDALONE_STATE.lock();
            match guard.as_ref() {
                Some(state) if state.poll_generation == generation && state.runtime.is_some() => {
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
        let Some(state) = guard.as_mut() else {
            return AbiError::NotInitialized as i32;
        };
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
            if let Some(state) = guard.as_mut() {
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
    let Some(state) = guard.as_mut() else {
        return AbiError::NotInitialized as i32;
    };
    if !state.device.is_active() {
        return AbiError::NotInitialized as i32;
    }

    let data_len: usize = segments.iter().map(|segment| segment.len()).sum();
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

    let mut dma_segments = Vec::with_capacity(segments.len());
    for segment in segments.iter() {
        let segment_len = segment.len();
        let Ok(len) = u32::try_from(segment_len) else {
            return AbiError::InvalidParam as i32;
        };
        dma_segments.push(crate::wq::DmaSegment {
            device_addr: segment.device_addr(),
            virt_addr: segment.cpu_ptr() as u64,
            len,
        });
    }
    if dma_segments.is_empty() {
        return AbiError::InvalidParam as i32;
    }

    match unsafe {
        state.device.transmit_segments(
            sq_index,
            &dma_segments,
            total_len,
            options,
        )
    } {
        Ok(wqe_idx) => {
            let slot = (wqe_idx as usize) % (MLX5_WQ_DEPTH as usize);
            state.tx_slots[sq_index][slot] = Some(submission.lease_id());
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
    let Some(state) = guard.as_mut() else {
        return AbiError::NotInitialized as i32;
    };
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
    let Some(state) = guard.as_ref() else {
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

extern "C" fn mlx5_netdev_stop(_opaque: u64) {
    let mut guard = MLX5_STANDALONE_STATE.lock();
    if let Some(state) = guard.as_mut() {
        state.runtime = None;
        state.poll_generation = state.poll_generation.wrapping_add(1);
    }
}

extern "C" fn mlx5_netdev_set_interrupts_enabled(_opaque: u64, _enabled: bool) -> i32 {
    AbiError::Success as i32
}

fn netdev_registration(state: &Mlx5StandaloneState) -> AbiNetPortRegistration {
    AbiNetPortRegistration::new(
        AbiNetPortInfo {
            port_id: 0x0002_0000,
            queue_pairs: cmp::max(state.device.num_rqs(), state.device.num_sqs()) as u16,
            reserved_queue: 0,
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
            if MLX5_STANDALONE_STATE.lock().is_some() {
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
                let _ = (kernel_api().unmap_mmio)(&mmio);
                return Err(map_driver_error(err));
            }

            let _ = unsafe { device.refresh_port_runtime_state(0) };

            let mut tx_slots = Vec::with_capacity(device.num_sqs());
            tx_slots.resize_with(device.num_sqs(), init_slot_ring::<TxLeaseId>);
            let mut rx_slots = Vec::with_capacity(device.num_rqs());
            rx_slots.resize_with(device.num_rqs(), init_slot_ring::<AbiPacketRefRaw>);

            let last_link_up = device
                .port(0)
                .map(|port| port.is_link_up())
                .unwrap_or(false);
            let state = Mlx5StandaloneState {
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
            *MLX5_STANDALONE_STATE.lock() = Some(state);
            Ok(())
        })
    }

    fn start(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        Box::pin(async move {
            let registration = {
                let guard = MLX5_STANDALONE_STATE.lock();
                let Some(state) = guard.as_ref() else {
                    return Err(kernel_api::error::KapiError::NotFound);
                };
                if state.registration_handle.is_some() {
                    return Ok(());
                }
                netdev_registration(state)
            };

            let handle =
                kernel_api::service::kernel::instance().register_netdev_port(&registration)?;
            let mut guard = MLX5_STANDALONE_STATE.lock();
            let Some(state) = guard.as_mut() else {
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
                let mut guard = MLX5_STANDALONE_STATE.lock();
                guard
                    .as_mut()
                    .and_then(|state| state.registration_handle.take())
            };
            if let Some(handle) = handle {
                let _ = kernel_api::service::kernel::instance().unregister_netdev_port(handle);
            }
            let state = MLX5_STANDALONE_STATE.lock().take();
            if let Some(state) = state {
                destroy_state(state);
            }
            Ok(())
        })
    }

    fn remove(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        self.stop()
    }
}

fn map_driver_error(err: Mlx5Error) -> kernel_api::error::KapiError {
    match err {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn slot(_phys_addr: u64, device_addr: u64, virt_addr: u64, size: usize) -> DmaSlot {
        DmaSlot {
            buffer: None,
            virt_addr,
            device_addr,
            size,
        }
    }

    #[test]
    fn to_allocated_resources_preserves_iova_addresses() {
        let dma = Mlx5DmaResources {
            cmdq: slot(0x1000, 0x2000, 0x3000, 0x100),
            cmd_in_mbox: slot(0x4000, 0x5000, 0x6000, 0x200),
            cmd_out_mbox: slot(0x7000, 0x8000, 0x9000, 0x200),
            fw_pages: vec![slot(0xa000, 0xb000, 0xc000, 0x1000)],
            eqs: vec![slot(0xd000, 0xe000, 0xf000, 0x100)],
            tx_cqs: vec![slot(0x11_000, 0x12_000, 0x13_000, 0x100)],
            tx_cq_dbs: vec![slot(0x14_000, 0x15_000, 0x16_000, 0x1000)],
            rx_cqs: vec![slot(0x17_000, 0x18_000, 0x19_000, 0x100)],
            rx_cq_dbs: vec![slot(0x1a_000, 0x1b_000, 0x1c_000, 0x1000)],
            sqs: vec![slot(0x1d_000, 0x1e_000, 0x1f_000, 0x200)],
            sq_dbs: vec![slot(0x20_000, 0x21_000, 0x22_000, 0x1000)],
            rqs: vec![slot(0x23_000, 0x24_000, 0x25_000, 0x200)],
            rq_dbs: vec![slot(0x26_000, 0x27_000, 0x28_000, 0x1000)],
            rmps: vec![slot(0x29_000, 0x2a_000, 0x2b_000, 0x200)],
            rmp_dbs: vec![slot(0x2c_000, 0x2d_000, 0x2e_000, 0x1000)],
        };

        let allocated = dma.to_allocated_resources();
        assert_eq!(allocated.cmdq, Mlx5DmaRegion::new(0x3000, 0x2000, 0x100));
        assert_eq!(
            allocated.tx_cqs[0],
            Mlx5QueueDmaRegion {
                entries: Mlx5DmaRegion::new(0x13_000, 0x12_000, 0x100),
                doorbell: Mlx5DmaRegion::new(0x16_000, 0x15_000, 0x1000),
            }
        );
        assert_eq!(
            allocated.rmps[0],
            Mlx5QueueDmaRegion {
                entries: Mlx5DmaRegion::new(0x2b_000, 0x2a_000, 0x200),
                doorbell: Mlx5DmaRegion::new(0x2e_000, 0x2d_000, 0x1000),
            }
        );
    }

    #[test]
    fn fw_pages_use_iova_addresses() {
        let fw_pages = [
            slot(0x1000, 0x2000, 0, 0x1000),
            slot(0x3000, 0x4000, 0, 0x1000),
        ];

        assert_eq!(
            fw_pages
                .iter()
                .map(DmaSlot::device_address)
                .collect::<Vec<_>>(),
            vec![0x2000, 0x4000]
        );
    }
}
