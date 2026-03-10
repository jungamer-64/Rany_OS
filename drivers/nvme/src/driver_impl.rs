use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};

use exorust_sync::PoisonLock;

use crate::polling_driver::NvmePollingDriver;
use kernel_api::KapiResult;
use kernel_api::abi::driver::{
    AbiBlockCommandKind, AbiBlockDeviceInfo, AbiBlockDeviceRegistration, AbiBlockTransport,
    AbiError, AbiIoCompletion, AbiNvmeNamespaceInfo, AbiNvmeNamespaceRegistration, DriverContext,
    PackedPciLocation,
};
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::driver::{Driver, DriverType};

const STORAGE_KIND_NVME: u64 = 1;
const PAGE_SIZE: u64 = 4096;

pub struct NvmeDriverWrapper {
    inner: PoisonLock<NvmePollingDriver>,
}

impl NvmeDriverWrapper {
    pub fn new(bar0: u64, cores: u32, pci_locator: PackedPciLocation) -> Self {
        Self {
            inner: PoisonLock::new(NvmePollingDriver::new(bar0, cores, pci_locator)),
        }
    }
}

impl Driver for NvmeDriverWrapper {
    fn name(&self) -> &str {
        "NVMe Polling Driver"
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Block
    }

    fn probe(&mut self) -> KapiResult<()> {
        let mut driver = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        driver.init().map_err(|_| kernel_api::KapiError::IoError)
    }
}

struct PendingRequest {
    core_id: u32,
    cid: u16,
    bytes: usize,
    prp_list: Option<DmaSlice<CpuOwned>>,
}

struct NvmeAbiState {
    driver: NvmePollingDriver,
    pci_locator: PackedPciLocation,
    block_handle: Option<u64>,
    namespace_handle: Option<u64>,
    next_queue: AtomicU32,
    pending: PoisonLock<BTreeMap<u64, PendingRequest>>,
}

static NVME_ABI_STATE: PoisonLock<Option<NvmeAbiState>> = PoisonLock::new(None);

fn with_state<R>(f: impl FnOnce(&mut NvmeAbiState) -> R) -> Option<R> {
    NVME_ABI_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .map(f)
}

fn build_prps(
    pci_locator: PackedPciLocation,
    iova: u64,
    len: usize,
) -> Result<(u64, u64, Option<DmaSlice<CpuOwned>>), i32> {
    if len == 0 {
        return Err(AbiError::InvalidParam as i32);
    }

    let page_mask = PAGE_SIZE - 1;
    let first_page = iova & !page_mask;
    let first_page_remaining = (PAGE_SIZE - (iova & page_mask)) as usize;
    if len <= first_page_remaining {
        return Ok((iova, 0, None));
    }

    let remaining_after_first = len - first_page_remaining;
    let second_page = first_page + PAGE_SIZE;
    if remaining_after_first <= PAGE_SIZE as usize {
        return Ok((iova, second_page, None));
    }

    let entry_count = remaining_after_first.div_ceil(PAGE_SIZE as usize);
    let mut prp_list = kernel_api::service::kernel::instance()
        .alloc_dma_for_device(PAGE_SIZE as usize, pci_locator)
        .map_err(|_| AbiError::OutOfMemory as i32)?;
    let table = prp_list.as_slice_mut();
    for (index, chunk) in table.chunks_exact_mut(8).take(entry_count).enumerate() {
        let addr = second_page + (index as u64 * PAGE_SIZE);
        chunk.copy_from_slice(&addr.to_le_bytes());
    }
    Ok((iova, prp_list.device_address(), Some(prp_list)))
}

extern "C" fn nvme_block_submit(
    _opaque: u64,
    request_id: u64,
    command: u32,
    lba: u64,
    blocks: u32,
    bytes: usize,
    iova: u64,
) -> i32 {
    with_state(|state| {
        let queue_count = state.driver.io_queue_count().max(1) as u32;
        let core_id = state.next_queue.fetch_add(1, Ordering::Relaxed) % queue_count;
        if command == AbiBlockCommandKind::Discard as u32 {
            return AbiError::NotSupported as i32;
        }

        let (prp1, prp2, prp_list) = if command == AbiBlockCommandKind::Flush as u32 {
            (0, 0, None)
        } else {
            match build_prps(state.pci_locator, iova, bytes) {
                Ok(prps) => prps,
                Err(err) => return err,
            }
        };

        let result = match command {
            x if x == AbiBlockCommandKind::Read as u32 => unsafe {
                state
                    .driver
                    .submit_read(core_id, state.driver.nsid, lba, blocks as u16, prp1, prp2)
            },
            x if x == AbiBlockCommandKind::Write as u32 => unsafe {
                state.driver.submit_write(
                    core_id,
                    state.driver.nsid,
                    lba,
                    blocks as u16,
                    prp1,
                    prp2,
                )
            },
            x if x == AbiBlockCommandKind::Flush as u32 => unsafe {
                state.driver.submit_flush(core_id, state.driver.nsid)
            },
            _ => return AbiError::NotSupported as i32,
        };

        match result {
            Ok(cid) => {
                state
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        request_id,
                        PendingRequest {
                            core_id,
                            cid,
                            bytes,
                            prp_list,
                        },
                    );
                AbiError::Success as i32
            }
            Err(_) => AbiError::IoError as i32,
        }
    })
    .unwrap_or(AbiError::NotInitialized as i32)
}

extern "C" fn nvme_block_poll(
    _opaque: u64,
    out: *mut AbiIoCompletion,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if out.is_null() || written.is_null() {
        return AbiError::InvalidParam as i32;
    }

    with_state(|state| {
        let completed_ids: alloc::vec::Vec<(u64, bool)> = {
            let pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
            pending
                .iter()
                .filter_map(|(request_id, pending_req)| {
                    unsafe {
                        state
                            .driver
                            .poll_completion_by_cid(pending_req.core_id, pending_req.cid)
                    }
                    .map(|cqe| (*request_id, cqe.is_success()))
                })
                .collect()
        };

        let mut count = 0usize;
        let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        for (request_id, ok) in completed_ids.into_iter().take(capacity) {
            if let Some(mut request) = pending.remove(&request_id) {
                request.prp_list.take();
                unsafe {
                    *out.add(count) = AbiIoCompletion {
                        request_id,
                        status: if ok {
                            AbiError::Success as i32
                        } else {
                            AbiError::IoError as i32
                        },
                        bytes: request.bytes,
                    };
                }
                count += 1;
            }
        }

        unsafe {
            *written = count;
        }
        AbiError::Success as i32
    })
    .unwrap_or(AbiError::NotInitialized as i32)
}

extern "C" fn nvme_block_is_ready(_opaque: u64) -> bool {
    with_state(|state| state.driver.is_active()).unwrap_or(false)
}

fn register_runtime_bridges() -> Result<(), kernel_api::KapiError> {
    with_state(|state| {
        if state.block_handle.is_some() || state.namespace_handle.is_some() {
            return Ok(());
        }

        let block_size = state.driver.namespace_block_size(state.driver.nsid);
        let max_transfer_blocks =
            (state.driver.max_transfer_size() / block_size as usize).min(u32::MAX as usize) as u32;
        let block_info = AbiBlockDeviceInfo {
            device_id: (STORAGE_KIND_NVME << 56) | state.driver.nsid as u64,
            namespace_id: state.driver.nsid,
            block_size,
            max_transfer_blocks,
            transport: AbiBlockTransport::Nvme as u32,
            flags: 0,
            controller_id: 0,
            port_id: 0,
        };
        let block_registration = AbiBlockDeviceRegistration::new(
            block_info,
            0,
            nvme_block_submit,
            nvme_block_poll,
            nvme_block_is_ready,
        );
        let namespace_registration = AbiNvmeNamespaceRegistration::new(AbiNvmeNamespaceInfo {
            device_id: state.driver.nsid as u64,
            namespace_id: state.driver.nsid,
            block_size,
            max_transfer_blocks,
            max_sgl_entries: state.driver.sgl_max_entries().unwrap_or(0) as u32,
            total_blocks: state.driver.namespace_total_blocks(),
            controller_id: 0,
            flags: 0,
        });

        let kernel = kernel_api::service::kernel::instance();
        let block_handle = kernel.register_block_device(&block_registration)?;
        let namespace_handle = kernel.register_nvme_namespace(&namespace_registration)?;
        state.block_handle = Some(block_handle);
        state.namespace_handle = Some(namespace_handle);
        Ok(())
    })
    .unwrap_or(Err(kernel_api::KapiError::NotFound))
}

fn unregister_runtime_bridges() {
    let _ = with_state(|state| {
        let kernel = kernel_api::service::kernel::instance();
        if let Some(handle) = state.namespace_handle.take() {
            let _ = kernel.unregister_nvme_namespace(handle);
        }
        if let Some(handle) = state.block_handle.take() {
            let _ = kernel.unregister_block_device(handle);
        }
        state
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    });
}

// ============================================================================
// ABI Export for Dynamic Cell Loading
// ============================================================================

fn abi_probe(ctx: &mut DriverContext) -> i32 {
    let mut state = NvmeAbiState {
        driver: NvmePollingDriver::new(ctx.device_address, 1, ctx.pci_location()),
        pci_locator: ctx.pci_location(),
        block_handle: None,
        namespace_handle: None,
        next_queue: AtomicU32::new(0),
        pending: PoisonLock::new(BTreeMap::new()),
    };
    if state.driver.init().is_err() {
        return -1;
    }
    *NVME_ABI_STATE.lock().unwrap_or_else(|e| e.into_inner()) = Some(state);
    0
}

fn abi_remove(_ctx: &mut DriverContext) -> i32 {
    unregister_runtime_bridges();
    let _ = NVME_ABI_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    0
}

fn abi_start(_ctx: &mut DriverContext) -> i32 {
    match register_runtime_bridges() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

fn abi_stop(_ctx: &mut DriverContext) -> i32 {
    unregister_runtime_bridges();
    0
}

fn driver_name() -> &'static str {
    "nvme"
}

kernel_api::export_driver!(
    probe: abi_probe,
    remove: abi_remove,
    name: driver_name,
    driver_type: (kernel_api::abi::driver::AbiDriverType::Block as u32),
    version: 0x00010000_u64,
    start: abi_start,
    stop: abi_stop,
);
