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
use kernel_api::driver_abi::{
    pack_version, AbiDmaBuffer, AbiMmioHandle, DriverCapabilities, DriverContext, DriverVTable,
    KernelApiV1, DRIVER_ABI_VERSION,
};

use crate::defs::{MLX5_CQ_DEPTH, MLX5_EQ_DEPTH, MLX5_PAGE_SIZE, MLX5_WQ_DEPTH};
use crate::device::Mlx5Device;
use crate::resources::MkeyParams;

const CMD_LOG_SIZE: u8 = 2; // 4 entries
const DMA_PAGE_BYTES: usize = MLX5_PAGE_SIZE;
const FW_BOOT_PAGE_COUNT: usize = 4;
const MLX5_EQ_SPARE_EQE: u32 = 0x80;

// ============================================================================
// External Kernel API Access
// ============================================================================

#[inline]
fn kernel_api() -> &'static KernelApiV1 {
    kernel_api::services::kernel_api_v1()
}

// ============================================================================
// DMA Resource Management
// ============================================================================

#[derive(Clone, Copy, Debug, Default)]
struct DmaSlot {
    handle: AbiDmaBuffer,
}

impl DmaSlot {
    fn alloc(size: usize, label: &'static str) -> Result<Self, i32> {
        // Use the high-level KernelServices API, then convert to ABI buffer using accessors.
        match kernel_api::services::kernel().alloc_dma(size) {
            Ok(buf) => {
                let handle = AbiDmaBuffer {
                    phys_addr: buf.physical_address(),
                    device_addr: buf.device_address(),
                    virt_addr: buf.as_ptr() as u64,
                    size: buf.size(),
                };
                Ok(Self { handle })
            }
            Err(e) => {
                log::error!(target: "mlx5", "DMA allocation failed for {}: {:?}", label, e);
                Err(-1)
            }
        }
    }

    fn as_ptr_u64(&self) -> u64 {
        self.handle.virt_addr
    }

    fn device_address(&self) -> u64 {
        self.handle.device_addr
    }

    fn free(self) {
        if self.handle.size != 0 {
            // Use the low-level ABI free function; simpler than reconstructing a DmaBuffer.
            (kernel_api().free_dma)(&self.handle);
        }
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
}

impl Mlx5DmaResources {
    fn allocate(num_queues: usize) -> Result<Self, i32> {
        let cmdq_size = DMA_PAGE_BYTES.max((1usize << CMD_LOG_SIZE) * 64);
        let cmd_mbox_size = DMA_PAGE_BYTES;

        let eq_target_depth = MLX5_EQ_DEPTH.saturating_add(MLX5_EQ_SPARE_EQE);
        let eq_log_size = (32 - (eq_target_depth - 1).leading_zeros()) as u8;
        let eq_alloc_depth = 1u32 << eq_log_size;
        let eq_size = (eq_alloc_depth as usize) * 64;
        let cq_size = (MLX5_CQ_DEPTH as usize) * 64;
        let sq_size = (MLX5_WQ_DEPTH as usize) * 64;
        let rq_size = (MLX5_WQ_DEPTH as usize) * 16;
        let db_record_size = DMA_PAGE_BYTES;

        let mut fw_pages = Vec::with_capacity(FW_BOOT_PAGE_COUNT);
        for _ in 0..FW_BOOT_PAGE_COUNT {
            fw_pages.push(DmaSlot::alloc(DMA_PAGE_BYTES, "fw_page")?);
        }

        let mut eqs = Vec::with_capacity(num_queues);
        let mut tx_cqs = Vec::with_capacity(num_queues);
        let mut tx_cq_dbs = Vec::with_capacity(num_queues);
        let mut rx_cqs = Vec::with_capacity(num_queues);
        let mut rx_cq_dbs = Vec::with_capacity(num_queues);
        let mut sqs = Vec::with_capacity(num_queues);
        let mut sq_dbs = Vec::with_capacity(num_queues);
        let mut rqs = Vec::with_capacity(num_queues);
        let mut rq_dbs = Vec::with_capacity(num_queues);

        for _ in 0..num_queues {
            eqs.push(DmaSlot::alloc(eq_size, "eq")?);
            tx_cqs.push(DmaSlot::alloc(cq_size, "tx_cq")?);
            tx_cq_dbs.push(DmaSlot::alloc(db_record_size, "tx_cq_db")?);
            rx_cqs.push(DmaSlot::alloc(cq_size, "rx_cq")?);
            rx_cq_dbs.push(DmaSlot::alloc(db_record_size, "rx_cq_db")?);
            sqs.push(DmaSlot::alloc(sq_size, "sq")?);
            sq_dbs.push(DmaSlot::alloc(db_record_size, "sq_db")?);
            rqs.push(DmaSlot::alloc(rq_size, "rq")?);
            rq_dbs.push(DmaSlot::alloc(db_record_size, "rq_db")?);
        }

        Ok(Self {
            cmdq: DmaSlot::alloc(cmdq_size, "cmdq")?,
            cmd_in_mbox: DmaSlot::alloc(cmd_mbox_size, "cmd_in_mbox")?,
            cmd_out_mbox: DmaSlot::alloc(cmd_mbox_size, "cmd_out_mbox")?,
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
        })
    }

    fn fw_page_device_addrs(&self) -> Vec<u64> {
        self.fw_pages.iter().map(|p| p.device_address()).collect()
    }
}

impl Drop for Mlx5DmaResources {
    fn drop(&mut self) {
        for page in self.fw_pages.drain(..) {
            page.free();
        }
        for q in self.rq_dbs.drain(..) { q.free(); }
        for q in self.rqs.drain(..) { q.free(); }
        for q in self.sq_dbs.drain(..) { q.free(); }
        for q in self.sqs.drain(..) { q.free(); }
        for q in self.rx_cq_dbs.drain(..) { q.free(); }
        for q in self.rx_cqs.drain(..) { q.free(); }
        for q in self.tx_cq_dbs.drain(..) { q.free(); }
        for q in self.tx_cqs.drain(..) { q.free(); }
        for q in self.eqs.drain(..) { q.free(); }
        self.cmd_out_mbox.free();
        self.cmd_in_mbox.free();
        self.cmdq.free();
    }
}

// ============================================================================
// Driver State
// ============================================================================

struct Mlx5DriverState {
    device: Mlx5Device,
    dma: Mlx5DmaResources,
    mmio: AbiMmioHandle,
}

// ============================================================================
// Driver Probe/Remove Functions
// ============================================================================

extern "C" fn mlx5_probe(ctx: *mut DriverContext) -> i32 {
    let ctx = unsafe { &mut *ctx };

    // BAR0 mapping
    let mut mmio = AbiMmioHandle::default();
    let res = (kernel_api().map_mmio)(ctx.device_address, 0x100000, &mut mmio);
    if res != 0 {
        log::error!(target: "mlx5", "Failed to map BAR0: {}", res);
        return res;
    }

    let num_queues = 4;
    let dma = match Mlx5DmaResources::allocate(num_queues) {
        Ok(d) => d,
        Err(e) => {
            (kernel_api().unmap_mmio)(&mmio);
            return e;
        }
    };

    let mut device = Mlx5Device::new(mmio.base, mmio.size as usize, ctx.device_id);
    // PCI BDF info is not passed in `DriverContext`; when running inside the
    // kernel the registry fills the fields.  In cell/FFI mode we leave them
    // at zero and avoid accessing them.
    
    let fw_page_addrs = dma.fw_page_device_addrs();
    let mkey_params = MkeyParams::default();

    let eq_log_size = (32 - (MLX5_EQ_DEPTH.saturating_add(MLX5_EQ_SPARE_EQE) - 1).leading_zeros()) as u8;
    let cq_log_size = (32 - (MLX5_CQ_DEPTH - 1).leading_zeros()) as u8;
    let sq_log_size = (32 - (MLX5_WQ_DEPTH - 1).leading_zeros()) as u8;
    let rq_log_size = (32 - (MLX5_WQ_DEPTH - 1).leading_zeros()) as u8;

    let eq_bufs: Vec<(u64, u64)> = dma.eqs.iter().map(|q| (q.as_ptr_u64(), q.device_address())).collect();
    let tx_cq_bufs: Vec<(u64, u64, u64, u64)> = dma.tx_cqs.iter().zip(dma.tx_cq_dbs.iter())
        .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();
    let rx_cq_bufs: Vec<(u64, u64, u64, u64)> = dma.rx_cqs.iter().zip(dma.rx_cq_dbs.iter())
        .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();
    let sq_bufs: Vec<(u64, u64, u64, u64)> = dma.sqs.iter().zip(dma.sq_dbs.iter())
        .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();
    let rq_bufs: Vec<(u64, u64, u64, u64)> = dma.rqs.iter().zip(dma.rq_dbs.iter())
        .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();

    let init_res = unsafe {
        device.init_multi_queue(
            dma.cmdq.as_ptr_u64(),
            dma.cmdq.device_address(),
            dma.cmd_in_mbox.as_ptr_u64(),
            dma.cmd_in_mbox.device_address(),
            dma.cmd_out_mbox.as_ptr_u64(),
            dma.cmd_out_mbox.device_address(),
            &fw_page_addrs,
            &mkey_params,
            &eq_bufs,
            &tx_cq_bufs,
            &rx_cq_bufs,
            &sq_bufs,
            &rq_bufs,
            eq_log_size,
            cq_log_size,
            sq_log_size,
            rq_log_size,
        )
    };

    if let Err(e) = init_res {
        log::error!(target: "mlx5", "Initialization failed: {:?}", e);
        (kernel_api().unmap_mmio)(&mmio);
        return -1;
    }

    let state = Box::new(Mlx5DriverState { device, dma, mmio });
    ctx.driver_data = Box::into_raw(state) as u64;

    0
}

extern "C" fn mlx5_start(_ctx: *mut DriverContext) -> i32 {
    0
}

extern "C" fn mlx5_stop(ctx: *mut DriverContext) -> i32 {
    let ctx = unsafe { &mut *ctx };
    if ctx.driver_data == 0 {
        return 0;
    }

    let state = unsafe { &mut *(ctx.driver_data as *mut Mlx5DriverState) };
    unsafe {
        if let Err(e) = state.device.teardown_full() {
            log::warn!(target: "mlx5", "Teardown error: {:?}", e);
        }
    }

    0
}

extern "C" fn mlx5_remove(ctx: *mut DriverContext) -> i32 {
    let ctx = unsafe { &mut *ctx };
    if ctx.driver_data == 0 {
        return 0;
    }

    let state = unsafe { Box::from_raw(ctx.driver_data as *mut Mlx5DriverState) };
    (kernel_api().unmap_mmio)(&state.mmio);
    
    ctx.driver_data = 0;
    0
}

// ============================================================================
// Driver Metadata Functions
// ============================================================================

extern "C" fn mlx5_name() -> *const u8 {
    b"mlx5\0".as_ptr()
}

extern "C" fn mlx5_name_len() -> usize {
    4
}

extern "C" fn mlx5_driver_type() -> u32 {
    4
}

extern "C" fn mlx5_version() -> u64 {
    pack_version(0, 1, 0)
}

extern "C" fn mlx5_request_capabilities(caps: *mut DriverCapabilities) {
    if !caps.is_null() {
        unsafe {
            (*caps).needs_dma = true;
            (*caps).needs_irq = true;
            (*caps).needs_mmio = true;
        }
    }
}

// ============================================================================
// Driver Entry Point
// ============================================================================

fn mlx5_driver_vtable() -> *const DriverVTable {
    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        mlx5_probe,
        mlx5_start,
        mlx5_stop,
        mlx5_remove,
        mlx5_name,
        mlx5_name_len,
        mlx5_driver_type,
        mlx5_version,
        Some(mlx5_request_capabilities),
        None,
    );

    &VTABLE
}

#[cfg(feature = "export_driver_entry")]
#[export_name = "_exorust_driver_entry"]
pub extern "C" fn _exorust_driver_entry() -> *const DriverVTable {
    mlx5_driver_vtable()
}

#[cfg(not(feature = "export_driver_entry"))]
pub(crate) fn _exorust_driver_entry_unique() -> *const DriverVTable {
    mlx5_driver_vtable()
}
