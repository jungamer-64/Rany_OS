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
#[cfg(test)]
use kernel_api::abi::driver::AbiDmaSlice;
use kernel_api::abi::driver::{AbiMmioHandle, DriverContext, KernelApiV2};
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::driver::{AsyncDriver, DriverFuture, DriverType, DriverVersion};

use crate::bootstrap::{
    Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan, Mlx5DmaRegion, Mlx5PciIdentity,
    Mlx5QueueDmaRegion, Mlx5QueueProfile,
};
use crate::defs::MLX5_CMD_MBOX_SIZE;
use crate::device::Mlx5Device;
use crate::error::Mlx5Error;

// ============================================================================
// External Kernel API Access
// ============================================================================

#[inline]
fn kernel_api() -> &'static KernelApiV2 {
    kernel_api::service::kernel::abi()
}

#[cfg(test)]
extern "C" fn test_kernel_log(_level: u32, _msg_ptr: *const u8, _msg_len: usize) {}

#[cfg(test)]
extern "C" fn test_kernel_alloc_dma_raw(
    _size: usize,
    _align: usize,
    _out: *mut AbiDmaSlice,
) -> i32 {
    -1
}

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
extern "C" fn test_kernel_release_dma_raw(_virt_addr: u64, _size: usize, _phys_addr: u64) -> i32 {
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
#[unsafe(no_mangle)]
pub static __exorust_kernel_api_v2: KernelApiV2 = KernelApiV2 {
    abi_version: kernel_api::abi::driver::KERNEL_API_ABI_VERSION,
    abi_size: core::mem::size_of::<KernelApiV2>() as u32,
    log: test_kernel_log,
    alloc_dma_raw: test_kernel_alloc_dma_raw,
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
    reserved: [0; 8],
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
    fn alloc(size: usize, label: &'static str) -> Result<Self, i32> {
        loop {
            match kernel_api::service::kernel::instance().alloc_dma(size) {
                Ok(buf) => {
                    let phys_addr = buf.physical_address();
                    let device_addr = buf.device_address();
                    let virt_addr = buf.as_ptr() as u64;
                    let size = buf.size();

                    // Skip anything below 1MB to avoid legacy/IOMMU reservation conflicts
                    if device_addr < 0x100000 {
                        log::warn!(target: "mlx5", "DMA allocated at IOVA {:#x} for {}, skipping (<1MB)", device_addr, label);
                        drop(buf);
                        continue;
                    }

                    log::info!(
                        target: "mlx5",
                        "DMA allocated for {}: device={:#x} phys={:#x} size={:#x}",
                        label, device_addr, phys_addr, size
                    );
                    return Ok(Self {
                        buffer: Some(buf),
                        virt_addr,
                        device_addr,
                        size,
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
}

impl Mlx5DmaResources {
    const fn command_mailbox_allocation_size() -> usize {
        MLX5_CMD_MBOX_SIZE
    }

    fn device_addresses(slots: &[DmaSlot]) -> Vec<u64> {
        slots.iter().map(DmaSlot::device_address).collect()
    }

    fn allocate(plan: &Mlx5BootstrapPlan) -> Result<Self, i32> {
        let profile = plan.queue_profile();

        let mut fw_pages = Vec::with_capacity(plan.fw_boot_page_count());
        for _ in 0..plan.fw_boot_page_count() {
            fw_pages.push(DmaSlot::alloc(plan.fw_page_size(), "fw_page")?);
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

        for _ in 0..profile.eq_count {
            eqs.push(DmaSlot::alloc(plan.eq_size(), "eq")?);
        }
        for _ in 0..profile.tx_queue_count {
            tx_cqs.push(DmaSlot::alloc(plan.cq_size(), "tx_cq")?);
            tx_cq_dbs.push(DmaSlot::alloc(plan.db_record_size(), "tx_cq_db")?);
            sqs.push(DmaSlot::alloc(plan.sq_size(), "sq")?);
            sq_dbs.push(DmaSlot::alloc(plan.db_record_size(), "sq_db")?);
        }
        for _ in 0..profile.rx_queue_count {
            rx_cqs.push(DmaSlot::alloc(plan.cq_size(), "rx_cq")?);
            rx_cq_dbs.push(DmaSlot::alloc(plan.db_record_size(), "rx_cq_db")?);
            rqs.push(DmaSlot::alloc(plan.rq_size(), "rq")?);
            rq_dbs.push(DmaSlot::alloc(plan.db_record_size(), "rq_db")?);
        }

        Ok(Self {
            cmdq: DmaSlot::alloc(plan.command_queue_size(), "cmdq")?,
            cmd_in_mbox: DmaSlot::alloc(plan.command_mailbox_size(), "cmd_in_mbox")?,
            cmd_out_mbox: DmaSlot::alloc(plan.command_mailbox_size(), "cmd_out_mbox")?,
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
        Self::device_addresses(&self.fw_pages)
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
        }
    }
}

impl Drop for Mlx5DmaResources {
    fn drop(&mut self) {
        self.fw_pages.clear();
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

struct Mlx5DriverState {
    device: Mlx5Device,
    dma: Mlx5DmaResources,
    mmio: AbiMmioHandle,
}

// ============================================================================
// Driver Probe/Remove Functions
// ============================================================================

pub struct Mlx5AsyncDriver {
    state: Option<Mlx5DriverState>,
}

impl Mlx5AsyncDriver {
    pub const fn new() -> Self {
        Self { state: None }
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
        Box::pin(async move {
            let config = Mlx5BootstrapConfig {
                queue_profile: Mlx5QueueProfile::default(),
                mkey_params: crate::resources::MkeyParams::default(),
                pci_identity: Mlx5PciIdentity::default(),
                is_vf: crate::defs::ConnectXVariant::is_vf_device_id(device_id),
            };
            let plan = Mlx5BootstrapPlan::new(&config);

            let mut mmio = AbiMmioHandle::default();
            // ConnectX BAR0 can be up to 32MB for PFs, and 4MB-16MB for VFs depending on UAR count.
            // Map 16MB to cover a reasonable range of UARs.
            let bar0_size = 0x1000000; // 16MB
            let res = (kernel_api().map_mmio)(bar0_phys, bar0_size, &mut mmio);
            if res != 0 {
                log::error!(target: "mlx5", "Failed to map BAR0: {}", res);
                return Err(kernel_api::error::KapiError::IoError);
            }

            let is_vf = crate::defs::ConnectXVariant::is_vf_device_id(device_id);
            if is_vf {
                log::info!(target: "mlx5", "PCI device {:#x} recognized as Virtual Function (VF)", device_id);
            }

            let dma = match Mlx5DmaResources::allocate(&plan) {
                Ok(dma) => dma,
                Err(_) => {
                    (kernel_api().unmap_mmio)(&mmio);
                    return Err(kernel_api::error::KapiError::OutOfMemory);
                }
            };

            let mut device = Mlx5Device::new(mmio.base, mmio.size as usize, device_id);
            let allocated = dma.to_allocated_resources();

            log::info!(
                target: "mlx5",
                "CMD DMA IOVA: cmdq={:#x} in_mbox={:#x} out_mbox={:#x}",
                dma.cmdq.device_address(),
                dma.cmd_in_mbox.device_address(),
                dma.cmd_out_mbox.device_address(),
            );

            match unsafe { device.bootstrap(&config, &allocated) } {
                Ok(()) => {
                    self.state = Some(Mlx5DriverState { device, dma, mmio });
                    Ok(())
                }
                Err(err) => {
                    log::error!(target: "mlx5", "Initialization failed: {:?}", err);
                    (kernel_api().unmap_mmio)(&mmio);
                    Err(map_driver_error(err))
                }
            }
        })
    }

    fn start(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        Box::pin(async move { Ok(()) })
    }

    fn stop(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        Box::pin(async move {
            if let Some(state) = self.state.as_mut() {
                unsafe {
                    if let Err(err) = state.device.teardown_full() {
                        log::warn!(target: "mlx5", "Teardown error: {:?}", err);
                    }
                }
            }
            Ok(())
        })
    }

    fn remove(&mut self) -> DriverFuture<'_, kernel_api::error::KapiResult<()>> {
        Box::pin(async move {
            if let Some(mut state) = self.state.take() {
                unsafe {
                    let _ = state.device.teardown_full();
                }
                let _ = (kernel_api().unmap_mmio)(&state.mmio);
            }
            Ok(())
        })
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
    fn command_mailbox_allocation_size_matches_driver_mailbox_size() {
        assert_eq!(
            Mlx5DmaResources::command_mailbox_allocation_size(),
            MLX5_CMD_MBOX_SIZE
        );
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
    }

    #[test]
    fn fw_pages_use_iova_addresses() {
        let fw_pages = [
            slot(0x1000, 0x2000, 0, 0x1000),
            slot(0x3000, 0x4000, 0, 0x1000),
        ];

        assert_eq!(
            Mlx5DmaResources::device_addresses(&fw_pages),
            vec![0x2000, 0x4000]
        );
    }
}
