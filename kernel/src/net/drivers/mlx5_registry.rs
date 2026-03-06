// ============================================================================
// kernel/src/net/drivers/mlx5_registry.rs - ConnectX Family Driver Registry
// ============================================================================

extern crate alloc;

use alloc::vec::Vec;
use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::services::kernel;
use kernel_api::DmaBuffer;

use mlx5_driver::defs::{MLX5_CQ_DEPTH, MLX5_EQ_DEPTH, MLX5_PAGE_SIZE, MLX5_WQ_DEPTH};
use mlx5_driver::regs::{cmd_entry, cqe, eqe, wqe};
use mlx5_driver::resources::MkeyParams;
use mlx5_driver::{ConnectXVariant, MELLANOX_VENDOR_ID, Mlx5Device, SUPPORTED_DEVICE_IDS};

const CMD_LOG_SIZE: u8 = 2; // 4 entries
const DMA_PAGE_BYTES: usize = MLX5_PAGE_SIZE;
const FW_BOOT_PAGE_COUNT: usize = 4;
const MLX5_EQ_SPARE_EQE: u32 = 0x80;

/// ConnectX ファミリのサポートデバイスID一覧を動的構築
fn build_supported_devices() -> Vec<DeviceId> {
    SUPPORTED_DEVICE_IDS
        .iter()
        .map(|&(vendor, device)| DeviceId {
            vendor,
            device,
            subsystem_vendor: None,
            subsystem_device: None,
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Default)]
struct DmaSlot {
    phys_addr: u64,
    device_addr: u64,
    virt_addr: u64,
    size: usize,
}

impl DmaSlot {
    fn from_dma_buffer(buffer: DmaBuffer) -> Self {
        Self {
            phys_addr: buffer.physical_address(),
            device_addr: buffer.device_address(),
            virt_addr: buffer.as_ptr() as u64,
            size: buffer.size(),
        }
    }

    fn as_ptr_u64(&self) -> u64 {
        self.virt_addr
    }

    fn phys_address(&self) -> u64 {
        self.phys_addr
    }

    fn device_address(&self) -> u64 {
        self.device_addr
    }

    fn into_dma_buffer(self) -> DmaBuffer {
        DmaBuffer::new_with_device_addr(
            self.phys_addr,
            self.device_addr,
            self.virt_addr as *mut u8,
            self.size,
        )
    }
}

fn release_dma_slot(slot: &mut DmaSlot) {
    if slot.size == 0 {
        return;
    }

    let owned = core::mem::take(slot);
    if owned.size != 0 {
        kernel().free_dma(owned.into_dma_buffer());
    }
}

/// mlx5 初期化中に確保する DMA リソース一式。
///
/// ドライバのライフタイム中は保持し、Drop 時に一括で解放する。
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
    fn fw_page_device_addrs(&self) -> Vec<u64> {
        self.fw_pages.iter().map(DmaSlot::device_address).collect()
    }
}

impl Drop for Mlx5DmaResources {
    fn drop(&mut self) {
        for page in self.fw_pages.iter_mut() {
            release_dma_slot(page);
        }

        for q in self.rq_dbs.iter_mut() { release_dma_slot(q); }
        for q in self.rqs.iter_mut() { release_dma_slot(q); }
        for q in self.sq_dbs.iter_mut() { release_dma_slot(q); }
        for q in self.sqs.iter_mut() { release_dma_slot(q); }
        for q in self.rx_cq_dbs.iter_mut() { release_dma_slot(q); }
        for q in self.rx_cqs.iter_mut() { release_dma_slot(q); }
        for q in self.tx_cq_dbs.iter_mut() { release_dma_slot(q); }
        for q in self.tx_cqs.iter_mut() { release_dma_slot(q); }
        for q in self.eqs.iter_mut() { release_dma_slot(q); }
        release_dma_slot(&mut self.cmd_out_mbox);
        release_dma_slot(&mut self.cmd_in_mbox);
        release_dma_slot(&mut self.cmdq);
    }
}

/// ConnectX ファミリドライバラッパー for DriverRegistry
pub struct Mlx5ConnectXDriver {
    /// 初期化済みかどうか
    initialized: bool,
    /// プローブしたデバイス種別（ログ表示用）
    variant: Option<ConnectXVariant>,
    /// デバイス起動中に保持する DMA リソース
    dma_resources: Option<Mlx5DmaResources>,
    /// サポートデバイスリスト（動的構築）
    supported_devices: Vec<DeviceId>,
}

impl Mlx5ConnectXDriver {
    /// 新しいドライバインスタンスを作成
    pub fn new() -> Self {
        Self {
            initialized: false,
            variant: None,
            dma_resources: None,
            supported_devices: build_supported_devices(),
        }
    }

    fn pack_iommu_device_id(device: crate::io::iommu::types::DeviceId) -> u64 {
        ((device.segment as u64) << 32)
            | ((device.bus as u64) << 16)
            | ((device.device as u64) << 8)
            | (device.function as u64)
    }

    fn alloc_dma_for_device(
        size: usize,
        packed_device_id: u64,
        label: &'static str,
    ) -> KapiResult<DmaSlot> {
        kernel()
            .alloc_dma_for_device(size, packed_device_id)
            .map(DmaSlot::from_dma_buffer)
            .map_err(|e| {
                log::error!(
                    target: "mlx5",
                    "DMA allocation failed: {} size={} err={:?}",
                    label,
                    size,
                    e
                );
                KapiError::OutOfMemory
            })
    }

    fn allocate_dma_resources(&self, packed_device_id: u64) -> KapiResult<Mlx5DmaResources> {
        let cmdq_size = DMA_PAGE_BYTES.max((1usize << CMD_LOG_SIZE) * cmd_entry::ENTRY_SIZE);
        let cmd_mbox_size = DMA_PAGE_BYTES;

        let eq_target_depth = MLX5_EQ_DEPTH.saturating_add(MLX5_EQ_SPARE_EQE);
        let eq_log_size = log2_ceil_u32(eq_target_depth);
        let eq_alloc_depth = 1u32 << eq_log_size;
        let eq_size = (eq_alloc_depth as usize) * eqe::EQE_SIZE;
        let cq_size = (MLX5_CQ_DEPTH as usize) * cqe::SIZE;
        // SQ WQ stride is 64 bytes (log_wq_stride=6) in CREATE_SQ.
        let sq_size = (MLX5_WQ_DEPTH as usize) * 64;
        let rq_size = (MLX5_WQ_DEPTH as usize) * wqe::WQEBB_SIZE;
        let db_record_size = DMA_PAGE_BYTES;

        let num_queues = 4;

        let mut fw_pages = Vec::with_capacity(FW_BOOT_PAGE_COUNT);
        for _ in 0..FW_BOOT_PAGE_COUNT {
            fw_pages.push(Self::alloc_dma_for_device(
                DMA_PAGE_BYTES,
                packed_device_id,
                "fw_page",
            )?);
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
            eqs.push(Self::alloc_dma_for_device(eq_size, packed_device_id, "eq")?);
            tx_cqs.push(Self::alloc_dma_for_device(cq_size, packed_device_id, "tx_cq")?);
            tx_cq_dbs.push(Self::alloc_dma_for_device(db_record_size, packed_device_id, "tx_cq_db")?);
            rx_cqs.push(Self::alloc_dma_for_device(cq_size, packed_device_id, "rx_cq")?);
            rx_cq_dbs.push(Self::alloc_dma_for_device(db_record_size, packed_device_id, "rx_cq_db")?);
            sqs.push(Self::alloc_dma_for_device(sq_size, packed_device_id, "sq")?);
            sq_dbs.push(Self::alloc_dma_for_device(db_record_size, packed_device_id, "sq_db")?);
            rqs.push(Self::alloc_dma_for_device(rq_size, packed_device_id, "rq")?);
            rq_dbs.push(Self::alloc_dma_for_device(db_record_size, packed_device_id, "rq_db")?);
        }

        Ok(Mlx5DmaResources {
            cmdq: Self::alloc_dma_for_device(cmdq_size, packed_device_id, "cmdq")?,
            cmd_in_mbox: Self::alloc_dma_for_device(cmd_mbox_size, packed_device_id, "cmd_in_mbox")?,
            cmd_out_mbox: Self::alloc_dma_for_device(cmd_mbox_size, packed_device_id, "cmd_out_mbox")?,
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

    /// PCI デバイスの完全な初期化を行う
    fn probe_device(&mut self, pci_dev: &crate::io::pci::PciDeviceInfo) -> KapiResult<()> {
        let variant = ConnectXVariant::from_device_id(pci_dev.device_id.0);
        log::info!(
            target: "mlx5",
            "Initializing {} at {:02x}:{:02x}.{} (vendor={:#06x} device={:#06x})",
            variant.name(),
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
            pci_dev.vendor_id.0,
            pci_dev.device_id.0,
        );

        // BAR0 取得
        let bar0 = pci_dev.bars[0].ok_or_else(|| {
            log::error!(target: "mlx5", "BAR0 not found");
            KapiError::IoError
        })?;

        let bar0_phys = bar0.base();
        let bar0_size_u64 = bar0.size();
        let bar0_size = bar0_size_u64 as usize;

        if bar0_phys == 0 || bar0_size == 0 {
            log::error!(
                target: "mlx5",
                "BAR0 invalid: phys={:#x} size={:#x}",
                bar0_phys,
                bar0_size
            );
            return Err(KapiError::IoError);
        }

        let bar0_base = ensure_bar_mapped(bar0_phys, bar0_size_u64).ok_or_else(|| {
            log::error!(
                target: "mlx5",
                "BAR0 mapping failed: phys={:#x} size={:#x}",
                bar0_phys,
                bar0_size
            );
            KapiError::IoError
        })?;

        log::info!(
            target: "mlx5",
            "BAR0: phys={:#x} virt={:#x} size={:#x} ({}KB)",
            bar0_phys,
            bar0_base,
            bar0_size,
            bar0_size / 1024
        );

        // バスマスタを有効化（DMA用）
        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();

        if let Some(msix_offset) = pci_dev.msix_cap_offset {
            log::info!(target: "mlx5", "MSI-X capability at offset {:#x}", msix_offset);
            
            // 必要なベクタ数を見積もる (EQの数など)
            let requested_vectors = 1;
            
            if let Ok(allocs) = crate::io::interrupt_manager::allocate_msix(
                pci_dev.bdf.to_u16() as u32,
                requested_vectors,
                "mlx5_event_queue",
                Some(0), // Target BSP
            ) {
                if !allocs.is_empty() {
                    let msix_vectors = allocs;
                    let base_vector = msix_vectors[0].vector;
                    log::info!(target: "mlx5", "Allocated MSI-X base vector: {}", base_vector);
                    
                    let config = &msix_vectors[0].config;
                    
                    // MSI-X テーブルの情報取得とマッピング
                    let table_info = crate::io::pci::pci_read(
                        pci_dev.bdf.bus(), pci_dev.bdf.device(), pci_dev.bdf.function(), (msix_offset + 4) as u8
                    );
                    let table_bir = (table_info & 0x7) as usize;
                    let table_offset = table_info & !0x7;
                    
                    if let Some(bar) = pci_dev.bars[table_bir] {
                        if let Some(table_bar_base) = ensure_bar_mapped(bar.base(), bar.size() as u64) {
                            let table_base_virt = table_bar_base + table_offset as u64;
                            let entry_ptr = table_base_virt as *mut u32;
                            
                            // Entry 0 を設定 (device.init_full で msix_vector=0 を使用するため)
                            unsafe {
                                core::ptr::write_volatile(entry_ptr.add(0), config.msi_address() as u32); // Msg Addr Lo
                                core::ptr::write_volatile(entry_ptr.add(1), (config.msi_address() >> 32) as u32); // Msg Addr Hi
                                core::ptr::write_volatile(entry_ptr.add(2), config.msi_data()); // Msg Data
                                core::ptr::write_volatile(entry_ptr.add(3), 0); // Vector Control (Unmask)
                            }
                            
                            // MSI-X を有効化し、Function Mask を解除
                            let dword = crate::io::pci::pci_read(
                                pci_dev.bdf.bus(), pci_dev.bdf.device(), pci_dev.bdf.function(), msix_offset as u8
                            );
                            let msg_ctrl = (dword >> 16) as u16;
                            let new_msg_ctrl = (msg_ctrl | 0x8000) & !0x4000; // Enable=1, Function Mask=0
                            crate::io::pci::pci_write(
                                pci_dev.bdf.bus(), pci_dev.bdf.device(), pci_dev.bdf.function(),
                                msix_offset as u8,
                                (dword & 0x0000FFFF) | ((new_msg_ctrl as u32) << 16)
                            );
                            
                            // レガシー INTx を無効化
                            let cmd = crate::io::pci::pci_read(
                                pci_dev.bdf.bus(), pci_dev.bdf.device(), pci_dev.bdf.function(), crate::io::pci::config_regs::COMMAND as u8
                            );
                            crate::io::pci::pci_write(
                                pci_dev.bdf.bus(), pci_dev.bdf.device(), pci_dev.bdf.function(),
                                crate::io::pci::config_regs::COMMAND as u8,
                                cmd | (crate::io::pci::command_bits::INTERRUPT_DISABLE as u32),
                            );
                        } else {
                            log::warn!(target: "mlx5", "Failed to map MSI-X table BAR");
                        }
                    }
                    
                    // ハンドラを登録（Interrupt-Waker Bridge連携）
                    for alloc in &msix_vectors {
                        let vec = alloc.vector;
                        crate::io::interrupt_manager::register_handler(vec, alloc::boxed::Box::new(move || {
                            crate::io::interrupt_manager::push_interrupt_event(vec);
                        }));
                    }
                } else {
                    log::warn!(target: "mlx5", "MSI-X allocation returned empty, falling back to polling");
                }
            } else {
                log::warn!(target: "mlx5", "Failed to allocate MSI-X vectors, falling back to polling");
            }
        } else {
            log::warn!(target: "mlx5", "MSI-X not available; using polling mode");
        }

        let iommu_device_id = crate::io::iommu::types::DeviceId::new(
            pci_dev.segment,
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
        );
        let packed_device_id = Self::pack_iommu_device_id(iommu_device_id);

        let dma_resources = self.allocate_dma_resources(packed_device_id)?;
        let fw_page_addrs = dma_resources.fw_page_device_addrs();

        let mut device = Mlx5Device::new(bar0_base, bar0_size, pci_dev.device_id.0);
        device.set_pci_bdf(
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
        );

        let eq_log_size = log2_ceil_u32(MLX5_EQ_DEPTH.saturating_add(MLX5_EQ_SPARE_EQE));
        let cq_log_size = log2_u32(MLX5_CQ_DEPTH);
        let sq_log_size = log2_u32(MLX5_WQ_DEPTH);
        let rq_log_size = log2_u32(MLX5_WQ_DEPTH);

        let eq_bufs: Vec<(u64, u64)> = dma_resources.eqs.iter().map(|q| (q.as_ptr_u64(), q.device_address())).collect();
        let tx_cq_bufs: Vec<(u64, u64, u64, u64)> = dma_resources.tx_cqs.iter().zip(dma_resources.tx_cq_dbs.iter())
            .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();
        let rx_cq_bufs: Vec<(u64, u64, u64, u64)> = dma_resources.rx_cqs.iter().zip(dma_resources.rx_cq_dbs.iter())
            .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();
        let sq_bufs: Vec<(u64, u64, u64, u64)> = dma_resources.sqs.iter().zip(dma_resources.sq_dbs.iter())
            .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();
        let rq_bufs: Vec<(u64, u64, u64, u64)> = dma_resources.rqs.iter().zip(dma_resources.rq_dbs.iter())
            .map(|(q, db)| (q.as_ptr_u64(), q.device_address(), db.as_ptr_u64(), db.device_address())).collect();

        log::info!(
            target: "mlx5",
            "CMD DMA IOVA: cmdq={:#x} in_mbox={:#x} out_mbox={:#x}",
            dma_resources.cmdq.device_address(),
            dma_resources.cmd_in_mbox.device_address(),
            dma_resources.cmd_out_mbox.device_address(),
        );

        let init_result = unsafe {
            device.init_multi_queue(
                dma_resources.cmdq.as_ptr_u64(),
                dma_resources.cmdq.device_address(),
                dma_resources.cmd_in_mbox.as_ptr_u64(),
                dma_resources.cmd_in_mbox.device_address(),
                dma_resources.cmd_out_mbox.as_ptr_u64(),
                dma_resources.cmd_out_mbox.device_address(),
                &fw_page_addrs,
                &MkeyParams::default(),
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
        if let Err(e) = init_result {
            log::error!(target: "mlx5", "Full init failed: {:?}", e);
            log::warn!(
                target: "mlx5",
                "Keeping mlx5 DMA mappings pinned after init failure to avoid unstable IOMMU unmap path"
            );
            core::mem::forget(dma_resources);
            return Err(KapiError::IoError);
        }

        crate::net::runtime::bridge::mlx5_bridge::register_mlx5_device(device);
        if let Err(e) = crate::net::runtime::bridge::mlx5_bridge::init_mlx5_bridge() {
            log::error!(target: "mlx5", "Bridge initialization failed: {}", e);

            if let Some(mut dev) = crate::net::runtime::bridge::mlx5_bridge::take_mlx5_device() {
                unsafe {
                    if let Err(teardown_err) = dev.teardown() {
                        log::warn!(target: "mlx5", "Teardown after bridge failure failed: {:?}", teardown_err);
                    }
                }
            }

            return Err(KapiError::IoError);
        }

        self.variant = Some(variant);
        self.dma_resources = Some(dma_resources);
        self.initialized = true;

        log::info!(
            target: "mlx5",
            "{} device initialized and bridge activated",
            variant.name()
        );
        Ok(())
    }
}

impl Default for Mlx5ConnectXDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for Mlx5ConnectXDriver {
    fn name(&self) -> &str {
        "mlx5"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 4, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "mlx5", "Probing for ConnectX family devices...");

        for &(_vendor_id, device_id) in SUPPORTED_DEVICE_IDS {
            let pci_devices = crate::io::pci::find_by_id(MELLANOX_VENDOR_ID, device_id);
            if let Some(first) = pci_devices.first() {
                let variant = ConnectXVariant::from_device_id(device_id);
                log::info!(
                    target: "mlx5",
                    "Found {} (device_id={:#06x})",
                    variant.name(),
                    device_id,
                );
                return self.probe_device(first);
            }
        }

        log::info!(target: "mlx5", "No ConnectX family devices found on PCI bus");
        Err(KapiError::NotFound)
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }

        let variant_name = self.variant.map(|v| v.name()).unwrap_or("ConnectX");
        log::info!(target: "mlx5", "{} driver started", variant_name);
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        let variant_name = self.variant.map(|v| v.name()).unwrap_or("ConnectX");
        log::info!(target: "mlx5", "{} driver stopping...", variant_name);

        // ブリッジ側のリソース（PacketRef等）を解放
        crate::net::runtime::bridge::mlx5_bridge::cleanup_mlx5_bridge();

        if let Some(mut dev) = crate::net::runtime::bridge::mlx5_bridge::take_mlx5_device() {
            unsafe {
                if let Err(e) = dev.teardown() {
                    log::warn!(target: "mlx5", "Teardown error: {:?}", e);
                }
            }
        }

        self.dma_resources = None;
        self.variant = None;
        self.initialized = false;
        log::info!(target: "mlx5", "{} driver stopped", variant_name);
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        &self.supported_devices
    }
}

/// log2 の整数計算（キュー深度からログサイズを得る）
fn log2_u32(val: u32) -> u8 {
    if val == 0 {
        return 0;
    }
    31 - val.leading_zeros() as u8
}

fn log2_ceil_u32(val: u32) -> u8 {
    if val <= 1 {
        return 0;
    }
    32 - (val - 1).leading_zeros() as u8
}

fn ensure_bar_mapped(base_phys: u64, bar_size: u64) -> Option<u64> {
    if base_phys == 0 || bar_size == 0 {
        return None;
    }

    let base_virt = crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(base_phys)).as_u64();
    let page_size = 0x1000u64;
    let map_size = crate::util::align_up_u64(bar_size, page_size);
    let virt_start = crate::mm::virt::higher_half::VirtAddr::new(base_virt);
    let phys_start = crate::mm::virt::higher_half::PhysAddr::new(base_phys);

    if let Some(pte) = crate::mm::virt::higher_half::get_current_pte(virt_start) {
        if pte.is_present() && pte.phys_addr() == phys_start {
            return Some(base_virt);
        }
    }

    let pm_offset = crate::mm::virt::higher_half::physical_memory_offset();
    let mut manager = unsafe { crate::mm::virt::higher_half::PageTableManager::from_current_cr3(pm_offset) };
    let flags = crate::mm::virt::higher_half::PageFlags::write_combining();
    match unsafe { manager.map_range(virt_start, phys_start, map_size, flags) } {
        Ok(()) | Err(crate::mm::virt::higher_half::MapError::AlreadyMapped) => Some(base_virt),
        Err(err) => {
            log::error!(
                target: "mlx5",
                "BAR mapping failed: phys={:#x} size={:#x} err={:?}",
                base_phys,
                bar_size,
                err
            );
            None
        }
    }
}
