// ============================================================================
// kernel/src/net/drivers/mlx5_registry.rs - ConnectX Family Driver Registry
// ============================================================================

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use kernel_api::DmaBuffer;
use kernel_api::driver::{AsyncDriver, DeviceId, Driver, DriverFuture, DriverType, DriverVersion};
use kernel_api::driver_abi::DriverContext;
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::services::kernel;

use crate::io::pci::{PcieBdf, PcieError, SriovCapability, SriovController, pcie_ext_config};
use crate::sync::{PoisonLock, PoisonLockGuard};
use mlx5_driver::{
    ConnectXVariant, MELLANOX_VENDOR_ID, Mlx5AllocatedResources, Mlx5BootstrapConfig,
    Mlx5BootstrapPlan, Mlx5Device, Mlx5DmaRegion, Mlx5Error, Mlx5PciIdentity,
    Mlx5QueueDmaRegion, Mlx5QueueProfile, SUPPORTED_DEVICE_IDS,
};
const KAPI_EINVAL: i32 = -22;

type GlobalMlx5SriovState = Mlx5SriovRuntimeState<SriovController>;
type Mlx5SriovStateGuard = PoisonLockGuard<'static, Option<GlobalMlx5SriovState>>;

static MLX5_SRIOV_STATE: PoisonLock<Option<GlobalMlx5SriovState>> = PoisonLock::new(None);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mlx5SriovStatus {
    pub driver_present: bool,
    pub bridge_initialized: bool,
    pub variant: Option<ConnectXVariant>,
    pub pf_bdf: Option<PcieBdf>,
    pub sriov_supported: bool,
    pub total_vfs: u16,
    pub vf_device_id: Option<u16>,
    pub active_vfs: u16,
    pub vf_bdfs: Vec<PcieBdf>,
}

struct Mlx5SriovRuntimeState<C> {
    variant: ConnectXVariant,
    pf_bdf: PcieBdf,
    controller: Option<C>,
}

trait SriovOps {
    fn capability(&self) -> Option<&SriovCapability>;
    fn enable_vfs(&mut self, num_vfs: u16) -> Result<(), PcieError>;
    fn disable_vfs(&mut self) -> Result<(), PcieError>;
    fn active_vf_count(&self) -> u32;
    fn get_vf_bdf(&self, vf_index: u16) -> Result<PcieBdf, PcieError>;
}

impl SriovOps for SriovController {
    fn capability(&self) -> Option<&SriovCapability> {
        self.capability()
    }

    fn enable_vfs(&mut self, num_vfs: u16) -> Result<(), PcieError> {
        SriovController::enable_vfs(self, num_vfs)
    }

    fn disable_vfs(&mut self) -> Result<(), PcieError> {
        SriovController::disable_vfs(self)
    }

    fn active_vf_count(&self) -> u32 {
        SriovController::active_vf_count(self)
    }

    fn get_vf_bdf(&self, vf_index: u16) -> Result<PcieBdf, PcieError> {
        SriovController::get_vf_bdf(self, vf_index)
    }
}

fn lock_mlx5_sriov_state(context: &str) -> Mlx5SriovStateGuard {
    match MLX5_SRIOV_STATE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!(
                target: "mlx5",
                "{}: mlx5 SR-IOV state lock poisoned; continuing best-effort",
                context
            );
            poisoned.into_inner()
        }
    }
}

fn current_bridge_initialized() -> bool {
    crate::net::runtime::bridge::mlx5_bridge::is_mlx5_bridge_initialized()
}

fn map_pcie_error(err: PcieError) -> KapiError {
    match err {
        PcieError::DeviceNotFound => KapiError::NotFound,
        PcieError::CapabilityNotFound | PcieError::NotSupported => KapiError::NotSupported,
        PcieError::ResourceExhausted | PcieError::VfAllocationFailed => KapiError::ResourceExhausted,
        PcieError::ConfigError | PcieError::AerError => KapiError::IoError,
    }
}

fn map_mlx5_error(err: Mlx5Error) -> KapiError {
    match err {
        Mlx5Error::DeviceNotFound => KapiError::NotFound,
        Mlx5Error::NotSupported => KapiError::NotSupported,
        Mlx5Error::NoResources => KapiError::ResourceExhausted,
        Mlx5Error::InvalidParameter => KapiError::Internal(KAPI_EINVAL),
        _ => KapiError::IoError,
    }
}

fn collect_vf_bdfs<C: SriovOps>(controller: &C) -> Vec<PcieBdf> {
    let active_vfs = controller.active_vf_count().min(u16::MAX as u32) as u16;
    let mut vf_bdfs = Vec::with_capacity(active_vfs as usize);
    for vf in 0..active_vfs {
        if let Ok(bdf) = controller.get_vf_bdf(vf) {
            vf_bdfs.push(bdf);
        }
    }
    vf_bdfs
}

fn sriov_status_from_state<C: SriovOps>(
    state: Option<&Mlx5SriovRuntimeState<C>>,
    bridge_initialized: bool,
) -> Mlx5SriovStatus {
    let Some(state) = state else {
        return Mlx5SriovStatus {
            driver_present: false,
            bridge_initialized,
            ..Mlx5SriovStatus::default()
        };
    };

    let controller = state.controller.as_ref();
    let capability = controller.and_then(SriovOps::capability);

    Mlx5SriovStatus {
        driver_present: true,
        bridge_initialized,
        variant: Some(state.variant),
        pf_bdf: Some(state.pf_bdf),
        sriov_supported: controller.is_some(),
        total_vfs: capability.map(|cap| cap.total_vfs).unwrap_or(0),
        vf_device_id: capability.map(|cap| cap.vf_device_id),
        active_vfs: controller
            .map(|ctrl| ctrl.active_vf_count().min(u16::MAX as u32) as u16)
            .unwrap_or(0),
        vf_bdfs: controller.map(collect_vf_bdfs).unwrap_or_default(),
    }
}

fn enable_vfs_with_runtime_state<C, F>(
    state: &mut Mlx5SriovRuntimeState<C>,
    num_vfs: u16,
    bridge_initialized: bool,
    mut bridge_activate: F,
) -> KapiResult<Mlx5SriovStatus>
where
    C: SriovOps,
    F: FnMut(u16) -> KapiResult<()>,
{
    let controller = state.controller.as_mut().ok_or(KapiError::NotSupported)?;
    controller.enable_vfs(num_vfs).map_err(map_pcie_error)?;

    if let Err(err) = bridge_activate(num_vfs) {
        if let Err(rollback_err) = controller.disable_vfs() {
            log::warn!(
                target: "mlx5",
                "SR-IOV bridge activation failed and PCI rollback also failed: {:?}",
                rollback_err
            );
        }
        return Err(err);
    }

    Ok(sriov_status_from_state(Some(state), bridge_initialized))
}

fn disable_vfs_with_runtime_state<C, F>(
    state: &mut Mlx5SriovRuntimeState<C>,
    bridge_initialized: bool,
    mut bridge_deactivate: F,
) -> KapiResult<Mlx5SriovStatus>
where
    C: SriovOps,
    F: FnMut(u16) -> KapiResult<()>,
{
    let controller = state.controller.as_mut().ok_or(KapiError::NotSupported)?;
    let active_vfs = controller.active_vf_count().min(u16::MAX as u32) as u16;
    let vport_err = if active_vfs == 0 {
        None
    } else {
        bridge_deactivate(active_vfs).err()
    };
    let pci_err = controller.disable_vfs().err();

    match (vport_err, pci_err) {
        (Some(vport_err), Some(pci_err)) => {
            log::warn!(
                target: "mlx5",
                "VF vport admin-down failed and PCI VF disable also failed: {:?}",
                pci_err
            );
            Err(vport_err)
        }
        (Some(vport_err), None) => Err(vport_err),
        (None, Some(pci_err)) => Err(map_pcie_error(pci_err)),
        (None, None) => Ok(sriov_status_from_state(Some(state), bridge_initialized)),
    }
}

fn detect_sriov_runtime_state(
    variant: ConnectXVariant,
    pf_bdf: PcieBdf,
    is_pf: bool,
) -> GlobalMlx5SriovState {
    let controller = if !is_pf {
        None
    } else {
        pcie_ext_config().and_then(|config| match SriovController::new(config, pf_bdf) {
            Ok(controller) => Some(controller),
            Err(PcieError::CapabilityNotFound) | Err(PcieError::NotSupported) => None,
            Err(err) => {
                log::warn!(
                    target: "mlx5",
                    "SR-IOV capability probe failed for {:02x}:{:02x}.{}: {:?}",
                    pf_bdf.bus,
                    pf_bdf.device,
                    pf_bdf.function,
                    err
                );
                None
            }
        })
    };

    Mlx5SriovRuntimeState {
        variant,
        pf_bdf,
        controller,
    }
}

fn set_mlx5_sriov_state(state: Option<GlobalMlx5SriovState>) {
    let mut guard = lock_mlx5_sriov_state("set_mlx5_sriov_state");
    *guard = state;
}

fn clear_mlx5_sriov_state() {
    set_mlx5_sriov_state(None);
}

pub fn mlx5_sriov_status() -> Mlx5SriovStatus {
    let guard = lock_mlx5_sriov_state("mlx5_sriov_status");
    sriov_status_from_state(guard.as_ref(), current_bridge_initialized())
}

pub fn mlx5_enable_vfs(num_vfs: u16) -> KapiResult<Mlx5SriovStatus> {
    if num_vfs == 0 {
        return Err(KapiError::Internal(KAPI_EINVAL));
    }

    let bridge_initialized = current_bridge_initialized();
    let mut guard = lock_mlx5_sriov_state("mlx5_enable_vfs");
    let state = guard.as_mut().ok_or(KapiError::NotFound)?;
    enable_vfs_with_runtime_state(state, num_vfs, bridge_initialized, |count| {
        crate::net::runtime::bridge::mlx5_bridge::activate_mlx5_vfs(count)
            .map_err(map_mlx5_error)
    })
}

pub fn mlx5_disable_vfs() -> KapiResult<Mlx5SriovStatus> {
    let bridge_initialized = current_bridge_initialized();
    let mut guard = lock_mlx5_sriov_state("mlx5_disable_vfs");
    let state = guard.as_mut().ok_or(KapiError::NotFound)?;
    disable_vfs_with_runtime_state(state, bridge_initialized, |count| {
        crate::net::runtime::bridge::mlx5_bridge::deactivate_mlx5_vfs(count)
            .map_err(map_mlx5_error)
    })
}

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

    fn as_region(&self) -> Mlx5DmaRegion {
        Mlx5DmaRegion::new(self.virt_addr, self.device_addr, self.size)
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
        for page in self.fw_pages.iter_mut() {
            release_dma_slot(page);
        }

        for q in self.rq_dbs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.rqs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.sq_dbs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.sqs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.rx_cq_dbs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.rx_cqs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.tx_cq_dbs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.tx_cqs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.eqs.iter_mut() {
            release_dma_slot(q);
        }
        release_dma_slot(&mut self.cmd_out_mbox);
        release_dma_slot(&mut self.cmd_in_mbox);
        release_dma_slot(&mut self.cmdq);
    }
}

/// Async-backed mlx5 driver core.
pub struct Mlx5AsyncDriver {
    /// 初期化済みかどうか
    initialized: bool,
    /// プローブしたデバイス種別（ログ表示用）
    variant: Option<ConnectXVariant>,
    /// デバイス起動中に保持する DMA リソース
    dma_resources: Option<Mlx5DmaResources>,
    /// サポートデバイスリスト（動的構築）
    supported_devices: Vec<DeviceId>,
}

impl Mlx5AsyncDriver {
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

    fn allocate_dma_resources(
        &self,
        packed_device_id: u64,
        plan: &Mlx5BootstrapPlan,
    ) -> KapiResult<Mlx5DmaResources> {
        let profile = plan.queue_profile();

        let mut fw_pages = Vec::with_capacity(plan.fw_boot_page_count());
        for _ in 0..plan.fw_boot_page_count() {
            fw_pages.push(Self::alloc_dma_for_device(
                plan.fw_page_size(),
                packed_device_id,
                "fw_page",
            )?);
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
            eqs.push(Self::alloc_dma_for_device(plan.eq_size(), packed_device_id, "eq")?);
        }

        for _ in 0..profile.tx_queue_count {
            tx_cqs.push(Self::alloc_dma_for_device(
                plan.cq_size(),
                packed_device_id,
                "tx_cq",
            )?);
            tx_cq_dbs.push(Self::alloc_dma_for_device(
                plan.db_record_size(),
                packed_device_id,
                "tx_cq_db",
            )?);
            sqs.push(Self::alloc_dma_for_device(plan.sq_size(), packed_device_id, "sq")?);
            sq_dbs.push(Self::alloc_dma_for_device(
                plan.db_record_size(),
                packed_device_id,
                "sq_db",
            )?);
        }

        for _ in 0..profile.rx_queue_count {
            rx_cqs.push(Self::alloc_dma_for_device(
                plan.cq_size(),
                packed_device_id,
                "rx_cq",
            )?);
            rx_cq_dbs.push(Self::alloc_dma_for_device(
                plan.db_record_size(),
                packed_device_id,
                "rx_cq_db",
            )?);
            rqs.push(Self::alloc_dma_for_device(plan.rq_size(), packed_device_id, "rq")?);
            rq_dbs.push(Self::alloc_dma_for_device(
                plan.db_record_size(),
                packed_device_id,
                "rq_db",
            )?);
        }

        Ok(Mlx5DmaResources {
            cmdq: Self::alloc_dma_for_device(plan.command_queue_size(), packed_device_id, "cmdq")?,
            cmd_in_mbox: Self::alloc_dma_for_device(
                plan.command_mailbox_size(),
                packed_device_id,
                "cmd_in_mbox",
            )?,
            cmd_out_mbox: Self::alloc_dma_for_device(
                plan.command_mailbox_size(),
                packed_device_id,
                "cmd_out_mbox",
            )?,
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
                        pci_dev.bdf.bus(),
                        pci_dev.bdf.device(),
                        pci_dev.bdf.function(),
                        (msix_offset + 4) as u8,
                    );
                    let table_bir = (table_info & 0x7) as usize;
                    let table_offset = table_info & !0x7;

                    if let Some(bar) = pci_dev.bars[table_bir] {
                        if let Some(table_bar_base) =
                            ensure_bar_mapped(bar.base(), bar.size() as u64)
                        {
                            let table_base_virt = table_bar_base + table_offset as u64;
                            let entry_ptr = table_base_virt as *mut u32;

                            // Entry 0 を設定 (device.init_full で msix_vector=0 を使用するため)
                            unsafe {
                                core::ptr::write_volatile(
                                    entry_ptr.add(0),
                                    config.msi_address() as u32,
                                ); // Msg Addr Lo
                                core::ptr::write_volatile(
                                    entry_ptr.add(1),
                                    (config.msi_address() >> 32) as u32,
                                ); // Msg Addr Hi
                                core::ptr::write_volatile(entry_ptr.add(2), config.msi_data()); // Msg Data
                                core::ptr::write_volatile(entry_ptr.add(3), 0); // Vector Control (Unmask)
                            }

                            // MSI-X を有効化し、Function Mask を解除
                            let dword = crate::io::pci::pci_read(
                                pci_dev.bdf.bus(),
                                pci_dev.bdf.device(),
                                pci_dev.bdf.function(),
                                msix_offset as u8,
                            );
                            let msg_ctrl = (dword >> 16) as u16;
                            let new_msg_ctrl = (msg_ctrl | 0x8000) & !0x4000; // Enable=1, Function Mask=0
                            crate::io::pci::pci_write(
                                pci_dev.bdf.bus(),
                                pci_dev.bdf.device(),
                                pci_dev.bdf.function(),
                                msix_offset as u8,
                                (dword & 0x0000FFFF) | ((new_msg_ctrl as u32) << 16),
                            );

                            // レガシー INTx を無効化
                            let cmd = crate::io::pci::pci_read(
                                pci_dev.bdf.bus(),
                                pci_dev.bdf.device(),
                                pci_dev.bdf.function(),
                                crate::io::pci::config_regs::COMMAND as u8,
                            );
                            crate::io::pci::pci_write(
                                pci_dev.bdf.bus(),
                                pci_dev.bdf.device(),
                                pci_dev.bdf.function(),
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
                        crate::io::interrupt_manager::register_handler(
                            vec,
                            alloc::boxed::Box::new(move || {
                                crate::io::interrupt_manager::push_interrupt_event(vec);
                            }),
                        );
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

        let config = Mlx5BootstrapConfig {
            queue_profile: Mlx5QueueProfile::default(),
            mkey_params: mlx5_driver::resources::MkeyParams::default(),
            pci_identity: Mlx5PciIdentity {
                bus: pci_dev.bdf.bus(),
                device: pci_dev.bdf.device(),
                function: pci_dev.bdf.function(),
            },
            is_vf: ConnectXVariant::is_vf_device_id(pci_dev.device_id.0),
        };
        let plan = Mlx5BootstrapPlan::new(&config);

        let iommu_device_id = crate::io::iommu::types::DeviceId::new(
            pci_dev.segment,
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
        );
        let packed_device_id = Self::pack_iommu_device_id(iommu_device_id);

        let dma_resources = self.allocate_dma_resources(packed_device_id, &plan)?;
        let allocated = dma_resources.to_allocated_resources();

        let mut device = Mlx5Device::new(bar0_base, bar0_size, pci_dev.device_id.0);

        log::info!(
            target: "mlx5",
            "CMD DMA IOVA: cmdq={:#x} in_mbox={:#x} out_mbox={:#x}",
            dma_resources.cmdq.device_address(),
            dma_resources.cmd_in_mbox.device_address(),
            dma_resources.cmd_out_mbox.device_address(),
        );

        let init_result = unsafe { device.bootstrap(&config, &allocated) };
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
        set_mlx5_sriov_state(Some(detect_sriov_runtime_state(
            variant,
            PcieBdf::new(
                pci_dev.bdf.bus(),
                pci_dev.bdf.device(),
                pci_dev.bdf.function(),
            ),
            !ConnectXVariant::is_vf_device_id(pci_dev.device_id.0),
        )));

        log::info!(
            target: "mlx5",
            "{} device initialized and bridge activated",
            variant.name()
        );
        Ok(())
    }
}

impl Default for Mlx5AsyncDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncDriver for Mlx5AsyncDriver {
    fn name(&self) -> &str {
        "mlx5"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 4, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(&mut self, _ctx: &mut DriverContext) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move {
            log::info!(target: "mlx5", "Probing for ConnectX family devices...");
            clear_mlx5_sriov_state();

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
        })
    }

    fn start(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move {
            if !self.initialized {
                return Err(KapiError::Internal(-1));
            }

            let variant_name = self.variant.map(|v| v.name()).unwrap_or("ConnectX");
            log::info!(target: "mlx5", "{} driver started", variant_name);
            Ok(())
        })
    }

    fn stop(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move {
            let variant_name = self.variant.map(|v| v.name()).unwrap_or("ConnectX");
            log::info!(target: "mlx5", "{} driver stopping...", variant_name);

            if mlx5_sriov_status().active_vfs != 0 {
                if let Err(err) = mlx5_disable_vfs() {
                    log::warn!(target: "mlx5", "Failed to disable active VFs during stop: {:?}", err);
                }
            }
            clear_mlx5_sriov_state();

            if let Some(if_id) = crate::net::runtime::bridge::mlx5_bridge::mlx5_if_id() {
                crate::net::runtime::bridge::shared::remove_port(if_id);
            } else {
                crate::net::runtime::bridge::mlx5_bridge::cleanup_mlx5_bridge();
            }

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
        })
    }

    fn remove(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move { self.stop().await })
    }

    fn supported_devices(&self) -> &[DeviceId] {
        &self.supported_devices
    }
}

/// Sync DriverRegistry wrapper for the async mlx5 core.
pub struct Mlx5ConnectXDriver {
    inner: Mlx5AsyncDriver,
}

impl Mlx5ConnectXDriver {
    pub fn new() -> Self {
        Self {
            inner: Mlx5AsyncDriver::new(),
        }
    }
}

impl Default for Mlx5ConnectXDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for Mlx5ConnectXDriver {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn version(&self) -> DriverVersion {
        self.inner.version()
    }

    fn driver_type(&self) -> DriverType {
        self.inner.driver_type()
    }

    fn probe(&mut self) -> KapiResult<()> {
        let mut ctx = DriverContext::default();
        crate::task::block_on(self.inner.probe(&mut ctx))
    }

    fn start(&mut self) -> KapiResult<()> {
        crate::task::block_on(self.inner.start())
    }

    fn stop(&mut self) -> KapiResult<()> {
        crate::task::block_on(self.inner.stop())
    }

    fn remove(&mut self) -> KapiResult<()> {
        crate::task::block_on(self.inner.remove())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        self.inner.supported_devices()
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
    let mut manager =
        unsafe { crate::mm::virt::higher_half::PageTableManager::from_current_cr3(pm_offset) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::RefCell;

    struct FakeSriovController {
        capability: Option<SriovCapability>,
        active_vfs: u16,
        vf_bdfs: Vec<PcieBdf>,
        fail_enable: Option<PcieError>,
        fail_disable: Option<PcieError>,
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeSriovController {
        fn new(events: Rc<RefCell<Vec<&'static str>>>, active_vfs: u16) -> Self {
            Self {
                capability: Some(SriovCapability {
                    offset: 0x180,
                    total_vfs: 8,
                    num_vfs: active_vfs,
                    first_vf_offset: 2,
                    vf_stride: 1,
                    vf_device_id: 0x101e,
                    supported_page_sizes: 0,
                    system_page_size: 0,
                }),
                active_vfs,
                vf_bdfs: Vec::from([PcieBdf::new(0, 2, 1), PcieBdf::new(0, 2, 2)]),
                fail_enable: None,
                fail_disable: None,
                events,
            }
        }
    }

    impl SriovOps for FakeSriovController {
        fn capability(&self) -> Option<&SriovCapability> {
            self.capability.as_ref()
        }

        fn enable_vfs(&mut self, num_vfs: u16) -> Result<(), PcieError> {
            self.events.borrow_mut().push("enable");
            if let Some(err) = self.fail_enable {
                return Err(err);
            }
            self.active_vfs = num_vfs;
            if let Some(cap) = self.capability.as_mut() {
                cap.num_vfs = num_vfs;
            }
            Ok(())
        }

        fn disable_vfs(&mut self) -> Result<(), PcieError> {
            self.events.borrow_mut().push("disable");
            if let Some(err) = self.fail_disable {
                return Err(err);
            }
            self.active_vfs = 0;
            if let Some(cap) = self.capability.as_mut() {
                cap.num_vfs = 0;
            }
            Ok(())
        }

        fn active_vf_count(&self) -> u32 {
            self.active_vfs as u32
        }

        fn get_vf_bdf(&self, vf_index: u16) -> Result<PcieBdf, PcieError> {
            self.vf_bdfs
                .get(vf_index as usize)
                .copied()
                .ok_or(PcieError::VfAllocationFailed)
        }
    }

    #[test_case]
    fn sriov_status_snapshot_includes_active_vf_bdfs() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let state = Mlx5SriovRuntimeState {
            variant: ConnectXVariant::CX5,
            pf_bdf: PcieBdf::new(0, 2, 0),
            controller: Some(FakeSriovController::new(events, 2)),
        };

        let status = sriov_status_from_state(Some(&state), true);
        assert!(status.driver_present);
        assert!(status.bridge_initialized);
        assert_eq!(status.variant, Some(ConnectXVariant::CX5));
        assert_eq!(status.pf_bdf, Some(PcieBdf::new(0, 2, 0)));
        assert!(status.sriov_supported);
        assert_eq!(status.total_vfs, 8);
        assert_eq!(status.vf_device_id, Some(0x101e));
        assert_eq!(status.active_vfs, 2);
        assert_eq!(
            status.vf_bdfs,
            Vec::from([PcieBdf::new(0, 2, 1), PcieBdf::new(0, 2, 2)])
        );
    }

    #[test_case]
    fn enable_vfs_rolls_back_when_bridge_sync_fails() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut state = Mlx5SriovRuntimeState {
            variant: ConnectXVariant::CX5,
            pf_bdf: PcieBdf::new(0, 2, 0),
            controller: Some(FakeSriovController::new(events.clone(), 0)),
        };

        let err = enable_vfs_with_runtime_state(&mut state, 2, true, |count| {
            assert_eq!(count, 2);
            events.borrow_mut().push("bridge_activate");
            Err(KapiError::IoError)
        })
        .unwrap_err();

        assert_eq!(err, KapiError::IoError);
        assert_eq!(
            events.borrow().as_slice(),
            ["enable", "bridge_activate", "disable"]
        );
        assert_eq!(
            state
                .controller
                .as_ref()
                .map(SriovOps::active_vf_count)
                .unwrap_or_default(),
            0
        );
    }

    #[test_case]
    fn disable_vfs_still_disables_pci_when_admin_down_fails() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut state = Mlx5SriovRuntimeState {
            variant: ConnectXVariant::CX5,
            pf_bdf: PcieBdf::new(0, 2, 0),
            controller: Some(FakeSriovController::new(events.clone(), 2)),
        };

        let err = disable_vfs_with_runtime_state(&mut state, true, |count| {
            assert_eq!(count, 2);
            events.borrow_mut().push("bridge_deactivate");
            Err(KapiError::IoError)
        })
        .unwrap_err();

        assert_eq!(err, KapiError::IoError);
        assert_eq!(events.borrow().as_slice(), ["bridge_deactivate", "disable"]);
        assert_eq!(
            state
                .controller
                .as_ref()
                .map(SriovOps::active_vf_count)
                .unwrap_or_default(),
            0
        );
    }
}
