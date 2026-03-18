// ============================================================================
// kernel/src/net/drivers/mlx5_registry.rs - ConnectX Family Driver Registry
// ============================================================================

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use kernel_api::abi::driver::{DriverContext, PackedPciLocation};
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::driver::{AsyncDriver, DeviceId, Driver, DriverFuture, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::service::kernel::instance as kernel;
pub use mlx5_driver::{MELLANOX_VENDOR_ID, SUPPORTED_DEVICE_IDS};

type DmaBuffer = DmaSlice<CpuOwned>;

use crate::drivers::pci::{PcieBdf, PcieError, SriovCapability, SriovController, pcie_ext_config};
use crate::sync::{PoisonLock, PoisonLockGuard};
use mlx5_driver::{
    ConnectXVariant, Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan, Mlx5Device,
    Mlx5DmaRegion, Mlx5Error, Mlx5PciIdentity, Mlx5QueueDmaRegion, Mlx5QueueProfile,
};
const KAPI_EINVAL: i32 = -22;

type GlobalMlx5SriovState = Mlx5SriovRuntimeState<SriovController>;
type Mlx5SriovStateGuard = PoisonLockGuard<'static, Option<GlobalMlx5SriovState>>;

static MLX5_SRIOV_STATE: PoisonLock<Option<GlobalMlx5SriovState>> = PoisonLock::new(None);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mlx5SriovStatus {
    pub driver_present: bool,
    pub port_runtime_initialized: bool,
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

fn current_port_runtime_initialized() -> bool {
    crate::net::runtime::device::list_port_keys(Some(
        kernel_api::service::netdev::NetPortKind::Mlx5,
    ))
    .into_iter()
    .next()
    .is_some()
}

fn map_pcie_error(err: PcieError) -> KapiError {
    match err {
        PcieError::DeviceNotFound => KapiError::NotFound,
        PcieError::CapabilityNotFound | PcieError::NotSupported => KapiError::NotSupported,
        PcieError::ResourceExhausted | PcieError::VfAllocationFailed => {
            KapiError::ResourceExhausted
        }
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
    port_runtime_initialized: bool,
) -> Mlx5SriovStatus {
    let Some(state) = state else {
        return Mlx5SriovStatus {
            driver_present: false,
            port_runtime_initialized,
            ..Mlx5SriovStatus::default()
        };
    };

    let controller = state.controller.as_ref();
    let capability = controller.and_then(SriovOps::capability);

    Mlx5SriovStatus {
        driver_present: true,
        port_runtime_initialized,
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
    port_runtime_initialized: bool,
    mut activate_vports: F,
) -> KapiResult<Mlx5SriovStatus>
where
    C: SriovOps,
    F: FnMut(u16) -> KapiResult<()>,
{
    let controller = state.controller.as_mut().ok_or(KapiError::NotSupported)?;
    controller.enable_vfs(num_vfs).map_err(map_pcie_error)?;

    if let Err(err) = activate_vports(num_vfs) {
        if let Err(rollback_err) = controller.disable_vfs() {
            log::warn!(
                target: "mlx5",
                "SR-IOV vport activation failed and PCI rollback also failed: {:?}",
                rollback_err
            );
        }
        return Err(err);
    }

    Ok(sriov_status_from_state(
        Some(state),
        port_runtime_initialized,
    ))
}

fn disable_vfs_with_runtime_state<C, F>(
    state: &mut Mlx5SriovRuntimeState<C>,
    port_runtime_initialized: bool,
    mut deactivate_vports: F,
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
        deactivate_vports(active_vfs).err()
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
        (None, None) => Ok(sriov_status_from_state(
            Some(state),
            port_runtime_initialized,
        )),
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
    sriov_status_from_state(guard.as_ref(), current_port_runtime_initialized())
}

pub fn mlx5_enable_vfs(num_vfs: u16) -> KapiResult<Mlx5SriovStatus> {
    if num_vfs == 0 {
        return Err(KapiError::Internal(KAPI_EINVAL));
    }

    let port_runtime_initialized = current_port_runtime_initialized();
    let mut guard = lock_mlx5_sriov_state("mlx5_enable_vfs");
    let state = guard.as_mut().ok_or(KapiError::NotFound)?;
    enable_vfs_with_runtime_state(state, num_vfs, port_runtime_initialized, |count| {
        crate::net::runtime::bridge::mlx5_bridge::activate_mlx5_vfs(count).map_err(map_mlx5_error)
    })
}

pub fn mlx5_disable_vfs() -> KapiResult<Mlx5SriovStatus> {
    let port_runtime_initialized = current_port_runtime_initialized();
    let mut guard = lock_mlx5_sriov_state("mlx5_disable_vfs");
    let state = guard.as_mut().ok_or(KapiError::NotFound)?;
    disable_vfs_with_runtime_state(state, port_runtime_initialized, |count| {
        crate::net::runtime::bridge::mlx5_bridge::deactivate_mlx5_vfs(count).map_err(map_mlx5_error)
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
struct DmaRegion {
    phys_addr: u64,
    device_addr: u64,
    virt_addr: u64,
    size: usize,
}

struct DmaSlot {
    region: DmaRegion,
    owned: Option<DmaBuffer>,
}

// SAFETY: Shared reads only expose the copied `region` metadata. The owned DMA
// buffer is kept private and is only consumed during teardown via `&mut self`,
// so `DmaSlot` never shares mutable access to DMA memory across threads.
unsafe impl Sync for DmaSlot {}

impl DmaSlot {
    fn from_dma_buffer(buffer: DmaBuffer) -> Self {
        Self {
            region: DmaRegion {
                phys_addr: buffer.device_address(),
                device_addr: buffer.device_address(),
                virt_addr: buffer.as_ptr() as u64,
                size: buffer.size(),
            },
            owned: Some(buffer),
        }
    }

    fn as_ptr_u64(&self) -> u64 {
        self.region.virt_addr
    }

    fn phys_address(&self) -> u64 {
        self.region.phys_addr
    }

    fn device_address(&self) -> u64 {
        self.region.device_addr
    }

    fn as_region(&self) -> Mlx5DmaRegion {
        Mlx5DmaRegion::new(
            self.region.virt_addr,
            self.region.device_addr,
            self.region.size,
        )
    }

    fn subregion(&self, offset: usize, size: usize) -> Self {
        debug_assert!(offset <= self.region.size);
        debug_assert!(size <= self.region.size.saturating_sub(offset));
        Self {
            region: DmaRegion {
                phys_addr: self.region.phys_addr + offset as u64,
                device_addr: self.region.device_addr + offset as u64,
                virt_addr: self.region.virt_addr + offset as u64,
                size,
            },
            owned: None,
        }
    }
}

fn release_dma_slot(slot: &mut DmaSlot) {
    let _ = slot.owned.take();
}

/// mlx5 初期化中に確保する DMA リソース一式。
///
/// ドライバのライフタイム中は保持し、Drop 時に一括で解放する。
struct Mlx5DmaResources {
    cmdq: DmaSlot,
    cmd_in_mbox: DmaSlot,
    cmd_out_mbox: DmaSlot,
    fw_page_chunks: Vec<DmaSlot>,
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
        for page in self.fw_pages.iter_mut() {
            release_dma_slot(page);
        }
        for chunk in self.fw_page_chunks.iter_mut() {
            release_dma_slot(chunk);
        }

        for q in self.rq_dbs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.rqs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.rmp_dbs.iter_mut() {
            release_dma_slot(q);
        }
        for q in self.rmps.iter_mut() {
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
    /// ログ表示用の代表デバイス種別
    variant: Option<ConnectXVariant>,
    /// 起動済み mlx5 PF 群
    devices: Vec<Mlx5RegisteredDevice>,
    /// サポートデバイスリスト（動的構築）
    supported_devices: Vec<DeviceId>,
}

struct Mlx5RegisteredDevice {
    index: u8,
    variant: ConnectXVariant,
    pci_locator: PackedPciLocation,
    dma_resources: Mlx5DmaResources,
}

struct Mlx5MsixGuard {
    locator: PackedPciLocation,
    armed: bool,
}

impl Mlx5MsixGuard {
    fn new(locator: PackedPciLocation) -> Self {
        Self {
            locator,
            armed: false,
        }
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Mlx5MsixGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = kernel().disable_msix(self.locator);
        }
    }
}

impl Mlx5AsyncDriver {
    /// 新しいドライバインスタンスを作成
    pub fn new() -> Self {
        Self {
            initialized: false,
            variant: None,
            devices: Vec::new(),
            supported_devices: build_supported_devices(),
        }
    }

    fn discover_pci_devices() -> Vec<(ConnectXVariant, crate::drivers::pci::PciDeviceInfo)> {
        let mut devices = alloc::collections::BTreeMap::<
            (u16, u8, u8, u8),
            (ConnectXVariant, crate::drivers::pci::PciDeviceInfo),
        >::new();
        for &(_vendor_id, device_id) in SUPPORTED_DEVICE_IDS {
            let variant = ConnectXVariant::from_device_id(device_id);
            for pci_device in crate::drivers::pci::find_by_id(MELLANOX_VENDOR_ID, device_id) {
                let key = (
                    pci_device.segment,
                    pci_device.bdf.bus(),
                    pci_device.bdf.device(),
                    pci_device.bdf.function(),
                );
                devices.entry(key).or_insert((variant, pci_device));
            }
        }
        devices.into_values().collect()
    }

    fn pack_iommu_device_id(device: crate::io::iommu::types::DeviceId) -> PackedPciLocation {
        PackedPciLocation::new(device.segment, device.bus, device.device, device.function)
    }

    fn alloc_dma_for_device(
        size: usize,
        packed_device_id: PackedPciLocation,
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
        packed_device_id: PackedPciLocation,
        plan: &Mlx5BootstrapPlan,
        _is_vf: bool,
    ) -> KapiResult<Mlx5DmaResources> {
        const FW_PAGES_PER_CHUNK: usize = 1;

        let profile = plan.queue_profile();

        // Keep the bootstrap pool small and let the driver grow it on demand
        // once QUERY_PAGES reports the actual PF requirement.
        let fw_boot_pages = plan.fw_boot_page_count().max(16);
        let fw_page_size = plan.fw_page_size();
        let mut fw_page_chunks = Vec::with_capacity(fw_boot_pages.div_ceil(FW_PAGES_PER_CHUNK));
        let mut fw_pages = Vec::with_capacity(fw_boot_pages);
        let mut remaining_fw_pages = fw_boot_pages;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while remaining_fw_pages > 0 {
            let pages_in_chunk = remaining_fw_pages.min(FW_PAGES_PER_CHUNK);
            let chunk_size = fw_page_size * pages_in_chunk;
            let chunk = Self::alloc_dma_for_device(chunk_size, packed_device_id, "fw_page_chunk")?;
            for page_idx in 0..pages_in_chunk {
                fw_pages.push(chunk.subregion(page_idx * fw_page_size, fw_page_size));
            }
            fw_page_chunks.push(chunk);
            remaining_fw_pages -= pages_in_chunk;
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
            eqs.push(Self::alloc_dma_for_device(
                plan.eq_size(),
                packed_device_id,
                "eq",
            )?);
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
            sqs.push(Self::alloc_dma_for_device(
                plan.sq_size(),
                packed_device_id,
                "sq",
            )?);
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
            rqs.push(Self::alloc_dma_for_device(
                plan.rq_size(),
                packed_device_id,
                "rq",
            )?);
            rq_dbs.push(Self::alloc_dma_for_device(
                plan.db_record_size(),
                packed_device_id,
                "rq_db",
            )?);
            rmps.push(Self::alloc_dma_for_device(
                plan.rmp_size(),
                packed_device_id,
                "rmp",
            )?);
            rmp_dbs.push(Self::alloc_dma_for_device(
                plan.db_record_size(),
                packed_device_id,
                "rmp_db",
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
            fw_page_chunks,
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

    /// PCI デバイスの完全な初期化を行う
    fn probe_device(
        &mut self,
        index: u8,
        pci_dev: &crate::drivers::pci::PciDeviceInfo,
    ) -> KapiResult<()> {
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

        let pci_locator = PackedPciLocation::new(
            pci_dev.segment,
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
        );
        let mut msix_guard = Mlx5MsixGuard::new(pci_locator);

        if pci_dev.msix_cap_offset.is_some() {
            let requested_vectors = 1;
            match kernel().enable_msix(pci_locator, requested_vectors) {
                Ok(msix_vectors) if !msix_vectors.is_empty() => {
                    msix_guard.arm();
                    log::info!(
                        target: "mlx5",
                        "Configured MSI-X vectors: {:?}",
                        msix_vectors
                            .iter()
                            .map(|info| info.vector)
                            .collect::<Vec<_>>()
                    );

                    for info in &msix_vectors {
                        let vec = info.vector as u8;
                        crate::io::interrupt_manager::register_handler(
                            vec,
                            alloc::boxed::Box::new(move || {
                                crate::io::interrupt_manager::push_interrupt_event(vec);
                            }),
                        );
                    }
                }
                Ok(_) => {
                    log::warn!(target: "mlx5", "MSI-X helper returned no vectors, falling back to polling");
                }
                Err(err) => {
                    log::warn!(
                        target: "mlx5",
                        "Failed to configure MSI-X via common helper: {:?}; falling back to polling",
                        err
                    );
                }
            }
        } else {
            log::warn!(target: "mlx5", "MSI-X not available; using polling mode");
        }

        // SR-IOV ケーパビリティの有無を確認して PF/VF 判定を補強
        let has_sriov_cap = pcie_ext_config()
            .map(|config| {
                config
                    .find_ext_capability(
                        PcieBdf::new(
                            pci_dev.bdf.bus(),
                            pci_dev.bdf.device(),
                            pci_dev.bdf.function(),
                        ),
                        crate::drivers::pci::ext_cap_id::SRIOV,
                    )
                    .is_some()
            })
            .unwrap_or(false);

        let mut device = Mlx5Device::new(bar0_base, bar0_size, pci_dev.device_id.0);
        let robust_is_vf = device.is_vf_robust(has_sriov_cap);
        let device_id_is_vf = ConnectXVariant::is_vf_device_id(pci_dev.device_id.0);
        if robust_is_vf != device_id_is_vf {
            log::warn!(
                target: "mlx5",
                "VF detect mismatch (device_id={:#x} has_sriov_cap={} robust_is_vf={}): forcing device-id based mode={}",
                pci_dev.device_id.0,
                has_sriov_cap,
                robust_is_vf,
                device_id_is_vf
            );
        }
        let is_vf = device_id_is_vf;
        log::info!(
            target: "mlx5",
            "mlx5 bootstrap mode: device_id={:#x} has_sriov_cap={} is_vf={}",
            pci_dev.device_id.0,
            has_sriov_cap,
            is_vf
        );

        let config = Mlx5BootstrapConfig {
            queue_profile: Mlx5QueueProfile::default(),
            mkey_params: mlx5_driver::resources::MkeyParams::default(),
            pci_identity: Mlx5PciIdentity {
                segment: pci_dev.segment,
                bus: pci_dev.bdf.bus(),
                device: pci_dev.bdf.device(),
                function: pci_dev.bdf.function(),
            },
            is_vf,
        };
        let plan = Mlx5BootstrapPlan::new(&config);

        let iommu_device_id = crate::io::iommu::types::DeviceId::new(
            pci_dev.segment,
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
        );
        let packed_device_id = Self::pack_iommu_device_id(iommu_device_id);

        let dma_resources = self.allocate_dma_resources(packed_device_id, &plan, is_vf)?;
        let allocated = dma_resources.to_allocated_resources();
        log::info!(
            target: "mlx5",
            "Allocated bootstrap fw pages: {} (plan requested {})",
            allocated.fw_pages.len(),
            plan.fw_boot_page_count()
        );
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
        crate::net::runtime::bridge::mlx5_bridge::register_mlx5_device(index, device);
        let adapter = crate::net::runtime::bridge::mlx5_bridge::mlx5_net_driver_adapter(index);
        let register_result = crate::net::runtime::device::register_port_with_default_config(
            crate::net::runtime::device::NetDeviceKey::Mlx5(index),
            adapter,
            crate::net::runtime::device::primary_if().is_none(),
        );
        if let Err(e) = register_result {
            log::error!(target: "mlx5", "Port runtime registration failed: {}", e);

            if let Some(mut dev) = crate::net::runtime::bridge::mlx5_bridge::take_mlx5_device(index)
            {
                unsafe {
                    if let Err(teardown_err) = dev.teardown() {
                        log::warn!(target: "mlx5", "Teardown after registration failure failed: {:?}", teardown_err);
                    }
                }
            }

            return Err(KapiError::IoError);
        }
        if let Ok(if_id) = register_result {
            crate::net::runtime::bridge::register_stack_glue_interface(if_id, None);
        }

        if self.variant.is_none() {
            self.variant = Some(variant);
        }
        self.devices.push(Mlx5RegisteredDevice {
            index,
            variant,
            pci_locator,
            dma_resources,
        });
        self.initialized = true;
        msix_guard.disarm();
        set_mlx5_sriov_state(Some(detect_sriov_runtime_state(
            variant,
            PcieBdf::new(
                pci_dev.bdf.bus(),
                pci_dev.bdf.device(),
                pci_dev.bdf.function(),
            ),
            !is_vf,
        )));

        log::info!(
            target: "mlx5",
            "{} device initialized and port runtime activated (index={})",
            variant.name(),
            index
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
            self.devices.clear();
            self.variant = None;
            self.initialized = false;

            let discovered = Self::discover_pci_devices();
            if discovered.is_empty() {
                log::info!(target: "mlx5", "No ConnectX family devices found on PCI bus");
                return Err(KapiError::NotFound);
            }

            let mut first_err = None;
            let mut probe_count = 0usize;
            for (slot, (variant, pci_device)) in discovered.into_iter().enumerate() {
                let index = slot as u8;
                log::info!(
                    target: "mlx5",
                    "Found {} at {:02x}:{:02x}.{} -> mlx5 index {}",
                    variant.name(),
                    pci_device.bdf.bus(),
                    pci_device.bdf.device(),
                    pci_device.bdf.function(),
                    index,
                );
                match self.probe_device(index, &pci_device) {
                    Ok(()) => probe_count += 1,
                    Err(err) => {
                        log::warn!(
                            target: "mlx5",
                            "mlx5 probe failed for {:02x}:{:02x}.{} index {}: {:?}",
                            pci_device.bdf.bus(),
                            pci_device.bdf.device(),
                            pci_device.bdf.function(),
                            index,
                            err
                        );
                        if first_err.is_none() {
                            first_err = Some(err);
                        }
                    }
                }
            }

            if probe_count == 0 {
                Err(first_err.unwrap_or(KapiError::IoError))
            } else {
                Ok(())
            }
        })
    }

    fn start(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(async move {
            if !self.initialized {
                return Err(KapiError::Internal(-1));
            }

            let variant_name = self.variant.map(|v| v.name()).unwrap_or("ConnectX");
            log::info!(
                target: "mlx5",
                "{} driver started with {} device(s)",
                variant_name,
                self.devices.len()
            );
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

            for device in &self.devices {
                if let Some(if_id) = crate::net::runtime::device::lookup_if_by_key(
                    crate::net::runtime::device::NetDeviceKey::Mlx5(device.index),
                ) {
                    let _ = crate::net::runtime::device::unregister_port(if_id);
                } else {
                    crate::net::runtime::bridge::mlx5_bridge::reset_mlx5_port_runtime(device.index);
                }
            }

            while let Some(device) = self.devices.pop() {
                if let Err(err) = kernel().disable_msix(device.pci_locator) {
                    log::warn!(target: "mlx5", "Failed to disable MSI-X during stop: {:?}", err);
                }

                if let Some(mut dev) =
                    crate::net::runtime::bridge::mlx5_bridge::take_mlx5_device(device.index)
                {
                    unsafe {
                        if let Err(e) = dev.teardown() {
                            log::warn!(target: "mlx5", "Teardown error: {:?}", e);
                        }
                    }
                }
            }

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
        crate::io::log::early_print("[MLX5_SYNC] probe enter\n");
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
    use alloc::alloc::{Layout, alloc, dealloc};
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DMA_RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn test_release_dma_buffer(ptr: *mut u8, size: usize, _phys_addr: u64) {
        DMA_RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        let layout = Layout::from_size_align(size.max(1), 1).expect("valid test dma layout");
        unsafe { dealloc(ptr, layout) };
    }

    fn test_dma_buffer(size: usize, phys_addr: u64, device_addr: u64) -> DmaBuffer {
        let layout = Layout::from_size_align(size.max(1), 1).expect("valid test dma layout");
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null());
        unsafe {
            DmaBuffer::from_internal_parts_unchecked(
                phys_addr,
                device_addr,
                ptr,
                size,
                kernel_api::dma::InternalDmaReclaimer::KernelBuffer {
                    releaser: Some(test_release_dma_buffer),
                },
            )
        }
    }

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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn sriov_status_snapshot_includes_active_vf_bdfs() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let state = Mlx5SriovRuntimeState {
            variant: ConnectXVariant::CX5,
            pf_bdf: PcieBdf::new(0, 2, 0),
            controller: Some(FakeSriovController::new(events, 2)),
        };

        let status = sriov_status_from_state(Some(&state), true);
        assert!(status.driver_present);
        assert!(status.port_runtime_initialized);
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn enable_vfs_rolls_back_when_port_runtime_sync_fails() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut state = Mlx5SriovRuntimeState {
            variant: ConnectXVariant::CX5,
            pf_bdf: PcieBdf::new(0, 2, 0),
            controller: Some(FakeSriovController::new(events.clone(), 0)),
        };

        let err = enable_vfs_with_runtime_state(&mut state, 2, true, |count| {
            assert_eq!(count, 2);
            events.borrow_mut().push("port_runtime_activate");
            Err(KapiError::IoError)
        })
        .unwrap_err();

        assert_eq!(err, KapiError::IoError);
        assert_eq!(
            events.borrow().as_slice(),
            ["enable", "port_runtime_activate", "disable"]
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn disable_vfs_still_disables_pci_when_admin_down_fails() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut state = Mlx5SriovRuntimeState {
            variant: ConnectXVariant::CX5,
            pf_bdf: PcieBdf::new(0, 2, 0),
            controller: Some(FakeSriovController::new(events.clone(), 2)),
        };

        let err = disable_vfs_with_runtime_state(&mut state, true, |count| {
            assert_eq!(count, 2);
            events.borrow_mut().push("port_runtime_deactivate");
            Err(KapiError::IoError)
        })
        .unwrap_err();

        assert_eq!(err, KapiError::IoError);
        assert_eq!(
            events.borrow().as_slice(),
            ["port_runtime_deactivate", "disable"]
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn dma_resources_to_allocated_resources_preserve_rmp_regions() {
        let dma_resources = Mlx5DmaResources {
            cmdq: DmaSlot::from_dma_buffer(test_dma_buffer(0x100, 0x1000, 0x2000)),
            cmd_in_mbox: DmaSlot::from_dma_buffer(test_dma_buffer(0x200, 0x3000, 0x4000)),
            cmd_out_mbox: DmaSlot::from_dma_buffer(test_dma_buffer(0x200, 0x5000, 0x6000)),
            fw_page_chunks: Vec::new(),
            fw_pages: Vec::new(),
            eqs: Vec::new(),
            tx_cqs: Vec::new(),
            tx_cq_dbs: Vec::new(),
            rx_cqs: Vec::new(),
            rx_cq_dbs: Vec::new(),
            sqs: Vec::new(),
            sq_dbs: Vec::new(),
            rqs: vec![DmaSlot::from_dma_buffer(test_dma_buffer(
                0x80, 0x7000, 0x8000,
            ))],
            rq_dbs: vec![DmaSlot::from_dma_buffer(test_dma_buffer(
                0x1000, 0x9000, 0xa000,
            ))],
            rmps: vec![DmaSlot::from_dma_buffer(test_dma_buffer(
                0x80, 0xb000, 0xc000,
            ))],
            rmp_dbs: vec![DmaSlot::from_dma_buffer(test_dma_buffer(
                0x1000, 0xd000, 0xe000,
            ))],
        };

        let allocated = dma_resources.to_allocated_resources();
        assert_eq!(allocated.rqs.len(), 1);
        assert_eq!(allocated.rmps.len(), 1);
        assert_eq!(
            allocated.rmps[0],
            Mlx5QueueDmaRegion {
                entries: Mlx5DmaRegion::new(
                    dma_resources.rmps[0].as_ptr_u64(),
                    dma_resources.rmps[0].device_address(),
                    0x80,
                ),
                doorbell: Mlx5DmaRegion::new(
                    dma_resources.rmp_dbs[0].as_ptr_u64(),
                    dma_resources.rmp_dbs[0].device_address(),
                    0x1000,
                ),
            }
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn dma_slot_subregion_keeps_owner_in_parent_buffer() {
        DMA_RELEASE_COUNT.store(0, Ordering::SeqCst);

        let mut chunk = DmaSlot::from_dma_buffer(test_dma_buffer(8192, 0x1000, 0x8000));
        let mut page = chunk.subregion(4096, 4096);

        assert_eq!(page.phys_address(), 0x2000);
        assert_eq!(page.device_address(), 0x9000);
        assert_eq!(page.as_ptr_u64(), chunk.as_ptr_u64() + 4096);

        release_dma_slot(&mut page);
        assert_eq!(DMA_RELEASE_COUNT.load(Ordering::SeqCst), 0);

        release_dma_slot(&mut chunk);
        assert_eq!(DMA_RELEASE_COUNT.load(Ordering::SeqCst), 1);

        release_dma_slot(&mut chunk);
        assert_eq!(DMA_RELEASE_COUNT.load(Ordering::SeqCst), 1);
    }
}
