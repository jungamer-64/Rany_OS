extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::domain::DomainId;
use crate::driver_domain::driver_domain_manager;
use crate::driver_registry::DriverHandle;
use crate::io::io_scheduler::{
    DeviceId as IoDeviceId, IoError, IoResult, hybrid_coordinator, io_scheduler,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::net::runtime::device::{self as net_device_runtime};
use crate::net::runtime::manager::NetIfId;
use crate::sync::{PoisonLock, PoisonRwLock};
#[cfg(test)]
use kernel_api::abi::driver::AbiNetPortOps;
use kernel_api::abi::driver::{
    AbiBlockCommandKind, AbiBlockCompletion, AbiBlockDeviceInfo, AbiBlockDeviceRegistration,
    AbiBlockTransport, AbiError as AbiErrorCode, AbiNetDriverEvent, AbiNetDriverEventKind,
    AbiNetPortInfo, AbiNetPortRegistration, AbiNetPortRuntime, AbiNetPortStats, AbiNetRxMeta,
    AbiNetTxMeta, AbiNetTxSegment, AbiNetTxSubmission, AbiNvmeNamespaceInfo,
    AbiNvmeNamespaceRegistration, AbiRxLease, AbiRxWritableRegion, AbiTxDeviceOutcome,
};
use kernel_api::resource::net::PacketByteCount;
use kernel_api::service::netdev::{
    MacAddress, NetDeviceInfo, NetDevicePort, NetDriverEvent, NetPortId, NetPortRegistration,
    NetPortRuntimeHandle, NetPortStats, NetRxFrameLayout, NetRxMeta, NetTxMeta, PrimaryPortPolicy,
    RxBuffer, TxLeaseId, TxPacketSubmission,
};
use kernel_api::service::storage::{StorageDeviceInfo, StorageTransport};
use x86_64::PhysAddr;

const STORAGE_FLAG_ACTIVE: u32 = 1 << 0;

pub(crate) mod balloon;
mod block;
use block::BlockDeviceAdapter;

pub mod direct_block;
pub mod dma;
pub mod fs;
pub mod ipc;
pub(crate) mod mmio;
pub mod net;
pub mod nvme;
pub mod storage;

pub(crate) use dma::DmaCleanupStats;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnerCleanupStats {
    pub(crate) files: usize,
    pub(crate) channels: usize,
    pub(crate) dma: DmaCleanupStats,
    pub(crate) direct_blocks: usize,
    pub(crate) block_devices: usize,
    pub(crate) nvme_namespaces: usize,
    pub(crate) net_ports: usize,
}

fn map_io_status(status: i32) -> IoResult {
    match AbiErrorCode::from_raw(status) {
        AbiErrorCode::Success => IoResult::Success(0),
        AbiErrorCode::Timeout => IoResult::Error(IoError::Timeout),
        AbiErrorCode::DeviceBusy => IoResult::Error(IoError::Busy),
        AbiErrorCode::InvalidParam
        | AbiErrorCode::InvalidSize
        | AbiErrorCode::InvalidAlignment
        | AbiErrorCode::InvalidAddress => IoResult::Error(IoError::InvalidParameter),
        AbiErrorCode::ResourceExhausted | AbiErrorCode::OutOfMemory => {
            IoResult::Error(IoError::NoResources)
        }
        AbiErrorCode::NotSupported => IoResult::Error(IoError::NotSupported),
        _ => IoResult::Error(IoError::DeviceError),
    }
}

fn map_storage_transport(raw: u32) -> StorageTransport {
    match raw {
        x if x == AbiBlockTransport::Nvme as u32 => StorageTransport::Nvme,
        x if x == AbiBlockTransport::Ahci as u32 => StorageTransport::Ahci,
        _ => StorageTransport::Other,
    }
}

/// Function pointers and their owner heap outlive every retained device index.
struct CallbackOwner {
    domain: DomainId,
    code: Option<crate::domain::DomainCodeLease>,
}

impl CallbackOwner {
    fn acquire(domain: DomainId) -> kernel_api::error::KapiResult<Self> {
        let code = if domain == DomainId::KERNEL {
            None
        } else {
            Some(
                crate::domain::registry::acquire_resource_code_lease(domain)
                    .ok_or(kernel_api::error::KapiError::Busy)?,
            )
        };
        Ok(Self { domain, code })
    }

    fn enter(
        &self,
        invocation: crate::domain::registry::ResourceInvocation,
    ) -> kernel_api::error::KapiResult<Option<crate::cpu::ExecutionContextGuard>> {
        match &self.code {
            Some(code) => crate::task::enter_resource_callback(self.domain, code, invocation)
                .map(Some)
                .map_err(|_| kernel_api::error::KapiError::Busy),
            None if crate::task::current_subject().domain == DomainId::KERNEL => Ok(None),
            None => crate::task::enter_domain(DomainId::KERNEL)
                .map(Some)
                .map_err(|_| kernel_api::error::KapiError::Busy),
        }
    }
}

struct BlockDeviceEntry {
    owner: DomainId,
    info: AbiBlockDeviceInfo,
    scheduler_device: IoDeviceId,
    adapter: Arc<BlockDeviceAdapter>,
}

pub(crate) struct BlockCleanupIncomplete {
    pub(crate) completed: usize,
    pub(crate) retained: usize,
    pub(crate) cause: AbiErrorCode,
}

struct BlockBridgeRegistry {
    entries: PoisonRwLock<BTreeMap<u64, BlockDeviceEntry>>,
    next_handle: AtomicU64,
}

impl BlockBridgeRegistry {
    const fn new() -> Self {
        Self {
            entries: PoisonRwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        owner: DomainId,
        registration: &AbiBlockDeviceRegistration,
    ) -> Result<u64, AbiErrorCode> {
        let handle = self
            .next_handle
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |handle| {
                handle.checked_add(1)
            })
            .map_err(|_| AbiErrorCode::ResourceExhausted)?;
        let scheduler_device = IoDeviceId::RegisteredBlock { handle };

        let adapter = Arc::try_new(BlockDeviceAdapter::prepare(owner, *registration)?)
            .map_err(|_| AbiErrorCode::OutOfMemory)?;
        let queue = registration.queue.identity()?;
        // Publication is serialized with domain admission closing. Prepare all
        // callback and per-request storage before acquiring that authority.
        crate::domain::with_resource_admission(owner, adapter, |_admission, adapter| {
            let mut entries = self
                .entries
                .write()
                .unwrap_or_else(|error| error.into_inner());
            if entries
                .values()
                .any(|entry| entry.adapter.claims_queue(queue))
            {
                return Err(AbiErrorCode::DeviceBusy);
            }
            io_scheduler().register_device(scheduler_device, Default::default());
            io_scheduler().register_device_ops(scheduler_device, adapter.clone());
            hybrid_coordinator()
                .polling_executor()
                .register_handler(scheduler_device, adapter.clone());
            entries.insert(
                handle,
                BlockDeviceEntry {
                    owner,
                    info: registration.info,
                    scheduler_device,
                    adapter,
                },
            );
            Ok(handle)
        })
        .map_err(|(cause, _adapter)| match cause {
            crate::domain::DomainResourceAdmissionError::UnknownOwner => {
                AbiErrorCode::DeviceNotFound
            }
            crate::domain::DomainResourceAdmissionError::RegistryUnavailable => {
                AbiErrorCode::IoError
            }
            crate::domain::DomainResourceAdmissionError::OwnerTerminated => {
                AbiErrorCode::DeviceBusy
            }
        })?
    }

    fn unregister(&self, owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
        let (scheduler_device, adapter) = {
            let entries = self
                .entries
                .read()
                .unwrap_or_else(|error| error.into_inner());
            let entry = entries.get(&handle).ok_or(AbiErrorCode::DeviceNotFound)?;
            if entry.owner != owner {
                return Err(AbiErrorCode::PermissionDenied);
            }
            (entry.scheduler_device, entry.adapter.clone())
        };
        // Closing is one-way. A preempted callback or accepted request keeps
        // the registration indexed and permits finalization polling on retry.
        adapter.stop()?;
        io_scheduler().unregister_device(scheduler_device);
        hybrid_coordinator()
            .polling_executor()
            .unregister_handler(scheduler_device);
        self.entries
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&handle);
        Ok(())
    }

    fn cleanup_owner(&self, owner: DomainId) -> Result<usize, BlockCleanupIncomplete> {
        let mut completed = 0;
        let initial_count = self
            .entries
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .filter(|entry| entry.owner == owner)
            .count();
        // LOOP_PROOF: mode=bounded; reason=The entry snapshot bounds removals and closed domain admission prevents new registrations;
        for _ in 0..initial_count {
            let handle = self
                .entries
                .read()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .find_map(|(&handle, entry)| (entry.owner == owner).then_some(handle));
            let Some(handle) = handle else {
                return Ok(completed);
            };
            if let Err(cause) = self.unregister(owner, handle) {
                let retained = self
                    .entries
                    .read()
                    .unwrap_or_else(|error| error.into_inner())
                    .values()
                    .filter(|entry| entry.owner == owner)
                    .count();
                return Err(BlockCleanupIncomplete {
                    completed,
                    retained,
                    cause,
                });
            }
            completed += 1;
        }
        Ok(completed)
    }

    fn storage_devices(&self) -> Vec<StorageDeviceInfo> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|entry| StorageDeviceInfo {
                device_id: entry.info.device_id,
                namespace_id: entry.info.namespace_id,
                block_size: entry.info.block_size,
                max_transfer_blocks: entry.info.max_transfer_blocks,
                transport: map_storage_transport(entry.info.transport),
                flags: entry.info.flags | STORAGE_FLAG_ACTIVE,
            })
            .collect()
    }
}

struct NvmeNamespaceEntry {
    owner: DomainId,
    info: AbiNvmeNamespaceInfo,
}

struct NvmeNamespaceRegistry {
    entries: PoisonRwLock<BTreeMap<u64, NvmeNamespaceEntry>>,
    next_handle: AtomicU64,
}

impl NvmeNamespaceRegistry {
    const fn new() -> Self {
        Self {
            entries: PoisonRwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        owner: DomainId,
        registration: &AbiNvmeNamespaceRegistration,
    ) -> Result<u64, AbiErrorCode> {
        {
            let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
            if entries
                .values()
                .any(|entry| entry.info.namespace_id == registration.info.namespace_id)
            {
                return Err(AbiErrorCode::DeviceBusy);
            }
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                handle,
                NvmeNamespaceEntry {
                    owner,
                    info: registration.info,
                },
            );
        Ok(handle)
    }

    fn unregister(&self, owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get(&handle) else {
            return Err(AbiErrorCode::DeviceNotFound);
        };
        if entry.owner != owner {
            return Err(AbiErrorCode::PermissionDenied);
        }
        entries.remove(&handle);
        Ok(())
    }

    fn cleanup_owner(&self, owner: DomainId) -> usize {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        for &handle in &handles {
            let _ = self.unregister(owner, handle);
        }
        handles.len()
    }

    pub fn lookup(namespace_id: u32) -> Option<AbiNvmeNamespaceInfo> {
        NVME_NAMESPACES
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|entry| entry.info.namespace_id == namespace_id)
            .map(|entry| entry.info)
    }
}

fn leak_driver_name(info: &AbiNetPortInfo) -> &'static str {
    if info.name_ptr.is_null() || info.name_len == 0 {
        return "standalone-netdev";
    }
    let bytes = unsafe { core::slice::from_raw_parts(info.name_ptr, info.name_len) };
    let owned = alloc::string::String::from_utf8_lossy(bytes).into_owned();
    Box::leak(owned.into_boxed_str())
}

struct NetRuntimeState {
    runtime: NetPortRuntimeHandle,
    table: AbiNetPortRuntime,
    rx_leases: PoisonLock<RxLeaseTable>,
    dma_mappings: Arc<NetPacketDmaMappings>,
}

const NET_PACKET_DMA_PAGE_SIZE: u64 = crate::mm::types::PAGE_SIZE_4K as u64;

#[derive(Debug)]
enum PacketTranslation {
    Ready(crate::io::iommu::api::DeviceMappedRange),
    Incomplete(crate::io::iommu::api::DeviceMappedRange),
}
impl PacketTranslation {
    fn into_mapping(self) -> crate::io::iommu::api::DeviceMappedRange {
        match self {
            Self::Ready(mapping) | Self::Incomplete(mapping) => mapping,
        }
    }
}

struct PacketMapping {
    physical_base: u64,
    byte_len: u64,
    translation: Option<PacketTranslation>,
    backing: Option<kernel_api::resource::net::PacketBackingLease>,
}
impl Drop for PacketMapping {
    fn drop(&mut self) {
        if self.translation.is_some() {
            // Dropping an observation is not DMA retirement. DeviceMappedRange
            // retains translation origin; this owner must also retain RAM.
            if let Some(backing) = self.backing.take() {
                core::mem::forget(backing);
            }
        }
    }
}

#[derive(Debug)]
enum NetPacketMappingError {
    InvalidRange,
    MetadataAllocation,
    TranslationIncomplete,
    BackingConflict,
    Iommu(crate::io::iommu::types::IommuError),
}
impl NetPacketMappingError {
    fn abi_status(&self) -> AbiErrorCode {
        use crate::io::iommu::types::IommuError;
        match self {
            Self::InvalidRange => AbiErrorCode::InvalidParam,
            Self::MetadataAllocation => AbiErrorCode::OutOfMemory,
            Self::TranslationIncomplete => AbiErrorCode::DeviceBusy,
            Self::BackingConflict => AbiErrorCode::InvalidAddress,
            Self::Iommu(IommuError::NotInitialized | IommuError::NotPresent) => {
                AbiErrorCode::NotInitialized
            }
            Self::Iommu(IommuError::OutOfMemory | IommuError::MetadataAllocation) => {
                AbiErrorCode::OutOfMemory
            }
            Self::Iommu(
                IommuError::OutOfIova | IommuError::GenerationExhausted | IommuError::InUse,
            ) => AbiErrorCode::DeviceBusy,
            Self::Iommu(
                IommuError::InvalidAddress
                | IommuError::InvalidAlignment
                | IommuError::InvalidPermissions,
            ) => AbiErrorCode::InvalidParam,
            Self::Iommu(_) => AbiErrorCode::IoError,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRange => "network DMA range is invalid",
            Self::MetadataAllocation => "network DMA mapping registry allocation failed",
            Self::TranslationIncomplete => "network DMA translation retirement is incomplete",
            Self::BackingConflict => "network DMA range conflicts with retained backing",
            Self::Iommu(_) => "network packet IOMMU mapping failed",
        }
    }
}

struct NetPacketDmaMappings {
    device: IommuDeviceId,
    pages: PoisonLock<Vec<PacketMapping>>,
}
impl NetPacketDmaMappings {
    fn new(device: IommuDeviceId) -> Self {
        Self {
            device,
            pages: PoisonLock::new(Vec::new()),
        }
    }
    fn map_region(
        &self,
        region: &kernel_api::resource::net::PacketDmaRegion,
    ) -> Result<u64, NetPacketMappingError> {
        use crate::io::iommu::api::DeviceMapFailure;
        let physical = region.physical_address().as_u64();
        let last = physical
            .checked_add(region.len().get() as u64 - 1)
            .ok_or(NetPacketMappingError::InvalidRange)?;
        if physical == 0 {
            return Err(NetPacketMappingError::InvalidRange);
        }
        if !crate::io::iommu::api::is_iommu_enabled() {
            return Err(NetPacketMappingError::Iommu(
                crate::io::iommu::types::IommuError::NotInitialized,
            ));
        }
        let mut pages = self.pages.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(page) = pages.iter().find(|page| {
            physical >= page.physical_base && last - page.physical_base < page.byte_len
        }) {
            let backing = page.backing.as_ref().expect("retained mapping backing");
            if !region.retains_backing(backing) {
                return Err(NetPacketMappingError::BackingConflict);
            }
            let Some(PacketTranslation::Ready(mapping)) = &page.translation else {
                return Err(NetPacketMappingError::TranslationIncomplete);
            };
            return mapping
                .iova()
                .checked_add(physical - page.physical_base)
                .ok_or(NetPacketMappingError::InvalidRange);
        }
        let backing = region.backing_lease();
        let backing_start = backing.physical_address().as_u64();
        let backing_last = backing_start
            .checked_add(backing.capacity().get() as u64 - 1)
            .ok_or(NetPacketMappingError::InvalidRange)?;
        if physical < backing_start || last > backing_last {
            return Err(NetPacketMappingError::InvalidRange);
        }
        let base = backing_start & !(NET_PACKET_DMA_PAGE_SIZE - 1);
        let end = (backing_last | (NET_PACKET_DMA_PAGE_SIZE - 1))
            .checked_add(1)
            .ok_or(NetPacketMappingError::InvalidRange)?;
        let size = end - base;
        if pages
            .iter()
            .any(|page| base < page.physical_base + page.byte_len && page.physical_base < end)
        {
            return Err(NetPacketMappingError::BackingConflict);
        }
        pages
            .try_reserve(1)
            .map_err(|_| NetPacketMappingError::MetadataAllocation)?;
        // SAFETY: the region came from a retained initialized packet allocation.
        // Its backing lease retains the containing physical pages independently
        // of CPU window/header recycling. Publication failure is stored below.
        let mapped = unsafe {
            crate::io::iommu::api::map_for_device_with_perms(
                &self.device,
                PhysAddr::new(base),
                size,
                true,
                true,
            )
        };
        match mapped {
            Ok(mapping) => {
                let address = mapping.iova().checked_add(physical - base);
                pages.push(PacketMapping {
                    physical_base: base,
                    byte_len: size,
                    translation: Some(PacketTranslation::Ready(mapping)),
                    backing: Some(backing),
                });
                address.ok_or(NetPacketMappingError::InvalidRange)
            }
            Err(DeviceMapFailure::Unpublished(cause)) => Err(NetPacketMappingError::Iommu(cause)),
            Err(DeviceMapFailure::TranslationPending { cause, mapping }) => {
                pages.push(PacketMapping {
                    physical_base: base,
                    byte_len: size,
                    translation: Some(PacketTranslation::Incomplete(mapping)),
                    backing: Some(backing),
                });
                Err(NetPacketMappingError::Iommu(cause))
            }
        }
    }
    fn revoke_all(&self) -> Result<(), NetPacketMappingError> {
        let mut pages = self.pages.lock().unwrap_or_else(|error| error.into_inner());
        let initial = pages.len();
        let mut failure = None;
        // LOOP_PROOF: mode=bounded; reason=The retained mapping snapshot bounds retirement attempts and the port has stopped new DMA admission;
        for index in (0..initial).rev() {
            let page = &mut pages[index];
            let translation = page.translation.take().expect("retained translation");
            match translation.into_mapping().unmap() {
                Ok(()) => {
                    pages.swap_remove(index);
                }
                Err(error) => {
                    page.translation = Some(PacketTranslation::Incomplete(error.mapping));
                    failure = Some(NetPacketMappingError::Iommu(error.cause));
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

const ABI_RX_LEASE_INDEX_BITS: u32 = 16;
const ABI_RX_LEASE_INDEX_MASK: u64 = (1_u64 << ABI_RX_LEASE_INDEX_BITS) - 1;
const ABI_RX_LEASE_GENERATION_MASK: u64 = (1_u64 << (64 - ABI_RX_LEASE_INDEX_BITS)) - 1;
const ABI_RX_LEASE_SLOT_LIMIT: usize = u16::MAX as usize;

struct RxLeaseSlot {
    generation: u64,
    buffer: Option<RxBuffer>,
}

#[derive(Default)]
struct RxLeaseTable {
    slots: Vec<RxLeaseSlot>,
    free: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RxLeaseAdmissionError {
    Exhausted,
    Allocation,
}

impl RxLeaseTable {
    fn admit(&mut self, buffer: RxBuffer) -> Result<NonZeroU64, RxLeaseAdmissionError> {
        let index = if let Some(index) = self.free.pop() {
            usize::from(index)
        } else {
            if self.slots.len() == ABI_RX_LEASE_SLOT_LIMIT {
                return Err(RxLeaseAdmissionError::Exhausted);
            }
            self.slots
                .try_reserve(1)
                .map_err(|_| RxLeaseAdmissionError::Allocation)?;
            self.free
                .try_reserve(1)
                .map_err(|_| RxLeaseAdmissionError::Allocation)?;
            let index = self.slots.len();
            self.slots.push(RxLeaseSlot {
                generation: 0,
                buffer: None,
            });
            index
        };

        let slot = &mut self.slots[index];
        debug_assert!(slot.buffer.is_none());
        slot.generation = slot.generation.wrapping_add(1) & ABI_RX_LEASE_GENERATION_MASK;
        if slot.generation == 0 {
            slot.generation = 1;
        }
        slot.buffer = Some(buffer);
        let raw = (slot.generation << ABI_RX_LEASE_INDEX_BITS) | ((index as u64) + 1);
        Ok(NonZeroU64::new(raw).expect("RX lease generation and index are non-zero"))
    }

    fn claim(&mut self, lease_id: NonZeroU64) -> Option<RxBuffer> {
        let raw = lease_id.get();
        let encoded_index = raw & ABI_RX_LEASE_INDEX_MASK;
        if encoded_index == 0 {
            return None;
        }
        let index = usize::try_from(encoded_index - 1).ok()?;
        let generation = raw >> ABI_RX_LEASE_INDEX_BITS;
        let slot = self.slots.get_mut(index)?;
        if slot.generation != generation {
            return None;
        }
        let free_index = u16::try_from(index).ok()?;
        let buffer = slot.buffer.take()?;
        self.free.push(free_index);
        Some(buffer)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetRuntimeStateCookie(NonZeroUsize);

impl NetRuntimeStateCookie {
    fn from_state(state: &mut NetRuntimeState) -> Self {
        let raw = state as *mut NetRuntimeState as usize;
        let Some(raw) = NonZeroUsize::new(raw) else {
            unreachable!("boxed runtime state addresses are non-null");
        };
        Self(raw)
    }

    fn from_raw(raw: u64) -> Option<Self> {
        let raw = usize::try_from(raw).ok()?;
        NonZeroUsize::new(raw).map(Self)
    }

    fn as_raw(self) -> u64 {
        self.0.get() as u64
    }

    fn with_state<R>(self, f: impl FnOnce(&NetRuntimeState) -> R) -> R {
        let ptr = self.0.get() as *const NetRuntimeState;
        // SAFETY: NetRuntimeStateCookie values are created from the Box stored
        // in NetdevPortAdapter::runtime_state during start(). The box keeps the
        // pointee stable until the driver is stopped and the runtime table is no
        // longer a valid callback target.
        unsafe { f(&*ptr) }
    }
}

extern "C" fn runtime_lease_rx_buffer(runtime_cookie: u64, out_lease: *mut AbiRxLease) -> i32 {
    if out_lease.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(|state| {
        let Some(buffer) = state.runtime.lease_rx_buffer() else {
            return AbiErrorCode::OutOfMemory as i32;
        };
        let writable = buffer.writable_region();
        let device_addr = match state.dma_mappings.map_region(writable) {
            Ok(device_addr) => device_addr,
            Err(cause) => return cause.abi_status() as i32,
        };
        let region = AbiRxWritableRegion {
            cpu_ptr: writable.cpu_ptr().cast_mut(),
            device_addr,
            writable_len: writable.len().get(),
        };
        let lease_id = match state
            .rx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .admit(buffer)
        {
            Ok(lease_id) => lease_id,
            Err(RxLeaseAdmissionError::Exhausted) => return AbiErrorCode::DeviceBusy as i32,
            Err(RxLeaseAdmissionError::Allocation) => return AbiErrorCode::OutOfMemory as i32,
        };
        let Some(lease) = AbiRxLease::new(lease_id, region) else {
            let _ = state
                .rx_leases
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .claim(lease_id);
            return AbiErrorCode::InvalidParam as i32;
        };
        unsafe {
            *out_lease = lease;
        }
        AbiErrorCode::Success as i32
    })
}

extern "C" fn runtime_release_rx_buffer(runtime_cookie: u64, lease: *mut AbiRxLease) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease) = (unsafe { AbiRxLease::take(lease) }) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease_id) = lease.lease_id() else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(|state| {
        match state
            .rx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .claim(lease_id)
        {
            Some(_) => AbiErrorCode::Success as i32,
            None => AbiErrorCode::InvalidParam as i32,
        }
    })
}

extern "C" fn runtime_submit_rx_buffer(
    runtime_cookie: u64,
    lease: *mut AbiRxLease,
    meta: AbiNetRxMeta,
) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease) = (unsafe { AbiRxLease::take(lease) }) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease_id) = lease.lease_id() else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(buffer) = cookie.with_state(|state| {
        state
            .rx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .claim(lease_id)
    }) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let layout = meta.layout();
    if !layout.is_valid() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let Some(frame_len) = PacketByteCount::new(layout.frame_len()) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(rx_layout) =
        NetRxFrameLayout::new(frame_len, layout.header_len(), layout.payload_len())
    else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let rx_meta = NetRxMeta::new(meta.queue_index(), rx_layout, meta.flags());
    // SAFETY: the driver transfers this exact generation after observing its
    // hardware completion. Claiming the lease excludes duplicate publication;
    // the driver ABI requires DMA writes to have ceased before this callback.
    let received = match unsafe { buffer.complete(rx_meta) } {
        Ok(received) => received,
        Err(_) => return AbiErrorCode::InvalidParam as i32,
    };
    cookie.with_state(|state| match state.runtime.submit_rx(received) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    })
}

extern "C" fn runtime_schedule_event(runtime_cookie: u64, event: AbiNetDriverEvent) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let translated = match event.kind {
        x if x == AbiNetDriverEventKind::Interrupt as u32 => NetDriverEvent::Interrupt,
        x if x == AbiNetDriverEventKind::QueueWake as u32 => NetDriverEvent::QueueWake {
            queue_index: event.queue_index,
        },
        _ => NetDriverEvent::Poll,
    };
    cookie.with_state(|state| match state.runtime.schedule_event(translated) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    })
}

extern "C" fn runtime_complete_tx_lease(
    runtime_cookie: u64,
    lease_id: u64,
    outcome: AbiTxDeviceOutcome,
) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(lease_id) = TxLeaseId::new(lease_id) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(outcome) = outcome.into_outcome() else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(
        |state| match state.runtime.complete_tx_lease(lease_id, outcome) {
            Ok(()) => AbiErrorCode::Success as i32,
            Err(_) => AbiErrorCode::DeviceNotFound as i32,
        },
    )
}

extern "C" fn runtime_update_link(runtime_cookie: u64, up: bool) -> i32 {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    cookie.with_state(|state| match state.runtime.update_link(up) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(_) => AbiErrorCode::IoError as i32,
    })
}

extern "C" fn runtime_log(runtime_cookie: u64, level: u32, msg_ptr: *const u8, msg_len: usize) {
    let Some(cookie) = NetRuntimeStateCookie::from_raw(runtime_cookie) else {
        return;
    };
    if msg_ptr.is_null() || msg_len == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
    if let Ok(message) = core::str::from_utf8(slice) {
        cookie.with_state(|state| {
            state.runtime.log(
                match level {
                    0 => kernel_api::service::netdev::NetLogLevel::Error,
                    1 => kernel_api::service::netdev::NetLogLevel::Warn,
                    3 => kernel_api::service::netdev::NetLogLevel::Debug,
                    4 => kernel_api::service::netdev::NetLogLevel::Trace,
                    _ => kernel_api::service::netdev::NetLogLevel::Info,
                },
                message,
            )
        });
    }
}

struct NetdevPortAdapter {
    callbacks: CallbackOwner,
    registration: AbiNetPortRegistration,
    driver_name: &'static str,
    runtime_state: PoisonLock<Option<Box<NetRuntimeState>>>,
    max_tx_segments: NonZeroU16,
    tx_abi_scratch: PoisonLock<Vec<AbiNetTxSegment>>,
    dma_mappings: Arc<NetPacketDmaMappings>,
}

unsafe impl Send for NetdevPortAdapter {}
unsafe impl Sync for NetdevPortAdapter {}

impl NetdevPortAdapter {
    fn new(
        owner: DomainId,
        registration: &AbiNetPortRegistration,
        driver_name: &'static str,
        dma_device: IommuDeviceId,
    ) -> Result<Self, AbiErrorCode> {
        let Some(max_tx_segments) = NonZeroU16::new(registration.info.max_tx_segments) else {
            return Err(AbiErrorCode::InvalidParam);
        };
        let mut tx_abi_scratch = Vec::new();
        tx_abi_scratch
            .try_reserve_exact(usize::from(max_tx_segments.get()))
            .map_err(|_| AbiErrorCode::OutOfMemory)?;
        Ok(Self {
            callbacks: CallbackOwner::acquire(owner).map_err(|_| AbiErrorCode::DeviceBusy)?,
            registration: *registration,
            driver_name,
            runtime_state: PoisonLock::new(None),
            max_tx_segments,
            tx_abi_scratch: PoisonLock::new(tx_abi_scratch),
            dma_mappings: Arc::try_new(NetPacketDmaMappings::new(dma_device))
                .map_err(|_| AbiErrorCode::OutOfMemory)?,
        })
    }
}

// SAFETY: the retained runtime and callback code owners outlive DMA; accepted routes complete only after device release and stop preserves failures.
unsafe impl NetDevicePort for NetdevPortAdapter {
    fn info(&self) -> NetDeviceInfo {
        let info = self.registration.info;
        NetDeviceInfo {
            port_id: NetPortId::new(info.port_id),
            if_id: None,
            driver_name: self.driver_name,
            queue_pairs: info.queue_pairs,
            max_tx_segments: self.max_tx_segments,
            mtu: info.mtu,
            mac: MacAddress(info.mac),
            flags: info.flags,
        }
    }

    fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
        let _execution = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Operation)
            .map_err(|_| "network callback owner is not runnable")?;
        let mut state = Box::try_new(NetRuntimeState {
            runtime,
            table: AbiNetPortRuntime::new(
                0,
                runtime_lease_rx_buffer,
                runtime_release_rx_buffer,
                runtime_submit_rx_buffer,
                runtime_complete_tx_lease,
                runtime_schedule_event,
                runtime_update_link,
                runtime_log,
            ),
            rx_leases: PoisonLock::new(RxLeaseTable::default()),
            dma_mappings: Arc::clone(&self.dma_mappings),
        })
        .map_err(|_| "network runtime callback storage allocation failed")?;
        state.table.runtime_cookie = NetRuntimeStateCookie::from_state(&mut state).as_raw();
        let table_ptr = &state.table as *const AbiNetPortRuntime;
        // Publish the callback owner before the first foreign call. Failure
        // keeps the exact box until stop proves every callback/DMA user ended.
        let mut owned = self.runtime_state.lock().unwrap_or_else(|e| e.into_inner());
        if owned.is_some() {
            return Err("standalone netdev runtime already owned");
        }
        *owned = Some(state);
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status = unsafe { (self.registration.start)(self.registration.opaque, table_ptr) };
        if !AbiErrorCode::from_raw(status).is_success() {
            return Err("standalone netdev start failed");
        }
        Ok(())
    }

    fn bind(&self, if_id: u16) -> Result<(), &'static str> {
        let _execution = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Operation)
            .map_err(|_| "network callback owner is not runnable")?;
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status = unsafe { (self.registration.bind)(self.registration.opaque, if_id) };
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev bind failed")
        }
    }

    fn submit_tx_chain(
        &self,
        submission: TxPacketSubmission<'_>,
        meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        let _execution = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Operation)
            .map_err(|_| "network callback owner is not runnable")?;
        let mut abi_segments = self
            .tx_abi_scratch
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        abi_segments.clear();
        if submission.regions().len() > abi_segments.capacity() {
            return Err("standalone netdev TX segment limit exceeded");
        }
        for segment in submission.regions() {
            let device_addr = self.dma_mappings.map_region(segment).map_err(|cause| {
                log::warn!("network packet DMA admission failed: {cause:?}");
                cause.as_str()
            })?;
            abi_segments.push(
                AbiNetTxSegment::from_checked_parts(segment.cpu_ptr(), device_addr, segment.len())
                    .ok_or("mapped packet range is not representable in the driver ABI")?,
            );
        }
        let abi_submission = AbiNetTxSubmission::new(submission.lease_id(), &abi_segments)
            .ok_or("standalone netdev empty tx submission")?;
        let abi_meta = AbiNetTxMeta {
            queue_index: meta.queue_index.unwrap_or(0),
            has_queue_index: meta.queue_index.is_some(),
            has_vlan_tag: meta.vlan_tag.is_some(),
            reserved0: 0,
            flags: meta.flags,
            vlan_tag: meta.vlan_tag.unwrap_or(0),
            reserved1: 0,
        };
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status = unsafe {
            (self.registration.submit_tx_chain)(self.registration.opaque, &abi_submission, abi_meta)
        };
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev tx failed")
        }
    }

    fn set_interrupts_enabled(&self, enabled: bool) -> Result<(), &'static str> {
        let _execution = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Operation)
            .map_err(|_| "network callback owner is not runnable")?;
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status = unsafe {
            (self.registration.set_interrupts_enabled)(self.registration.opaque, enabled)
        };
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev interrupt toggle failed")
        }
    }

    fn poll(&self, if_id: u16) -> Result<(), &'static str> {
        let _execution = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Operation)
            .map_err(|_| "network callback owner is not runnable")?;
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status = unsafe { (self.registration.poll)(self.registration.opaque, if_id) };
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev poll failed")
        }
    }

    fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
        let _execution = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Operation)
            .map_err(|_| "network callback owner is not runnable")?;
        let abi_event = match event {
            NetDriverEvent::Interrupt => AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::Interrupt as u32,
                queue_index: 0,
                _padding: 0,
            },
            NetDriverEvent::QueueWake { queue_index } => AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::QueueWake as u32,
                queue_index,
                _padding: 0,
            },
            NetDriverEvent::Poll => AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::Poll as u32,
                queue_index: 0,
                _padding: 0,
            },
        };
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status =
            unsafe { (self.registration.handle_event)(self.registration.opaque, if_id, abi_event) };
        if AbiErrorCode::from_raw(status).is_success() {
            Ok(())
        } else {
            Err("standalone netdev event failed")
        }
    }

    fn stats(&self) -> NetPortStats {
        let Ok(_execution) = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Operation)
        else {
            return NetPortStats::default();
        };
        let mut stats = AbiNetPortStats::default();
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status = unsafe { (self.registration.stats)(self.registration.opaque, &mut stats) };
        if !AbiErrorCode::from_raw(status).is_success() {
            return NetPortStats::default();
        }
        NetPortStats {
            tx_packets: stats.tx_packets,
            rx_packets: stats.rx_packets,
            tx_errors: stats.tx_errors,
            rx_errors: stats.rx_errors,
            initialized: stats.initialized,
        }
    }

    fn stop(&self) -> kernel_api::error::KapiResult<()> {
        let _execution = self
            .callbacks
            .enter(crate::domain::registry::ResourceInvocation::Finalize)?;
        // SAFETY: the callback admission/code guard retains the registered
        // opaque instance and every synchronous input/output borrow.
        let status = unsafe { (self.registration.stop)(self.registration.opaque) };
        match AbiErrorCode::from_raw(status) {
            AbiErrorCode::Success => {}
            AbiErrorCode::DeviceBusy => return Err(kernel_api::error::KapiError::Busy),
            _ => return Err(kernel_api::error::KapiError::IoError),
        }
        self.dma_mappings.revoke_all().map_err(|cause| {
            log::warn!("network packet translation retirement remains incomplete: {cause:?}");
            kernel_api::error::KapiError::Busy
        })?;
        let _ = self
            .runtime_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Ok(())
    }
}

pub(crate) struct NetOwnerCleanupError {
    completed: usize,
    retained: usize,
    cause: kernel_api::error::KapiError,
}

enum NetdevPortPhase {
    Registered,
    Finalizing,
}

struct NetdevPortEntry {
    owner: DomainId,
    if_id: NetIfId,
    phase: NetdevPortPhase,
}

struct NetdevBridgeRegistry {
    entries: PoisonRwLock<BTreeMap<u64, NetdevPortEntry>>,
    next_handle: AtomicU64,
}

impl NetdevBridgeRegistry {
    const fn new() -> Self {
        Self {
            entries: PoisonRwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        owner: DomainId,
        dma_device: IommuDeviceId,
        registration: &AbiNetPortRegistration,
    ) -> kernel_api::error::KapiResult<u64> {
        let name = leak_driver_name(&registration.info);
        let adapter: Box<dyn NetDevicePort> = Box::new(
            NetdevPortAdapter::new(owner, registration, name, dma_device).map_err(|cause| {
                match cause {
                    AbiErrorCode::OutOfMemory => kernel_api::error::KapiError::OutOfMemory,
                    _ => kernel_api::error::KapiError::IoError,
                }
            })?,
        );
        let info = adapter.info();
        let runtime = crate::net::runtime::default_runtime();
        let outcome = net_device_runtime::register_port_in(
            runtime,
            NetPortRegistration::new(info, adapter, PrimaryPortPolicy::Auto),
        );
        let (if_id, failed) = match outcome {
            Ok(if_id) => (if_id, false),
            Err(
                net_device_runtime::NetPortRegistrationError::NotPublished(_)
                | net_device_runtime::NetPortRegistrationError::Released(_),
            ) => {
                return Err(kernel_api::error::KapiError::IoError);
            }
            Err(net_device_runtime::NetPortRegistrationError::Retained { if_id, .. }) => {
                (if_id, true)
            }
        };
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                handle,
                NetdevPortEntry {
                    owner,
                    if_id,
                    phase: NetdevPortPhase::Registered,
                },
            );
        if failed {
            return Err(kernel_api::error::KapiError::NetRegistrationRetained { handle });
        }
        Ok(handle)
    }

    fn unregister(&self, owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
        let if_id = {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            let entry = entries
                .get_mut(&handle)
                .ok_or(AbiErrorCode::DeviceNotFound)?;
            if entry.owner != owner {
                return Err(AbiErrorCode::PermissionDenied);
            }
            if matches!(entry.phase, NetdevPortPhase::Finalizing) {
                return Err(AbiErrorCode::DeviceBusy);
            }
            entry.phase = NetdevPortPhase::Finalizing;
            entry.if_id
        };
        let result =
            net_device_runtime::unregister_port_in(crate::net::runtime::default_runtime(), if_id);
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(true) => {
                entries.remove(&handle);
                Ok(())
            }
            outcome => {
                // Restore only retry admission. The runtime retains its stopped
                // device, DMA and callback state throughout a failed finalizer.
                if let Some(entry) = entries.get_mut(&handle) {
                    entry.phase = NetdevPortPhase::Registered;
                }
                Err(match outcome {
                    Err(kernel_api::error::KapiError::Busy) => AbiErrorCode::DeviceBusy,
                    Err(_) => AbiErrorCode::IoError,
                    Ok(false) => AbiErrorCode::DeviceNotFound,
                    Ok(true) => unreachable!(),
                })
            }
        }
    }

    fn cleanup_owner(&self, owner: DomainId) -> Result<usize, NetOwnerCleanupError> {
        let handles: Vec<u64> = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        let mut completed = 0;
        let mut failure = None;
        for handle in handles {
            match self.unregister(owner, handle) {
                Ok(()) => completed += 1,
                Err(cause) => {
                    let cause = match cause {
                        AbiErrorCode::DeviceBusy => kernel_api::error::KapiError::Busy,
                        AbiErrorCode::DeviceNotFound => kernel_api::error::KapiError::NotFound,
                        AbiErrorCode::PermissionDenied => {
                            kernel_api::error::KapiError::PermissionDenied
                        }
                        _ => kernel_api::error::KapiError::IoError,
                    };
                    failure.get_or_insert(cause);
                }
            }
        }
        let retained = self
            .entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|entry| entry.owner == owner)
            .count();
        match failure {
            Some(cause) => Err(NetOwnerCleanupError {
                completed,
                retained,
                cause,
            }),
            None if retained != 0 => Err(NetOwnerCleanupError {
                completed,
                retained,
                cause: kernel_api::error::KapiError::Busy,
            }),
            None => Ok(completed),
        }
    }
}

static BLOCK_DEVICES: BlockBridgeRegistry = BlockBridgeRegistry::new();
static NVME_NAMESPACES: NvmeNamespaceRegistry = NvmeNamespaceRegistry::new();
static NETDEV_PORTS: NetdevBridgeRegistry = NetdevBridgeRegistry::new();

/// Finalize foreign callbacks before revoking their DMA or owner heap.
/// Failure retains the remaining indices and reports committed partial progress.
pub(crate) fn cleanup_owner_domain(
    owner: DomainId,
) -> Result<OwnerCleanupStats, crate::domain::DomainLifecycleError> {
    let net_ports = net::cleanup_owner(owner).map_err(|failure| {
        crate::domain::DomainLifecycleError::ResourceCleanupIncomplete {
            completed_net_ports: failure.completed,
            retained_net_ports: failure.retained,
            completed_block_devices: 0,
            retained_block_devices: 0,
            completed_dma_leases: 0,
            retained_dma_leases: dma::owner_lease_count(owner),
            retained_balloon_pages: balloon::owner_count(owner),
            cause: failure.cause,
        }
    })?;
    let block_devices = storage::cleanup_owner(owner).map_err(|failure| {
        crate::domain::DomainLifecycleError::ResourceCleanupIncomplete {
            completed_net_ports: net_ports,
            retained_net_ports: 0,
            completed_block_devices: failure.completed,
            retained_block_devices: failure.retained,
            completed_dma_leases: 0,
            retained_dma_leases: dma::owner_lease_count(owner),
            retained_balloon_pages: balloon::owner_count(owner),
            cause: failure
                .cause
                .into_result()
                .err()
                .unwrap_or(kernel_api::KapiError::IoError),
        }
    })?;
    let dma = dma::cleanup_owner(owner);
    let retained_dma_leases = dma::owner_lease_count(owner);
    let retained_balloon_pages = balloon::owner_count(owner);
    if retained_dma_leases != 0 || retained_balloon_pages != 0 {
        return Err(
            crate::domain::DomainLifecycleError::ResourceCleanupIncomplete {
                completed_net_ports: net_ports,
                retained_net_ports: 0,
                completed_block_devices: block_devices,
                retained_block_devices: 0,
                completed_dma_leases: dma.released_handles,
                retained_dma_leases,
                retained_balloon_pages,
                cause: kernel_api::error::KapiError::Busy,
            },
        );
    }
    Ok(OwnerCleanupStats {
        files: fs::cleanup_owner(owner.as_u64()),
        channels: ipc::cleanup_owner(owner.as_u64()),
        dma,
        direct_blocks: direct_block::cleanup_owner(owner.as_u64()),
        block_devices,
        nvme_namespaces: nvme::cleanup_owner(owner),
        net_ports,
    })
}

pub(crate) fn cleanup_for_driver_handle(
    handle: DriverHandle,
) -> Result<(), crate::domain::DomainLifecycleError> {
    let Some(cell_id) = driver_domain_manager().find_by_driver_handle(handle) else {
        return Ok(());
    };
    let domain = driver_domain_manager()
        .with_cell(cell_id, |cell| cell.domain_id)
        .map_err(|_| crate::domain::DomainLifecycleError::NotFound)?;
    if let Some(domain) = domain {
        cleanup_owner_domain(domain)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainId;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn packet_dma_admission_preserves_abi_failure_semantics() {
        use crate::io::iommu::types::IommuError;
        for (cause, expected) in [
            (
                NetPacketMappingError::Iommu(IommuError::NotInitialized),
                AbiErrorCode::NotInitialized,
            ),
            (
                NetPacketMappingError::Iommu(IommuError::NotPresent),
                AbiErrorCode::NotInitialized,
            ),
            (
                NetPacketMappingError::MetadataAllocation,
                AbiErrorCode::OutOfMemory,
            ),
            (
                NetPacketMappingError::Iommu(IommuError::OutOfMemory),
                AbiErrorCode::OutOfMemory,
            ),
            (
                NetPacketMappingError::Iommu(IommuError::OutOfIova),
                AbiErrorCode::DeviceBusy,
            ),
            (
                NetPacketMappingError::TranslationIncomplete,
                AbiErrorCode::DeviceBusy,
            ),
            (
                NetPacketMappingError::BackingConflict,
                AbiErrorCode::InvalidAddress,
            ),
            (
                NetPacketMappingError::InvalidRange,
                AbiErrorCode::InvalidParam,
            ),
            (
                NetPacketMappingError::Iommu(IommuError::HardwareError),
                AbiErrorCode::IoError,
            ),
        ] {
            assert_eq!(cause.abi_status(), expected);
        }
    }

    unsafe extern "C" fn test_block_submit(
        _opaque: u64,
        _input: *const kernel_api::abi::driver::AbiBlockSubmission,
    ) -> kernel_api::abi::driver::AbiBlockSubmitOutcome {
        kernel_api::abi::driver::AbiBlockSubmitOutcome::rejected(AbiErrorCode::NotSupported)
    }

    unsafe extern "C" fn test_block_poll(
        _opaque: u64,
        _out: *mut kernel_api::abi::driver::AbiBlockCompletion,
        _capacity: usize,
        written: *mut usize,
    ) -> i32 {
        // SAFETY: the host supplies an exclusive output count for this callback.
        unsafe { written.write(0) };
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_block_ready(_opaque: u64) -> bool {
        true
    }
    unsafe extern "C" fn test_block_stop(_opaque: u64) -> i32 {
        AbiErrorCode::Success as i32
    }

    static TEST_NET_INTERRUPT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TEST_NET_INTERRUPTS_ENABLED: AtomicBool = AtomicBool::new(true);

    extern "C" fn test_net_start(_opaque: u64, _runtime: *const AbiNetPortRuntime) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_bind(_opaque: u64, _if_id: u16) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_submit_tx(
        _opaque: u64,
        submission: *const AbiNetTxSubmission,
        _meta: AbiNetTxMeta,
    ) -> i32 {
        if submission.is_null() {
            return AbiErrorCode::InvalidParam as i32;
        }
        let submission = unsafe { &*submission };
        let Some(_segments) = submission.regions() else {
            return AbiErrorCode::InvalidParam as i32;
        };
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_poll(_opaque: u64, _if_id: u16) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_handle_event(
        _opaque: u64,
        _if_id: u16,
        _event: AbiNetDriverEvent,
    ) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_stats(_opaque: u64, out: *mut AbiNetPortStats) -> i32 {
        if out.is_null() {
            return AbiErrorCode::InvalidParam as i32;
        }
        unsafe {
            *out = AbiNetPortStats::default();
        }
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_stop(_opaque: u64) -> i32 {
        AbiErrorCode::Success as i32
    }

    extern "C" fn test_net_set_interrupts_enabled(_opaque: u64, enabled: bool) -> i32 {
        TEST_NET_INTERRUPT_CALLS.fetch_add(1, Ordering::Relaxed);
        TEST_NET_INTERRUPTS_ENABLED.store(enabled, Ordering::Release);
        AbiErrorCode::Success as i32
    }

    fn test_net_info(port_index: u16) -> AbiNetPortInfo {
        AbiNetPortInfo {
            port_id: 0x9000 + port_index as u64,
            queue_pairs: 1,
            max_tx_segments: 1,
            mtu: 1500,
            flags: 0,
            mac: [0x02, 0, 0, 0, 0, port_index as u8],
            reserved0: [0; 2],
            name_ptr: core::ptr::null(),
            name_len: 0,
        }
    }

    fn test_net_registration(port_index: u16) -> AbiNetPortRegistration {
        AbiNetPortRegistration::new(
            test_net_info(port_index),
            0,
            AbiNetPortOps {
                start: test_net_start,
                bind: test_net_bind,
                submit_tx_chain: test_net_submit_tx,
                poll: test_net_poll,
                handle_event: test_net_handle_event,
                stats: test_net_stats,
                stop: test_net_stop,
                set_interrupts_enabled: test_net_set_interrupts_enabled,
            },
        )
    }

    fn test_block_registration(device_id: u64, namespace_id: u32) -> AbiBlockDeviceRegistration {
        AbiBlockDeviceRegistration {
            abi_size: core::mem::size_of::<AbiBlockDeviceRegistration>() as u64,
            info: AbiBlockDeviceInfo {
                device_id,
                namespace_id,
                block_size: 512,
                block_count: 2048,
                max_transfer_blocks: 128,
                transport: AbiBlockTransport::Nvme as u32,
                flags: 0,
                controller_id: 0,
                port_id: 0,
            },
            queue: kernel_api::abi::driver::AbiBlockQueueInfo {
                device: kernel_api::abi::driver::PackedPciLocation::new(0, 0, 4, 0),
                index: 0,
                capacity: 32,
                generation: 1,
            },
            opaque: 0,
            submit: test_block_submit,
            poll: test_block_poll,
            is_ready: test_block_ready,
            stop: test_block_stop,
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn block_registration_validates_geometry_before_owner_admission() {
        let mut registration = test_block_registration(0x100, 1);
        registration.info.block_count = 0;
        let registry = BlockBridgeRegistry::new();
        assert_eq!(
            registry.register(DomainId::new(11), &registration),
            Err(AbiErrorCode::InvalidParam)
        );
        assert!(registry.storage_devices().is_empty());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn nvme_namespace_registry_enforces_unique_namespace_and_owner() {
        let registry = NvmeNamespaceRegistry::new();
        let owner_a = DomainId::new(21);
        let owner_b = DomainId::new(22);
        let registration = AbiNvmeNamespaceRegistration::new(AbiNvmeNamespaceInfo {
            device_id: 0x200,
            namespace_id: 7,
            block_size: 4096,
            max_transfer_blocks: 256,
            max_sgl_entries: 32,
            total_blocks: 4096,
            controller_id: 0,
            flags: 0,
        });

        let handle = registry
            .register(owner_a, &registration)
            .expect("namespace registration");
        assert_eq!(
            registry.register(owner_b, &registration),
            Err(AbiErrorCode::DeviceBusy)
        );
        assert_eq!(
            registry.unregister(owner_b, handle),
            Err(AbiErrorCode::PermissionDenied)
        );
        registry.cleanup_owner(owner_a);
        assert!(
            registry
                .entries
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn netdev_adapter_v3_invokes_interrupt_toggle_callback() {
        TEST_NET_INTERRUPT_CALLS.store(0, Ordering::Relaxed);
        TEST_NET_INTERRUPTS_ENABLED.store(true, Ordering::Release);

        let registration = test_net_registration(2);
        let adapter = NetdevPortAdapter::new(
            DomainId::KERNEL,
            &registration,
            "test-net",
            IommuDeviceId {
                segment: 0,
                bus: 0,
                device: 2,
                function: 0,
            },
        )
        .expect("v3 adapter");

        assert_eq!(adapter.set_interrupts_enabled(false), Ok(()));
        assert_eq!(TEST_NET_INTERRUPT_CALLS.load(Ordering::Relaxed), 1);
        assert!(!TEST_NET_INTERRUPTS_ENABLED.load(Ordering::Acquire));
    }
}
