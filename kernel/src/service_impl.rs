// ============================================================================
// kernel/src/service_impl.rs - KernelServices Implementation
// ============================================================================
//!
//! # ExoKernel Implementation of KernelServices
//!
//! This module implements the `KernelServices` trait from `kernel_api`,
//! bridging the contract defined in the interface to the kernel's internal
//! implementations.

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::KapiResult;
use kernel_api::dma::{CpuOwned as KapiCpuOwned, DmaSlice};
use kernel_api::error::KapiError;
use kernel_api::ipc::ChannelHandle;
use kernel_api::resource::fs::{FileHandle, OpenMode};
use kernel_api::resource::net::{Packet, RawEndpointHandle, TcpEndpoint};
use kernel_api::resource::storage::{
    DirectBlockHandle, NvmeIoHandle, NvmeIoPriority, NvmeIoResult, NvmeIoType, NvmeRwRequest,
};
use kernel_api::resource::task::TaskHandle;
use kernel_api::service::kernel::KernelServices;

use crate::io::dma;
use crate::sync::PoisonLock;
use crate::task;
use crate::task::context;

type DmaBuffer = DmaSlice<KapiCpuOwned>;

// ============================================================================
// File Handle Registry
// ============================================================================

struct FileHandleEntry {
    path: String,
    mode: OpenMode,
    position: u64,
    token: Option<u64>,
    owner: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelRole {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChannelEntry {
    channel_id: u64,
    role: ChannelRole,
}

struct ChannelRegistry {
    channels: PoisonLock<BTreeMap<u64, ChannelEntry>>,
    next_id: AtomicU64,
    next_channel_id: AtomicU64,
}

impl ChannelRegistry {
    const fn new() -> Self {
        Self {
            channels: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            next_channel_id: AtomicU64::new(1),
        }
    }
    fn allocate_channel_id(&self) -> u64 {
        self.next_channel_id.fetch_add(1, Ordering::Relaxed)
    }
    fn register(&self, entry: ChannelEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, entry);
        id
    }
    fn unregister(&self, id: u64) -> Option<ChannelEntry> {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

struct FileHandleRegistry {
    handles: PoisonLock<BTreeMap<u64, FileHandleEntry>>,
    next_id: AtomicU64,
}

impl FileHandleRegistry {
    const fn new() -> Self {
        Self {
            handles: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
    fn register(&self, entry: FileHandleEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, entry);
        id
    }
    fn unregister(&self, id: u64) -> Option<FileHandleEntry> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

static FILE_HANDLE_REGISTRY: FileHandleRegistry = FileHandleRegistry::new();
static CHANNEL_REGISTRY: ChannelRegistry = ChannelRegistry::new();

struct DmaEntry {
    buffer: Box<dyn core::any::Any + Send>,
    phys: u64,
    owner: u64,
}

struct DmaRegistry {
    buffers: PoisonLock<BTreeMap<usize, DmaEntry>>,
}

impl DmaRegistry {
    const fn new() -> Self {
        Self {
            buffers: PoisonLock::new(BTreeMap::new()),
        }
    }
    fn register_with_key(
        &self,
        key: usize,
        buffer: Box<dyn core::any::Any + Send>,
        phys: u64,
        owner: u64,
    ) {
        self.buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                key,
                DmaEntry {
                    buffer,
                    phys,
                    owner,
                },
            );
    }
    fn unregister(&self, virt_ptr: usize) -> Option<DmaEntry> {
        self.buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&virt_ptr)
    }
    fn get_owner(&self, virt_ptr: usize) -> Option<u64> {
        self.buffers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&virt_ptr)
            .map(|e| e.owner)
    }
}

struct PhysOwnershipRegistry {
    ranges: PoisonLock<BTreeMap<u64, (usize, u64)>>,
}

impl PhysOwnershipRegistry {
    const fn new() -> Self {
        Self {
            ranges: PoisonLock::new(BTreeMap::new()),
        }
    }
    fn register(&self, phys: u64, size: usize, owner: u64) {
        self.ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(phys, (size, owner));
    }
    fn unregister(&self, phys: u64) {
        self.ranges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&phys);
    }
    fn is_owned_by(&self, phys: u64, size: usize, domain_id: u64) -> bool {
        let ranges = self.ranges.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((&start, &(r_size, r_owner))) = ranges.range(..=phys).next_back() {
            if r_owner == domain_id
                && phys >= start
                && (phys + size as u64) <= (start + r_size as u64)
            {
                return true;
            }
        }
        false
    }
}

static DMA_REGISTRY: DmaRegistry = DmaRegistry::new();
static PHYS_OWNERSHIP_REGISTRY: PhysOwnershipRegistry = PhysOwnershipRegistry::new();

use crate::io::iommu::types::DeviceId as IommuDeviceId;
use x86_64::PhysAddr;
mod kernel_services;
pub use kernel_services::*;

struct IommuMapping {
    device: IommuDeviceId,
    iova: u64,
    size: u64,
}

impl IommuMapping {
    fn unmap(self) {
        let _ = crate::io::iommu::api::unmap_for_device(&self.device, self.iova, self.size);
    }
}

struct NvmeDmaContextEntry {
    dma: crate::io::nvme::dma::NvmeDmaRegion,
    owner: u64,
}

struct NvmeDmaContextRegistry {
    contexts: PoisonLock<BTreeMap<u64, NvmeDmaContextEntry>>,
    next_id: AtomicU64,
}

impl NvmeDmaContextRegistry {
    const fn new() -> Self {
        Self {
            contexts: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
    fn register(&self, entry: NvmeDmaContextEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.contexts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, entry);
        id
    }
    fn unregister(&self, id: u64) -> Option<NvmeDmaContextEntry> {
        self.contexts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

static NVME_DMA_CONTEXT_REGISTRY: NvmeDmaContextRegistry = NvmeDmaContextRegistry::new();

struct IommuMappingRegistry {
    mappings: PoisonLock<BTreeMap<u64, IommuMapping>>,
    next_id: AtomicU64,
}

impl IommuMappingRegistry {
    const fn new() -> Self {
        Self {
            mappings: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
    fn register(&self, mapping: IommuMapping) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.mappings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, mapping);
        id
    }
    fn unregister(&self, id: u64) -> Option<IommuMapping> {
        self.mappings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

static IOMMU_MAPPING_REGISTRY: IommuMappingRegistry = IommuMappingRegistry::new();

fn map_for_iommu(
    device: Option<IommuDeviceId>,
    phys_addr: u64,
    size: usize,
) -> Result<(u64, Option<IommuMapping>), KapiError> {
    if !crate::io::iommu::api::is_iommu_enabled() {
        if crate::io::iommu::api::is_iommu_required() {
            return Err(KapiError::IoError);
        }
        if !crate::io::iommu::api::is_unsafe_identity_mapping_allowed() {
            return Err(KapiError::IoError);
        }
        return Ok((phys_addr, None));
    }
    let dev = device.ok_or(KapiError::IoError)?;
    let map_len = crate::io::nvme::dma::align_up_page(size);
    let iova = unsafe {
        crate::io::iommu::api::map_for_device(&dev, PhysAddr::new(phys_addr), map_len as u64)
    }
    .map_err(|_| KapiError::IoError)?;
    Ok((
        iova,
        Some(IommuMapping {
            device: dev,
            iova,
            size: map_len as u64,
        }),
    ))
}

struct NvmeOpenEntry {
    device_id: u64,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    owner: u64,
    token: Option<u64>,
}

struct NvmeDirectRegistry {
    opens: PoisonLock<BTreeMap<u64, NvmeOpenEntry>>,
    next_id: AtomicU64,
}

impl NvmeDirectRegistry {
    const fn new() -> Self {
        Self {
            opens: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
    fn register(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        block_size: u32,
        owner: u64,
        token: Option<u64>,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.opens.lock().unwrap_or_else(|e| e.into_inner()).insert(
            id,
            NvmeOpenEntry {
                device_id,
                start_block,
                block_count,
                block_size,
                owner,
                token,
            },
        );
        id
    }
    fn unregister_if_owner_or_admin(&self, id: u64, caller: u64) -> Option<NvmeOpenEntry> {
        let mgr = crate::security::capability::manager();
        let has_admin = mgr.has_capability(caller, crate::security::capability::CAP_SYS_ADMIN);
        let mut opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = opens.get(&id) {
            if entry.owner == caller || has_admin {
                return opens.remove(&id);
            }
        }
        None
    }
}

static NVME_DIRECT_REGISTRY: NvmeDirectRegistry = NvmeDirectRegistry::new();

pub struct ExoKernel;

impl ExoKernel {
    pub const fn new() -> Self {
        ExoKernel
    }
}
