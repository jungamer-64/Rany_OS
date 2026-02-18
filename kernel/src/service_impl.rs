// ============================================================================
// kernel/src/service_impl.rs - KernelServices Implementation
// ============================================================================
//!
//! # ExoKernel Implementation of KernelServices
//!
//! This module implements the `KernelServices` trait from `kernel_api`,
//! bridging the contract defined in the interface to the kernel's internal
//! implementations.
//!
//! ## Design (設計書準拠)
//! - SPL: Single Privilege Level - all calls are direct function calls
//! - No syscall overhead - just vtable dispatch
//! - Type-safe capability model via traits
//!
//! ## Task Integration
//! Uses `per_core_executor::Task::new_boxed()` to avoid double-boxing
//! when receiving pre-boxed futures from external callers.

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::error::KapiError;
use kernel_api::KapiResult;
use kernel_api::services::KernelServices;
use kernel_api::{
    ChannelHandle, DirectBlockHandle, DmaBuffer, FileHandle, NvmeDmaHandle,
    NvmeIoHandle, NvmeIoPriority, NvmeIoResult, NvmeIoType, NvmeRwRequest,
    OpenMode, Packet, RawSocketHandle, TaskHandle, TcpEndpoint,
};
use spin::Mutex;

use crate::io::dma;
use crate::task::context;
use crate::task::per_core_executor::{Priority, Task, executor_manager};
use crate::task::timer;

// ============================================================================
// File Handle Registry
// ============================================================================

/// Entry for an open file handle
struct FileHandleEntry {
    path: String,
    mode: OpenMode,
    position: u64,
    token: Option<u64>,
    owner: u64,
}

// Channel Registry for IPC
use crate::ipc::pipe::{PipeReader, PipeWriter};

enum ChannelEntry {
    Reader(PipeReader),
    Writer(PipeWriter),
}

struct ChannelRegistry {
    channels: Mutex<BTreeMap<u64, ChannelEntry>>,
    next_id: AtomicU64,
}

impl ChannelRegistry {
    const fn new() -> Self {
        Self {
            channels: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, entry: ChannelEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.channels.lock().insert(id, entry);
        id
    }

    fn unregister(&self, id: u64) -> Option<ChannelEntry> {
        self.channels.lock().remove(&id)
    }
}

/// Registry for tracking open file handles
struct FileHandleRegistry {
    handles: Mutex<BTreeMap<u64, FileHandleEntry>>,
    next_id: AtomicU64,
}

impl FileHandleRegistry {
    const fn new() -> Self {
        Self {
            handles: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, entry: FileHandleEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().insert(id, entry);
        id
    }

    fn unregister(&self, id: u64) -> Option<FileHandleEntry> {
        self.handles.lock().remove(&id)
    }

/// Return a list of handle IDs owned by `owner` (domain id).
fn list_handles_by_owner(&self, owner: u64) -> alloc::vec::Vec<u64> {
        let mut result = alloc::vec::Vec::new();
        let handles = self.handles.lock();
        for (id, entry) in handles.iter() {
            if entry.owner == owner {
                result.push(*id);
            }
        }
        result
    }

    /// Get the registered path for a given handle id.
    fn get_handle_path(&self, id: u64) -> Option<String> {
        self.handles.lock().get(&id).map(|e| e.path.clone())
    }
}

/// Global file handle registry
static FILE_HANDLE_REGISTRY: FileHandleRegistry = FileHandleRegistry::new();
static CHANNEL_REGISTRY: ChannelRegistry = ChannelRegistry::new();

// Accessors for per-domain file handles (used by procfs)
pub(crate) fn file_handles_for_owner(owner: u64) -> alloc::vec::Vec<u64> {
    FILE_HANDLE_REGISTRY.list_handles_by_owner(owner)
}

pub(crate) fn file_handle_path(handle_id: u64) -> Option<String> {
    FILE_HANDLE_REGISTRY.get_handle_path(handle_id)
}

// DMA registry stores heap allocated TypedDmaSlice instances keyed by
// the virtual pointer to the buffer so we can free them later.
struct DmaRegistry {
    /// Registry of DMA buffers keyed by virtual address.
    /// Uses `Box<dyn Any + Send>` to support both CoherentDmaBuffer and TypedDmaSlice.
    buffers: Mutex<BTreeMap<usize, Box<dyn core::any::Any + Send>>>,
}

impl DmaRegistry {
    const fn new() -> Self {
        Self {
            buffers: Mutex::new(BTreeMap::new()),
        }
    }

    fn register(
        &self,
        buf: Box<dyn core::any::Any + Send>,
    ) -> usize {
        // Register with a runtime-generated key based on the pointer value.
        // Since we don't have direct access to the inner buffer here,
        // the caller must provide the key externally if needed.
        // For now, use a simple counter-based approach.
        // Actually, we'll let the caller register with a known key.
        0 // placeholder - caller should use register_with_key
    }

    fn register_with_key(
        &self,
        key: usize,
        buf: Box<dyn core::any::Any + Send>,
    ) {
        self.buffers.lock().insert(key, buf);
    }

    fn unregister(
        &self,
        virt_ptr: usize,
    ) -> Option<Box<dyn core::any::Any + Send>> {
        self.buffers.lock().remove(&virt_ptr)
    }
}

static DMA_REGISTRY: DmaRegistry = DmaRegistry::new();

// ============================================================================
// NVMe DMA Context Registry (Option B-2: Full Abstraction)
// ============================================================================

use crate::io::dma::{CpuOwned, DeviceOwned, SliceDmaGuard, TypedDmaSlice};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use x86_64::PhysAddr;
mod _split_1;
pub use _split_1::*;

const NVME_PAGE_SIZE: usize = 4096;

/// IOMMU mapping info for cleanup
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

/// PRP list page (DMA buffer for PRP entries)
struct PrpListPage {
    dev: TypedDmaSlice<DeviceOwned>,
    guard: SliceDmaGuard,
    map: Option<IommuMapping>,
    iova: u64,
}

/// Chain of PRP list pages
struct PrpListChain {
    pages: alloc::vec::Vec<PrpListPage>,
}

impl PrpListChain {
    fn first_iova(&self) -> u64 {
        self.pages.first().map(|p| p.iova).unwrap_or(0)
    }

    fn complete(self) {
        for page in self.pages {
            let _ = page.guard.complete(page.dev);
            if let Some(m) = page.map {
                m.unmap();
            }
        }
    }
}

/// Stored DMA context entry
struct NvmeDmaContextEntry {
    data_dev: Option<TypedDmaSlice<DeviceOwned>>,
    data_guard: Option<SliceDmaGuard>,
    prp_list: Option<PrpListChain>,
    data_map: Option<IommuMapping>,
    logical_len: usize,
}

impl NvmeDmaContextEntry {
    fn complete(mut self) -> TypedDmaSlice<CpuOwned> {
        if let Some(prp) = self.prp_list.take() {
            prp.complete();
        }
        let data_dev = self.data_dev.take().expect("missing data_dev");
        let data_guard = self.data_guard.take().expect("missing data_guard");
        let data = data_guard.complete(data_dev);
        if let Some(m) = self.data_map.take() {
            m.unmap();
        }
        data
    }
}

struct NvmeDmaContextRegistry {
    contexts: Mutex<BTreeMap<u64, NvmeDmaContextEntry>>,
    next_id: AtomicU64,
}

impl NvmeDmaContextRegistry {
    const fn new() -> Self {
        Self {
            contexts: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, entry: NvmeDmaContextEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.contexts.lock().insert(id, entry);
        id
    }

    fn unregister(&self, id: u64) -> Option<NvmeDmaContextEntry> {
        self.contexts.lock().remove(&id)
    }
}

static NVME_DMA_CONTEXT_REGISTRY: NvmeDmaContextRegistry = NvmeDmaContextRegistry::new();

// IOMMU Mapping Registry for tracking active mappings
struct IommuMappingRegistry {
    mappings: Mutex<BTreeMap<u64, IommuMapping>>,
    next_id: AtomicU64,
}

impl IommuMappingRegistry {
    const fn new() -> Self {
        Self {
            mappings: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, mapping: IommuMapping) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.mappings.lock().insert(id, mapping);
        id
    }

    fn unregister(&self, id: u64) -> Option<IommuMapping> {
        self.mappings.lock().remove(&id)
    }
}

static IOMMU_MAPPING_REGISTRY: IommuMappingRegistry = IommuMappingRegistry::new();

// Helper: align up to page size
fn align_up_page(value: usize) -> usize {
    (value + NVME_PAGE_SIZE - 1) & !(NVME_PAGE_SIZE - 1)
}

// Helper: map physical address for IOMMU
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
    let map_len = align_up_page(size);
    let iova = unsafe {
        crate::io::iommu::api::map_for_device(&dev, PhysAddr::new(phys_addr), map_len as u64)
    }
    .map_err(|_| KapiError::IoError)?;

    Ok((iova, Some(IommuMapping { device: dev, iova, size: map_len as u64 })))
}

// Helper: build PRP list for multi-page transfers
fn build_prp_list_internal(
    device: Option<IommuDeviceId>,
    base_addr: u64,
    len: usize,
) -> Result<(u64, Option<PrpListChain>), KapiError> {
    if len == 0 {
        return Err(KapiError::IoError);
    }

    let pages = (len + NVME_PAGE_SIZE - 1) / NVME_PAGE_SIZE;
    if pages <= 1 {
        return Ok((0, None));
    }
    if pages == 2 {
        return Ok((base_addr + NVME_PAGE_SIZE as u64, None));
    }

    // Need PRP list for > 2 pages
    let total_entries = pages - 1;
    let (mut list_buffers, list_iovas, list_maps) =
        allocate_prp_list_buffers(device, total_entries)?;

    fill_prp_entries(&mut list_buffers, &list_iovas, base_addr, total_entries)?;

    let mut prp_pages = alloc::vec::Vec::with_capacity(list_buffers.len());
    for ((list, map), iova) in list_buffers.into_iter().zip(list_maps).zip(list_iovas) {
        let (dev, guard) = list.start_dma();
        prp_pages.push(PrpListPage { dev, guard, map, iova });
    }

    let chain = PrpListChain { pages: prp_pages };
    let prp2 = chain.first_iova();
    Ok((prp2, Some(chain)))
}

/// PRP リスト用のDMAバッファを確保しIOMMUマッピングを行う
fn allocate_prp_list_buffers(
    device: Option<IommuDeviceId>,
    total_entries: usize,
) -> Result<(
    alloc::vec::Vec<TypedDmaSlice<CpuOwned>>,
    alloc::vec::Vec<u64>,
    alloc::vec::Vec<Option<IommuMapping>>,
), KapiError> {
    let mut remaining = total_entries;
    let mut list_buffers = alloc::vec::Vec::new();

    while remaining > 0 {
        let list = TypedDmaSlice::<CpuOwned>::new(NVME_PAGE_SIZE)
            .ok_or(KapiError::OutOfMemory)?;
        list_buffers.push(list);
        remaining = if remaining > 512 { remaining - 511 } else { 0 };
    }

    let mut list_iovas = alloc::vec::Vec::with_capacity(list_buffers.len());
    let mut list_maps = alloc::vec::Vec::with_capacity(list_buffers.len());
    for list in &list_buffers {
        let list_phys = list.phys_addr().as_u64();
        let (list_addr, list_map) = map_for_iommu(device, list_phys, NVME_PAGE_SIZE)?;
        list_iovas.push(list_addr);
        list_maps.push(list_map);
    }

    Ok((list_buffers, list_iovas, list_maps))
}

/// PRPエントリにページアドレスとチェインポインタを書き込む
fn fill_prp_entries(
    list_buffers: &mut [TypedDmaSlice<CpuOwned>],
    list_iovas: &[u64],
    base_addr: u64,
    total_entries: usize,
) -> Result<(), KapiError> {
    let mut filled = 0usize;
    for idx in 0..list_buffers.len() {
        let remaining_entries = total_entries - filled;
        let needs_chain = remaining_entries > 512;
        let data_capacity = if needs_chain { 511 } else { remaining_entries };

        let entries = unsafe {
            core::slice::from_raw_parts_mut(
                list_buffers[idx].as_mut_slice().as_mut_ptr() as *mut u64,
                NVME_PAGE_SIZE / 8,
            )
        };

        for j in 0..data_capacity {
            entries[j] = base_addr + ((filled + j + 1) * NVME_PAGE_SIZE) as u64;
        }

        if needs_chain {
            entries[511] = list_iovas.get(idx + 1).copied().ok_or(KapiError::IoError)?;
        }

        filled += data_capacity;
    }
    Ok(())
}

// ============================================================================
// NVMe Direct Handle Registry
// ============================================================================

/// Entry for a kernel-opened direct block handle
struct NvmeOpenEntry {
    device_id: u64,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    owner: u64,
    token: Option<u64>,
}

struct NvmeDirectRegistry {
    opens: Mutex<BTreeMap<u64, NvmeOpenEntry>>,
    next_id: AtomicU64,
}

impl NvmeDirectRegistry {
    const fn new() -> Self {
        Self {
            opens: Mutex::new(BTreeMap::new()),
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
        self.opens.lock().insert(
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

    /// Unregister only if caller is owner or has CAP_SYS_ADMIN
    fn unregister_if_owner_or_admin(&self, id: u64, caller: u64) -> Option<NvmeOpenEntry> {
        // Check permission first
        let mgr = crate::security::capability::manager();
        let has_admin = mgr.has_capability(caller, crate::security::capability::CAP_SYS_ADMIN);
        let mut opens = self.opens.lock();
        if let Some(entry) = opens.get(&id) {
            if entry.owner == caller || has_admin {
                return opens.remove(&id);
            }
        }
        None
    }
}

static NVME_DIRECT_REGISTRY: NvmeDirectRegistry = NvmeDirectRegistry::new();

// ============================================================================
// ExoKernel: The KernelServices Implementation
// ============================================================================

/// ExoKernel - The concrete implementation of KernelServices
///
/// This struct has no fields; all state is managed via static globals
/// within the kernel. This keeps the implementation simple and allows
/// registration as a `&'static dyn KernelServices`.
pub struct ExoKernel;

impl ExoKernel {
    /// Create the singleton instance
    pub const fn new() -> Self {
        ExoKernel
    }
}
