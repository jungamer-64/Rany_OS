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

// SAFETY: ExoKernel is stateless and accesses thread-safe globals
unsafe impl Send for ExoKernel {}
unsafe impl Sync for ExoKernel {}

impl KernelServices for ExoKernel {
    // ========================================================================
    // Task Management
    // ========================================================================

    fn spawn_task(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Result<TaskHandle, KapiError> {
        // Use Task::new_boxed to avoid double-boxing (optimization)
        let task = Task::new_boxed(future, Priority::Normal, None);
        let task_id = task.metadata.id.as_u64();

        // Submit to ExecutorManager for load-balanced scheduling
        executor_manager().spawn(task);

        Ok(TaskHandle::new(task_id))
    }

    fn current_tick(&self) -> u64 {
        timer::current_tick()
    }

    fn current_task_id(&self) -> u64 {
        context::current_task_id()
    }

    // ========================================================================
    // Memory Management
    // ========================================================================

    fn alloc_dma(&self, size: usize) -> Result<DmaBuffer, KapiError> {
        // Use CoherentDmaBuffer for proper DMA allocation with correct physical address
        match dma::CoherentDmaBuffer::new(size, dma::DmaMemoryAttributes::MMIO) {
            Some(buffer) => {
                let phys = buffer.phys_addr().as_u64();
                let dev_addr = buffer.device_addr();
                let virt_ptr = unsafe { buffer.as_slice().as_ptr() } as usize;
                // Box up the buffer and register by virtual address so it can be freed later
                let boxed: Box<dyn core::any::Any + Send> = Box::new(buffer);
                DMA_REGISTRY.register_with_key(virt_ptr, boxed);
                Ok(DmaBuffer::new_with_device_addr(phys, dev_addr, virt_ptr as *mut u8, size))
            }
            None => Err(KapiError::OutOfMemory),
        }
    }

    fn free_dma(&self, buffer: DmaBuffer) {
        // Try to lookup the registered buffer by its virtual pointer
        let virt_ptr = buffer.as_ptr() as usize;
        if DMA_REGISTRY.unregister(virt_ptr).is_some() {
            // Successfully unregistered and dropped
            return;
        }

        // If we couldn't find it, quietly ignore (or log) — do not panic in kernel
        log::info!("[KAPI] free_dma: unknown buffer: {:x}\n", virt_ptr);
    }

    // ========================================================================
    // I/O Operations
    // ========================================================================

    fn port_read_u8(&self, port: u16) -> u8 {
        hal::port_io::PortU8::new(port).read()
    }

    fn port_write_u8(&self, port: u16, value: u8) {
        hal::port_io::PortU8::new(port).write(value)
    }

    // ========================================================================
    // Logging
    // ========================================================================

    fn log(&self, message: &str) {
        log::info!("{}", message);
    }

    // ========================================================================
    // Network (Connected to network stack)
    // ========================================================================

    fn net_create_endpoint(&self) -> Result<TcpEndpoint, KapiError> {
        use crate::net::endpoint::create_tcp_socket;

        let owned = create_tcp_socket();
        let fd = owned.fd();

        // Detach from OwnedSocket so it remains registered in SocketManager
        // and doesn't close on drop.
        let _ = owned.into_inner();

        Ok(TcpEndpoint::new(fd.raw() as u64))
    }
    fn net_close_endpoint(&self, endpoint: TcpEndpoint) -> Result<(), KapiError> {
        use crate::net::endpoint::{SocketFd, socket_manager};

        let fd = SocketFd::from_raw(endpoint.id() as u32);

        if let Some(mgr_lock) = socket_manager() {
            let guard = mgr_lock.read();
            if let Some(mgr) = guard.as_ref() {
                if mgr.unregister(fd).is_some() {
                    return Ok(());
                }
            }
        }

        Err(KapiError::InvalidHandle)
    }

    fn net_recv_packet(&self, endpoint: TcpEndpoint) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        // Create and await RecvFuture
                        let fut = crate::net::endpoint::futures::RecvFuture::new(socket.clone(), crate::net::stack::MAX_PACKET_SIZE);
                        match fut.await {
                            Ok(vec) => Ok(Packet::new(vec)),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    fn net_send_packet(&self, endpoint: TcpEndpoint, packet: Packet) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        // Clone/convert packet data for socket send
                        let data = packet.data().to_vec();
                        let fut = crate::net::endpoint::futures::SendFuture::new(socket.clone(), data);
                        match fut.await {
                            Ok(_) => Ok(()),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    fn net_create_raw_socket(&self) -> Result<RawSocketHandle, KapiError> {
        use crate::net::endpoint::create_raw_socket;

        let owned = create_raw_socket();
        let fd = owned.fd();

        // Detach so it remains registered
        let _ = owned.into_inner();

        Ok(RawSocketHandle::new(fd.raw() as u64))
    }

    fn net_close_raw_socket(&self, endpoint: RawSocketHandle) -> Result<(), KapiError> {
        use crate::net::endpoint::{SocketFd, socket_manager};

        let fd = SocketFd::from_raw(endpoint.id() as u32);

        if let Some(mgr_lock) = socket_manager() {
            let guard = mgr_lock.read();
            if let Some(mgr) = guard.as_ref() {
                if mgr.unregister(fd).is_some() {
                    return Ok(());
                }
            }
        }

        Err(KapiError::InvalidHandle)
    }

    fn net_recv_raw(&self, endpoint: RawSocketHandle) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        let fut = crate::net::endpoint::futures::RecvFuture::new(socket.clone(), crate::net::stack::MAX_PACKET_SIZE);
                        match fut.await {
                            Ok(vec) => Ok(Packet::new(vec)),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    fn net_send_raw(&self, endpoint: RawSocketHandle, packet: Packet) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        let data = packet.data().to_vec();
                        let fut = crate::net::endpoint::futures::SendFuture::new(socket.clone(), data);
                        match fut.await {
                            Ok(_) => Ok(()),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    // ========================================================================
    // Filesystem (Connected to memfs)
    // ========================================================================

    fn fs_open(&self, path: &str, mode: OpenMode) -> Result<FileHandle, KapiError> {
        // Backward-compatible: open without token
        self.fs_open_with_token(path, mode, None)
    }

    fn fs_open_with_token(&self, path: &str, mode: OpenMode, token: Option<u64>) -> Result<FileHandle, KapiError> {
        use crate::fs::memfs;

        // Check if file exists
        let path_buf = alloc::string::String::from(path);

        match mode {
            OpenMode::Read => {
                // For read, file must exist
                if memfs::stat_file(&path_buf, "/").is_err() {
                    return Err(KapiError::NotFound);
                }
            }
            OpenMode::Write | OpenMode::ReadWrite | OpenMode::Append | OpenMode::Create => {
                // For write, create if not exists
                if memfs::stat_file(&path_buf, "/").is_err() {
                    if let Err(_) = memfs::touch_file(&path_buf, "/") {
                        return Err(KapiError::IoError);
                    }
                }
            }
        }

        let caller = context::current_subject().domain.as_u64();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_FOWNER) {
                return Err(KapiError::PermissionDenied);
            }

            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register in file handle table (recording owner domain for /proc/<pid>/fd)
        let handle_id = FILE_HANDLE_REGISTRY.register(FileHandleEntry {
            path: path_buf,
            mode,
            position: 0,
            token,
            owner: caller,
        });

        Ok(FileHandle::new(handle_id, mode))
    }

    fn fs_close(&self, handle: FileHandle) -> Result<(), KapiError> {
        let handle_id = handle.id();
        if let Some(entry) = FILE_HANDLE_REGISTRY.unregister(handle_id) {
            if let Some(t) = entry.token {
                let _ = crate::security::capability::manager().decrement_in_flight(t);
            }
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }

    fn nvme_open_direct(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
    ) -> Result<DirectBlockHandle, KapiError> {
        // Backward-compatible: open without token
        self.nvme_open_direct_with_token(device_id, start_block, block_count, None)
    }

    fn nvme_open_direct_with_token(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> Result<DirectBlockHandle, KapiError> {
        if block_count == 0 {
            return Err(KapiError::IoError);
        }

        let nsid = if device_id == 0 { 1 } else { device_id as u32 };
        let block_size =
            crate::io::nvme::with_driver(|driver| driver.namespace_block_size(nsid))
                .unwrap_or(512);

        let caller = context::current_subject().domain.as_u64();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_DMA) {
                return Err(KapiError::PermissionDenied);
            }
            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register the open in kernel registry and return a handle with open_id
        let id = NVME_DIRECT_REGISTRY.register(device_id, start_block, block_count, block_size, caller, token);
        Ok(DirectBlockHandle::new_with_id(device_id, start_block, block_count, block_size, id))
    }

    fn nvme_close_direct(&self, handle: DirectBlockHandle) -> Result<(), KapiError> {
        let id = handle.open_id();
        if id == 0 {
            return Err(KapiError::InvalidHandle);
        }

        let caller = context::current_subject().domain.as_u64();

        match NVME_DIRECT_REGISTRY.unregister_if_owner_or_admin(id, caller) {
            Some(entry) => {
                if let Some(t) = entry.token {
                    // Best-effort decrement
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                Ok(())
            }
            None => Err(KapiError::InvalidHandle),
        }
    }

    fn nvme_read_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .read_blocks_dma(block_offset, buffer)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_write_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .write_blocks_dma(block_offset, buffer)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_flush_direct(
        &self,
        handle: DirectBlockHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct.flush().await.map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_discard_direct(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        block_count: u64,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .discard(block_offset, block_count)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_block_size(&self, device_id: u64) -> Option<u64> {
        let nsid = if device_id == 0 { 1 } else { device_id as u32 };
        crate::io::nvme::with_driver(|driver| driver.namespace_block_size(nsid) as u64)
    }

    fn nvme_sgl_max_entries(&self, _device_id: u64) -> Option<usize> {
        crate::io::nvme::global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
            driver.sgl_max_entries()
        })
        .flatten()
    }

    fn nvme_prepare_dma_read(&self, _device_id: u64, len: usize) -> KapiResult<NvmeDmaHandle> {
        if len == 0 {
            return Err(KapiError::IoError);
        }

        let alloc_len = align_up_page(len);
        let data = TypedDmaSlice::<CpuOwned>::new(alloc_len)
            .ok_or(KapiError::OutOfMemory)?;
        let data_phys = data.phys_addr().as_u64();

        let device = crate::io::nvme::iommu_device();
        let (data_addr, data_map) = map_for_iommu(device, data_phys, alloc_len)?;
        let (prp2, prp_list) = build_prp_list_internal(device, data_addr, alloc_len)?;

        let (data_dev, data_guard) = data.start_dma();

        let entry = NvmeDmaContextEntry {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            prp_list,
            data_map,
            logical_len: len,
        };

        let id = NVME_DMA_CONTEXT_REGISTRY.register(entry);
        Ok(NvmeDmaHandle::new(id, data_addr, prp2, len))
    }

    fn nvme_prepare_dma_write(&self, _device_id: u64, data: &[u8]) -> KapiResult<NvmeDmaHandle> {
        if data.is_empty() {
            return Err(KapiError::IoError);
        }

        let alloc_len = align_up_page(data.len());
        let mut dma_buf = TypedDmaSlice::<CpuOwned>::new(alloc_len)
            .ok_or(KapiError::OutOfMemory)?;

        // Copy data into DMA buffer
        dma_buf.as_mut_slice()[..data.len()].copy_from_slice(data);
        if alloc_len > data.len() {
            dma_buf.as_mut_slice()[data.len()..].fill(0);
        }

        let data_phys = dma_buf.phys_addr().as_u64();
        let device = crate::io::nvme::iommu_device();
        let (data_addr, data_map) = map_for_iommu(device, data_phys, alloc_len)?;
        let (prp2, prp_list) = build_prp_list_internal(device, data_addr, alloc_len)?;

        let (data_dev, data_guard) = dma_buf.start_dma();

        let entry = NvmeDmaContextEntry {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            prp_list,
            data_map,
            logical_len: data.len(),
        };

        let id = NVME_DMA_CONTEXT_REGISTRY.register(entry);
        Ok(NvmeDmaHandle::new(id, data_addr, prp2, data.len()))
    }

    fn nvme_complete_dma_read(&self, handle: NvmeDmaHandle) -> KapiResult<alloc::vec::Vec<u8>> {
        let entry = NVME_DMA_CONTEXT_REGISTRY.unregister(handle.id())
            .ok_or(KapiError::InvalidHandle)?;
        let logical_len = entry.logical_len;
        let dma_slice = entry.complete();

        // Copy data from DMA buffer
        let mut result = alloc::vec![0u8; logical_len];
        result.copy_from_slice(&dma_slice.as_slice()[..logical_len]);
        Ok(result)
    }

    fn nvme_complete_dma_write(&self, handle: NvmeDmaHandle) -> KapiResult<()> {
        let entry = NVME_DMA_CONTEXT_REGISTRY.unregister(handle.id())
            .ok_or(KapiError::InvalidHandle)?;
        let _ = entry.complete();
        Ok(())
    }

    fn nvme_iommu_device_id(&self, _device_id: u64) -> Option<u64> {
        crate::io::nvme::iommu_device().map(|d| {
            // Pack IommuDeviceId into u64 for API boundary
            // DeviceId has public fields: segment, bus, device, function
            ((d.segment as u64) << 32) | ((d.bus as u64) << 16) | ((d.device as u64) << 8) | (d.function as u64)
        })
    }

    fn nvme_iommu_map(
        &self,
        _device_id: u64,
        phys_addr: u64,
        size: usize,
    ) -> KapiResult<(u64, u64)> {
        let device = crate::io::nvme::iommu_device();
        let (iova, mapping) = map_for_iommu(device, phys_addr, size)?;
        
        // If we have a mapping, register it and return the ID
        if let Some(m) = mapping {
            let id = IOMMU_MAPPING_REGISTRY.register(m);
            Ok((iova, id))
        } else {
            // No IOMMU - identity mapping
            Ok((iova, 0))
        }
    }

    fn nvme_iommu_unmap(&self, mapping_id: u64) -> KapiResult<()> {
        if mapping_id == 0 {
            // Identity mapping, nothing to unmap
            return Ok(());
        }
        
        if let Some(mapping) = IOMMU_MAPPING_REGISTRY.unregister(mapping_id) {
            mapping.unmap();
        }
        Ok(())
    }

    fn nvme_submit_rw(
        &self,
        request: NvmeRwRequest,
        io_type: NvmeIoType,
    ) -> KapiResult<NvmeIoHandle> {
        use crate::io::io_scheduler::{
            DeviceId as IoDeviceId, IoPriority, IoCommand, DmaBufHandle,
        };

        let device = IoDeviceId::Nvme {
            controller: 0,
            namespace: request.namespace_id,
        };

        let priority = match request.priority {
            NvmeIoPriority::Background => IoPriority::Background,
            NvmeIoPriority::Idle => IoPriority::Idle,
            NvmeIoPriority::Normal => IoPriority::Normal,
            NvmeIoPriority::High => IoPriority::High,
            NvmeIoPriority::Realtime => IoPriority::Realtime,
        };

        // Build IoCommand (new API) and submit via submit_io_command
        let command = match io_type {
            NvmeIoType::Read => IoCommand::BlockRead {
                lba: request.lba,
                blocks: request.blocks,
                bytes: request.bytes,
                buf: DmaBufHandle {
                    iova: request.prp1,
                    len: request.bytes,
                },
            },
            NvmeIoType::Write => IoCommand::BlockWrite {
                lba: request.lba,
                blocks: request.blocks,
                bytes: request.bytes,
                buf: DmaBufHandle {
                    iova: request.prp1,
                    len: request.bytes,
                },
            },
            NvmeIoType::Flush => IoCommand::Flush,
            NvmeIoType::Discard => IoCommand::Discard {
                lba: request.lba,
                blocks: request.blocks as u16,
            },
        };

        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
            device, command, priority,
        );
        let request_id = future.request_id().0;

        Ok(NvmeIoHandle::new(request_id))
    }

    fn nvme_wait_io(
        &self,
        handle: NvmeIoHandle,
    ) -> Pin<Box<dyn Future<Output = NvmeIoResult> + Send>> {
        use crate::io::io_scheduler::{IoRequestId, IoResult as SchedIoResult};

        let request_id = IoRequestId(handle.request_id());
        
        Box::pin(async move {
            // Poll the io_scheduler for completion
            loop {
                if let Some(result) = crate::io::io_scheduler::io_scheduler().take_result(request_id) {
                    return match result {
                        SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                        SchedIoResult::Error(e) => match e {
                            crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                            crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                            crate::io::io_scheduler::IoError::InvalidParameter => NvmeIoResult::InvalidParameter,
                            _ => NvmeIoResult::DeviceError,
                        },
                    };
                }
                // Yield to allow other tasks to run
                core::hint::spin_loop();
            }
        })
    }

    fn nvme_register_completion_hook(
        &self,
        handle: NvmeIoHandle,
        hook: Box<dyn FnOnce(NvmeIoResult) + Send>,
    ) {
        use crate::io::io_scheduler::{CompletionHook, IoRequestId, IoResult as SchedIoResult};

        let request_id = IoRequestId(handle.request_id());
        
        let wrapper: CompletionHook = Box::new(move |result: SchedIoResult| {
            let converted = match result {
                SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                SchedIoResult::Error(e) => match e {
                    crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                    crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                    crate::io::io_scheduler::IoError::InvalidParameter => NvmeIoResult::InvalidParameter,
                    _ => NvmeIoResult::DeviceError,
                },
            };
            hook(converted);
        });

        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, wrapper);
    }

    fn ipc_create_channel(&self) -> Result<(ChannelHandle, ChannelHandle), KapiError> {
        // Create a new pipe
        let pipe = crate::ipc::pipe::pipe();

        // Register reader and writer
        let reader_id = CHANNEL_REGISTRY.register(ChannelEntry::Reader(pipe.reader));
        let writer_id = CHANNEL_REGISTRY.register(ChannelEntry::Writer(pipe.writer));

        // info!(target: "ipc", "Created channel: reader={}, writer={}", reader_id, writer_id);

        Ok((ChannelHandle::new(writer_id), ChannelHandle::new(reader_id))) // Return (Sender, Receiver)
    }

    fn ipc_close(&self, channel: ChannelHandle) -> Result<(), KapiError> {
        let channel_id = channel.id();
        if CHANNEL_REGISTRY.unregister(channel_id).is_some() {
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }

    fn gui(&self) -> Option<&dyn kernel_api::gui::GuiServices> {
        #[cfg(not(any(test, feature = "bench")))]
        {
            // GUI services are available only if framebuffer exists
            if crate::graphics::framebuffer().is_some() {
                Some(self)
            } else {
                None
            }
        }

        #[cfg(any(test, feature = "bench"))]
        {
            // In test/bench builds, graphics subsystem is disabled
            None
        }
    }

    fn shell(&self) -> Option<&dyn kernel_api::shell::ShellServices> {
        // Shell services are always available
        Some(self)
    }
}

// ============================================================================
// GuiServices Implementation
// ============================================================================

use kernel_api::gui::{
    FramebufferInfo as KapiFramebufferInfo, GuiServices, InputStreamHandle,
    PixelFormat as KapiPixelFormat,
};
use kernel_api::security::DomainCapabilities;

impl GuiServices for ExoKernel {
    fn request_framebuffer(
        &self,
        access_token: &DomainCapabilities,
    ) -> Result<KapiFramebufferInfo, KapiError> {
        // Security check: require DMA or I/O capability for direct framebuffer access
        if !access_token.has_dma() && !access_token.has_io() {
            return Err(KapiError::PermissionDenied);
        }

        // Get framebuffer info from global
        #[cfg(not(any(test, feature = "bench")))]
        {
            crate::graphics::with_framebuffer(|fb| {
                let info = fb.info();

                // Convert graphic_types::PixelFormat to kernel_api::gui::PixelFormat
                let format = match info.format {
                    crate::graphics::PixelFormat::Rgba8888 => KapiPixelFormat::Rgb32,
                    crate::graphics::PixelFormat::Bgra8888 => KapiPixelFormat::Bgr32,
                    crate::graphics::PixelFormat::Rgb888 => KapiPixelFormat::Rgb24,
                    crate::graphics::PixelFormat::Bgr888 => KapiPixelFormat::Bgr24,
                    _ => KapiPixelFormat::Unknown,
                };

                Ok(KapiFramebufferInfo {
                    width: info.width as usize,
                    height: info.height as usize,
                    stride: info.stride as usize,
                    format,
                    vaddr: info.address as usize,
                    size: info.size(),
                })
            })
            .unwrap_or(Err(KapiError::ResourceExhausted))
        }
        #[cfg(any(test, feature = "bench"))]
        {
            // Graphics unavailable in test builds
            Err(KapiError::NotSupported)
        }
    }

    fn get_input_stream_handle(&self) -> Result<InputStreamHandle, KapiError> {
        // Return a fixed handle ID for the global HID input stream
        // In a full implementation, this would register with an input manager
        Ok(InputStreamHandle(1))
    }

    fn current_tick(&self) -> u64 {
        crate::task::timer::current_tick()
    }

    fn poll_input_event(&self) -> Option<kernel_api::gui::InputEvent> {
        use kernel_api::gui::{
            InputEvent, KeyEvent as KapiKeyEvent, KeyState as KapiKeyState,
        };
        use crate::io::hid::keyboard::KeyEventExt;
        use spin::Mutex;
        use crate::io::hid::keyboard::KeyboardStream;



        // Lazy initialization of the global keyboard stream
        // We use a static Mutex to hold the stream exclusively for GuiServices
        static KEYBOARD_STREAM: Mutex<Option<KeyboardStream>> = Mutex::new(None);


        // Poll Keyboard Stream
        let hid_event_opt = {
            let mut stream_guard = KEYBOARD_STREAM.lock();
            
            // Initialize if empty
            if stream_guard.is_none() {
                 match crate::io::hid::keyboard::take_stream() {
                    Ok(stream) => *stream_guard = Some(stream),
                    Err(_) => {
                        // Stream taken by someone else?
                        // Just log once or ignore?
                    }
                 }
            }

            if let Some(stream) = stream_guard.as_mut() {
                // Manually poll the stream using its synchronous interface
                stream.poll()
            } else {
                None
            }
        };

        if let Some(hid_event) = hid_event_opt {
            let kapi_state = match hid_event.state {
                crate::io::hid::KeyState::Pressed => KapiKeyState::Pressed,
                crate::io::hid::KeyState::Released => KapiKeyState::Released,
            };

            // Encode modifiers as bitfield
            let mod_bits = {
                let mut bits = 0u8;
                if hid_event.modifiers.shift {
                    bits |= 0x01;
                }
                if hid_event.modifiers.ctrl {
                    bits |= 0x02;
                }
                if hid_event.modifiers.alt {
                    bits |= 0x04;
                }
                if hid_event.modifiers.alt_gr {
                    bits |= 0x08;
                }
                if hid_event.modifiers.caps_lock {
                    bits |= 0x10;
                }
                bits
            };

            // `to_char()` returns an `Option<char>`. Convert to an ASCII
            // `u8` (0 if not printable) to match the `char_value` field in
            // the kernel API `KeyEvent` (which stores ASCII bytes).
            let char_value = hid_event.to_char().map(|c| c as u8).unwrap_or(0u8);

            let kapi_event = KapiKeyEvent {
                scancode: hid_event.raw_scancode,
                char_value,
                state: kapi_state,
                modifiers: mod_bits,
            };

            return Some(InputEvent::Key(kapi_event));
        }



        None
    }

    fn yield_control(&self) {
        // Synchronous yield - just hint to the scheduler that we're willing to yield
        // In an async context, the caller should use `.await` on yield_now() instead
        core::hint::spin_loop();
    }
}

// ============================================================================
// ShellServices Implementation
// ============================================================================

use kernel_api::shell::{
    DirEntry as KapiDirEntry, DomainInfo, DomainState as KapiDomainState, MemoryStats,
    ShellServices, SystemInfo as KapiSystemInfo,
};

fn map_domain_state(state: crate::domain_system::DomainState) -> KapiDomainState {
    match state {
        crate::domain_system::DomainState::Initializing => KapiDomainState::Initializing,
        crate::domain_system::DomainState::Running => KapiDomainState::Running,
        crate::domain_system::DomainState::Suspended => KapiDomainState::Suspended,
        crate::domain_system::DomainState::Stopped => KapiDomainState::Stopped,
        crate::domain_system::DomainState::Terminated => KapiDomainState::Terminated,
    }
}

fn ensure_domain_control(target: crate::domain_system::DomainId) -> Result<(), &'static str> {
    let subject = crate::task::current_subject();
    if subject.domain == target {
        return Ok(());
    }
    if subject
        .caps
        .has_capability(crate::security::capability::CAP_KILL)
    {
        return Ok(());
    }
    Err("Permission denied: owner or CAP_KILL required")
}

impl ShellServices for ExoKernel {
    fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            total_kb: crate::memory::total_memory_kb() as usize,
            free_kb: crate::memory::free_memory_kb() as usize,
            used_kb: crate::memory::used_memory_kb() as usize,
        }
    }

    fn current_tick(&self) -> u64 {
        crate::task::timer::current_tick()
    }

    fn list_domains(&self) -> alloc::vec::Vec<DomainInfo> {
        crate::domain_system::list_domain_snapshots()
            .into_iter()
            .map(|snap| DomainInfo {
                id: snap.id.as_u64(),
                name: snap.name,
                state: map_domain_state(snap.state),
                tasks: snap.tasks,
                memory_kb: (snap.memory_bytes / 1024) as usize,
                rrefs: snap.rrefs,
                last_error: snap.last_error,
            })
            .collect()
    }

    fn get_domain(&self, id: u64) -> Option<DomainInfo> {
        crate::domain_system::get_domain_snapshot(crate::domain_system::DomainId::new(id)).map(
            |snap| DomainInfo {
                id: snap.id.as_u64(),
                name: snap.name,
                state: map_domain_state(snap.state),
                tasks: snap.tasks,
                memory_kb: (snap.memory_bytes / 1024) as usize,
                rrefs: snap.rrefs,
                last_error: snap.last_error,
            },
        )
    }

    fn terminate_domain(&self, id: u64) -> Result<(), &'static str> {
        let target = crate::domain_system::DomainId::new(id);
        ensure_domain_control(target)?;
        crate::domain_system::terminate_domain(target)
    }

    fn stop_domain(&self, id: u64) -> Result<(), &'static str> {
        let target = crate::domain_system::DomainId::new(id);
        ensure_domain_control(target)?;
        crate::domain_system::stop_domain(target)
    }

    fn resume_domain(&self, id: u64) -> Result<(), &'static str> {
        let target = crate::domain_system::DomainId::new(id);
        ensure_domain_control(target)?;
        crate::domain_system::resume_domain(target)
    }

    fn current_domain(&self) -> u64 {
        crate::task::current_subject().domain.as_u64()
    }

    fn system_info(&self) -> KapiSystemInfo {
        KapiSystemInfo {
            uptime_ticks: crate::task::timer::current_tick(),
            cpu_temperature: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
        }
    }

    fn monitor_info(&self) -> kernel_api::shell::MonitorInfo {
        let snap = crate::monitor::snapshot();
        kernel_api::shell::MonitorInfo {
            timestamp: snap.timestamp,
            cpu_usage: snap.cpu_usage,
            memory: kernel_api::shell::MemoryMonitorInfo {
                heap_used: snap.memory.heap_used,
                heap_free: snap.memory.heap_free,
                heap_total: snap.memory.heap_total,
                usage_percent: snap.memory.usage_percent,
            },
            domains: kernel_api::shell::DomainMonitorInfo {
                total: snap.domains.total,
                running: snap.domains.running,
                stopped: snap.domains.stopped,
            },
            tasks: kernel_api::shell::TaskMonitorInfo {
                context_switches: snap.tasks.context_switches,
                voluntary_yields: snap.tasks.voluntary_yields,
                forced_preemptions: snap.tasks.forced_preemptions,
            },
            network: kernel_api::shell::NetworkMonitorInfo {
                rx_packets: snap.network.rx_packets,
                tx_packets: snap.network.tx_packets,
                rx_bytes: snap.network.rx_bytes,
                tx_bytes: snap.network.tx_bytes,
            },
        }
    }

    fn thermal_info(&self) -> kernel_api::shell::ThermalInfo {
        let tm = crate::thermal::thermal_manager();
        let (polling_count, trip_events) = tm.stats();
        let throttle = tm.throttle_controller();
        let sensors = tm
            .sensors()
            .iter()
            .map(|s| kernel_api::shell::ThermalSensorInfo {
                id: s.id as usize,
                name: s.name.clone(),
                current_c: if s.current.is_valid() {
                    Some(s.current.celsius() as f32)
                } else {
                    None
                },
                is_hot: s.is_hot(),
                is_critical: s.is_critical(),
            })
            .collect();

        kernel_api::shell::ThermalInfo {
            cpu_celsius: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
            polling_count,
            trip_events,
            throttle_policy: alloc::format!("{:?}", throttle.current_policy()),
            throttle_count: throttle.throttle_count(),
            sensors,
        }
    }

    fn watchdog_info(&self) -> kernel_api::shell::WatchdogInfo {
        let wm = crate::watchdog::watchdog_manager();
        let (heartbeats, timeouts, checks) = wm.software().stats();
        kernel_api::shell::WatchdogInfo {
            heartbeats,
            timeouts,
            checks,
            deadlocks_detected: wm.deadlock_detector().deadlocks_detected(),
        }
    }

    fn power_info(&self) -> kernel_api::shell::PowerInfo {
        let pm = crate::power::power_manager();
        let idle = crate::power::cpu_idle();
        let (c1, c2, c3) = idle.stats();
        let stats = pm.stats();

        kernel_api::shell::PowerInfo {
            state: alloc::format!("{:?}", pm.current_state()),
            power_button_presses: stats
                .power_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            sleep_button_presses: stats
                .sleep_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            cpu_idle: kernel_api::shell::CpuIdleInfo {
                c1_count: c1,
                c2_count: c2,
                c3_count: c3,
            },
        }
    }

    fn cpu_temperature(&self) -> Option<f32> {
        crate::thermal::cpu_temperature().map(|t| t.celsius() as f32)
    }

    fn shutdown(&self) -> ! {
        crate::power::shutdown()
    }

    fn reboot(&self) -> ! {
        crate::power::reboot()
    }

    fn list_directory(&self, path: &str) -> Result<alloc::vec::Vec<KapiDirEntry>, &'static str> {
        if let Some(result) = crate::fs::sysfs::list_directory(path) {
            return result.map(|entries| {
                entries
                    .into_iter()
                    .map(|e| {
                        let file_type = match e.file_type {
                            crate::fs::FileType::Directory => {
                                kernel_api::shell::FileType::Directory
                            }
                            crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                            crate::fs::FileType::CharDevice => {
                                kernel_api::shell::FileType::CharDevice
                            }
                            crate::fs::FileType::BlockDevice => {
                                kernel_api::shell::FileType::BlockDevice
                            }
                            crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                            crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                            _ => kernel_api::shell::FileType::File,
                        };
                        KapiDirEntry {
                            name: e.name,
                            file_type,
                            size: 0,
                            ino: e.ino,
                        }
                    })
                    .collect()
            });
        }
        match crate::fs::list_directory(path, "/") {
            Ok(entries) => {
                let result = entries
                    .into_iter()
                    .map(|e| {
                        let file_type = match e.file_type {
                            crate::fs::FileType::Directory => {
                                kernel_api::shell::FileType::Directory
                            }
                            crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                            crate::fs::FileType::CharDevice => {
                                kernel_api::shell::FileType::CharDevice
                            }
                            crate::fs::FileType::BlockDevice => {
                                kernel_api::shell::FileType::BlockDevice
                            }
                            crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                            crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                            _ => kernel_api::shell::FileType::File,
                        };
                        KapiDirEntry {
                            name: e.name,
                            file_type,
                            size: 0,
                            ino: e.ino,
                        }
                    })
                    .collect();
                Ok(result)
            }
            Err(_) => Err("Failed to list directory"),
        }
    }

    fn read_file(&self, path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
        if let Some(result) = crate::fs::sysfs::read_file(path) {
            return result;
        }
        crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")
    }

    fn read_file_zero_copy(
        &self,
        path: &str,
    ) -> Result<alloc::sync::Arc<alloc::vec::Vec<u8>>, &'static str> {
        // Use async_memfs's Bytes type internally for zero-copy semantics
        use crate::fs::async_memfs::Bytes;

        if let Some(result) = crate::fs::sysfs::read_file(path) {
            let content = result?;
            let bytes = Bytes::from(content);
            return Ok(bytes.into_inner());
        }

        // Read content
        let content = crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")?;

        // Wrap in Bytes and extract Arc
        let bytes = Bytes::from(content);
        Ok(bytes.into_inner())
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), &'static str> {
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::write_file_content(path, "/", data).map_err(|_| "Failed to write file")
    }

    fn stat_file(&self, path: &str) -> Result<kernel_api::shell::FileAttributes, &'static str> {
        if let Some(result) = crate::fs::sysfs::stat_file(path) {
            return result.map(|attr| {
                let file_type = match attr.file_type {
                    crate::fs::FileType::Directory => kernel_api::shell::FileType::Directory,
                    crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                    crate::fs::FileType::CharDevice => kernel_api::shell::FileType::CharDevice,
                    crate::fs::FileType::BlockDevice => kernel_api::shell::FileType::BlockDevice,
                    crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                    crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                    _ => kernel_api::shell::FileType::File,
                };
                kernel_api::shell::FileAttributes {
                    size: attr.size,
                    ino: attr.ino,
                    nlink: attr.nlink as u64,
                    file_type,
                }
            });
        }
        match crate::fs::stat_file(path, "/") {
            Ok(attr) => {
                let file_type = match attr.file_type {
                    crate::fs::FileType::Directory => kernel_api::shell::FileType::Directory,
                    crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                    crate::fs::FileType::CharDevice => kernel_api::shell::FileType::CharDevice,
                    crate::fs::FileType::BlockDevice => kernel_api::shell::FileType::BlockDevice,
                    crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                    crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                    _ => kernel_api::shell::FileType::File,
                };
                Ok(kernel_api::shell::FileAttributes {
                    size: attr.size,
                    ino: attr.ino,
                    nlink: attr.nlink as u64,
                    file_type,
                })
            }
            Err(_) => Err("Failed to stat file"),
        }
    }

    fn make_directory(&self, path: &str) -> Result<(), &'static str> {
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::make_directory(path, "/").map_err(|_| "Failed to create directory")
    }

    fn remove_file(&self, path: &str) -> Result<(), &'static str> {
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::remove_file(path, "/").map_err(|_| "Failed to remove file")
    }

    fn remove_directory(&self, path: &str) -> Result<(), &'static str> {
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::remove_directory(path, "/").map_err(|_| "Failed to remove directory")
    }
}

/// The global ExoKernel instance
static EXOKERNEL: ExoKernel = ExoKernel::new();

/// Register the kernel services (call from kmain early in boot)
///
/// # Safety
/// Must be called exactly once, before any KAPI functions are used.
pub unsafe fn register_kernel_services() {
    unsafe {
        kernel_api::register_kernel(&EXOKERNEL);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod nvme_tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
    use crate::security::capability::{self, CapabilitySet};
    use crate::task::context::{get_current_task, set_current_task, TaskControlBlock};

    fn idle_entry(_: u64) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    struct CurrentTaskGuard {
        prev: Option<*mut TaskControlBlock>,
        current: *mut TaskControlBlock,
    }

    impl Drop for CurrentTaskGuard {
        fn drop(&mut self) {
            let cpu_id = crate::smp::current_cpu() as usize;
            let prev_ptr = self.prev.unwrap_or(core::ptr::null_mut());
            unsafe {
                set_current_task(cpu_id, prev_ptr);
                drop(Box::from_raw(self.current));
            }
        }
    }

    fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev = get_current_task(cpu_id);
        let mut tcb = TaskControlBlock::new(idle_entry, 0, 0, domain_id)
            .expect("failed to create test TCB");
        let caps = crate::security::capability::manager().get_capabilities(domain_id.as_u64());
        tcb.security = Arc::new(DomainSecurity {
            credentials: DomainCredentials::ROOT,
            caps,
        });
        let boxed = Box::new(tcb);
        let current = Box::into_raw(boxed);
        unsafe {
            set_current_task(cpu_id, current);
        }
        CurrentTaskGuard { prev, current }
    }

    #[test_case]
    fn test_nvme_open_with_token_reclaim() {
        // Setup: create caller and target domains
        let caller = DomainId::new(300);
        let target = DomainId::new(301);

        // Caller gets permission to grant CAP_DMA
        crate::security::capability::manager()
            .set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(crate::security::capability::CAP_DMA));
        let _caller_guard = set_current_subject(caller);

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_DMA, None, false)
            .unwrap();

        // Target opens using token
        let handle = {
            let _target_guard = set_current_subject(target);
            EXOKERNEL
                .nvme_open_direct_with_token(0, 0, 1, Some(token))
                .expect("open should succeed")
        };
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Target closes handle
        {
            let _target_guard = set_current_subject(target);
            assert!(EXOKERNEL.nvme_close_direct(handle).is_ok());
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }
}

#[cfg(test)]
mod fs_tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
    use crate::security::capability::{self, CapabilitySet};
    use crate::task::context::{get_current_task, set_current_task, TaskControlBlock};

    fn idle_entry(_: u64) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    struct CurrentTaskGuard {
        prev: Option<*mut TaskControlBlock>,
        current: *mut TaskControlBlock,
    }

    impl Drop for CurrentTaskGuard {
        fn drop(&mut self) {
            let cpu_id = crate::smp::current_cpu() as usize;
            let prev_ptr = self.prev.unwrap_or(core::ptr::null_mut());
            unsafe {
                set_current_task(cpu_id, prev_ptr);
                drop(Box::from_raw(self.current));
            }
        }
    }

    fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev = get_current_task(cpu_id);
        let mut tcb = TaskControlBlock::new(idle_entry, 0, 0, domain_id)
            .expect("failed to create test TCB");
        let caps = crate::security::capability::manager().get_capabilities(domain_id.as_u64());
        tcb.security = Arc::new(DomainSecurity {
            credentials: DomainCredentials::ROOT,
            caps,
        });
        let boxed = Box::new(tcb);
        let current = Box::into_raw(boxed);
        unsafe {
            set_current_task(cpu_id, current);
        }
        CurrentTaskGuard { prev, current }
    }

    #[test_case]
    fn test_fs_open_with_token_reclaim() {
        // Setup: create caller and target domains
        let caller = DomainId::new(400);
        let target = DomainId::new(401);

        // Caller gets permission to grant CAP_FOWNER
        crate::security::capability::manager()
            .set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));
        let _caller_guard = set_current_subject(caller);

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Target opens using token
        let handle = {
            let _target_guard = set_current_subject(target);
            EXOKERNEL
                .fs_open_with_token("test_token_file", kernel_api::OpenMode::Write, Some(token))
                .expect("open should succeed")
        };
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Close file handle
        {
            let _target_guard = set_current_subject(target);
            assert!(EXOKERNEL.fs_close(handle).is_ok());
        }

        // Now reclaim should succeed
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }
}

/// Get a reference to the exokernel (for internal use)
pub fn exokernel() -> &'static ExoKernel {
    &EXOKERNEL
}
