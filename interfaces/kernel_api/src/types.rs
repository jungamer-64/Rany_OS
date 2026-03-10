// ============================================================================
// kernel_api/src/types.rs - Shared Type Definitions
// ============================================================================
//!
//! Pure type definitions that can be used by kernel, drivers, and applications.
//! These types have no kernel dependencies.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{MaybeUninit, align_of, size_of};
use core::ops::{Add, AddAssign};
use core::ptr;

/// Task handle - opaque reference to a spawned task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskHandle {
    id: u64,
}

impl TaskHandle {
    /// Create a new task handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get the task ID
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// Network packet with ownership semantics
pub struct Packet {
    data: Vec<u8>,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Packet {
    /// Create a new packet
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            src_port: 0,
            dst_port: 0,
        }
    }

    /// Create with port info
    pub fn with_ports(data: Vec<u8>, src_port: u16, dst_port: u16) -> Self {
        Self {
            data,
            src_port,
            dst_port,
        }
    }

    /// Get packet data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable packet data
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Packet length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Is packet empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Canonical physical address wrapper shared across kernel-facing interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PhysicalAddress(u64);

impl PhysicalAddress {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl Add<u64> for PhysicalAddress {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl AddAssign<u64> for PhysicalAddress {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.saturating_add(rhs);
    }
}

/// Packet classification hint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    #[default]
    Unknown = 0,
    Unicast = 1,
    Multicast = 2,
    Broadcast = 3,
}

/// Parsed packet metadata cached across stack layers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketMeta {
    pub l2_len: u8,
    pub l3_len: u8,
    pub l4_len: u8,
    pub l4_proto: u8,
    pub flow_hash: u32,
    pub csum_flags: u8,
    pub pkt_type: PacketType,
    pub vlan_tag: Option<u16>,
    pub timestamp: u64,
}

impl PacketMeta {
    #[inline]
    pub fn ip_csum_verified(&self) -> bool {
        self.csum_flags & 0x01 != 0
    }

    #[inline]
    pub fn l4_csum_verified(&self) -> bool {
        self.csum_flags & 0x02 != 0
    }

    #[inline]
    pub fn set_ip_csum_verified(&mut self) {
        self.csum_flags |= 0x01;
    }

    #[inline]
    pub fn set_l4_csum_verified(&mut self) {
        self.csum_flags |= 0x02;
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        self.l2_len as usize + self.l3_len as usize + self.l4_len as usize
    }

    #[inline]
    pub fn l3_offset(&self) -> usize {
        self.l2_len as usize
    }

    #[inline]
    pub fn l4_offset(&self) -> usize {
        self.l2_len as usize + self.l3_len as usize
    }

    #[inline]
    pub fn payload_offset(&self) -> usize {
        self.header_len()
    }
}

pub const PACKET_REF_STORAGE_WORDS: usize = 4;

/// Inline opaque storage used by `PacketRef` backings.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketRefStorage {
    words: [usize; PACKET_REF_STORAGE_WORDS],
}

impl PacketRefStorage {
    pub const fn zeroed() -> Self {
        Self {
            words: [0; PACKET_REF_STORAGE_WORDS],
        }
    }

    /// Pack an arbitrary backing state into the inline storage.
    ///
    /// # Safety
    /// `T` must fit into `PacketRefStorage` and must not require stronger
    /// alignment than `PacketRefStorage`.
    pub unsafe fn from_state<T>(state: T) -> Self {
        assert!(size_of::<T>() <= size_of::<Self>());
        assert!(align_of::<T>() <= align_of::<Self>());
        let mut storage = MaybeUninit::<Self>::zeroed();
        unsafe {
            storage.as_mut_ptr().cast::<T>().write(state);
            storage.assume_init()
        }
    }

    /// Reinterpret the storage as an immutable backing state.
    ///
    /// # Safety
    /// The storage must currently contain a valid `T`.
    pub unsafe fn as_state_ref<T>(&self) -> &T {
        debug_assert!(size_of::<T>() <= size_of::<Self>());
        debug_assert!(align_of::<T>() <= align_of::<Self>());
        unsafe { &*ptr::from_ref(self).cast::<T>() }
    }

    /// Reinterpret the storage as a mutable backing state.
    ///
    /// # Safety
    /// The storage must currently contain a valid `T`.
    pub unsafe fn as_state_mut<T>(&mut self) -> &mut T {
        debug_assert!(size_of::<T>() <= size_of::<Self>());
        debug_assert!(align_of::<T>() <= align_of::<Self>());
        unsafe { &mut *ptr::from_mut(self).cast::<T>() }
    }
}

/// Opaque backing operations for zero-copy packet references.
#[derive(Clone, Copy)]
pub struct PacketRefVTable {
    pub data_ptr: unsafe fn(&PacketRefStorage) -> *const u8,
    pub data_mut_ptr: unsafe fn(&mut PacketRefStorage) -> *mut u8,
    pub len: unsafe fn(&PacketRefStorage) -> usize,
    pub set_len: unsafe fn(&mut PacketRefStorage, usize),
    pub capacity: unsafe fn(&PacketRefStorage) -> usize,
    pub phys_addr: unsafe fn(&PacketRefStorage) -> u64,
    pub device_address: unsafe fn(&PacketRefStorage) -> u64,
    pub advance: unsafe fn(&mut PacketRefStorage, usize),
    pub clone_storage: unsafe fn(&PacketRefStorage) -> PacketRefStorage,
    pub drop_storage: unsafe fn(&mut PacketRefStorage),
}

/// Shared zero-copy packet reference used by kernel adapters and driver crates.
pub struct PacketRef {
    storage: PacketRefStorage,
    vtable: &'static PacketRefVTable,
    meta_cache: PacketMeta,
    _not_sync: PhantomData<*mut ()>,
}

impl PacketRef {
    /// Construct from opaque backing storage.
    ///
    /// # Safety
    /// `storage` must contain the backing expected by `vtable`.
    pub unsafe fn from_opaque_parts(
        storage: PacketRefStorage,
        vtable: &'static PacketRefVTable,
    ) -> Self {
        Self {
            storage,
            vtable,
            meta_cache: PacketMeta::default(),
            _not_sync: PhantomData,
        }
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        let ptr = unsafe { (self.vtable.data_ptr)(&self.storage) };
        let len = unsafe { (self.vtable.len)(&self.storage) };
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = unsafe { (self.vtable.len)(&self.storage) };
        let ptr = unsafe { (self.vtable.data_mut_ptr)(&mut self.storage) };
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }

    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        unsafe { (self.vtable.data_ptr)(&self.storage) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        unsafe { (self.vtable.len)(&self.storage) }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn set_len(&mut self, len: usize) {
        unsafe { (self.vtable.set_len)(&mut self.storage, len) };
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        unsafe { (self.vtable.capacity)(&self.storage) }
    }

    #[inline]
    pub fn phys_addr(&self) -> PhysicalAddress {
        PhysicalAddress::new(unsafe { (self.vtable.phys_addr)(&self.storage) })
    }

    #[inline]
    pub fn device_address(&self) -> u64 {
        unsafe { (self.vtable.device_address)(&self.storage) }
    }

    #[inline]
    pub fn advance(&mut self, size: usize) {
        unsafe { (self.vtable.advance)(&mut self.storage, size) };
    }

    #[inline]
    pub fn meta(&self) -> &PacketMeta {
        &self.meta_cache
    }

    #[inline]
    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.meta_cache
    }

    #[inline]
    pub fn set_meta(&mut self, meta: PacketMeta) {
        self.meta_cache = meta;
    }

    #[inline]
    pub fn clone_ref(&self) -> Self {
        self.clone()
    }
}

impl Clone for PacketRef {
    fn clone(&self) -> Self {
        let storage = unsafe { (self.vtable.clone_storage)(&self.storage) };
        Self {
            storage,
            vtable: self.vtable,
            meta_cache: self.meta_cache,
            _not_sync: PhantomData,
        }
    }
}

impl Drop for PacketRef {
    fn drop(&mut self) {
        unsafe { (self.vtable.drop_storage)(&mut self.storage) };
    }
}

unsafe impl Send for PacketRef {}

impl fmt::Debug for PacketRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketRef")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("phys_addr", &self.phys_addr())
            .field("device_address", &self.device_address())
            .field("meta", &self.meta_cache)
            .finish()
    }
}

/// System information
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub total_memory: u64,
    pub free_memory: u64,
    pub uptime_ms: u64,
    pub cpu_count: u32,
}

/// File open mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
    Append,
    Create,
}

/// File handle
pub struct FileHandle {
    id: u64,
    mode: OpenMode,
}

impl FileHandle {
    /// Create new file handle (kernel-only)
    pub const fn new(id: u64, mode: OpenMode) -> Self {
        Self { id, mode }
    }

    /// Get file ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get open mode
    pub fn mode(&self) -> OpenMode {
        self.mode
    }
}

/// Direct block device handle (NVMe namespace)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectBlockHandle {
    device_id: u64,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    /// Optional kernel-assigned open id (0 == not an open returned by kernel)
    open_id: u64,
}

impl DirectBlockHandle {
    /// Create a new direct block handle (kernel-only)
    /// This constructor represents a *standalone* handle (not a kernel-registered open).
    pub const fn new(device_id: u64, start_block: u64, block_count: u64, block_size: u32) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
            open_id: 0,
        }
    }

    /// Create a kernel-registered handle with an `open_id`
    pub const fn new_with_id(
        device_id: u64,
        start_block: u64,
        block_count: u64,
        block_size: u32,
        open_id: u64,
    ) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
            open_id,
        }
    }

    pub fn device_id(&self) -> u64 {
        self.device_id
    }

    pub fn start_block(&self) -> u64 {
        self.start_block
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Kernel-assigned open id (0 if not from `nvme_open_direct_with_token`/`nvme_open_direct`)
    pub fn open_id(&self) -> u64 {
        self.open_id
    }
}

/// IPC channel handle
pub struct ChannelHandle {
    id: u64,
}

impl ChannelHandle {
    /// Create new channel handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get channel ID
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// TCP endpoint
pub struct TcpEndpoint {
    id: u64,
    connected: bool,
}

impl TcpEndpoint {
    /// Create new TCP endpoint
    pub fn new(id: u64) -> Self {
        Self {
            id,
            connected: false,
        }
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Set connection state (kernel-only)
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// Get raw endpoint id
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Consume the endpoint and return its raw id
    pub fn into_raw(self) -> u64 {
        self.id
    }
}

/// Raw endpoint handle (for packet-oriented raw endpoints)
pub struct RawEndpointHandle {
    id: u64,
}

impl RawEndpointHandle {
    /// Create new raw endpoint handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get raw id
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Consume and return raw id
    pub fn into_raw(self) -> u64 {
        self.id
    }
}

// ============================================================================
// NVMe I/O Request Types (io_scheduler abstraction)
// ============================================================================

/// NVMe I/O operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeIoType {
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Flush operation
    Flush,
    /// Discard/TRIM operation
    Discard,
}

/// NVMe I/O priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvmeIoPriority {
    /// Background (lowest)
    Background,
    /// Idle
    Idle,
    /// Normal (default)
    #[default]
    Normal,
    /// High priority
    High,
    /// Realtime (highest)
    Realtime,
}

/// NVMe Read/Write request parameters
#[derive(Debug, Clone)]
pub struct NvmeRwRequest {
    /// NVMe device ID
    pub device_id: u64,
    /// NVMe namespace ID
    pub namespace_id: u32,
    /// Starting LBA
    pub lba: u64,
    /// Number of blocks
    pub blocks: u16,
    /// PRP1 (first page IOVA)
    pub prp1: u64,
    /// PRP2 (second page or PRP list IOVA)
    pub prp2: u64,
    /// Transfer size in bytes
    pub bytes: usize,
    /// I/O priority
    pub priority: NvmeIoPriority,
}

/// NVMe I/O request handle
#[derive(Debug, Clone, Copy)]
pub struct NvmeIoHandle {
    request_id: u64,
}

impl NvmeIoHandle {
    /// Create a new handle (kernel-only)
    pub const fn new(request_id: u64) -> Self {
        Self { request_id }
    }

    /// Get the request ID
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

/// NVMe I/O result
#[derive(Debug, Clone)]
pub enum NvmeIoResult {
    /// Success with transferred byte count
    Success(usize),
    /// Device error
    DeviceError,
    /// Timeout
    Timeout,
    /// Cancelled
    Cancelled,
    /// Invalid parameter
    InvalidParameter,
}

#[cfg(test)]
mod packet_ref_tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static HEAP_RELEASES: AtomicUsize = AtomicUsize::new(0);
    static DMA_RELEASES: AtomicUsize = AtomicUsize::new(0);

    struct SharedHeapBuffer {
        data: Box<[u8; 64]>,
        addr: u64,
    }

    impl Drop for SharedHeapBuffer {
        fn drop(&mut self) {
            HEAP_RELEASES.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct HeapPacketState {
        backing: Arc<SharedHeapBuffer>,
        offset: usize,
        len: usize,
    }

    unsafe fn heap_state_ref(storage: &PacketRefStorage) -> &HeapPacketState {
        unsafe { storage.as_state_ref::<HeapPacketState>() }
    }

    unsafe fn heap_state_mut(storage: &mut PacketRefStorage) -> &mut HeapPacketState {
        unsafe { storage.as_state_mut::<HeapPacketState>() }
    }

    unsafe fn heap_data_ptr(storage: &PacketRefStorage) -> *const u8 {
        let state = unsafe { heap_state_ref(storage) };
        state.backing.data.as_ptr().wrapping_add(state.offset)
    }

    unsafe fn heap_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
        let state = unsafe { heap_state_mut(storage) };
        state
            .backing
            .data
            .as_ptr()
            .cast_mut()
            .wrapping_add(state.offset)
    }

    unsafe fn heap_len(storage: &PacketRefStorage) -> usize {
        unsafe { heap_state_ref(storage) }.len
    }

    unsafe fn heap_set_len(storage: &mut PacketRefStorage, len: usize) {
        let state = unsafe { heap_state_mut(storage) };
        state.len = len.min(state.backing.data.len().saturating_sub(state.offset));
    }

    unsafe fn heap_capacity(storage: &PacketRefStorage) -> usize {
        unsafe { heap_state_ref(storage) }.backing.data.len()
    }

    unsafe fn heap_phys(storage: &PacketRefStorage) -> u64 {
        let state = unsafe { heap_state_ref(storage) };
        state.backing.addr + state.offset as u64
    }

    unsafe fn heap_device(storage: &PacketRefStorage) -> u64 {
        unsafe { heap_phys(storage) }
    }

    unsafe fn heap_advance(storage: &mut PacketRefStorage, size: usize) {
        let state = unsafe { heap_state_mut(storage) };
        state.offset = state
            .offset
            .saturating_add(size)
            .min(state.backing.data.len());
        state.len = state.len.saturating_sub(size);
    }

    unsafe fn heap_clone(storage: &PacketRefStorage) -> PacketRefStorage {
        let state = unsafe { heap_state_ref(storage) };
        unsafe { PacketRefStorage::from_state(state.clone()) }
    }

    unsafe fn heap_drop(storage: &mut PacketRefStorage) {
        unsafe { ptr::drop_in_place(storage.as_state_mut::<HeapPacketState>()) };
    }

    static HEAP_VTABLE: PacketRefVTable = PacketRefVTable {
        data_ptr: heap_data_ptr,
        data_mut_ptr: heap_data_mut_ptr,
        len: heap_len,
        set_len: heap_set_len,
        capacity: heap_capacity,
        phys_addr: heap_phys,
        device_address: heap_device,
        advance: heap_advance,
        clone_storage: heap_clone,
        drop_storage: heap_drop,
    };

    struct SharedDmaBuffer {
        dma: Box<crate::dma::DmaSlice<crate::dma::CpuOwned>>,
        ptr: *mut u8,
        len: usize,
        phys_addr: u64,
        device_addr: u64,
    }

    #[derive(Clone)]
    struct DmaPacketState {
        backing: Arc<SharedDmaBuffer>,
        offset: usize,
        len: usize,
    }

    unsafe fn dma_state_ref(storage: &PacketRefStorage) -> &DmaPacketState {
        unsafe { storage.as_state_ref::<DmaPacketState>() }
    }

    unsafe fn dma_state_mut(storage: &mut PacketRefStorage) -> &mut DmaPacketState {
        unsafe { storage.as_state_mut::<DmaPacketState>() }
    }

    unsafe fn dma_data_ptr(storage: &PacketRefStorage) -> *const u8 {
        let state = unsafe { dma_state_ref(storage) };
        state.backing.ptr.wrapping_add(state.offset)
    }

    unsafe fn dma_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
        let state = unsafe { dma_state_mut(storage) };
        state.backing.ptr.wrapping_add(state.offset)
    }

    unsafe fn dma_len(storage: &PacketRefStorage) -> usize {
        unsafe { dma_state_ref(storage) }.len
    }

    unsafe fn dma_set_len(storage: &mut PacketRefStorage, len: usize) {
        let state = unsafe { dma_state_mut(storage) };
        state.len = len.min(state.backing.len.saturating_sub(state.offset));
    }

    unsafe fn dma_capacity(storage: &PacketRefStorage) -> usize {
        unsafe { dma_state_ref(storage) }.backing.len
    }

    unsafe fn dma_phys(storage: &PacketRefStorage) -> u64 {
        let state = unsafe { dma_state_ref(storage) };
        state.backing.phys_addr + state.offset as u64
    }

    unsafe fn dma_device(storage: &PacketRefStorage) -> u64 {
        let state = unsafe { dma_state_ref(storage) };
        state.backing.device_addr + state.offset as u64
    }

    unsafe fn dma_advance(storage: &mut PacketRefStorage, size: usize) {
        let state = unsafe { dma_state_mut(storage) };
        state.offset = state.offset.saturating_add(size).min(state.backing.len);
        state.len = state.len.saturating_sub(size);
    }

    unsafe fn dma_clone(storage: &PacketRefStorage) -> PacketRefStorage {
        let state = unsafe { dma_state_ref(storage) };
        unsafe { PacketRefStorage::from_state(state.clone()) }
    }

    unsafe fn dma_drop(storage: &mut PacketRefStorage) {
        unsafe { ptr::drop_in_place(storage.as_state_mut::<DmaPacketState>()) };
    }

    static DMA_VTABLE: PacketRefVTable = PacketRefVTable {
        data_ptr: dma_data_ptr,
        data_mut_ptr: dma_data_mut_ptr,
        len: dma_len,
        set_len: dma_set_len,
        capacity: dma_capacity,
        phys_addr: dma_phys,
        device_address: dma_device,
        advance: dma_advance,
        clone_storage: dma_clone,
        drop_storage: dma_drop,
    };

    unsafe fn dma_releaser(ptr: *mut u8, size: usize, phys_addr: u64) {
        assert_eq!(size, 64);
        assert_eq!(phys_addr, 0x3000);
        DMA_RELEASES.fetch_add(1, Ordering::SeqCst);
        let _ = unsafe { Box::from_raw(ptr.cast::<[u8; 64]>()) };
    }

    fn make_heap_packet() -> PacketRef {
        let mut data = Box::new([0u8; 64]);
        data[..6].copy_from_slice(b"kernel");
        let state = HeapPacketState {
            backing: Arc::new(SharedHeapBuffer { data, addr: 0x1000 }),
            offset: 0,
            len: 6,
        };

        unsafe { PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &HEAP_VTABLE) }
    }

    fn make_dma_packet() -> PacketRef {
        let mut raw = Box::new([0u8; 64]);
        raw[..7].copy_from_slice(b"virtio!");
        let ptr = Box::into_raw(raw).cast::<u8>();
        let dma = unsafe {
            crate::dma::DmaSlice::from_raw_parts(0x3000, 0x4000, ptr, 64, Some(dma_releaser))
        };
        let state = DmaPacketState {
            backing: Arc::new(SharedDmaBuffer {
                ptr,
                len: 64,
                phys_addr: 0x3000,
                device_addr: 0x4000,
                dma: Box::new(dma),
            }),
            offset: 0,
            len: 7,
        };

        unsafe { PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &DMA_VTABLE) }
    }

    #[test]
    fn heap_backing_supports_len_advance_clone_drop_and_meta() {
        HEAP_RELEASES.store(0, Ordering::SeqCst);

        let mut packet = make_heap_packet();
        assert_eq!(packet.len(), 6);
        assert_eq!(packet.data(), b"kernel");
        assert_eq!(packet.capacity(), 64);
        assert_eq!(packet.phys_addr().as_u64(), 0x1000);
        assert_eq!(packet.device_address(), 0x1000);

        let mut meta = PacketMeta::default();
        meta.l2_len = 14;
        meta.l3_len = 20;
        meta.set_ip_csum_verified();
        packet.set_meta(meta);
        assert!(packet.meta().ip_csum_verified());
        assert_eq!(packet.meta().header_len(), 34);

        let mut clone = packet.clone_ref();
        clone.advance(2);
        assert_eq!(clone.len(), 4);
        assert_eq!(clone.data(), b"rnel");
        assert_eq!(clone.phys_addr().as_u64(), 0x1002);
        assert_eq!(packet.len(), 6);

        drop(packet);
        assert_eq!(HEAP_RELEASES.load(Ordering::SeqCst), 0);
        drop(clone);
        assert_eq!(HEAP_RELEASES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dma_backing_matches_packet_ref_contract() {
        DMA_RELEASES.store(0, Ordering::SeqCst);

        let mut packet = make_dma_packet();
        assert_eq!(packet.len(), 7);
        assert_eq!(packet.data(), b"virtio!");
        assert_eq!(packet.capacity(), 64);
        assert_eq!(packet.phys_addr().as_u64(), 0x3000);
        assert_eq!(packet.device_address(), 0x4000);

        packet.set_len(6);
        packet.advance(1);
        assert_eq!(packet.len(), 5);
        assert_eq!(packet.data(), b"irtio");
        assert_eq!(packet.phys_addr().as_u64(), 0x3001);
        assert_eq!(packet.device_address(), 0x4001);

        packet.meta_mut().pkt_type = PacketType::Unicast;
        let clone = packet.clone_ref();
        assert_eq!(clone.meta().pkt_type, PacketType::Unicast);
        assert_eq!(clone.device_address(), 0x4001);

        drop(packet);
        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 0);
        drop(clone);
        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 1);
    }
}
