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

/// Interface selection used by network-related KAPI calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceScope {
    #[default]
    Any,
    Pinned(u16),
}

impl InterfaceScope {
    pub const fn pinned(if_id: u16) -> Self {
        Self::Pinned(if_id)
    }

    pub const fn as_if_id(self) -> Option<u16> {
        match self {
            Self::Any => None,
            Self::Pinned(if_id) => Some(if_id),
        }
    }
}

/// Shared default headroom for L2/L3/L4 header prepends.
pub const DEFAULT_PACKET_HEADROOM: usize = 128;

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

pub const PACKET_REF_STORAGE_WORDS: usize = 5;

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
    pub set_len: unsafe fn(&mut PacketRefStorage, usize) -> bool,
    pub capacity: unsafe fn(&PacketRefStorage) -> usize,
    pub phys_addr: unsafe fn(&PacketRefStorage) -> u64,
    pub device_address: unsafe fn(&PacketRefStorage) -> u64,
    pub headroom: unsafe fn(&PacketRefStorage) -> usize,
    pub advance: unsafe fn(&mut PacketRefStorage, usize) -> bool,
    pub retreat: unsafe fn(&mut PacketRefStorage, usize) -> bool,
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
    #[must_use]
    pub fn set_len(&mut self, len: usize) -> bool {
        unsafe { (self.vtable.set_len)(&mut self.storage, len) }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        unsafe { (self.vtable.capacity)(&self.storage) }
    }

    #[inline]
    pub fn headroom(&self) -> usize {
        unsafe { (self.vtable.headroom)(&self.storage) }
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
    #[must_use]
    pub fn advance(&mut self, size: usize) -> bool {
        unsafe { (self.vtable.advance)(&mut self.storage, size) }
    }

    #[inline]
    pub fn retreat(&mut self, size: usize) -> bool {
        unsafe { (self.vtable.retreat)(&mut self.storage, size) }
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
            .field("headroom", &self.headroom())
            .field("phys_addr", &self.phys_addr())
            .field("device_address", &self.device_address())
            .field("meta", &self.meta_cache)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct PacketChain {
    segments: Vec<PacketRef>,
    total_len: usize,
}

impl PacketChain {
    pub const fn new() -> Self {
        Self {
            segments: Vec::new(),
            total_len: 0,
        }
    }

    pub fn from_segments(segments: Vec<PacketRef>) -> Self {
        let total_len = segments.iter().map(PacketRef::len).sum();
        Self {
            segments,
            total_len,
        }
    }

    pub fn push(&mut self, packet: PacketRef) {
        self.total_len = self.total_len.saturating_add(packet.len());
        self.segments.push(packet);
    }

    pub fn push_front(&mut self, packet: PacketRef) {
        self.total_len = self.total_len.saturating_add(packet.len());
        self.segments.insert(0, packet);
    }

    pub fn segments(&self) -> &[PacketRef] {
        &self.segments
    }

    pub fn segments_mut(&mut self) -> &mut [PacketRef] {
        &mut self.segments
    }

    pub fn into_segments(self) -> Vec<PacketRef> {
        self.segments
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }
}

#[derive(Debug)]
pub enum PacketPayload {
    Single(PacketRef),
    Chain(PacketChain),
}

impl PacketPayload {
    pub fn segments(&self) -> &[PacketRef] {
        match self {
            Self::Single(packet) => core::slice::from_ref(packet),
            Self::Chain(chain) => chain.segments(),
        }
    }

    pub fn segments_mut(&mut self) -> &mut [PacketRef] {
        match self {
            Self::Single(packet) => core::slice::from_mut(packet),
            Self::Chain(chain) => chain.segments_mut(),
        }
    }
}

impl Default for PacketPayload {
    fn default() -> Self {
        Self::Chain(PacketChain::new())
    }
}

impl PacketPayload {
    pub fn single(packet: PacketRef) -> Self {
        Self::Single(packet)
    }

    pub fn chain(chain: PacketChain) -> Self {
        Self::Chain(chain)
    }

    pub fn prepend(self, packet: PacketRef) -> Self {
        match self {
            Self::Single(existing) => {
                Self::Chain(PacketChain::from_segments(alloc::vec![packet, existing,]))
            }
            Self::Chain(mut chain) => {
                chain.push_front(packet);
                Self::Chain(chain)
            }
        }
    }

    pub fn total_len(&self) -> usize {
        match self {
            Self::Single(packet) => packet.len(),
            Self::Chain(chain) => chain.total_len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.total_len() == 0
    }

    pub fn into_segments(self) -> Vec<PacketRef> {
        match self {
            Self::Single(packet) => alloc::vec![packet],
            Self::Chain(chain) => chain.into_segments(),
        }
    }
}

/// System information
#[derive(Debug)]
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

    /// Kernel-assigned open id (0 if not from `nvme_open_direct_with_token`)
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

/// Shared socket address for KAPI TCP endpoint operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetSocketAddr {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}

impl NetSocketAddr {
    pub const fn v4(ip: [u8; 4], port: u16) -> Self {
        Self::V4 { ip, port }
    }

    pub const fn v6(ip: [u8; 16], port: u16) -> Self {
        Self::V6 { ip, port }
    }

    pub const fn port(self) -> u16 {
        match self {
            Self::V4 { port, .. } | Self::V6 { port, .. } => port,
        }
    }

    pub const fn is_ipv6(self) -> bool {
        matches!(self, Self::V6 { .. })
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
#[derive(Debug)]
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
#[derive(Debug)]
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
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DMA_RELEASES: AtomicUsize = AtomicUsize::new(0);

    struct SharedDmaBuffer {
        dma: Box<crate::dma::DmaSlice<crate::dma::CpuOwned>>,
        phys_addr: u64,
        device_addr: u64,
    }

    struct DmaPacketState {
        backing: NonNull<SharedDmaBuffer>,
        offset: usize,
        len: usize,
    }

    fn dma_backing(state: &DmaPacketState) -> &SharedDmaBuffer {
        unsafe { state.backing.as_ref() }
    }

    unsafe fn dma_state_ref(storage: &PacketRefStorage) -> &DmaPacketState {
        unsafe { storage.as_state_ref::<DmaPacketState>() }
    }

    unsafe fn dma_state_mut(storage: &mut PacketRefStorage) -> &mut DmaPacketState {
        unsafe { storage.as_state_mut::<DmaPacketState>() }
    }

    unsafe fn dma_data_ptr(storage: &PacketRefStorage) -> *const u8 {
        let state = unsafe { dma_state_ref(storage) };
        dma_backing(state).dma.as_ptr().wrapping_add(state.offset)
    }

    unsafe fn dma_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
        let state = unsafe { dma_state_mut(storage) };
        dma_backing(state).dma.as_ptr().wrapping_add(state.offset)
    }

    unsafe fn dma_len(storage: &PacketRefStorage) -> usize {
        unsafe { dma_state_ref(storage) }.len
    }

    unsafe fn dma_set_len(storage: &mut PacketRefStorage, len: usize) -> bool {
        let state = unsafe { dma_state_mut(storage) };
        if len > dma_backing(state).dma.size().saturating_sub(state.offset) {
            return false;
        }
        state.len = len;
        true
    }

    unsafe fn dma_capacity(storage: &PacketRefStorage) -> usize {
        dma_backing(unsafe { dma_state_ref(storage) }).dma.size()
    }

    unsafe fn dma_headroom(storage: &PacketRefStorage) -> usize {
        unsafe { dma_state_ref(storage) }.offset
    }

    unsafe fn dma_phys(storage: &PacketRefStorage) -> u64 {
        let state = unsafe { dma_state_ref(storage) };
        dma_backing(state).phys_addr + state.offset as u64
    }

    unsafe fn dma_device(storage: &PacketRefStorage) -> u64 {
        let state = unsafe { dma_state_ref(storage) };
        dma_backing(state).device_addr + state.offset as u64
    }

    unsafe fn dma_advance(storage: &mut PacketRefStorage, size: usize) -> bool {
        let state = unsafe { dma_state_mut(storage) };
        if size > state.len {
            return false;
        }
        state.offset += size;
        state.len -= size;
        true
    }

    unsafe fn dma_retreat(storage: &mut PacketRefStorage, size: usize) -> bool {
        let state = unsafe { dma_state_mut(storage) };
        if size > state.offset {
            return false;
        }
        let Some(new_len) = state.len.checked_add(size) else {
            return false;
        };
        let new_offset = state.offset - size;
        if new_len > dma_backing(state).dma.size().saturating_sub(new_offset) {
            return false;
        }
        state.offset = new_offset;
        state.len = new_len;
        true
    }

    unsafe fn dma_drop(storage: &mut PacketRefStorage) {
        let state = unsafe { storage.as_state_mut::<DmaPacketState>() };
        let backing = state.backing;
        unsafe {
            ptr::drop_in_place(state);
            drop(Box::from_raw(backing.as_ptr()));
        }
    }

    static DMA_VTABLE: PacketRefVTable = PacketRefVTable {
        data_ptr: dma_data_ptr,
        data_mut_ptr: dma_data_mut_ptr,
        len: dma_len,
        set_len: dma_set_len,
        capacity: dma_capacity,
        phys_addr: dma_phys,
        device_address: dma_device,
        headroom: dma_headroom,
        advance: dma_advance,
        retreat: dma_retreat,
        drop_storage: dma_drop,
    };

    fn dma_releaser(ptr: *mut u8, size: usize, phys_addr: u64) {
        assert_eq!(size, 64);
        assert_eq!(phys_addr, 0x3000);
        DMA_RELEASES.fetch_add(1, Ordering::SeqCst);
        let _ = unsafe { Box::from_raw(ptr.cast::<[u8; 64]>()) };
    }

    fn make_dma_packet() -> PacketRef {
        let mut raw = Box::new([0u8; 64]);
        raw[..7].copy_from_slice(b"packet!");
        let ptr = Box::into_raw(raw).cast::<u8>();
        let dma = unsafe {
            crate::dma::DmaSlice::from_internal_parts_unchecked(
                0x3000,
                0x4000,
                ptr,
                64,
                crate::dma::InternalDmaReclaimer::KernelBuffer {
                    releaser: Some(dma_releaser),
                },
            )
        };
        let state = DmaPacketState {
            backing: NonNull::from(Box::leak(Box::new(SharedDmaBuffer {
                phys_addr: 0x3000,
                device_addr: 0x4000,
                dma: Box::new(dma),
            }))),
            offset: 0,
            len: 7,
        };

        unsafe { PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &DMA_VTABLE) }
    }

    #[test]
    fn dma_backing_matches_packet_ref_contract() {
        DMA_RELEASES.store(0, Ordering::SeqCst);

        let mut packet = make_dma_packet();
        assert_eq!(packet.len(), 7);
        assert_eq!(packet.data(), b"packet!");
        assert_eq!(packet.capacity(), 64);
        assert_eq!(packet.phys_addr().as_u64(), 0x3000);
        assert_eq!(packet.device_address(), 0x4000);

        assert!(packet.set_len(6));
        assert!(packet.advance(1));
        assert_eq!(packet.len(), 5);
        assert_eq!(packet.data(), b"acket");
        assert_eq!(packet.phys_addr().as_u64(), 0x3001);
        assert_eq!(packet.device_address(), 0x4001);

        packet.meta_mut().pkt_type = PacketType::Unicast;
        assert_eq!(packet.meta().pkt_type, PacketType::Unicast);
        assert_eq!(packet.device_address(), 0x4001);

        drop(packet);
        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 1);
    }
}
