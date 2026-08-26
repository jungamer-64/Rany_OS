// ============================================================================
// interfaces/kernel_api/src/netdev.rs - Network device discovery and runtime traits
// ============================================================================

extern crate alloc;

use crate::resource::net::{PacketByteCount, PacketRef};
use crate::service::kernel;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::num::NonZeroU16;
use core::num::NonZeroU64;
use core::num::NonZeroUsize;
use core::ptr::NonNull;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const ZERO: Self = Self([0; 6]);

    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }

    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetPortId(pub u64);

impl NetPortId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrimaryPortPolicy {
    #[default]
    Auto,
    Prefer,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetLogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDriverEvent {
    Interrupt,
    QueueWake { queue_index: u16 },
    Poll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetRxFrameLayout {
    frame_len: PacketByteCount,
    header_len: u16,
    payload_len: u16,
}

impl NetRxFrameLayout {
    pub fn new(frame_len: PacketByteCount, header_len: usize, payload_len: usize) -> Option<Self> {
        if header_len > u16::MAX as usize || payload_len > u16::MAX as usize {
            return None;
        }
        if header_len.checked_add(payload_len)? != frame_len.get() {
            return None;
        }
        Some(Self {
            frame_len,
            header_len: header_len as u16,
            payload_len: payload_len as u16,
        })
    }

    pub fn whole_payload(frame_len: PacketByteCount) -> Option<Self> {
        Self::new(frame_len, 0, frame_len.get())
    }

    pub const fn frame_len(self) -> PacketByteCount {
        self.frame_len
    }

    pub const fn header_len(self) -> usize {
        self.header_len as usize
    }

    pub const fn payload_len(self) -> usize {
        self.payload_len as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetRxMeta {
    queue_index: u16,
    layout: NetRxFrameLayout,
    flags: u32,
}

pub const NET_RX_FLAG_IP_CSUM_VERIFIED: u32 = 1 << 0;
pub const NET_RX_FLAG_L4_CSUM_VERIFIED: u32 = 1 << 1;

impl NetRxMeta {
    pub const fn new(queue_index: u16, layout: NetRxFrameLayout, flags: u32) -> Self {
        Self {
            queue_index,
            layout,
            flags,
        }
    }

    pub const fn queue_index(self) -> u16 {
        self.queue_index
    }

    pub const fn layout(self) -> NetRxFrameLayout {
        self.layout
    }

    pub const fn flags(self) -> u32 {
        self.flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxCompletionTicket(NonZeroU64);

impl TxCompletionTicket {
    pub const fn new(id: u64) -> Option<Self> {
        match NonZeroU64::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetTxMeta {
    pub queue_index: Option<u16>,
    pub flags: u32,
    pub vlan_tag: Option<u16>,
}

impl Default for NetTxMeta {
    fn default() -> Self {
        Self {
            queue_index: None,
            flags: 0,
            vlan_tag: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxLeaseId(NonZeroU64);

impl TxLeaseId {
    pub const fn new(id: u64) -> Option<Self> {
        match NonZeroU64::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDeviceOutcome {
    Transmitted,
    NotTransmitted,
    OutcomeUnknown,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct NetTxSegment(NetTxSegmentDescriptor);

// SAFETY: the descriptor carries a read-only packet data pointer plus DMA
// address and length. The runtime keeps the owning packet lease alive while the
// descriptor may cross worker queues.
unsafe impl Send for NetTxSegment {}
unsafe impl Sync for NetTxSegment {}

#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
struct NetTxSegmentDescriptor {
    cpu_ptr: NonNull<u8>,
    physical_addr: NonZeroU64,
    device_addr: NonZeroU64,
    len: PacketByteCount,
}

impl NetTxSegment {
    pub fn from_dma(
        cpu_ptr: *const u8,
        physical_addr: u64,
        device_addr: u64,
        len: PacketByteCount,
    ) -> Option<Self> {
        Some(Self(NetTxSegmentDescriptor {
            cpu_ptr: NonNull::new(cpu_ptr.cast_mut())?,
            physical_addr: NonZeroU64::new(physical_addr)?,
            device_addr: NonZeroU64::new(device_addr)?,
            len,
        }))
    }

    pub const fn cpu_ptr(&self) -> *const u8 {
        self.0.cpu_ptr.as_ptr().cast_const()
    }

    pub const fn device_addr(&self) -> NonZeroU64 {
        self.0.device_addr
    }

    pub const fn physical_addr(&self) -> NonZeroU64 {
        self.0.physical_addr
    }

    pub const fn len(&self) -> PacketByteCount {
        self.0.len
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NonEmptyTxSegments<'a> {
    segments: &'a [NetTxSegment],
}

impl<'a> NonEmptyTxSegments<'a> {
    pub const fn new(segments: &'a [NetTxSegment]) -> Option<Self> {
        if segments.is_empty() {
            None
        } else {
            Some(Self { segments })
        }
    }

    pub const fn as_slice(self) -> &'a [NetTxSegment] {
        self.segments
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TxSubmission<'a> {
    lease_id: TxLeaseId,
    segments: NonEmptyTxSegments<'a>,
}

impl<'a> TxSubmission<'a> {
    pub const fn new(lease_id: TxLeaseId, segments: NonEmptyTxSegments<'a>) -> Self {
        Self { lease_id, segments }
    }

    pub const fn lease_id(self) -> TxLeaseId {
        self.lease_id
    }

    pub const fn segments(self) -> &'a [NetTxSegment] {
        self.segments.as_slice()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetPortStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
    pub initialized: bool,
}

pub const NETDEV_FLAG_ADMIN_UP: u32 = 1 << 0;
pub const NETDEV_FLAG_BOUND_PORT: u32 = 1 << 1;
pub const NETDEV_FLAG_HEALTHY: u32 = 1 << 2;
pub const NETDEV_FLAG_PRIMARY: u32 = 1 << 3;
pub const NETDEV_FLAG_LINK_UP: u32 = 1 << 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDeviceInfo {
    pub port_id: NetPortId,
    pub if_id: Option<u16>,
    pub driver_name: &'static str,
    pub queue_pairs: u16,
    pub max_tx_segments: NonZeroU16,
    pub mtu: u32,
    pub mac: MacAddress,
    pub flags: u32,
}

impl Default for NetDeviceInfo {
    fn default() -> Self {
        Self {
            port_id: NetPortId::new(0),
            if_id: None,
            driver_name: "unknown",
            queue_pairs: 1,
            max_tx_segments: NonZeroU16::MIN,
            mtu: 1500,
            mac: MacAddress::ZERO,
            flags: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetPortRuntimeCookie(NonZeroUsize);

impl NetPortRuntimeCookie {
    pub const unsafe fn from_raw_unchecked(raw: usize) -> Self {
        Self(unsafe { NonZeroUsize::new_unchecked(raw) })
    }

    pub const fn from_raw(raw: usize) -> Option<Self> {
        match NonZeroUsize::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    pub const fn as_raw(self) -> usize {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxWritableRegion {
    cpu_ptr: NonNull<u8>,
    device_addr: NonZeroU64,
    writable_len: NonZeroUsize,
}

impl RxWritableRegion {
    pub const fn cpu_ptr(self) -> *mut u8 {
        self.cpu_ptr.as_ptr()
    }

    pub const fn device_addr(self) -> NonZeroU64 {
        self.device_addr
    }

    pub const fn writable_len(self) -> usize {
        self.writable_len.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxBufferErrorCause {
    VisibleData,
    EmptyWritableRegion,
    MissingDeviceAddress,
}

#[derive(Debug)]
pub struct RxBufferBuildError {
    cause: RxBufferErrorCause,
    packet: PacketRef,
}

impl RxBufferBuildError {
    pub const fn cause(&self) -> RxBufferErrorCause {
        self.cause
    }

    pub fn into_packet(self) -> PacketRef {
        self.packet
    }
}

#[derive(Debug)]
pub struct RxBuffer {
    packet: PacketRef,
    region: RxWritableRegion,
}

impl RxBuffer {
    pub fn try_from_empty_packet(mut packet: PacketRef) -> Result<Self, RxBufferBuildError> {
        if !packet.is_empty() {
            return Err(RxBufferBuildError {
                cause: RxBufferErrorCause::VisibleData,
                packet,
            });
        }
        let Some((cpu_ptr, device_addr, writable_len)) = packet.unpublished_writable_region()
        else {
            return Err(RxBufferBuildError {
                cause: RxBufferErrorCause::EmptyWritableRegion,
                packet,
            });
        };
        let Some(cpu_ptr) = NonNull::new(cpu_ptr) else {
            return Err(RxBufferBuildError {
                cause: RxBufferErrorCause::EmptyWritableRegion,
                packet,
            });
        };
        let Some(device_addr) = NonZeroU64::new(device_addr) else {
            return Err(RxBufferBuildError {
                cause: RxBufferErrorCause::MissingDeviceAddress,
                packet,
            });
        };
        let Some(writable_len) = NonZeroUsize::new(writable_len) else {
            return Err(RxBufferBuildError {
                cause: RxBufferErrorCause::EmptyWritableRegion,
                packet,
            });
        };
        Ok(Self {
            packet,
            region: RxWritableRegion {
                cpu_ptr,
                device_addr,
                writable_len,
            },
        })
    }

    pub const fn writable_region(&self) -> RxWritableRegion {
        self.region
    }

    pub fn physical_addr(&self) -> u64 {
        self.packet.phys_addr().as_u64()
    }

    pub fn complete(mut self, meta: NetRxMeta) -> Result<ReceivedPacket, RxCompletionError> {
        if meta.layout().frame_len().get() > self.region.writable_len() {
            return Err(RxCompletionError {
                cause: RxCompletionErrorCause::FrameTooLarge,
                buffer: self,
            });
        }
        // SAFETY: the driver may call `complete` only after the device has
        // stopped writing this buffer. The checked layout bounds the exact
        // initialized prefix that becomes visible.
        if unsafe {
            self.packet
                .publish_device_written(meta.layout().frame_len())
        }
        .is_err()
        {
            return Err(RxCompletionError {
                cause: RxCompletionErrorCause::FrameTooLarge,
                buffer: self,
            });
        }
        Ok(ReceivedPacket {
            packet: self.packet,
            meta,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxCompletionErrorCause {
    FrameTooLarge,
}

#[derive(Debug)]
pub struct RxCompletionError {
    cause: RxCompletionErrorCause,
    buffer: RxBuffer,
}

impl RxCompletionError {
    pub const fn cause(&self) -> RxCompletionErrorCause {
        self.cause
    }

    pub fn into_buffer(self) -> RxBuffer {
        self.buffer
    }
}

#[derive(Debug)]
pub struct ReceivedPacket {
    packet: PacketRef,
    meta: NetRxMeta,
}

impl ReceivedPacket {
    pub fn into_parts(self) -> (PacketRef, NetRxMeta) {
        (self.packet, self.meta)
    }
}

pub struct NetPortRuntimeOps {
    pub lease_rx_buffer: fn(NetPortRuntimeCookie, NetPortId) -> Option<RxBuffer>,
    pub submit_rx: fn(NetPortRuntimeCookie, NetPortId, ReceivedPacket) -> Result<(), &'static str>,
    pub complete_tx_lease:
        fn(NetPortRuntimeCookie, NetPortId, TxLeaseId, TxDeviceOutcome) -> Result<(), &'static str>,
    pub schedule_event:
        fn(NetPortRuntimeCookie, NetPortId, NetDriverEvent) -> Result<(), &'static str>,
    pub update_link: fn(NetPortRuntimeCookie, NetPortId, bool) -> Result<(), &'static str>,
    pub log: fn(NetLogLevel, &str),
}

impl NetPortRuntimeOps {
    pub const fn new(
        lease_rx_buffer: fn(NetPortRuntimeCookie, NetPortId) -> Option<RxBuffer>,
        submit_rx: fn(NetPortRuntimeCookie, NetPortId, ReceivedPacket) -> Result<(), &'static str>,
        complete_tx_lease: fn(
            NetPortRuntimeCookie,
            NetPortId,
            TxLeaseId,
            TxDeviceOutcome,
        ) -> Result<(), &'static str>,
        schedule_event: fn(
            NetPortRuntimeCookie,
            NetPortId,
            NetDriverEvent,
        ) -> Result<(), &'static str>,
        update_link: fn(NetPortRuntimeCookie, NetPortId, bool) -> Result<(), &'static str>,
        log: fn(NetLogLevel, &str),
    ) -> Self {
        Self {
            lease_rx_buffer,
            submit_rx,
            complete_tx_lease,
            schedule_event,
            update_link,
            log,
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetPortRuntimeHandle {
    context: NetPortRuntimeCookie,
    port_id: NetPortId,
    ops: &'static NetPortRuntimeOps,
}

impl NetPortRuntimeHandle {
    pub const fn new(
        context: NetPortRuntimeCookie,
        port_id: NetPortId,
        ops: &'static NetPortRuntimeOps,
    ) -> Self {
        Self {
            context,
            port_id,
            ops,
        }
    }

    pub const fn port_id(self) -> NetPortId {
        self.port_id
    }

    pub fn lease_rx_buffer(self) -> Option<RxBuffer> {
        (self.ops.lease_rx_buffer)(self.context, self.port_id)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the receiver cannot accept the operation.
    pub fn submit_rx(self, packet: ReceivedPacket) -> Result<(), &'static str> {
        (self.ops.submit_rx)(self.context, self.port_id, packet)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    pub fn complete_tx_lease(
        self,
        lease_id: TxLeaseId,
        outcome: TxDeviceOutcome,
    ) -> Result<(), &'static str> {
        (self.ops.complete_tx_lease)(self.context, self.port_id, lease_id, outcome)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    pub fn schedule_event(self, event: NetDriverEvent) -> Result<(), &'static str> {
        (self.ops.schedule_event)(self.context, self.port_id, event)
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or cannot be completed.
    pub fn update_link(self, up: bool) -> Result<(), &'static str> {
        (self.ops.update_link)(self.context, self.port_id, up)
    }

    pub fn log(self, level: NetLogLevel, message: &str) {
        (self.ops.log)(level, message);
    }
}

impl core::fmt::Debug for NetPortRuntimeHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetPortRuntimeHandle")
            .field("port_id", &self.port_id)
            .finish()
    }
}

pub trait NetDevicePort: Send + Sync {
    fn info(&self) -> NetDeviceInfo;

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str>;

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    fn bind(&self, _if_id: u16) -> Result<(), &'static str> {
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the receiver cannot accept the operation.
    fn submit_tx_chain(
        &self,
        submission: TxSubmission<'_>,
        meta: NetTxMeta,
    ) -> Result<(), &'static str>;

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or cannot be completed.
    fn set_interrupts_enabled(&self, _enabled: bool) -> Result<(), &'static str> {
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the service is not ready, times out, or reports a failed completion.
    fn poll(&self, _if_id: u16) -> Result<(), &'static str> {
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the service is not ready, times out, or reports a failed completion.
    fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str>;

    fn stats(&self) -> NetPortStats;

    /// Stops new DMA work and returns only after every device access to
    /// previously accepted buffers has been quiesced or revoked.
    ///
    /// # Errors
    ///
    /// Returns an error when DMA quiescence cannot be proven. The runtime must
    /// quarantine outstanding leases after such a failure.
    fn stop(&self) -> Result<(), &'static str>;
}

pub struct NetPortRegistration {
    pub info: NetDeviceInfo,
    pub driver: Box<dyn NetDevicePort>,
    pub primary_policy: PrimaryPortPolicy,
}

impl NetPortRegistration {
    pub fn new(
        info: NetDeviceInfo,
        driver: Box<dyn NetDevicePort>,
        primary_policy: PrimaryPortPolicy,
    ) -> Self {
        Self {
            info,
            driver,
            primary_policy,
        }
    }
}

pub trait NetDeviceServices: Send + Sync {
    fn devices(&self) -> Vec<NetDeviceInfo>;

    fn primary_device(&self) -> Option<NetDeviceInfo> {
        let devices = self.devices();
        devices
            .iter()
            .copied()
            .find(|device| device.flags & NETDEV_FLAG_PRIMARY != 0)
            .or_else(|| {
                devices
                    .into_iter()
                    .find(|device| device.flags & NETDEV_FLAG_BOUND_PORT != 0)
            })
    }
}

#[inline]
pub fn try_instance() -> Option<&'static dyn NetDeviceServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().netdev()
}

#[inline]
/// # Panics
///
/// Panics if network-device services have not been installed.
pub fn instance() -> &'static dyn NetDeviceServices {
    try_instance().expect("NetDeviceServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::net::{PacketRefStorage, PacketRefVTable, PacketWindowError};
    use alloc::vec;

    const RX_TEST_BACKING_LEN: usize = 32;
    const RX_TEST_HEADROOM: usize = 8;

    #[derive(Clone, Copy)]
    struct RxTestPacketState {
        base: *mut u8,
        offset: usize,
        len: usize,
        backing_len: usize,
    }

    unsafe fn rx_test_state(storage: &PacketRefStorage) -> &RxTestPacketState {
        unsafe { storage.as_state_ref::<RxTestPacketState>() }
    }

    unsafe fn rx_test_state_mut(storage: &mut PacketRefStorage) -> &mut RxTestPacketState {
        unsafe { storage.as_state_mut::<RxTestPacketState>() }
    }

    unsafe fn rx_test_data_ptr(storage: &PacketRefStorage) -> *const u8 {
        let state = unsafe { rx_test_state(storage) };
        unsafe { state.base.add(state.offset) }
    }

    unsafe fn rx_test_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
        let state = unsafe { rx_test_state_mut(storage) };
        unsafe { state.base.add(state.offset) }
    }

    unsafe fn rx_test_len(storage: &PacketRefStorage) -> usize {
        unsafe { rx_test_state(storage) }.len
    }

    unsafe fn rx_test_resize(storage: &mut PacketRefStorage, len: usize) -> bool {
        let state = unsafe { rx_test_state_mut(storage) };
        if len > state.backing_len.saturating_sub(state.offset) {
            return false;
        }
        state.len = len;
        true
    }

    unsafe fn rx_test_data_capacity(storage: &PacketRefStorage) -> usize {
        let state = unsafe { rx_test_state(storage) };
        state.backing_len.saturating_sub(state.offset)
    }

    unsafe fn rx_test_phys_addr(storage: &PacketRefStorage) -> u64 {
        0x7000 + unsafe { rx_test_state(storage) }.offset as u64
    }

    unsafe fn rx_test_device_address(storage: &PacketRefStorage) -> u64 {
        0x8000 + unsafe { rx_test_state(storage) }.offset as u64
    }

    unsafe fn rx_test_headroom(storage: &PacketRefStorage) -> usize {
        unsafe { rx_test_state(storage) }.offset
    }

    unsafe fn rx_test_advance(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
        let state = unsafe { rx_test_state_mut(storage) };
        if size.get() > state.len {
            return false;
        }
        state.offset += size.get();
        state.len -= size.get();
        true
    }

    unsafe fn rx_test_retreat(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
        let state = unsafe { rx_test_state_mut(storage) };
        if size.get() > state.offset {
            return false;
        }
        let Some(len) = state.len.checked_add(size.get()) else {
            return false;
        };
        let offset = state.offset - size.get();
        if len > state.backing_len.saturating_sub(offset) {
            return false;
        }
        state.offset = offset;
        state.len = len;
        true
    }

    unsafe fn rx_test_split_front(
        _storage: &PacketRefStorage,
        _len: PacketByteCount,
    ) -> Option<(PacketRefStorage, PacketRefStorage)> {
        None
    }

    unsafe fn rx_test_drop(storage: &mut PacketRefStorage) {
        let state = unsafe { rx_test_state_mut(storage) };
        let raw = state.base.cast::<[u8; RX_TEST_BACKING_LEN]>();
        unsafe { drop(Box::from_raw(raw)) };
    }

    static RX_TEST_VTABLE: PacketRefVTable = PacketRefVTable {
        data_ptr: rx_test_data_ptr,
        data_mut_ptr: rx_test_data_mut_ptr,
        len: rx_test_len,
        resize: rx_test_resize,
        data_capacity: rx_test_data_capacity,
        phys_addr: rx_test_phys_addr,
        device_address: rx_test_device_address,
        headroom: rx_test_headroom,
        advance: rx_test_advance,
        retreat: rx_test_retreat,
        split_front: rx_test_split_front,
        drop_storage: rx_test_drop,
    };

    fn make_rx_test_packet() -> PacketRef {
        let base = Box::into_raw(Box::new([0xCC; RX_TEST_BACKING_LEN])).cast::<u8>();
        let state = RxTestPacketState {
            base,
            offset: RX_TEST_HEADROOM,
            len: 0,
            backing_len: RX_TEST_BACKING_LEN,
        };
        unsafe {
            PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &RX_TEST_VTABLE)
        }
    }

    fn rx_meta(frame_len: usize) -> NetRxMeta {
        let frame_len = PacketByteCount::new(frame_len).expect("non-empty RX frame");
        let layout = NetRxFrameLayout::whole_payload(frame_len).expect("valid RX frame layout");
        NetRxMeta::new(0, layout, 0)
    }

    struct FakeServices {
        devices: Vec<NetDeviceInfo>,
    }

    impl NetDeviceServices for FakeServices {
        fn devices(&self) -> Vec<NetDeviceInfo> {
            self.devices.iter().copied().collect()
        }
    }

    struct FakePort {
        info: NetDeviceInfo,
        stats: NetPortStats,
    }

    impl NetDevicePort for FakePort {
        fn info(&self) -> NetDeviceInfo {
            self.info
        }

        fn start(&self, _runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
            Ok(())
        }

        fn submit_tx_chain(
            &self,
            _submission: TxSubmission<'_>,
            _meta: NetTxMeta,
        ) -> Result<(), &'static str> {
            Ok(())
        }

        fn handle_event(&self, _if_id: u16, _event: NetDriverEvent) -> Result<(), &'static str> {
            Ok(())
        }

        fn stats(&self) -> NetPortStats {
            self.stats
        }

        fn stop(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    #[test]
    fn mac_address_helpers_roundtrip() {
        let mac = MacAddress::from_octets(1, 2, 3, 4, 5, 6);
        assert_eq!(mac.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }

    #[test]
    fn primary_device_prefers_primary_flag_over_bound_port() {
        let bound = NetDeviceInfo {
            port_id: NetPortId::new(1),
            flags: NETDEV_FLAG_BOUND_PORT,
            ..NetDeviceInfo::default()
        };
        let primary = NetDeviceInfo {
            port_id: NetPortId::new(2),
            flags: NETDEV_FLAG_PRIMARY,
            ..NetDeviceInfo::default()
        };
        let services = FakeServices {
            devices: vec![bound, primary],
        };

        assert_eq!(services.primary_device(), Some(primary));
    }

    #[test]
    fn net_device_port_trait_object_reports_info_and_stats() {
        let port: Box<dyn NetDevicePort> = Box::new(FakePort {
            info: NetDeviceInfo {
                port_id: NetPortId::new(99),
                driver_name: "fake-port",
                queue_pairs: 2,
                flags: NETDEV_FLAG_HEALTHY,
                ..NetDeviceInfo::default()
            },
            stats: NetPortStats {
                tx_packets: 3,
                rx_packets: 4,
                initialized: true,
                ..NetPortStats::default()
            },
        });

        assert_eq!(port.info().port_id, NetPortId::new(99));
        assert_eq!(port.stats().rx_packets, 4);
        assert!(port.stats().initialized);
    }

    #[test]
    fn tx_segment_requires_checked_pointer_dma_and_len() {
        static BYTES: [u8; 8] = [0; 8];
        let len = PacketByteCount::new(8).expect("non-zero length");

        assert!(NetTxSegment::from_dma(core::ptr::null(), 1, 2, len).is_none());
        assert!(NetTxSegment::from_dma(BYTES.as_ptr(), 0, 2, len).is_none());
        assert!(NetTxSegment::from_dma(BYTES.as_ptr(), 1, 0, len).is_none());
        assert!(PacketByteCount::new(0).is_none());

        let segment = NetTxSegment::from_dma(BYTES.as_ptr(), 1, 2, len).expect("valid descriptor");
        assert_eq!(segment.cpu_ptr(), BYTES.as_ptr());
        assert_eq!(segment.physical_addr().get(), 1);
        assert_eq!(segment.device_addr().get(), 2);
        assert_eq!(segment.len().get(), 8);
    }

    #[test]
    fn tx_submission_requires_non_empty_segments() {
        static BYTES: [u8; 1] = [0; 1];
        let len = PacketByteCount::new(1).expect("non-zero length");
        let segment = NetTxSegment::from_dma(BYTES.as_ptr(), 1, 2, len).expect("valid descriptor");

        assert!(NonEmptyTxSegments::new(&[]).is_none());
        let segments = [segment];
        let non_empty = NonEmptyTxSegments::new(&segments).expect("non-empty slice");
        let lease_id = TxLeaseId::new(7).expect("non-zero lease");
        let submission = TxSubmission::new(lease_id, non_empty);

        assert_eq!(submission.lease_id(), lease_id);
        assert_eq!(submission.segments().len(), 1);
    }

    #[test]
    fn rx_frame_layout_rejects_inconsistent_lengths() {
        let frame_len = PacketByteCount::new(8).expect("non-zero frame");

        assert!(NetRxFrameLayout::new(frame_len, 4, 3).is_none());
        assert!(NetRxFrameLayout::new(frame_len, u16::MAX as usize + 1, 0).is_none());

        let layout = NetRxFrameLayout::new(frame_len, 3, 5).expect("consistent layout");
        assert_eq!(layout.frame_len().get(), 8);
        assert_eq!(layout.header_len(), 3);
        assert_eq!(layout.payload_len(), 5);
    }

    #[test]
    fn rx_writable_region_excludes_headroom_and_accepts_last_dma_byte() {
        let buffer = RxBuffer::try_from_empty_packet(make_rx_test_packet())
            .expect("empty packet becomes an RX buffer");
        let region = buffer.writable_region();

        assert_eq!(
            region.writable_len(),
            RX_TEST_BACKING_LEN - RX_TEST_HEADROOM
        );
        assert_eq!(region.device_addr().get(), 0x8000 + RX_TEST_HEADROOM as u64);
        // SAFETY: this test acts as the device while `buffer` exclusively owns
        // the unpublished writable region and writes within its exact bounds.
        unsafe {
            region.cpu_ptr().write_bytes(0x5A, region.writable_len());
            region.cpu_ptr().add(region.writable_len() - 1).write(0xA5);
        }

        let received = buffer
            .complete(rx_meta(region.writable_len()))
            .expect("a full-span DMA frame is valid");
        let (packet, _) = received.into_parts();
        assert_eq!(packet.len(), region.writable_len());
        assert_eq!(packet.data()[region.writable_len() - 1], 0xA5);
    }

    #[test]
    fn rx_completion_rejects_oversized_frame_and_returns_buffer() {
        let buffer = RxBuffer::try_from_empty_packet(make_rx_test_packet())
            .expect("empty packet becomes an RX buffer");
        let writable_len = buffer.writable_region().writable_len();

        let error = buffer
            .complete(rx_meta(writable_len + 1))
            .expect_err("oversized DMA completion must be rejected");
        assert_eq!(error.cause(), RxCompletionErrorCause::FrameTooLarge);
        assert_eq!(
            error.into_buffer().writable_region().writable_len(),
            writable_len
        );
    }

    #[test]
    fn rx_publishes_only_written_prefix_and_software_growth_zeroes_tail() {
        let buffer = RxBuffer::try_from_empty_packet(make_rx_test_packet())
            .expect("empty packet becomes an RX buffer");
        let region = buffer.writable_region();
        // SAFETY: this test acts as the device while `buffer` exclusively owns
        // the unpublished writable region. Bytes after the frame deliberately
        // remain at the backing sentinel value and must not become visible.
        unsafe {
            region.cpu_ptr().write(0x11);
            region.cpu_ptr().add(1).write(0x22);
            region.cpu_ptr().add(2).write(0x33);
        }

        let received = buffer
            .complete(rx_meta(3))
            .expect("device-written prefix is valid");
        let (mut packet, _) = received.into_parts();
        assert_eq!(packet.data(), &[0x11, 0x22, 0x33]);
        assert_eq!(packet.tailroom(), region.writable_len() - 3);

        packet.try_resize(6).expect("software growth fits backing");
        assert_eq!(packet.data(), &[0x11, 0x22, 0x33, 0, 0, 0]);
        assert_eq!(
            packet.try_resize(region.writable_len() + 1),
            Err(PacketWindowError::OutOfBounds)
        );
    }
}
