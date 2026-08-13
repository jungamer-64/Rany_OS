// ============================================================================
// interfaces/kernel_api/src/netdev.rs - Network device discovery and runtime traits
// ============================================================================

extern crate alloc;

use crate::resource::net::{PacketByteCount, PacketRef};
use crate::service::kernel;
use alloc::boxed::Box;
use alloc::vec::Vec;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TxCompletionMode {
    #[default]
    QueueAcceptance,
    DeviceCompletion(TxCompletionTicket),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetTxMeta {
    pub queue_index: Option<u16>,
    pub flags: u32,
    pub vlan_tag: Option<u16>,
    pub completion: TxCompletionMode,
}

impl Default for NetTxMeta {
    fn default() -> Self {
        Self {
            queue_index: None,
            flags: 0,
            vlan_tag: None,
            completion: TxCompletionMode::QueueAcceptance,
        }
    }
}

impl NetTxMeta {
    pub const fn completion(&self) -> TxCompletionMode {
        self.completion
    }

    pub const fn device_completion_ticket(&self) -> Option<TxCompletionTicket> {
        match self.completion {
            TxCompletionMode::QueueAcceptance => None,
            TxCompletionMode::DeviceCompletion(ticket) => Some(ticket),
        }
    }
}

pub type TxLeaseId = u64;

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
    device_addr: NonZeroU64,
    len: PacketByteCount,
}

impl NetTxSegment {
    pub fn from_dma(cpu_ptr: *const u8, device_addr: u64, len: PacketByteCount) -> Option<Self> {
        Some(Self(NetTxSegmentDescriptor {
            cpu_ptr: NonNull::new(cpu_ptr.cast_mut())?,
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

pub struct NetPortRuntimeOps {
    pub alloc_packet: fn(NetPortRuntimeCookie, NetPortId) -> Option<PacketRef>,
    pub submit_rx:
        fn(NetPortRuntimeCookie, NetPortId, PacketRef, NetRxMeta) -> Result<(), &'static str>,
    pub complete_tx_lease: fn(
        NetPortRuntimeCookie,
        NetPortId,
        TxLeaseId,
        Result<(), &'static str>,
    ) -> Result<(), &'static str>,
    pub schedule_event:
        fn(NetPortRuntimeCookie, NetPortId, NetDriverEvent) -> Result<(), &'static str>,
    pub update_link: fn(NetPortRuntimeCookie, NetPortId, bool) -> Result<(), &'static str>,
    pub log: fn(NetLogLevel, &str),
}

impl NetPortRuntimeOps {
    pub const fn new(
        alloc_packet: fn(NetPortRuntimeCookie, NetPortId) -> Option<PacketRef>,
        submit_rx: fn(
            NetPortRuntimeCookie,
            NetPortId,
            PacketRef,
            NetRxMeta,
        ) -> Result<(), &'static str>,
        complete_tx_lease: fn(
            NetPortRuntimeCookie,
            NetPortId,
            TxLeaseId,
            Result<(), &'static str>,
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
            alloc_packet,
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

    pub fn alloc_packet(self) -> Option<PacketRef> {
        (self.ops.alloc_packet)(self.context, self.port_id)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the receiver cannot accept the operation.
    pub fn submit_rx(self, packet: PacketRef, meta: NetRxMeta) -> Result<(), &'static str> {
        (self.ops.submit_rx)(self.context, self.port_id, packet, meta)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    pub fn complete_tx_lease(
        self,
        lease_id: TxLeaseId,
        result: Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        (self.ops.complete_tx_lease)(self.context, self.port_id, lease_id, result)
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

    fn stop(&self);
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
    use alloc::vec;

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

        fn stop(&self) {}
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

        assert!(NetTxSegment::from_dma(core::ptr::null(), 1, len).is_none());
        assert!(NetTxSegment::from_dma(BYTES.as_ptr(), 0, len).is_none());
        assert!(PacketByteCount::new(0).is_none());

        let segment = NetTxSegment::from_dma(BYTES.as_ptr(), 1, len).expect("valid descriptor");
        assert_eq!(segment.cpu_ptr(), BYTES.as_ptr());
        assert_eq!(segment.device_addr().get(), 1);
        assert_eq!(segment.len().get(), 8);
    }

    #[test]
    fn tx_submission_requires_non_empty_segments() {
        static BYTES: [u8; 1] = [0; 1];
        let len = PacketByteCount::new(1).expect("non-zero length");
        let segment = NetTxSegment::from_dma(BYTES.as_ptr(), 1, len).expect("valid descriptor");

        assert!(NonEmptyTxSegments::new(&[]).is_none());
        let segments = [segment];
        let non_empty = NonEmptyTxSegments::new(&segments).expect("non-empty slice");
        let submission = TxSubmission::new(7, non_empty);

        assert_eq!(submission.lease_id(), 7);
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
}
