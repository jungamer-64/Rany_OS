fn complete_immediately<F: core::future::Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => {
            panic!("completed operation unexpectedly remained pending")
        }
    }
}

use super::*;
use crate::net::runtime::NetRuntimeHandle;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};

struct FakeDriverState {
    bind_calls: AtomicUsize,
    last_if_id: AtomicU16,
    last_event_queue: AtomicU16,
    poll_calls: AtomicUsize,
    stop_calls: AtomicUsize,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    initialized: AtomicBool,
    runtime: PoisonLock<Option<NetPortRuntimeHandle>>,
}

impl FakeDriverState {
    const fn new() -> Self {
        Self {
            bind_calls: AtomicUsize::new(0),
            last_if_id: AtomicU16::new(0),
            last_event_queue: AtomicU16::new(u16::MAX),
            poll_calls: AtomicUsize::new(0),
            stop_calls: AtomicUsize::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
            runtime: PoisonLock::new(None),
        }
    }

    fn set_stats(&self, tx_packets: u64, rx_packets: u64, initialized: bool) {
        self.tx_packets.store(tx_packets, Ordering::Release);
        self.rx_packets.store(rx_packets, Ordering::Release);
        self.initialized.store(initialized, Ordering::Release);
    }

    fn update_link(&self, up: bool) -> Result<(), &'static str> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "fake runtime lock poisoned")?
            .ok_or("fake runtime not installed")?;
        runtime.update_link(up)
    }

    fn submit_rx(&self, packet: PacketRef, meta: NetRxMeta) -> Result<(), &'static str> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "fake runtime lock poisoned")?
            .ok_or("fake runtime not installed")?;
        let buffer = runtime
            .lease_rx_buffer()
            .ok_or("fake driver could not lease RX storage")?;
        let region = buffer.writable_region();
        if packet.len() > region.len().get() {
            return Err("fake RX packet exceeds writable DMA region");
        }
        // SAFETY: the RX lease grants exclusive write access to the
        // advertised region until completion consumes it.
        unsafe {
            core::ptr::copy_nonoverlapping(
                packet.data().as_ptr(),
                region.cpu_ptr().cast_mut(),
                packet.len(),
            );
        }
        // SAFETY: the synchronous emulated device write above has finished.
        let received =
            unsafe { buffer.complete(meta) }.map_err(|_| "fake RX completion layout is invalid")?;
        runtime.submit_rx(received)
    }
}

struct FakeDriver {
    state: Arc<FakeDriverState>,
    driver_name: &'static str,
    start_error: Option<&'static str>,
    stop_error: Option<kernel_api::error::KapiError>,
}

impl FakeDriver {
    const fn new(state: Arc<FakeDriverState>) -> Self {
        Self {
            state,
            driver_name: "fake",
            start_error: None,
            stop_error: None,
        }
    }

    const fn with_start_error(
        state: Arc<FakeDriverState>,
        driver_name: &'static str,
        start_error: &'static str,
    ) -> Self {
        Self {
            state,
            driver_name,
            start_error: Some(start_error),
            stop_error: None,
        }
    }

    const fn with_stop_error(
        state: Arc<FakeDriverState>,
        driver_name: &'static str,
        stop_error: kernel_api::error::KapiError,
    ) -> Self {
        Self {
            state,
            driver_name,
            start_error: None,
            stop_error: Some(stop_error),
        }
    }
}

fn fake_driver() -> (Arc<FakeDriverState>, Box<dyn NetDevicePort>) {
    let state = Arc::new(FakeDriverState::new());
    (Arc::clone(&state), Box::new(FakeDriver::new(state)))
}

fn fake_driver_with_start_error(
    driver_name: &'static str,
    start_error: &'static str,
) -> (Arc<FakeDriverState>, Box<dyn NetDevicePort>) {
    let state = Arc::new(FakeDriverState::new());
    (
        Arc::clone(&state),
        Box::new(FakeDriver::with_start_error(
            state,
            driver_name,
            start_error,
        )),
    )
}

fn fake_driver_with_stop_error(
    driver_name: &'static str,
    stop_error: kernel_api::error::KapiError,
) -> (Arc<FakeDriverState>, Box<dyn NetDevicePort>) {
    let state = Arc::new(FakeDriverState::new());
    (
        Arc::clone(&state),
        Box::new(FakeDriver::with_stop_error(state, driver_name, stop_error)),
    )
}

// SAFETY: this fixture performs no hardware access and holds no DMA authority after rejection or completion.
unsafe impl NetDevicePort for FakeDriver {
    fn info(&self) -> NetDeviceInfo {
        NetDeviceInfo {
            port_id: NetPortId::new(0x9009),
            if_id: None,
            driver_name: self.driver_name,
            queue_pairs: 1,
            max_tx_segments: core::num::NonZeroU16::new(8).expect("fake segment limit is non-zero"),
            mtu: stack::MTU as u32,
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 5),
            flags: NETDEV_FLAG_HEALTHY,
        }
    }

    fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
        if let Some(error) = self.start_error {
            Err(error)
        } else {
            *self
                .state
                .runtime
                .lock()
                .map_err(|_| "fake runtime lock poisoned")? = Some(runtime);
            Ok(())
        }
    }

    fn bind(&self, if_id: u16) -> Result<(), &'static str> {
        self.state.bind_calls.fetch_add(1, Ordering::Relaxed);
        self.state.last_if_id.store(if_id, Ordering::Release);
        Ok(())
    }

    fn submit_tx_chain(
        &self,
        _submission: TxPacketSubmission<'_>,
        _meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    fn poll(&self, if_id: u16) -> Result<(), &'static str> {
        self.state.last_if_id.store(if_id, Ordering::Release);
        self.state.poll_calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
        self.state.last_if_id.store(if_id, Ordering::Release);
        if let NetDriverEvent::QueueWake { queue_index } = event {
            self.state
                .last_event_queue
                .store(queue_index, Ordering::Release);
        }
        Ok(())
    }

    fn stats(&self) -> NetPortStats {
        NetPortStats {
            tx_packets: self.state.tx_packets.load(Ordering::Acquire),
            rx_packets: self.state.rx_packets.load(Ordering::Acquire),
            tx_errors: 0,
            rx_errors: 0,
            initialized: self.state.initialized.load(Ordering::Acquire),
        }
    }

    fn stop(&self) -> kernel_api::error::KapiResult<()> {
        let stop_index = self.state.stop_calls.fetch_add(1, Ordering::Relaxed);
        match (self.stop_error, stop_index) {
            (Some(error), 0) => Err(error),
            _ => Ok(()),
        }
    }
}

fn test_port_id(index: u16) -> NetPortId {
    NetPortId::new(0x9000 + u64::from(index))
}

fn register_test_port(
    runtime: NetRuntimeHandle,
    index: u16,
    driver: Box<dyn NetDevicePort>,
    primary_policy: PrimaryPortPolicy,
) -> Result<NetIfId, NetPortRegistrationError> {
    let info = NetDeviceInfo {
        port_id: test_port_id(index),
        driver_name: "fake",
        queue_pairs: 1,
        mtu: stack::MTU as u32,
        mac: MacAddress::from_octets(0, 1, 2, 3, 4, index as u8),
        flags: NETDEV_FLAG_HEALTHY | NETDEV_FLAG_ADMIN_UP | NETDEV_FLAG_LINK_UP,
        ..NetDeviceInfo::default()
    };
    register_port_in(
        runtime,
        NetPortRegistration::new(info, driver, primary_policy),
    )
}

fn unregister_test_port(runtime: NetRuntimeHandle, if_id: NetIfId) -> bool {
    unregister_port_in(runtime, if_id).expect("fake driver quiesces during stop")
}

struct PacketFixtureBytes(core::cell::UnsafeCell<Box<[u8]>>);
// SAFETY: this storage provides no access independently of packet windows.
// Descriptor and mapping leases only retain its allocation lifetime.
unsafe impl Sync for PacketFixtureBytes {}
struct PacketFixture {
    header: core::mem::MaybeUninit<kernel_api::resource::net::PacketBufferMemory>,
    releases: Arc<AtomicUsize>,
}
unsafe fn retire_packet_fixture(owner: core::ptr::NonNull<()>) {
    // SAFETY: construction transfers this sole Box to the last counted
    // window/descriptor; the retained counter remains valid on any CPU.
    let mut fixture = unsafe { Box::from_raw(owner.cast::<PacketFixture>().as_ptr()) };
    fixture.releases.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the fixture initialized this header before sole acquisition.
    unsafe { fixture.header.assume_init_drop() };
}
fn packet_fixture(len: usize, physical: u64) -> PacketRef {
    counted_packet_fixture(len, physical, &Arc::new(AtomicUsize::new(0)))
}
fn counted_packet_fixture(len: usize, physical: u64, releases: &Arc<AtomicUsize>) -> PacketRef {
    let capacity = len.max(64);
    assert!(physical.checked_add(capacity as u64 - 1).is_some());
    let mut storage = Arc::new(PacketFixtureBytes(core::cell::UnsafeCell::new(
        alloc::vec![0u8; capacity].into_boxed_slice(),
    )));
    let data =
        core::ptr::NonNull::new(Arc::get_mut(&mut storage).unwrap().0.get_mut().as_mut_ptr())
            .unwrap();
    let mut fixture = Box::new(PacketFixture {
        header: core::mem::MaybeUninit::uninit(),
        releases: Arc::clone(releases),
    });
    let owner = core::ptr::NonNull::from(fixture.as_mut()).cast();
    // SAFETY: this fixture models a physical RAM range without submitting
    // hardware access. Initialized retained storage has a stable header and
    // no independent CPU access; mapping retention owns a separate Arc.
    fixture.header.write(unsafe {
        kernel_api::resource::net::PacketBufferMemory::new(
            data,
            kernel_api::dma::DmaByteCount::new(capacity).unwrap(),
            kernel_api::resource::memory::PhysicalAddress::new(physical),
            storage,
            owner,
            retire_packet_fixture,
        )
    });
    let header = core::ptr::NonNull::new(fixture.header.as_mut_ptr()).unwrap();
    // SAFETY: the fixture owns the live header at its first sole acquisition.
    let mut packet = unsafe { PacketRef::acquire(header, 0) }.unwrap();
    let _retirement_owner = Box::into_raw(fixture);
    packet.try_resize(len).unwrap();
    packet
}

async fn schedule_event_from_interrupt_context_enqueues_successfully(runtime: NetRuntimeHandle) {
    let (state, driver) = fake_driver();
    let if_id =
        register_test_port(runtime, 89, driver, PrimaryPortPolicy::Never).expect("register port");

    let result = with_port_handle_in(runtime, if_id, |handle| {
        handle.enqueue_event_from_isr(NetDriverEvent::QueueWake { queue_index: 3 })
    })
    .expect("handle");

    assert!(result);
    let handled = async {
        // LOOP_PROOF: mode=event; reason=The ordinary port worker publishes handling of this event and a real timer bounds each observation under the enclosing deadline.;
        loop {
            if state.last_event_queue.load(Ordering::Acquire) == 3 {
                return Ok::<_, kernel_api::service::time::TimerError>(());
            }
            crate::task::sleep_ms(1).await?;
        }
    };
    assert!(matches!(
        crate::task::with_timeout(handled, 5_000).await,
        crate::task::TimeoutResult::Completed(Ok(()))
    ));
    assert!(unregister_test_port(runtime, if_id));
}

fn device_handle_rebind_updates_binding_smoke(runtime: NetRuntimeHandle) {
    let (state, driver) = fake_driver();
    let handle = NetDeviceHandle::new(
        driver,
        NetDeviceBinding {
            port_id: test_port_id(9),
            if_id: NetIfId(1),
        },
        runtime.context(),
    );

    handle
        .rebind(NetDeviceBinding {
            port_id: test_port_id(9),
            if_id: NetIfId(22),
        })
        .expect("rebind");

    assert_eq!(handle.binding().if_id, NetIfId(22));
    assert_eq!(state.bind_calls.load(Ordering::Relaxed), 1);
    assert_eq!(state.last_if_id.load(Ordering::Acquire), 22);
    handle.stop().expect("unpublished fake handle quiesces");
}

fn register_port_exposes_snapshot_smoke(runtime: NetRuntimeHandle) {
    let (state, driver) = fake_driver();
    state.set_stats(11, 7, true);

    let if_id =
        register_test_port(runtime, 90, driver, PrimaryPortPolicy::Never).expect("register port");

    let info = port_info_in(runtime, test_port_id(90)).expect("port info");
    let stats = port_stats_in(runtime, test_port_id(90)).expect("port stats");

    assert_eq!(
        lookup_if_by_port_id_in(runtime, test_port_id(90)),
        Some(if_id)
    );
    assert_eq!(info.port_id, test_port_id(90));
    assert_eq!(info.if_id, Some(if_id.0));
    assert_eq!(stats.tx_packets, 11);
    assert_eq!(stats.rx_packets, 7);
    assert!(list_port_ids_in(runtime).contains(&test_port_id(90)));

    assert!(unregister_test_port(runtime, if_id));
    assert_eq!(state.stop_calls.load(Ordering::Relaxed), 1);
}

fn register_port_rolls_back_device_state_when_driver_start_fails(runtime: NetRuntimeHandle) {
    let (_state, driver) = fake_driver_with_start_error("start-fail", "start failed");

    assert_eq!(
        register_test_port(runtime, 88, driver, PrimaryPortPolicy::Never),
        Err(NetPortRegistrationError::Released("start failed"))
    );
    assert_eq!(lookup_if_by_port_id_in(runtime, test_port_id(88)), None);
    assert!(!list_port_ids_in(runtime).contains(&test_port_id(88)));
    assert!(
        manager::list_interfaces_in(runtime)
            .expect("manager query")
            .iter()
            .all(|iface| iface.name != "start-fail")
    );
}

fn failed_start_retains_owned_interface_until_shutdown_acknowledges(runtime: NetRuntimeHandle) {
    let state = Arc::new(FakeDriverState::new());
    let driver = Box::new(FakeDriver {
        state: Arc::clone(&state),
        driver_name: "start-retained",
        start_error: Some("start failed"),
        stop_error: Some(kernel_api::error::KapiError::Busy),
    });
    let result = register_test_port(runtime, 84, driver, PrimaryPortPolicy::Never);
    let if_id = lookup_if_by_port_id_in(runtime, test_port_id(84))
        .expect("failed shutdown retains the owned index");
    assert_eq!(
        result,
        Err(NetPortRegistrationError::Retained {
            if_id,
            cause: "start failed",
            shutdown: kernel_api::error::KapiError::Busy,
        })
    );
    assert_eq!(state.stop_calls.load(Ordering::Acquire), 1);
    assert!(unregister_test_port(runtime, if_id));
    assert_eq!(state.stop_calls.load(Ordering::Acquire), 2);
    assert_eq!(lookup_if_by_port_id_in(runtime, test_port_id(84)), None);
}

fn duplicate_port_registration_preserves_the_canonical_interface(runtime: NetRuntimeHandle) {
    let (_, driver_a) = fake_driver();
    let (_, duplicate_driver) = fake_driver();

    let if_id = register_test_port(runtime, 86, driver_a, PrimaryPortPolicy::Auto)
        .expect("register first port");
    let duplicate = register_test_port(runtime, 86, duplicate_driver, PrimaryPortPolicy::Prefer)
        .expect("repeat registration");

    assert_eq!(duplicate, if_id);
    assert_eq!(
        lookup_if_by_port_id_in(runtime, test_port_id(86)),
        Some(if_id)
    );
    assert_eq!(manager::primary_interface_in(runtime), Some(if_id));
    assert!(unregister_test_port(runtime, if_id));
}

fn register_port_prefer_primary_updates_primary_selection_smoke(runtime: NetRuntimeHandle) {
    let (_, driver_a) = fake_driver();
    let (_, driver_b) = fake_driver();

    let if_a = register_test_port(runtime, 91, driver_a, PrimaryPortPolicy::Auto)
        .expect("register first port");
    let if_b = register_test_port(runtime, 92, driver_b, PrimaryPortPolicy::Prefer)
        .expect("register second port");

    assert_eq!(manager::primary_interface_in(runtime), Some(if_b));
    assert!(
        port_info_in(runtime, test_port_id(92))
            .expect("primary info")
            .flags
            & NETDEV_FLAG_PRIMARY
            != 0
    );

    assert!(unregister_test_port(runtime, if_b));
    assert_eq!(manager::primary_interface_in(runtime), Some(if_a));
    assert!(unregister_test_port(runtime, if_a));
}

fn primary_link_callback_promotes_secondary(runtime: NetRuntimeHandle) {
    let (state_a, driver_a) = fake_driver();
    let (_, driver_b) = fake_driver();

    let if_a = register_test_port(runtime, 93, driver_a, PrimaryPortPolicy::Auto)
        .expect("register first port");
    let if_b = register_test_port(runtime, 94, driver_b, PrimaryPortPolicy::Auto)
        .expect("register second port");
    assert_eq!(manager::primary_interface_in(runtime), Some(if_a));

    state_a.update_link(false).expect("publish link down");

    assert_eq!(manager::primary_interface_in(runtime), Some(if_b));
    assert!(!manager::is_interface_operational_in(runtime, if_a));
    assert!(manager::is_interface_operational_in(runtime, if_b));
    let payload =
        PacketPayload::try_single(packet_fixture(1, 0x4000)).expect("test payload is non-empty");
    assert!(transmit_packet_in(runtime, if_a, payload, NetTxMeta::default(),).is_err());

    assert!(unregister_test_port(runtime, if_b));
    assert!(unregister_test_port(runtime, if_a));
}

fn unregister_primary_without_survivor_clears_primary_runtime(runtime: NetRuntimeHandle) {
    let (_, driver) = fake_driver();
    let if_a =
        register_test_port(runtime, 95, driver, PrimaryPortPolicy::Auto).expect("register port");
    assert_eq!(manager::primary_interface_in(runtime), Some(if_a));

    assert!(unregister_test_port(runtime, if_a));
    assert_eq!(manager::primary_interface_in(runtime), None);
    assert!(
        manager::get_interface_in(runtime, if_a)
            .expect("manager query")
            .is_none()
    );
}

fn recovered_interface_does_not_reclaim_primary_after_failover(runtime: NetRuntimeHandle) {
    let (state_a, driver_a) = fake_driver();
    let (_, driver_b) = fake_driver();

    let if_a = register_test_port(runtime, 96, driver_a, PrimaryPortPolicy::Auto)
        .expect("register first port");
    let if_b = register_test_port(runtime, 97, driver_b, PrimaryPortPolicy::Auto)
        .expect("register second port");

    assert_eq!(manager::primary_interface_in(runtime), Some(if_a));
    state_a.update_link(false).expect("publish link down");
    assert_eq!(manager::primary_interface_in(runtime), Some(if_b));

    state_a.update_link(true).expect("publish link recovery");
    assert_eq!(manager::primary_interface_in(runtime), Some(if_b));

    assert!(unregister_test_port(runtime, if_b));
    assert!(unregister_test_port(runtime, if_a));
}

fn stopped_interface_rejects_rx_at_the_device_boundary(runtime: NetRuntimeHandle) {
    let (state, driver) = fake_driver();
    let if_id =
        register_test_port(runtime, 98, driver, PrimaryPortPolicy::Auto).expect("register port");
    state.update_link(false).expect("publish link down");

    let frame_len = PacketByteCount::new(14).expect("non-empty frame");
    let layout = kernel_api::service::netdev::NetRxFrameLayout::whole_payload(frame_len)
        .expect("valid frame layout");
    let packet = packet_fixture(frame_len.get(), 0x3000);
    assert_eq!(
        state.submit_rx(packet, NetRxMeta::new(0, layout, 0)),
        Err("network interface is not operational")
    );

    assert!(unregister_test_port(runtime, if_id));
}

fn tx_completion_future_resolves_success(runtime: NetRuntimeHandle) {
    let (completion_id, future) = register_tx_completion_in(runtime);
    assert!(complete_tx_request_in(runtime, completion_id, Ok(())));
    assert_eq!(complete_immediately(future), Ok(()));
}

fn tx_completion_future_resolves_error(runtime: NetRuntimeHandle) {
    let (completion_id, future) = register_tx_completion_in(runtime);
    assert!(complete_tx_request_in(
        runtime,
        completion_id,
        Err("submit failed")
    ));
    assert_eq!(complete_immediately(future), Err("submit failed"));
}

fn tx_payload_lease_derives_descriptor_for_each_owner(runtime: NetRuntimeHandle) {
    let first = packet_fixture(8, 0x1000);
    let second = packet_fixture(16, 0x2000);
    let payload = PacketPayload::try_pair(first, second).expect("non-empty test segments");

    let lease = TxPayloadLease::from_payload(payload).expect("payload lease");
    let registered =
        register_tx_payload_lease_in(runtime, NetIfId(1), lease, None, NetTxMeta::default())
            .expect("registered test lease");
    let request = registered.into_request();
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(2)
        .expect("descriptor scratch");
    assert!(build_tx_descriptors_in(runtime, request.lease_id, &mut descriptors, 2,).is_some());
    assert_eq!(descriptors.len(), 2);
    assert_eq!(descriptors[0].physical_address().as_u64(), 0x1000);
    assert_eq!(descriptors[0].len().get(), 8);
    assert_eq!(descriptors[1].physical_address().as_u64(), 0x2000);
    assert_eq!(descriptors[1].len().get(), 16);
    assert!(reject_registered_tx_lease_in(
        runtime,
        request.lease_id,
        "test cleanup",
    ));
}

fn tx_descriptor_plan_rejects_device_fanout_limit(runtime: NetRuntimeHandle) {
    let payload = PacketPayload::try_pair(packet_fixture(8, 0x1000), packet_fixture(8, 0x2000))
        .expect("two retained test packets");
    let lease = TxPayloadLease::from_payload(payload).expect("payload lease");
    let registered =
        register_tx_payload_lease_in(runtime, NetIfId(1), lease, None, NetTxMeta::default())
            .expect("registered test lease");
    let request = registered.into_request();
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(1)
        .expect("descriptor scratch");
    assert!(build_tx_descriptors_in(runtime, request.lease_id, &mut descriptors, 1,).is_none());
    assert!(reject_registered_tx_lease_in(
        runtime,
        request.lease_id,
        "test cleanup",
    ));
}

fn packet_window_descriptors_reference_original_packet_range(runtime: NetRuntimeHandle) {
    let mut packet = crate::net::datapath::mempool::alloc_packet_in(runtime).expect("packet");
    packet.try_resize(32).expect("test packet resize succeeds");
    let base_ptr = packet.data().as_ptr() as usize;
    let base_physical = packet.phys_addr().as_u64();
    let owners = TxPayloadOwners::from_packets(alloc::vec![packet]).expect("owners");
    let header = packet_fixture(8, 0x40);

    let bounds = TxPayloadWindowBounds::checked(
        &owners,
        8,
        PacketByteCount::new(16).expect("non-empty window"),
    )
    .expect("owner-bound window");
    let lease = TxPayloadLease::from_header_and_owner_window(header, &owners, bounds)
        .expect("fragment lease");
    let group_id = register_tx_owner_group_in(
        runtime,
        owners,
        TxOwnerGroupLeaseCount::new(1).expect("one lease"),
        None,
    );
    let request = register_grouped_tx_payload_lease_in(
        runtime,
        NetIfId(1),
        lease,
        group_id,
        NetTxMeta::default(),
    )
    .expect("registered fragment lease");
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(2)
        .expect("descriptor scratch");
    assert!(build_tx_descriptors_in(runtime, request.lease_id, &mut descriptors, 2,).is_some());
    let payload_descriptor = &descriptors[1];

    assert_eq!(descriptors.len(), 2);
    assert_eq!(payload_descriptor.cpu_ptr(), (base_ptr + 8) as *const u8);
    assert_eq!(
        payload_descriptor.physical_address().as_u64(),
        base_physical + 8
    );
    assert_eq!(payload_descriptor.len().get(), 16);
    assert!(reject_registered_tx_lease_in(
        runtime,
        request.lease_id,
        "test cleanup",
    ));
}

fn tx_owner_group_completes_after_all_fragment_leases(runtime: NetRuntimeHandle) {
    let mut owner = crate::net::datapath::mempool::alloc_packet_in(runtime).expect("owner");
    owner.try_resize(32).expect("test owner resize succeeds");
    let mut header_a = crate::net::datapath::mempool::alloc_packet_in(runtime).expect("header a");
    header_a
        .try_resize(8)
        .expect("first test header resize succeeds");
    let mut header_b = crate::net::datapath::mempool::alloc_packet_in(runtime).expect("header b");
    header_b
        .try_resize(8)
        .expect("second test header resize succeeds");
    let (completion_id, future) = register_tx_completion_in(runtime);
    let owners = TxPayloadOwners::from_packets(alloc::vec![owner]).expect("non-empty owner");
    let group_id = register_tx_owner_group_in(
        runtime,
        owners,
        TxOwnerGroupLeaseCount::new(2).expect("non-zero leases"),
        Some(completion_id),
    );
    let request_a = register_grouped_tx_payload_lease_in(
        runtime,
        NetIfId(1),
        TxPayloadLease::from_payload(
            PacketPayload::try_single(header_a).expect("non-empty first header"),
        )
        .expect("request a lease"),
        group_id,
        NetTxMeta::default(),
    )
    .expect("request a");
    let request_b = register_grouped_tx_payload_lease_in(
        runtime,
        NetIfId(1),
        TxPayloadLease::from_payload(
            PacketPayload::try_single(header_b).expect("non-empty second header"),
        )
        .expect("request b lease"),
        group_id,
        NetTxMeta::default(),
    )
    .expect("request b");

    assert!(
        runtime
            .context()
            .tx_owner_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&group_id)
    );
    assert!(begin_tx_submission_in(runtime, request_a.lease_id));
    assert!(complete_tx_lease_in(
        runtime,
        request_a.lease_id,
        TxDeviceOutcome::Transmitted,
    ));
    assert!(
        runtime
            .context()
            .tx_owner_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&group_id)
    );
    assert!(begin_tx_submission_in(runtime, request_b.lease_id));
    assert!(complete_tx_lease_in(
        runtime,
        request_b.lease_id,
        TxDeviceOutcome::NotTransmitted,
    ));
    assert!(
        !runtime
            .context()
            .tx_owner_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&group_id)
    );
    assert_eq!(
        complete_immediately(future),
        Err("device did not transmit packet")
    );
}

fn accepted_tx_lease_retains_backing_until_exactly_one_completion(runtime: NetRuntimeHandle) {
    let releases = Arc::new(AtomicUsize::new(0));
    let payload = PacketPayload::try_single(counted_packet_fixture(8, 0x9100, &releases))
        .expect("counted payload is non-empty");
    let lease = TxPayloadLease::from_payload(payload).expect("payload lease");
    let request =
        register_tx_payload_lease_in(runtime, NetIfId(301), lease, None, NetTxMeta::default())
            .expect("registered lease")
            .into_request();

    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert!(begin_tx_submission_in(runtime, request.lease_id));
    assert!(mark_tx_device_owned_in(runtime, request.lease_id));
    assert_eq!(releases.load(Ordering::SeqCst), 0);

    assert!(complete_tx_lease_in(
        runtime,
        request.lease_id,
        TxDeviceOutcome::Transmitted,
    ));
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert!(!complete_tx_lease_in(
        runtime,
        request.lease_id,
        TxDeviceOutcome::Transmitted,
    ));
    assert_eq!(releases.load(Ordering::SeqCst), 1);
}

fn synchronous_completion_consumes_submitting_lease_without_recycling_early(
    runtime: NetRuntimeHandle,
) {
    let releases = Arc::new(AtomicUsize::new(0));
    let payload = PacketPayload::try_single(counted_packet_fixture(8, 0x9200, &releases))
        .expect("counted payload is non-empty");
    let request = register_tx_payload_lease_in(
        runtime,
        NetIfId(302),
        TxPayloadLease::from_payload(payload).expect("payload lease"),
        None,
        NetTxMeta::default(),
    )
    .expect("registered lease")
    .into_request();

    let mut regions = Vec::new();
    regions.try_reserve_exact(1).unwrap();
    assert!(build_tx_descriptors_in(runtime, request.lease_id, &mut regions, 1).is_some());
    assert!(begin_tx_submission_in(runtime, request.lease_id));
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert!(complete_tx_lease_in(
        runtime,
        request.lease_id,
        TxDeviceOutcome::Transmitted,
    ));
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    regions.clear();
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert!(mark_tx_device_owned_in(runtime, request.lease_id));
    assert!(!complete_tx_lease_in(
        runtime,
        request.lease_id,
        TxDeviceOutcome::Transmitted,
    ));
}

fn rejected_tx_lease_returns_backing_without_device_ownership(runtime: NetRuntimeHandle) {
    let releases = Arc::new(AtomicUsize::new(0));
    let payload = PacketPayload::try_single(counted_packet_fixture(8, 0x9300, &releases))
        .expect("counted payload is non-empty");
    let request = register_tx_payload_lease_in(
        runtime,
        NetIfId(303),
        TxPayloadLease::from_payload(payload).expect("payload lease"),
        None,
        NetTxMeta::default(),
    )
    .expect("registered lease")
    .into_request();

    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert!(reject_registered_tx_lease_in(
        runtime,
        request.lease_id,
        "fake driver rejected request",
    ));
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert!(!complete_tx_lease_in(
        runtime,
        request.lease_id,
        TxDeviceOutcome::Transmitted,
    ));
}

fn successful_stop_releases_queued_and_device_owned_leases_after_quiesce(
    runtime: NetRuntimeHandle,
) {
    let (state, driver) = fake_driver();
    let if_id = NetIfId(304);
    let handle = NetDeviceHandle::new(
        driver,
        NetDeviceBinding {
            port_id: test_port_id(304),
            if_id,
        },
        runtime.context(),
    );
    let queued_releases = Arc::new(AtomicUsize::new(0));
    let queued_payload =
        PacketPayload::try_single(counted_packet_fixture(8, 0x9400, &queued_releases))
            .expect("queued payload is non-empty");
    assert!(
        handle
            .enqueue_tx(queued_payload, NetTxMeta::default())
            .is_ok()
    );

    let owned_releases = Arc::new(AtomicUsize::new(0));
    let owned_payload =
        PacketPayload::try_single(counted_packet_fixture(8, 0x9500, &owned_releases))
            .expect("owned payload is non-empty");
    let owned_request = register_tx_payload_lease_in(
        runtime,
        if_id,
        TxPayloadLease::from_payload(owned_payload).expect("owned payload lease"),
        None,
        NetTxMeta::default(),
    )
    .expect("registered owned lease")
    .into_request();
    assert!(begin_tx_submission_in(runtime, owned_request.lease_id));
    assert!(mark_tx_device_owned_in(runtime, owned_request.lease_id));

    assert_eq!(queued_releases.load(Ordering::SeqCst), 0);
    assert_eq!(owned_releases.load(Ordering::SeqCst), 0);
    handle.stop().expect("fake driver quiesces");
    assert_eq!(state.stop_calls.load(Ordering::Relaxed), 1);
    assert_eq!(queued_releases.load(Ordering::SeqCst), 1);
    assert_eq!(owned_releases.load(Ordering::SeqCst), 1);
}

fn failed_stop_keeps_port_and_device_owned_lease_quarantined_until_completion(
    runtime: NetRuntimeHandle,
) {
    let (_state, driver) =
        fake_driver_with_stop_error("stop-fail", kernel_api::error::KapiError::Busy);
    let if_id = register_test_port(runtime, 85, driver, PrimaryPortPolicy::Never)
        .expect("register stop-failure port");
    let releases = Arc::new(AtomicUsize::new(0));
    let payload = PacketPayload::try_single(counted_packet_fixture(8, 0x9600, &releases))
        .expect("counted payload is non-empty");
    let request = register_tx_payload_lease_in(
        runtime,
        if_id,
        TxPayloadLease::from_payload(payload).expect("payload lease"),
        None,
        NetTxMeta::default(),
    )
    .expect("registered lease")
    .into_request();
    assert!(begin_tx_submission_in(runtime, request.lease_id));
    assert!(mark_tx_device_owned_in(runtime, request.lease_id));

    assert_eq!(
        unregister_port_in(runtime, if_id),
        Err(kernel_api::error::KapiError::Busy)
    );
    assert_eq!(
        lookup_if_by_port_id_in(runtime, test_port_id(85)),
        Some(if_id)
    );
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert!(
        runtime
            .context()
            .tx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains_key(&request.lease_id)
    );

    assert!(complete_tx_lease_in(
        runtime,
        request.lease_id,
        TxDeviceOutcome::OutcomeUnknown,
    ));
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert!(unregister_test_port(runtime, if_id));
    assert_eq!(lookup_if_by_port_id_in(runtime, test_port_id(85)), None);
}

pub(crate) async fn device_ownership() -> bool {
    let runtime = crate::net::runtime::create_runtime().expect("isolated device runtime");
    log::info!("[kernel-test][net][device] ISR event delivery");
    schedule_event_from_interrupt_context_enqueues_successfully(runtime).await;
    let cases: &[(&str, fn(NetRuntimeHandle))] = &[
        (
            "device_handle_rebind_updates_binding_smoke",
            device_handle_rebind_updates_binding_smoke,
        ),
        (
            "register_port_exposes_snapshot_smoke",
            register_port_exposes_snapshot_smoke,
        ),
        (
            "register_port_rolls_back_device_state_when_driver_start_fails",
            register_port_rolls_back_device_state_when_driver_start_fails,
        ),
        (
            "failed_start_retains_owned_interface_until_shutdown_acknowledges",
            failed_start_retains_owned_interface_until_shutdown_acknowledges,
        ),
        (
            "duplicate_port_registration_preserves_the_canonical_interface",
            duplicate_port_registration_preserves_the_canonical_interface,
        ),
        (
            "register_port_prefer_primary_updates_primary_selection_smoke",
            register_port_prefer_primary_updates_primary_selection_smoke,
        ),
        (
            "primary_link_callback_promotes_secondary",
            primary_link_callback_promotes_secondary,
        ),
        (
            "unregister_primary_without_survivor_clears_primary_runtime",
            unregister_primary_without_survivor_clears_primary_runtime,
        ),
        (
            "recovered_interface_does_not_reclaim_primary_after_failover",
            recovered_interface_does_not_reclaim_primary_after_failover,
        ),
        (
            "stopped_interface_rejects_rx_at_the_device_boundary",
            stopped_interface_rejects_rx_at_the_device_boundary,
        ),
        (
            "tx_completion_future_resolves_success",
            tx_completion_future_resolves_success,
        ),
        (
            "tx_completion_future_resolves_error",
            tx_completion_future_resolves_error,
        ),
        (
            "tx_payload_lease_derives_descriptor_for_each_owner",
            tx_payload_lease_derives_descriptor_for_each_owner,
        ),
        (
            "tx_descriptor_plan_rejects_device_fanout_limit",
            tx_descriptor_plan_rejects_device_fanout_limit,
        ),
        (
            "packet_window_descriptors_reference_original_packet_range",
            packet_window_descriptors_reference_original_packet_range,
        ),
        (
            "tx_owner_group_completes_after_all_fragment_leases",
            tx_owner_group_completes_after_all_fragment_leases,
        ),
        (
            "accepted_tx_lease_retains_backing_until_exactly_one_completion",
            accepted_tx_lease_retains_backing_until_exactly_one_completion,
        ),
        (
            "synchronous_completion_consumes_submitting_lease_without_recycling_early",
            synchronous_completion_consumes_submitting_lease_without_recycling_early,
        ),
        (
            "rejected_tx_lease_returns_backing_without_device_ownership",
            rejected_tx_lease_returns_backing_without_device_ownership,
        ),
        (
            "successful_stop_releases_queued_and_device_owned_leases_after_quiesce",
            successful_stop_releases_queued_and_device_owned_leases_after_quiesce,
        ),
        (
            "failed_stop_keeps_port_and_device_owned_lease_quarantined_until_completion",
            failed_stop_keeps_port_and_device_owned_lease_quarantined_until_completion,
        ),
    ];
    for (name, run) in cases {
        log::info!("[kernel-test][net][device] {name}");
        run(runtime);
        assert!(list_port_ids_in(runtime).is_empty());
        assert!(
            runtime
                .context()
                .tx_leases
                .lock()
                .unwrap_or_else(|_| panic!("lease registry poisoned"))
                .is_empty()
        );
        assert!(
            runtime
                .context()
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|_| panic!("owner groups poisoned"))
                .is_empty()
        );
        assert!(
            runtime
                .context()
                .tx_completions
                .read()
                .unwrap_or_else(|_| panic!("completion registry poisoned"))
                .is_empty()
        );
        crate::task::yield_now().await;
    }
    true
}
