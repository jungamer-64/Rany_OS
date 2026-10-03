// ============================================================================
// kernel/src/net/l4/test_support.rs - L4 / test support
// ============================================================================

use crate::net::datapath::mempool::PacketRef;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};
use kernel_api::resource::net::PacketByteCount;

unsafe fn noop_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &NOOP_WAKER_VTABLE)
}

unsafe fn noop_wake(_: *const ()) {}

unsafe fn noop_wake_by_ref(_: *const ()) {}

unsafe fn noop_drop(_: *const ()) {}

static NOOP_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(noop_clone, noop_wake, noop_wake_by_ref, noop_drop);

unsafe fn counting_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &COUNTING_WAKER_VTABLE)
}

unsafe fn counting_wake(data: *const ()) {
    let counter = unsafe { &*(data as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
}

unsafe fn counting_wake_by_ref(data: *const ()) {
    let counter = unsafe { &*(data as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
}

unsafe fn counting_drop(_: *const ()) {}

static COUNTING_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    counting_clone,
    counting_wake,
    counting_wake_by_ref,
    counting_drop,
);

pub(crate) fn noop_waker() -> Waker {
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

pub(crate) fn counting_waker(counter: &'static AtomicUsize) -> Waker {
    unsafe {
        Waker::from_raw(RawWaker::new(
            counter as *const AtomicUsize as *const (),
            &COUNTING_WAKER_VTABLE,
        ))
    }
}

struct FixtureBytes(core::cell::UnsafeCell<Box<[u8]>>);
// SAFETY: storage grants no byte access independently of acquired packet
// windows. Its only shared operation is lifetime retention by mapping owners.
unsafe impl Sync for FixtureBytes {}

struct PacketFixture {
    memory: core::mem::MaybeUninit<kernel_api::resource::net::PacketBufferMemory>,
    bytes: alloc::sync::Arc<FixtureBytes>,
}

unsafe fn retire_fixture(owner: core::ptr::NonNull<()>) {
    // SAFETY: fixture construction transfers this sole Box to the callback,
    // which runs after the last packet partition returns.
    let mut fixture = unsafe { Box::from_raw(owner.cast::<PacketFixture>().as_ptr()) };
    // SAFETY: construction initialized the header before first acquisition;
    // this last-reference callback ends all header users.
    unsafe { fixture.memory.assume_init_drop() };
}

pub(crate) fn packet_fixture(cap: usize) -> PacketRef {
    let capacity = kernel_api::dma::DmaByteCount::new(cap).expect("valid fixture capacity");
    let mut bytes = alloc::sync::Arc::new(FixtureBytes(core::cell::UnsafeCell::new(
        alloc::vec![0u8; cap].into_boxed_slice(),
    )));
    let data = core::ptr::NonNull::new(
        alloc::sync::Arc::get_mut(&mut bytes)
            .expect("sole fixture storage")
            .0
            .get_mut()
            .as_mut_ptr(),
    )
    .expect("fixture bytes");
    let mut allocation = Box::new(PacketFixture {
        memory: core::mem::MaybeUninit::uninit(),
        bytes,
    });
    let owner = core::ptr::NonNull::from(allocation.as_mut()).cast();
    // SAFETY: this fixture retains initialized bytes and the stable header in
    // one Box. No device accesses it, and the callback reclaims it once after
    // every disjoint packet window has returned.
    allocation.memory.write(unsafe {
        kernel_api::resource::net::PacketBufferMemory::new(
            data,
            capacity,
            kernel_api::resource::memory::PhysicalAddress::new(0),
            alloc::sync::Arc::clone(&allocation.bytes) as alloc::sync::Arc<dyn Send + Sync>,
            owner,
            retire_fixture,
        )
    });
    let memory = core::ptr::NonNull::new(allocation.memory.as_mut_ptr()).expect("fixture header");
    // SAFETY: this live header belongs to the retained fixture Box. The sole
    // acquisition transfers its retirement responsibility to the packet.
    let packet = unsafe { PacketRef::acquire(memory, 0) }.expect("fixture acquisition");
    let _owner = Box::into_raw(allocation);
    packet
}

pub(crate) fn packet_fixture_with_data(data: &[u8]) -> PacketRef {
    let cap = data.len().max(1);
    let mut packet = packet_fixture(cap);
    packet
        .try_resize(data.len())
        .expect("test packet fits its backing");
    packet.data_mut()[..data.len()].copy_from_slice(data);
    packet
}
