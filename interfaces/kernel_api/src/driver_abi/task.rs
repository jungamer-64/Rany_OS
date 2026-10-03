//! Linear Future transfer and validated admission across the driver boundary.

use alloc::boxed::Box;
use core::future::Future;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::ptr::NonNull;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::resource::cpu::{CpuId, CpuSet, MAX_POSSIBLE_CPUS, NumaNodeId};
use crate::resource::domain::DomainId;
use crate::resource::task::{
    SpawnError, TaskId, TaskMappingError, TaskOptions, TaskPlacement, TaskPriority,
};

type BoxedFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Borrowed notification authority for exactly one poll call. Its raw vtable
/// remains in the kernel image; saved clones never refer to the cell's code.
/// The importing runtime validates TASK_WAKER_ABI before accepting this Rust
/// notification representation; the opaque C Future itself has no Rust layout.
#[repr(C)]
pub struct AbiTaskWaker {
    data: *const (),
    vtable: *const RawWakerVTable,
}

impl AbiTaskWaker {
    pub(super) fn borrow(waker: &Waker) -> Self {
        Self {
            data: waker.data(),
            vtable: waker.vtable(),
        }
    }

    /// # Safety
    /// The kernel supplied this borrowed raw waker and retains its data and
    /// vtable throughout this call. Cloning establishes a separate owned ref.
    pub(super) unsafe fn clone_owned(&self) -> Waker {
        // SAFETY: the caller's live kernel Waker retains this reference. The
        // temporary view must not decrement it; clone invokes its own vtable.
        let borrowed =
            ManuallyDrop::new(unsafe { Waker::from_raw(RawWaker::new(self.data, &*self.vtable)) });
        Waker::clone(&borrowed)
    }
}

/// Owns one pinned Future until consumed by spawn or destroyed on rejection.
/// Numeric metadata cannot reconstruct this owner. The scheduler retains the
/// originating code generation through poll, suspension and destructor return.
#[repr(C)]
pub struct AbiTaskFuture {
    data: Option<NonNull<()>>,
    poll: unsafe extern "C" fn(*mut (), *const AbiTaskWaker) -> u8,
    destroy: unsafe extern "C" fn(*mut ()),
}

// SAFETY: the only constructor requires a Send Future. The capsule transfers
// its unique Box; it never grants shared polling or concurrent destruction.
unsafe impl Send for AbiTaskFuture {}

unsafe extern "C" fn poll_boxed(data: *mut (), waker: *const AbiTaskWaker) -> u8 {
    // SAFETY: the owning capsule supplies its pinned, uniquely borrowed Box
    // and a kernel raw waker retained for the entire synchronous poll call.
    let future = unsafe { &mut *data.cast::<BoxedFuture>() };
    // SAFETY: the raw borrowed waker remains live until this callback returns.
    let waker = unsafe { (&*waker).clone_owned() };
    let mut context = Context::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(()) => 0,
        Poll::Pending => 1,
    }
}

unsafe extern "C" fn destroy_boxed(data: *mut ()) {
    // SAFETY: destruction consumes the sole capsule reference. Its code lease
    // remains live and no active/suspended poll can reach this transition.
    drop(unsafe { Box::from_raw(data.cast::<BoxedFuture>()) });
}

impl AbiTaskFuture {
    /// # Errors
    /// The ABI envelope is reserved before ownership crosses into the kernel.
    /// Failure drops the supplied Future in its originating invocation.
    pub fn new(future: BoxedFuture) -> Result<Self, SpawnError> {
        let owner = Box::try_new(future).map_err(|_| SpawnError::PhysicalMemoryExhausted)?;
        Ok(Self {
            data: Some(NonNull::from(Box::leak(owner)).cast()),
            poll: poll_boxed,
            destroy: destroy_boxed,
        })
    }

    /// Removes the sole owner from an ABI input. Repeated consumption returns
    /// None and does not create another Future or destructor authority.
    pub fn take(&mut self) -> Option<Self> {
        Some(Self {
            data: Some(self.data.take()?),
            poll: self.poll,
            destroy: self.destroy,
        })
    }
}

impl Future for AbiTaskFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let owner = self.get_mut();
        let data = owner.data.expect("consumed Future cannot be polled");
        let waker = AbiTaskWaker::borrow(context.waker());
        // SAFETY: this mutable capsule uniquely owns the pinned Future. The
        // scheduler's state machine and code lease cover this whole call.
        match unsafe { (owner.poll)(data.as_ptr().cast(), &waker) } {
            0 => Poll::Ready(()),
            1 => Poll::Pending,
            _ => panic!("invalid Future poll outcome across driver ABI"),
        }
    }
}

impl Drop for AbiTaskFuture {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            // SAFETY: take removes the only destructor authority; the Future
            // has no active poll when the scheduler retires this owner.
            unsafe { (self.destroy)(data.as_ptr().cast()) };
        }
    }
}

/// Validity is checked before scheduler resource admission. The four words
/// encode CPU coordinates 0..255 without truncation to the first machine word.
#[repr(C)]
pub struct AbiTaskOptions {
    pub allowed: [u64; 4],
    pub capacity: u16,
    pub preferred_cpu: u16,
    pub preferred_node: u8,
    pub priority: u8,
    pub reserved: u16,
}

const _: () = assert!(MAX_POSSIBLE_CPUS == 256);

impl AbiTaskOptions {
    pub fn from_options(options: TaskOptions) -> Self {
        let mut allowed = [0; 4];
        for cpu in options.placement.allowed_cpus().iter() {
            let index = cpu.as_usize();
            allowed[index / 64] |= 1 << (index % 64);
        }
        Self {
            allowed,
            capacity: options.placement.allowed_cpus().capacity() as u16,
            preferred_cpu: options
                .placement
                .preferred_cpu()
                .map_or(u16::MAX, CpuId::as_u16),
            preferred_node: options
                .placement
                .preferred_node()
                .map_or(u8::MAX, NumaNodeId::as_u8),
            priority: match options.priority {
                TaskPriority::Low => 0,
                TaskPriority::Normal => 1,
                TaskPriority::High => 2,
                TaskPriority::Critical => 3,
            },
            reserved: 0,
        }
    }

    /// # Errors
    /// Invalid coordinates, width, priority, preferences or reserved fields
    /// reject the whole input before acquiring a task slot or physical page.
    pub fn decode(&self) -> Result<TaskOptions, SpawnError> {
        if self.reserved != 0 {
            return Err(SpawnError::InvalidOptions);
        }
        let mut allowed =
            CpuSet::new(usize::from(self.capacity)).map_err(|_| SpawnError::InvalidOptions)?;
        for (word_index, word) in self.allowed.iter().copied().enumerate() {
            let mut bits = word;
            // LOOP_PROOF: mode=condition; reason=Each iteration consumes one of the at most 64 set bits in the current ABI word.;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let cpu = CpuId::try_from(word_index * 64 + bit)
                    .map_err(|_| SpawnError::InvalidOptions)?;
                allowed
                    .insert(cpu)
                    .map_err(|_| SpawnError::InvalidOptions)?;
            }
        }
        let preferred_cpu = match self.preferred_cpu {
            u16::MAX => None,
            cpu => Some(CpuId::try_from(usize::from(cpu)).map_err(|_| SpawnError::InvalidOptions)?),
        };
        let preferred_node = match self.preferred_node {
            u8::MAX => None,
            node => Some(NumaNodeId::new(node)),
        };
        let placement = TaskPlacement::new(allowed, preferred_cpu, preferred_node)
            .map_err(|_| SpawnError::InvalidOptions)?;
        let priority = match self.priority {
            0 => TaskPriority::Low,
            1 => TaskPriority::Normal,
            2 => TaskPriority::High,
            3 => TaskPriority::Critical,
            _ => return Err(SpawnError::InvalidOptions),
        };
        Ok(TaskOptions::new(priority, placement))
    }
}

/// A synchronous spawn result contains either one task identity or a typed
/// rejection. Failure never carries a partially published task handle.
#[repr(C)]
pub struct AbiTaskSpawnResult {
    pub kind: u32,
    pub reserved: u32,
    pub detail: u64,
}

impl AbiTaskSpawnResult {
    pub fn from_result(result: Result<TaskId, SpawnError>) -> Self {
        let (kind, detail) = match result {
            Ok(task) => (0, task.as_u64()),
            Err(SpawnError::SchedulerUnavailable) => (1, 0),
            Err(SpawnError::NoOnlineCpu) => (2, 0),
            Err(SpawnError::PlacementUnavailable) => (3, 0),
            Err(SpawnError::CpuNotPresent(cpu)) => (4, u64::from(cpu.as_u16())),
            Err(SpawnError::CpuOffline(cpu)) => (5, u64::from(cpu.as_u16())),
            Err(SpawnError::TaskIdentityExhausted) => (6, 0),
            Err(SpawnError::TaskSlotsExhausted) => (7, 0),
            Err(SpawnError::PhysicalMemoryExhausted) => (8, 0),
            Err(SpawnError::MappingFailed(cause)) => (
                9,
                match cause {
                    TaskMappingError::AlreadyMapped => 0,
                    TaskMappingError::NotMapped => 1,
                    TaskMappingError::InvalidAddress => 2,
                    TaskMappingError::Alignment => 3,
                    TaskMappingError::ParentHugePage => 4,
                    TaskMappingError::Hardware => 5,
                    TaskMappingError::ParentPermissionDenied => 6,
                    TaskMappingError::MappingChanged => 7,
                    TaskMappingError::UnsupportedPageSize => 8,
                },
            ),
            Err(SpawnError::DomainUnavailable(domain)) => (10, domain.as_u64()),
            Err(SpawnError::InvalidOptions) => (11, 0),
            Err(SpawnError::InvalidAbiResponse) => (12, 0),
            Err(SpawnError::RuntimeAbiMismatch) => (13, 0),
        };
        Self {
            kind,
            reserved: 0,
            detail,
        }
    }

    /// # Errors
    /// Preserves the scheduler's exact failure. Malformed replies fail as an
    /// ABI contract violation rather than fabricating success or exhaustion.
    pub fn into_result(self) -> Result<TaskId, SpawnError> {
        if self.reserved != 0 {
            return Err(SpawnError::InvalidAbiResponse);
        }
        let cause = match (self.kind, self.detail) {
            (0, identity) if identity != 0 => return Ok(TaskId::from_raw(identity)),
            (1, 0) => SpawnError::SchedulerUnavailable,
            (2, 0) => SpawnError::NoOnlineCpu,
            (3, 0) => SpawnError::PlacementUnavailable,
            (kind @ (4 | 5), cpu) => {
                let cpu = usize::try_from(cpu)
                    .ok()
                    .and_then(|cpu| CpuId::try_from(cpu).ok())
                    .ok_or(SpawnError::InvalidAbiResponse)?;
                if kind == 4 {
                    SpawnError::CpuNotPresent(cpu)
                } else {
                    SpawnError::CpuOffline(cpu)
                }
            }
            (6, 0) => SpawnError::TaskIdentityExhausted,
            (7, 0) => SpawnError::TaskSlotsExhausted,
            (8, 0) => SpawnError::PhysicalMemoryExhausted,
            (9, mapping) => SpawnError::MappingFailed(match mapping {
                0 => TaskMappingError::AlreadyMapped,
                1 => TaskMappingError::NotMapped,
                2 => TaskMappingError::InvalidAddress,
                3 => TaskMappingError::Alignment,
                4 => TaskMappingError::ParentHugePage,
                5 => TaskMappingError::Hardware,
                6 => TaskMappingError::ParentPermissionDenied,
                7 => TaskMappingError::MappingChanged,
                8 => TaskMappingError::UnsupportedPageSize,
                _ => return Err(SpawnError::InvalidAbiResponse),
            }),
            (10, domain) => SpawnError::DomainUnavailable(DomainId::new(domain)),
            (11, 0) => SpawnError::InvalidOptions,
            (13, 0) => SpawnError::RuntimeAbiMismatch,
            _ => SpawnError::InvalidAbiResponse,
        };
        Err(cause)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct PendingFuture {
        notifications: Arc<Mutex<Option<Waker>>>,
        drops: Arc<AtomicUsize>,
        polls: Arc<AtomicUsize>,
    }

    impl Future for PendingFuture {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            *self.notifications.lock().unwrap() = Some(context.waker().clone());
            Poll::Pending
        }
    }

    impl Drop for PendingFuture {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct NotificationCount(AtomicUsize);

    impl Wake for NotificationCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn transferred_future_keeps_one_owner_and_preserves_saved_waker() {
        let notifications = Arc::new(Mutex::new(None));
        let drops = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let future = PendingFuture {
            notifications: notifications.clone(),
            drops: drops.clone(),
            polls: polls.clone(),
        };
        let mut input = AbiTaskFuture::new(Box::pin(future)).unwrap();
        let mut admitted = input.take().unwrap();
        assert!(input.take().is_none());
        drop(input);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let count = Arc::new(NotificationCount(AtomicUsize::new(0)));
        let kernel_waker = Waker::from(count.clone());
        let mut context = Context::from_waker(&kernel_waker);
        assert!(Pin::new(&mut admitted).poll(&mut context).is_pending());
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        let saved = notifications.lock().unwrap().take().unwrap();
        assert!(saved.will_wake(&kernel_waker));
        drop(admitted);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        saved.wake();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rejected_future_is_destroyed_without_polling() {
        let drops = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let future = PendingFuture {
            notifications: Arc::new(Mutex::new(None)),
            drops: drops.clone(),
            polls: polls.clone(),
        };
        drop(AbiTaskFuture::new(Box::pin(future)).unwrap());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(polls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sparse_options_decode_all_words_and_locality_separately() {
        // Independent ABI coordinates: CPU 71 is word 1 bit 7, 255 is word 3 bit 63.
        let raw = AbiTaskOptions {
            allowed: [0, 1 << 7, 0, 1 << 63],
            capacity: 256,
            preferred_cpu: 255,
            preferred_node: 3,
            priority: 2,
            reserved: 0,
        };
        let options = raw.decode().unwrap();
        let allowed = options.placement.allowed_cpus();
        assert!(allowed.contains(CpuId::new(71).unwrap()));
        assert!(allowed.contains(CpuId::new(255).unwrap()));
        assert!(!allowed.contains(CpuId::BOOTSTRAP));
        assert_eq!(
            options.placement.preferred_cpu(),
            Some(CpuId::new(255).unwrap())
        );
        assert_eq!(options.placement.preferred_node(), Some(NumaNodeId::new(3)));
        assert_eq!(options.priority, TaskPriority::High);
        let encoded = AbiTaskOptions::from_options(options);
        assert_eq!(encoded.allowed, raw.allowed);
        assert_eq!(encoded.capacity, 256);
    }

    #[test]
    fn malformed_options_are_rejected_before_admission() {
        let mut raw = AbiTaskOptions::from_options(TaskOptions::pinned(CpuId::BOOTSTRAP));
        raw.capacity = 64;
        raw.allowed[1] = 1;
        assert_eq!(raw.decode(), Err(SpawnError::InvalidOptions));
        raw.allowed[1] = 0;
        raw.priority = 4;
        assert_eq!(raw.decode(), Err(SpawnError::InvalidOptions));
        raw.priority = 0;
        raw.reserved = 1;
        assert_eq!(raw.decode(), Err(SpawnError::InvalidOptions));
    }

    #[test]
    fn admission_receipts_preserve_resource_and_placement_causes() {
        for (kind, detail, expected) in [
            (0, 37, Ok(TaskId::from_raw(37))),
            (
                5,
                255,
                Err(SpawnError::CpuOffline(CpuId::new(255).unwrap())),
            ),
            (7, 0, Err(SpawnError::TaskSlotsExhausted)),
            (8, 0, Err(SpawnError::PhysicalMemoryExhausted)),
            (
                9,
                4,
                Err(SpawnError::MappingFailed(TaskMappingError::ParentHugePage)),
            ),
            (
                9,
                6,
                Err(SpawnError::MappingFailed(
                    TaskMappingError::ParentPermissionDenied,
                )),
            ),
            (
                10,
                44,
                Err(SpawnError::DomainUnavailable(DomainId::new(44))),
            ),
            (0, 0, Err(SpawnError::InvalidAbiResponse)),
            (8, 17, Err(SpawnError::InvalidAbiResponse)),
            (
                9,
                7,
                Err(SpawnError::MappingFailed(TaskMappingError::MappingChanged)),
            ),
            (
                9,
                8,
                Err(SpawnError::MappingFailed(
                    TaskMappingError::UnsupportedPageSize,
                )),
            ),
            (9, 9, Err(SpawnError::InvalidAbiResponse)),
        ] {
            assert_eq!(
                AbiTaskSpawnResult {
                    kind,
                    detail,
                    reserved: 0
                }
                .into_result(),
                expected
            );
        }
    }
}
