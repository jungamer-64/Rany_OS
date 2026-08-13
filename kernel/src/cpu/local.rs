use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sync::MpscRingBuffer;

use super::CpuId;

const CONTROL_QUEUE_SLOTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuControlMessage {
    WakeExecutor,
    Start,
    Park,
    TlbShootdown { generation: u64 },
    RcuQuiesce { epoch: u64 },
}

pub struct CpuRemoteAccess {
    control: MpscRingBuffer<CpuControlMessage, CONTROL_QUEUE_SLOTS>,
    wake_pending: AtomicBool,
    observed_epoch: AtomicU64,
}

impl CpuRemoteAccess {
    const fn new() -> Self {
        Self {
            control: MpscRingBuffer::new(),
            wake_pending: AtomicBool::new(false),
            observed_epoch: AtomicU64::new(0),
        }
    }

    pub fn send(&self, message: CpuControlMessage) -> Result<(), CpuControlMessage> {
        self.control.try_push(message)
    }

    pub fn request_wake(&self) -> bool {
        !self.wake_pending.swap(true, Ordering::AcqRel)
    }

    pub fn observed_epoch(&self) -> u64 {
        self.observed_epoch.load(Ordering::Acquire)
    }
}

struct CpuOwnedState {
    execution: Option<crate::task::ExecutionContext>,
}

pub struct CpuLocal {
    id: CpuId,
    owned: UnsafeCell<CpuOwnedState>,
    remote: CpuRemoteAccess,
    _pin: PhantomPinned,
}

// SAFETY: `owned` is only accessed through a `CurrentCpu` token, which is
// non-Send/non-Sync and can only be acquired for the executing CPU. All
// cross-CPU access is confined to `CpuRemoteAccess` atomics and its MPSC queue.
unsafe impl Sync for CpuLocal {}

impl CpuLocal {
    pub(crate) fn allocate(id: CpuId) -> Pin<Box<Self>> {
        Box::pin(Self {
            id,
            owned: UnsafeCell::new(CpuOwnedState { execution: None }),
            remote: CpuRemoteAccess::new(),
            _pin: PhantomPinned,
        })
    }

    pub const fn id(&self) -> CpuId {
        self.id
    }

    pub fn remote(&self) -> &CpuRemoteAccess {
        &self.remote
    }

    fn execution(&self) -> Option<crate::task::ExecutionContext> {
        with_owner_access(|| {
            // SAFETY: the caller holds the current-CPU token and interrupts are
            // excluded while the owner-only value is copied.
            unsafe { (*self.owned.get()).execution }
        })
    }

    fn replace_execution(
        &self,
        execution: Option<crate::task::ExecutionContext>,
    ) -> Option<crate::task::ExecutionContext> {
        with_owner_access(|| {
            // SAFETY: mutation is restricted to the owning CPU by CurrentCpu.
            unsafe { core::mem::replace(&mut (*self.owned.get()).execution, execution) }
        })
    }

    fn take_control(&self) -> Option<CpuControlMessage> {
        let message = self.remote.control.pop();
        if message.is_some() && self.remote.control.is_empty() {
            self.remote.wake_pending.store(false, Ordering::Release);
        }
        message
    }

    fn record_epoch(&self, epoch: u64) {
        self.remote.observed_epoch.store(epoch, Ordering::Release);
    }
}

pub struct CurrentCpu {
    local: &'static CpuLocal,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CurrentCpu {
    pub fn acquire() -> Option<Self> {
        let raw_id = crate::per_cpu::try_current_cpu_id()?;
        let id = CpuId::try_from(raw_id).ok()?;
        let local = super::runtime().cpu_local(id)?;
        Some(Self {
            local,
            _not_send_or_sync: PhantomData,
        })
    }

    pub const fn id(&self) -> CpuId {
        self.local.id()
    }

    pub fn execution(&self) -> Option<crate::task::ExecutionContext> {
        self.local.execution()
    }

    pub(crate) fn enter_execution(
        self,
        execution: crate::task::ExecutionContext,
    ) -> ExecutionContextGuard {
        let previous = self.local.replace_execution(Some(execution));
        ExecutionContextGuard {
            current: self,
            previous,
        }
    }

    pub fn take_control(&self) -> Option<CpuControlMessage> {
        self.local.take_control()
    }

    pub fn record_epoch(&self, epoch: u64) {
        self.local.record_epoch(epoch);
    }
}

pub(crate) struct ExecutionContextGuard {
    current: CurrentCpu,
    previous: Option<crate::task::ExecutionContext>,
}

impl Drop for ExecutionContextGuard {
    fn drop(&mut self) {
        self.current.local.replace_execution(self.previous);
    }
}

fn with_owner_access<R>(operation: impl FnOnce() -> R) -> R {
    #[cfg(any(test, feature = "std", target_os = "linux", target_os = "windows"))]
    {
        operation()
    }

    #[cfg(not(any(test, feature = "std", target_os = "linux", target_os = "windows")))]
    {
        x86_64::instructions::interrupts::without_interrupts(operation)
    }
}
