use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::sync::MpscRingBuffer;
use crate::sync::atomic_waker::WakerQueueState;
use exorust_sync::{NotificationQueue, WakerSlot};

use super::{CpuGenerationResource, CpuId};

const CONTROL_QUEUE_SLOTS: usize = 32;
const INTERRUPT_WAKE_WORDS: usize =
    crate::task::interrupt_waker::MAX_INTERRUPT_INDICES.div_ceil(u64::BITS as usize);
const IA32_FS_BASE: u32 = 0xc000_0100;
const IA32_GS_BASE: u32 = 0xc000_0101;
const TLB_ACTIVE: u8 = 0;
const TLB_LAZY: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuControlMessage {
    WakeExecutor,
    Start,
    Park,
    ReclaimMemory,
}

pub struct CpuRemoteAccess {
    heap_allocations: AtomicU64,
    control: MpscRingBuffer<CpuControlMessage, CONTROL_QUEUE_SLOTS>,
    wake_pending: AtomicBool,
    online_acknowledgements: AtomicU64,
    park_acknowledgements: AtomicU64,
    numa_node: AtomicU8,
    interrupt_depth: AtomicU32,
    interrupt_record_revision: AtomicU64,
    last_interrupt_vector: AtomicU8,
    last_interrupt_rip: AtomicU64,
    last_interrupt_rsp: AtomicU64,
    timer_event_pending: AtomicBool,
    runtime_timer_armed: AtomicBool,
    rcu_read_depth: AtomicU32,
    rcu_quiescent_count: AtomicU64,
    tlb_mode: AtomicU8,
    tlb_requested_generation: AtomicU64,
    tlb_observed_generation: AtomicU64,
    atomic_notifications: NotificationQueue<WakerSlot>,
    queue_notifications: NotificationQueue<WakerQueueState>,
    interrupt_wakes: InterruptWakeSet,
}

/// One bit per source coalesces repeated IRQs without consuming queue slots.
/// Draining detaches all words before callbacks, so events arriving during
/// delivery belong to the next scheduler pass.
struct InterruptWakeSet {
    words: [AtomicU64; INTERRUPT_WAKE_WORDS],
}

impl InterruptWakeSet {
    const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; INTERRUPT_WAKE_WORDS],
        }
    }

    fn publish(&self, index: usize) {
        assert!(index < crate::task::interrupt_waker::MAX_INTERRUPT_INDICES);
        self.words[index / u64::BITS as usize]
            .fetch_or(1 << (index % u64::BITS as usize), Ordering::Release);
    }

    fn drain(&self, mut deliver: impl FnMut(usize)) {
        let snapshot: [u64; INTERRUPT_WAKE_WORDS] =
            core::array::from_fn(|word| self.words[word].swap(0, Ordering::AcqRel));
        for (word, mut bits) in snapshot.into_iter().enumerate() {
            // LOOP_PROOF: mode=condition; reason=Each iteration clears one set bit from this detached word, which has at most 64 source notifications.;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                deliver(word * u64::BITS as usize + bit);
            }
        }
    }

    fn pending_count(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.load(Ordering::Acquire).count_ones() as usize)
            .sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptContext {
    pub vector: u8,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
}

impl CpuRemoteAccess {
    const fn new() -> Self {
        Self {
            heap_allocations: AtomicU64::new(0),
            control: MpscRingBuffer::new(),
            wake_pending: AtomicBool::new(false),
            online_acknowledgements: AtomicU64::new(0),
            park_acknowledgements: AtomicU64::new(0),
            numa_node: AtomicU8::new(u8::MAX),
            interrupt_depth: AtomicU32::new(0),
            interrupt_record_revision: AtomicU64::new(0),
            last_interrupt_vector: AtomicU8::new(0),
            last_interrupt_rip: AtomicU64::new(0),
            last_interrupt_rsp: AtomicU64::new(0),
            timer_event_pending: AtomicBool::new(false),
            runtime_timer_armed: AtomicBool::new(false),
            rcu_read_depth: AtomicU32::new(0),
            rcu_quiescent_count: AtomicU64::new(0),
            // Every newly allocated CPU-local block starts detached from
            // address-space execution. The bootstrap CPU activates after GS
            // binding; application CPUs activate only after online commit.
            tlb_mode: AtomicU8::new(TLB_LAZY),
            tlb_requested_generation: AtomicU64::new(0),
            tlb_observed_generation: AtomicU64::new(0),
            atomic_notifications: NotificationQueue::new(),
            queue_notifications: NotificationQueue::new(),
            interrupt_wakes: InterruptWakeSet::new(),
        }
    }

    pub fn send(&self, message: CpuControlMessage) -> Result<(), CpuControlMessage> {
        self.control.try_push(message)
    }

    pub fn request_wake(&self) -> bool {
        !self.wake_pending.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn online_acknowledgements(&self) -> u64 {
        self.online_acknowledgements.load(Ordering::Acquire)
    }

    pub(crate) fn acknowledge_online(&self) {
        self.online_acknowledgements
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .unwrap_or_else(|_| panic!("CPU online acknowledgement generation exhausted"));
    }

    pub(crate) fn park_acknowledgements(&self) -> u64 {
        self.park_acknowledgements.load(Ordering::Acquire)
    }

    pub(crate) fn acknowledge_parked(&self) {
        self.park_acknowledgements
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .unwrap_or_else(|_| panic!("CPU park acknowledgement generation exhausted"));
    }

    pub(crate) fn heap_allocations(&self) -> u64 {
        self.heap_allocations.load(Ordering::Relaxed)
    }

    pub fn numa_node(&self) -> Option<u8> {
        let node = self.numa_node.load(Ordering::Acquire);
        (node != u8::MAX).then_some(node)
    }

    pub(super) fn set_numa_node(&self, node: crate::mm::types::NumaNodeId) {
        self.numa_node.store(node.as_u8(), Ordering::Release);
    }

    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth.load(Ordering::Acquire) != 0
    }

    pub(crate) fn record_interrupt(&self, context: InterruptContext) {
        self.interrupt_record_revision
            .fetch_add(1, Ordering::AcqRel);
        self.last_interrupt_rip
            .store(context.instruction_pointer, Ordering::Relaxed);
        self.last_interrupt_rsp
            .store(context.stack_pointer, Ordering::Relaxed);
        self.last_interrupt_vector
            .store(context.vector, Ordering::Relaxed);
        self.interrupt_record_revision
            .fetch_add(1, Ordering::Release);
    }

    pub fn last_interrupt_context(&self) -> Option<InterruptContext> {
        // LOOP_PROOF: mode=event; reason=Return only when the owner interrupt writer has published the same even revision before and after the snapshot.;
        loop {
            let before = self.interrupt_record_revision.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }

            let context = InterruptContext {
                vector: self.last_interrupt_vector.load(Ordering::Relaxed),
                instruction_pointer: self.last_interrupt_rip.load(Ordering::Relaxed),
                stack_pointer: self.last_interrupt_rsp.load(Ordering::Relaxed),
            };
            let after = self.interrupt_record_revision.load(Ordering::Acquire);
            if before == after {
                return (before != 0).then_some(context);
            }
            core::hint::spin_loop();
        }
    }

    pub(crate) fn request_timer_event(&self) {
        self.timer_event_pending.store(true, Ordering::Release);
    }

    pub(crate) fn take_timer_event(&self) -> bool {
        self.timer_event_pending.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn arm_runtime_timer_once(&self) -> bool {
        self.runtime_timer_armed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn disarm_runtime_timer(&self) {
        self.runtime_timer_armed.store(false, Ordering::Release);
    }

    pub fn runtime_timer_armed(&self) -> bool {
        self.runtime_timer_armed.load(Ordering::Acquire)
    }

    pub(crate) fn rcu_read_depth(&self) -> u32 {
        self.rcu_read_depth.load(Ordering::Acquire)
    }

    pub(crate) fn rcu_quiescent_count(&self) -> u64 {
        self.rcu_quiescent_count.load(Ordering::Acquire)
    }

    pub(crate) fn request_tlb_generation(&self, generation: u64) {
        self.tlb_requested_generation
            .fetch_max(generation, Ordering::SeqCst);
    }

    pub(crate) fn observed_tlb_generation(&self) -> u64 {
        self.tlb_observed_generation.load(Ordering::SeqCst)
    }

    pub(crate) fn tlb_is_lazy(&self) -> bool {
        self.tlb_mode.load(Ordering::SeqCst) == TLB_LAZY
    }

    fn pending_tlb_generation(&self) -> Option<u64> {
        let requested = self.tlb_requested_generation.load(Ordering::SeqCst);
        (requested > self.observed_tlb_generation()).then_some(requested)
    }

    fn complete_tlb_generation(&self, generation: u64) {
        self.tlb_observed_generation
            .fetch_max(generation, Ordering::SeqCst);
    }

    fn defer_interrupt_wake(&self, index: usize) {
        self.interrupt_wakes.publish(index);
    }

    pub(crate) fn pending_interrupt_wakes(&self) -> usize {
        self.interrupt_wakes.pending_count()
    }

    pub(crate) fn pending_deferred_work(&self) -> usize {
        self.atomic_notifications
            .pending_count()
            .saturating_add(self.queue_notifications.pending_count())
            .saturating_add(self.interrupt_wakes.pending_count())
    }

    fn physical_generation_residue(&self) -> Option<CpuGenerationResource> {
        if !self.control.is_empty() || self.wake_pending.load(Ordering::Acquire) {
            return Some(CpuGenerationResource::ControlQueue);
        }
        if self.interrupt_depth.load(Ordering::Acquire) != 0 {
            return Some(CpuGenerationResource::InterruptContext);
        }
        if self.timer_event_pending.load(Ordering::Acquire)
            || self.runtime_timer_armed.load(Ordering::Acquire)
        {
            return Some(CpuGenerationResource::Timer);
        }
        if self.rcu_read_depth.load(Ordering::Acquire) != 0 {
            return Some(CpuGenerationResource::RcuReader);
        }
        if !self.tlb_is_lazy() {
            return Some(CpuGenerationResource::TlbState);
        }
        if self.pending_deferred_work() != 0 {
            return Some(CpuGenerationResource::DeferredWork);
        }
        None
    }

    fn acknowledge_cold_tlb(&self) {
        let requested = self.tlb_requested_generation.load(Ordering::SeqCst);
        self.tlb_observed_generation
            .store(requested, Ordering::SeqCst);
    }
}

struct CpuOwnedState {
    execution: Option<crate::task::ExecutionContext>,
    page_fault_active: bool,
    task_fuel: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuLocalAllocationError {
    DescriptorTablesAllocationFailed,
    InvalidTlsLayout,
    TlsAllocationFailed,
}

struct CpuTls {
    allocation: NonNull<u8>,
    layout: Layout,
    fs_base: u64,
    template: boot_proto::TlsInfo,
    file_size: usize,
}

// SAFETY: CpuTls owns its allocation. The pointer is only installed into FS
// on the CPU that owns the enclosing CpuLocal and is never dereferenced by a
// remote CPU.
unsafe impl Send for CpuTls {}

impl CpuTls {
    fn allocate(template: boot_proto::TlsInfo) -> Result<Option<Self>, CpuLocalAllocationError> {
        if template.start_addr == 0 || template.mem_size == 0 {
            return Ok(None);
        }
        let size = usize::try_from(template.mem_size)
            .map_err(|_| CpuLocalAllocationError::InvalidTlsLayout)?;
        let file_size = usize::try_from(template.file_size)
            .map_err(|_| CpuLocalAllocationError::InvalidTlsLayout)?
            .min(size);
        let requested_align = usize::try_from(template.align)
            .map_err(|_| CpuLocalAllocationError::InvalidTlsLayout)?;
        let align = requested_align.max(core::mem::align_of::<usize>());
        let align = align
            .checked_next_power_of_two()
            .ok_or(CpuLocalAllocationError::InvalidTlsLayout)?;
        let layout = Layout::from_size_align(size, align)
            .map_err(|_| CpuLocalAllocationError::InvalidTlsLayout)?;
        let allocation = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or(CpuLocalAllocationError::TlsAllocationFailed)?;
        if file_size != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    template.start_addr as *const u8,
                    allocation.as_ptr(),
                    file_size,
                );
            }
        }
        let fs_base = (allocation.as_ptr() as usize)
            .checked_add(size)
            .and_then(|address| u64::try_from(address).ok())
            .ok_or_else(|| {
                unsafe { dealloc(allocation.as_ptr(), layout) };
                CpuLocalAllocationError::InvalidTlsLayout
            })?;
        Ok(Some(Self {
            allocation,
            layout,
            fs_base,
            template,
            file_size,
        }))
    }

    /// Restores the initial TLS image for a new physical CPU generation.
    ///
    /// # Safety
    ///
    /// No CPU may have this allocation installed as its FS-backed TLS area.
    unsafe fn rearm_physical_generation(&self) {
        unsafe { core::ptr::write_bytes(self.allocation.as_ptr(), 0, self.layout.size()) };
        if self.file_size != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.template.start_addr as *const u8,
                    self.allocation.as_ptr(),
                    self.file_size,
                )
            };
        }
    }
}

impl Drop for CpuTls {
    fn drop(&mut self) {
        unsafe { dealloc(self.allocation.as_ptr(), self.layout) };
    }
}

#[repr(C, align(64))]
pub struct CpuLocal {
    preemption: hal::preemption::CpuPreemptionHeader,
    scheduler_xstate: UnsafeCell<super::xstate::XStateImage>,
    id: CpuId,
    owned: UnsafeCell<CpuOwnedState>,
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    frame_cache: core::cell::RefCell<crate::mm::phys::frame_allocator::LocalFrameCache>,
    heap_cache: core::cell::RefCell<crate::heap::HeapCache>,
    exchange_cache: core::cell::RefCell<crate::heap::ExchangeMagazine>,
    remote: CpuRemoteAccess,
    descriptor_tables: Pin<Box<crate::interrupts::gdt::CpuDescriptorTables>>,
    tls: Option<CpuTls>,
    _pin: PhantomPinned,
}

// SAFETY: `owned` is only accessed through a `CurrentCpu` token, which is
// non-Send/non-Sync and can only be acquired for the executing CPU. All
// cross-CPU access is confined to `CpuRemoteAccess` atomics and its MPSC queue.
// Descriptor/TLS/owned-state rearming is serialized by CpuRuntime while the
// slot is firmware-absent, after the prior physical CPU has ceased execution.
unsafe impl Sync for CpuLocal {}

impl CpuLocal {
    pub(crate) fn allocate(
        id: CpuId,
        tls_template: Option<boot_proto::TlsInfo>,
    ) -> Result<Pin<Box<Self>>, CpuLocalAllocationError> {
        let tls = tls_template.map(CpuTls::allocate).transpose()?.flatten();
        let descriptor_tables = crate::interrupts::gdt::CpuDescriptorTables::allocate()
            .ok_or(CpuLocalAllocationError::DescriptorTablesAllocationFailed)?;
        let mut local = Box::pin(Self {
            preemption: hal::preemption::CpuPreemptionHeader::unbound(),
            scheduler_xstate: UnsafeCell::new(super::xstate::XStateImage::initial()),
            id,
            owned: UnsafeCell::new(CpuOwnedState {
                execution: None,
                page_fault_active: false,
                task_fuel: 0,
            }),
            #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
            frame_cache: core::cell::RefCell::new(
                crate::mm::phys::frame_allocator::LocalFrameCache::new(),
            ),
            heap_cache: core::cell::RefCell::new(crate::heap::HeapCache::new()),
            exchange_cache: core::cell::RefCell::new(crate::heap::ExchangeMagazine::new()),
            remote: CpuRemoteAccess::new(),
            descriptor_tables,
            tls,
            _pin: PhantomPinned,
        });
        let address = local.as_ref().get_ref() as *const Self as usize;
        unsafe {
            Pin::get_unchecked_mut(local.as_mut())
                .preemption
                .self_address = address
        };
        Ok(local)
    }

    pub const fn id(&self) -> CpuId {
        self.id
    }

    pub fn remote(&self) -> &CpuRemoteAccess {
        &self.remote
    }

    /// Rearms state that belongs to one physical incarnation of this CPU slot.
    ///
    /// # Safety
    ///
    /// The previous physical CPU must be absent and unable to execute with
    /// this `CpuLocal`; no new CPU may be launched until this call returns.
    pub(crate) unsafe fn rearm_physical_generation(&self) -> Result<(), CpuGenerationResource> {
        assert!(
            self.exchange_cache.borrow().is_empty(),
            "offline CPU must drain its exchange cache"
        );
        assert!(
            self.heap_cache.borrow().is_empty(),
            "offline CPU must drain its heap cache"
        );
        #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
        assert!(
            self.frame_cache.borrow().is_empty(),
            "CPU cache must be drained before re-add"
        );
        if let Some(resource) = self.remote.physical_generation_residue() {
            return Err(resource);
        }

        let owned = unsafe { &mut *self.owned.get() };
        if owned.execution.is_some() {
            return Err(CpuGenerationResource::ExecutionContext);
        }
        if owned.page_fault_active {
            return Err(CpuGenerationResource::PageFault);
        }
        if self.preemption.state().guarded() {
            return Err(CpuGenerationResource::ExecutionContext);
        }
        unsafe { self.preemption.state().reset_for_new_cpu_generation() };
        owned.task_fuel = 0;

        if let Some(tls) = self.tls.as_ref() {
            unsafe { tls.rearm_physical_generation() };
        }
        unsafe {
            self.descriptor_tables
                .as_ref()
                .get_ref()
                .rearm_physical_generation()
        };
        self.remote.acknowledge_cold_tlb();
        Ok(())
    }

    fn is_self_address(&self, address: usize) -> bool {
        self.preemption.self_address == address && address == self as *const Self as usize
    }

    unsafe fn install_on_current_cpu(&self) {
        unsafe { write_msr(IA32_GS_BASE, self.preemption.self_address as u64) };
        if let Some(tls) = self.tls.as_ref() {
            unsafe { write_msr(IA32_FS_BASE, tls.fs_base) };
        }
    }

    fn execution(&self) -> Option<crate::task::Subject> {
        with_owner_access(|| {
            // SAFETY: the caller holds the current-CPU token and interrupts are
            // excluded while the owner-only value is copied.
            unsafe {
                (*self.owned.get())
                    .execution
                    .as_ref()
                    .map(|context| context.subject())
            }
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

    fn enter_interrupt(&self) {
        self.remote.interrupt_depth.fetch_add(1, Ordering::AcqRel);
    }

    fn exit_interrupt(&self) {
        let previous = self.remote.interrupt_depth.fetch_sub(1, Ordering::AcqRel);
        assert!(previous != 0, "interrupt nesting depth underflow");
    }

    fn try_enter_page_fault(&self) -> bool {
        with_owner_access(|| {
            let owned = unsafe { &mut *self.owned.get() };
            if owned.page_fault_active {
                false
            } else {
                owned.page_fault_active = true;
                true
            }
        })
    }

    fn exit_page_fault(&self) {
        with_owner_access(|| unsafe { (*self.owned.get()).page_fault_active = false });
    }

    fn refill_task_fuel(&self, amount: u64) {
        with_owner_access(|| unsafe { (*self.owned.get()).task_fuel = amount });
    }

    fn consume_task_fuel(&self, amount: u64) -> bool {
        with_owner_access(|| {
            let owned = unsafe { &mut *self.owned.get() };
            if owned.execution.is_none() {
                return true;
            }
            match owned.task_fuel.checked_sub(amount) {
                Some(remaining) => {
                    owned.task_fuel = remaining;
                    true
                }
                None => {
                    owned.task_fuel = 0;
                    false
                }
            }
        })
    }

    fn task_fuel(&self) -> u64 {
        with_owner_access(|| unsafe { (*self.owned.get()).task_fuel })
    }

    fn enter_rcu_read(&self) {
        let previous = self.remote.rcu_read_depth.fetch_add(1, Ordering::Acquire);
        assert!(previous != u32::MAX, "RCU read nesting depth overflow");
    }

    fn exit_rcu_read(&self) {
        let previous = self.remote.rcu_read_depth.fetch_sub(1, Ordering::Release);
        assert!(previous != 0, "RCU read nesting depth underflow");
    }

    fn note_rcu_quiescent(&self) -> bool {
        if self.remote.rcu_read_depth.load(Ordering::Acquire) != 0 {
            return false;
        }
        self.remote
            .rcu_quiescent_count
            .fetch_add(1, Ordering::Release);
        true
    }

    fn enter_lazy_tlb(&self) {
        self.remote.tlb_mode.store(TLB_LAZY, Ordering::SeqCst);
    }

    fn activate_tlb(&self) -> Option<u64> {
        self.remote.tlb_mode.store(TLB_ACTIVE, Ordering::SeqCst);
        self.remote.pending_tlb_generation()
    }
}

pub struct CurrentCpu {
    local: &'static CpuLocal,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CurrentCpu {
    pub(crate) fn record_heap_allocation(&self) -> bool {
        with_owner_access(|| {
            let Some(current) = Self::acquire() else {
                return false;
            };
            if !core::ptr::eq(current.local, self.local) {
                return false;
            }
            // This counter has one writer. Remote observers only load it; no
            // global cache line or atomic RMW is touched on the allocation path.
            let counter = &self.local.remote.heap_allocations;
            counter.store(
                counter.load(Ordering::Relaxed).wrapping_add(1),
                Ordering::Relaxed,
            );
            true
        })
    }

    /// CPU-local authority exists only after a bare-metal kernel entry binds
    /// its pinned GS block. A process on a host OS cannot acquire this authority.
    pub fn acquire() -> Option<Self> {
        #[cfg(not(target_os = "none"))]
        {
            None
        }
        #[cfg(target_os = "none")]
        {
            let address = usize::try_from(unsafe { read_msr(IA32_GS_BASE) }).ok()?;
            if address == 0 || address % core::mem::align_of::<CpuLocal>() != 0 {
                return None;
            }
            // SAFETY: each kernel entry path clears IA32_GS_BASE before using
            // allocation or locking services. A non-zero value is installed only
            // from a pinned CpuLocal owned by CpuRuntime and is never repointed
            // during that CPU's lifetime.
            let local = unsafe { &*(address as *const CpuLocal) };
            if !local.is_self_address(address) {
                return None;
            }
            Some(Self {
                local,
                _not_send_or_sync: PhantomData,
            })
        }
    }

    pub(crate) fn with_exchange_cache<R>(
        &self,
        operation: impl FnOnce(&mut crate::heap::ExchangeMagazine) -> R,
    ) -> Option<R> {
        with_owner_access(|| {
            let current = Self::acquire()?;
            if !core::ptr::eq(current.local, self.local) {
                return None;
            }
            self.local
                .exchange_cache
                .try_borrow_mut()
                .ok()
                .map(|mut cache| operation(&mut cache))
        })
    }

    pub(crate) fn with_heap_cache<R>(
        &self,
        operation: impl FnOnce(&mut crate::heap::HeapCache) -> R,
    ) -> Option<R> {
        with_owner_access(|| {
            let current = Self::acquire()?;
            if !core::ptr::eq(current.local, self.local) {
                return None;
            }
            self.local
                .heap_cache
                .try_borrow_mut()
                .ok()
                .map(|mut cache| operation(&mut cache))
        })
    }

    /// Offline completion requires all owner cache borrows to have ended and
    /// all retained entries to have returned. A loan in flight is not empty.
    pub(crate) fn memory_caches_empty(&self) -> bool {
        let empty = self.with_exchange_cache(|cache| cache.is_empty()) == Some(true)
            && self.with_heap_cache(|cache| cache.is_empty()) == Some(true);
        #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
        {
            empty && self.with_frame_cache(|cache| cache.is_empty()) == Some(true)
        }
        #[cfg(all(
            test,
            not(feature = "full_mm_tests"),
            not(feature = "qemu-test-export")
        ))]
        {
            empty
        }
    }

    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    pub(crate) fn with_frame_cache<R>(
        &self,
        operation: impl FnOnce(&mut crate::mm::phys::frame_allocator::LocalFrameCache) -> R,
    ) -> Option<R> {
        // Interrupt exclusion also excludes interrupt-driven preemption. The
        // closure is synchronous and cannot retain the mutable owner borrow.
        // RefCell rejects recursive allocator entry instead of aliasing state.
        with_owner_access(|| {
            let current = Self::acquire()?;
            if !core::ptr::eq(current.local, self.local) {
                return None;
            }
            self.local
                .frame_cache
                .try_borrow_mut()
                .ok()
                .map(|mut cache| operation(&mut cache))
        })
    }

    pub(crate) fn memory_node(&self) -> Option<crate::mm::types::NumaNodeId> {
        self.local
            .remote
            .numa_node()
            .map(crate::mm::types::NumaNodeId::new)
    }

    pub(crate) fn clear_boot_binding() {
        #[cfg(target_os = "none")]
        unsafe {
            write_msr(IA32_GS_BASE, 0)
        };
    }

    pub(crate) fn bind(id: CpuId) -> Result<Self, CurrentCpuBindError> {
        #[cfg(not(target_os = "none"))]
        {
            let _ = id;
            Err(CurrentCpuBindError::UnsupportedPlatform)
        }
        #[cfg(target_os = "none")]
        {
            let runtime = super::try_runtime().ok_or(CurrentCpuBindError::RuntimeUnavailable)?;
            let local = runtime
                .cpu_local(id)
                .ok_or(CurrentCpuBindError::UnknownCpu(id))?;
            unsafe { local.install_on_current_cpu() };
            let mask = match super::xstate::configuration() {
                super::xstate::XStateConfiguration::Fxsave => 0,
                super::xstate::XStateConfiguration::Xsave { mask, .. } => mask,
            };
            // SAFETY: CpuRuntime pins this CPU-local image across the whole CPU
            // generation and the BSP/AP xstate policy bounds the image size.
            unsafe {
                local
                    .preemption
                    .state()
                    .configure_xstate(local.scheduler_xstate.get() as usize, mask)
            };
            Self::acquire().ok_or(CurrentCpuBindError::BindingRejected(id))
        }
    }

    pub const fn id(&self) -> CpuId {
        self.local.id()
    }

    pub fn execution(&self) -> Option<crate::task::Subject> {
        self.local.execution()
    }

    /// Charge through the installed account while borrowing CPU-local state.
    /// The borrow excludes interrupts/preemption and cannot escape this call.
    pub(crate) fn reserve_memory(
        &self,
        bytes: u64,
    ) -> Result<Option<crate::domain::quota::MemoryCredit>, crate::domain::quota::QuotaError> {
        with_owner_access(|| {
            // SAFETY: CurrentCpu restricts access to its owning CPU; the short
            // borrow never allocates or calls back into execution switching.
            let owned = unsafe { &*self.local.owned.get() };
            match owned.execution.as_ref() {
                Some(context) => context.reserve_memory(bytes),
                None => Ok(None), // bootstrap/kernel execution is uncharged
            }
        })
    }

    pub(crate) fn execution_cell(&self) -> Option<crate::loader::CellId> {
        with_owner_access(|| {
            // SAFETY: the short owner-only borrow excludes replacement and
            // returns only a copied code-generation observation.
            unsafe {
                (*self.local.owned.get())
                    .execution
                    .as_ref()
                    .and_then(|context| context.cell)
            }
        })
    }

    pub(crate) fn finalization_authority(
        &self,
        domain: crate::domain::DomainId,
    ) -> Option<crate::task::execution::FinalizationAuthority> {
        with_owner_access(|| {
            // SAFETY: Arc retention does not call into execution replacement.
            // Derivation is limited to the installed owner's cleanup authority.
            unsafe {
                (*self.local.owned.get())
                    .execution
                    .as_ref()
                    .filter(|context| context.subject().domain == domain)
                    .and_then(|context| context.finalization.clone())
            }
        })
    }

    pub(crate) fn preemption_state(&self) -> &hal::preemption::PreemptionState {
        self.local.preemption.state()
    }

    pub(crate) fn enter_execution(
        self,
        execution: crate::task::ExecutionContext,
    ) -> ExecutionContextGuard {
        let previous = self.local.replace_execution(Some(execution));
        ExecutionContextGuard {
            current: self,
            previous,
            code_lease: None,
        }
    }

    pub fn take_control(&self) -> Option<CpuControlMessage> {
        self.local.take_control()
    }

    pub(crate) fn acknowledge_online(&self) {
        self.local.remote.acknowledge_online();
    }

    pub(crate) fn acknowledge_parked(&self) {
        self.local.remote.acknowledge_parked();
    }

    pub fn in_interrupt(&self) -> bool {
        self.local.remote.in_interrupt()
    }

    pub(crate) fn descriptor_tables(&self) -> &'static crate::interrupts::gdt::CpuDescriptorTables {
        let tables = self.local.descriptor_tables.as_ref().get_ref();
        let pointer = tables as *const crate::interrupts::gdt::CpuDescriptorTables;
        // SAFETY: CurrentCpu holds a static CpuLocal and the descriptor-table
        // allocation is pinned for exactly that CpuLocal's lifetime.
        unsafe { &*pointer }
    }

    pub(crate) fn enter_interrupt(self) -> InterruptContextGuard {
        self.local.enter_interrupt();
        InterruptContextGuard { current: self }
    }

    pub(crate) fn record_interrupt(&self, context: InterruptContext) {
        self.local.remote.record_interrupt(context);
    }

    pub(crate) fn request_timer_event(&self) {
        self.local.remote.request_timer_event();
    }

    pub(crate) fn take_timer_event(&self) -> bool {
        self.local.remote.take_timer_event()
    }

    pub(crate) fn arm_runtime_timer_once(&self) -> bool {
        self.local.remote.arm_runtime_timer_once()
    }

    pub(crate) fn disarm_runtime_timer(&self) {
        self.local.remote.disarm_runtime_timer();
    }

    pub(crate) fn runtime_timer_armed(&self) -> bool {
        self.local.remote.runtime_timer_armed()
    }

    pub(crate) fn install_task_fuel(&self, budget: &crate::task::PollBudget) {
        self.local.refill_task_fuel(budget.remaining());
    }

    pub(crate) fn exhaust_task_fuel(&self) {
        self.local.refill_task_fuel(0);
    }

    pub(crate) fn consume_task_fuel(&self, amount: u64) -> bool {
        self.local.consume_task_fuel(amount)
    }

    pub(crate) fn task_fuel(&self) -> u64 {
        self.local.task_fuel()
    }

    pub(crate) fn enter_rcu_read(&self) {
        self.local.enter_rcu_read();
    }

    pub(crate) fn exit_rcu_read(&self) {
        self.local.exit_rcu_read();
    }

    pub(crate) fn rcu_read_active(&self) -> bool {
        self.local.remote.rcu_read_depth() != 0
    }

    pub(crate) fn note_rcu_quiescent(&self) -> bool {
        self.local.note_rcu_quiescent()
    }

    pub(crate) fn enter_lazy_tlb(&self) {
        self.local.enter_lazy_tlb();
    }

    pub(crate) fn activate_tlb(&self) -> Option<u64> {
        self.local.activate_tlb()
    }

    pub(crate) fn pending_tlb_generation(&self) -> Option<u64> {
        self.local.remote.pending_tlb_generation()
    }

    pub(crate) fn complete_tlb_generation(&self, generation: u64) {
        self.local.remote.complete_tlb_generation(generation);
    }

    pub(crate) fn defer_interrupt_wake(&self, index: usize) {
        self.local.remote.defer_interrupt_wake(index);
    }

    pub(crate) fn atomic_notifications(&self) -> &NotificationQueue<WakerSlot> {
        &self.local.remote.atomic_notifications
    }

    pub(crate) fn queue_notifications(&self) -> &NotificationQueue<WakerQueueState> {
        &self.local.remote.queue_notifications
    }

    pub(crate) fn drain_interrupt_wakes(&self, deliver: impl FnMut(usize)) {
        self.local.remote.interrupt_wakes.drain(deliver);
    }

    pub(crate) fn pending_deferred_work(&self) -> usize {
        self.local.remote.pending_deferred_work()
    }

    pub(crate) fn try_enter_page_fault(self) -> Result<PageFaultGuard, Self> {
        if self.local.try_enter_page_fault() {
            Ok(PageFaultGuard { current: self })
        } else {
            Err(self)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CurrentCpuBindError {
    UnsupportedPlatform,
    RuntimeUnavailable,
    UnknownCpu(CpuId),
    BindingRejected(CpuId),
}

pub(crate) struct PageFaultGuard {
    current: CurrentCpu,
}

pub(crate) struct InterruptContextGuard {
    current: CurrentCpu,
}

impl Drop for InterruptContextGuard {
    fn drop(&mut self) {
        self.current.local.exit_interrupt();
    }
}

impl Drop for PageFaultGuard {
    fn drop(&mut self) {
        self.current.local.exit_page_fault();
    }
}

pub(crate) struct ExecutionContextGuard {
    current: CurrentCpu,
    previous: Option<crate::task::ExecutionContext>,
    code_lease: Option<crate::domain::DomainCodeLease>,
}

impl ExecutionContextGuard {
    /// Restore the scheduler/caller and return the exact installed execution.
    /// Nested guards remain owned on an interrupted task's stack.
    pub(crate) fn leave(self) -> Option<crate::task::ExecutionContext> {
        let mut guard = core::mem::ManuallyDrop::new(self);
        let previous = guard.previous.take();
        let execution = guard.current.local.replace_execution(previous);
        drop(guard.code_lease.take());
        execution
    }

    pub(crate) fn retain_code(mut self, lease: crate::domain::DomainCodeLease) -> Self {
        self.code_lease = Some(lease);
        self
    }
}

impl Drop for ExecutionContextGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        drop(self.current.local.replace_execution(previous));
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

unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

unsafe fn write_msr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn deferred_notifications_coalesce_and_retain_their_target() {
        let remote = CpuRemoteAccess::new();
        let target =
            alloc::sync::Arc::new(exorust_sync::DeferredNotification::new(WakerSlot::new()));
        let weak = alloc::sync::Arc::downgrade(&target);
        target.value().register(core::task::Waker::noop());
        for _ in 0..10_000 {
            remote.atomic_notifications.publish(&target);
        }
        assert_eq!(remote.pending_deferred_work(), 1);
        assert_eq!(
            remote.physical_generation_residue(),
            Some(CpuGenerationResource::DeferredWork)
        );
        drop(target);
        assert!(weak.upgrade().is_some());
        remote.atomic_notifications.drain(WakerSlot::wake);
        assert!(weak.upgrade().is_none());
        assert_eq!(remote.pending_deferred_work(), 0);
        assert_eq!(remote.physical_generation_residue(), None);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn deferred_queues_keep_message_classes_separate() {
        let remote = CpuRemoteAccess::new();
        let atomic =
            alloc::sync::Arc::new(exorust_sync::DeferredNotification::new(WakerSlot::new()));
        let queue = alloc::sync::Arc::new(exorust_sync::DeferredNotification::new(
            WakerQueueState::new(),
        ));
        remote.atomic_notifications.publish(&atomic);
        remote.queue_notifications.publish(&queue);
        remote.defer_interrupt_wake(66);
        assert_eq!(remote.pending_deferred_work(), 3);
        remote.atomic_notifications.drain(WakerSlot::wake);
        remote.queue_notifications.drain(WakerQueueState::wake_all);
        remote.interrupt_wakes.drain(|index| assert_eq!(index, 66));
        assert_eq!(remote.pending_deferred_work(), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn interrupt_storm_preserves_other_sources_and_snapshot_republication() {
        let notifications = InterruptWakeSet::new();
        for _ in 0..10_000 {
            notifications.publish(1);
        }
        notifications.publish(crate::task::interrupt_waker::MAX_INTERRUPT_INDICES - 1);
        assert_eq!(notifications.pending_count(), 2);
        let mut delivered = alloc::vec::Vec::new();
        notifications.drain(|index| {
            delivered.push(index);
            notifications.publish(1);
        });
        assert_eq!(
            delivered,
            [1, crate::task::interrupt_waker::MAX_INTERRUPT_INDICES - 1]
        );
        assert_eq!(notifications.pending_count(), 1);
        notifications.drain(|index| assert_eq!(index, 1));
        assert_eq!(notifications.pending_count(), 0);
    }
}
