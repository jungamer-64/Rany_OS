use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::sync::MpscRingBuffer;

use super::CpuId;

const CONTROL_QUEUE_SLOTS: usize = 32;
const DEFERRED_WAKE_QUEUE_SLOTS: usize = 257;
const IO_COMPLETION_QUEUE_SLOTS: usize = 257;
const INTERRUPT_WAKE_QUEUE_SLOTS: usize = 1025;
const IA32_FS_BASE: u32 = 0xc000_0100;
const IA32_GS_BASE: u32 = 0xc000_0101;
const TLB_ACTIVE: u8 = 0;
const TLB_LAZY: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuControlMessage {
    WakeExecutor,
    Start,
    Park,
}

pub struct CpuRemoteAccess {
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
    deferred_atomic_wakes: MpscRingBuffer<usize, DEFERRED_WAKE_QUEUE_SLOTS>,
    deferred_queue_wakes: MpscRingBuffer<usize, DEFERRED_WAKE_QUEUE_SLOTS>,
    deferred_io_completions: MpscRingBuffer<(u64, u64, u64), IO_COMPLETION_QUEUE_SLOTS>,
    interrupt_wakes: MpscRingBuffer<usize, INTERRUPT_WAKE_QUEUE_SLOTS>,
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
            deferred_atomic_wakes: MpscRingBuffer::new(),
            deferred_queue_wakes: MpscRingBuffer::new(),
            deferred_io_completions: MpscRingBuffer::new(),
            interrupt_wakes: MpscRingBuffer::new(),
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

    pub fn numa_node(&self) -> Option<u8> {
        let node = self.numa_node.load(Ordering::Acquire);
        (node != u8::MAX).then_some(node)
    }

    pub(crate) fn set_numa_node(&self, node: Option<u8>) {
        self.numa_node
            .store(node.unwrap_or(u8::MAX), Ordering::Release);
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

    fn defer_atomic_wake(&self, pointer: usize) -> bool {
        self.deferred_atomic_wakes.try_push(pointer).is_ok()
    }

    fn take_atomic_wake(&self) -> Option<usize> {
        self.deferred_atomic_wakes.pop()
    }

    fn defer_queue_wake(&self, pointer: usize) -> bool {
        self.deferred_queue_wakes.try_push(pointer).is_ok()
    }

    fn take_queue_wake(&self) -> Option<usize> {
        self.deferred_queue_wakes.pop()
    }

    fn defer_io_completion(&self, completion: (u64, u64, u64)) -> bool {
        self.deferred_io_completions.try_push(completion).is_ok()
    }

    fn take_io_completion(&self) -> Option<(u64, u64, u64)> {
        self.deferred_io_completions.pop()
    }

    fn defer_interrupt_wake(&self, encoded_source: usize) -> bool {
        self.interrupt_wakes.try_push(encoded_source).is_ok()
    }

    fn take_interrupt_wake(&self) -> Option<usize> {
        self.interrupt_wakes.pop()
    }

    pub(crate) fn pending_interrupt_wakes(&self) -> usize {
        self.interrupt_wakes.len()
    }

    pub(crate) fn pending_deferred_work(&self) -> usize {
        self.deferred_atomic_wakes
            .len()
            .saturating_add(self.deferred_queue_wakes.len())
            .saturating_add(self.deferred_io_completions.len())
            .saturating_add(self.interrupt_wakes.len())
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
        }))
    }
}

impl Drop for CpuTls {
    fn drop(&mut self) {
        unsafe { dealloc(self.allocation.as_ptr(), self.layout) };
    }
}

#[repr(C, align(64))]
pub struct CpuLocal {
    self_address: usize,
    id: CpuId,
    owned: UnsafeCell<CpuOwnedState>,
    remote: CpuRemoteAccess,
    descriptor_tables: Pin<Box<crate::interrupts::gdt::CpuDescriptorTables>>,
    tls: Option<CpuTls>,
    _pin: PhantomPinned,
}

// SAFETY: `owned` is only accessed through a `CurrentCpu` token, which is
// non-Send/non-Sync and can only be acquired for the executing CPU. All
// cross-CPU access is confined to `CpuRemoteAccess` atomics and its MPSC queue.
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
            self_address: 0,
            id,
            owned: UnsafeCell::new(CpuOwnedState {
                execution: None,
                page_fault_active: false,
                task_fuel: 0,
            }),
            remote: CpuRemoteAccess::new(),
            descriptor_tables,
            tls,
            _pin: PhantomPinned,
        });
        let address = local.as_ref().get_ref() as *const Self as usize;
        unsafe { Pin::get_unchecked_mut(local.as_mut()).self_address = address };
        Ok(local)
    }

    pub const fn id(&self) -> CpuId {
        self.id
    }

    pub fn remote(&self) -> &CpuRemoteAccess {
        &self.remote
    }

    fn is_self_address(&self, address: usize) -> bool {
        self.self_address == address && self.self_address == self as *const Self as usize
    }

    unsafe fn install_on_current_cpu(&self) {
        unsafe { write_msr(IA32_GS_BASE, self.self_address as u64) };
        if let Some(tls) = self.tls.as_ref() {
            unsafe { write_msr(IA32_FS_BASE, tls.fs_base) };
        }
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
    pub fn acquire() -> Option<Self> {
        let address = usize::try_from(unsafe { read_msr(IA32_GS_BASE) }).ok()?;
        if address == 0 {
            return None;
        }
        let local = super::try_runtime()?.cpu_local_by_address(address)?;
        if !local.is_self_address(address) {
            return None;
        }
        Some(Self {
            local,
            _not_send_or_sync: PhantomData,
        })
    }

    pub(crate) fn bind(id: CpuId) -> Result<Self, CurrentCpuBindError> {
        let runtime = super::try_runtime().ok_or(CurrentCpuBindError::RuntimeUnavailable)?;
        let local = runtime
            .cpu_local(id)
            .ok_or(CurrentCpuBindError::UnknownCpu(id))?;
        unsafe { local.install_on_current_cpu() };
        Self::acquire().ok_or(CurrentCpuBindError::BindingRejected(id))
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

    pub(crate) fn refill_task_fuel(&self, amount: u64) {
        self.local.refill_task_fuel(amount);
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

    pub(crate) fn defer_atomic_wake(&self, pointer: usize) -> bool {
        self.local.remote.defer_atomic_wake(pointer)
    }

    pub(crate) fn take_atomic_wake(&self) -> Option<usize> {
        self.local.remote.take_atomic_wake()
    }

    pub(crate) fn defer_queue_wake(&self, pointer: usize) -> bool {
        self.local.remote.defer_queue_wake(pointer)
    }

    pub(crate) fn take_queue_wake(&self) -> Option<usize> {
        self.local.remote.take_queue_wake()
    }

    pub(crate) fn defer_io_completion(&self, completion: (u64, u64, u64)) -> bool {
        self.local.remote.defer_io_completion(completion)
    }

    pub(crate) fn take_io_completion(&self) -> Option<(u64, u64, u64)> {
        self.local.remote.take_io_completion()
    }

    pub(crate) fn defer_interrupt_wake(&self, encoded_source: usize) -> bool {
        self.local.remote.defer_interrupt_wake(encoded_source)
    }

    pub(crate) fn take_interrupt_wake(&self) -> Option<usize> {
        self.local.remote.take_interrupt_wake()
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
    fn deferred_queue_is_bounded_and_preserves_fifo_order() {
        let remote = CpuRemoteAccess::new();

        for pointer in 1..=DEFERRED_WAKE_QUEUE_SLOTS - 1 {
            assert!(remote.defer_atomic_wake(pointer));
        }
        assert!(!remote.defer_atomic_wake(DEFERRED_WAKE_QUEUE_SLOTS));

        for pointer in 1..=DEFERRED_WAKE_QUEUE_SLOTS - 1 {
            assert_eq!(remote.take_atomic_wake(), Some(pointer));
        }
        assert_eq!(remote.take_atomic_wake(), None);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn deferred_queues_keep_message_classes_separate() {
        let remote = CpuRemoteAccess::new();

        assert!(remote.defer_atomic_wake(11));
        assert!(remote.defer_queue_wake(22));
        assert!(remote.defer_io_completion((33, 44, 55)));
        assert!(remote.defer_interrupt_wake(66));
        assert_eq!(remote.pending_deferred_work(), 4);

        assert_eq!(remote.take_atomic_wake(), Some(11));
        assert_eq!(remote.take_queue_wake(), Some(22));
        assert_eq!(remote.take_io_completion(), Some((33, 44, 55)));
        assert_eq!(remote.take_interrupt_wake(), Some(66));
        assert_eq!(remote.pending_deferred_work(), 0);
    }
}
