// ============================================================================
// kernel/src/io/iommu/runtime/command/queue.rs
// ============================================================================

//!
// Command Queue for IOMMU - initial implementation
// - Per-controller MPSC queue using existing BoundedChannel
// - Preallocated completion slots (no per-command heap allocations)
// - submit_sync() API that blocks by using backoff spin until completion
// - process_once() worker to be called periodically by the Executor

use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;
use crate::sync::lockfree::Backoff;
use crate::sync::lockfree::BoundedChannel;
use crate::sync::lockfree::BoundedReceiver;
use crate::sync::lockfree::BoundedSender;
use crate::sync::lockfree::DEFAULT_QUEUE_SIZE;
use core::future::poll_fn;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use alloc::alloc::Layout;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::io::iommu::types::DeviceId;

/// Command kinds (initial subset)
#[derive(Debug, Clone)]
pub enum IommuCommandKind {
    InvalidateIotlbDomain {
        domain: u16,
    },
    InvalidateIotlbGlobal,
    /// Map a region into the given domain
    MapRegion {
        domain: u16,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    },
    /// Map a region for a specific device (device-scoped invalidation)
    MapRegionDevice {
        device: DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    },
    /// Unmap a region from the given domain (size may be 4KB-aligned)
    UnmapRegion {
        domain: u16,
        iova: u64,
        size: u64,
    },
    /// Unmap a region for a specific device
    UnmapRegionDevice {
        device: DeviceId,
        iova: u64,
        size: u64,
    },
    // TODO: PRQ/QR ops etc.
}

/// A command pushed onto the queue
#[derive(Debug, Clone)]
pub struct IommuCommand {
    pub kind: IommuCommandKind,
    pub slot_idx: usize,
}

/// Completion slot for commands
pub struct CompletionSlot {
    /// 0 = free, 1 = pending, 2 = done
    state: AtomicU8,
    /// result code (0 = Ok, negative for error)
    result: AtomicI32,
    /// cancellation flag (0 = normal, 1 = canceled)
    canceled: AtomicU8,
    waker: AtomicWaker,
}

impl core::fmt::Debug for CompletionSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompletionSlot")
            .field("state", &self.state.load(Ordering::Relaxed))
            .field("result", &self.result.load(Ordering::Relaxed))
            .field("canceled", &self.canceled.load(Ordering::Relaxed))
            .field("waker", &"<AtomicWaker>")
            .finish()
    }
}

// Result codes
const RESULT_OK: i32 = 0;
const RESULT_HW_ERR: i32 = -1;
const RESULT_CANCELLED: i32 = -2;
const RESULT_TIMEOUT: i32 = -3;
pub(crate) const RESULT_POISONED: i32 = -4;
const MAX_COMPLETION_SPINS: usize = DEFAULT_QUEUE_SIZE * 256;
const MAX_SUBMIT_RETRIES: usize = DEFAULT_QUEUE_SIZE * 4;
const WAIT_WARN_INTERVAL: usize = DEFAULT_QUEUE_SIZE * 16;
const SLOT_STATE_POISONING: u8 = 3;

#[inline]
const fn bounded_channel_capacity() -> usize {
    DEFAULT_QUEUE_SIZE - 1
}

#[inline]
fn reset_slot_to_free(slot: &CompletionSlot) {
    slot.result.store(0, Ordering::Release);
    slot.canceled.store(0, Ordering::Release);
    slot.state.store(0, Ordering::Release);
}

#[inline]
fn take_completed_result(slot: &CompletionSlot) -> Option<i32> {
    if slot.state.load(Ordering::Acquire) != 2 {
        return None;
    }
    let result = slot.result.load(Ordering::Acquire);
    reset_slot_to_free(slot);
    Some(result)
}

#[inline]
fn take_completed_result_and_notify(
    slot: &CompletionSlot,
    queue_ptr: *const CommandQueue,
) -> Option<i32> {
    let result = take_completed_result(slot)?;
    let queue = unsafe { &*queue_ptr };
    queue.notify_slot_available();
    Some(result)
}

impl CompletionSlot {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            result: AtomicI32::new(0),
            canceled: AtomicU8::new(0),
            waker: AtomicWaker::new(),
        }
    }

    #[inline]
    pub fn try_acquire(&self) -> bool {
        let ok = self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
        if ok {
            // reset canceled flag to be safe
            self.canceled.store(0, Ordering::Release);
        }
        ok
    }

    #[inline]
    pub fn complete(&self, code: i32) {
        self.result.store(code, Ordering::Release);
        self.state.store(2, Ordering::Release);
        self.waker.wake();
    }

    #[inline]
    fn complete_poisoned(&self) -> bool {
        if self
            .state
            .compare_exchange(1, SLOT_STATE_POISONING, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }

        self.result.store(RESULT_POISONED, Ordering::Release);
        self.state.store(2, Ordering::Release);
        self.waker.wake();
        true
    }

    #[inline]
    pub fn wait_result_spin(&self) -> i32 {
        let mut backoff = Backoff::new();
        for _ in 0..MAX_COMPLETION_SPINS {
            if let Some(result) = take_completed_result(self) {
                return result;
            }
            backoff.spin();
        }
        RESULT_TIMEOUT
    }

    #[inline]
    pub fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire) != 0
    }

    #[inline]
    pub fn cancel(&self) -> bool {
        // Can't cancel if already completed
        if self.state.load(Ordering::Acquire) == 2 {
            return false;
        }
        self.canceled
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }
}

/// Completion object returned for a submitted command.
pub struct CommandCompletion {
    slot_idx: usize,
    slots_ptr: *const CompletionSlot,
    queue_ptr: *const CommandQueue,
}

impl CommandCompletion {
    /// Blocking wait until command completes (legacy blocking shim)
    pub fn wait_blocking(&self) -> i32 {
        let slot = unsafe { &*self.slots_ptr.add(self.slot_idx) };
        let mut backoff = Backoff::new();
        for spins in 0..MAX_COMPLETION_SPINS {
            if let Some(result) = take_completed_result_and_notify(slot, self.queue_ptr) {
                return result;
            }
            if spins > 0 && spins % WAIT_WARN_INTERVAL == 0 {
                crate::io::log::early_print("[IOMMU] wait_blocking still pending\n");
            }
            backoff.spin();
        }
        RESULT_TIMEOUT
    }

    /// Synchronous wait that also acts as a worker to drain the queue.
    pub fn wait_sync_with_worker<F>(&self, q: &CommandQueue, mut handler: F) -> i32
    where
        F: FnMut(&IommuCommandKind) -> Result<i32, ()>,
    {
        let slot = unsafe { &*self.slots_ptr.add(self.slot_idx) };
        let mut backoff = Backoff::new();
        for spins in 0..MAX_COMPLETION_SPINS {
            if let Some(result) = take_completed_result_and_notify(slot, self.queue_ptr) {
                return result;
            }

            // Try to make progress by processing the queue manually
            let processed = q.process_up_to(&mut handler, 1);
            if processed == 0 {
                backoff.spin();
                if spins > 0 && spins % WAIT_WARN_INTERVAL == 0 {
                    crate::io::log::early_print(
                        "[IOMMU] wait_sync_with_worker stuck spin warning\n",
                    );
                }
            } else {
                backoff = Backoff::new(); // reset backoff
            }
        }
        RESULT_TIMEOUT
    }

    pub fn cancel(&self) -> bool {
        let q = unsafe { &*self.queue_ptr };
        // record an attempt to cancel
        q.cancel_attempts.fetch_add(1, Ordering::Relaxed);
        let slot = unsafe { &*self.slots_ptr.add(self.slot_idx) };
        slot.cancel()
    }
}

impl Drop for CommandCompletion {
    fn drop(&mut self) {
        let slot = unsafe { &*self.slots_ptr.add(self.slot_idx) };
        if slot.state.load(Ordering::Acquire) != 1 {
            return;
        }
        // Best-effort cancel when the completion object is dropped
        let q = unsafe { &*self.queue_ptr };
        q.cancel_attempts.fetch_add(1, Ordering::Relaxed);
        let _ = slot.cancel();
    }
}

impl core::future::Future for CommandCompletion {
    type Output = i32;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let slot = unsafe { &*self.slots_ptr.add(self.slot_idx) };
        if let Some(result) = take_completed_result_and_notify(slot, self.queue_ptr) {
            return Poll::Ready(result);
        }

        slot.waker.register(cx.waker());
        if let Some(result) = take_completed_result_and_notify(slot, self.queue_ptr) {
            Poll::Ready(result)
        } else {
            Poll::Pending
        }
    }
}

/// CommandQueue holds sender/receiver and completion slots
pub struct CommandQueue {
    sender: BoundedSender<IommuCommand, DEFAULT_QUEUE_SIZE>,
    receiver: PoisonLock<BoundedReceiver<IommuCommand, DEFAULT_QUEUE_SIZE>>,
    slots: &'static [CompletionSlot],
    next_alloc: AtomicUsize,
    poisoned: AtomicBool,
    /// Optional NUMA node hint used for allocating the slots array
    numa_node: Option<usize>,
    /// Waker for tasks waiting for a free slot
    slot_waiter: AtomicWaker,
    /// Waker for tasks waiting for send space on the channel
    send_waiter: AtomicWaker,
    /// Waker for tasks waiting for new commands
    recv_waiter: AtomicWaker,
    /// Counters for metrics and diagnostics
    processed_count: AtomicUsize,
    cancelled_count: AtomicUsize,
    cancel_attempts: AtomicUsize,
    reclaimed_count: AtomicUsize,
    send_backpressure_count: AtomicUsize,
}

impl core::fmt::Debug for CommandQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommandQueue")
            .field("next_alloc", &self.next_alloc.load(Ordering::Relaxed))
            .field("poisoned", &self.is_poisoned())
            .field("numa_node", &self.numa_node)
            .field(
                "processed_count",
                &self.processed_count.load(Ordering::Relaxed),
            )
            .field(
                "cancelled_count",
                &self.cancelled_count.load(Ordering::Relaxed),
            )
            .field(
                "reclaimed_count",
                &self.reclaimed_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl CommandQueue {
    pub fn new_with_numa(numa_node: Option<usize>) -> Self {
        let (s, r) = BoundedChannel::<IommuCommand, DEFAULT_QUEUE_SIZE>::new();

        // Try to allocate slots on the given NUMA node for locality benefits.
        let layout = Layout::array::<CompletionSlot>(DEFAULT_QUEUE_SIZE).expect("layout");
        let slots: &'static [CompletionSlot] = if let Some(nonnull) =
            crate::mm::numa::topology::allocate_zeroed_on_node(layout, numa_node)
        {
            unsafe {
                let ptr = nonnull.as_ptr() as *mut CompletionSlot;
                for i in 0..DEFAULT_QUEUE_SIZE {
                    core::ptr::write(ptr.add(i), CompletionSlot::new());
                }
                let slice = core::slice::from_raw_parts_mut(ptr, DEFAULT_QUEUE_SIZE);
                let boxed = Box::from_raw(slice as *mut [CompletionSlot]);
                let slot_mut_ref: &'static mut [CompletionSlot] = Box::leak(boxed);
                let slot_ref: &'static [CompletionSlot] = &*slot_mut_ref;
                slot_ref
            }
        } else {
            // Fallback to global allocator
            let mut v: Vec<CompletionSlot> = Vec::with_capacity(DEFAULT_QUEUE_SIZE);
            for _ in 0..DEFAULT_QUEUE_SIZE {
                v.push(CompletionSlot::new());
            }
            let boxed = v.into_boxed_slice();
            let slot_mut_ref: &'static mut [CompletionSlot] = Box::leak(boxed);
            let slot_ref: &'static [CompletionSlot] = &*slot_mut_ref;
            slot_ref
        };

        Self {
            sender: s,
            receiver: PoisonLock::new(r),
            slots,
            next_alloc: AtomicUsize::new(0),
            poisoned: AtomicBool::new(false),
            numa_node,
            slot_waiter: AtomicWaker::new(),
            send_waiter: AtomicWaker::new(),
            recv_waiter: AtomicWaker::new(),
            processed_count: AtomicUsize::new(0),
            cancelled_count: AtomicUsize::new(0),
            cancel_attempts: AtomicUsize::new(0),
            reclaimed_count: AtomicUsize::new(0),
            send_backpressure_count: AtomicUsize::new(0),
        }
    }

    /// Convenience constructor with no NUMA hint
    pub fn new() -> Self {
        Self::new_with_numa(None)
    }

    #[inline]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    fn poison(&self) {
        if self.poisoned.swap(true, Ordering::AcqRel) {
            return;
        }

        for slot in self.slots.iter() {
            let _ = slot.complete_poisoned();
        }

        self.slot_waiter.wake();
        self.send_waiter.wake();
        self.recv_waiter.wake();
    }

    fn with_receiver<R>(
        &self,
        f: impl FnOnce(&BoundedReceiver<IommuCommand, DEFAULT_QUEUE_SIZE>) -> R,
    ) -> Result<R, ()> {
        match self.receiver.lock() {
            Ok(guard) => Ok(f(&guard)),
            Err(poisoned) => {
                drop(poisoned.into_inner());
                self.poison();
                Err(())
            }
        }
    }

    #[inline]
    fn ensure_receiver_available(&self) -> Result<(), ()> {
        if self.is_poisoned() {
            return Err(());
        }
        self.with_receiver(|_| ())
    }

    /// Allocate a free slot index or return None if none available now
    fn alloc_slot(&self) -> Option<usize> {
        if self.is_poisoned() {
            return None;
        }
        let n = self.slots.len();
        // First pass: preferentially reclaim completed slots (state == 2)
        let start = self.next_alloc.fetch_add(1, Ordering::Relaxed) % n;
        for i in 0..n {
            let idx = (start + i) % n;
            if self.slots[idx]
                .state
                .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Clear stale result and canceled flag and return this slot
                self.slots[idx].result.store(0, Ordering::Release);
                self.slots[idx].canceled.store(0, Ordering::Release);
                // Metrics: reclaimed completed slot
                self.reclaimed_count.fetch_add(1, Ordering::Relaxed);
                return Some(idx);
            }
        }

        // Second pass: try to acquire a fresh free slot (0 -> 1)
        let mut backoff = Backoff::new();
        for _ in 0..n {
            let idx = self.next_alloc.fetch_add(1, Ordering::Relaxed) % n;
            if self.slots[idx].try_acquire() {
                return Some(idx);
            }
            backoff.snooze();
        }
        None
    }

    /// Non-blocking attempt to allocate a slot; useful for async submit futures
    fn try_alloc_slot(&self) -> Option<usize> {
        if self.is_poisoned() {
            return None;
        }
        let n = self.slots.len();
        let start = self.next_alloc.fetch_add(1, Ordering::Relaxed) % n;
        // First pass: try to reclaim any completed slots (2 -> 1)
        for i in 0..n {
            let idx = (start + i) % n;
            if self.slots[idx]
                .state
                .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.slots[idx].result.store(0, Ordering::Release);
                self.slots[idx].canceled.store(0, Ordering::Release);
                // Metrics: reclaimed completed slot
                self.reclaimed_count.fetch_add(1, Ordering::Relaxed);
                return Some(idx);
            }
        }
        // Second pass: try to acquire a fresh slot (0 -> 1)
        for _i in 0..n {
            let idx = self.next_alloc.fetch_add(1, Ordering::Relaxed) % n;
            if self.slots[idx].try_acquire() {
                return Some(idx);
            }
        }
        None
    }

    /// Notify tasks waiting for a free slot
    fn notify_slot_available(&self) {
        self.slot_waiter.wake();
    }

    /// Notify tasks waiting for send space on the channel
    fn notify_send_available(&self) {
        self.send_waiter.wake();
    }

    #[inline]
    fn release_unsubmitted_slot(&self, slot_idx: usize) {
        reset_slot_to_free(&self.slots[slot_idx]);
        self.notify_slot_available();
    }

    #[inline]
    fn release_future_slot(&self, slot_idx: Option<usize>) {
        if let Some(idx) = slot_idx {
            if self.slots[idx].state.load(Ordering::Acquire) == 1 {
                self.release_unsubmitted_slot(idx);
            }
        }
    }

    /// Non-blocking submit: returns a `CommandCompletion` which implements `Future`
    pub fn submit(&self, kind: IommuCommandKind) -> Result<CommandCompletion, ()> {
        self.ensure_receiver_available()?;
        let slot_idx = match self.alloc_slot() {
            Some(i) => i,
            None => {
                return Err(());
            }
        };

        if self.ensure_receiver_available().is_err() {
            self.release_unsubmitted_slot(slot_idx);
            return Err(());
        }

        let cmd = IommuCommand { kind, slot_idx };

        // Wait for sender to accept (bounded). Try with small backoff
        let mut backoff = Backoff::new();
        for _attempt in 0..MAX_SUBMIT_RETRIES {
            if self.is_poisoned() {
                self.release_unsubmitted_slot(slot_idx);
                return Err(());
            }
            match self.sender.send(cmd.clone()) {
                Ok(_) => {
                    self.recv_waiter.wake();
                    return Ok(CommandCompletion {
                        slot_idx,
                        slots_ptr: self.slots.as_ptr() as *const CompletionSlot,
                        queue_ptr: self as *const CommandQueue,
                    });
                }
                Err(_) => {
                    if self.ensure_receiver_available().is_err() {
                        self.release_unsubmitted_slot(slot_idx);
                        return Err(());
                    }
                    self.send_backpressure_count.fetch_add(1, Ordering::Relaxed);
                    backoff.spin();
                }
            }
        }
        self.release_unsubmitted_slot(slot_idx);
        Err(())
    }

    /// Async submit (non-busy): returns a Future that waits for slot & channel space
    pub fn submit_async(&self, kind: IommuCommandKind) -> SubmitFuture {
        SubmitFuture::new(self as *const CommandQueue, kind)
    }

    /// Synchronous submit (blocking shim) preserved for compatibility
    pub fn submit_sync(&self, kind: IommuCommandKind) -> Result<(), ()> {
        if self.is_poisoned() {
            return Err(());
        }
        let comp = self.submit(kind)?;
        let rc = comp.wait_blocking();
        if rc == RESULT_OK { Ok(()) } else { Err(()) }
    }

    /// Synchronous submit with polling worker implementation to prevent deadlocks
    pub fn submit_sync_with_worker<F>(
        &self,
        kind: IommuCommandKind,
        mut handler: F,
    ) -> Result<(), ()>
    where
        F: FnMut(&IommuCommandKind) -> Result<i32, ()>,
    {
        self.ensure_receiver_available()?;
        // Allocate a slot first
        let mut backoff = Backoff::new();
        let mut slot_idx = None;
        for _attempt in 0..MAX_SUBMIT_RETRIES {
            if self.is_poisoned() {
                return Err(());
            }
            slot_idx = self.alloc_slot();
            if slot_idx.is_some() {
                break;
            }
            // If we can't allocate a slot, the queue might be full. Process to free slots.
            let _ = self.process_up_to(&mut handler, 1);
            if self.ensure_receiver_available().is_err() {
                return Err(());
            }
            backoff.snooze();
        }
        let Some(slot_idx) = slot_idx else {
            return Err(());
        };

        if self.ensure_receiver_available().is_err() {
            self.release_unsubmitted_slot(slot_idx);
            return Err(());
        }

        let cmd = IommuCommand { kind, slot_idx };

        // Wait for sender to accept (bounded). Try with small backoff and drain queue
        backoff.reset();
        let mut submitted = false;
        for _attempt in 0..MAX_SUBMIT_RETRIES {
            if self.is_poisoned() {
                self.release_unsubmitted_slot(slot_idx);
                return Err(());
            }
            match self.sender.send(cmd.clone()) {
                Ok(_) => {
                    self.recv_waiter.wake();
                    submitted = true;
                    break;
                }
                Err(_) => {
                    if self.ensure_receiver_available().is_err() {
                        self.release_unsubmitted_slot(slot_idx);
                        return Err(());
                    }
                    self.send_backpressure_count.fetch_add(1, Ordering::Relaxed);
                    // Queue full, drain it to make progress
                    let processed = self.process_up_to(&mut handler, 1);
                    if processed == 0 {
                        backoff.snooze();
                    } else {
                        backoff.reset();
                    }
                }
            }
        }
        if !submitted {
            self.release_unsubmitted_slot(slot_idx);
            return Err(());
        }

        let comp = CommandCompletion {
            slot_idx,
            slots_ptr: self.slots.as_ptr() as *const CompletionSlot,
            queue_ptr: self as *const CommandQueue,
        };

        let rc = comp.wait_sync_with_worker(self, &mut handler);
        if rc == RESULT_OK { Ok(()) } else { Err(()) }
    }

    /// Await until work arrives on the queue.
    pub async fn wait_for_work(&self) {
        poll_fn(|cx| {
            if self.is_poisoned() {
                return Poll::Ready(());
            }
            match self.with_receiver(|rx| rx.is_empty()) {
                Ok(false) => return Poll::Ready(()),
                Ok(true) => {}
                Err(()) => return Poll::Ready(()),
            }
            self.recv_waiter.register(cx.waker());
            if self.is_poisoned() {
                self.recv_waiter.clear();
                return Poll::Ready(());
            }
            match self.with_receiver(|rx| rx.is_empty()) {
                Ok(false) => {
                    self.recv_waiter.clear();
                    Poll::Ready(())
                }
                Ok(true) => Poll::Pending,
                Err(()) => {
                    self.recv_waiter.clear();
                    Poll::Ready(())
                }
            }
        })
        .await;
    }

    /// Process pending commands (single pass)
    /// Returns number of processed commands
    pub fn process_once<F>(&self, mut handler: F) -> usize
    where
        F: FnMut(&IommuCommandKind) -> Result<i32, ()>,
    {
        let mut processed = 0usize;

        // LOOP_PROOF: mode=event; reason=Processing loop exits when receiver is empty or fuel gate stops and each recv handles one command.;
        loop {
            if self.is_poisoned() {
                break;
            }
            // If fuel is active and there is no work, break early
            #[cfg(all(test, not(target_os = "none")))]
            if crate::task::fuel::Fuel::is_active() {
                match self.with_receiver(|rx| rx.is_empty()) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(()) => break,
                }
                if !crate::task::fuel::Fuel::consume(1) {
                    break;
                }
            }

            let cmd = match self.with_receiver(|rx| rx.recv()) {
                Ok(cmd) => cmd,
                Err(()) => break,
            };

            if let Some(cmd) = cmd {
                // Receiving an item freed up channel capacity; notify potential senders
                self.notify_send_available();

                // If the slot was canceled while the command was still queued, short-circuit
                let slot = &self.slots[cmd.slot_idx];
                if slot.is_canceled() {
                    // cancellation
                    self.slots[cmd.slot_idx].complete(RESULT_CANCELLED);
                    // Completed a slot -> notify slot waiters
                    self.notify_slot_available();
                    processed += 1;
                    // Metrics: cancelled command (processed)
                    self.cancelled_count.fetch_add(1, Ordering::Relaxed);
                    self.processed_count.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // handle
                let res = handler(&cmd.kind);
                let code = match res {
                    Ok(0) => RESULT_OK,
                    Ok(_) => RESULT_OK,
                    Err(_) => RESULT_HW_ERR,
                };
                // publish completion
                self.slots[cmd.slot_idx].complete(code);
                // Completed a slot -> notify slot waiters
                self.notify_slot_available();
                processed += 1;
                // Metrics: processed
                self.processed_count.fetch_add(1, Ordering::Relaxed);
            } else {
                break;
            }
        }

        processed
    }

    /// Process up to `max` commands; useful for bounded per-loop processing
    pub fn process_up_to<F>(&self, mut handler: F, max: usize) -> usize
    where
        F: FnMut(&IommuCommandKind) -> Result<i32, ()>,
    {
        let mut processed = 0usize;

        // LOOP_PROOF: mode=condition; reason=Loop is explicitly bounded by max and also exits early when receiver is empty or fuel is exhausted.;
        while processed < max {
            if self.is_poisoned() {
                break;
            }
            // If fuel is active and there is no work, break early.
            #[cfg(all(test, not(target_os = "none")))]
            if crate::task::fuel::Fuel::is_active() {
                match self.with_receiver(|rx| rx.is_empty()) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(()) => break,
                }
                if !crate::task::fuel::Fuel::consume(1) {
                    break;
                }
            }

            let cmd = match self.with_receiver(|rx| rx.recv()) {
                Ok(cmd) => cmd,
                Err(()) => break,
            };

            if let Some(cmd) = cmd {
                // Receiving an item freed up channel capacity; notify potential senders
                self.notify_send_available();
                // If the slot was canceled while queued, short-circuit
                let slot = &self.slots[cmd.slot_idx];
                if slot.is_canceled() {
                    self.slots[cmd.slot_idx].complete(RESULT_CANCELLED);
                    // Completed a slot -> notify slot waiters
                    self.notify_slot_available();
                    processed += 1;
                    continue;
                }

                let res = handler(&cmd.kind);
                let code = match res {
                    Ok(0) => RESULT_OK,
                    Ok(_) => RESULT_OK,
                    Err(_) => RESULT_HW_ERR,
                };
                self.slots[cmd.slot_idx].complete(code);
                // Completed a slot -> notify slot waiters
                self.notify_slot_available();
                processed += 1;
            } else {
                break;
            }
        }

        processed
    }

    /// Diagnostics: total number of processed commands
    pub fn processed_total(&self) -> usize {
        self.processed_count.load(Ordering::Relaxed)
    }

    /// Diagnostics: total number of cancelled commands (completed by worker)
    pub fn cancelled_total(&self) -> usize {
        self.cancelled_count.load(Ordering::Relaxed)
    }

    /// Diagnostics: total number of cancel attempts (calls to cancel()/drops)
    pub fn cancel_attempts_total(&self) -> usize {
        self.cancel_attempts.load(Ordering::Relaxed)
    }

    /// Diagnostics: total number of reclaimed slots
    pub fn reclaimed_total(&self) -> usize {
        self.reclaimed_count.load(Ordering::Relaxed)
    }

    /// Diagnostics: total send backpressure events observed
    pub fn send_backpressure_total(&self) -> usize {
        self.send_backpressure_count.load(Ordering::Relaxed)
    }
}

// Future returned by `submit_async()`
pub struct SubmitFuture {
    queue_ptr: *const CommandQueue,
    kind: Option<IommuCommandKind>,
    slot_idx: Option<usize>,
}

impl SubmitFuture {
    fn new(queue_ptr: *const CommandQueue, kind: IommuCommandKind) -> Self {
        Self {
            queue_ptr,
            kind: Some(kind),
            slot_idx: None,
        }
    }
}

impl core::future::Future for SubmitFuture {
    type Output = Result<CommandCompletion, ()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let q = unsafe { &*this.queue_ptr };

        if q.ensure_receiver_available().is_err() {
            q.release_future_slot(this.slot_idx.take());
            this.kind = None;
            return Poll::Ready(Err(()));
        }

        // Try to acquire a slot if we don't have one
        if this.slot_idx.is_none() {
            if let Some(idx) = q.try_alloc_slot() {
                this.slot_idx = Some(idx);
            } else {
                q.slot_waiter.register(cx.waker());
                if q.is_poisoned() {
                    q.slot_waiter.clear();
                    this.kind = None;
                    return Poll::Ready(Err(()));
                }
                if let Some(idx) = q.try_alloc_slot() {
                    q.slot_waiter.clear();
                    this.slot_idx = Some(idx);
                } else {
                    return Poll::Pending;
                }
            }
        }

        let idx = this.slot_idx.expect("slot acquired");
        let cmd = IommuCommand {
            kind: this.kind.as_ref().unwrap().clone(),
            slot_idx: idx,
        };

        // Try non-busy send
        match q.sender.send(cmd.clone()) {
            Ok(_) => {
                q.recv_waiter.wake();
                this.kind = None;
                let comp = CommandCompletion {
                    slot_idx: idx,
                    slots_ptr: q.slots.as_ptr() as *const CompletionSlot,
                    queue_ptr: this.queue_ptr,
                };
                Poll::Ready(Ok(comp))
            }
            Err(_) => {
                if q.ensure_receiver_available().is_err() {
                    q.send_waiter.clear();
                    q.release_future_slot(this.slot_idx.take());
                    this.kind = None;
                    return Poll::Ready(Err(()));
                }
                // Count backpressure events for diagnostics
                q.send_backpressure_count.fetch_add(1, Ordering::Relaxed);
                q.send_waiter.register(cx.waker());
                if q.is_poisoned() {
                    q.send_waiter.clear();
                    q.release_future_slot(this.slot_idx.take());
                    this.kind = None;
                    return Poll::Ready(Err(()));
                }
                if q.sender.send(cmd).is_ok() {
                    q.recv_waiter.wake();
                    q.send_waiter.clear();
                    this.kind = None;
                    let comp = CommandCompletion {
                        slot_idx: idx,
                        slots_ptr: q.slots.as_ptr() as *const CompletionSlot,
                        queue_ptr: this.queue_ptr,
                    };
                    Poll::Ready(Ok(comp))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl Drop for SubmitFuture {
    fn drop(&mut self) {
        if self.kind.is_none() {
            return;
        }
        let q = unsafe { &*self.queue_ptr };
        q.release_future_slot(self.slot_idx.take());
    }
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_reclaim_completed_slot() -> bool {
    let q = Box::leak(Box::new(CommandQueue::new()));

    let comp1 = q
        .submit(IommuCommandKind::InvalidateIotlbDomain { domain: 1 })
        .expect("submit");
    let idx = comp1.slot_idx;
    drop(comp1);

    q.slots[idx].complete(RESULT_OK);

    let submit2 = q.submit(IommuCommandKind::InvalidateIotlbDomain { domain: 2 });
    submit2.is_ok() && q.reclaimed_total() > 0
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_cancel_queued_command() -> bool {
    let q = Box::leak(Box::new(CommandQueue::new()));

    let comp = q
        .submit(IommuCommandKind::InvalidateIotlbDomain { domain: 3 })
        .expect("submit");
    if !comp.cancel() {
        return false;
    }

    let processed = q.process_once(|_k| Ok(0));
    if processed != 1 {
        return false;
    }

    let rc = crate::task::block_on(async { comp.await });
    rc == RESULT_CANCELLED
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_drop_triggers_cancel() -> bool {
    let q = Box::leak(Box::new(CommandQueue::new()));

    let comp = q
        .submit(IommuCommandKind::InvalidateIotlbDomain { domain: 4 })
        .expect("submit");
    let idx = comp.slot_idx;
    drop(comp);

    let processed = q.process_once(|_k| Ok(0));
    if processed != 1 {
        return false;
    }

    let rc = q.slots[idx].wait_result_spin();
    rc == RESULT_CANCELLED
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_process_up_to_respects_fuel() -> bool {
    let q = Box::leak(Box::new(CommandQueue::new()));

    let mut comps: Vec<CommandCompletion> = Vec::new();
    for i in 0..5 {
        comps.push(
            q.submit(IommuCommandKind::InvalidateIotlbDomain { domain: i as u16 })
                .expect("submit"),
        );
    }

    // process_up_to() always enforces `max`; fuel gating is compiled only in #[cfg(test)] paths.
    let first = q.process_up_to(|_k| Ok(0), 2);
    let second = q.process_up_to(|_k| Ok(0), 2);
    let third = q.process_up_to(|_k| Ok(0), 2);
    let _ = comps;
    first == 2 && second == 2 && third == 1
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_fuel_shim_basic() -> bool {
    crate::task::fuel::Fuel::refill(2);
    if !crate::task::fuel::Fuel::is_active() {
        return false;
    }
    if crate::task::fuel::Fuel::remaining() != 2 {
        return false;
    }
    if !crate::task::fuel::Fuel::consume(1) {
        return false;
    }
    if crate::task::fuel::Fuel::remaining() != 1 {
        return false;
    }
    if !crate::task::fuel::Fuel::consume(1) {
        return false;
    }
    if crate::task::fuel::Fuel::remaining() != 0 {
        return false;
    }
    !crate::task::fuel::Fuel::consume(1)
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_metrics_counts() -> bool {
    let q = Box::leak(Box::new(CommandQueue::new()));
    if q.processed_total() != 0 || q.cancelled_total() != 0 || q.cancel_attempts_total() != 0 {
        return false;
    }

    let comp = q
        .submit(IommuCommandKind::InvalidateIotlbDomain { domain: 1 })
        .expect("submit");
    if !comp.cancel() {
        return false;
    }
    if q.cancel_attempts_total() < 1 {
        return false;
    }

    let processed = q.process_once(|_k| Ok(0));
    processed == 1 && q.cancelled_total() >= 1 && q.processed_total() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::boxed::Box;

    #[cfg(feature = "std")]
    fn poison_receiver_lock(q: &CommandQueue) {
        crate::sync::set_panicking(true);
        {
            let _guard = q.receiver.lock().unwrap();
        }
        crate::sync::set_panicking(false);
        assert!(q.receiver.is_poisoned());
    }

    #[cfg(feature = "std")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_cmd_queue_basic() {
        // Leak the queue to get a 'static reference for thread spawn in tests
        let q = Box::leak(Box::new(CommandQueue::new()));

        // Worker thread: act as executor and process commands
        let worker_q: &'static CommandQueue = &*q;
        let worker = std::thread::spawn(move || {
            let mut attempts = 0;
            loop {
                let processed = worker_q.process_once(|_k| Ok(0));
                if processed > 0 {
                    break;
                }
                attempts += 1;
                if attempts > 1000 {
                    panic!("CQ worker timed out");
                }
                std::thread::yield_now();
            }
        });

        // Submit a simple command and wait for completion
        let kind = IommuCommandKind::InvalidateIotlbDomain { domain: 1 };
        let res = q.submit_sync(kind);
        assert!(res.is_ok());

        worker.join().expect("worker join failed");
    }

    #[cfg(feature = "std")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_cmd_queue_map_unmap() {
        // Leak the queue to get a 'static reference for thread spawn in tests
        let q = Box::leak(Box::new(CommandQueue::new()));

        // Worker thread: process incoming commands and validate content
        let worker_q: &'static CommandQueue = &*q;
        let worker = std::thread::spawn(move || {
            let mut map_seen = false;
            let mut unmap_seen = false;
            let mut attempts = 0;
            while !(map_seen && unmap_seen) {
                let _ = worker_q.process_once(|k| match k {
                    IommuCommandKind::MapRegion {
                        domain,
                        iova,
                        phys,
                        size,
                        read,
                        write,
                    } => {
                        assert_eq!(*domain, 1);
                        assert_eq!(*iova, 0x1000);
                        assert_eq!(*phys, 0x2000);
                        assert_eq!(*size, 0x1000);
                        assert!(*read && *write);
                        map_seen = true;
                        Ok(0)
                    }
                    IommuCommandKind::UnmapRegion { domain, iova, size } => {
                        assert_eq!(*domain, 1);
                        assert_eq!(*iova, 0x1000);
                        assert_eq!(*size, 0x1000);
                        unmap_seen = true;
                        Ok(0)
                    }
                    _ => Err(()),
                });

                attempts += 1;
                if attempts > 2000 {
                    panic!("CQ worker timed out");
                }
                std::thread::yield_now();
            }
        });

        // Submit MapRegion command (blocking until processed)
        let map_cmd = IommuCommandKind::MapRegion {
            domain: 1,
            iova: 0x1000,
            phys: 0x2000,
            size: 0x1000,
            read: true,
            write: true,
        };

        assert!(q.submit_sync(map_cmd).is_ok());

        // Submit UnmapRegion command
        let unmap_cmd = IommuCommandKind::UnmapRegion {
            domain: 1,
            iova: 0x1000,
            size: 0x1000,
        };
        assert!(q.submit_sync(unmap_cmd).is_ok());

        worker.join().expect("worker join failed");
    }

    // Ensure `CommandCompletion` works as a Future (wakes properly)
    #[cfg(feature = "std")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_cmd_completion_future() {
        let q = Box::leak(Box::new(CommandQueue::new()));
        let worker_q: &'static CommandQueue = &*q;

        let worker = std::thread::spawn(move || {
            let mut attempts = 0;
            // LOOP_PROOF: mode=event; reason=Test worker exits after first processed command or panics via attempts timeout guard.;
            loop {
                let processed = worker_q.process_once(|k| match k {
                    IommuCommandKind::InvalidateIotlbDomain { domain } => {
                        assert_eq!(*domain, 42);
                        Ok(0)
                    }
                    _ => Err(()),
                });
                if processed > 0 {
                    break;
                }
                attempts += 1;
                if attempts > 1000 {
                    panic!("CQ worker timed out");
                }
                std::thread::yield_now();
            }
        });

        let kind = IommuCommandKind::InvalidateIotlbDomain { domain: 42 };
        let comp = q.submit(kind).expect("submit");
        let rc = crate::task::block_on(async { comp.await });
        assert_eq!(rc, 0);

        worker.join().expect("worker join failed");
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_new_with_numa_allocates_slots() {
        // Ensure we can allocate CommandQueue with a NUMA hint and slots are initialized
        let q = CommandQueue::new_with_numa(Some(0));
        assert_eq!(q.slots.len(), DEFAULT_QUEUE_SIZE);
        // try to acquire a slot and ensure completion works
        assert!(q.slots[0].try_acquire());
        q.slots[0].complete(RESULT_OK);
        let rc = q.slots[0].wait_result_spin();
        assert_eq!(rc, RESULT_OK);
        // sanity check
        assert_eq!(q.numa_node, Some(0));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_wait_result_spin_times_out_for_never_completed_slot() {
        let slot = CompletionSlot::new();
        assert!(slot.try_acquire());
        assert_eq!(slot.wait_result_spin(), RESULT_TIMEOUT);
        assert_eq!(slot.state.load(Ordering::Acquire), 1);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_submit_releases_slot_when_channel_remains_full() {
        let q = CommandQueue::new();

        for idx in 0..(q.slots.len() - 1) {
            assert!(q.slots[idx].try_acquire());
        }

        for domain in 0..bounded_channel_capacity() {
            q.sender
                .send(IommuCommand {
                    kind: IommuCommandKind::InvalidateIotlbDomain {
                        domain: domain as u16,
                    },
                    slot_idx: 0,
                })
                .expect("fill channel");
        }

        assert!(
            q.submit(IommuCommandKind::InvalidateIotlbDomain { domain: 0xdead })
                .is_err()
        );
        assert!(q.try_alloc_slot().is_some());
    }

    #[cfg(feature = "std")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_submit_detects_receiver_poison() {
        let q = CommandQueue::new();
        poison_receiver_lock(&q);

        assert!(
            q.submit(IommuCommandKind::InvalidateIotlbDomain { domain: 0xbeef })
                .is_err()
        );
        assert!(q.is_poisoned());
    }

    #[cfg(feature = "std")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_submit_async_detects_receiver_poison() {
        let q = CommandQueue::new();
        poison_receiver_lock(&q);

        let rc = crate::task::block_on(async {
            q.submit_async(IommuCommandKind::InvalidateIotlbDomain { domain: 0xcafe })
                .await
        });

        assert!(rc.is_err());
        assert!(q.is_poisoned());
    }

    #[cfg(feature = "std")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_wait_for_work_returns_when_queue_poisoned() {
        let q = CommandQueue::new();

        std::thread::scope(|scope| {
            let worker_q = &q;
            let worker = scope.spawn(move || {
                crate::task::block_on(async {
                    worker_q.wait_for_work().await;
                });
            });

            std::thread::yield_now();
            q.poison();

            worker.join().expect("wait_for_work join failed");
        });
        assert!(q.is_poisoned());
    }

    #[cfg(feature = "std")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_submit_async_basic() {
        let q = Box::leak(Box::new(CommandQueue::new()));
        let worker_q: &'static CommandQueue = &*q;

        let worker = std::thread::spawn(move || {
            let mut attempts = 0;
            loop {
                let processed = worker_q.process_once(|k| match k {
                    IommuCommandKind::InvalidateIotlbDomain { domain } => {
                        assert_eq!(*domain, 7);
                        Ok(0)
                    }
                    _ => Err(()),
                });
                if processed > 0 {
                    break;
                }
                attempts += 1;
                if attempts > 1000 {
                    panic!("CQ worker timed out");
                }
                std::thread::yield_now();
            }
        });

        let rc = crate::task::block_on(async {
            let rc = {
                let comp = q
                    .submit_async(IommuCommandKind::InvalidateIotlbDomain { domain: 7 })
                    .await
                    .expect("submit_async");
                comp.await
            };
            rc
        });
        assert_eq!(rc, 0);

        worker.join().expect("worker join failed");
    }
}
