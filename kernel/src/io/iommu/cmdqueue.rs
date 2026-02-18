// ============================================================================
// kernel/src/io/iommu/cmdqueue.rs
// ============================================================================
//!
// Command Queue for IOMMU - initial implementation
// - Per-controller MPSC queue using existing BoundedChannel
// - Preallocated completion slots (no per-command heap allocations)
// - submit_sync() API that blocks by using backoff spin until completion
// - process_once() worker to be called periodically by the Executor

use crate::sync::atomic_waker::AtomicWaker;
use crate::sync::lockfree::Backoff;
use crate::sync::lockfree::BoundedChannel;
use crate::sync::lockfree::BoundedReceiver;
use crate::sync::lockfree::BoundedSender;
use crate::sync::lockfree::DEFAULT_QUEUE_SIZE;
use core::future::poll_fn;
use core::pin::Pin;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};
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

// Result codes
const RESULT_OK: i32 = 0;
const RESULT_HW_ERR: i32 = -1;
const RESULT_CANCELLED: i32 = -2;

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
    pub fn wait_result_spin(&self) -> i32 {
        let mut backoff = Backoff::new();
        loop {
            if self.state.load(Ordering::Acquire) == 2 {
                let r = self.result.load(Ordering::Acquire);
                // free slot
                self.result.store(0, Ordering::Release);
                self.canceled.store(0, Ordering::Release);
                self.state.store(0, Ordering::Release);
                return r;
            }
            backoff.spin();
        }
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

/// Completion object returned for a submitted command. Implements `Future` so callers
/// on async executors can `await` completion. Also provides `wait_blocking()` for
/// synchronous callers (legacy tests / blocking callers).
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
        loop {
            if slot.state.load(Ordering::Acquire) == 2 {
                let r = slot.result.load(Ordering::Acquire);
                // reset slot state/result and return
                slot.result.store(0, Ordering::Release);
                slot.canceled.store(0, Ordering::Release);
                slot.state.store(0, Ordering::Release);
                // Notify tasks waiting for slots
                let q = unsafe { &*self.queue_ptr };
                q.notify_slot_available();
                return r;
            }
            backoff.spin();
        }
    }

    /// Attempt to cancel a queued (not yet processed) command. Returns true if the
    /// cancellation flag was set successfully. This does not guarantee the command
    /// won't be processed if the worker already pulled it - cancellation is best-effort.
    pub fn cancel(&self) -> bool {
        let q = unsafe { &*self.queue_ptr };
        // record an attempt to cancel
        q.cancel_attempts.fetch_add(1, Ordering::Relaxed);
        let slot = unsafe { &*self.slots_ptr.add(self.slot_idx) };
        // Don't update `cancelled_count` here; the worker will account for effective cancellations
        slot.cancel()
    }
}

impl Drop for CommandCompletion {
    fn drop(&mut self) {
        // Best-effort cancel when the completion object is dropped
        let q = unsafe { &*self.queue_ptr };
        // record an attempt
        q.cancel_attempts.fetch_add(1, Ordering::Relaxed);
        // best-effort cancel; worker will count successful cancellations
        let _ = unsafe { &*self.slots_ptr.add(self.slot_idx) }.cancel();
    }
}
impl core::future::Future for CommandCompletion {
    type Output = i32;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let slot = unsafe { &*self.slots_ptr.add(self.slot_idx) };
        if slot.state.load(Ordering::Acquire) == 2 {
            let r = slot.result.load(Ordering::Acquire);
            // clear canceled flag and free slot
            slot.canceled.store(0, Ordering::Release);
            slot.result.store(0, Ordering::Release);
            slot.state.store(0, Ordering::Release);
            // Notify tasks waiting for slots
            let q = unsafe { &*self.queue_ptr };
            q.notify_slot_available();
            Poll::Ready(r)
        } else {
            slot.waker.register(cx.waker());
            if slot.state.load(Ordering::Acquire) == 2 {
                let r = slot.result.load(Ordering::Acquire);
                // clear canceled flag and free slot
                slot.canceled.store(0, Ordering::Release);
                slot.result.store(0, Ordering::Release);
                slot.state.store(0, Ordering::Release);
                // Notify tasks waiting for slots
                let q = unsafe { &*self.queue_ptr };
                q.notify_slot_available();
                Poll::Ready(r)
            } else {
                Poll::Pending
            }
        }
    }
}

/// CommandQueue holds sender/receiver and completion slots
pub struct CommandQueue {
    sender: BoundedSender<IommuCommand, DEFAULT_QUEUE_SIZE>,
    receiver: BoundedReceiver<IommuCommand, DEFAULT_QUEUE_SIZE>,
    slots: &'static [CompletionSlot],
    next_alloc: AtomicUsize,
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

impl CommandQueue {
    pub fn new_with_numa(numa_node: Option<usize>) -> Self {
        let (s, r) = BoundedChannel::<IommuCommand, DEFAULT_QUEUE_SIZE>::new();

        // Try to allocate slots on the given NUMA node for locality benefits.
        let layout = Layout::array::<CompletionSlot>(DEFAULT_QUEUE_SIZE).expect("layout");
        let slots: &'static [CompletionSlot] =
            if let Some(nonnull) = crate::mm::numa::allocate_zeroed_on_node(layout, numa_node) {
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
            receiver: r,
            slots,
            next_alloc: AtomicUsize::new(0),
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

    /// Allocate a free slot index or return None if none available now
    fn alloc_slot(&self) -> Option<usize> {
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
        for i in 0..n {
            let idx = (start + i) % n;
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

    /// Non-blocking submit: returns a `CommandCompletion` which implements `Future`
    /// Use `await` on async executors or `wait_blocking()` for tests/legacy callers.
    pub fn submit(&self, kind: IommuCommandKind) -> Result<CommandCompletion, ()> {
        let slot_idx = match self.alloc_slot() {
            Some(i) => i,
            None => {
                return Err(());
            }
        };

        let cmd = IommuCommand { kind, slot_idx };

        // Wait for sender to accept (bounded). Try with small backoff
        let mut backoff = Backoff::new();
        loop {
            match self.sender.send(cmd.clone()) {
                Ok(_) => {
                    self.recv_waiter.wake();
                    break;
                }
                Err(_) => {
                    backoff.spin();
                }
            }
        }

        Ok(CommandCompletion {
            slot_idx,
            slots_ptr: self.slots.as_ptr() as *const CompletionSlot,
            queue_ptr: self as *const CommandQueue,
        })
    }

    /// Async submit (non-busy): returns a Future that waits for slot & channel space
    pub fn submit_async(&self, kind: IommuCommandKind) -> SubmitFuture {
        SubmitFuture::new(self as *const CommandQueue, kind)
    }

    /// Synchronous submit (blocking shim) preserved for compatibility
    pub fn submit_sync(&self, kind: IommuCommandKind) -> Result<(), ()> {
        let comp = self.submit(kind)?;
        let rc = comp.wait_blocking();
        if rc == RESULT_OK { Ok(()) } else { Err(()) }
    }

    /// Await until work arrives on the queue.
    pub async fn wait_for_work(&self) {
        poll_fn(|cx| {
            if !self.receiver.is_empty() {
                return Poll::Ready(());
            }
            self.recv_waiter.register(cx.waker());
            if !self.receiver.is_empty() {
                return Poll::Ready(());
            }
            Poll::Pending
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

        loop {
            // If fuel is active and there is no work, break early
            #[cfg(all(test, not(target_os = "none")))]
            if crate::task::fuel::Fuel::is_active() {
                if self.receiver.is_empty() {
                    break;
                }
                if !crate::task::fuel::Fuel::consume(1) {
                    break;
                }
            }

            if let Some(cmd) = self.receiver.recv() {
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

        while processed < max {
            // If fuel is active and there is no work, break early. If fuel is active and depleted,
            // consume will return false and we'll break before popping an item (avoids losing it).
            #[cfg(all(test, not(target_os = "none")))]
            if crate::task::fuel::Fuel::is_active() {
                if self.receiver.is_empty() {
                    break;
                }
                if !crate::task::fuel::Fuel::consume(1) {
                    break;
                }
            }

            if let Some(cmd) = self.receiver.recv() {
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

        // Try to acquire a slot if we don't have one
        if this.slot_idx.is_none() {
            if let Some(idx) = q.try_alloc_slot() {
                this.slot_idx = Some(idx);
            } else {
                q.slot_waiter.register(cx.waker());
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
                // Count backpressure events for diagnostics
                q.send_backpressure_count.fetch_add(1, Ordering::Relaxed);
                q.send_waiter.register(cx.waker());
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
    use alloc::vec::Vec;

    #[cfg(feature = "std")]
    #[test_case]
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
    #[test_case]
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
    #[test_case]
    fn test_cmd_completion_future() {
        let q = Box::leak(Box::new(CommandQueue::new()));
        let worker_q: &'static CommandQueue = &*q;

        let worker = std::thread::spawn(move || {
            let mut attempts = 0;
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

    // NOTE: Excluded from custom test framework (was #[ignore]). Run manually if needed.
    #[cfg(feature = "std")]
    fn test_cq_stress_multi_threaded() {
        use alloc::sync::Arc as AllocArc;
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        const PRODUCERS: usize = 4;
        const PER_PRODUCER: usize = 100;
        const TOTAL: usize = PRODUCERS * PER_PRODUCER;

        let q = Box::leak(Box::new(CommandQueue::new()));
        let processed = AllocArc::new(AtomicUsize::new(0));

        // Worker: process commands until TOTAL processed
        let processed_w = processed.clone();
        let q_worker: &'static CommandQueue = q;
        let worker = thread::spawn(move || {
            while processed_w.load(Ordering::Relaxed) < TOTAL {
                let n = q_worker.process_once(|_k| Ok(0));
                if n > 0 {
                    processed_w.fetch_add(n, Ordering::Relaxed);
                } else {
                    std::thread::yield_now();
                }
            }
        });

        // Producers
        let mut producers = Vec::new();
        for p in 0..PRODUCERS {
            let qref: &'static CommandQueue = q;
            let handle = thread::spawn(move || {
                for i in 0..PER_PRODUCER {
                    let comp = qref
                        .submit(IommuCommandKind::InvalidateIotlbDomain { domain: (p as u16) })
                        .expect("submit");
                    // Deterministic: drop some completions, keep others
                    if (p + i) % 3 == 0 {
                        drop(comp);
                    } else {
                        // Wait for completion
                        let _ = crate::task::block_on(async { comp.await });
                    }
                }
            });
            producers.push(handle);
        }

        for h in producers {
            h.join().expect("producer join");
        }
        worker.join().expect("worker join");

        // After all work, we should be able to submit again (slots reclaimed)
        assert!(
            q.submit(IommuCommandKind::InvalidateIotlbDomain { domain: 99 })
                .is_ok()
        );
    }

    #[test_case]
    fn test_new_with_numa_allocates_slots() {
        // Ensure we can allocate CommandQueue with a NUMA hint and slots are initialized
        let q = Box::leak(Box::new(CommandQueue::new_with_numa(Some(0))));
        assert_eq!(q.slots.len(), DEFAULT_QUEUE_SIZE);
        // try to acquire a slot and ensure completion works
        assert!(q.slots[0].try_acquire());
        q.slots[0].complete(RESULT_OK);
        let rc = q.slots[0].wait_result_spin();
        assert_eq!(rc, RESULT_OK);
        // sanity check
        assert_eq!(q.numa_node, Some(0));
    }

    #[cfg(feature = "std")]
    #[test_case]
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

    #[cfg(feature = "std")]
    #[test_case]
    fn test_submit_async_backpressure() {
        // Fill the channel completely by allocating slots and pushing directly
        let q = Box::leak(Box::new(CommandQueue::new()));
        // Fill until sender reports full or we can't allocate further slots
        while !q.sender.is_full() {
            if let Some(idx) = q.try_alloc_slot() {
                let cmd = IommuCommand {
                    kind: IommuCommandKind::InvalidateIotlbDomain { domain: 1 },
                    slot_idx: idx,
                };
                let _ = q.sender.send(cmd);
            } else {
                break;
            }
        }

        // Now start an async submit which should pend until we process at least one entry
        use alloc::sync::Arc as AllocArc;
        use core::sync::atomic::{AtomicBool, Ordering};
        let done = AllocArc::new(AtomicBool::new(false));
        let done_cloned = done.clone();
        let qref: &'static CommandQueue = q;
        let handle = std::thread::spawn(move || {
            let rc = crate::task::block_on(async {
                let comp = qref
                    .submit_async(IommuCommandKind::InvalidateIotlbDomain { domain: 99 })
                    .await
                    .expect("submit_async");
                comp.await
            });
            // mark done and return
            done_cloned.store(true, Ordering::SeqCst);
            rc
        });

        // Wait until the submit future registers as waiting for a slot or send availability
        while !q.slot_waiter.has_waker() && !q.send_waiter.has_waker() {
            std::thread::yield_now();
        }
        // Inspect queue state before processing one item
        // Process one item to free space and complete a slot (bounded)
        let processed1 = q.process_up_to(|_k| Ok(0), 1);
        assert!(processed1 >= 1);

        // Drain remaining items (best-effort)
        let _processed2 = q.process_up_to(|_k| Ok(0), DEFAULT_QUEUE_SIZE);

        // Process until the spawned submit thread completes (it will set `done`)
        let mut iter = 0;
        while !done.load(Ordering::SeqCst) && iter < 10000 {
            let n = q.process_up_to(|_k| Ok(0), 8);
            if n == 0 {
                std::thread::yield_now();
            }
            iter += 1;
        }
        assert!(
            done.load(Ordering::SeqCst),
            "submit thread did not complete in time"
        );

        let rc = handle.join().expect("submit join");
        assert_eq!(rc, 0);

        // ensure we saw at least one backpressure event during the test
        assert!(q.send_backpressure_total() > 0);
    }
}
