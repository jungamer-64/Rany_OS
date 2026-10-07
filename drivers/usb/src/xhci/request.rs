//! Each hardware submission owns one completion receipt. Cancellation retires
//! only the observer; the controller retains the request and its DMA until a
//! validated completion or stop. Reusing a ring address cannot reuse a receipt.

#![forbid(unsafe_code)]

use super::controller::XhciController;
use crate::{UsbError, UsbResult};
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use exorust_sync::{Mutex, WakerSlot};
use kernel_api::service::time::{SleepFuture, sleep_ms, try_instance};

enum ReceiptState<T> {
    Waiting,
    Completed(UsbResult<T>),
    Consumed,
}

pub(super) struct Receipt<T> {
    state: Mutex<ReceiptState<T>>,
    waker: WakerSlot,
}

impl<T> Receipt<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ReceiptState::Waiting),
            waker: WakerSlot::new(),
        })
    }

    /// Caller dispatches the wake after releasing all device-state locks.
    pub fn complete(&self, result: UsbResult<T>) {
        let mut state = self.state.lock();
        assert!(
            matches!(*state, ReceiptState::Waiting),
            "a hardware receipt completes only once"
        );
        *state = ReceiptState::Completed(result);
    }

    pub fn notify(&self) {
        self.waker.wake();
    }

    fn take(&self) -> Option<UsbResult<T>> {
        let mut state = self.state.lock();
        if matches!(*state, ReceiptState::Completed(_)) {
            let ReceiptState::Completed(result) =
                core::mem::replace(&mut *state, ReceiptState::Consumed)
            else {
                unreachable!("completed state checked under the same exclusive guard")
            };
            Some(result)
        } else {
            None
        }
    }
}

pub(super) struct RequestFuture<'controller, T> {
    controller: &'controller XhciController,
    receipt: Arc<Receipt<T>>,
    pulse: Option<SleepFuture>,
    deadline: Option<u64>,
}

impl<'controller, T> RequestFuture<'controller, T> {
    pub fn new(controller: &'controller XhciController, receipt: Arc<Receipt<T>>) -> Self {
        let deadline = try_instance().map(|time| time.current_tick_ms().saturating_add(1000));
        let pulse = deadline.map(|_| sleep_ms(1));
        Self {
            controller,
            receipt,
            pulse,
            deadline,
        }
    }
}

impl<T> Future for RequestFuture<'_, T> {
    type Output = UsbResult<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.receipt.waker.register(cx.waker());
        if let Err(error) = this.controller.process_events() {
            return Poll::Ready(Err(error));
        }
        if let Some(result) = this.receipt.take() {
            return Poll::Ready(result);
        }
        if let Some(deadline) = this.deadline
            && try_instance().is_some_and(|time| time.current_tick_ms() >= deadline)
        {
            return Poll::Ready(Err(UsbError::Timeout));
        }
        // A regular task timer supplies bounded polling if a device suppresses
        // interrupts. Standalone IRQ-only providers use the same receipt path.
        if let Some(pulse) = &mut this.pulse {
            match Pin::new(pulse).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(cause)) => return Poll::Ready(Err(UsbError::Timer(cause))),
                Poll::Ready(Ok(())) => {
                    this.pulse = Some(sleep_ms(1));
                    if let Some(pulse) = &mut this.pulse {
                        match Pin::new(pulse).poll(cx) {
                            Poll::Ready(Err(cause)) => {
                                return Poll::Ready(Err(UsbError::Timer(cause)));
                            }
                            Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
                            Poll::Pending => {}
                        }
                    }
                }
            }
        }
        Poll::Pending
    }
}

impl<T> Drop for RequestFuture<'_, T> {
    fn drop(&mut self) {
        self.receipt.waker.clear();
    }
}
