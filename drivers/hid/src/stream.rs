use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::{KeyEvent, Keymap, Modifiers};

/// Driver-side minimal API required by the stream/future helpers.
///
/// The kernel-side `KeyboardDriver` implements this trait so the
/// stream/futures can be implemented in the `hid_driver` crate without
/// depending on kernel internals.
pub trait DriverOps: Sync {
    fn poll_key_event_internal(&self) -> Option<KeyEvent>;
    fn register_waker(&self, waker: &Waker);
    fn process_pending_wake(&self) -> bool;
    fn has_event(&self) -> bool;
    fn get_modifiers(&self) -> Modifiers;
    fn return_stream(&self);
}

/// キーボード入力ストリーム (所有権ベース SPSC consumer)
pub struct KeyboardStream {
    driver: &'static dyn DriverOps,
    keymap: &'static dyn Keymap,
}

impl KeyboardStream {
    /// Kernel側から利用するためのコンストラクタ
    pub fn new(driver: &'static dyn DriverOps, keymap: &'static dyn Keymap) -> Self {
        Self { driver, keymap }
    }

    pub fn read_key(&mut self) -> KeyEventFuture {
        KeyEventFuture {
            driver: self.driver,
        }
    }

    pub fn read_char(&mut self) -> CharFuture {
        CharFuture {
            driver: self.driver,
            keymap: self.keymap,
            budget: DEFAULT_POLL_BUDGET,
        }
    }

    pub fn read_char_with_budget(&mut self, budget: usize) -> CharFuture {
        CharFuture {
            driver: self.driver,
            keymap: self.keymap,
            budget,
        }
    }

    pub fn poll(&mut self) -> Option<KeyEvent> {
        self.driver.poll_key_event_internal()
    }

    pub fn has_event(&self) -> bool {
        self.driver.has_event()
    }

    pub fn modifiers(&self) -> Modifiers {
        self.driver.get_modifiers()
    }

    pub fn keymap(&self) -> &'static dyn Keymap {
        self.keymap
    }
}

impl Drop for KeyboardStream {
    fn drop(&mut self) {
        self.driver.return_stream();
    }
}

/// Arc-based variant that owns an Arc<dyn Keymap>
pub struct KeyboardStreamArc {
    driver: &'static dyn DriverOps,
    keymap: Arc<dyn Keymap>,
}

impl KeyboardStreamArc {
    pub fn new(driver: &'static dyn DriverOps, keymap: Arc<dyn Keymap>) -> Self {
        Self { driver, keymap }
    }

    pub fn read_key(&mut self) -> KeyEventFuture {
        KeyEventFuture {
            driver: self.driver,
        }
    }

    pub fn read_char(&mut self) -> CharFutureArc<'_> {
        CharFutureArc {
            driver: self.driver,
            keymap: &self.keymap,
        }
    }

    pub fn poll(&mut self) -> Option<KeyEvent> {
        self.driver.poll_key_event_internal()
    }

    pub fn has_event(&self) -> bool {
        self.driver.has_event()
    }

    pub fn modifiers(&self) -> Modifiers {
        self.driver.get_modifiers()
    }

    pub fn keymap(&self) -> Arc<dyn Keymap> {
        Arc::clone(&self.keymap)
    }

    pub fn keymap_ref(&self) -> &dyn Keymap {
        &*self.keymap
    }

    pub fn set_keymap(&mut self, keymap: Arc<dyn Keymap>) {
        self.keymap = keymap;
    }
}

impl Drop for KeyboardStreamArc {
    fn drop(&mut self) {
        self.driver.return_stream();
    }
}

/// Future that yields the next KeyEvent
pub struct KeyEventFuture {
    driver: &'static dyn DriverOps,
}

impl Future for KeyEventFuture {
    type Output = KeyEvent;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Process pending wake notifications
        self.driver.process_pending_wake();

        if let Some(event) = self.driver.poll_key_event_internal() {
            Poll::Ready(event)
        } else {
            self.driver.register_waker(cx.waker());
            if let Some(event) = self.driver.poll_key_event_internal() {
                Poll::Ready(event)
            } else {
                Poll::Pending
            }
        }
    }
}

/// Default poll budget for CharFuture
pub const DEFAULT_POLL_BUDGET: usize = 16;

/// Future that yields the next character (skips released/convertible-only keys)
pub struct CharFuture {
    driver: &'static dyn DriverOps,
    keymap: &'static dyn Keymap,
    budget: usize,
}

impl Future for CharFuture {
    type Output = char;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Handle pending wake
        self.driver.process_pending_wake();

        let mut events_checked: usize = 0;
        let budget = self.budget;

        loop {
            if events_checked >= budget {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            if let Some(event) = self.driver.poll_key_event_internal() {
                events_checked += 1;
                if event.state == crate::KeyState::Released {
                    continue;
                }
                if let Some(c) = self.keymap.to_char(event.key, &event.modifiers) {
                    return Poll::Ready(c);
                }
                continue;
            } else {
                self.driver.register_waker(cx.waker());
                if let Some(event) = self.driver.poll_key_event_internal() {
                    events_checked += 1;
                    if event.state == crate::KeyState::Released {
                        continue;
                    }
                    if let Some(c) = self.keymap.to_char(event.key, &event.modifiers) {
                        return Poll::Ready(c);
                    }
                    continue;
                }
                return Poll::Pending;
            }
        }
    }
}

/// CharFuture using Arc<dyn Keymap>
pub struct CharFutureArc<'a> {
    driver: &'static dyn DriverOps,
    keymap: &'a Arc<dyn Keymap>,
}

impl Future for CharFutureArc<'_> {
    type Output = char;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.driver.process_pending_wake();

        let mut events_processed = 0;
        loop {
            if events_processed >= DEFAULT_POLL_BUDGET {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            if let Some(event) = self.driver.poll_key_event_internal() {
                events_processed += 1;
                if event.state == crate::KeyState::Pressed {
                    if let Some(ch) = self.keymap.to_char(event.key, &event.modifiers) {
                        return Poll::Ready(ch);
                    }
                }
            } else {
                self.driver.register_waker(cx.waker());
                if let Some(event) = self.driver.poll_key_event_internal() {
                    if event.state == crate::KeyState::Pressed {
                        if let Some(ch) = self.keymap.to_char(event.key, &event.modifiers) {
                            return Poll::Ready(ch);
                        }
                    }
                } else {
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod qemu_tests {
    use super::*;
    use alloc::boxed::Box;
    use core::ptr;
    use core::task::{RawWaker, RawWakerVTable, Waker};

    fn noop_raw_waker() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            noop_raw_waker()
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        RawWaker::new(
            ptr::null(),
            &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
        )
    }

    fn noop_waker() -> Waker {
        unsafe { Waker::from_raw(noop_raw_waker()) }
    }

    pub fn char_future_ready_smoke() -> bool {
        let driver: &'static crate::driver::KeyboardDriver =
            Box::leak(Box::new(crate::driver::KeyboardDriver::new()));
        let mut stream = KeyboardStream::new(driver, &crate::keymap::DEFAULT_KEYMAP);
        let mut future = stream.read_char();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        if !Pin::new(&mut future).poll(&mut cx).is_pending() {
            return false;
        }

        driver.handle_scancode(0x1E);

        matches!(Pin::new(&mut future).poll(&mut cx), Poll::Ready('a'))
    }
}


#[cfg(test)]
mod qemu_smoke_tests {
    use super::qemu_tests;

    #[test]
    fn char_future_ready_smoke() {
        assert!(qemu_tests::char_future_ready_smoke());
    }
}
