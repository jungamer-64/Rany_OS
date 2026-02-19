// ============================================================================
// drivers/hid/src/driver.rs - Keyboard Driver Core Implementation
// ============================================================================
//!
//! Core keyboard driver implementation that is platform-independent.
//!
//! This module provides the `KeyboardDriver` struct which manages:
//! - Scancode queue (lock-free SPSC)
//! - Modifier key state tracking
//! - ISR-safe waker notification
//! - Stream ownership enforcement
//!
//! The driver is designed to be instantiated as a static variable in the kernel.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::Waker;

use crate::keyboard::{IsrSafeWaker, KeyCodeExt, ModifierState};
use crate::keymap::{DEFAULT_KEYMAP, Keymap};
use crate::queue::ScancodeQueue;
use crate::stream::{DriverOps, KeyboardStream, KeyboardStreamArc};
use crate::{KeyCode, KeyEvent, KeyState, Modifiers, StreamAlreadyTaken};

// ============================================================================
// Scancode Constants
// ============================================================================

/// PS/2 scancode: Extended prefix (0xE0)
const SCANCODE_EXTENDED_PREFIX: u8 = 0xE0;

/// Queue data: Extended flag bit (bit 8)
const QUEUE_EXTENDED_FLAG: u16 = 0x0100;

/// Scancode: Key release bit (bit 7)
const SCANCODE_RELEASE_BIT: u8 = 0x80;

/// Scancode: Keycode mask (bit 0-6)
const SCANCODE_KEYCODE_MASK: u8 = 0x7F;

// ============================================================================
// KeyboardDriver
// ============================================================================

/// Keyboard driver core implementation
///
/// All state is contained within the instance, enabling support for
/// multiple keyboard devices if needed.
///
/// # SPSC Contract
///
/// This driver enforces strict Single Producer Single Consumer:
/// - Producer: ISR (interrupt handler) only
/// - Consumer: `KeyboardStream` owner only
///
/// `KeyboardStream` is not `Clone`, ensuring single consumer at compile time.
pub struct KeyboardDriver {
    /// Initialization flag
    initialized: AtomicBool,
    /// Scancode queue
    queue: ScancodeQueue,
    /// Modifier key state
    modifiers: ModifierState,
    /// ISR extended scancode pending flag
    extended_pending: AtomicBool,
    /// Waker notification (ISR-safe)
    waker: IsrSafeWaker,
    /// Stream issued flag
    stream_taken: AtomicBool,
    /// Dropped events counter (diagnostic)
    dropped_events: AtomicU64,
}

impl KeyboardDriver {
    /// Create a new driver
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            queue: ScancodeQueue::new(),
            modifiers: ModifierState::new(),
            extended_pending: AtomicBool::new(false),
            waker: IsrSafeWaker::new(),
            stream_taken: AtomicBool::new(false),
            dropped_events: AtomicU64::new(0),
        }
    }

    /// Initialize the driver
    ///
    /// This function is idempotent but logs a warning on subsequent calls.
    pub fn init(&self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            #[cfg(feature = "log")]
            log::info!("[KEYBOARD] WARNING: init() called multiple times (ignored)\n");
            return;
        }
        #[cfg(feature = "log")]
        log::info!("[KEYBOARD] Keyboard driver initialized (Instance-based)\n");
    }

    /// Process a scancode (called from ISR)
    ///
    /// # Safety Contract
    /// This function should only be called from ISR context.
    /// Lock-free implementation prevents deadlock.
    pub fn handle_scancode(&self, scancode: u8) {
        if scancode == SCANCODE_EXTENDED_PREFIX {
            self.extended_pending.store(true, Ordering::Relaxed);
            return;
        }

        let extended = self.extended_pending.swap(false, Ordering::Relaxed);
        let data: u16 = (scancode as u16) | if extended { QUEUE_EXTENDED_FLAG } else { 0 };

        if self.queue.push(data) {
            // In ISR: only notify (set flag)
            // Actual wake() is done in Consumer's poll()
            self.waker.notify();
        } else {
            // Queue full: record dropped event
            // In ISR: avoid logging, just increment counter
            // Saturating add: clamp at u64::MAX on overflow
            let _ = self
                .dropped_events
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_add(1).or(Some(u64::MAX))
                });
            // Notify consumer even when queue is full
            self.waker.notify();
        }
    }

    /// Get dropped events count (diagnostic)
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Reset dropped events counter (diagnostic)
    ///
    /// Returns the value before reset.
    pub fn reset_dropped_events(&self) -> u64 {
        self.dropped_events.swap(0, Ordering::Relaxed)
    }

    /// Get next key event (non-blocking, internal)
    fn poll_key_event_internal(&self) -> Option<KeyEvent> {
        let data = self.queue.pop()?;

        let extended = (data & QUEUE_EXTENDED_FLAG) != 0;
        let scancode = (data & 0xFF) as u8;
        let released = (scancode & SCANCODE_RELEASE_BIT) != 0;
        let code = scancode & SCANCODE_KEYCODE_MASK;

        let key = KeyCode::from_scancode(code, extended);
        let state = if released {
            KeyState::Released
        } else {
            KeyState::Pressed
        };

        // Store raw scancode for debugging
        let raw_scancode = data;

        Some(KeyEvent {
            key,
            state,
            modifiers: self.modifiers.snapshot(),
            raw_scancode,
        })
    }

    /// Take keyboard stream (ownership-based SPSC enforcement)
    ///
    /// Uses default US keymap. For other keymaps, use `take_stream_with_keymap()`.
    ///
    /// # Errors
    /// Returns `Err(StreamAlreadyTaken)` if a stream has already been issued.
    pub fn take_stream(&'static self) -> Result<KeyboardStream, StreamAlreadyTaken> {
        self.take_stream_with_keymap(&DEFAULT_KEYMAP)
    }

    /// Take keyboard stream with specified keymap
    ///
    /// # Arguments
    /// * `keymap` - Keymap to use (must have 'static lifetime)
    ///
    /// # Errors
    /// Returns `Err(StreamAlreadyTaken)` if a stream has already been issued.
    pub fn take_stream_with_keymap(
        &'static self,
        keymap: &'static dyn Keymap,
    ) -> Result<KeyboardStream, StreamAlreadyTaken> {
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            return Err(StreamAlreadyTaken);
        }
        Ok(KeyboardStream::new(self, keymap))
    }

    /// Take keyboard stream with Arc<dyn Keymap>
    ///
    /// For dynamic keymap switching or non-'static keymaps.
    pub fn take_stream_with_arc_keymap(
        &'static self,
        keymap: Arc<dyn Keymap>,
    ) -> Result<KeyboardStreamArc, StreamAlreadyTaken> {
        if self.stream_taken.swap(true, Ordering::SeqCst) {
            return Err(StreamAlreadyTaken);
        }
        Ok(KeyboardStreamArc::new(self, keymap))
    }

    /// Return stream (for testing)
    fn return_stream(&self) {
        self.stream_taken.store(false, Ordering::SeqCst);
    }

    /// Register waker (internal)
    fn register_waker(&self, waker: &Waker) {
        self.waker.register(waker);
    }

    /// Process pending ISR notifications
    ///
    /// Call this in the executor's polling loop to convert
    /// ISR notifications to actual Waker wake-ups.
    ///
    /// # Returns
    /// `true` if a wake was performed, `false` otherwise
    pub fn process_pending_wake(&self) -> bool {
        self.waker.check_and_wake()
    }

    /// Check if there are pending wake notifications
    pub fn has_pending_wake(&self) -> bool {
        self.waker.is_pending()
    }

    /// Check if there are events in the queue
    pub fn has_event(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Get current modifier key state
    pub fn get_modifiers(&self) -> Modifiers {
        self.modifiers.snapshot()
    }
}

impl Default for KeyboardDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DriverOps Implementation
// ============================================================================

impl DriverOps for KeyboardDriver {
    fn poll_key_event_internal(&self) -> Option<KeyEvent> {
        KeyboardDriver::poll_key_event_internal(self)
    }

    fn register_waker(&self, waker: &Waker) {
        KeyboardDriver::register_waker(self, waker)
    }

    fn process_pending_wake(&self) -> bool {
        KeyboardDriver::process_pending_wake(self)
    }

    fn has_event(&self) -> bool {
        KeyboardDriver::has_event(self)
    }

    fn get_modifiers(&self) -> Modifiers {
        KeyboardDriver::get_modifiers(self)
    }

    fn return_stream(&self) {
        KeyboardDriver::return_stream(self)
    }
}
