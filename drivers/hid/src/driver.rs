// ============================================================================
// drivers/hid/src/driver.rs - Keyboard Driver Core Implementation
// ============================================================================
//!
//! Core keyboard driver implementation that is platform-independent.
//!
//! This module provides the `KeyboardDriver` struct which manages:
//! - Key-event queue (lock-free SPSC)
//! - Modifier key state tracking
//! - ISR-safe waker notification
//! - Stream ownership enforcement
//!
//! The driver is designed to be instantiated as a static variable in the kernel.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::Waker;

use crate::keyboard::{IsrSafeWaker, KeyCodeExt, ModifierState};
use crate::keymap::{DEFAULT_KEYMAP, Keymap};
use crate::queue::KeyEventQueue;
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

/// Packed event layout: key[7:0], pressed[8], modifiers[15:9], raw_scancode[31:16].
const PACKED_KEY_MASK: u32 = 0x0000_00FF;
const PACKED_STATE_MASK: u32 = 0x0000_0100;
const PACKED_MODIFIERS_SHIFT: u32 = 9;
const PACKED_RAW_SCANCODE_SHIFT: u32 = 16;

const PACKED_MOD_SHIFT: u8 = 1 << 0;
const PACKED_MOD_CTRL: u8 = 1 << 1;
const PACKED_MOD_ALT: u8 = 1 << 2;
const PACKED_MOD_ALT_GR: u8 = 1 << 3;
const PACKED_MOD_CAPS_LOCK: u8 = 1 << 4;
const PACKED_MOD_NUM_LOCK: u8 = 1 << 5;
const PACKED_MOD_SCROLL_LOCK: u8 = 1 << 6;

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
    /// Normalized key-event queue
    queue: KeyEventQueue,
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
    /// Optional IRQ-side observer tap (kernel-owned, best-effort)
    event_tap: AtomicUsize,
}

impl KeyboardDriver {
    /// Create a new driver
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            queue: KeyEventQueue::new(),
            modifiers: ModifierState::new(),
            extended_pending: AtomicBool::new(false),
            waker: IsrSafeWaker::new(),
            stream_taken: AtomicBool::new(false),
            dropped_events: AtomicU64::new(0),
            event_tap: AtomicUsize::new(0),
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
        let pressed = (scancode & SCANCODE_RELEASE_BIT) == 0;
        let code = scancode & SCANCODE_KEYCODE_MASK;
        self.update_modifiers_from_scancode(code, extended, pressed);
        let raw_scancode = (scancode as u16) | if extended { QUEUE_EXTENDED_FLAG } else { 0 };
        let event = KeyEvent {
            key: KeyCode::from_scancode(code, extended),
            state: if pressed {
                KeyState::Pressed
            } else {
                KeyState::Released
            },
            modifiers: self.modifiers.snapshot(),
            raw_scancode,
        };
        self.emit_tap_event(event);
        self.enqueue_key_event(event);
    }

    /// Process a normalized key event from a non-PS/2 transport.
    ///
    /// This keeps the consumer path transport-neutral while preserving the
    /// existing PS/2 producer interface.
    pub fn handle_key_event(&self, event: KeyEvent) {
        self.modifiers.overwrite_from_snapshot(event.modifiers);
        self.emit_tap_event(event);
        self.enqueue_key_event(event);
    }

    #[inline]
    fn emit_tap_event(&self, event: KeyEvent) {
        let tap = self.event_tap.load(Ordering::Acquire);
        if tap == 0 {
            return;
        }

        // Function pointers are installed by the kernel and read atomically here.
        // `0` means "no tap". This keeps the ISR path lock-free.
        let callback: fn(KeyEvent) = unsafe { core::mem::transmute(tap) };
        callback(event);
    }

    #[inline]
    fn enqueue_key_event(&self, event: KeyEvent) {
        if self.queue.push(pack_key_event(event)) {
            self.waker.notify();
            return;
        }

        let _ = self
            .dropped_events
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                v.checked_add(1).or(Some(u64::MAX))
            });
        self.waker.notify();
    }

    /// Update modifier-state bits from a raw set-1 scancode.
    ///
    /// This must run on the producer path (IRQ) so that queued key events carry
    /// the latest modifier snapshot when consumed.
    fn update_modifiers_from_scancode(&self, code: u8, extended: bool, pressed: bool) {
        match (code, extended) {
            // Shift
            (0x2A, false) => self
                .modifiers
                .update_bit(ModifierState::LEFT_SHIFT, pressed),
            (0x36, false) => self
                .modifiers
                .update_bit(ModifierState::RIGHT_SHIFT, pressed),
            // Ctrl (E0 1D = right ctrl)
            (0x1D, false) => self.modifiers.update_bit(ModifierState::LEFT_CTRL, pressed),
            (0x1D, true) => self
                .modifiers
                .update_bit(ModifierState::RIGHT_CTRL, pressed),
            // Alt (E0 38 = right alt / AltGr)
            (0x38, false) => self.modifiers.update_bit(ModifierState::LEFT_ALT, pressed),
            (0x38, true) => self.modifiers.update_bit(ModifierState::RIGHT_ALT, pressed),
            // Locks: toggle on key press only
            (0x3A, false) if pressed => self.modifiers.toggle_bit(ModifierState::CAPS_LOCK),
            (0x45, false) if pressed => self.modifiers.toggle_bit(ModifierState::NUM_LOCK),
            (0x46, false) if pressed => self.modifiers.toggle_bit(ModifierState::SCROLL_LOCK),
            _ => {}
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

    /// Register or clear a best-effort IRQ-side event tap.
    ///
    /// The callback runs in interrupt context and must not block.
    pub fn set_event_tap(&self, tap: Option<fn(KeyEvent)>) {
        let raw = tap.map(|f| f as usize).unwrap_or(0);
        self.event_tap.store(raw, Ordering::Release);
    }

    /// Get next key event (non-blocking, internal)
    fn poll_key_event_internal(&self) -> Option<KeyEvent> {
        self.queue.pop().map(unpack_key_event)
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
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
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

#[inline]
fn pack_modifiers(modifiers: Modifiers) -> u8 {
    let mut packed = 0u8;
    if modifiers.shift {
        packed |= PACKED_MOD_SHIFT;
    }
    if modifiers.ctrl {
        packed |= PACKED_MOD_CTRL;
    }
    if modifiers.alt {
        packed |= PACKED_MOD_ALT;
    }
    if modifiers.alt_gr {
        packed |= PACKED_MOD_ALT_GR;
    }
    if modifiers.caps_lock {
        packed |= PACKED_MOD_CAPS_LOCK;
    }
    if modifiers.num_lock {
        packed |= PACKED_MOD_NUM_LOCK;
    }
    if modifiers.scroll_lock {
        packed |= PACKED_MOD_SCROLL_LOCK;
    }
    packed
}

#[inline]
fn unpack_modifiers(packed: u8) -> Modifiers {
    Modifiers {
        shift: (packed & PACKED_MOD_SHIFT) != 0,
        ctrl: (packed & PACKED_MOD_CTRL) != 0,
        alt: (packed & PACKED_MOD_ALT) != 0,
        alt_gr: (packed & PACKED_MOD_ALT_GR) != 0,
        caps_lock: (packed & PACKED_MOD_CAPS_LOCK) != 0,
        num_lock: (packed & PACKED_MOD_NUM_LOCK) != 0,
        scroll_lock: (packed & PACKED_MOD_SCROLL_LOCK) != 0,
    }
}

#[inline]
fn pack_key_event(event: KeyEvent) -> u32 {
    let key = event.key as u32;
    let state = if matches!(event.state, KeyState::Pressed) {
        PACKED_STATE_MASK
    } else {
        0
    };
    let modifiers = (pack_modifiers(event.modifiers) as u32) << PACKED_MODIFIERS_SHIFT;
    let raw_scancode = (event.raw_scancode as u32) << PACKED_RAW_SCANCODE_SHIFT;
    key | state | modifiers | raw_scancode
}

#[inline]
fn unpack_key_event(packed: u32) -> KeyEvent {
    let key_raw = (packed & PACKED_KEY_MASK) as u8;
    let state = if (packed & PACKED_STATE_MASK) != 0 {
        KeyState::Pressed
    } else {
        KeyState::Released
    };
    let modifiers = unpack_modifiers(((packed >> PACKED_MODIFIERS_SHIFT) & 0x7F) as u8);
    let raw_scancode = (packed >> PACKED_RAW_SCANCODE_SHIFT) as u16;

    KeyEvent {
        key: unsafe { core::mem::transmute::<u8, KeyCode>(key_raw) },
        state,
        modifiers,
        raw_scancode,
    }
}
