// ============================================================================
// drivers/hid/src/keyboard.rs - Keyboard helper types and utilities
// ============================================================================
//! Helper types that are independent of kernel internals and can live in the
//! `hid_driver` crate. These are used by the kernel-side keyboard driver
//! implementation but don't depend on kernel-only APIs.
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::keymap::Keymap;
use core::task::Waker;

use crate::keymap::DEFAULT_KEYMAP;
use crate::{KeyCode, KeyEvent, KeyState, Modifiers};

// ============================================================================
// StreamAlreadyTaken
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamAlreadyTaken;

impl fmt::Display for StreamAlreadyTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyboard stream already taken by another consumer")
    }
}

// ============================================================================
// KeyCodeExt
// ============================================================================

/// Helper extension trait for `KeyCode` providing scancode conversions.
pub trait KeyCodeExt {
    fn from_scancode(scancode: u8, extended: bool) -> Self;
    fn to_char(&self, shift: bool, caps_lock: bool) -> Option<char>;
}

impl KeyCodeExt for KeyCode {
    fn from_scancode(scancode: u8, extended: bool) -> Self {
        if extended {
            match scancode {
                0x48 => KeyCode::Up,
                0x50 => KeyCode::Down,
                0x4B => KeyCode::Left,
                0x4D => KeyCode::Right,
                0x52 => KeyCode::Insert,
                0x53 => KeyCode::Delete,
                0x47 => KeyCode::Home,
                0x4F => KeyCode::End,
                0x49 => KeyCode::PageUp,
                0x51 => KeyCode::PageDown,
                0x1C => KeyCode::NumPadEnter,
                0x35 => KeyCode::NumPadDivide,
                _ => KeyCode::Unknown,
            }
        } else {
            match scancode {
                0x01 => KeyCode::Escape,
                0x02 => KeyCode::Key1,
                0x03 => KeyCode::Key2,
                0x04 => KeyCode::Key3,
                0x05 => KeyCode::Key4,
                0x06 => KeyCode::Key5,
                0x07 => KeyCode::Key6,
                0x08 => KeyCode::Key7,
                0x09 => KeyCode::Key8,
                0x0A => KeyCode::Key9,
                0x0B => KeyCode::Key0,
                0x0C => KeyCode::Minus,
                0x0D => KeyCode::Equals,
                0x0E => KeyCode::Backspace,
                0x0F => KeyCode::Tab,
                0x10 => KeyCode::Q,
                0x11 => KeyCode::W,
                0x12 => KeyCode::E,
                0x13 => KeyCode::R,
                0x14 => KeyCode::T,
                0x15 => KeyCode::Y,
                0x16 => KeyCode::U,
                0x17 => KeyCode::I,
                0x18 => KeyCode::O,
                0x19 => KeyCode::P,
                0x1A => KeyCode::LeftBracket,
                0x1B => KeyCode::RightBracket,
                0x1C => KeyCode::Enter,
                0x1D => KeyCode::LeftCtrl,
                0x1E => KeyCode::A,
                0x1F => KeyCode::S,
                0x20 => KeyCode::D,
                0x21 => KeyCode::F,
                0x22 => KeyCode::G,
                0x23 => KeyCode::H,
                0x24 => KeyCode::J,
                0x25 => KeyCode::K,
                0x26 => KeyCode::L,
                0x27 => KeyCode::Semicolon,
                0x28 => KeyCode::Quote,
                0x29 => KeyCode::BackTick,
                0x2A => KeyCode::LeftShift,
                0x2B => KeyCode::Backslash,
                0x2C => KeyCode::Z,
                0x2D => KeyCode::X,
                0x2E => KeyCode::C,
                0x2F => KeyCode::V,
                0x30 => KeyCode::B,
                0x31 => KeyCode::N,
                0x32 => KeyCode::M,
                0x33 => KeyCode::Comma,
                0x34 => KeyCode::Period,
                0x35 => KeyCode::Slash,
                0x36 => KeyCode::RightShift,
                0x37 => KeyCode::NumPadMultiply,
                0x38 => KeyCode::LeftAlt,
                0x39 => KeyCode::Space,
                0x3A => KeyCode::CapsLock,
                0x3B => KeyCode::F1,
                0x3C => KeyCode::F2,
                0x3D => KeyCode::F3,
                0x3E => KeyCode::F4,
                0x3F => KeyCode::F5,
                0x40 => KeyCode::F6,
                0x41 => KeyCode::F7,
                0x42 => KeyCode::F8,
                0x43 => KeyCode::F9,
                0x44 => KeyCode::F10,
                0x45 => KeyCode::NumLock,
                0x46 => KeyCode::ScrollLock,
                0x47 => KeyCode::NumPad7,
                0x48 => KeyCode::NumPad8,
                0x49 => KeyCode::NumPad9,
                0x4A => KeyCode::NumPadMinus,
                0x4B => KeyCode::NumPad4,
                0x4C => KeyCode::NumPad5,
                0x4D => KeyCode::NumPad6,
                0x4E => KeyCode::NumPadPlus,
                0x4F => KeyCode::NumPad1,
                0x50 => KeyCode::NumPad2,
                0x51 => KeyCode::NumPad3,
                0x52 => KeyCode::NumPad0,
                0x53 => KeyCode::NumPadDecimal,
                0x57 => KeyCode::F11,
                0x58 => KeyCode::F12,
                _ => KeyCode::Unknown,
            }
        }
    }

    fn to_char(&self, shift: bool, caps_lock: bool) -> Option<char> {
        let modifiers = Modifiers {
            shift,
            caps_lock,
            ..Default::default()
        };
        DEFAULT_KEYMAP.to_char(*self, &modifiers)
    }
}

// ============================================================================
// KeyEventExt
// ============================================================================

/// KeyEvent extension trait (character conversion)
pub trait KeyEventExt {
    fn to_char(&self) -> Option<char>;
    fn to_char_with_keymap<K: crate::keymap::Keymap>(&self, keymap: &K) -> Option<char>;
}

impl KeyEventExt for KeyEvent {
    fn to_char(&self) -> Option<char> {
        if self.state == KeyState::Released {
            return None;
        }
        DEFAULT_KEYMAP.to_char(self.key, &self.modifiers)
    }

    fn to_char_with_keymap<K: crate::keymap::Keymap>(&self, keymap: &K) -> Option<char> {
        if self.state == KeyState::Released {
            return None;
        }
        keymap.to_char(self.key, &self.modifiers)
    }
}

// ============================================================================
// ModifierState
// ============================================================================

#[derive(Debug)]
pub struct ModifierState {
    bits: AtomicU32,
}

impl ModifierState {
    const BIT_LEFT_SHIFT: u32 = 0;
    const BIT_RIGHT_SHIFT: u32 = 1;
    const BIT_LEFT_CTRL: u32 = 2;
    const BIT_RIGHT_CTRL: u32 = 3;
    const BIT_LEFT_ALT: u32 = 4;
    const BIT_RIGHT_ALT: u32 = 5;
    const BIT_CAPS_LOCK: u32 = 6;
    const BIT_NUM_LOCK: u32 = 7;
    const BIT_SCROLL_LOCK: u32 = 8;

    const LEFT_SHIFT: u32 = 1 << Self::BIT_LEFT_SHIFT;
    const RIGHT_SHIFT: u32 = 1 << Self::BIT_RIGHT_SHIFT;
    const LEFT_CTRL: u32 = 1 << Self::BIT_LEFT_CTRL;
    const RIGHT_CTRL: u32 = 1 << Self::BIT_RIGHT_CTRL;
    const LEFT_ALT: u32 = 1 << Self::BIT_LEFT_ALT;
    const RIGHT_ALT: u32 = 1 << Self::BIT_RIGHT_ALT;
    const CAPS_LOCK: u32 = 1 << Self::BIT_CAPS_LOCK;
    const NUM_LOCK: u32 = 1 << Self::BIT_NUM_LOCK;
    const SCROLL_LOCK: u32 = 1 << Self::BIT_SCROLL_LOCK;

    pub const fn new() -> Self {
        Self { bits: AtomicU32::new(0) }
    }

    pub fn snapshot(&self) -> Modifiers {
        let bits = self.bits.load(Ordering::Acquire);
        Modifiers {
            shift: (bits & (Self::LEFT_SHIFT | Self::RIGHT_SHIFT)) != 0,
            ctrl: (bits & (Self::LEFT_CTRL | Self::RIGHT_CTRL)) != 0,
            alt: (bits & Self::LEFT_ALT) != 0,
            alt_gr: (bits & Self::RIGHT_ALT) != 0,
            caps_lock: (bits & Self::CAPS_LOCK) != 0,
            num_lock: (bits & Self::NUM_LOCK) != 0,
            scroll_lock: (bits & Self::SCROLL_LOCK) != 0,
        }
    }

    #[inline]
    pub fn set_bit(&self, mask: u32) {
        self.bits.fetch_or(mask, Ordering::Release);
    }

    #[inline]
    pub fn clear_bit(&self, mask: u32) {
        self.bits.fetch_and(!mask, Ordering::Release);
    }

    #[inline]
    pub fn toggle_bit(&self, mask: u32) {
        self.bits.fetch_xor(mask, Ordering::Release);
    }

    #[inline]
    pub fn update_bit(&self, mask: u32, pressed: bool) {
        if pressed {
            self.set_bit(mask);
        } else {
            self.clear_bit(mask);
        }
    }
}

// ============================================================================
// IsrSafeWaker - IRQ-safe Waker
// ============================================================================

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "IsrSafeWaker is only verified on x86_64 (TSO memory model). \
     ARM/RISC-V require formal verification with Loom/Miri before use. \
     To enable on other architectures, add feature 'experimental-weak-memory'."
);

pub struct IsrSafeWaker {
    pending: AtomicBool,
    current_epoch: AtomicU64,
    waker_slots: [UnsafeCell<Option<Waker>>; 2],
    has_waker: AtomicBool,
}

unsafe impl Send for IsrSafeWaker {}
unsafe impl Sync for IsrSafeWaker {}

impl IsrSafeWaker {
    pub const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            current_epoch: AtomicU64::new(0),
            waker_slots: [
                UnsafeCell::new(None),
                UnsafeCell::new(None),
            ],
            has_waker: AtomicBool::new(false),
        }
    }

    pub fn register(&self, waker: &Waker) {
        let old_epoch = self.current_epoch.load(Ordering::Acquire);
        let next_epoch = old_epoch.wrapping_add(1);
        let next_slot = (next_epoch % 2) as usize;

        unsafe {
            let slot = &mut *self.waker_slots[next_slot].get();
            if let Some(existing) = slot {
                if existing.will_wake(waker) {
                    return;
                }
            }
            *slot = Some(waker.clone());
        }

        self.current_epoch.store(next_epoch, Ordering::Release);
        self.has_waker.store(true, Ordering::Release);
    }

    #[inline]
    pub fn notify(&self) {
        self.pending.store(true, Ordering::Release);
    }

    pub fn check_and_wake(&self) -> bool {
        if !self.pending.swap(false, Ordering::AcqRel) {
            return false;
        }

        if self.has_waker.load(Ordering::Acquire) {
            let epoch = self.current_epoch.load(Ordering::Acquire);
            let slot_idx = (epoch % 2) as usize;
            let waker_slot = unsafe { &*self.waker_slots[slot_idx].get() };
            if let Some(waker) = waker_slot {
                waker.wake_by_ref();
                return true;
            }
        }

        false
    }

    #[allow(dead_code)]
    pub fn wake_now(&self) {
        if self.has_waker.load(Ordering::Acquire) {
            let epoch = self.current_epoch.load(Ordering::Acquire);
            let slot_idx = (epoch % 2) as usize;
            let waker_slot = unsafe { &*self.waker_slots[slot_idx].get() };
            if let Some(waker) = waker_slot {
                waker.wake_by_ref();
            }
        }
    }

    #[inline]
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    #[allow(dead_code)]
    pub fn is_registered(&self) -> bool {
        self.has_waker.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_scancode_basic() {
        assert_eq!(KeyCode::from_scancode(0x10, false), KeyCode::Q);
        assert_eq!(KeyCode::from_scancode(0x48, true), KeyCode::Up);
    }
}
