// ============================================================================
// kernel/src/io/hid/mod.rs - Human Interface Device (HID) Subsystem
// ============================================================================
//!
//! # HIDサブシステム
//!
//! キーボードなどの入力デバイスを統合管理するサブシステム。
//!
//! ## モジュール構成
//! - `ps2` - PS/2コントローラドライバ
//! - `keyboard` - 非同期キーボードドライバ (SPSC ownership-based)
//! - `keymap` - キーボードレイアウト抽象化 (i18n対応)
//!
//! ## 使用方法
//!
//! 新しいコードでは直接的なパスを使用してください:
//! - キーボード: `crate::io::hid::keyboard`
//! - PS/2: `crate::io::hid::ps2`

pub mod keyboard;
pub mod keyboard_driver;
pub use hid_driver::ps2;

// Re-export keymap from hid_driver
pub use hid_driver::keymap;

// Re-exports from hid_driver crate
pub use hid_driver::{HidError, HidResult};

// ============================================================================
// Core Type Re-exports (from keyboard)
// ============================================================================

pub use keyboard::{
    CharFuture,
    CharFutureArc,
    // Core types
    KeyCode,
    // Extension traits
    KeyCodeExt,
    KeyEvent,
    KeyEventExt,
    // Async futures
    KeyEventFuture,
    KeyState,
    // Driver and stream
    KeyboardDriver,
    KeyboardStream,
    KeyboardStreamArc,
    Modifiers,
    StreamAlreadyTaken,
    has_event,
    // Functions (init removed - use Ps2KeyboardDriver via DriverRegistry)
    process_pending_wakes,
    take_stream,
    take_stream_with_arc_keymap,
    take_stream_with_keymap,
};

// ============================================================================
// PS/2 Re-exports
// ============================================================================

pub use ps2::{
    DeviceType,
    KeyboardHandler,
    MouseHandler,
    // Types
    Ps2Controller,
    // Note: Top-level PS/2 convenience re-exports (e.g., `ps2_init`, `ps2_ports`, `ps2_status`, `ps2_commands`) were removed.
    // Access the raw PS/2 module directly: `crate::io::hid::ps2::init()` or use `Ps2Controller` APIs.
    // Functions
    keyboard_interrupt_handler,
    // Constants (use `crate::io::hid::ps2::ports` / `crate::io::hid::ps2::status` directly)
    set_leds,
};

// ============================================================================
// Driver Trait Re-exports
// ============================================================================

pub use keyboard_driver::Ps2KeyboardDriver;

// ============================================================================
// Keymap Re-exports
// ============================================================================

pub use keymap::{
    DEFAULT_KEYMAP, DVORAK_KEYMAP, DvorakKeymap, JIS_KEYMAP, JisKeymap, Keymap, UsQwertyKeymap,
};
