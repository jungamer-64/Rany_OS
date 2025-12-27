// ============================================================================
// kernel/src/io/hid/mod.rs - Human Interface Device (HID) Subsystem
// ============================================================================
//!
//! # HIDサブシステム
//!
//! キーボード、マウスなどの入力デバイスを統合管理するサブシステム。
//!
//! ## モジュール構成
//! - `ps2` - PS/2コントローラドライバ
//! - `keyboard` - 非同期キーボードドライバ (SPSC ownership-based)
//! - `keymap` - キーボードレイアウト抽象化 (i18n対応)
//! - `mouse` - PS/2マウスドライバ
//!
//! ## 使用方法
//!
//! 新しいコードでは直接的なパスを使用してください:
//! - キーボード: `crate::io::hid::keyboard`
//! - マウス: `crate::io::hid::mouse`
//! - PS/2: `crate::io::hid::ps2`

pub mod keyboard;
pub mod mouse;
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
    handle_keyboard_interrupt,
    has_event,
    // Functions
    init as keyboard_init,
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
    commands as ps2_commands,
    get_key_event,
    get_modifiers,
    get_mouse_event,
    // Functions
    init as ps2_init,
    keyboard_interrupt_handler,
    mouse_interrupt_handler,
    // Constants
    ports as ps2_ports,
    set_leds,
    status as ps2_status,
};

// ============================================================================
// Mouse Re-exports
// ============================================================================

pub use hid_driver::{MouseButton, MouseEvent};
pub use mouse::{
    Mouse, MouseInitError, handle_mouse_packet, has_mouse_event, init as mouse_init,
    is_mouse_initialized, poll_mouse_event,
};

// ============================================================================
// Keymap Re-exports
// ============================================================================

pub use keymap::{
    DEFAULT_KEYMAP, DVORAK_KEYMAP, DvorakKeymap, JIS_KEYMAP, JisKeymap, Keymap, UsQwertyKeymap,
};

// ============================================================================
// Internal Backward Compatibility (crate-only)
// ============================================================================

#[doc(hidden)]
pub(crate) use keyboard::poll_input_event;
