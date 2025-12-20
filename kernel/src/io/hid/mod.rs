// ============================================================================
// src/io/hid/mod.rs - Human Interface Device (HID) Subsystem
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
//! ## キーボードドライバ
//! 同期・非同期両方のインターフェースを提供:
//! - 同期: `poll_key_event()`, `has_key_event()`
//! - 非同期: `KeyboardStream` (所有権ベースSPSCコンシューマ)
//!
//! ## キーマップサポート
//! キーマップモジュールはi18n対応のためのキーボードレイアウト抽象化を提供:
//! - `Keymap` trait: キーボードレイアウトの抽象インターフェース
//! - `UsQwertyKeymap`: デフォルトUS QWERTYレイアウト
//! - 追加レイアウト対応可能 (JIS, AZERTY, Dvorak等)

pub mod keyboard;
pub mod mouse;
pub use hid_driver::ps2;

// Re-export keymap from hid_driver
pub use hid_driver::keymap;

// Re-exports from hid_driver crate (error types only - core types exported via keyboard/mouse)
pub use hid_driver::{HidError, HidResult};

// PS/2 Controller exports
#[allow(unused_imports)]
#[deprecated(
    note = "Ps2DeviceType is deprecated; prefer `DeviceType` from the `ps2` module or generic HID types."
)]
pub use ps2::DeviceType as Ps2DeviceType;

#[deprecated(note = "Ps2KeyCode is deprecated; prefer `KeyCode` directly.")]
pub use ps2::KeyCode as Ps2KeyCode;

#[deprecated(note = "Ps2KeyEvent is deprecated; prefer `KeyEvent` directly.")]
pub use ps2::KeyEvent as Ps2KeyEvent;

pub use ps2::KeyboardHandler;

#[deprecated(note = "Ps2Modifiers is deprecated; prefer `Modifiers` directly.")]
pub use ps2::Modifiers as Ps2Modifiers;

pub use ps2::MouseButton;
pub use ps2::MouseEvent;
pub use ps2::MouseHandler;

// Types
pub use ps2::Ps2Controller;
#[deprecated(
    note = "ps2_commands (top-level re-export) is deprecated; prefer using `crate::io::hid::ps2::commands` directly or `Ps2Controller` APIs where appropriate."
)]
pub use ps2::commands as ps2_commands;

// Functions
#[deprecated(
    note = "ps2_init is deprecated; prefer registering the PS/2 driver via `driver_registry::register_driver(Box::new(Ps2Driver::new()))` or calling `crate::io::hid::ps2::init()` directly; this free function will be removed in a future release."
)]
pub use ps2::init as ps2_init;
#[deprecated(
    note = "ps2_kbd_commands is deprecated; prefer `crate::io::hid::ps2::kbd_commands` or `Ps2Controller` helper methods instead."
)]
pub use ps2::kbd_commands as ps2_kbd_commands;
pub use ps2::keyboard_interrupt_handler;
#[deprecated(
    note = "ps2_mouse_commands is deprecated; prefer `crate::io::hid::ps2::mouse_commands` or `Ps2Controller` helper methods instead."
)]
pub use ps2::mouse_commands as ps2_mouse_commands;
pub use ps2::mouse_interrupt_handler;

// Constants
pub use ps2::ports as ps2_ports;
pub use ps2::set_leds;
pub use ps2::status as ps2_status;

/// Deprecated PS/2 helpers - prefer `KeyboardStream` or unified HID APIs
#[deprecated(
    note = "ps2::get_key_event is deprecated; prefer `KeyboardStream` or `keyboard::has_event` instead."
)]
pub use ps2::get_key_event;

#[deprecated(
    note = "ps2::get_modifiers is deprecated; prefer using keyboard APIs and `KeyboardStream`."
)]
pub use ps2::get_modifiers;

#[deprecated(
    note = "ps2::get_mouse_event is deprecated; prefer using `MouseEvent` streams or unified HID APIs."
)]
pub use ps2::get_mouse_event;

// Keymap exports (i18n keyboard layout support)
#[allow(unused_imports)]
pub use keymap::{
    DEFAULT_KEYMAP, DVORAK_KEYMAP, DvorakKeymap, JIS_KEYMAP, JisKeymap, Keymap, UsQwertyKeymap,
};

// Keyboard driver exports
#[allow(unused_imports)]
pub use keyboard::{
    CharFuture,
    CharFutureArc, // Phase 5: Arc<dyn Keymap>サポート
    // Core types
    KeyCode,
    KeyEvent,
    KeyEventExt,
    // Async futures
    KeyEventFuture,
    KeyState,
    // Driver and stream
    KeyboardDriver,
    KeyboardStream,
    KeyboardStreamArc, // Phase 5: Arc<dyn Keymap>サポート
    Modifiers,
    StreamAlreadyTaken,
    handle_keyboard_interrupt,
    init as keyboard_init,
    // Functions
    keyboard,
    // ISR notification processing (for executors)
    process_pending_wakes,
};

// Deprecated compatibility alias: prefers explicit `keyboard::has_event` or `KeyboardStream` usage
#[deprecated(
    note = "`has_key_event` is deprecated; use `keyboard::has_event` or the `KeyboardStream` API instead."
)]
pub use keyboard::has_event as has_key_event;

// Deprecated compatibility aliases (prefer direct types)
#[deprecated(note = "InputKeyCode is deprecated. Use `KeyCode` directly.")]
pub use keyboard::KeyCode as InputKeyCode;

#[deprecated(note = "InputKeyEvent is deprecated. Use `KeyEvent` directly.")]
pub use keyboard::KeyEvent as InputKeyEvent;

#[deprecated(note = "InputKeyState is deprecated. Use `KeyState` directly.")]
pub use keyboard::KeyState as InputKeyState;

#[deprecated(note = "InputModifiers is deprecated. Use `Modifiers` directly.")]
pub use keyboard::Modifiers as InputModifiers;

// Crate-internal re-exports for legacy shell code
// TODO: Migrate shell code to use KeyboardStream
#[doc(hidden)]
#[deprecated(
    note = "poll_key_char is deprecated; use `keyboard::poll_char` or `KeyboardStream` instead."
)]
pub(crate) use keyboard::poll_char as poll_key_char;

#[doc(hidden)]
#[deprecated(
    note = "poll_key_event is deprecated; use `KeyboardStream` or the stream API instead."
)]
pub(crate) use keyboard::poll_key_event;

#[doc(hidden)]
#[deprecated(
    note = "poll_input_event is deprecated; use `KeyboardStream` or the stream API instead."
)]
pub(crate) use keyboard::poll_key_event as poll_input_event;

// Mouse driver exports
#[allow(unused_imports)]
pub use mouse::handle_mouse_packet;

#[deprecated(
    note = "has_mouse_event is deprecated; prefer `mouse::has_event()` or event-driven MouseEvent streams."
)]
pub use mouse::has_mouse_event;

pub use mouse::init as mouse_init;
pub use mouse::is_mouse_initialized;

#[deprecated(
    note = "poll_mouse_event is deprecated; prefer async MouseEvent streams or `mouse::poll_event` APIs."
)]
pub use mouse::poll_mouse_event;

// Deprecated convenience alias: use `MouseButton`/`MouseEvent` directly
#[deprecated(note = "MouseBtn is deprecated; use `MouseButton` directly.")]
pub use mouse::MouseButton as MouseBtn;

#[deprecated(note = "MouseEvt is deprecated; use `MouseEvent` directly.")]
pub use mouse::MouseEvent as MouseEvt;
