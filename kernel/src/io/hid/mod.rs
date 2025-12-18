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
pub mod ps2;

// Re-export keymap from hid_driver
pub use hid_driver::keymap;

// Re-exports from hid_driver crate (error types only - core types exported via keyboard/mouse)
pub use hid_driver::{HidError, HidResult};

// PS/2 Controller exports
#[allow(unused_imports)]
pub use ps2::{
    DeviceType as Ps2DeviceType,
    KeyCode as Ps2KeyCode,
    KeyEvent as Ps2KeyEvent,
    KeyboardHandler,
    Modifiers as Ps2Modifiers,
    MouseButton,
    MouseEvent,
    MouseHandler,
    // Types
    Ps2Controller,
    commands as ps2_commands,
    get_key_event,
    get_modifiers,
    get_mouse_event,
    // Functions
    init as ps2_init,
    kbd_commands as ps2_kbd_commands,
    keyboard_interrupt_handler,
    mouse_commands as ps2_mouse_commands,
    mouse_interrupt_handler,
    // Constants
    ports as ps2_ports,
    set_leds,
    status as ps2_status,
};

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
#[deprecated(note = "`has_key_event` is deprecated; use `keyboard::has_event` or the `KeyboardStream` API instead.")]
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
#[deprecated(note = "poll_key_char is deprecated; use `keyboard::poll_char` or `KeyboardStream` instead.")]
pub(crate) use keyboard::poll_char as poll_key_char;

#[doc(hidden)]
#[deprecated(note = "poll_key_event is deprecated; use `KeyboardStream` or the stream API instead.")]
pub(crate) use keyboard::poll_key_event;

#[doc(hidden)]
#[deprecated(note = "poll_input_event is deprecated; use `KeyboardStream` or the stream API instead.")]
pub(crate) use keyboard::poll_key_event as poll_input_event;

// Mouse driver exports
#[allow(unused_imports)]
pub use mouse::{
    // Types
    handle_mouse_packet,
    has_mouse_event,
    // Functions
    init as mouse_init,
    is_mouse_initialized,
    poll_mouse_event,
};

// Deprecated convenience alias: use `MouseButton`/`MouseEvent` directly
#[deprecated(note = "MouseBtn is deprecated; use `MouseButton` directly.")]
pub use mouse::MouseButton as MouseBtn;

#[deprecated(note = "MouseEvt is deprecated; use `MouseEvent` directly.")]
pub use mouse::MouseEvent as MouseEvt;
