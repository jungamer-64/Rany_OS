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
pub mod keymap;
pub mod mouse;
pub mod ps2;

// PS/2 Controller exports
#[allow(unused_imports)]
pub use ps2::{
    // Constants
    ports as ps2_ports,
    status as ps2_status,
    commands as ps2_commands,
    kbd_commands as ps2_kbd_commands,
    mouse_commands as ps2_mouse_commands,
    // Types
    Ps2Controller,
    DeviceType as Ps2DeviceType,
    KeyCode as Ps2KeyCode,
    KeyEvent as Ps2KeyEvent,
    Modifiers as Ps2Modifiers,
    MouseButton,
    MouseEvent,
    KeyboardHandler,
    MouseHandler,
    // Functions
    init as ps2_init,
    keyboard_interrupt_handler,
    mouse_interrupt_handler,
    get_key_event,
    get_mouse_event,
    get_modifiers,
    set_leds,
};

// Keymap exports (i18n keyboard layout support)
#[allow(unused_imports)]
pub use keymap::{
    Keymap,
    UsQwertyKeymap,
    JisKeymap,
    DvorakKeymap,
    DEFAULT_KEYMAP,
};

// Keyboard driver exports
#[allow(unused_imports)]
pub use keyboard::{
    // Core types
    KeyCode,
    KeyState,
    KeyEvent,
    Modifiers,
    // Driver and stream
    KeyboardDriver,
    KeyboardStream,
    // Async futures (deprecated - use KeyboardStream instead)
    KeyEventFuture,
    CharFuture,
    // LineFuture is deprecated - use KeyboardStream instead
    // Type aliases for compatibility with old shell code
    KeyCode as InputKeyCode,
    KeyState as InputKeyState,
    KeyEvent as InputKeyEvent,
    Modifiers as InputModifiers,
    // Functions
    keyboard,
    init as keyboard_init,
    handle_keyboard_interrupt,
    // Synchronous polling API
    poll_key_event,
    poll_char as poll_key_char,
    has_event as has_key_event,
    // Compatibility aliases
    poll_key_event as poll_input_event,
};

// Mouse driver exports
#[allow(unused_imports)]
pub use mouse::{
    // Types
    MouseButton as MouseBtn,
    MouseEvent as MouseEvt,
    // Functions
    init as mouse_init,
    handle_mouse_packet,
    poll_mouse_event,
    has_mouse_event,
    is_mouse_initialized,
};
