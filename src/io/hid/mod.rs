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
//! - `keyboard` - 非同期キーボードドライバ

pub mod keyboard;
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

// Keyboard driver exports
#[allow(unused_imports)]
pub use keyboard::{
    // Types
    KeyCode,
    KeyState,
    KeyEvent,
    KeyboardDriver,
    KeyEventFuture,
    CharFuture,
    LineFuture,
    // Functions
    keyboard,
    init as keyboard_init,
    handle_keyboard_interrupt,
};
