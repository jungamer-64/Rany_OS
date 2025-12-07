// ============================================================================
// src/io/hid/ps2/mod.rs - PS/2 Controller Module
// ============================================================================
//!
//! PS/2コントローラドライバ
//!
//! - キーボードとマウスの初期化
//! - スキャンコード処理
//! - イベント管理
//!

mod constants;
mod controller;
mod keyboard;
mod keycode;
mod mouse;
mod mouse_types;

pub use constants::{commands, kbd_commands, mouse_commands, ports, status};
pub use controller::{DeviceType, Ps2Controller};
pub use keyboard::KeyboardHandler;
pub use keycode::{KeyCode, KeyEvent, Modifiers};
pub use mouse::MouseHandler;
pub use mouse_types::{MouseButton, MouseEvent};

use spin::Mutex;

// ============================================================================
// Global State
// ============================================================================

/// グローバルPS/2コントローラ
static PS2_CONTROLLER: Mutex<Option<Ps2Controller>> = Mutex::new(None);
/// グローバルキーボードハンドラ
static KEYBOARD: Mutex<Option<KeyboardHandler>> = Mutex::new(None);
/// グローバルマウスハンドラ
static MOUSE: Mutex<Option<MouseHandler>> = Mutex::new(None);

/// PS/2コントローラを初期化
pub fn init() {
    let mut controller = Ps2Controller::new();

    if controller.initialize() {
        // キーボードハンドラを初期化
        if controller.port1_type.is_some() {
            *KEYBOARD.lock() = Some(KeyboardHandler::new());
        }

        // マウスハンドラを初期化
        if let Some(mouse_type) = controller.port2_type {
            let has_wheel = matches!(
                mouse_type,
                DeviceType::ScrollMouse | DeviceType::FiveButtonMouse
            );
            *MOUSE.lock() = Some(MouseHandler::new(has_wheel));
        }

        *PS2_CONTROLLER.lock() = Some(controller);
    }
}

/// キーボード割り込みハンドラ
pub fn keyboard_interrupt_handler() {
    let status_val: u8;
    let data: u8;

    unsafe {
        core::arch::asm!("in al, dx", out("al") status_val, in("dx") ports::STATUS, options(nomem, nostack));
        if (status_val & status::OUTPUT_FULL) == 0 {
            return;
        }
        core::arch::asm!("in al, dx", out("al") data, in("dx") ports::DATA, options(nomem, nostack));
    }

    if let Some(ref mut kbd) = *KEYBOARD.lock() {
        kbd.process_scancode(data);
    }
}

/// マウス割り込みハンドラ
pub fn mouse_interrupt_handler() {
    let status_val: u8;
    let data: u8;

    unsafe {
        core::arch::asm!("in al, dx", out("al") status_val, in("dx") ports::STATUS, options(nomem, nostack));
        if (status_val & status::OUTPUT_FULL) == 0 {
            return;
        }
        core::arch::asm!("in al, dx", out("al") data, in("dx") ports::DATA, options(nomem, nostack));
    }

    if let Some(ref mut mouse) = *MOUSE.lock() {
        mouse.process_byte(data);
    }
}

/// キーイベントを取得
pub fn get_key_event() -> Option<KeyEvent> {
    KEYBOARD.lock().as_mut()?.pop_event()
}

/// マウスイベントを取得
pub fn get_mouse_event() -> Option<MouseEvent> {
    MOUSE.lock().as_mut()?.pop_event()
}

/// 修飾キー状態を取得
pub fn get_modifiers() -> Option<Modifiers> {
    Some(KEYBOARD.lock().as_ref()?.modifiers())
}

/// キーボードLEDを設定
pub fn set_leds(scroll: bool, num: bool, caps: bool) {
    if let Some(ref controller) = *PS2_CONTROLLER.lock() {
        controller.set_keyboard_leds(scroll, num, caps);
    }
}
