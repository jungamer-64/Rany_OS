// ============================================================================
// src/io/usb/class/hid.rs - USB HID (Human Interface Device) Class Driver
// ============================================================================
//!
//! # USB HID クラスドライバ
//!
//! キーボード、マウス、ゲームパッド等のHIDデバイスをサポート。
//!
//! ## サポート機能
//! - Boot Protocol (BIOS互換モード)
//! - Report Protocol (フル機能モード)
//! - 複数レポート
//!
//! ## 参照仕様
//! - USB HID Specification 1.11
//! - HID Usage Tables 1.12
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use hid_driver::{KeyCode, KeyEvent, KeyState, Modifiers};
use spin::Mutex;
mod keycodes;

use super::{
    ClassDriverError, ClassDriverEvent, REQUEST_DIR_IN, REQUEST_DIR_OUT,
    REQUEST_TYPE_CLASS_INTERFACE, SetupPacket, TransferStatus, UsbClass, UsbClassDriver,
};

// ============================================================================
// HID Constants
// ============================================================================

/// HID クラスコード
pub const HID_CLASS: u8 = 0x03;

/// HID サブクラス: None
pub const HID_SUBCLASS_NONE: u8 = 0x00;
/// HID サブクラス: Boot Interface
pub const HID_SUBCLASS_BOOT: u8 = 0x01;

/// HID プロトコル: None
pub const HID_PROTOCOL_NONE: u8 = 0x00;
/// HID プロトコル: Keyboard
pub const HID_PROTOCOL_KEYBOARD: u8 = 0x01;
/// HID プロトコル: Mouse
pub const HID_PROTOCOL_MOUSE: u8 = 0x02;

// ============================================================================
// HID Request Codes
// ============================================================================

/// GET_REPORT
pub const HID_GET_REPORT: u8 = 0x01;
/// GET_IDLE
pub const HID_GET_IDLE: u8 = 0x02;
/// GET_PROTOCOL
pub const HID_GET_PROTOCOL: u8 = 0x03;
/// SET_REPORT
pub const HID_SET_REPORT: u8 = 0x09;
/// SET_IDLE
pub const HID_SET_IDLE: u8 = 0x0A;
/// SET_PROTOCOL
pub const HID_SET_PROTOCOL: u8 = 0x0B;

// ============================================================================
// HID Report Types
// ============================================================================

/// レポートタイプ: Input
pub const HID_REPORT_TYPE_INPUT: u8 = 0x01;
/// レポートタイプ: Output
pub const HID_REPORT_TYPE_OUTPUT: u8 = 0x02;
/// レポートタイプ: Feature
pub const HID_REPORT_TYPE_FEATURE: u8 = 0x03;

// ============================================================================
// HID Descriptor Types
// ============================================================================

/// HID ディスクリプタ
pub const HID_DESCRIPTOR_TYPE_HID: u8 = 0x21;
/// Report ディスクリプタ
pub const HID_DESCRIPTOR_TYPE_REPORT: u8 = 0x22;
/// Physical ディスクリプタ
pub const HID_DESCRIPTOR_TYPE_PHYSICAL: u8 = 0x23;

const USB_RAW_SCANCODE_FLAG: u16 = 0x8000;

static KEYBOARD_EVENT_SINK: AtomicUsize = AtomicUsize::new(0);

pub fn set_keyboard_event_sink(sink: Option<fn(KeyEvent)>) {
    let raw = sink.map(|f| f as usize).unwrap_or(0);
    KEYBOARD_EVENT_SINK.store(raw, Ordering::Release);
}

fn emit_keyboard_event_sink(event: KeyEvent) {
    let raw = KEYBOARD_EVENT_SINK.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }

    let callback: fn(KeyEvent) = unsafe { core::mem::transmute(raw) };
    callback(event);
}

// ============================================================================
// HID Subclass / Protocol Enums
// ============================================================================

/// HID サブクラス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidSubclass {
    /// サブクラスなし
    None,
    /// Boot Interface
    Boot,
    /// 不明
    Unknown(u8),
}

impl HidSubclass {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::None,
            0x01 => Self::Boot,
            v => Self::Unknown(v),
        }
    }
}

/// HID プロトコル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidProtocol {
    /// プロトコルなし
    None,
    /// キーボード
    Keyboard,
    /// マウス
    Mouse,
    /// 不明
    Unknown(u8),
}

impl HidProtocol {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::None,
            0x01 => Self::Keyboard,
            0x02 => Self::Mouse,
            v => Self::Unknown(v),
        }
    }
}

// ============================================================================
// HID Report
// ============================================================================

/// HID レポート
#[derive(Debug, Clone)]
pub struct HidReport {
    /// レポートID（0 = レポートIDなし）
    pub report_id: u8,
    /// レポートタイプ
    pub report_type: u8,
    /// レポートデータ
    pub data: Vec<u8>,
}

impl HidReport {
    /// 新しいレポートを作成
    pub fn new(report_type: u8) -> Self {
        Self {
            report_id: 0,
            report_type,
            data: Vec::new(),
        }
    }

    /// レポートIDを設定
    pub fn with_id(mut self, id: u8) -> Self {
        self.report_id = id;
        self
    }

    /// データを設定
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }
}

// ============================================================================
// HID Descriptor
// ============================================================================

/// HID ディスクリプタ
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct HidDescriptor {
    /// 長さ
    pub length: u8,
    /// ディスクリプタタイプ (0x21)
    pub descriptor_type: u8,
    /// HID仕様バージョン (BCD)
    pub hid_version: u16,
    /// 国コード
    pub country_code: u8,
    /// クラスディスクリプタ数
    pub num_descriptors: u8,
    /// ディスクリプタタイプ (最初のもの、通常はReport)
    pub descriptor_type_1: u8,
    /// ディスクリプタ長（最初のもの）
    pub descriptor_length_1: u16,
}

// ============================================================================
// HID Device (Generic)
// ============================================================================

/// 汎用 HID デバイス
pub struct HidDevice {
    /// スロットID
    slot_id: AtomicU8,
    /// サブクラス
    subclass: HidSubclass,
    /// プロトコル
    protocol: HidProtocol,
    /// INエンドポイント
    in_endpoint: u8,
    /// 現在のプロトコルモード（true = Report, false = Boot）
    report_protocol: AtomicBool,
    /// 最新の入力レポート
    last_report: Mutex<Vec<u8>>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
}

impl HidDevice {
    /// 新しい HID デバイスを作成
    pub fn new(subclass: HidSubclass, protocol: HidProtocol, in_endpoint: u8) -> Self {
        Self {
            slot_id: AtomicU8::new(0),
            subclass,
            protocol,
            in_endpoint,
            report_protocol: AtomicBool::new(true),
            last_report: Mutex::new(Vec::new()),
            initialized: AtomicBool::new(false),
        }
    }

    /// プロトコルを取得
    pub fn protocol(&self) -> HidProtocol {
        self.protocol
    }

    /// Boot Protocol に切り替え
    pub fn set_boot_protocol(&self) -> Result<(), ClassDriverError> {
        // SET_PROTOCOL(0) を送信
        self.report_protocol.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Report Protocol に切り替え
    pub fn set_report_protocol(&self) -> Result<(), ClassDriverError> {
        // SET_PROTOCOL(1) を送信
        self.report_protocol.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// アイドルレートを設定
    pub fn set_idle(&self, _duration: u8, _report_id: u8) -> Result<(), ClassDriverError> {
        // SET_IDLE を送信
        Ok(())
    }

    /// レポートを取得
    pub fn get_report(
        &self,
        report_type: u8,
        report_id: u8,
    ) -> Result<HidReport, ClassDriverError> {
        // GET_REPORT を送信
        let report = HidReport::new(report_type).with_id(report_id);
        Ok(report)
    }

    /// レポートを設定
    pub fn set_report(&self, _report: &HidReport) -> Result<(), ClassDriverError> {
        // SET_REPORT を送信
        Ok(())
    }

    /// 最新のレポートを取得
    pub fn last_report(&self) -> Vec<u8> {
        self.last_report.lock().clone()
    }

    /// レポートを更新（内部用）
    pub fn update_report(&self, data: &[u8]) {
        *self.last_report.lock() = data.to_vec();
    }

    /// GET_REPORT セットアップパケットを構築
    pub fn build_get_report(
        report_type: u8,
        report_id: u8,
        length: u16,
        interface: u8,
    ) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_IN,
            request: HID_GET_REPORT,
            value: ((report_type as u16) << 8) | (report_id as u16),
            index: interface as u16,
            length,
        }
    }

    /// SET_REPORT セットアップパケットを構築
    pub fn build_set_report(
        report_type: u8,
        report_id: u8,
        length: u16,
        interface: u8,
    ) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_OUT,
            request: HID_SET_REPORT,
            value: ((report_type as u16) << 8) | (report_id as u16),
            index: interface as u16,
            length,
        }
    }

    /// SET_IDLE セットアップパケットを構築
    pub fn build_set_idle(duration: u8, report_id: u8, interface: u8) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_OUT,
            request: HID_SET_IDLE,
            value: ((duration as u16) << 8) | (report_id as u16),
            index: interface as u16,
            length: 0,
        }
    }

    /// SET_PROTOCOL セットアップパケットを構築
    pub fn build_set_protocol(protocol: bool, interface: u8) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_OUT,
            request: HID_SET_PROTOCOL,
            value: if protocol { 1 } else { 0 },
            index: interface as u16,
            length: 0,
        }
    }
}

impl UsbClassDriver for HidDevice {
    fn name(&self) -> &'static str {
        "USB HID Device"
    }

    fn class_code(&self) -> UsbClass {
        UsbClass::Hid
    }

    fn probe(&self, class: u8, subclass: u8, protocol: u8) -> bool {
        class == HID_CLASS
            && (subclass == HID_SUBCLASS_NONE || subclass == HID_SUBCLASS_BOOT)
            && (protocol == HID_PROTOCOL_NONE
                || protocol == HID_PROTOCOL_KEYBOARD
                || protocol == HID_PROTOCOL_MOUSE)
    }

    fn init(&mut self, slot_id: u8) -> Result<(), ClassDriverError> {
        self.slot_id.store(slot_id, Ordering::SeqCst);

        // Boot プロトコルの場合、Boot Protocol モードに設定
        if self.subclass == HidSubclass::Boot {
            self.set_boot_protocol()?;
        }

        // アイドルレートを0に設定（変更があった時だけ報告）
        self.set_idle(0, 0)?;

        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn release(&mut self) -> Result<(), ClassDriverError> {
        self.initialized.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn poll(&mut self) -> Result<(), ClassDriverError> {
        // INエンドポイントからデータを読み取り
        // 実際の実装ではxHCIドライバとの連携が必要
        Ok(())
    }

    fn on_event(&mut self, event: ClassDriverEvent) {
        if let ClassDriverEvent::TransferComplete {
            endpoint,
            status,
            bytes_transferred,
        } = event
        {
            if endpoint == self.in_endpoint && status == TransferStatus::Success {
                // レポートを処理
                let _ = bytes_transferred;
            }
        }
    }
}

// ============================================================================
// USB Keyboard
// ============================================================================

/// Boot Protocol キーボードレポート
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct BootKeyboardReport {
    /// 修飾キー
    pub modifiers: u8,
    /// 予約
    pub reserved: u8,
    /// キーコード (最大6キー同時押し)
    pub keycodes: [u8; 6],
}

impl BootKeyboardReport {
    /// 修飾キーが押されているか
    pub fn is_modifier_pressed(&self, modifier: KeyboardModifier) -> bool {
        (self.modifiers & modifier as u8) != 0
    }

    /// 指定されたキーが押されているか
    pub fn is_key_pressed(&self, keycode: u8) -> bool {
        self.keycodes.contains(&keycode)
    }

    /// 押されているキーのリストを取得
    pub fn pressed_keys(&self) -> Vec<u8> {
        self.keycodes.iter().filter(|&&k| k != 0).copied().collect()
    }
}

/// キーボード修飾キー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyboardModifier {
    LeftCtrl = 0x01,
    LeftShift = 0x02,
    LeftAlt = 0x04,
    LeftGui = 0x08,
    RightCtrl = 0x10,
    RightShift = 0x20,
    RightAlt = 0x40,
    RightGui = 0x80,
}

/// USB キーボードドライバ
pub struct UsbKeyboard {
    /// 基本HIDデバイス
    hid: HidDevice,
    /// 前回のレポート
    prev_report: Mutex<BootKeyboardReport>,
    /// LEDステータス
    led_status: AtomicU8,
    /// キー押下コールバック
    key_callback: Mutex<Option<Box<dyn Fn(KeyEvent) + Send + Sync>>>,
}

impl UsbKeyboard {
    /// 新しいキーボードを作成
    pub fn new(in_endpoint: u8) -> Self {
        Self {
            hid: HidDevice::new(HidSubclass::Boot, HidProtocol::Keyboard, in_endpoint),
            prev_report: Mutex::new(BootKeyboardReport::default()),
            led_status: AtomicU8::new(0),
            key_callback: Mutex::new(None),
        }
    }

    /// キーイベントコールバックを設定
    pub fn set_key_callback<F>(&self, callback: F)
    where
        F: Fn(KeyEvent) + Send + Sync + 'static,
    {
        *self.key_callback.lock() = Some(Box::new(callback));
    }

    /// LEDステータスを設定
    pub fn set_leds(
        &self,
        num_lock: bool,
        caps_lock: bool,
        scroll_lock: bool,
    ) -> Result<(), ClassDriverError> {
        let status = (if num_lock { 1 } else { 0 })
            | (if caps_lock { 2 } else { 0 })
            | (if scroll_lock { 4 } else { 0 });

        self.led_status.store(status, Ordering::SeqCst);

        // SET_REPORTでLEDステータスを送信
        let report = HidReport::new(HID_REPORT_TYPE_OUTPUT).with_data(vec![status]);
        self.hid.set_report(&report)
    }

    fn emit_event(
        callback: Option<&dyn Fn(KeyEvent)>,
        boot_keycode: u8,
        state: KeyState,
        modifiers: Modifiers,
    ) {
        let event = KeyEvent {
            key: boot_keycode_to_key_code(boot_keycode),
            state,
            modifiers,
            raw_scancode: USB_RAW_SCANCODE_FLAG | boot_keycode as u16,
        };

        if let Some(callback) = callback {
            callback(event);
        }
        emit_keyboard_event_sink(event);
    }

    fn detect_modifier_changes(
        old: u8,
        new: u8,
        lock_state: u8,
        callback: Option<&dyn Fn(KeyEvent)>,
    ) {
        for (mask, keycode) in [
            (KeyboardModifier::LeftCtrl as u8, keycodes::KEY_LEFT_CTRL),
            (KeyboardModifier::LeftShift as u8, keycodes::KEY_LEFT_SHIFT),
            (KeyboardModifier::LeftAlt as u8, keycodes::KEY_LEFT_ALT),
            (KeyboardModifier::LeftGui as u8, keycodes::KEY_LEFT_GUI),
            (KeyboardModifier::RightCtrl as u8, keycodes::KEY_RIGHT_CTRL),
            (
                KeyboardModifier::RightShift as u8,
                keycodes::KEY_RIGHT_SHIFT,
            ),
            (KeyboardModifier::RightAlt as u8, keycodes::KEY_RIGHT_ALT),
            (KeyboardModifier::RightGui as u8, keycodes::KEY_RIGHT_GUI),
        ] {
            let was_pressed = (old & mask) != 0;
            let is_pressed = (new & mask) != 0;
            if was_pressed == is_pressed {
                continue;
            }

            let state = if is_pressed {
                KeyState::Pressed
            } else {
                KeyState::Released
            };
            let modifiers = modifiers_from_boot_state(new, lock_state);
            Self::emit_event(callback, keycode, state, modifiers);
        }
    }

    fn detect_key_changes(
        old: &[u8; 6],
        new: &[u8; 6],
        lock_state: &mut u8,
        modifiers_byte: u8,
        callback: Option<&dyn Fn(KeyEvent)>,
    ) {
        for &key in new {
            if key == 0 || old.contains(&key) {
                continue;
            }

            if let Some(bit) = lock_bit_for_boot_keycode(key) {
                *lock_state ^= bit;
            }

            let modifiers = modifiers_from_boot_state(modifiers_byte, *lock_state);
            Self::emit_event(callback, key, KeyState::Pressed, modifiers);
        }

        for &key in old {
            if key == 0 || new.contains(&key) {
                continue;
            }

            let modifiers = modifiers_from_boot_state(modifiers_byte, *lock_state);
            Self::emit_event(callback, key, KeyState::Released, modifiers);
        }
    }

    pub fn process_report(&self, data: &[u8]) {
        if data.len() < 8 {
            return;
        }

        let report = BootKeyboardReport {
            modifiers: data[0],
            reserved: data[1],
            keycodes: [data[2], data[3], data[4], data[5], data[6], data[7]],
        };

        let prev = {
            let guard = self.prev_report.lock();
            *guard
        };
        let callback_guard = self.key_callback.lock();
        let callback = callback_guard
            .as_ref()
            .map(|cb| cb.as_ref() as &dyn Fn(KeyEvent));
        let mut lock_state = self.led_status.load(Ordering::Acquire);

        Self::detect_modifier_changes(prev.modifiers, report.modifiers, lock_state, callback);
        Self::detect_key_changes(
            &prev.keycodes,
            &report.keycodes,
            &mut lock_state,
            report.modifiers,
            callback,
        );

        self.led_status.store(lock_state, Ordering::Release);
        *self.prev_report.lock() = report;
    }
}

fn modifiers_from_boot_state(modifiers: u8, lock_state: u8) -> Modifiers {
    Modifiers {
        shift: (modifiers
            & ((KeyboardModifier::LeftShift as u8) | (KeyboardModifier::RightShift as u8)))
            != 0,
        ctrl: (modifiers
            & ((KeyboardModifier::LeftCtrl as u8) | (KeyboardModifier::RightCtrl as u8)))
            != 0,
        alt: (modifiers & (KeyboardModifier::LeftAlt as u8)) != 0,
        alt_gr: (modifiers & (KeyboardModifier::RightAlt as u8)) != 0,
        caps_lock: (lock_state & 0b010) != 0,
        num_lock: (lock_state & 0b001) != 0,
        scroll_lock: (lock_state & 0b100) != 0,
    }
}

fn lock_bit_for_boot_keycode(keycode: u8) -> Option<u8> {
    match keycode {
        keycodes::KEY_CAPS_LOCK => Some(0b010),
        keycodes::KEY_NUM_LOCK => Some(0b001),
        keycodes::KEY_SCROLL_LOCK => Some(0b100),
        _ => None,
    }
}

fn boot_keycode_to_key_code(keycode: u8) -> KeyCode {
    match keycode {
        keycodes::KEY_A => KeyCode::A,
        keycodes::KEY_B => KeyCode::B,
        keycodes::KEY_C => KeyCode::C,
        keycodes::KEY_D => KeyCode::D,
        keycodes::KEY_E => KeyCode::E,
        keycodes::KEY_F => KeyCode::F,
        keycodes::KEY_G => KeyCode::G,
        keycodes::KEY_H => KeyCode::H,
        keycodes::KEY_I => KeyCode::I,
        keycodes::KEY_J => KeyCode::J,
        keycodes::KEY_K => KeyCode::K,
        keycodes::KEY_L => KeyCode::L,
        keycodes::KEY_M => KeyCode::M,
        keycodes::KEY_N => KeyCode::N,
        keycodes::KEY_O => KeyCode::O,
        keycodes::KEY_P => KeyCode::P,
        keycodes::KEY_Q => KeyCode::Q,
        keycodes::KEY_R => KeyCode::R,
        keycodes::KEY_S => KeyCode::S,
        keycodes::KEY_T => KeyCode::T,
        keycodes::KEY_U => KeyCode::U,
        keycodes::KEY_V => KeyCode::V,
        keycodes::KEY_W => KeyCode::W,
        keycodes::KEY_X => KeyCode::X,
        keycodes::KEY_Y => KeyCode::Y,
        keycodes::KEY_Z => KeyCode::Z,
        keycodes::KEY_1 => KeyCode::Key1,
        keycodes::KEY_2 => KeyCode::Key2,
        keycodes::KEY_3 => KeyCode::Key3,
        keycodes::KEY_4 => KeyCode::Key4,
        keycodes::KEY_5 => KeyCode::Key5,
        keycodes::KEY_6 => KeyCode::Key6,
        keycodes::KEY_7 => KeyCode::Key7,
        keycodes::KEY_8 => KeyCode::Key8,
        keycodes::KEY_9 => KeyCode::Key9,
        keycodes::KEY_0 => KeyCode::Key0,
        keycodes::KEY_ENTER => KeyCode::Enter,
        keycodes::KEY_ESC => KeyCode::Escape,
        keycodes::KEY_BACKSPACE => KeyCode::Backspace,
        keycodes::KEY_TAB => KeyCode::Tab,
        keycodes::KEY_SPACE => KeyCode::Space,
        keycodes::KEY_MINUS => KeyCode::Minus,
        keycodes::KEY_EQUAL => KeyCode::Equals,
        keycodes::KEY_LEFT_BRACKET => KeyCode::LeftBracket,
        keycodes::KEY_RIGHT_BRACKET => KeyCode::RightBracket,
        keycodes::KEY_BACKSLASH => KeyCode::Backslash,
        keycodes::KEY_SEMICOLON => KeyCode::Semicolon,
        keycodes::KEY_APOSTROPHE => KeyCode::Quote,
        keycodes::KEY_GRAVE => KeyCode::BackTick,
        keycodes::KEY_COMMA => KeyCode::Comma,
        keycodes::KEY_DOT => KeyCode::Period,
        keycodes::KEY_SLASH => KeyCode::Slash,
        keycodes::KEY_CAPS_LOCK => KeyCode::CapsLock,
        keycodes::KEY_F1 => KeyCode::F1,
        keycodes::KEY_F2 => KeyCode::F2,
        keycodes::KEY_F3 => KeyCode::F3,
        keycodes::KEY_F4 => KeyCode::F4,
        keycodes::KEY_F5 => KeyCode::F5,
        keycodes::KEY_F6 => KeyCode::F6,
        keycodes::KEY_F7 => KeyCode::F7,
        keycodes::KEY_F8 => KeyCode::F8,
        keycodes::KEY_F9 => KeyCode::F9,
        keycodes::KEY_F10 => KeyCode::F10,
        keycodes::KEY_F11 => KeyCode::F11,
        keycodes::KEY_F12 => KeyCode::F12,
        keycodes::KEY_SCROLL_LOCK => KeyCode::ScrollLock,
        keycodes::KEY_INSERT => KeyCode::Insert,
        keycodes::KEY_HOME => KeyCode::Home,
        keycodes::KEY_PAGE_UP => KeyCode::PageUp,
        keycodes::KEY_DELETE => KeyCode::Delete,
        keycodes::KEY_END => KeyCode::End,
        keycodes::KEY_PAGE_DOWN => KeyCode::PageDown,
        keycodes::KEY_RIGHT_ARROW => KeyCode::Right,
        keycodes::KEY_LEFT_ARROW => KeyCode::Left,
        keycodes::KEY_DOWN_ARROW => KeyCode::Down,
        keycodes::KEY_UP_ARROW => KeyCode::Up,
        keycodes::KEY_NUM_LOCK => KeyCode::NumLock,
        keycodes::KEY_LEFT_CTRL => KeyCode::LeftCtrl,
        keycodes::KEY_LEFT_SHIFT => KeyCode::LeftShift,
        keycodes::KEY_LEFT_ALT => KeyCode::LeftAlt,
        keycodes::KEY_LEFT_GUI => KeyCode::Unknown,
        keycodes::KEY_RIGHT_CTRL => KeyCode::Unknown,
        keycodes::KEY_RIGHT_SHIFT => KeyCode::RightShift,
        keycodes::KEY_RIGHT_ALT => KeyCode::Unknown,
        keycodes::KEY_RIGHT_GUI => KeyCode::Unknown,
        _ => KeyCode::Unknown,
    }
}

// ============================================================================
// USB Mouse
// ============================================================================

/// Boot Protocol マウスレポート
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct BootMouseReport {
    /// ボタン状態
    pub buttons: u8,
    /// X移動量（符号付き）
    pub x: i8,
    /// Y移動量（符号付き）
    pub y: i8,
}

impl BootMouseReport {
    /// 左ボタンが押されているか
    pub fn left_button(&self) -> bool {
        (self.buttons & 0x01) != 0
    }

    /// 右ボタンが押されているか
    pub fn right_button(&self) -> bool {
        (self.buttons & 0x02) != 0
    }

    /// 中ボタンが押されているか
    pub fn middle_button(&self) -> bool {
        (self.buttons & 0x04) != 0
    }
}

/// マウスボタン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseButton {
    Left = 0x01,
    Right = 0x02,
    Middle = 0x04,
    Button4 = 0x08,
    Button5 = 0x10,
}

/// USB マウスドライバ
pub struct UsbMouse {
    /// 前回のボタン状態
    prev_buttons: AtomicU8,
    /// 累積X移動量
    accumulated_x: Mutex<i32>,
    /// 累積Y移動量
    accumulated_y: Mutex<i32>,
    /// ホイール移動量
    accumulated_wheel: Mutex<i32>,
    /// マウスイベントコールバック
    mouse_callback: Mutex<Option<Box<dyn Fn(MouseEvent) + Send + Sync>>>,
}

/// マウスイベント
#[derive(Debug, Clone)]
pub enum MouseEvent {
    /// 移動
    Move { dx: i32, dy: i32 },
    /// ボタン押下
    ButtonDown(MouseButton),
    /// ボタン解放
    ButtonUp(MouseButton),
    /// ホイールスクロール
    Wheel(i32),
}

impl UsbMouse {
    /// 新しいマウスを作成
    pub fn new() -> Self {
        Self {
            prev_buttons: AtomicU8::new(0),
            accumulated_x: Mutex::new(0),
            accumulated_y: Mutex::new(0),
            accumulated_wheel: Mutex::new(0),
            mouse_callback: Mutex::new(None),
        }
    }

    /// マウスイベントコールバックを設定
    pub fn set_mouse_callback<F>(&self, callback: F)
    where
        F: Fn(MouseEvent) + Send + Sync + 'static,
    {
        *self.mouse_callback.lock() = Some(Box::new(callback));
    }

    /// 累積移動量を取得してリセット
    pub fn get_and_reset_movement(&self) -> (i32, i32) {
        let x = core::mem::replace(&mut *self.accumulated_x.lock(), 0);
        let y = core::mem::replace(&mut *self.accumulated_y.lock(), 0);
        (x, y)
    }

    /// レポートを処理
    pub fn process_report(&self, data: &[u8]) {
        if data.len() < 3 {
            return;
        }

        let (buttons, dx, dy, wheel) = Self::parse_report_data(data);

        // 移動量を累積
        *self.accumulated_x.lock() += dx;
        *self.accumulated_y.lock() += dy;
        *self.accumulated_wheel.lock() += wheel;

        let prev_buttons = self.prev_buttons.swap(buttons, Ordering::SeqCst);

        if let Some(ref callback) = *self.mouse_callback.lock() {
            // 移動イベント
            if dx != 0 || dy != 0 {
                callback(MouseEvent::Move { dx, dy });
            }

            // ボタンイベント
            for &(bit, button) in &[
                (0x01, MouseButton::Left),
                (0x02, MouseButton::Right),
                (0x04, MouseButton::Middle),
                (0x08, MouseButton::Button4),
                (0x10, MouseButton::Button5),
            ] {
                if let Some(event) = Self::button_event(buttons, prev_buttons, bit, button) {
                    callback(event);
                }
            }

            // ホイールイベント
            if wheel != 0 {
                callback(MouseEvent::Wheel(wheel));
            }
        }
    }

    /// Decode raw HID report bytes into (buttons, dx, dy, wheel).
    fn parse_report_data(data: &[u8]) -> (u8, i32, i32, i32) {
        let buttons = data[0];
        let dx = data[1] as i8 as i32;
        let dy = data[2] as i8 as i32;
        let wheel = if data.len() > 3 {
            data[3] as i8 as i32
        } else {
            0
        };
        (buttons, dx, dy, wheel)
    }

    /// Determine the mouse event for a single button, if its state changed.
    fn button_event(buttons: u8, prev: u8, bit: u8, button: MouseButton) -> Option<MouseEvent> {
        if (buttons & bit) != 0 && (prev & bit) == 0 {
            Some(MouseEvent::ButtonDown(button))
        } else if (buttons & bit) == 0 && (prev & bit) != 0 {
            Some(MouseEvent::ButtonUp(button))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use spin::Mutex;

    #[test]
    fn usb_boot_keycode_translation_smoke() {
        assert_eq!(boot_keycode_to_key_code(keycodes::KEY_A), KeyCode::A);
        assert_eq!(
            boot_keycode_to_key_code(keycodes::KEY_ENTER),
            KeyCode::Enter
        );
        assert_eq!(
            boot_keycode_to_key_code(keycodes::KEY_LEFT_ARROW),
            KeyCode::Left
        );
    }

    #[test]
    fn usb_keyboard_process_report_emits_modifier_and_key_events() {
        let keyboard = UsbKeyboard::new(1);
        let events = Arc::new(Mutex::new(Vec::<KeyEvent>::new()));
        let sink = Arc::clone(&events);

        keyboard.set_key_callback(move |event| {
            sink.lock().push(event);
        });

        keyboard.process_report(&[
            KeyboardModifier::LeftShift as u8,
            0,
            keycodes::KEY_A,
            0,
            0,
            0,
            0,
            0,
        ]);

        let events = events.lock();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].key, KeyCode::LeftShift);
        assert_eq!(events[0].state, KeyState::Pressed);
        assert!(events[0].modifiers.shift);
        assert_eq!(events[1].key, KeyCode::A);
        assert_eq!(events[1].state, KeyState::Pressed);
        assert!(events[1].modifiers.shift);
    }
}
