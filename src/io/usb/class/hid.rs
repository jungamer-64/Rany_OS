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

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;

use super::{
    ClassDriverError, ClassDriverEvent, SetupPacket, TransferStatus, UsbClass, UsbClassDriver,
    REQUEST_DIR_IN, REQUEST_DIR_OUT, REQUEST_TYPE_CLASS_INTERFACE,
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
    /// インターフェース番号
    interface: u8,
    /// サブクラス
    subclass: HidSubclass,
    /// プロトコル
    protocol: HidProtocol,
    /// INエンドポイント
    in_endpoint: u8,
    /// OUTエンドポイント（オプション）
    out_endpoint: Option<u8>,
    /// 現在のプロトコルモード（true = Report, false = Boot）
    report_protocol: AtomicBool,
    /// レポートディスクリプタ
    report_descriptor: Mutex<Vec<u8>>,
    /// 最新の入力レポート
    last_report: Mutex<Vec<u8>>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
}

impl HidDevice {
    /// 新しい HID デバイスを作成
    pub fn new(
        interface: u8,
        subclass: HidSubclass,
        protocol: HidProtocol,
        in_endpoint: u8,
        out_endpoint: Option<u8>,
    ) -> Self {
        Self {
            slot_id: AtomicU8::new(0),
            interface,
            subclass,
            protocol,
            in_endpoint,
            out_endpoint,
            report_protocol: AtomicBool::new(true),
            report_descriptor: Mutex::new(Vec::new()),
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
    pub fn get_report(&self, report_type: u8, report_id: u8) -> Result<HidReport, ClassDriverError> {
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
    pub fn build_get_report(report_type: u8, report_id: u8, length: u16, interface: u8) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_IN,
            request: HID_GET_REPORT,
            value: ((report_type as u16) << 8) | (report_id as u16),
            index: interface as u16,
            length,
        }
    }
    
    /// SET_REPORT セットアップパケットを構築
    pub fn build_set_report(report_type: u8, report_id: u8, length: u16, interface: u8) -> SetupPacket {
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
        if let ClassDriverEvent::TransferComplete { endpoint, status, bytes_transferred } = event {
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
        self.keycodes.iter()
            .filter(|&&k| k != 0)
            .copied()
            .collect()
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
    key_callback: Mutex<Option<Box<dyn Fn(u8, bool) + Send + Sync>>>,
}

impl UsbKeyboard {
    /// 新しいキーボードを作成
    pub fn new(interface: u8, in_endpoint: u8, out_endpoint: Option<u8>) -> Self {
        Self {
            hid: HidDevice::new(
                interface,
                HidSubclass::Boot,
                HidProtocol::Keyboard,
                in_endpoint,
                out_endpoint,
            ),
            prev_report: Mutex::new(BootKeyboardReport::default()),
            led_status: AtomicU8::new(0),
            key_callback: Mutex::new(None),
        }
    }
    
    /// キーイベントコールバックを設定
    pub fn set_key_callback<F>(&self, callback: F)
    where
        F: Fn(u8, bool) + Send + Sync + 'static,
    {
        *self.key_callback.lock() = Some(Box::new(callback));
    }
    
    /// LEDステータスを設定
    pub fn set_leds(&self, num_lock: bool, caps_lock: bool, scroll_lock: bool) -> Result<(), ClassDriverError> {
        let status = (if num_lock { 1 } else { 0 })
            | (if caps_lock { 2 } else { 0 })
            | (if scroll_lock { 4 } else { 0 });
        
        self.led_status.store(status, Ordering::SeqCst);
        
        // SET_REPORTでLEDステータスを送信
        let report = HidReport::new(HID_REPORT_TYPE_OUTPUT).with_data(vec![status]);
        self.hid.set_report(&report)
    }
    
    /// レポートを処理
    pub fn process_report(&self, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        
        let report = BootKeyboardReport {
            modifiers: data[0],
            reserved: data[1],
            keycodes: [data[2], data[3], data[4], data[5], data[6], data[7]],
        };
        
        let prev = *self.prev_report.lock();
        
        // キー押下/解放を検出
        if let Some(ref callback) = *self.key_callback.lock() {
            // 新しく押されたキー
            for &keycode in &report.keycodes {
                if keycode != 0 && !prev.keycodes.contains(&keycode) {
                    callback(keycode, true);
                }
            }
            
            // 解放されたキー
            for &keycode in &prev.keycodes {
                if keycode != 0 && !report.keycodes.contains(&keycode) {
                    callback(keycode, false);
                }
            }
        }
        
        *self.prev_report.lock() = report;
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
    /// 基本HIDデバイス
    hid: HidDevice,
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
    pub fn new(interface: u8, in_endpoint: u8) -> Self {
        Self {
            hid: HidDevice::new(
                interface,
                HidSubclass::Boot,
                HidProtocol::Mouse,
                in_endpoint,
                None,
            ),
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
        
        let buttons = data[0];
        let dx = data[1] as i8 as i32;
        let dy = data[2] as i8 as i32;
        let wheel = if data.len() > 3 { data[3] as i8 as i32 } else { 0 };
        
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
            for (bit, button) in [
                (0x01, MouseButton::Left),
                (0x02, MouseButton::Right),
                (0x04, MouseButton::Middle),
                (0x08, MouseButton::Button4),
                (0x10, MouseButton::Button5),
            ] {
                if (buttons & bit) != 0 && (prev_buttons & bit) == 0 {
                    callback(MouseEvent::ButtonDown(button));
                } else if (buttons & bit) == 0 && (prev_buttons & bit) != 0 {
                    callback(MouseEvent::ButtonUp(button));
                }
            }
            
            // ホイールイベント
            if wheel != 0 {
                callback(MouseEvent::Wheel(wheel));
            }
        }
    }
}

// ============================================================================
// Key Code Constants
// ============================================================================

/// USB HID キーコード
pub mod keycodes {
    pub const KEY_A: u8 = 0x04;
    pub const KEY_B: u8 = 0x05;
    pub const KEY_C: u8 = 0x06;
    pub const KEY_D: u8 = 0x07;
    pub const KEY_E: u8 = 0x08;
    pub const KEY_F: u8 = 0x09;
    pub const KEY_G: u8 = 0x0A;
    pub const KEY_H: u8 = 0x0B;
    pub const KEY_I: u8 = 0x0C;
    pub const KEY_J: u8 = 0x0D;
    pub const KEY_K: u8 = 0x0E;
    pub const KEY_L: u8 = 0x0F;
    pub const KEY_M: u8 = 0x10;
    pub const KEY_N: u8 = 0x11;
    pub const KEY_O: u8 = 0x12;
    pub const KEY_P: u8 = 0x13;
    pub const KEY_Q: u8 = 0x14;
    pub const KEY_R: u8 = 0x15;
    pub const KEY_S: u8 = 0x16;
    pub const KEY_T: u8 = 0x17;
    pub const KEY_U: u8 = 0x18;
    pub const KEY_V: u8 = 0x19;
    pub const KEY_W: u8 = 0x1A;
    pub const KEY_X: u8 = 0x1B;
    pub const KEY_Y: u8 = 0x1C;
    pub const KEY_Z: u8 = 0x1D;
    pub const KEY_1: u8 = 0x1E;
    pub const KEY_2: u8 = 0x1F;
    pub const KEY_3: u8 = 0x20;
    pub const KEY_4: u8 = 0x21;
    pub const KEY_5: u8 = 0x22;
    pub const KEY_6: u8 = 0x23;
    pub const KEY_7: u8 = 0x24;
    pub const KEY_8: u8 = 0x25;
    pub const KEY_9: u8 = 0x26;
    pub const KEY_0: u8 = 0x27;
    pub const KEY_ENTER: u8 = 0x28;
    pub const KEY_ESC: u8 = 0x29;
    pub const KEY_BACKSPACE: u8 = 0x2A;
    pub const KEY_TAB: u8 = 0x2B;
    pub const KEY_SPACE: u8 = 0x2C;
    pub const KEY_MINUS: u8 = 0x2D;
    pub const KEY_EQUAL: u8 = 0x2E;
    pub const KEY_LEFT_BRACKET: u8 = 0x2F;
    pub const KEY_RIGHT_BRACKET: u8 = 0x30;
    pub const KEY_BACKSLASH: u8 = 0x31;
    pub const KEY_SEMICOLON: u8 = 0x33;
    pub const KEY_APOSTROPHE: u8 = 0x34;
    pub const KEY_GRAVE: u8 = 0x35;
    pub const KEY_COMMA: u8 = 0x36;
    pub const KEY_DOT: u8 = 0x37;
    pub const KEY_SLASH: u8 = 0x38;
    pub const KEY_CAPS_LOCK: u8 = 0x39;
    pub const KEY_F1: u8 = 0x3A;
    pub const KEY_F2: u8 = 0x3B;
    pub const KEY_F3: u8 = 0x3C;
    pub const KEY_F4: u8 = 0x3D;
    pub const KEY_F5: u8 = 0x3E;
    pub const KEY_F6: u8 = 0x3F;
    pub const KEY_F7: u8 = 0x40;
    pub const KEY_F8: u8 = 0x41;
    pub const KEY_F9: u8 = 0x42;
    pub const KEY_F10: u8 = 0x43;
    pub const KEY_F11: u8 = 0x44;
    pub const KEY_F12: u8 = 0x45;
    pub const KEY_PRINT_SCREEN: u8 = 0x46;
    pub const KEY_SCROLL_LOCK: u8 = 0x47;
    pub const KEY_PAUSE: u8 = 0x48;
    pub const KEY_INSERT: u8 = 0x49;
    pub const KEY_HOME: u8 = 0x4A;
    pub const KEY_PAGE_UP: u8 = 0x4B;
    pub const KEY_DELETE: u8 = 0x4C;
    pub const KEY_END: u8 = 0x4D;
    pub const KEY_PAGE_DOWN: u8 = 0x4E;
    pub const KEY_RIGHT_ARROW: u8 = 0x4F;
    pub const KEY_LEFT_ARROW: u8 = 0x50;
    pub const KEY_DOWN_ARROW: u8 = 0x51;
    pub const KEY_UP_ARROW: u8 = 0x52;
    pub const KEY_NUM_LOCK: u8 = 0x53;
}
