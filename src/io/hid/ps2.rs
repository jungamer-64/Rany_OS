// ============================================================================
// src/io/ps2.rs - PS/2 Controller Driver
// ============================================================================
//!
//! # PS/2 Controller Driver
//!
//! PS/2キーボード・マウスコントローラのドライバ。
//!
//! ## 機能
//! - PS/2キーボード入力処理
//! - PS/2マウス入力処理
//! - ホットプラグ検出
//! - スキャンコードセット2のサポート

#![allow(dead_code)]

use alloc::collections::VecDeque;
use spin::Mutex;

// ============================================================================
// PS/2 Constants
// ============================================================================

/// PS/2コントローラI/Oポート
pub mod ports {
    pub const DATA: u16 = 0x60; // データポート
    pub const STATUS: u16 = 0x64; // ステータス（読み取り）
    pub const COMMAND: u16 = 0x64; // コマンド（書き込み）
}

/// ステータスレジスタビット
pub mod status {
    pub const OUTPUT_FULL: u8 = 0x01; // 出力バッファフル
    pub const INPUT_FULL: u8 = 0x02; // 入力バッファフル
    pub const SYSTEM: u8 = 0x04; // システムフラグ
    pub const COMMAND: u8 = 0x08; // コマンド/データ
    pub const TIMEOUT: u8 = 0x40; // タイムアウトエラー
    pub const PARITY: u8 = 0x80; // パリティエラー
}

/// PS/2コントローラコマンド
pub mod commands {
    pub const READ_CONFIG: u8 = 0x20; // 設定バイト読み取り
    pub const WRITE_CONFIG: u8 = 0x60; // 設定バイト書き込み
    pub const DISABLE_PORT2: u8 = 0xA7; // ポート2無効化
    pub const ENABLE_PORT2: u8 = 0xA8; // ポート2有効化
    pub const TEST_PORT2: u8 = 0xA9; // ポート2テスト
    pub const SELF_TEST: u8 = 0xAA; // セルフテスト
    pub const TEST_PORT1: u8 = 0xAB; // ポート1テスト
    pub const DISABLE_PORT1: u8 = 0xAD; // ポート1無効化
    pub const ENABLE_PORT1: u8 = 0xAE; // ポート1有効化
    pub const READ_OUTPUT: u8 = 0xD0; // 出力ポート読み取り
    pub const WRITE_OUTPUT: u8 = 0xD1; // 出力ポート書き込み
    pub const WRITE_PORT2: u8 = 0xD4; // ポート2にデータ送信
}

/// キーボードコマンド
pub mod kbd_commands {
    pub const SET_LEDS: u8 = 0xED; // LED設定
    pub const ECHO: u8 = 0xEE; // エコー
    pub const GET_SET_SCANCODE: u8 = 0xF0; // スキャンコードセット取得/設定
    pub const IDENTIFY: u8 = 0xF2; // デバイス識別
    pub const SET_RATE: u8 = 0xF3; // タイプマティックレート設定
    pub const ENABLE_SCAN: u8 = 0xF4; // スキャン有効化
    pub const DISABLE_SCAN: u8 = 0xF5; // スキャン無効化
    pub const SET_DEFAULTS: u8 = 0xF6; // デフォルト設定
    pub const RESEND: u8 = 0xFE; // 再送
    pub const RESET: u8 = 0xFF; // リセット
}

/// マウスコマンド
pub mod mouse_commands {
    pub const SET_SCALING_1_1: u8 = 0xE6; // 1:1スケーリング
    pub const SET_SCALING_2_1: u8 = 0xE7; // 2:1スケーリング
    pub const SET_RESOLUTION: u8 = 0xE8; // 解像度設定
    pub const GET_STATUS: u8 = 0xE9; // ステータス取得
    pub const SET_STREAM: u8 = 0xEA; // ストリームモード
    pub const READ_DATA: u8 = 0xEB; // データ読み取り
    pub const RESET_WRAP: u8 = 0xEC; // ラップモードリセット
    pub const SET_WRAP: u8 = 0xEE; // ラップモード設定
    pub const SET_REMOTE: u8 = 0xF0; // リモートモード
    pub const GET_ID: u8 = 0xF2; // デバイスID取得
    pub const SET_SAMPLE_RATE: u8 = 0xF3; // サンプルレート設定
    pub const ENABLE_DATA: u8 = 0xF4; // データレポート有効化
    pub const DISABLE_DATA: u8 = 0xF5; // データレポート無効化
    pub const SET_DEFAULTS: u8 = 0xF6; // デフォルト設定
    pub const RESEND: u8 = 0xFE; // 再送
    pub const RESET: u8 = 0xFF; // リセット
}

// ============================================================================
// Keyboard Scancode
// ============================================================================

/// キーコード（仮想キーコード）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCode(pub u8);

impl KeyCode {
    // 特殊キー
    pub const ESCAPE: Self = Self(0x01);
    pub const BACKSPACE: Self = Self(0x0E);
    pub const TAB: Self = Self(0x0F);
    pub const ENTER: Self = Self(0x1C);
    pub const LEFT_CTRL: Self = Self(0x1D);
    pub const LEFT_SHIFT: Self = Self(0x2A);
    pub const RIGHT_SHIFT: Self = Self(0x36);
    pub const LEFT_ALT: Self = Self(0x38);
    pub const SPACE: Self = Self(0x39);
    pub const CAPS_LOCK: Self = Self(0x3A);
    pub const F1: Self = Self(0x3B);
    pub const F2: Self = Self(0x3C);
    pub const F3: Self = Self(0x3D);
    pub const F4: Self = Self(0x3E);
    pub const F5: Self = Self(0x3F);
    pub const F6: Self = Self(0x40);
    pub const F7: Self = Self(0x41);
    pub const F8: Self = Self(0x42);
    pub const F9: Self = Self(0x43);
    pub const F10: Self = Self(0x44);
    pub const NUM_LOCK: Self = Self(0x45);
    pub const SCROLL_LOCK: Self = Self(0x46);
    pub const F11: Self = Self(0x57);
    pub const F12: Self = Self(0x58);

    // 拡張キー（E0プレフィックス）
    pub const INSERT: Self = Self(0x52);
    pub const DELETE: Self = Self(0x53);
    pub const HOME: Self = Self(0x47);
    pub const END: Self = Self(0x4F);
    pub const PAGE_UP: Self = Self(0x49);
    pub const PAGE_DOWN: Self = Self(0x51);
    pub const UP: Self = Self(0x48);
    pub const DOWN: Self = Self(0x50);
    pub const LEFT: Self = Self(0x4B);
    pub const RIGHT: Self = Self(0x4D);
    pub const RIGHT_CTRL: Self = Self(0x9D);
    pub const RIGHT_ALT: Self = Self(0xB8);
}

/// キーイベント
#[derive(Clone, Copy, Debug)]
pub struct KeyEvent {
    /// キーコード
    pub code: KeyCode,
    /// 押下（true）または解放（false）
    pub pressed: bool,
    /// 拡張キーか
    pub extended: bool,
}

/// 修飾キー状態
#[derive(Clone, Copy, Debug, Default)]
pub struct Modifiers {
    pub left_shift: bool,
    pub right_shift: bool,
    pub left_ctrl: bool,
    pub right_ctrl: bool,
    pub left_alt: bool,
    pub right_alt: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl Modifiers {
    pub fn shift(&self) -> bool {
        self.left_shift || self.right_shift
    }

    pub fn ctrl(&self) -> bool {
        self.left_ctrl || self.right_ctrl
    }

    pub fn alt(&self) -> bool {
        self.left_alt || self.right_alt
    }
}

// ============================================================================
// Mouse Event
// ============================================================================

/// マウスボタン
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Button4,
    Button5,
}

/// マウスイベント
#[derive(Clone, Copy, Debug)]
pub struct MouseEvent {
    /// X移動量
    pub dx: i16,
    /// Y移動量
    pub dy: i16,
    /// ホイール移動量
    pub wheel: i8,
    /// ボタン状態
    pub buttons: u8,
}

impl MouseEvent {
    /// ボタンが押されているか
    pub fn is_pressed(&self, button: MouseButton) -> bool {
        let bit = match button {
            MouseButton::Left => 0,
            MouseButton::Right => 1,
            MouseButton::Middle => 2,
            MouseButton::Button4 => 3,
            MouseButton::Button5 => 4,
        };
        (self.buttons & (1 << bit)) != 0
    }
}

// ============================================================================
// PS/2 Controller
// ============================================================================

/// PS/2コントローラ
pub struct Ps2Controller {
    /// デュアルチャネルサポート
    dual_channel: bool,
    /// ポート1（キーボード）デバイスタイプ
    port1_type: Option<DeviceType>,
    /// ポート2（マウス）デバイスタイプ
    port2_type: Option<DeviceType>,
    /// 設定バイト
    config: u8,
}

/// PS/2デバイスタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Unknown,
    AtKeyboard,
    MfKeyboard,
    StandardMouse,
    ScrollMouse,
    FiveButtonMouse,
}

impl Ps2Controller {
    /// 新しいPS/2コントローラを作成
    fn new() -> Self {
        Self {
            dual_channel: false,
            port1_type: None,
            port2_type: None,
            config: 0,
        }
    }

    /// ステータスレジスタを読み取り
    #[inline]
    fn read_status(&self) -> u8 {
        unsafe {
            let value: u8;
            core::arch::asm!("in al, dx", out("al") value, in("dx") ports::STATUS, options(nomem, nostack));
            value
        }
    }

    /// 出力バッファが空になるまで待機
    fn wait_output(&self) -> bool {
        for _ in 0..100_000 {
            if (self.read_status() & status::OUTPUT_FULL) != 0 {
                return true;
            }
        }
        false
    }

    /// 入力バッファが空になるまで待機
    fn wait_input(&self) -> bool {
        for _ in 0..100_000 {
            if (self.read_status() & status::INPUT_FULL) == 0 {
                return true;
            }
        }
        false
    }

    /// データポートから読み取り
    fn read_data(&self) -> u8 {
        self.wait_output();
        unsafe {
            let value: u8;
            core::arch::asm!("in al, dx", out("al") value, in("dx") ports::DATA, options(nomem, nostack));
            value
        }
    }

    /// データポートに書き込み
    fn write_data(&self, value: u8) {
        self.wait_input();
        unsafe {
            core::arch::asm!("out dx, al", in("dx") ports::DATA, in("al") value, options(nomem, nostack));
        }
    }

    /// コマンドポートに書き込み
    fn write_command(&self, cmd: u8) {
        self.wait_input();
        unsafe {
            core::arch::asm!("out dx, al", in("dx") ports::COMMAND, in("al") cmd, options(nomem, nostack));
        }
    }

    /// 設定バイトを読み取り
    fn read_config(&mut self) -> u8 {
        self.write_command(commands::READ_CONFIG);
        let config = self.read_data();
        self.config = config;
        config
    }

    /// 設定バイトを書き込み
    fn write_config(&mut self, config: u8) {
        self.write_command(commands::WRITE_CONFIG);
        self.write_data(config);
        self.config = config;
    }

    /// セルフテスト
    fn self_test(&self) -> bool {
        self.write_command(commands::SELF_TEST);
        self.wait_output();
        self.read_data() == 0x55
    }

    /// ポート1テスト
    fn test_port1(&self) -> bool {
        self.write_command(commands::TEST_PORT1);
        self.wait_output();
        self.read_data() == 0x00
    }

    /// ポート2テスト
    fn test_port2(&self) -> bool {
        self.write_command(commands::TEST_PORT2);
        self.wait_output();
        self.read_data() == 0x00
    }

    /// ポート1（キーボード）にコマンド送信
    fn send_port1(&self, cmd: u8) -> Option<u8> {
        self.write_data(cmd);
        self.wait_output();
        let response = self.read_data();
        if response == 0xFA {
            // ACK
            Some(response)
        } else if response == 0xFE {
            // RESEND
            // リトライ
            self.write_data(cmd);
            self.wait_output();
            Some(self.read_data())
        } else {
            Some(response)
        }
    }

    /// ポート2（マウス）にコマンド送信
    fn send_port2(&self, cmd: u8) -> Option<u8> {
        self.write_command(commands::WRITE_PORT2);
        self.write_data(cmd);
        self.wait_output();
        let response = self.read_data();
        if response == 0xFA {
            Some(response)
        } else if response == 0xFE {
            self.write_command(commands::WRITE_PORT2);
            self.write_data(cmd);
            self.wait_output();
            Some(self.read_data())
        } else {
            Some(response)
        }
    }

    /// デバイス識別
    fn identify_device(&self, port2: bool) -> Option<DeviceType> {
        let send = if port2 {
            Self::send_port2
        } else {
            Self::send_port1
        };

        // IDENTIFYコマンド送信
        if send(self, kbd_commands::IDENTIFY) != Some(0xFA) {
            return None;
        }

        // 最初のバイトを読み取り
        if !self.wait_output() {
            return None;
        }
        let byte1 = self.read_data();

        // デバイスタイプを判定
        match byte1 {
            0x00 => Some(DeviceType::StandardMouse),
            0x03 => Some(DeviceType::ScrollMouse),
            0x04 => Some(DeviceType::FiveButtonMouse),
            0xAB => {
                // キーボード - 2バイト目を読み取り
                if self.wait_output() {
                    let byte2 = self.read_data();
                    match byte2 {
                        0x41 | 0xC1 => Some(DeviceType::MfKeyboard),
                        0x83 => Some(DeviceType::MfKeyboard),
                        _ => Some(DeviceType::AtKeyboard),
                    }
                } else {
                    Some(DeviceType::AtKeyboard)
                }
            }
            _ => Some(DeviceType::Unknown),
        }
    }

    /// キーボードを初期化
    fn init_keyboard(&self) -> bool {
        // リセット
        if self.send_port1(kbd_commands::RESET) != Some(0xFA) {
            return false;
        }
        // BAT完了を待機
        self.wait_output();
        if self.read_data() != 0xAA {
            return false;
        }

        // スキャンコードセット2を設定
        self.send_port1(kbd_commands::GET_SET_SCANCODE);
        self.send_port1(0x02);

        // スキャン有効化
        self.send_port1(kbd_commands::ENABLE_SCAN);

        true
    }

    /// マウスを初期化
    fn init_mouse(&self) -> Option<DeviceType> {
        // リセット
        if self.send_port2(mouse_commands::RESET) != Some(0xFA) {
            return None;
        }
        // BAT完了を待機
        self.wait_output();
        if self.read_data() != 0xAA {
            return None;
        }
        // デバイスIDを読み飛ばし
        self.wait_output();
        let _ = self.read_data();

        // IntelliMouseプロトコルの有効化を試行
        self.send_port2(mouse_commands::SET_SAMPLE_RATE);
        self.send_port2(200);
        self.send_port2(mouse_commands::SET_SAMPLE_RATE);
        self.send_port2(100);
        self.send_port2(mouse_commands::SET_SAMPLE_RATE);
        self.send_port2(80);

        // デバイスIDを確認
        self.send_port2(mouse_commands::GET_ID);
        self.wait_output();
        let device_id = self.read_data();

        let device_type = match device_id {
            0x00 => DeviceType::StandardMouse,
            0x03 => {
                // 5ボタンマウスの有効化を試行
                self.send_port2(mouse_commands::SET_SAMPLE_RATE);
                self.send_port2(200);
                self.send_port2(mouse_commands::SET_SAMPLE_RATE);
                self.send_port2(200);
                self.send_port2(mouse_commands::SET_SAMPLE_RATE);
                self.send_port2(80);

                self.send_port2(mouse_commands::GET_ID);
                self.wait_output();
                let device_id2 = self.read_data();

                if device_id2 == 0x04 {
                    DeviceType::FiveButtonMouse
                } else {
                    DeviceType::ScrollMouse
                }
            }
            0x04 => DeviceType::FiveButtonMouse,
            _ => DeviceType::Unknown,
        };

        // データレポート有効化
        self.send_port2(mouse_commands::ENABLE_DATA);

        Some(device_type)
    }

    /// コントローラを初期化
    pub fn initialize(&mut self) -> bool {
        // 両ポートを無効化
        self.write_command(commands::DISABLE_PORT1);
        self.write_command(commands::DISABLE_PORT2);

        // 出力バッファをフラッシュ
        while (self.read_status() & status::OUTPUT_FULL) != 0 {
            let _ = self.read_data();
        }

        // 設定バイトを読み取り
        let mut config = self.read_config();

        // デュアルチャネルかどうかを確認
        self.dual_channel = (config & 0x20) != 0;

        // 割り込みを無効化、変換を無効化
        config &= !0x43;
        self.write_config(config);

        // セルフテスト
        if !self.self_test() {
            return false;
        }

        // 設定を再書き込み（セルフテストでリセットされる可能性）
        self.write_config(config);

        // デュアルチャネルを確認
        if self.dual_channel {
            self.write_command(commands::ENABLE_PORT2);
            let config2 = self.read_config();
            self.dual_channel = (config2 & 0x20) == 0;
            if self.dual_channel {
                self.write_command(commands::DISABLE_PORT2);
            }
        }

        // ポートテスト
        let port1_ok = self.test_port1();
        let port2_ok = self.dual_channel && self.test_port2();

        // ポートを有効化
        if port1_ok {
            self.write_command(commands::ENABLE_PORT1);
            config |= 0x01; // ポート1割り込み有効
        }

        if port2_ok {
            self.write_command(commands::ENABLE_PORT2);
            config |= 0x02; // ポート2割り込み有効
        }

        self.write_config(config);

        // デバイスを初期化
        if port1_ok {
            if self.init_keyboard() {
                self.port1_type = Some(DeviceType::MfKeyboard);
            }
        }

        if port2_ok {
            self.port2_type = self.init_mouse();
        }

        true
    }

    /// キーボードLEDを設定
    pub fn set_keyboard_leds(&self, scroll: bool, num: bool, caps: bool) {
        let leds = (scroll as u8) | ((num as u8) << 1) | ((caps as u8) << 2);
        self.send_port1(kbd_commands::SET_LEDS);
        self.send_port1(leds);
    }
}

// ============================================================================
// Keyboard Handler
// ============================================================================

/// キーボードハンドラ
pub struct KeyboardHandler {
    /// イベントキュー
    events: VecDeque<KeyEvent>,
    /// 修飾キー状態
    modifiers: Modifiers,
    /// E0プレフィックスフラグ
    e0_prefix: bool,
    /// E1プレフィックスフラグ
    e1_prefix: bool,
}

impl KeyboardHandler {
    /// 新しいキーボードハンドラを作成
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            modifiers: Modifiers::default(),
            e0_prefix: false,
            e1_prefix: false,
        }
    }

    /// スキャンコードを処理
    pub fn process_scancode(&mut self, scancode: u8) {
        // プレフィックスをチェック
        if scancode == 0xE0 {
            self.e0_prefix = true;
            return;
        }
        if scancode == 0xE1 {
            self.e1_prefix = true;
            return;
        }

        // ブレークコード（キー解放）をチェック
        let pressed = (scancode & 0x80) == 0;
        let code = scancode & 0x7F;

        let extended = self.e0_prefix;
        self.e0_prefix = false;
        self.e1_prefix = false;

        let key_code = KeyCode(code);

        // 修飾キーを更新
        self.update_modifiers(key_code, pressed, extended);

        // イベントをキューに追加
        self.events.push_back(KeyEvent {
            code: key_code,
            pressed,
            extended,
        });
    }

    /// 修飾キー状態を更新
    fn update_modifiers(&mut self, code: KeyCode, pressed: bool, extended: bool) {
        match (code, extended) {
            (KeyCode::LEFT_SHIFT, false) => self.modifiers.left_shift = pressed,
            (KeyCode::RIGHT_SHIFT, false) => self.modifiers.right_shift = pressed,
            (KeyCode::LEFT_CTRL, false) => self.modifiers.left_ctrl = pressed,
            (KeyCode::LEFT_CTRL, true) => self.modifiers.right_ctrl = pressed,
            (KeyCode::LEFT_ALT, false) => self.modifiers.left_alt = pressed,
            (KeyCode::LEFT_ALT, true) => self.modifiers.right_alt = pressed,
            (KeyCode::CAPS_LOCK, false) if pressed => {
                self.modifiers.caps_lock = !self.modifiers.caps_lock;
            }
            (KeyCode::NUM_LOCK, false) if pressed => {
                self.modifiers.num_lock = !self.modifiers.num_lock;
            }
            (KeyCode::SCROLL_LOCK, false) if pressed => {
                self.modifiers.scroll_lock = !self.modifiers.scroll_lock;
            }
            _ => {}
        }
    }

    /// イベントをポップ
    pub fn pop_event(&mut self) -> Option<KeyEvent> {
        self.events.pop_front()
    }

    /// 修飾キー状態を取得
    pub fn modifiers(&self) -> Modifiers {
        self.modifiers
    }

    /// スキャンコードを文字に変換
    pub fn scancode_to_char(&self, scancode: u8, extended: bool) -> Option<char> {
        if extended {
            return None;
        }

        let shifted = self.modifiers.shift() ^ self.modifiers.caps_lock;

        // US配列のマッピング（簡易版）
        let c = match scancode {
            0x02 => {
                if shifted {
                    '!'
                } else {
                    '1'
                }
            }
            0x03 => {
                if shifted {
                    '@'
                } else {
                    '2'
                }
            }
            0x04 => {
                if shifted {
                    '#'
                } else {
                    '3'
                }
            }
            0x05 => {
                if shifted {
                    '$'
                } else {
                    '4'
                }
            }
            0x06 => {
                if shifted {
                    '%'
                } else {
                    '5'
                }
            }
            0x07 => {
                if shifted {
                    '^'
                } else {
                    '6'
                }
            }
            0x08 => {
                if shifted {
                    '&'
                } else {
                    '7'
                }
            }
            0x09 => {
                if shifted {
                    '*'
                } else {
                    '8'
                }
            }
            0x0A => {
                if shifted {
                    '('
                } else {
                    '9'
                }
            }
            0x0B => {
                if shifted {
                    ')'
                } else {
                    '0'
                }
            }
            0x0C => {
                if shifted {
                    '_'
                } else {
                    '-'
                }
            }
            0x0D => {
                if shifted {
                    '+'
                } else {
                    '='
                }
            }
            0x10 => {
                if shifted {
                    'Q'
                } else {
                    'q'
                }
            }
            0x11 => {
                if shifted {
                    'W'
                } else {
                    'w'
                }
            }
            0x12 => {
                if shifted {
                    'E'
                } else {
                    'e'
                }
            }
            0x13 => {
                if shifted {
                    'R'
                } else {
                    'r'
                }
            }
            0x14 => {
                if shifted {
                    'T'
                } else {
                    't'
                }
            }
            0x15 => {
                if shifted {
                    'Y'
                } else {
                    'y'
                }
            }
            0x16 => {
                if shifted {
                    'U'
                } else {
                    'u'
                }
            }
            0x17 => {
                if shifted {
                    'I'
                } else {
                    'i'
                }
            }
            0x18 => {
                if shifted {
                    'O'
                } else {
                    'o'
                }
            }
            0x19 => {
                if shifted {
                    'P'
                } else {
                    'p'
                }
            }
            0x1A => {
                if shifted {
                    '{'
                } else {
                    '['
                }
            }
            0x1B => {
                if shifted {
                    '}'
                } else {
                    ']'
                }
            }
            0x1E => {
                if shifted {
                    'A'
                } else {
                    'a'
                }
            }
            0x1F => {
                if shifted {
                    'S'
                } else {
                    's'
                }
            }
            0x20 => {
                if shifted {
                    'D'
                } else {
                    'd'
                }
            }
            0x21 => {
                if shifted {
                    'F'
                } else {
                    'f'
                }
            }
            0x22 => {
                if shifted {
                    'G'
                } else {
                    'g'
                }
            }
            0x23 => {
                if shifted {
                    'H'
                } else {
                    'h'
                }
            }
            0x24 => {
                if shifted {
                    'J'
                } else {
                    'j'
                }
            }
            0x25 => {
                if shifted {
                    'K'
                } else {
                    'k'
                }
            }
            0x26 => {
                if shifted {
                    'L'
                } else {
                    'l'
                }
            }
            0x27 => {
                if shifted {
                    ':'
                } else {
                    ';'
                }
            }
            0x28 => {
                if shifted {
                    '"'
                } else {
                    '\''
                }
            }
            0x29 => {
                if shifted {
                    '~'
                } else {
                    '`'
                }
            }
            0x2B => {
                if shifted {
                    '|'
                } else {
                    '\\'
                }
            }
            0x2C => {
                if shifted {
                    'Z'
                } else {
                    'z'
                }
            }
            0x2D => {
                if shifted {
                    'X'
                } else {
                    'x'
                }
            }
            0x2E => {
                if shifted {
                    'C'
                } else {
                    'c'
                }
            }
            0x2F => {
                if shifted {
                    'V'
                } else {
                    'v'
                }
            }
            0x30 => {
                if shifted {
                    'B'
                } else {
                    'b'
                }
            }
            0x31 => {
                if shifted {
                    'N'
                } else {
                    'n'
                }
            }
            0x32 => {
                if shifted {
                    'M'
                } else {
                    'm'
                }
            }
            0x33 => {
                if shifted {
                    '<'
                } else {
                    ','
                }
            }
            0x34 => {
                if shifted {
                    '>'
                } else {
                    '.'
                }
            }
            0x35 => {
                if shifted {
                    '?'
                } else {
                    '/'
                }
            }
            0x39 => ' ',
            0x0F => '\t',
            0x1C => '\n',
            _ => return None,
        };

        Some(c)
    }
}

// ============================================================================
// Mouse Handler
// ============================================================================

/// マウスハンドラ
pub struct MouseHandler {
    /// イベントキュー
    events: VecDeque<MouseEvent>,
    /// パケットバッファ
    packet: [u8; 4],
    /// パケットインデックス
    packet_index: usize,
    /// パケットサイズ（3または4）
    packet_size: usize,
    /// 現在のボタン状態
    buttons: u8,
    /// 現在のX座標
    x: i32,
    /// 現在のY座標
    y: i32,
}

impl MouseHandler {
    /// 新しいマウスハンドラを作成
    fn new(has_wheel: bool) -> Self {
        Self {
            events: VecDeque::new(),
            packet: [0; 4],
            packet_index: 0,
            packet_size: if has_wheel { 4 } else { 3 },
            buttons: 0,
            x: 0,
            y: 0,
        }
    }

    /// バイトを処理
    pub fn process_byte(&mut self, byte: u8) {
        // 同期チェック（最初のバイトはビット3が常に1）
        if self.packet_index == 0 && (byte & 0x08) == 0 {
            return;
        }

        self.packet[self.packet_index] = byte;
        self.packet_index += 1;

        if self.packet_index >= self.packet_size {
            self.process_packet();
            self.packet_index = 0;
        }
    }

    /// パケットを処理
    fn process_packet(&mut self) {
        let flags = self.packet[0];
        let mut dx = self.packet[1] as i16;
        let mut dy = self.packet[2] as i16;

        // 符号拡張
        if (flags & 0x10) != 0 {
            dx -= 256;
        }
        if (flags & 0x20) != 0 {
            dy -= 256;
        }

        // Y軸を反転（PS/2マウスは上が正）
        dy = -dy;

        // ホイール（4バイトパケットの場合）
        let wheel = if self.packet_size == 4 {
            let w = self.packet[3] as i8;
            if w > 7 { 0 } else { w }
        } else {
            0
        };

        // ボタン状態
        let buttons = flags & 0x07;

        // イベントを生成
        self.events.push_back(MouseEvent {
            dx,
            dy,
            wheel,
            buttons,
        });

        // 位置を更新
        self.buttons = buttons;
    }

    /// イベントをポップ
    pub fn pop_event(&mut self) -> Option<MouseEvent> {
        self.events.pop_front()
    }

    /// 現在のボタン状態を取得
    pub fn buttons(&self) -> u8 {
        self.buttons
    }
}

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
    let status: u8;
    let data: u8;

    unsafe {
        core::arch::asm!("in al, dx", out("al") status, in("dx") ports::STATUS, options(nomem, nostack));
        if (status & status::OUTPUT_FULL) == 0 {
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
    let status: u8;
    let data: u8;

    unsafe {
        core::arch::asm!("in al, dx", out("al") status, in("dx") ports::STATUS, options(nomem, nostack));
        if (status & status::OUTPUT_FULL) == 0 {
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
