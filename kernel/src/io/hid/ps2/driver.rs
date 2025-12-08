// ============================================================================
// kernel/src/io/hid/ps2/driver.rs - PS/2 Driver implementing Driver trait
// ============================================================================
//!
//! # PS/2 Driver
//!
//! Wrapper around PS/2 controller implementing the `kernel_api::Driver` trait.
//! This is the pilot driver demonstrating the new driver architecture.

use kernel_api::driver::{Driver, DriverType, DriverVersion, DeviceId};
use kernel_api::error::KapiResult;
use super::controller::{Ps2Controller, DeviceType};

/// PS/2ドライバ - Driver trait 実装のパイロット
pub struct Ps2Driver {
    /// 内部コントローラ
    controller: Ps2Controller,
    /// 初期化済みフラグ
    initialized: bool,
}

impl Ps2Driver {
    /// 新しいPS/2ドライバを作成
    pub fn new() -> Self {
        Self {
            controller: Ps2Controller::new(),
            initialized: false,
        }
    }

    /// キーボードが検出されたか
    pub fn has_keyboard(&self) -> bool {
        matches!(
            self.controller.port1_type,
            Some(DeviceType::AtKeyboard) | Some(DeviceType::MfKeyboard)
        )
    }

    /// マウスが検出されたか
    pub fn has_mouse(&self) -> bool {
        matches!(
            self.controller.port2_type,
            Some(DeviceType::StandardMouse)
                | Some(DeviceType::ScrollMouse)
                | Some(DeviceType::FiveButtonMouse)
        )
    }

    /// マウスタイプを取得
    pub fn mouse_type(&self) -> Option<DeviceType> {
        self.controller.port2_type
    }

    /// データポートから読み取り（割り込みハンドラ用）
    pub fn read_data(&self) -> u8 {
        self.controller.read_data()
    }

    /// キーボードLEDを設定
    pub fn set_keyboard_leds(&self, scroll: bool, num: bool, caps: bool) {
        self.controller.set_keyboard_leds(scroll, num, caps);
    }
}

impl Default for Ps2Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for Ps2Driver {
    fn name(&self) -> &str {
        "ps2"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(1, 0, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Hid
    }

    fn probe(&mut self) -> KapiResult<()> {
        if self.controller.initialize() {
            self.initialized = true;
            
            // ログ出力
            let kb = if self.has_keyboard() { "Keyboard" } else { "None" };
            let mouse_type = match self.controller.port2_type {
                Some(DeviceType::StandardMouse) => "Standard Mouse",
                Some(DeviceType::ScrollMouse) => "Scroll Mouse",
                Some(DeviceType::FiveButtonMouse) => "5-Button Mouse",
                _ => "None",
            };
            
            crate::log!("[PS2] Port1: {}, Port2: {}\n", kb, mouse_type);
            Ok(())
        } else {
            Err(kernel_api::KapiError::IoError)
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        // 割り込みは既にprobe()で有効化されている
        // 追加の開始処理は不要
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        // PS/2は通常シャットダウン時まで動作し続ける
        // ホットスワップ非対応デバイスなので特に処理なし
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // PS/2はレガシーデバイスなのでDeviceId不使用
        &[]
    }
}
