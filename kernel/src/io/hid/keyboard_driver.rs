// ============================================================================
// kernel/src/io/hid/keyboard_driver.rs - PS/2 Keyboard Driver (Driver Trait)
// ============================================================================
//!
//! # PS/2 キーボードドライバ (Driver Trait 実装)
//!
//! `kernel_api::driver::Driver` トレイトを実装し、DriverRegistry 経由で
//! 動的にロード・管理可能にする。

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use super::keyboard::PS2_KEYBOARD;

/// PS/2 キーボードドライバ
///
/// DriverRegistry に登録して動的に管理する。
pub struct Ps2KeyboardDriver {
    /// 初期化済みフラグ
    initialized: bool,
}

impl Ps2KeyboardDriver {
    /// 新しいドライバインスタンスを作成
    pub const fn new() -> Self {
        Self { initialized: false }
    }
}

impl Default for Ps2KeyboardDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for Ps2KeyboardDriver {
    fn name(&self) -> &str {
        "ps2-keyboard"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(1, 0, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Hid
    }

    fn probe(&mut self) -> KapiResult<()> {
        if self.initialized {
            return Ok(());
        }

        // PS/2 キーボードを初期化
        PS2_KEYBOARD.init();
        self.initialized = true;

        log::info!("[PS2_KEYBOARD] Driver probed successfully\n");
        Ok(())
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1)); // Not initialized
        }

        log::info!("[PS2_KEYBOARD] Driver started\n");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        log::info!("[PS2_KEYBOARD] Driver stopped\n");
        Ok(())
    }

    fn remove(&mut self) -> KapiResult<()> {
        self.initialized = false;
        log::info!("[PS2_KEYBOARD] Driver removed\n");
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // PS/2 は PCI デバイスではないため空
        &[]
    }
}
