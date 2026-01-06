// ============================================================================
// kernel/src/io/hid/mouse_driver.rs - PS/2 Mouse Driver (Driver Trait)
// ============================================================================
//!
//! # PS/2 マウスドライバ (Driver Trait 実装)
//!
//! `kernel_api::driver::Driver` トレイトを実装し、DriverRegistry 経由で
//! 動的にロード・管理可能にする。

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use super::mouse::MOUSE;

/// PS/2 マウスドライバ
///
/// DriverRegistry に登録して動的に管理する。
pub struct Ps2MouseDriver {
    /// 初期化済みフラグ
    initialized: bool,
}

impl Ps2MouseDriver {
    /// 新しいドライバインスタンスを作成
    pub const fn new() -> Self {
        Self { initialized: false }
    }
}

impl Default for Ps2MouseDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for Ps2MouseDriver {
    fn name(&self) -> &str {
        "ps2-mouse"
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

        // PS/2 マウスを初期化
        match MOUSE.lock().init() {
            Ok(()) => {
                self.initialized = true;
                log::info!("[PS2_MOUSE] Driver probed successfully\n");
                Ok(())
            }
            Err(e) => {
                log::warn!("[PS2_MOUSE] Probe failed: {:?}\n", e);
                Err(KapiError::NotFound)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1)); // Not initialized
        }

        log::info!("[PS2_MOUSE] Driver started\n");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        log::info!("[PS2_MOUSE] Driver stopped\n");
        Ok(())
    }

    fn remove(&mut self) -> KapiResult<()> {
        self.initialized = false;
        log::info!("[PS2_MOUSE] Driver removed\n");
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // PS/2 は PCI デバイスではないため空
        &[]
    }
}
