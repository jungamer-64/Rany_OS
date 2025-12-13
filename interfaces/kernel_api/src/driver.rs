// ============================================================================
// kernel_api/src/driver.rs - Driver Trait Definition
// ============================================================================
//!
//! # Driver Interface
//!
//! This module defines the `Driver` trait that all driver cells must implement.
//! It provides a unified interface for driver lifecycle management,
//! enabling future hot-swap capabilities and dynamic driver loading.
//!
//! ## Design Rationale
//!
//! - **Uniform Interface**: All drivers expose the same lifecycle methods
//! - **Capability-Based**: Drivers request capabilities during probe
//! - **Hot-Swap Ready**: Clean start/stop semantics for dynamic loading
//! - **Zero-Copy Friendly**: Uses references where possible

use crate::error::{KapiError, KapiResult};
use crate::driver_abi::DriverContext;
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

/// Future type returned by AsyncDriver methods
pub type DriverFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ============================================================================
// Driver Trait
// ============================================================================

/// すべてのドライバ（セル）が実装すべきトレイト
///
/// ドライバのライフサイクル管理を統一化し、
/// 将来のホットスワップ機能の基盤を提供する。
///
/// ## ライフサイクル
///
/// ```text
/// ┌─────────────────────────────────────────────────────┐
/// │                  Driver Lifecycle                    │
/// │                                                      │
/// │   ┌─────────┐    probe()     ┌──────────┐          │
/// │   │ Created │ ───────────── ▶│ Probed   │          │
/// │   └─────────┘                └──────────┘          │
/// │                                   │                 │
/// │                              start()               │
/// │                                   ▼                 │
/// │                              ┌──────────┐          │
/// │                              │ Running  │          │
/// │                              └──────────┘          │
/// │                                   │                 │
/// │                              stop()                │
/// │                                   ▼                 │
/// │                              ┌──────────┐          │
/// │                              │ Stopped  │          │
/// │                              └──────────┘          │
/// └─────────────────────────────────────────────────────┘
/// ```
pub trait Driver: Send + Sync {
    /// ドライバ名（デバッグ・ログ用）
    ///
    /// 人間が読みやすい識別子を返す。
    fn name(&self) -> &str;

    /// ドライバのバージョン
    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    /// ドライバの種類
    fn driver_type(&self) -> DriverType;

    /// デバイスプローブ（初期化）
    ///
    /// デバイスの検出と初期設定を行う。
    /// 必要なケイパビリティの要求もここで行う。
    ///
    /// # Returns
    /// - `Ok(())` - プローブ成功、ドライバ使用可能
    /// - `Err(KapiError)` - プローブ失敗、ドライバは使用不可
    fn probe(&mut self) -> KapiResult<()>;

    /// ドライバを開始
    ///
    /// probe() 成功後に呼ばれる。
    /// 割り込みハンドラの登録やポーリング開始など。
    fn start(&mut self) -> KapiResult<()> {
        // デフォルト実装: 何もしない
        Ok(())
    }

    /// ドライバを停止
    ///
    /// ホットスワップやシャットダウン時に呼ばれる。
    /// リソースの解放、割り込みの無効化など。
    fn stop(&mut self) -> KapiResult<()> {
        // デフォルト実装: 何もしない
        Ok(())
    }

    /// ドライバを削除/アンレジスター
    ///
    /// ドライバのリソース解放や、ホットアンロード時のクリーンアップを行う。
    /// デフォルトでは何もしない（`Ok(())` を返す）。
    fn remove(&mut self) -> KapiResult<()> {
        Ok(())
    }

    /// ドライバがサポートするデバイス情報
    fn supported_devices(&self) -> &[DeviceId] {
        &[]
    }

}

// ============================================================================
// Async Driver Trait
// ============================================================================

/// 非同期ドライバ（セル）のためのトレイト
///
/// `Driver`トレイトの非同期版であり、`async/await`構文を利用して
/// 初期化処理やデバイス操作を行うことができる。
///
/// # Async-First Design
/// RanyOSは非同期中心主義を採用しているため、長時間かかる初期化処理（ハードウェア待ちなど）は
/// 必ず非同期で行う必要がある。
pub trait AsyncDriver: Send + Sync {
    /// ドライバ名
    fn name(&self) -> &str;

    /// ドライバのバージョン
    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    /// ドライバの種類
    fn driver_type(&self) -> DriverType;

    /// 非同期プローブ
    ///
    /// デバイスの初期化を行う。
    fn probe(&mut self, ctx: &mut DriverContext) -> DriverFuture<'_, KapiResult<()>>;

    /// 非同期開始
    ///
    /// 割り込み待ち受けやバックグラウンドタスクの起動を行う。
    /// `kernel_api::services::kernel().spawn_task()` を使用してタスクを生成できる。
    fn start(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(core::future::ready(Ok(())))
    }

    /// 非同期停止
    fn stop(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(core::future::ready(Ok(())))
    }

    /// 非同期削除
    fn remove(&mut self) -> DriverFuture<'_, KapiResult<()>> {
        Box::pin(core::future::ready(Ok(())))
    }

    /// サポートするデバイス
    fn supported_devices(&self) -> &[DeviceId] {
        &[]
    }
}

// ============================================================================
// Driver Types and Metadata
// ============================================================================

/// ドライバのバージョン情報
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl DriverVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl core::fmt::Display for DriverVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// ドライバの種類
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverType {
    /// PCIデバイスドライバ
    Pci,
    /// USBデバイスドライバ
    Usb,
    /// ブロックデバイス（ストレージ）
    Block,
    /// ネットワークデバイス
    Network,
    /// HID（キーボード、マウス等）
    Hid,
    /// グラフィックス
    Graphics,
    /// シリアル/UART
    Serial,
    /// その他
    Other,
}

impl DriverType {
    /// Convert to ABI-stable u32 representation
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// デバイス識別子
///
/// PCI Vendor/Device ID、USB VID/PID など
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceId {
    /// ベンダーID
    pub vendor: u16,
    /// デバイスID
    pub device: u16,
    /// サブシステムベンダーID（オプション）
    pub subsystem_vendor: Option<u16>,
    /// サブシステムデバイスID（オプション）
    pub subsystem_device: Option<u16>,
}

impl DeviceId {
    pub const fn new(vendor: u16, device: u16) -> Self {
        Self {
            vendor,
            device,
            subsystem_vendor: None,
            subsystem_device: None,
        }
    }

    pub const fn with_subsystem(
        vendor: u16,
        device: u16,
        subsystem_vendor: u16,
        subsystem_device: u16,
    ) -> Self {
        Self {
            vendor,
            device,
            subsystem_vendor: Some(subsystem_vendor),
            subsystem_device: Some(subsystem_device),
        }
    }

    /// PCI形式の文字列表現
    pub fn pci_id_string(&self) -> alloc::string::String {
        alloc::format!("{:04x}:{:04x}", self.vendor, self.device)
    }
}

// ============================================================================
// Driver Registration (for kernel use)
// ============================================================================

/// ドライバ登録情報
pub struct DriverInfo {
    /// ドライバ名
    pub name: &'static str,
    /// ドライバの種類
    pub driver_type: DriverType,
    /// サポートするデバイスID一覧
    pub supported_devices: &'static [DeviceId],
}

/// ドライバ状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    /// 登録済み（未プローブ）
    Registered,
    /// プローブ成功
    Probed,
    /// 動作中
    Running,
    /// 停止
    Stopped,
    /// エラー
    Error,
    /// 削除済み（ドライバがアンレジスターされた、またはロード解除済み）
    Removed,
}
