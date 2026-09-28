// ============================================================================
// drivers/mlx5/src/error.rs - Error types
// ============================================================================
//! mlx5 ドライバエラー型

use core::fmt;

/// mlx5 ドライバエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mlx5Error {
    /// ファームウェア初期化失敗
    FirmwareInitFailed,
    /// コマンドタイムアウト
    CommandTimeout,
    /// Reset was published but its acknowledgement/outcome could not be established.
    ResetOutcomeUnknown,
    /// コマンドがエラーステータスを返した
    CommandFailed(u8),
    /// 不正なコマンドレスポンス
    InvalidResponse,
    /// バーマッピング失敗
    BarMapFailed,
    /// Register geometry failure; no access is made outside the retained mapping.
    MmioAccess(hal::mmio::MmioAccessError),
    /// DMAバッファ割り当て失敗
    DmaAllocFailed,
    /// デバイスが見つからない
    DeviceNotFound,
    /// デバイスが応答しない
    DeviceNotReady,
    /// キュー作成失敗
    QueueCreationFailed,
    /// ポート初期化失敗
    PortInitFailed,
    /// MSI-X設定失敗
    MsixSetupFailed,
    /// IOMMU設定失敗
    IommuError,
    /// リソース不足
    NoResources,
    /// 不正なパラメータ
    InvalidParameter,
    /// このデバイス/FWで未対応
    NotSupported,
    /// 内部エラー
    Internal,
    /// Registry transition/finalization failure; the device page owner retains the capability.
    DmaLease(kernel_api::dma::DmaLeaseError),
    /// Scoped firmware-page allocation failure, preserving the kernel cause.
    PageAllocation(kernel_api::error::KapiError),
}

impl fmt::Display for Mlx5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirmwareInitFailed => write!(f, "firmware init failed"),
            Self::CommandTimeout => write!(f, "command timeout"),
            Self::ResetOutcomeUnknown => write!(f, "reset outcome unknown; resources retained"),
            Self::CommandFailed(status) => write!(f, "command failed: status={:#x}", status),
            Self::InvalidResponse => write!(f, "invalid response"),
            Self::BarMapFailed => write!(f, "BAR mapping failed"),
            Self::MmioAccess(cause) => write!(f, "MMIO access: {cause:?}"),
            Self::DmaAllocFailed => write!(f, "DMA allocation failed"),
            Self::DeviceNotFound => write!(f, "device not found"),
            Self::DeviceNotReady => write!(f, "device not ready"),
            Self::QueueCreationFailed => write!(f, "queue creation failed"),
            Self::PortInitFailed => write!(f, "port init failed"),
            Self::MsixSetupFailed => write!(f, "MSI-X setup failed"),
            Self::IommuError => write!(f, "IOMMU error"),
            Self::NoResources => write!(f, "no resources"),
            Self::InvalidParameter => write!(f, "invalid parameter"),
            Self::NotSupported => write!(f, "not supported"),
            Self::Internal => write!(f, "internal error"),
            Self::DmaLease(cause) => write!(f, "DMA lease: {cause:?}"),
            Self::PageAllocation(cause) => write!(f, "firmware page allocation: {cause}"),
        }
    }
}

/// Result type for mlx5 operations
pub type Mlx5Result<T> = Result<T, Mlx5Error>;

impl From<hal::mmio::MmioAccessError> for Mlx5Error {
    fn from(cause: hal::mmio::MmioAccessError) -> Self {
        Self::MmioAccess(cause)
    }
}
