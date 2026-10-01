use super::*;

mod device_context;
pub use device_context::*;
// ============================================================================
// Device-bound DMA Allocator Trait and Implementation
// ============================================================================

// // use spin::Mutex;

/// DMAアロケータのエラー型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// メモリ不足
    OutOfMemory,
    /// アライメントエラー
    InvalidAlignment,
    /// サイズエラー
    InvalidSize,
    /// アドレス範囲が無効
    InvalidAddress,
    /// IOMMUマッピング失敗
    IommuMappingFailed,
    /// アドレス変換失敗
    AddressTranslationFailed,
    /// デバイスが見つからない
    DeviceNotFound,
    /// IOMMUが必須だが利用できない
    IommuRequired,
}

// ============================================================================
// Device-specific DMA Context
// ============================================================================

/// デバイス固有のDMAコンテキスト
///
/// 各ドライバはこれを保持してDMA操作を行う。
/// IOMMUドメインやデバイス固有の設定を管理。
pub struct DeviceDmaContext {
    /// デバイスID
    device_id: Option<crate::io::iommu::types::DeviceId>,
    /// IOMMUドメインID
    domain_id: Option<u16>,
}
