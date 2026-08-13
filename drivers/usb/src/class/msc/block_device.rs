#![allow(clippy::wildcard_imports)]
use super::*;

// ============================================================================
// Block Device Interface
// ============================================================================

/// ブロックデバイスインターフェース（ファイルシステム連携用）
///
/// このトレイトはUSBドライバ内部で使用されます。
/// カーネル側へ公開する場合は `kernel_api::block_io` 境界に接続してください。
pub trait UsbBlockDevice: Send + Sync {
    /// ブロックサイズを取得
    fn block_size(&self) -> u32;

    /// 総ブロック数を取得
    fn total_blocks(&self) -> u64;

    /// ブロックを読み取り
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    fn read_blocks(
        &self,
        start_lba: u64,
        count: u32,
        buffer: &mut [u8],
    ) -> Result<(), ClassDriverError>;

    /// ブロックを書き込み
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    fn write_blocks(
        &self,
        start_lba: u64,
        count: u32,
        buffer: &[u8],
    ) -> Result<(), ClassDriverError>;

    /// キャッシュをフラッシュ
    /// # Errors
    ///
    /// Returns an error if the device is not ready, times out, or reports a failed completion.
    fn flush(&self) -> Result<(), ClassDriverError>;
}
