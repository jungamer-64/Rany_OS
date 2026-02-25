#![allow(clippy::wildcard_imports)]
use super::*;

// ============================================================================
// Block Device Interface
// ============================================================================

/// ブロックデバイスインターフェース（ファイルシステム連携用）
///
/// このトレイトはUSBドライバ内部で使用されます。
/// VFS連携が必要な場合は`vfs_integration`フィーチャーを有効にして
/// `vfs::block::SimpleBlockDevice`を使用してください。
pub trait UsbBlockDevice: Send + Sync {
    /// ブロックサイズを取得
    fn block_size(&self) -> u32;

    /// 総ブロック数を取得
    fn total_blocks(&self) -> u64;

    /// ブロックを読み取り
    fn read_blocks(
        &self,
        start_lba: u64,
        count: u32,
        buffer: &mut [u8],
    ) -> Result<(), ClassDriverError>;

    /// ブロックを書き込み
    fn write_blocks(
        &self,
        start_lba: u64,
        count: u32,
        buffer: &[u8],
    ) -> Result<(), ClassDriverError>;

    /// キャッシュをフラッシュ
    fn flush(&self) -> Result<(), ClassDriverError>;
}

// ============================================================================
// VFS SimpleBlockDevice Integration
// ============================================================================

#[cfg(feature = "vfs_integration")]
mod vfs_adapter {
    use super::{ClassDriverError, MscDevice};
    use vfs::block::{BlockError, BlockResult, SimpleBlockDevice};

    impl From<ClassDriverError> for BlockError {
        fn from(err: ClassDriverError) -> Self {
            match err {
                ClassDriverError::InitFailed => BlockError::NotReady,
                ClassDriverError::NoDevice => BlockError::NotReady,
                ClassDriverError::UnsupportedDevice => BlockError::IoError,
                ClassDriverError::TransferError(_) => BlockError::IoError,
                ClassDriverError::Timeout => BlockError::Timeout,
                ClassDriverError::ProtocolError => BlockError::IoError,
                ClassDriverError::NoResources => BlockError::QueueFull,
                ClassDriverError::InvalidParameter => BlockError::InvalidBufferSize,
                ClassDriverError::AlreadyBound => BlockError::IoError,
                ClassDriverError::Internal => BlockError::IoError,
            }
        }
    }

    impl SimpleBlockDevice for MscDevice {
        fn block_size(&self) -> u32 {
            self.device_info()
                .map(|info| info.block_size)
                .unwrap_or(512)
        }

        fn total_blocks(&self) -> u64 {
            self.device_info()
                .map(|info| info.total_blocks)
                .unwrap_or(0)
        }

        fn name(&self) -> &'static str {
            "usb_msc"
        }

        fn is_read_only(&self) -> bool {
            false
        }

        fn read_blocks(&self, start_lba: u64, count: u32, buffer: &mut [u8]) -> BlockResult<()> {
            // TODO: 実際のSCSI READ(10)コマンドを実行
            // 現在はスタブ実装
            let _ = (start_lba, count, buffer);
            Err(BlockError::NotReady)
        }

        fn write_blocks(&self, start_lba: u64, count: u32, buffer: &[u8]) -> BlockResult<()> {
            // TODO: 実際のSCSI WRITE(10)コマンドを実行
            // 現在はスタブ実装
            let _ = (start_lba, count, buffer);
            Err(BlockError::NotReady)
        }

        fn flush(&self) -> BlockResult<()> {
            // TODO: SYNCHRONIZE CACHEコマンドを実行
            Ok(())
        }
    }
}

#[cfg(feature = "vfs_integration")]
pub use vfs_adapter::*;
