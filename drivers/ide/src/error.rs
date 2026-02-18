use super::*;


// ============================================================================
// IDE Error
// ============================================================================

/// IDEエラー
#[derive(Clone, Copy, Debug)]
pub enum IdeError {
    /// デバイスなし
    NoDevice,
    /// タイムアウト
    Timeout,
    /// デバイスエラー
    DeviceError,
    /// バッファが小さすぎる
    BufferTooSmall,
    /// サポートされていない操作
    NotSupported,
}

// ============================================================================
// Global IDE Controller
// ============================================================================

/// グローバルIDEコントローラ
pub(crate) static IDE_CHANNELS: Mutex<Option<[IdeChannel; 2]>> = Mutex::new(None);

/// IDEコントローラを初期化
pub fn init() {
    let mut primary = IdeChannel::new(IdeController::Primary);
    let mut secondary = IdeChannel::new(IdeController::Secondary);

    primary.detect_devices();
    secondary.detect_devices();

    // 検出されたデバイスをログ
    for (i, device) in primary.devices.iter().enumerate() {
        if let Some(dev) = device {
            let drive = if i == 0 { "Master" } else { "Slave" };
            log::info!(
                "Primary {}: {} ({} MB)",
                drive,
                dev.model,
                dev.capacity() / (1024 * 1024)
            );
        }
    }

    for (i, device) in secondary.devices.iter().enumerate() {
        if let Some(dev) = device {
            let drive = if i == 0 { "Master" } else { "Slave" };
            log::info!(
                "Secondary {}: {} ({} MB)",
                drive,
                dev.model,
                dev.capacity() / (1024 * 1024)
            );
        }
    }

    *IDE_CHANNELS.lock() = Some([primary, secondary]);
}

/// セクタを読み取り
pub fn read_sectors(
    controller: IdeController,
    drive: DriveSel,
    lba: u64,
    count: u16,
    buffer: &mut [u8],
) -> Result<(), IdeError> {
    let channels = IDE_CHANNELS.lock();
    let channels = channels.as_ref().ok_or(IdeError::NoDevice)?;

    let channel = match controller {
        IdeController::Primary => &channels[0],
        IdeController::Secondary => &channels[1],
    };

    channel.read_sectors(drive, lba, count, buffer)
}
