use super::{DriveSel, IdeChannel, IdeController, Mutex};

// ============================================================================
// IDE Error
// ============================================================================

/// IDEエラー
#[derive(Clone, Copy, Debug)]
pub enum IdeError {
    InvalidPortRange,
    InvalidRequest,
    TransferInterrupted {
        transferred_sectors: usize,
        phase: TransferPhase,
        fault: TransferFault,
    },
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

/// The device may have accepted a prefix after command publication. Write
/// data is not durable until the cache-flush phase succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferPhase {
    ReadData,
    WriteData,
    CacheFlush,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferFault {
    Timeout,
    DeviceError,
}

impl From<TransferFault> for IdeError {
    fn from(fault: TransferFault) -> Self {
        match fault {
            TransferFault::Timeout => Self::Timeout,
            TransferFault::DeviceError => Self::DeviceError,
        }
    }
}

// ============================================================================
// Global IDE Controller
// ============================================================================

/// グローバルIDEコントローラ
pub static IDE_CHANNELS: Mutex<Option<[IdeChannel; 2]>> = Mutex::new(None);

/// IDEコントローラを初期化
///
/// # Errors
/// Rejects an invalid platform command/control allocation before publication.
pub fn init() -> Result<(), IdeError> {
    let mut channels = IDE_CHANNELS.lock();
    if channels.is_some() {
        return Ok(());
    }
    let acquire = |controller: IdeController| {
        // SAFETY: the registry lock excludes duplicate initialization, and the
        // platform reserves these fixed command blocks for the IDE subsystem.
        let command_ports = unsafe { hal::IoPortRange::from_raw_parts(controller.io_base(), 8) }
            .map_err(|_| IdeError::InvalidPortRange)?;
        // SAFETY: the matching control port has the same exclusive owner.
        let control_port = unsafe { hal::IoPortRange::single(controller.control_base()) };
        IdeChannel::new(command_ports, control_port)
    };
    let mut primary = acquire(IdeController::Primary)?;
    let mut secondary = acquire(IdeController::Secondary)?;

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

    *channels = Some([primary, secondary]);
    Ok(())
}

/// セクタを読み取り
/// # Errors
///
/// Returns an error if the request is invalid or the required state cannot be read.
pub fn read_sectors(
    controller: IdeController,
    drive: DriveSel,
    lba: u64,
    count: u16,
    buffer: &mut [u8],
) -> Result<(), IdeError> {
    let mut channels = IDE_CHANNELS.lock();
    let channels = channels.as_mut().ok_or(IdeError::NoDevice)?;

    let channel = match controller {
        IdeController::Primary => &mut channels[0],
        IdeController::Secondary => &mut channels[1],
    };

    channel.read_sectors(drive, lba, count, buffer)
}
