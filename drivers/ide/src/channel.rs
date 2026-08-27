#![forbid(unsafe_code)]

use super::{DeviceType, DriveSel, IdeChannel, IdeError, IdentifyData, commands, regs, status};
use hal::{IoPort, PortValue};

impl IdeChannel {
    /// Takes ownership of one allocated ATA command/control block.
    ///
    /// # Errors
    /// Rejects any command block other than eight ports or control block other
    /// than one port before performing device I/O.
    pub fn new(
        command_ports: hal::IoPortRange,
        control_port: hal::IoPortRange,
    ) -> Result<Self, IdeError> {
        if command_ports.len() != 8 || control_port.len() != 1 {
            return Err(IdeError::InvalidPortRange);
        }
        Ok(Self {
            command_ports,
            control_port,
            devices: [None, None],
        })
    }

    fn command_port<T: PortValue>(&self, register: u16) -> IoPort<'_, T> {
        self.command_ports
            .port(register)
            .expect("ATA register offsets fit the command block")
    }

    fn control_port(&self) -> IoPort<'_, u8> {
        self.control_port
            .first()
            .expect("the ATA control range contains exactly one port")
    }

    /// レジスタを読み取り
    #[inline]
    pub(super) fn read_reg(&self, reg: u16) -> u8 {
        self.command_port::<u8>(reg).read()
    }

    /// レジスタに書き込み
    #[inline]
    pub(super) fn write_reg(&self, reg: u16, value: u8) {
        self.command_port::<u8>(reg).write(value);
    }

    /// ステータスを読み取り
    #[inline]
    pub(super) fn read_status(&self) -> u8 {
        self.read_reg(regs::STATUS)
    }

    /// 代替ステータスを読み取り（割り込みクリアなし）
    #[inline]
    pub(super) fn read_alt_status(&self) -> u8 {
        self.control_port().read()
    }

    /// ビジーフラグが解除されるまで待機
    fn wait_not_busy(&self) -> Result<(), super::TransferFault> {
        let mut timeout = 100_000;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while timeout > 0 {
            let status = self.read_alt_status();
            if (status & status::BSY) == 0 {
                return Ok(());
            }
            timeout -= 1;
        }
        Err(super::TransferFault::Timeout)
    }

    /// DRQがセットされるまで待機
    fn wait_drq(&self) -> Result<(), super::TransferFault> {
        let mut timeout = 100_000;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while timeout > 0 {
            let status = self.read_alt_status();
            if (status & status::BSY) == 0 {
                if (status & (status::ERR | status::DF)) != 0 {
                    return Err(super::TransferFault::DeviceError);
                }
                if (status & status::DRQ) != 0 {
                    return Ok(());
                }
            }
            timeout -= 1;
        }
        Err(super::TransferFault::Timeout)
    }

    /// ドライブを選択
    fn select_drive(&self, drive: DriveSel) {
        self.write_reg(regs::DRIVE, drive.value());
        // 400ns待機（4回のステータス読み取り）
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }
    }

    /// ソフトリセット
    pub fn soft_reset(&mut self) {
        // SRST=1
        {
            let mut ctrl = self.control_port();
            ctrl.write(0x04);
        }
        // 少なくとも5us待機
        for _ in 0..10 {
            let _ = self.read_alt_status();
        }
        // SRST=0
        {
            let mut ctrl = self.control_port();
            ctrl.write(0x00);
        }
        // 400ns待機
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }
    }

    /// デバイスを検出
    pub fn detect_devices(&mut self) {
        for (i, drive) in [DriveSel::Master, DriveSel::Slave].iter().enumerate() {
            if let Some(identify) = self.identify_device(*drive) {
                self.devices[i] = Some(identify);
            }
        }
    }

    /// ATAPIかATAかを判定
    fn detect_device_type(&self) -> Option<DeviceType> {
        let lba_mid = self.read_reg(regs::LBA_MID);
        let lba_high = self.read_reg(regs::LBA_HIGH);
        if lba_mid == 0x14 && lba_high == 0xEB {
            self.write_reg(regs::COMMAND, commands::IDENTIFY_PACKET);
            if self.wait_drq().is_err() {
                return None;
            }
            Some(DeviceType::Atapi)
        } else if lba_mid == 0 && lba_high == 0 {
            if self.wait_drq().is_err() {
                return None;
            }
            Some(DeviceType::Ata)
        } else {
            None
        }
    }

    /// デバイスを識別
    fn identify_device(&self, drive: DriveSel) -> Option<IdentifyData> {
        self.select_drive(drive);

        // フローティングバスチェック
        if self.read_status() == 0xFF {
            return None;
        }

        // ドライブ選択後の待機
        self.select_drive(drive);
        self.write_reg(regs::SECTOR_COUNT, 0);
        self.write_reg(regs::LBA_LOW, 0);
        self.write_reg(regs::LBA_MID, 0);
        self.write_reg(regs::LBA_HIGH, 0);

        // IDENTIFYコマンドを発行
        self.write_reg(regs::COMMAND, commands::IDENTIFY);

        // ステータスが0ならデバイスなし
        let status = self.read_status();
        if status == 0 {
            return None;
        }

        // ビジー解除を待機
        if self.wait_not_busy().is_err() {
            return None;
        }

        // ATAPIデバイスチェック
        let device_type = self.detect_device_type()?;

        // IDENTIFYデータを読み取り
        let mut words = [0u16; 256];
        let mut data_port = self.command_port::<u16>(regs::DATA);
        data_port.read_words(&mut words);

        let mut identify = IdentifyData::from_words(&words);
        identify.device_type = device_type;

        Some(identify)
    }

    /// Reads complete logical sectors into the caller's byte-aligned buffer.
    ///
    /// # Errors
    /// Validation failures occur before command publication. A transfer error
    /// reports exactly how many complete sectors were written into the buffer.
    pub fn read_sectors(
        &mut self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &mut [u8],
    ) -> Result<(), IdeError> {
        let device = self.get_device(drive).ok_or(IdeError::NoDevice)?;
        let plan = TransferPlan::new(device, drive, lba, count, buffer.len())?;
        self.wait_not_busy().map_err(IdeError::from)?;
        self.publish_transfer(&plan, TransferDirection::Read);
        let mut data = self.command_port::<u16>(regs::DATA);
        for (transferred, sector) in buffer[..plan.byte_count]
            .chunks_exact_mut(plan.sector_bytes)
            .enumerate()
        {
            self.wait_drq()
                .map_err(|fault| IdeError::TransferInterrupted {
                    transferred_sectors: transferred,
                    phase: super::TransferPhase::ReadData,
                    fault,
                })?;
            for bytes in sector.as_chunks_mut::<2>().0 {
                bytes.copy_from_slice(&data.read().to_le_bytes());
            }
        }
        Ok(())
    }

    /// Writes logical sectors and waits for the device cache flush.
    ///
    /// # Errors
    /// Validation failures publish no command. Once published, failures retain
    /// the number of sectors sent and distinguish data transfer from cache-flush
    /// failure; those sectors must not be assumed durable or blindly retried.
    pub fn write_sectors(
        &mut self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &[u8],
    ) -> Result<(), IdeError> {
        let device = self.get_device(drive).ok_or(IdeError::NoDevice)?;
        let plan = TransferPlan::new(device, drive, lba, count, buffer.len())?;
        self.wait_not_busy().map_err(IdeError::from)?;
        self.publish_transfer(&plan, TransferDirection::Write);
        let mut data = self.command_port::<u16>(regs::DATA);
        for (transferred, sector) in buffer[..plan.byte_count]
            .chunks_exact(plan.sector_bytes)
            .enumerate()
        {
            self.wait_drq()
                .map_err(|fault| IdeError::TransferInterrupted {
                    transferred_sectors: transferred,
                    phase: super::TransferPhase::WriteData,
                    fault,
                })?;
            for bytes in sector.as_chunks::<2>().0 {
                data.write(u16::from_le_bytes(*bytes));
            }
        }
        let flush = match plan.task_file {
            TaskFile::Lba28 { .. } => commands::CACHE_FLUSH,
            TaskFile::Lba48 { .. } => commands::CACHE_FLUSH_EXT,
        };
        self.write_reg(regs::COMMAND, flush);
        self.wait_not_busy()
            .map_err(|fault| IdeError::TransferInterrupted {
                transferred_sectors: usize::from(count),
                phase: super::TransferPhase::CacheFlush,
                fault,
            })?;
        if self.read_status() & (status::ERR | status::DF) != 0 {
            return Err(IdeError::TransferInterrupted {
                transferred_sectors: usize::from(count),
                phase: super::TransferPhase::CacheFlush,
                fault: super::TransferFault::DeviceError,
            });
        }
        Ok(())
    }

    fn publish_transfer(&self, plan: &TransferPlan, direction: TransferDirection) {
        let (drive_head, command) = match (&plan.task_file, direction) {
            (TaskFile::Lba28 { drive_head, .. }, TransferDirection::Read) => {
                (*drive_head, commands::READ_SECTORS)
            }
            (TaskFile::Lba28 { drive_head, .. }, TransferDirection::Write) => {
                (*drive_head, commands::WRITE_SECTORS)
            }
            (TaskFile::Lba48 { drive_head, .. }, TransferDirection::Read) => {
                (*drive_head, commands::READ_SECTORS_EXT)
            }
            (TaskFile::Lba48 { drive_head, .. }, TransferDirection::Write) => {
                (*drive_head, commands::WRITE_SECTORS_EXT)
            }
        };
        self.write_reg(regs::DRIVE, drive_head);
        for _ in 0..4 {
            let _status = self.read_alt_status();
        }
        match plan.task_file {
            TaskFile::Lba28 { count, lba, .. } => {
                self.write_reg(regs::SECTOR_COUNT, count);
                self.write_reg(regs::LBA_LOW, lba[0]);
                self.write_reg(regs::LBA_MID, lba[1]);
                self.write_reg(regs::LBA_HIGH, lba[2]);
            }
            TaskFile::Lba48 { count, lba, .. } => {
                self.write_reg(regs::SECTOR_COUNT, count[1]);
                self.write_reg(regs::LBA_LOW, lba[3]);
                self.write_reg(regs::LBA_MID, lba[4]);
                self.write_reg(regs::LBA_HIGH, lba[5]);
                self.write_reg(regs::SECTOR_COUNT, count[0]);
                self.write_reg(regs::LBA_LOW, lba[0]);
                self.write_reg(regs::LBA_MID, lba[1]);
                self.write_reg(regs::LBA_HIGH, lba[2]);
            }
        }
        self.write_reg(regs::COMMAND, command);
    }

    pub fn get_device(&self, drive: DriveSel) -> Option<&IdentifyData> {
        self.devices[if drive == DriveSel::Master { 0 } else { 1 }].as_ref()
    }
}

#[derive(Clone, Copy)]
enum TransferDirection {
    Read,
    Write,
}

#[derive(Debug)]
enum TaskFile {
    Lba28 {
        drive_head: u8,
        count: u8,
        lba: [u8; 3],
    },
    Lba48 {
        drive_head: u8,
        count: [u8; 2],
        lba: [u8; 6],
    },
}

/// Fully validated host request and its hardware register representation.
/// No size arithmetic or narrowing conversion remains after publication.
#[derive(Debug)]
struct TransferPlan {
    sector_bytes: usize,
    byte_count: usize,
    task_file: TaskFile,
}

impl TransferPlan {
    fn new(
        device: &IdentifyData,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer_length: usize,
    ) -> Result<Self, IdeError> {
        if device.device_type != DeviceType::Ata {
            return Err(IdeError::NotSupported);
        }
        if count == 0 || device.sector_size == 0 || !device.sector_size.is_multiple_of(2) {
            return Err(IdeError::InvalidRequest);
        }
        let sector_bytes =
            usize::try_from(device.sector_size).map_err(|_| IdeError::InvalidRequest)?;
        let byte_count = sector_bytes
            .checked_mul(usize::from(count))
            .ok_or(IdeError::InvalidRequest)?;
        if byte_count > buffer_length {
            return Err(IdeError::BufferTooSmall);
        }
        let end = lba
            .checked_add(u64::from(count))
            .ok_or(IdeError::InvalidRequest)?;
        let capacity = if device.lba48_supported {
            device.sectors_48
        } else {
            u64::from(device.sectors_28)
        };
        if end > capacity || end > (1u64 << 48) {
            return Err(IdeError::InvalidRequest);
        }
        let bytes = lba.to_le_bytes();
        let task_file = if end <= (1u64 << 28) && count <= 256 {
            let encoded_count = if count == 256 {
                0
            } else {
                u8::try_from(count).map_err(|_| IdeError::InvalidRequest)?
            };
            TaskFile::Lba28 {
                drive_head: drive.value() | 0x40 | bytes[3],
                count: encoded_count,
                lba: [bytes[0], bytes[1], bytes[2]],
            }
        } else if device.lba48_supported {
            TaskFile::Lba48 {
                drive_head: drive.value() | 0x40,
                count: count.to_le_bytes(),
                lba: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
            }
        } else {
            return Err(IdeError::NotSupported);
        };
        Ok(Self {
            sector_bytes,
            byte_count,
            task_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(lba48_supported: bool) -> IdentifyData {
        IdentifyData {
            device_type: DeviceType::Ata,
            model: alloc::string::String::new(),
            serial: alloc::string::String::new(),
            firmware: alloc::string::String::new(),
            sectors_28: 1 << 28,
            sectors_48: 1 << 48,
            lba48_supported,
            dma_supported: false,
            udma_mode: None,
            sector_size: 512,
        }
    }

    #[test]
    fn zero_count_is_not_a_hardware_maximum_transfer() {
        assert!(matches!(
            TransferPlan::new(&disk(true), DriveSel::Master, 0, 0, 0),
            Err(IdeError::InvalidRequest)
        ));
    }

    #[test]
    fn buffer_and_capacity_are_validated_before_publication() {
        assert!(matches!(
            TransferPlan::new(&disk(false), DriveSel::Master, 0, 2, 511),
            Err(IdeError::BufferTooSmall)
        ));
        assert!(matches!(
            TransferPlan::new(&disk(true), DriveSel::Master, u64::MAX, 1, 512),
            Err(IdeError::InvalidRequest)
        ));
        assert!(matches!(
            TransferPlan::new(&disk(false), DriveSel::Master, (1 << 28) - 1, 2, 1024),
            Err(IdeError::InvalidRequest)
        ));
    }

    #[test]
    fn logical_sector_size_must_be_nonzero_and_word_divisible() {
        let mut device = disk(true);
        for invalid in [0, 511, 513] {
            device.sector_size = invalid;
            assert!(matches!(
                TransferPlan::new(&device, DriveSel::Master, 0, 1, usize::MAX),
                Err(IdeError::InvalidRequest)
            ));
        }
        device.sector_size = 4096;
        let plan = TransferPlan::new(&device, DriveSel::Master, 0, 2, 8192)
            .expect("valid logical-sector request");
        assert_eq!(plan.byte_count, 8192);
    }

    #[test]
    fn register_count_encoding_matches_addressing_mode() {
        let plan = TransferPlan::new(&disk(false), DriveSel::Slave, 0, 256, 256 * 512)
            .expect("valid LBA28 request");
        assert!(matches!(
            plan.task_file,
            TaskFile::Lba28 {
                count: 0,
                drive_head: 0xf0,
                ..
            }
        ));
        let plan = TransferPlan::new(&disk(true), DriveSel::Master, 0, 257, 257 * 512)
            .expect("valid LBA48 request");
        assert!(matches!(
            plan.task_file,
            TaskFile::Lba48 { count: [1, 1], .. }
        ));
    }
}
