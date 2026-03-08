use super::{
    DeviceType, DriveSel, IdeChannel, IdeController, IdeError, IdentifyData, PortU8, PortU16,
    commands, regs, status,
};

impl IdeChannel {
    /// 新しいIDEチャネルを作成
    pub fn new(controller: IdeController) -> Self {
        Self {
            controller,
            io_base: controller.io_base(),
            control_base: controller.control_base(),
            devices: [None, None],
        }
    }

    /// レジスタを読み取り
    #[inline]
    pub(super) fn read_reg(&self, reg: u16) -> u8 {
        // 8-bit I/O registers. PortU8::read() is a safe wrapper around the
        // architecture-specific inb instruction; therefore this is safe.
        PortU8::new(self.io_base + reg).read()
    }

    /// レジスタに書き込み
    #[inline]
    pub(super) fn write_reg(&self, reg: u16, value: u8) {
        PortU8::new(self.io_base + reg).write(value);
    }

    /// ステータスを読み取り
    #[inline]
    pub(super) fn read_status(&self) -> u8 {
        self.read_reg(regs::STATUS)
    }

    /// 代替ステータスを読み取り（割り込みクリアなし）
    #[inline]
    pub(super) fn read_alt_status(&self) -> u8 {
        PortU8::new(self.control_base).read()
    }

    /// ビジーフラグが解除されるまで待機
    unsafe fn wait_not_busy(&self) -> Result<(), IdeError> {
        let mut timeout = 100_000;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while timeout > 0 {
            let status = self.read_alt_status();
            if (status & status::BSY) == 0 {
                return Ok(());
            }
            timeout -= 1;
        }
        Err(IdeError::Timeout)
    }

    /// DRQがセットされるまで待機
    unsafe fn wait_drq(&self) -> Result<(), IdeError> {
        let mut timeout = 100_000;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while timeout > 0 {
            let status = self.read_alt_status();
            if (status & status::BSY) == 0 {
                if (status & status::ERR) != 0 {
                    return Err(IdeError::DeviceError);
                }
                if (status & status::DRQ) != 0 {
                    return Ok(());
                }
            }
            timeout -= 1;
        }
        Err(IdeError::Timeout)
    }

    /// ドライブを選択
    unsafe fn select_drive(&self, drive: DriveSel) {
        unsafe {
            self.write_reg(regs::DRIVE, drive.value());
        }
        // 400ns待機（4回のステータス読み取り）
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }
    }

    /// ソフトリセット
    pub unsafe fn soft_reset(&self) {
        // SRST=1
        {
            let mut ctrl = PortU8::new(self.control_base);
            ctrl.write(0x04);
        }
        // 少なくとも5us待機
        for _ in 0..10 {
            let _ = self.read_alt_status();
        }
        // SRST=0
        {
            let mut ctrl = PortU8::new(self.control_base);
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
            if let Some(identify) = unsafe { self.identify_device(*drive) } {
                self.devices[i] = Some(identify);
            }
        }
    }

    /// ATAPIかATAかを判定
    unsafe fn detect_device_type(&self) -> Option<DeviceType> {
        let lba_mid = self.read_reg(regs::LBA_MID);
        let lba_high = self.read_reg(regs::LBA_HIGH);
        if lba_mid == 0x14 && lba_high == 0xEB {
            unsafe {
                self.write_reg(regs::COMMAND, commands::IDENTIFY_PACKET);
            }
            if unsafe { self.wait_drq() }.is_err() {
                return None;
            }
            Some(DeviceType::Atapi)
        } else if lba_mid == 0 && lba_high == 0 {
            if unsafe { self.wait_drq() }.is_err() {
                return None;
            }
            Some(DeviceType::Ata)
        } else {
            None
        }
    }

    /// デバイスを識別
    unsafe fn identify_device(&self, drive: DriveSel) -> Option<IdentifyData> {
        unsafe {
            self.select_drive(drive);
        }

        // フローティングバスチェック
        if self.read_status() == 0xFF {
            return None;
        }

        // ドライブ選択後の待機
        unsafe {
            self.select_drive(drive);
        }
        unsafe {
            self.write_reg(regs::SECTOR_COUNT, 0);
        }
        unsafe {
            self.write_reg(regs::LBA_LOW, 0);
        }
        unsafe {
            self.write_reg(regs::LBA_MID, 0);
        }
        unsafe {
            self.write_reg(regs::LBA_HIGH, 0);
        }

        // IDENTIFYコマンドを発行
        unsafe {
            self.write_reg(regs::COMMAND, commands::IDENTIFY);
        }

        // ステータスが0ならデバイスなし
        let status = unsafe { self.read_status() };
        if status == 0 {
            return None;
        }

        // ビジー解除を待機
        if unsafe { self.wait_not_busy() }.is_err() {
            return None;
        }

        // ATAPIデバイスチェック
        let device_type = unsafe { self.detect_device_type() }?;

        // IDENTIFYデータを読み取り
        let mut words = [0u16; 256];
        let mut data_port = PortU16::new(self.io_base + regs::DATA);
        unsafe { data_port.read_words(&mut words) };

        let mut identify = IdentifyData::from_words(&words);
        identify.device_type = device_type;

        Some(identify)
    }

    /// セクタを読み取り（PIO）
    pub fn read_sectors(
        &self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &mut [u8],
    ) -> Result<(), IdeError> {
        let device = &self.devices[if drive == DriveSel::Master { 0 } else { 1 }];
        let device = device.as_ref().ok_or(IdeError::NoDevice)?;

        if device.device_type != DeviceType::Ata {
            return Err(IdeError::NotSupported);
        }

        let sector_size = device.sector_size as usize;
        let required_size = count as usize * sector_size;
        if buffer.len() < required_size {
            return Err(IdeError::BufferTooSmall);
        }

        unsafe {
            self.wait_not_busy()?;

            if device.lba48_supported && lba >= 0x10000000 {
                self.read_sectors_lba48(drive, lba, count, buffer)
            } else {
                self.read_sectors_lba28(drive, lba as u32, count as u8, buffer)
            }
        }
    }

    /// LBA28モードでセクタを読み取り
    unsafe fn read_sectors_lba28(
        &self,
        drive: DriveSel,
        lba: u32,
        count: u8,
        buffer: &mut [u8],
    ) -> Result<(), IdeError> {
        // ドライブとLBA上位4ビットを選択
        let drive_head = drive.value() | 0x40 | ((lba >> 24) & 0x0F) as u8;
        unsafe {
            self.write_reg(regs::DRIVE, drive_head);
        }

        // 400ns待機
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }

        unsafe {
            self.write_reg(regs::SECTOR_COUNT, count);
        }
        unsafe {
            self.write_reg(regs::LBA_LOW, lba as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_MID, (lba >> 8) as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_HIGH, (lba >> 16) as u8);
        }
        unsafe {
            self.write_reg(regs::COMMAND, commands::READ_SECTORS);
        }

        let mut data_port = PortU16::new(self.io_base + regs::DATA);
        let sectors_to_read = if count == 0 { 256 } else { count as usize };

        for i in 0..sectors_to_read {
            unsafe {
                self.wait_drq()?;
            }

            // ワード単位で読み取り
            let offset = i * 512;
            let sector_buffer = &mut buffer[offset..offset + 512];
            let word_buffer: &mut [u16] = unsafe {
                core::slice::from_raw_parts_mut(sector_buffer.as_mut_ptr() as *mut u16, 256)
            };
            unsafe { data_port.read_words(word_buffer) };
        }

        Ok(())
    }

    /// LBA48モードでセクタを読み取り
    unsafe fn read_sectors_lba48(
        &self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &mut [u8],
    ) -> Result<(), IdeError> {
        // ドライブを選択（LBAモード）
        let drive_head = drive.value() | 0x40;
        unsafe {
            self.write_reg(regs::DRIVE, drive_head);
        }

        // 400ns待機
        for _ in 0..4 {
            let _ = unsafe { self.read_alt_status() };
        }

        // 高位バイトを先に書き込み
        unsafe {
            self.write_reg(regs::SECTOR_COUNT, (count >> 8) as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_LOW, (lba >> 24) as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_MID, (lba >> 32) as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_HIGH, (lba >> 40) as u8);
        }

        // 低位バイトを書き込み
        unsafe {
            self.write_reg(regs::SECTOR_COUNT, count as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_LOW, lba as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_MID, (lba >> 8) as u8);
        }
        unsafe {
            self.write_reg(regs::LBA_HIGH, (lba >> 16) as u8);
        }

        unsafe {
            self.write_reg(regs::COMMAND, commands::READ_SECTORS_EXT);
        }

        let mut data_port = PortU16::new(self.io_base + regs::DATA);
        let sectors_to_read = if count == 0 { 65536 } else { count as usize };

        for i in 0..sectors_to_read {
            unsafe {
                self.wait_drq()?;
            }

            let offset = i * 512;
            let sector_buffer = &mut buffer[offset..offset + 512];
            let word_buffer: &mut [u16] = unsafe {
                core::slice::from_raw_parts_mut(sector_buffer.as_mut_ptr() as *mut u16, 256)
            };
            unsafe { data_port.read_words(word_buffer) };
        }

        Ok(())
    }

    /// セクタを書き込み（PIO）
    pub fn write_sectors(
        &self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &[u8],
    ) -> Result<(), IdeError> {
        let device = &self.devices[if drive == DriveSel::Master { 0 } else { 1 }];
        let device = device.as_ref().ok_or(IdeError::NoDevice)?;

        if device.device_type != DeviceType::Ata {
            return Err(IdeError::NotSupported);
        }

        let sector_size = device.sector_size as usize;
        let required_size = count as usize * sector_size;
        if buffer.len() < required_size {
            return Err(IdeError::BufferTooSmall);
        }

        unsafe {
            self.wait_not_busy()?;

            if device.lba48_supported && lba >= 0x10000000 {
                self.write_sectors_lba48(drive, lba, count, buffer)
            } else {
                self.write_sectors_lba28(drive, lba as u32, count as u8, buffer)
            }
        }
    }

    /// LBA28モードでセクタを書き込み
    unsafe fn write_sectors_lba28(
        &self,
        drive: DriveSel,
        lba: u32,
        count: u8,
        buffer: &[u8],
    ) -> Result<(), IdeError> {
        let drive_head = drive.value() | 0x40 | ((lba >> 24) & 0x0F) as u8;
        self.write_reg(regs::DRIVE, drive_head);

        for _ in 0..4 {
            let _ = self.read_alt_status();
        }

        self.write_reg(regs::SECTOR_COUNT, count);
        self.write_reg(regs::LBA_LOW, lba as u8);
        self.write_reg(regs::LBA_MID, (lba >> 8) as u8);
        self.write_reg(regs::LBA_HIGH, (lba >> 16) as u8);
        self.write_reg(regs::COMMAND, commands::WRITE_SECTORS);

        let mut data_port = PortU16::new(self.io_base + regs::DATA);
        let sectors_to_write = if count == 0 { 256 } else { count as usize };

        for i in 0..sectors_to_write {
            unsafe {
                self.wait_drq()?;
            }

            let offset = i * 512;
            let sector_buffer = &buffer[offset..offset + 512];
            let word_buffer: &[u16] =
                unsafe { core::slice::from_raw_parts(sector_buffer.as_ptr() as *const u16, 256) };
            unsafe { data_port.write_words(word_buffer) };
        }

        // キャッシュフラッシュ
        self.write_reg(regs::COMMAND, commands::CACHE_FLUSH);
        unsafe {
            self.wait_not_busy()?;
        }

        Ok(())
    }

    /// LBA48モードでセクタを書き込み
    unsafe fn write_sectors_lba48(
        &self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &[u8],
    ) -> Result<(), IdeError> {
        let drive_head = drive.value() | 0x40;
        unsafe {
            self.write_reg(regs::DRIVE, drive_head);
        }

        for _ in 0..4 {
            let _ = unsafe { self.read_alt_status() };
        }

        unsafe {
            self.write_reg(regs::SECTOR_COUNT, (count >> 8) as u8);
            self.write_reg(regs::LBA_LOW, (lba >> 24) as u8);
            self.write_reg(regs::LBA_MID, (lba >> 32) as u8);
            self.write_reg(regs::LBA_HIGH, (lba >> 40) as u8);

            self.write_reg(regs::SECTOR_COUNT, count as u8);
            self.write_reg(regs::LBA_LOW, lba as u8);
            self.write_reg(regs::LBA_MID, (lba >> 8) as u8);
            self.write_reg(regs::LBA_HIGH, (lba >> 16) as u8);

            self.write_reg(regs::COMMAND, commands::WRITE_SECTORS_EXT);
        }

        let mut data_port = PortU16::new(self.io_base + regs::DATA);
        let sectors_to_write = if count == 0 { 65536 } else { count as usize };

        for i in 0..sectors_to_write {
            unsafe {
                self.wait_drq()?;
                let offset = i * 512;
                let sector_buffer = &buffer[offset..offset + 512];
                let word_buffer: &[u16] = unsafe {
                    core::slice::from_raw_parts(sector_buffer.as_ptr() as *const u16, 256)
                };
                data_port.write_words(word_buffer);
            }
        }

        unsafe {
            self.write_reg(regs::COMMAND, commands::CACHE_FLUSH_EXT);
            self.wait_not_busy()?;
        }

        Ok(())
    }

    /// 接続されたデバイス情報を取得
    pub fn get_device(&self, drive: DriveSel) -> Option<&IdentifyData> {
        self.devices[if drive == DriveSel::Master { 0 } else { 1 }].as_ref()
    }
}
