
// AHCI ATAPI - re-export from driver crate

//! ATAPI support for AHCI (migrated to `ahci_driver` crate).
//! This file exists for backward compatibility and re-exports the driver API.

pub use ahci_driver::atapi::*;

    /// トレイをイジェクト
    pub fn eject(&mut self) -> AhciResult<()> {
        let cdb = ScsiCdb12::start_stop_unit(false, true);
        let mut buffer = [];
        self.packet_command(&cdb, &mut buffer, false)?;
        Ok(())
    }

    /// トレイをロード
    pub fn load(&mut self) -> AhciResult<()> {
        let cdb = ScsiCdb12::start_stop_unit(true, true);
        let mut buffer = [];
        self.packet_command(&cdb, &mut buffer, false)?;
        Ok(())
    }

    /// スピンアップ
    pub fn spin_up(&mut self) -> AhciResult<()> {
        let cdb = ScsiCdb12::start_stop_unit(true, false);
        let mut buffer = [];
        self.packet_command(&cdb, &mut buffer, false)?;
        Ok(())
    }

    // ========================================================================
    // Internal Methods
    // ========================================================================

    fn find_slot(&self) -> Option<SlotNumber> {
        let sact = self.read_port(0x34);
        let ci = self.read_port(PX_CI);
        let busy = sact | ci;

        for i in 0..32 {
            if (busy & (1 << i)) == 0 {
                return Some(SlotNumber(i));
            }
        }

        None
    }

    fn wait_completion(&self, slot: SlotNumber) -> AhciResult<()> {
        let slot_mask = 1u32 << slot.as_u8();

        for _ in 0..100000 {
            let ci = self.read_port(PX_CI);
            if (ci & slot_mask) == 0 {
                let tfd = self.read_port(PX_TFD);
                let status = (tfd & 0xFF) as u8;
                let error = ((tfd >> 8) & 0xFF) as u8;

                if (status & 0x01) != 0 {
                    return Err(AhciError::TaskFileError(error));
                }

                return Ok(());
            }

            let is = self.read_port(PX_IS);
            if (is & (1 << 30)) != 0 {
                let tfd = self.read_port(PX_TFD);
                let error = ((tfd >> 8) & 0xFF) as u8;
                return Err(AhciError::TaskFileError(error));
            }
        }

        Err(AhciError::Timeout)
    }

    fn read_port(&self, offset: u32) -> u32 {
        crate::io::mmio::mmio_read_u32((self.port_base + offset as u64) as usize)
    }

    fn write_port(&self, offset: u32, value: u32) {
        crate::io::mmio::mmio_write_u32((self.port_base + offset as u64) as usize, value);
    }
}

// ============================================================================
// CD/DVD Drive Abstraction
// ============================================================================

/// CD/DVDドライブ情報
#[derive(Debug, Clone)]
pub struct CdDvdDriveInfo {
    /// ベンダー名
    pub vendor: String,
    /// プロダクト名
    pub product: String,
    /// リビジョン
    pub revision: String,
    /// デバイスタイプ
    pub device_type: AtapiDeviceType,
    /// リムーバブル
    pub removable: bool,
}

/// CD/DVDドライブ
pub struct CdDvdDrive {
    port: AtapiPort,
    info: Option<CdDvdDriveInfo>,
}

impl CdDvdDrive {
    /// 新しいCD/DVDドライブを作成
    pub fn new(base: u64, port_number: PortNumber) -> Self {
        Self {
            port: AtapiPort::new(base, port_number),
            info: None,
        }
    }

    /// ドライブを初期化
    pub fn init(&mut self) -> AhciResult<()> {
        // Inquiryでデバイス情報を取得
        let inquiry = self.port.inquiry()?;

        self.info = Some(CdDvdDriveInfo {
            vendor: inquiry.vendor_string(),
            product: inquiry.product_string(),
            revision: inquiry.revision_string(),
            device_type: inquiry.device_type(),
            removable: inquiry.is_removable(),
        });

        Ok(())
    }

    /// ドライブ情報を取得
    pub fn info(&self) -> Option<&CdDvdDriveInfo> {
        self.info.as_ref()
    }

    /// メディアが挿入されているか確認
    pub fn is_media_present(&mut self) -> bool {
        self.port.test_unit_ready().unwrap_or(false)
    }

    /// メディア容量を取得
    pub fn media_capacity(&mut self) -> AhciResult<(u64, u32)> {
        let cap = self.port.read_capacity()?;
        Ok((cap.total_blocks(), cap.block_length()))
    }

    /// セクタを読み取り
    pub fn read(&mut self, lba: u32, count: u16, buffer: &mut [u8]) -> AhciResult<usize> {
        self.port.read_sectors(lba, count, buffer)
    }

    /// TOCを読み取り
    pub fn read_toc(&mut self) -> AhciResult<TableOfContents> {
        self.port.read_toc()
    }

    /// トレイをイジェクト
    pub fn eject(&mut self) -> AhciResult<()> {
        self.port.eject()
    }

    /// トレイをロード
    pub fn load(&mut self) -> AhciResult<()> {
        self.port.load()
    }

    /// 最後のエラー情報を取得
    pub fn last_error(&mut self) -> AhciResult<SenseData> {
        self.port.request_sense()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdb_read10() {
        let cdb = ScsiCdb12::read10(0x12345678, 256);
        assert_eq!(cdb.opcode, ScsiOpcode::Read10 as u8);
        assert_eq!(cdb.lba_hi, 0x12);
        assert_eq!(cdb.lba_mid_hi, 0x34);
        assert_eq!(cdb.lba_mid_lo, 0x56);
        assert_eq!(cdb.lba_lo, 0x78);
        assert_eq!(cdb.length_mid_lo, 0x01);
        assert_eq!(cdb.length_lo, 0x00);
    }

    #[test]
    fn test_sense_key() {
        assert_eq!(SenseKey::from_code(0x00), SenseKey::NoSense);
        assert_eq!(SenseKey::from_code(0x02), SenseKey::NotReady);
        assert_eq!(SenseKey::from_code(0x05), SenseKey::IllegalRequest);
    }

    #[test]
    fn test_read_capacity_endianness() {
        let response = ReadCapacityResponse {
            last_lba_be: 0x01020304u32.to_be(),
            block_length_be: 0x00000800u32.to_be(), // 2048
        };
        assert_eq!(response.last_lba(), 0x01020304);
        assert_eq!(response.block_length(), 2048);
    }
}
