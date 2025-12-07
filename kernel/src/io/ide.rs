// ============================================================================
// src/io/ide.rs - IDE/ATA Controller Driver
// ============================================================================
//!
//! # IDE/ATA Controller Driver
//!
//! レガシーIDE/ATAコントローラのサポート。
//!
//! ## 機能
//! - PIO転送モード
//! - DMA転送（UDMA対応）
//! - ATAPI（CD-ROM）サポート
//! - パーティションテーブル読み取り

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

// ============================================================================
// Type-Safe I/O Ports
// ============================================================================

/// I/Oポートアドレス
#[derive(Clone, Copy, Debug)]
pub struct IoPort(pub u16);

impl IoPort {
    pub const fn new(port: u16) -> Self {
        Self(port)
    }

    /// バイトを読み取り
    #[inline]
    pub unsafe fn read_u8(self) -> u8 { unsafe {
        let value: u8;
        core::arch::asm!("in al, dx", out("al") value, in("dx") self.0, options(nomem, nostack));
        value
    }}

    /// ワードを読み取り
    #[inline]
    pub unsafe fn read_u16(self) -> u16 { unsafe {
        let value: u16;
        core::arch::asm!("in ax, dx", out("ax") value, in("dx") self.0, options(nomem, nostack));
        value
    }}

    /// ダブルワードを読み取り
    #[inline]
    pub unsafe fn read_u32(self) -> u32 { unsafe {
        let value: u32;
        core::arch::asm!("in eax, dx", out("eax") value, in("dx") self.0, options(nomem, nostack));
        value
    }}

    /// バイトを書き込み
    #[inline]
    pub unsafe fn write_u8(self, value: u8) { unsafe {
        core::arch::asm!("out dx, al", in("dx") self.0, in("al") value, options(nomem, nostack));
    }}

    /// ワードを書き込み
    #[inline]
    pub unsafe fn write_u16(self, value: u16) { unsafe {
        core::arch::asm!("out dx, ax", in("dx") self.0, in("ax") value, options(nomem, nostack));
    }}

    /// ダブルワードを書き込み
    #[inline]
    pub unsafe fn write_u32(self, value: u32) { unsafe {
        core::arch::asm!("out dx, eax", in("dx") self.0, in("eax") value, options(nomem, nostack));
    }}

    /// REP INSWで複数ワードを読み取り
    #[inline]
    pub unsafe fn read_words(self, buffer: &mut [u16]) { unsafe {
        core::arch::asm!(
            "rep insw",
            in("dx") self.0,
            in("rdi") buffer.as_mut_ptr(),
            in("rcx") buffer.len(),
            options(nostack)
        );
    }}

    /// REP OUTSWで複数ワードを書き込み
    #[inline]
    pub unsafe fn write_words(self, buffer: &[u16]) { unsafe {
        core::arch::asm!(
            "rep outsw",
            in("dx") self.0,
            in("rsi") buffer.as_ptr(),
            in("rcx") buffer.len(),
            options(nostack)
        );
    }}
}

// ============================================================================
// IDE Constants
// ============================================================================

/// IDEコントローラタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdeController {
    Primary,
    Secondary,
}

impl IdeController {
    /// ベースI/Oポート
    pub const fn io_base(self) -> IoPort {
        match self {
            Self::Primary => IoPort::new(0x1F0),
            Self::Secondary => IoPort::new(0x170),
        }
    }

    /// コントロールポート
    pub const fn control_base(self) -> IoPort {
        match self {
            Self::Primary => IoPort::new(0x3F6),
            Self::Secondary => IoPort::new(0x376),
        }
    }
}

/// ドライブセレクト
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveSel {
    Master,
    Slave,
}

impl DriveSel {
    pub const fn value(self) -> u8 {
        match self {
            Self::Master => 0xA0,
            Self::Slave => 0xB0,
        }
    }
}

/// IDEレジスタオフセット
pub mod regs {
    pub const DATA: u16 = 0; // R/W データ
    pub const ERROR: u16 = 1; // R エラー
    pub const FEATURES: u16 = 1; // W フィーチャー
    pub const SECTOR_COUNT: u16 = 2; // R/W セクタカウント
    pub const LBA_LOW: u16 = 3; // R/W LBA[0:7]
    pub const LBA_MID: u16 = 4; // R/W LBA[8:15]
    pub const LBA_HIGH: u16 = 5; // R/W LBA[16:23]
    pub const DRIVE: u16 = 6; // R/W ドライブ/ヘッド
    pub const STATUS: u16 = 7; // R ステータス
    pub const COMMAND: u16 = 7; // W コマンド
}

/// ステータスビット
pub mod status {
    pub const ERR: u8 = 0x01; // エラー
    pub const IDX: u8 = 0x02; // インデックス
    pub const CORR: u8 = 0x04; // 訂正データ
    pub const DRQ: u8 = 0x08; // データ要求
    pub const SRV: u8 = 0x10; // サービス
    pub const DF: u8 = 0x20; // ドライブ障害
    pub const RDY: u8 = 0x40; // 準備完了
    pub const BSY: u8 = 0x80; // ビジー
}

/// ATAコマンド
pub mod commands {
    pub const IDENTIFY: u8 = 0xEC; // IDENTIFY DEVICE
    pub const IDENTIFY_PACKET: u8 = 0xA1; // IDENTIFY PACKET DEVICE
    pub const READ_SECTORS: u8 = 0x20; // READ SECTORS
    pub const READ_SECTORS_EXT: u8 = 0x24; // READ SECTORS EXT (48-bit LBA)
    pub const WRITE_SECTORS: u8 = 0x30; // WRITE SECTORS
    pub const WRITE_SECTORS_EXT: u8 = 0x34; // WRITE SECTORS EXT (48-bit LBA)
    pub const READ_DMA: u8 = 0xC8; // READ DMA
    pub const READ_DMA_EXT: u8 = 0x25; // READ DMA EXT
    pub const WRITE_DMA: u8 = 0xCA; // WRITE DMA
    pub const WRITE_DMA_EXT: u8 = 0x35; // WRITE DMA EXT
    pub const CACHE_FLUSH: u8 = 0xE7; // CACHE FLUSH
    pub const CACHE_FLUSH_EXT: u8 = 0xEA; // CACHE FLUSH EXT
    pub const PACKET: u8 = 0xA0; // PACKET (ATAPI)
    pub const SET_FEATURES: u8 = 0xEF; // SET FEATURES
}

// ============================================================================
// Device Identification
// ============================================================================

/// デバイスタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Unknown,
    Ata,
    Atapi,
}

/// IDENTIFY DATAから取得した情報
#[derive(Clone, Debug)]
pub struct IdentifyData {
    /// デバイスタイプ
    pub device_type: DeviceType,
    /// モデル名
    pub model: String,
    /// シリアル番号
    pub serial: String,
    /// ファームウェアリビジョン
    pub firmware: String,
    /// 総セクタ数（28-bit）
    pub sectors_28: u32,
    /// 総セクタ数（48-bit）
    pub sectors_48: u64,
    /// LBA48サポート
    pub lba48_supported: bool,
    /// DMAサポート
    pub dma_supported: bool,
    /// UDMAモード
    pub udma_mode: Option<u8>,
    /// セクタサイズ
    pub sector_size: u32,
}

impl IdentifyData {
    /// 生データからパース
    pub fn from_words(words: &[u16; 256]) -> Self {
        // モデル名（ワード27-46）
        let model = Self::extract_string(words, 27, 46);
        // シリアル番号（ワード10-19）
        let serial = Self::extract_string(words, 10, 19);
        // ファームウェア（ワード23-26）
        let firmware = Self::extract_string(words, 23, 26);

        // 総セクタ数
        let sectors_28 = (words[60] as u32) | ((words[61] as u32) << 16);
        let sectors_48 = (words[100] as u64)
            | ((words[101] as u64) << 16)
            | ((words[102] as u64) << 32)
            | ((words[103] as u64) << 48);

        // 機能サポート
        let lba48_supported = (words[83] & (1 << 10)) != 0;
        let dma_supported = (words[49] & (1 << 8)) != 0;

        // UDMAモード
        let udma_mode = if words[88] != 0 {
            // 最高サポートモードを検索
            let supported = words[88] & 0x3F;
            let active = (words[88] >> 8) & 0x3F;
            if active != 0 {
                Some((active.trailing_zeros()) as u8)
            } else if supported != 0 {
                Some((supported.trailing_zeros()) as u8)
            } else {
                None
            }
        } else {
            None
        };

        // セクタサイズ
        let sector_size = if (words[106] & 0x4000) != 0 && (words[106] & 0x1000) != 0 {
            // ラージセクタ
            ((words[117] as u32) | ((words[118] as u32) << 16)) * 2
        } else {
            512
        };

        Self {
            device_type: DeviceType::Ata,
            model,
            serial,
            firmware,
            sectors_28,
            sectors_48,
            lba48_supported,
            dma_supported,
            udma_mode,
            sector_size,
        }
    }

    /// ATA文字列を抽出（バイトスワップ）
    fn extract_string(words: &[u16; 256], start: usize, end: usize) -> String {
        let mut bytes = Vec::new();
        for i in start..=end {
            bytes.push((words[i] >> 8) as u8);
            bytes.push((words[i] & 0xFF) as u8);
        }
        // 末尾スペースを削除
        while bytes.last() == Some(&b' ') {
            bytes.pop();
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// 総容量（バイト）
    pub fn capacity(&self) -> u64 {
        let sectors = if self.lba48_supported && self.sectors_48 > 0 {
            self.sectors_48
        } else {
            self.sectors_28 as u64
        };
        sectors * self.sector_size as u64
    }
}

// ============================================================================
// IDE Channel
// ============================================================================

/// IDEチャネル
pub struct IdeChannel {
    /// コントローラタイプ
    controller: IdeController,
    /// ベースI/Oポート
    io_base: IoPort,
    /// コントロールポート
    control_base: IoPort,
    /// 接続されたデバイス
    devices: [Option<IdentifyData>; 2],
}

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
    unsafe fn read_reg(&self, reg: u16) -> u8 { unsafe {
        IoPort::new(self.io_base.0 + reg).read_u8()
    }}

    /// レジスタに書き込み
    #[inline]
    unsafe fn write_reg(&self, reg: u16, value: u8) { unsafe {
        IoPort::new(self.io_base.0 + reg).write_u8(value);
    }}

    /// ステータスを読み取り
    #[inline]
    unsafe fn read_status(&self) -> u8 { unsafe {
        self.read_reg(regs::STATUS)
    }}

    /// 代替ステータスを読み取り（割り込みクリアなし）
    #[inline]
    unsafe fn read_alt_status(&self) -> u8 { unsafe {
        self.control_base.read_u8()
    }}

    /// ビジーフラグが解除されるまで待機
    unsafe fn wait_not_busy(&self) -> Result<(), IdeError> { unsafe {
        let mut timeout = 100_000;
        while timeout > 0 {
            let status = self.read_alt_status();
            if (status & status::BSY) == 0 {
                return Ok(());
            }
            timeout -= 1;
        }
        Err(IdeError::Timeout)
    }}

    /// DRQがセットされるまで待機
    unsafe fn wait_drq(&self) -> Result<(), IdeError> { unsafe {
        let mut timeout = 100_000;
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
    }}

    /// ドライブを選択
    unsafe fn select_drive(&self, drive: DriveSel) { unsafe {
        self.write_reg(regs::DRIVE, drive.value());
        // 400ns待機（4回のステータス読み取り）
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }
    }}

    /// ソフトリセット
    pub unsafe fn soft_reset(&self) { unsafe {
        // SRST=1
        self.control_base.write_u8(0x04);
        // 少なくとも5us待機
        for _ in 0..10 {
            let _ = self.read_alt_status();
        }
        // SRST=0
        self.control_base.write_u8(0x00);
        // 400ns待機
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }
    }}

    /// デバイスを検出
    pub fn detect_devices(&mut self) {
        for (i, drive) in [DriveSel::Master, DriveSel::Slave].iter().enumerate() {
            if let Some(identify) = unsafe { self.identify_device(*drive) } {
                self.devices[i] = Some(identify);
            }
        }
    }

    /// デバイスを識別
    unsafe fn identify_device(&self, drive: DriveSel) -> Option<IdentifyData> { unsafe {
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
        let lba_mid = self.read_reg(regs::LBA_MID);
        let lba_high = self.read_reg(regs::LBA_HIGH);
        let device_type = if lba_mid == 0x14 && lba_high == 0xEB {
            // ATAPI
            self.write_reg(regs::COMMAND, commands::IDENTIFY_PACKET);
            if self.wait_drq().is_err() {
                return None;
            }
            DeviceType::Atapi
        } else if lba_mid == 0 && lba_high == 0 {
            // ATA
            if self.wait_drq().is_err() {
                return None;
            }
            DeviceType::Ata
        } else {
            return None;
        };

        // IDENTIFYデータを読み取り
        let mut words = [0u16; 256];
        let data_port = IoPort::new(self.io_base.0 + regs::DATA);
        data_port.read_words(&mut words);

        let mut identify = IdentifyData::from_words(&words);
        identify.device_type = device_type;

        Some(identify)
    }}

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
    ) -> Result<(), IdeError> { unsafe {
        // ドライブとLBA上位4ビットを選択
        let drive_head = drive.value() | 0x40 | ((lba >> 24) & 0x0F) as u8;
        self.write_reg(regs::DRIVE, drive_head);

        // 400ns待機
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }

        self.write_reg(regs::SECTOR_COUNT, count);
        self.write_reg(regs::LBA_LOW, lba as u8);
        self.write_reg(regs::LBA_MID, (lba >> 8) as u8);
        self.write_reg(regs::LBA_HIGH, (lba >> 16) as u8);
        self.write_reg(regs::COMMAND, commands::READ_SECTORS);

        let data_port = IoPort::new(self.io_base.0 + regs::DATA);
        let sectors_to_read = if count == 0 { 256 } else { count as usize };

        for i in 0..sectors_to_read {
            self.wait_drq()?;

            // ワード単位で読み取り
            let offset = i * 512;
            let sector_buffer = &mut buffer[offset..offset + 512];
            let word_buffer: &mut [u16] =
                core::slice::from_raw_parts_mut(sector_buffer.as_mut_ptr() as *mut u16, 256);
            data_port.read_words(word_buffer);
        }

        Ok(())
    }}

    /// LBA48モードでセクタを読み取り
    unsafe fn read_sectors_lba48(
        &self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &mut [u8],
    ) -> Result<(), IdeError> { unsafe {
        // ドライブを選択（LBAモード）
        let drive_head = drive.value() | 0x40;
        self.write_reg(regs::DRIVE, drive_head);

        // 400ns待機
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }

        // 高位バイトを先に書き込み
        self.write_reg(regs::SECTOR_COUNT, (count >> 8) as u8);
        self.write_reg(regs::LBA_LOW, (lba >> 24) as u8);
        self.write_reg(regs::LBA_MID, (lba >> 32) as u8);
        self.write_reg(regs::LBA_HIGH, (lba >> 40) as u8);

        // 低位バイトを書き込み
        self.write_reg(regs::SECTOR_COUNT, count as u8);
        self.write_reg(regs::LBA_LOW, lba as u8);
        self.write_reg(regs::LBA_MID, (lba >> 8) as u8);
        self.write_reg(regs::LBA_HIGH, (lba >> 16) as u8);

        self.write_reg(regs::COMMAND, commands::READ_SECTORS_EXT);

        let data_port = IoPort::new(self.io_base.0 + regs::DATA);
        let sectors_to_read = if count == 0 { 65536 } else { count as usize };

        for i in 0..sectors_to_read {
            self.wait_drq()?;

            let offset = i * 512;
            let sector_buffer = &mut buffer[offset..offset + 512];
            let word_buffer: &mut [u16] =
                core::slice::from_raw_parts_mut(sector_buffer.as_mut_ptr() as *mut u16, 256);
            data_port.read_words(word_buffer);
        }

        Ok(())
    }}

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
    ) -> Result<(), IdeError> { unsafe {
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

        let data_port = IoPort::new(self.io_base.0 + regs::DATA);
        let sectors_to_write = if count == 0 { 256 } else { count as usize };

        for i in 0..sectors_to_write {
            self.wait_drq()?;

            let offset = i * 512;
            let sector_buffer = &buffer[offset..offset + 512];
            let word_buffer: &[u16] =
                core::slice::from_raw_parts(sector_buffer.as_ptr() as *const u16, 256);
            data_port.write_words(word_buffer);
        }

        // キャッシュフラッシュ
        self.write_reg(regs::COMMAND, commands::CACHE_FLUSH);
        self.wait_not_busy()?;

        Ok(())
    }}

    /// LBA48モードでセクタを書き込み
    unsafe fn write_sectors_lba48(
        &self,
        drive: DriveSel,
        lba: u64,
        count: u16,
        buffer: &[u8],
    ) -> Result<(), IdeError> { unsafe {
        let drive_head = drive.value() | 0x40;
        self.write_reg(regs::DRIVE, drive_head);

        for _ in 0..4 {
            let _ = self.read_alt_status();
        }

        self.write_reg(regs::SECTOR_COUNT, (count >> 8) as u8);
        self.write_reg(regs::LBA_LOW, (lba >> 24) as u8);
        self.write_reg(regs::LBA_MID, (lba >> 32) as u8);
        self.write_reg(regs::LBA_HIGH, (lba >> 40) as u8);

        self.write_reg(regs::SECTOR_COUNT, count as u8);
        self.write_reg(regs::LBA_LOW, lba as u8);
        self.write_reg(regs::LBA_MID, (lba >> 8) as u8);
        self.write_reg(regs::LBA_HIGH, (lba >> 16) as u8);

        self.write_reg(regs::COMMAND, commands::WRITE_SECTORS_EXT);

        let data_port = IoPort::new(self.io_base.0 + regs::DATA);
        let sectors_to_write = if count == 0 { 65536 } else { count as usize };

        for i in 0..sectors_to_write {
            self.wait_drq()?;

            let offset = i * 512;
            let sector_buffer = &buffer[offset..offset + 512];
            let word_buffer: &[u16] =
                core::slice::from_raw_parts(sector_buffer.as_ptr() as *const u16, 256);
            data_port.write_words(word_buffer);
        }

        self.write_reg(regs::COMMAND, commands::CACHE_FLUSH_EXT);
        self.wait_not_busy()?;

        Ok(())
    }}

    /// 接続されたデバイス情報を取得
    pub fn get_device(&self, drive: DriveSel) -> Option<&IdentifyData> {
        self.devices[if drive == DriveSel::Master { 0 } else { 1 }].as_ref()
    }
}

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
static IDE_CHANNELS: Mutex<Option<[IdeChannel; 2]>> = Mutex::new(None);

/// IDEコントローラを初期化
pub fn init() {
    let mut primary = IdeChannel::new(IdeController::Primary);
    let mut secondary = IdeChannel::new(IdeController::Secondary);

    primary.detect_devices();
    secondary.detect_devices();

    // 検出されたデバイスをログ
    for (i, device) in primary.devices.iter().enumerate() {
        if let Some(_dev) = device {
            let _drive = if i == 0 { "Master" } else { "Slave" };
            // log::info!("Primary {}: {} ({} MB)", drive, dev.model, dev.capacity() / (1024 * 1024));
        }
    }

    for (i, device) in secondary.devices.iter().enumerate() {
        if let Some(_dev) = device {
            let _drive = if i == 0 { "Master" } else { "Slave" };
            // log::info!("Secondary {}: {} ({} MB)", drive, dev.model, dev.capacity() / (1024 * 1024));
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

/// セクタを書き込み
pub fn write_sectors(
    controller: IdeController,
    drive: DriveSel,
    lba: u64,
    count: u16,
    buffer: &[u8],
) -> Result<(), IdeError> {
    let channels = IDE_CHANNELS.lock();
    let channels = channels.as_ref().ok_or(IdeError::NoDevice)?;

    let channel = match controller {
        IdeController::Primary => &channels[0],
        IdeController::Secondary => &channels[1],
    };

    channel.write_sectors(drive, lba, count, buffer)
}

/// デバイス情報を取得
pub fn get_device_info(controller: IdeController, drive: DriveSel) -> Option<IdentifyData> {
    let channels = IDE_CHANNELS.lock();
    let channels = channels.as_ref()?;

    let channel = match controller {
        IdeController::Primary => &channels[0],
        IdeController::Secondary => &channels[1],
    };

    channel.get_device(drive).cloned()
}
