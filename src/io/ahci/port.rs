//! AHCIポート実装
//!
//! 個々のSATAポートの管理とコマンド実行

extern crate alloc;

use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::AtomicU32;

use super::command::{CommandHeader, CommandTable, PhysicalRegionDescriptor, ReceivedFis};
use super::fis::FisRegH2D;
use super::identify::IdentifyData;
use super::types::{
    AhciError, AhciResult, DeviceType, Lba, PortNumber, SectorCount, SlotNumber,
    PORT_BASE, PORT_SIZE, PX_CI, PX_CLB, PX_CLBU, PX_CMD, PX_CMD_CR, PX_CMD_FR,
    PX_CMD_FRE, PX_CMD_ST, PX_FB, PX_FBU, PX_IE, PX_IS, PX_IS_DHRS, PX_IS_DSS,
    PX_IS_PSS, PX_IS_SDBS, PX_IS_TFES, PX_SACT, PX_SERR, PX_SIG, PX_TFD,
};

/// AHCIポート
pub struct AhciPort {
    /// ポート番号
    port: PortNumber,
    /// ベースアドレス
    base: u64,
    /// ポートベースアドレス
    port_base: u64,
    /// デバイスタイプ
    device_type: DeviceType,
    /// コマンドリスト
    command_list: Box<[CommandHeader; 32]>,
    /// Received FIS
    received_fis: Box<ReceivedFis>,
    /// コマンドテーブル
    command_tables: [Option<Box<CommandTable>>; 32],
    /// アクティブなコマンド
    active_commands: AtomicU32,
}

impl AhciPort {
    /// 新しいポートを作成
    pub fn new(base: u64, port: PortNumber) -> Self {
        let port_base = base + PORT_BASE as u64 + (port.as_u8() as u64 * PORT_SIZE as u64);

        Self {
            port,
            base,
            port_base,
            device_type: DeviceType::None,
            command_list: Box::new([CommandHeader::default(); 32]),
            received_fis: Box::new(unsafe { core::mem::zeroed() }),
            command_tables: Default::default(),
            active_commands: AtomicU32::new(0),
        }
    }

    /// ポートを初期化
    pub fn init(&mut self) -> AhciResult<()> {
        // ポートを停止
        self.stop()?;

        // コマンドリストとFISのアドレスを設定
        let clb = self.command_list.as_ptr() as u64;
        let fb = self.received_fis.as_ref() as *const _ as u64;

        self.write_port(PX_CLB, clb as u32);
        self.write_port(PX_CLBU, (clb >> 32) as u32);
        self.write_port(PX_FB, fb as u32);
        self.write_port(PX_FBU, (fb >> 32) as u32);

        // SATAエラーをクリア
        self.write_port(PX_SERR, 0xFFFFFFFF);

        // 割り込みをクリア
        self.write_port(PX_IS, 0xFFFFFFFF);

        // 割り込みを有効化
        self.write_port(
            PX_IE,
            PX_IS_DHRS | PX_IS_PSS | PX_IS_DSS | PX_IS_SDBS | PX_IS_TFES,
        );

        // ポートを開始
        self.start()?;

        // デバイスシグネチャを確認
        let sig = self.read_port(PX_SIG);
        self.device_type = DeviceType::from_signature(sig);

        Ok(())
    }

    /// ポートを開始
    fn start(&self) -> AhciResult<()> {
        // FIS受信を有効化
        let mut cmd = self.read_port(PX_CMD);
        cmd |= PX_CMD_FRE;
        self.write_port(PX_CMD, cmd);

        // コマンド実行を有効化
        cmd = self.read_port(PX_CMD);
        cmd |= PX_CMD_ST;
        self.write_port(PX_CMD, cmd);

        Ok(())
    }

    /// ポートを停止
    fn stop(&self) -> AhciResult<()> {
        // コマンド実行を停止
        let mut cmd = self.read_port(PX_CMD);
        cmd &= !PX_CMD_ST;
        self.write_port(PX_CMD, cmd);

        // CRビットがクリアされるまで待機
        for _ in 0..500 {
            let cmd = self.read_port(PX_CMD);
            if (cmd & PX_CMD_CR) == 0 {
                break;
            }
        }

        // FIS受信を停止
        cmd = self.read_port(PX_CMD);
        cmd &= !PX_CMD_FRE;
        self.write_port(PX_CMD, cmd);

        // FRビットがクリアされるまで待機
        for _ in 0..500 {
            let cmd = self.read_port(PX_CMD);
            if (cmd & PX_CMD_FR) == 0 {
                return Ok(());
            }
        }

        Err(AhciError::Timeout)
    }

    /// 空きコマンドスロットを見つける
    fn find_slot(&self) -> Option<SlotNumber> {
        let sact = self.read_port(PX_SACT);
        let ci = self.read_port(PX_CI);
        let busy = sact | ci;

        for i in 0..32 {
            if (busy & (1 << i)) == 0 {
                return Some(SlotNumber(i));
            }
        }

        None
    }

    /// IDENTIFYコマンドを実行
    pub fn identify(&mut self) -> AhciResult<IdentifyData> {
        let slot = self.find_slot().ok_or(AhciError::NoCommandSlot)?;

        // コマンドテーブルを準備
        let cmd_table = Box::new(CommandTable::default());
        let cmd_table_addr = cmd_table.as_ref() as *const _ as u64;

        // FISを設定
        let fis = FisRegH2D::identify();
        unsafe {
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_ptr() as *mut u8,
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // 結果バッファを用意
        let identify_buffer = Box::new([0u16; 256]);
        let buffer_addr = identify_buffer.as_ptr() as u64;

        // PRDTを設定
        unsafe {
            let prdt_ptr = cmd_table.prdt.as_ptr() as *mut PhysicalRegionDescriptor;
            *prdt_ptr = PhysicalRegionDescriptor::new(buffer_addr, 512, true);
        }

        // コマンドヘッダを設定
        let header = &mut self.command_list[slot.as_usize()];
        header.set_flags(5, false, false, false); // CFL = 5 dwords
        header.prdtl = 1;
        header.prdbc = 0;
        header.set_ctba(cmd_table_addr);

        // コマンドテーブルを保存
        self.command_tables[slot.as_usize()] = Some(cmd_table);

        // コマンドを発行
        self.write_port(PX_CI, 1 << slot.as_u8());

        // 完了を待機
        self.wait_completion(slot)?;

        // 結果を取得
        Ok(IdentifyData::from_words(&identify_buffer))
    }

    /// セクタを読み取り
    pub fn read_sectors(
        &mut self,
        lba: Lba,
        count: SectorCount,
        buffer: &mut [u8],
    ) -> AhciResult<()> {
        if buffer.len() < count.to_bytes() as usize {
            return Err(AhciError::InvalidParameter);
        }

        let slot = self.find_slot().ok_or(AhciError::NoCommandSlot)?;

        // コマンドテーブルを準備
        let mut cmd_table = Box::new(CommandTable::default());
        let cmd_table_addr = cmd_table.as_ref() as *const _ as u64;

        // FISを設定
        let fis = FisRegH2D::read_dma_ext(lba, count);
        unsafe {
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // PRDTを設定
        let buffer_addr = buffer.as_ptr() as u64;
        cmd_table.prdt[0] =
            PhysicalRegionDescriptor::new(buffer_addr, count.to_bytes() as u32, true);

        // コマンドヘッダを設定
        let header = &mut self.command_list[slot.as_usize()];
        header.set_flags(5, false, false, false);
        header.prdtl = 1;
        header.prdbc = 0;
        header.set_ctba(cmd_table_addr);

        self.command_tables[slot.as_usize()] = Some(cmd_table);

        // コマンドを発行
        self.write_port(PX_CI, 1 << slot.as_u8());

        // 完了を待機
        self.wait_completion(slot)
    }

    /// セクタを書き込み
    pub fn write_sectors(&mut self, lba: Lba, count: SectorCount, buffer: &[u8]) -> AhciResult<()> {
        if buffer.len() < count.to_bytes() as usize {
            return Err(AhciError::InvalidParameter);
        }

        let slot = self.find_slot().ok_or(AhciError::NoCommandSlot)?;

        // コマンドテーブルを準備
        let mut cmd_table = Box::new(CommandTable::default());
        let cmd_table_addr = cmd_table.as_ref() as *const _ as u64;

        // FISを設定
        let fis = FisRegH2D::write_dma_ext(lba, count);
        unsafe {
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );
        }

        // PRDTを設定
        let buffer_addr = buffer.as_ptr() as u64;
        cmd_table.prdt[0] =
            PhysicalRegionDescriptor::new(buffer_addr, count.to_bytes() as u32, true);

        // コマンドヘッダを設定
        let header = &mut self.command_list[slot.as_usize()];
        header.set_flags(5, true, false, false); // W=1 for write
        header.prdtl = 1;
        header.prdbc = 0;
        header.set_ctba(cmd_table_addr);

        self.command_tables[slot.as_usize()] = Some(cmd_table);

        // コマンドを発行
        self.write_port(PX_CI, 1 << slot.as_u8());

        // 完了を待機
        self.wait_completion(slot)
    }

    /// コマンド完了を待機
    fn wait_completion(&self, slot: SlotNumber) -> AhciResult<()> {
        let slot_mask = 1u32 << slot.as_u8();

        for _ in 0..100000 {
            let ci = self.read_port(PX_CI);
            if (ci & slot_mask) == 0 {
                // 完了
                let tfd = self.read_port(PX_TFD);
                let status = (tfd & 0xFF) as u8;
                let error = ((tfd >> 8) & 0xFF) as u8;

                if (status & 0x01) != 0 {
                    // エラーステータス
                    return Err(AhciError::TaskFileError(error));
                }

                return Ok(());
            }

            // タスクファイルエラーを確認
            let is = self.read_port(PX_IS);
            if (is & PX_IS_TFES) != 0 {
                let tfd = self.read_port(PX_TFD);
                let error = ((tfd >> 8) & 0xFF) as u8;
                return Err(AhciError::TaskFileError(error));
            }
        }

        Err(AhciError::Timeout)
    }

    /// デバイスタイプを取得
    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    /// ポートレジスタを読み取り
    pub fn read_port(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.port_base + offset as u64) as *const u32) }
    }

    /// ポートレジスタを書き込み
    pub fn write_port(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.port_base + offset as u64) as *mut u32, value) }
    }
}

// Default実装
impl Default for AhciPort {
    fn default() -> Self {
        Self {
            port: PortNumber(0),
            base: 0,
            port_base: 0,
            device_type: DeviceType::None,
            command_list: Box::new([CommandHeader::default(); 32]),
            received_fis: Box::new(unsafe { core::mem::zeroed() }),
            command_tables: Default::default(),
            active_commands: AtomicU32::new(0),
        }
    }
}
