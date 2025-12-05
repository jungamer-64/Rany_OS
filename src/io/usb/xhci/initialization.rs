// ============================================================================
// src/io/usb/xhci/initialization.rs - xHCI Controller Initialization
// ============================================================================
//!
//! xHCI コントローラの初期化シーケンス。
//!
//! ## 初期化フロー
//! 1. ケーパビリティレジスタ読み取り
//! 2. コントローラ停止・リセット
//! 3. 構造体（DCBAA, コマンドリング, イベントリング）設定
//! 4. コントローラ開始

#![allow(dead_code)]

use core::ptr;

use super::{
    CONFIG, CRCR, DCBAAP, ERDP, ERSTBA, ERSTSZ, IMAN, IR0,
    USBCMD, USBCMD_HCRST, USBCMD_INTE, USBCMD_RUN, USBSTS, USBSTS_CNR, USBSTS_HCH,
};
use crate::io::usb::{UsbError, UsbResult};

// Register offsets from Capability Registers
const CAPLENGTH: usize = 0x00;
const HCIVERSION: usize = 0x02;
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCSPARAMS3: usize = 0x0C;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;
const HCCPARAMS2: usize = 0x1C;

/// xHCI ケーパビリティ情報
#[derive(Debug, Clone)]
pub struct XhciCapabilities {
    /// HCI バージョン
    pub hci_version: u16,
    /// 最大スロット数
    pub max_slots: u8,
    /// 最大インタラプタ数
    pub max_interrupters: u16,
    /// 最大ポート数
    pub max_ports: u8,
    /// Isoch Scheduling Threshold
    pub ist: u8,
    /// Event Ring Segment Table Max
    pub erst_max: u8,
    /// 64ビットアドレッシングサポート
    pub ac64: bool,
    /// Bandwidth Negotiation Capability
    pub bnc: bool,
    /// 64バイトコンテキストサイズ
    pub context_size_64: bool,
    /// ページサイズ
    pub page_size: u32,
    /// Operational Registers オフセット
    pub op_offset: u64,
    /// Runtime Registers オフセット
    pub rt_offset: u64,
    /// Doorbell Registers オフセット
    pub db_offset: u64,
}

impl XhciCapabilities {
    /// ケーパビリティレジスタを読み取り
    pub fn read(base_addr: u64) -> Self {
        let caplength = unsafe { ptr::read_volatile((base_addr + CAPLENGTH as u64) as *const u8) };
        let hciversion = unsafe { ptr::read_volatile((base_addr + HCIVERSION as u64) as *const u16) };
        let hcsparams1 = unsafe { ptr::read_volatile((base_addr + HCSPARAMS1 as u64) as *const u32) };
        let hcsparams2 = unsafe { ptr::read_volatile((base_addr + HCSPARAMS2 as u64) as *const u32) };
        let hccparams1 = unsafe { ptr::read_volatile((base_addr + HCCPARAMS1 as u64) as *const u32) };
        let dboff = unsafe { ptr::read_volatile((base_addr + DBOFF as u64) as *const u32) };
        let rtsoff = unsafe { ptr::read_volatile((base_addr + RTSOFF as u64) as *const u32) };

        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_interrupters = ((hcsparams1 >> 8) & 0x7FF) as u16;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

        let ist = (hcsparams2 & 0x0F) as u8;
        let erst_max = ((hcsparams2 >> 4) & 0x0F) as u8;

        let ac64 = (hccparams1 & 0x01) != 0;
        let bnc = (hccparams1 & 0x02) != 0;
        let context_size_64 = (hccparams1 & 0x04) != 0;

        let op_offset = base_addr + caplength as u64;
        let rt_offset = base_addr + (rtsoff & !0x1F) as u64;
        let db_offset = base_addr + (dboff & !0x03) as u64;

        Self {
            hci_version: hciversion,
            max_slots,
            max_interrupters,
            max_ports,
            ist,
            erst_max,
            ac64,
            bnc,
            context_size_64,
            page_size: 4096, // デフォルト、PAGESIZEレジスタから読み取り可能
            op_offset,
            rt_offset,
            db_offset,
        }
    }
}

/// xHCI 初期化コンテキスト
pub struct XhciInitContext {
    base_addr: u64,
    op_offset: u64,
    rt_offset: u64,
}

impl XhciInitContext {
    pub fn new(base_addr: u64, caps: &XhciCapabilities) -> Self {
        Self {
            base_addr,
            op_offset: caps.op_offset,
            rt_offset: caps.rt_offset,
        }
    }

    /// コントローラを停止
    pub fn stop_controller(&self) -> UsbResult<()> {
        let mut cmd = self.read_op(USBCMD);
        cmd &= !USBCMD_RUN;
        self.write_op(USBCMD, cmd);

        // HCHビットが1になるまで待機
        for _ in 0..100 {
            let status = self.read_op(USBSTS);
            if (status & USBSTS_HCH) != 0 {
                return Ok(());
            }
            // 短い遅延
            core::hint::spin_loop();
        }

        Err(UsbError::Timeout)
    }

    /// コントローラをリセット
    pub fn reset_controller(&self) -> UsbResult<()> {
        let mut cmd = self.read_op(USBCMD);
        cmd |= USBCMD_HCRST;
        self.write_op(USBCMD, cmd);

        // HCRSTビットが0になるまで待機
        for _ in 0..100 {
            let cmd = self.read_op(USBCMD);
            if (cmd & USBCMD_HCRST) == 0 {
                // CNRビットも確認
                let status = self.read_op(USBSTS);
                if (status & USBSTS_CNR) == 0 {
                    return Ok(());
                }
            }
            core::hint::spin_loop();
        }

        Err(UsbError::Timeout)
    }

    /// 構造体アドレスを設定
    pub fn setup_data_structures(
        &self,
        max_slots: u8,
        dcbaa_addr: u64,
        command_ring_addr: u64,
        erst_addr: u64,
        event_ring_addr: u64,
    ) {
        // 最大スロット数を設定
        self.write_op(CONFIG, max_slots as u32);

        // DCBAAを設定
        self.write_op_64(DCBAAP, dcbaa_addr);

        // コマンドリングを設定 (RCS = 1)
        self.write_op_64(CRCR, command_ring_addr | 1);

        // イベントリングを設定
        // ERSTSZ (Event Ring Segment Table Size)
        self.write_runtime(ERSTSZ, 1);

        // ERDP (Event Ring Dequeue Pointer)
        self.write_runtime_64(ERDP, event_ring_addr);

        // ERSTBA (Event Ring Segment Table Base Address)
        self.write_runtime_64(ERSTBA, erst_addr);

        // 割り込みを有効化 (IP | IE)
        self.write_runtime(IMAN, 0x3);
    }

    /// コントローラを開始
    pub fn start_controller(&self) -> UsbResult<()> {
        let mut cmd = self.read_op(USBCMD);
        cmd |= USBCMD_RUN | USBCMD_INTE;
        self.write_op(USBCMD, cmd);

        // HCHビットが0になるまで待機
        for _ in 0..100 {
            let status = self.read_op(USBSTS);
            if (status & USBSTS_HCH) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(UsbError::Timeout)
    }

    /// 完全な初期化シーケンス
    pub fn full_initialization(
        &self,
        max_slots: u8,
        dcbaa_addr: u64,
        command_ring_addr: u64,
        erst_addr: u64,
        event_ring_addr: u64,
    ) -> UsbResult<()> {
        // 1. 停止
        self.stop_controller()?;

        // 2. リセット
        self.reset_controller()?;

        // 3. データ構造設定
        self.setup_data_structures(
            max_slots,
            dcbaa_addr,
            command_ring_addr,
            erst_addr,
            event_ring_addr,
        );

        // 4. 開始
        self.start_controller()?;

        Ok(())
    }

    // ヘルパー関数
    fn read_op(&self, offset: usize) -> u32 {
        unsafe { ptr::read_volatile((self.op_offset + offset as u64) as *const u32) }
    }

    fn write_op(&self, offset: usize, value: u32) {
        unsafe { ptr::write_volatile((self.op_offset + offset as u64) as *mut u32, value) }
    }

    fn write_op_64(&self, offset: usize, value: u64) {
        unsafe { ptr::write_volatile((self.op_offset + offset as u64) as *mut u64, value) }
    }

    fn read_runtime(&self, offset: usize) -> u32 {
        unsafe { ptr::read_volatile((self.rt_offset + IR0 as u64 + offset as u64) as *const u32) }
    }

    fn write_runtime(&self, offset: usize, value: u32) {
        unsafe { ptr::write_volatile((self.rt_offset + IR0 as u64 + offset as u64) as *mut u32, value) }
    }

    fn write_runtime_64(&self, offset: usize, value: u64) {
        unsafe { ptr::write_volatile((self.rt_offset + IR0 as u64 + offset as u64) as *mut u64, value) }
    }
}
