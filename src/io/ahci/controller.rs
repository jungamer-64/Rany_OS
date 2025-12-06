//! AHCIコントローラ実装
//!
//! HBAの管理とポートの初期化

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use spin::Mutex;

use super::port::AhciPort;
use super::types::{
    AhciResult, PortNumber,
    GHC_AE, GHC_CAP, GHC_GHC, GHC_IE, GHC_PI, GHC_VS,
    PORT_BASE, PORT_SIZE, PX_SSTS,
};

/// AHCIコントローラ
pub struct AhciController {
    /// ベースアドレス
    base: u64,
    /// 利用可能なポートのビットマップ
    ports_implemented: u32,
    /// ポート
    ports: Mutex<[Option<Box<AhciPort>>; 32]>,
    /// バージョン
    version: u32,
    /// コマンドスロット数
    command_slots: u8,
}

impl AhciController {
    /// 新しいコントローラを作成
    pub fn new(base: u64) -> AhciResult<Self> {
        let cap = unsafe { ptr::read_volatile((base + GHC_CAP as u64) as *const u32) };
        let pi = unsafe { ptr::read_volatile((base + GHC_PI as u64) as *const u32) };
        let vs = unsafe { ptr::read_volatile((base + GHC_VS as u64) as *const u32) };

        let command_slots = ((cap >> 8) & 0x1F) as u8 + 1;
        let _version_major = (vs >> 16) & 0xFFFF;
        let _version_minor = vs & 0xFFFF;

        const NONE_PORT: Option<Box<AhciPort>> = None;

        Ok(Self {
            base,
            ports_implemented: pi,
            ports: Mutex::new([NONE_PORT; 32]),
            version: vs,
            command_slots,
        })
    }

    /// コントローラを初期化
    pub fn init(&mut self) -> AhciResult<()> {
        // AHCIを有効化
        let mut ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_AE;
        self.write_ghc(GHC_GHC, ghc);

        // 実装されているポートを初期化
        let mut ports = self.ports.lock();
        for i in 0..32 {
            if (self.ports_implemented & (1 << i)) != 0 {
                let port = PortNumber(i);
                let mut ahci_port = Box::new(AhciPort::new(self.base, port));

                // ポートステータスを確認
                let ssts = self.read_port_reg(port, PX_SSTS);
                let det = ssts & 0x0F;

                if det == 3 {
                    // デバイスが接続されている
                    let _ = ahci_port.init();
                }

                ports[i as usize] = Some(ahci_port);
            }
        }

        // 割り込みを有効化
        ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_IE;
        self.write_ghc(GHC_GHC, ghc);

        Ok(())
    }

    /// ポートを取得
    pub fn port(&self, port: PortNumber) -> Option<&AhciPort> {
        if !port.is_valid() {
            return None;
        }
        if (self.ports_implemented & (1 << port.as_u8())) == 0 {
            return None;
        }

        // Note: 実際の実装では適切なライフタイム管理が必要
        None
    }

    /// 実装されているポートのビットマップを取得
    pub fn ports_implemented(&self) -> u32 {
        self.ports_implemented
    }

    /// バージョンを取得
    pub fn version(&self) -> u32 {
        self.version
    }

    /// コマンドスロット数を取得
    pub fn command_slots(&self) -> u8 {
        self.command_slots
    }

    /// GHCレジスタを読み取り
    pub fn read_ghc(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    /// GHCレジスタを書き込み
    pub fn write_ghc(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((self.base + offset as u64) as *mut u32, value) }
    }

    /// ポートレジスタを読み取り
    pub fn read_port_reg(&self, port: PortNumber, offset: u32) -> u32 {
        let addr =
            self.base + PORT_BASE as u64 + (port.as_u8() as u64 * PORT_SIZE as u64) + offset as u64;
        unsafe { ptr::read_volatile(addr as *const u32) }
    }
}

/// PCIデバイスからAHCIを初期化
pub fn init_from_pci(base_addr: u64) -> AhciResult<Arc<Mutex<AhciController>>> {
    let mut controller = AhciController::new(base_addr)?;
    controller.init()?;
    Ok(Arc::new(Mutex::new(controller)))
}
