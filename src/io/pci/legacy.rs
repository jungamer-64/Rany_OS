// ============================================================================
// src/io/pci/legacy.rs - Legacy PCI I/O Port Access
// ============================================================================
//!
//! Legacy PCI Configuration Space アクセス (I/O ポートベース)
//!
//! 従来の PCI 2.x 方式の CF8h/CFCh ポートを使用した Configuration Space アクセス。
//! 256バイトの Configuration Space のみアクセス可能。

use super::traits::ConfigSpaceAccessor;
use super::types::BdfAddress;
use spin::Mutex;
use x86_64::instructions::port::Port;

// ============================================================================
// Constants
// ============================================================================

/// PCI configuration address port
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
/// PCI configuration data port
const PCI_CONFIG_DATA: u16 = 0xCFC;

// ============================================================================
// Legacy PCI Accessor
// ============================================================================

/// Legacy PCI I/O ポートアクセサ（内部状態）
struct LegacyPciPorts {
    address_port: Port<u32>,
    data_port: Port<u32>,
}

impl LegacyPciPorts {
    const fn new() -> Self {
        Self {
            address_port: Port::new(PCI_CONFIG_ADDRESS),
            data_port: Port::new(PCI_CONFIG_DATA),
        }
    }
}

/// グローバルな Legacy PCI アクセサ
static LEGACY_PCI: Mutex<LegacyPciPorts> = Mutex::new(LegacyPciPorts::new());

/// Legacy PCI Configuration Space アクセサ
///
/// I/O ポート 0xCF8/0xCFC を使用した従来の PCI アクセス方式。
#[derive(Clone, Copy, Debug, Default)]
pub struct LegacyPciAccessor;

impl LegacyPciAccessor {
    /// 新しいアクセサを作成
    pub const fn new() -> Self {
        Self
    }

    /// PCI アドレスを作成
    fn make_address(bdf: BdfAddress, offset: u8) -> u32 {
        ((bdf.bus.0 as u32) << 16)
            | ((bdf.device.0 as u32) << 11)
            | ((bdf.function.0 as u32) << 8)
            | ((offset as u32) & 0xFC)
            | 0x80000000 // Enable bit
    }

    /// 32ビット読み取り（内部）
    fn read_dword(&self, bdf: BdfAddress, offset: u8) -> u32 {
        let address = Self::make_address(bdf, offset);
        let mut ports = LEGACY_PCI.lock();
        unsafe {
            ports.address_port.write(address);
            ports.data_port.read()
        }
    }

    /// 32ビット書き込み（内部）
    fn write_dword(&self, bdf: BdfAddress, offset: u8, value: u32) {
        let address = Self::make_address(bdf, offset);
        let mut ports = LEGACY_PCI.lock();
        unsafe {
            ports.address_port.write(address);
            ports.data_port.write(value);
        }
    }
}

impl ConfigSpaceAccessor for LegacyPciAccessor {
    fn read8(&self, bdf: BdfAddress, offset: u16) -> u8 {
        if offset >= 256 {
            return 0xFF;
        }
        let dword = self.read_dword(bdf, (offset & 0xFC) as u8);
        let shift = (offset & 3) * 8;
        (dword >> shift) as u8
    }

    fn read16(&self, bdf: BdfAddress, offset: u16) -> u16 {
        if offset >= 256 || (offset & 1) != 0 {
            return 0xFFFF;
        }
        let dword = self.read_dword(bdf, (offset & 0xFC) as u8);
        let shift = (offset & 2) * 8;
        (dword >> shift) as u16
    }

    fn read32(&self, bdf: BdfAddress, offset: u16) -> u32 {
        if offset >= 256 || (offset & 3) != 0 {
            return 0xFFFFFFFF;
        }
        self.read_dword(bdf, offset as u8)
    }

    fn write8(&self, bdf: BdfAddress, offset: u16, value: u8) {
        if offset >= 256 {
            return;
        }
        let aligned_offset = (offset & 0xFC) as u8;
        let shift = (offset & 3) * 8;
        let mask = !(0xFF << shift);
        let dword = self.read_dword(bdf, aligned_offset);
        let new_value = (dword & mask) | ((value as u32) << shift);
        self.write_dword(bdf, aligned_offset, new_value);
    }

    fn write16(&self, bdf: BdfAddress, offset: u16, value: u16) {
        if offset >= 256 || (offset & 1) != 0 {
            return;
        }
        let aligned_offset = (offset & 0xFC) as u8;
        let shift = (offset & 2) * 8;
        let mask = !(0xFFFF << shift);
        let dword = self.read_dword(bdf, aligned_offset);
        let new_value = (dword & mask) | ((value as u32) << shift);
        self.write_dword(bdf, aligned_offset, new_value);
    }

    fn write32(&self, bdf: BdfAddress, offset: u16, value: u32) {
        if offset >= 256 || (offset & 3) != 0 {
            return;
        }
        self.write_dword(bdf, offset as u8, value);
    }
}

// ============================================================================
// Global Functions (Backward Compatibility)
// ============================================================================

/// グローバルな Legacy PCI アクセサ
static GLOBAL_LEGACY_ACCESSOR: LegacyPciAccessor = LegacyPciAccessor::new();

/// Legacy PCI 32ビット読み取り
pub fn pci_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let bdf = BdfAddress::new(bus, device, function);
    GLOBAL_LEGACY_ACCESSOR.read32(bdf, offset as u16)
}

/// Legacy PCI 32ビット書き込み
pub fn pci_write(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let bdf = BdfAddress::new(bus, device, function);
    GLOBAL_LEGACY_ACCESSOR.write32(bdf, offset as u16, value);
}

/// Legacy PCI 16ビット読み取り
pub fn pci_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let bdf = BdfAddress::new(bus, device, function);
    GLOBAL_LEGACY_ACCESSOR.read16(bdf, offset as u16)
}

/// Legacy PCI 8ビット読み取り
pub fn pci_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let bdf = BdfAddress::new(bus, device, function);
    GLOBAL_LEGACY_ACCESSOR.read8(bdf, offset as u16)
}

/// グローバルアクセサを取得
pub fn get_legacy_accessor() -> &'static LegacyPciAccessor {
    &GLOBAL_LEGACY_ACCESSOR
}
