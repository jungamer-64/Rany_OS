// ============================================================================
// src/io/pci/legacy.rs - Legacy PCI I/O Port Access
// ============================================================================
//!
//! Legacy PCI Configuration Space アクセス (I/O ポートベース)
//!
//! 従来の PCI 2.x 方式の CF8h/CFCh ポートを使用した Configuration Space アクセス。
//! 256バイトの Configuration Space のみアクセス可能。

use crate::traits::ConfigSpaceAccessor;
use crate::types::BdfAddress;
use exorust_sync::IrqPoisonLock;
use hal::IoPortRange;
use spin::Once;

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
    range: IoPortRange,
}

impl LegacyPciPorts {
    fn new() -> Self {
        // SAFETY: PCI configuration mechanism #1 reserves CF8-CFF as one
        // serialized platform resource. `LEGACY_PCI` is its sole owner.
        let range = unsafe { IoPortRange::from_raw_parts(PCI_CONFIG_ADDRESS, 8) }
            .expect("the fixed PCI configuration range cannot overflow");
        Self { range }
    }
}

/// グローバルな Legacy PCI アクセサ
static LEGACY_PCI: Once<IrqPoisonLock<LegacyPciPorts>> = Once::new();

fn legacy_ports() -> &'static IrqPoisonLock<LegacyPciPorts> {
    LEGACY_PCI.call_once(|| IrqPoisonLock::new(LegacyPciPorts::new()))
}

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

    /// The address latch and data access form one IRQ/SMP-serialized transaction.
    fn with_selected<R>(
        bdf: BdfAddress,
        offset: u8,
        access: impl FnOnce(&IoPortRange, u16) -> R,
    ) -> R {
        let address = Self::make_address(bdf, offset);
        let ports = legacy_ports()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut address_port = ports
            .range
            .first::<u32>()
            .expect("the address port is inside the PCI configuration range");
        address_port.write(address);
        access(
            &ports.range,
            PCI_CONFIG_DATA - PCI_CONFIG_ADDRESS + u16::from(offset & 3),
        )
    }
}

impl ConfigSpaceAccessor for LegacyPciAccessor {
    fn read8(&self, bdf: BdfAddress, offset: u16) -> u8 {
        if offset >= 256 {
            return 0xFF;
        }
        Self::with_selected(bdf, offset as u8, |ports, data| {
            ports
                .port::<u8>(data)
                .expect("validated PCI byte lane")
                .read()
        })
    }

    fn read16(&self, bdf: BdfAddress, offset: u16) -> u16 {
        if offset >= 256 || (offset & 1) != 0 {
            return 0xFFFF;
        }
        Self::with_selected(bdf, offset as u8, |ports, data| {
            ports
                .port::<u16>(data)
                .expect("validated PCI word lane")
                .read()
        })
    }

    fn read32(&self, bdf: BdfAddress, offset: u16) -> u32 {
        if offset >= 256 || (offset & 3) != 0 {
            return 0xFFFFFFFF;
        }
        Self::with_selected(bdf, offset as u8, |ports, data| {
            ports
                .port::<u32>(data)
                .expect("validated PCI dword lane")
                .read()
        })
    }

    fn write8(&self, bdf: BdfAddress, offset: u16, value: u8) {
        if offset >= 256 {
            return;
        }
        Self::with_selected(bdf, offset as u8, |ports, data| {
            ports
                .port::<u8>(data)
                .expect("validated PCI byte lane")
                .write(value);
        });
    }

    fn write16(&self, bdf: BdfAddress, offset: u16, value: u16) {
        if offset >= 256 || (offset & 1) != 0 {
            return;
        }
        Self::with_selected(bdf, offset as u8, |ports, data| {
            ports
                .port::<u16>(data)
                .expect("validated PCI word lane")
                .write(value);
        });
    }

    fn write32(&self, bdf: BdfAddress, offset: u16, value: u32) {
        if offset >= 256 || (offset & 3) != 0 {
            return;
        }
        Self::with_selected(bdf, offset as u8, |ports, data| {
            ports
                .port::<u32>(data)
                .expect("validated PCI dword lane")
                .write(value);
        });
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

/// グローバルアクセサを取得（内部利用限定）
///
/// NOTE: External callers should prefer ECAM APIs (`EcamAccess`) or
/// `pci_driver`'s modern accessors. This function's visibility is intentionally
/// restricted to crate-local use to avoid propagating legacy I/O accessors.
#[doc(hidden)]
pub(crate) fn get_legacy_accessor() -> &'static LegacyPciAccessor {
    &GLOBAL_LEGACY_ACCESSOR
}
