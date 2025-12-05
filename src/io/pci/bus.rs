// ============================================================================
// src/io/pci/bus.rs - PCI Bus Enumeration
// ============================================================================
//!
//! # PCIバス列挙
//!
//! PCIデバイスの検出と列挙機能を提供。
//! レガシーPCIとPCIe両方のアクセス方式に対応。

use alloc::vec::Vec;
use super::traits::ConfigSpaceAccessor;
use super::types::{BdfAddress, ClassCode, Bar, VendorId, DeviceId};

// ============================================================================
// Configuration Space Register Offsets
// ============================================================================

/// 標準PCI設定空間レジスタオフセット
pub mod config_regs {
    pub const VENDOR_ID: u16 = 0x00;
    pub const DEVICE_ID: u16 = 0x02;
    pub const COMMAND: u16 = 0x04;
    pub const STATUS: u16 = 0x06;
    pub const REVISION_ID: u16 = 0x08;
    pub const PROG_IF: u16 = 0x09;
    pub const SUBCLASS: u16 = 0x0A;
    pub const CLASS_CODE: u16 = 0x0B;
    pub const CACHE_LINE_SIZE: u16 = 0x0C;
    pub const LATENCY_TIMER: u16 = 0x0D;
    pub const HEADER_TYPE: u16 = 0x0E;
    pub const BIST: u16 = 0x0F;
    pub const BAR0: u16 = 0x10;
    pub const BAR1: u16 = 0x14;
    pub const BAR2: u16 = 0x18;
    pub const BAR3: u16 = 0x1C;
    pub const BAR4: u16 = 0x20;
    pub const BAR5: u16 = 0x24;
    pub const CARDBUS_CIS: u16 = 0x28;
    pub const SUBSYSTEM_VENDOR_ID: u16 = 0x2C;
    pub const SUBSYSTEM_ID: u16 = 0x2E;
    pub const EXPANSION_ROM: u16 = 0x30;
    pub const CAPABILITIES_PTR: u16 = 0x34;
    pub const INTERRUPT_LINE: u16 = 0x3C;
    pub const INTERRUPT_PIN: u16 = 0x3D;
    pub const MIN_GRANT: u16 = 0x3E;
    pub const MAX_LATENCY: u16 = 0x3F;
}

/// コマンドレジスタビットフラグ
pub mod command_bits {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MWI_ENABLE: u16 = 1 << 4;
    pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
    pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
    pub const SERR_ENABLE: u16 = 1 << 8;
    pub const FAST_B2B_ENABLE: u16 = 1 << 9;
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

/// ステータスレジスタビットフラグ
pub mod status_bits {
    pub const INTERRUPT_STATUS: u16 = 1 << 3;
    pub const CAPABILITIES_LIST: u16 = 1 << 4;
    pub const MHZ_66_CAPABLE: u16 = 1 << 5;
    pub const FAST_B2B_CAPABLE: u16 = 1 << 7;
    pub const MASTER_DATA_PARITY_ERROR: u16 = 1 << 8;
    pub const SIGNALED_TARGET_ABORT: u16 = 1 << 11;
    pub const RECEIVED_TARGET_ABORT: u16 = 1 << 12;
    pub const RECEIVED_MASTER_ABORT: u16 = 1 << 13;
    pub const SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
    pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
}

// ============================================================================
// Capability IDs
// ============================================================================

/// ケーパビリティID
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CapabilityId {
    PowerManagement = 0x01,
    Agp = 0x02,
    VitalProductData = 0x03,
    SlotId = 0x04,
    Msi = 0x05,
    CompactPciHotSwap = 0x06,
    PciX = 0x07,
    HyperTransport = 0x08,
    VendorSpecific = 0x09,
    DebugPort = 0x0A,
    CompactPciCentral = 0x0B,
    PciHotPlug = 0x0C,
    PciBridgeSubsystemVendorId = 0x0D,
    Agp8x = 0x0E,
    SecureDevice = 0x0F,
    PciExpress = 0x10,
    MsiX = 0x11,
    SataDataIndex = 0x12,
    AdvancedFeatures = 0x13,
    EnhancedAllocation = 0x14,
    FlatteningPortalBridge = 0x15,
}

impl CapabilityId {
    /// u8値から変換
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::PowerManagement),
            0x02 => Some(Self::Agp),
            0x03 => Some(Self::VitalProductData),
            0x04 => Some(Self::SlotId),
            0x05 => Some(Self::Msi),
            0x06 => Some(Self::CompactPciHotSwap),
            0x07 => Some(Self::PciX),
            0x08 => Some(Self::HyperTransport),
            0x09 => Some(Self::VendorSpecific),
            0x0A => Some(Self::DebugPort),
            0x0B => Some(Self::CompactPciCentral),
            0x0C => Some(Self::PciHotPlug),
            0x0D => Some(Self::PciBridgeSubsystemVendorId),
            0x0E => Some(Self::Agp8x),
            0x0F => Some(Self::SecureDevice),
            0x10 => Some(Self::PciExpress),
            0x11 => Some(Self::MsiX),
            0x12 => Some(Self::SataDataIndex),
            0x13 => Some(Self::AdvancedFeatures),
            0x14 => Some(Self::EnhancedAllocation),
            0x15 => Some(Self::FlatteningPortalBridge),
            _ => None,
        }
    }
}

// ============================================================================
// PCI Device Information
// ============================================================================

/// PCIデバイス情報
#[derive(Clone, Debug)]
pub struct PciDeviceInfo {
    /// BDFアドレス
    pub bdf: BdfAddress,
    /// ベンダーID
    pub vendor_id: VendorId,
    /// デバイスID
    pub device_id: DeviceId,
    /// リビジョンID
    pub revision_id: u8,
    /// クラスコード
    pub class_code: ClassCode,
    /// ヘッダタイプ
    pub header_type: u8,
    /// サブシステムベンダーID
    pub subsystem_vendor_id: u16,
    /// サブシステムID
    pub subsystem_id: u16,
    /// 割り込みライン
    pub interrupt_line: u8,
    /// 割り込みピン
    pub interrupt_pin: u8,
    /// BARs (最大6個)
    pub bars: [Option<Bar>; 6],
    /// ケーパビリティリスト
    pub capabilities: Vec<(CapabilityId, u8)>,
    /// MSIケーパビリティオフセット
    pub msi_cap_offset: Option<u8>,
    /// MSI-Xケーパビリティオフセット
    pub msix_cap_offset: Option<u8>,
    /// PCIeケーパビリティオフセット
    pub pcie_cap_offset: Option<u8>,
}

impl PciDeviceInfo {
    /// マルチファンクションデバイスかどうか
    pub fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }

    /// ヘッダタイプ値（0x7Fマスク）
    pub fn header_type_value(&self) -> u8 {
        self.header_type & 0x7F
    }

    /// PCIブリッジかどうか
    pub fn is_pci_bridge(&self) -> bool {
        self.header_type_value() == 0x01
    }

    /// MSI対応かどうか
    pub fn supports_msi(&self) -> bool {
        self.msi_cap_offset.is_some()
    }

    /// MSI-X対応かどうか
    pub fn supports_msix(&self) -> bool {
        self.msix_cap_offset.is_some()
    }

    /// PCIe対応かどうか
    pub fn is_pcie(&self) -> bool {
        self.pcie_cap_offset.is_some()
    }
}

// ============================================================================
// PCI Bus Scanner
// ============================================================================

/// PCIバススキャナ
/// 
/// ConfigSpaceAccessorトレイトを使用してPCIバスをスキャンし、
/// デバイスを列挙します。
pub struct PciBusScanner<'a> {
    accessor: &'a dyn ConfigSpaceAccessor,
}

impl<'a> PciBusScanner<'a> {
    /// 新しいスキャナを作成
    pub fn new(accessor: &'a dyn ConfigSpaceAccessor) -> Self {
        Self { accessor }
    }

    /// 指定したBDFにデバイスが存在するか確認
    pub fn device_exists(&self, bdf: BdfAddress) -> bool {
        self.accessor.read_vendor_id(bdf) != 0xFFFF
    }

    /// デバイス情報を読み取り
    pub fn read_device(&self, bdf: BdfAddress) -> Option<PciDeviceInfo> {
        let vendor_id = self.accessor.read_vendor_id(bdf);
        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id = self.accessor.read_device_id(bdf);
        let revision_id = self.accessor.read8(bdf, config_regs::REVISION_ID);
        let prog_if = self.accessor.read8(bdf, config_regs::PROG_IF);
        let subclass = self.accessor.read8(bdf, config_regs::SUBCLASS);
        let class_code = self.accessor.read8(bdf, config_regs::CLASS_CODE);
        let header_type = self.accessor.read8(bdf, config_regs::HEADER_TYPE);
        let subsystem_vendor_id = self.accessor.read16(bdf, config_regs::SUBSYSTEM_VENDOR_ID);
        let subsystem_id = self.accessor.read16(bdf, config_regs::SUBSYSTEM_ID);
        let interrupt_line = self.accessor.read8(bdf, config_regs::INTERRUPT_LINE);
        let interrupt_pin = self.accessor.read8(bdf, config_regs::INTERRUPT_PIN);

        // BARs読み取り
        let bars = self.read_bars(bdf);

        // ケーパビリティ読み取り
        let (capabilities, msi_cap_offset, msix_cap_offset, pcie_cap_offset) = 
            self.read_capabilities(bdf);

        Some(PciDeviceInfo {
            bdf,
            vendor_id: VendorId(vendor_id),
            device_id: DeviceId(device_id),
            revision_id,
            class_code: ClassCode {
                class: class_code,
                subclass,
                prog_if,
            },
            header_type,
            subsystem_vendor_id,
            subsystem_id,
            interrupt_line,
            interrupt_pin,
            bars,
            capabilities,
            msi_cap_offset,
            msix_cap_offset,
            pcie_cap_offset,
        })
    }

    /// BARを読み取り
    fn read_bars(&self, bdf: BdfAddress) -> [Option<Bar>; 6] {
        let mut bars: [Option<Bar>; 6] = [None; 6];
        let mut i = 0;

        while i < 6 {
            let bar_offset = config_regs::BAR0 + (i as u16 * 4);
            let bar_value = self.accessor.read32(bdf, bar_offset);

            if bar_value == 0 {
                i += 1;
                continue;
            }

            // BARサイズを決定するために一時的に全ビット1を書き込み
            self.accessor.write32(bdf, bar_offset, 0xFFFF_FFFF);
            let size_mask = self.accessor.read32(bdf, bar_offset);
            self.accessor.write32(bdf, bar_offset, bar_value);

            if size_mask == 0 || size_mask == 0xFFFF_FFFF {
                i += 1;
                continue;
            }

            let is_io = (bar_value & 0x01) != 0;

            if is_io {
                // I/O BAR
                let base = (bar_value & !0x03) as u64;
                let size = (!(size_mask & !0x03) + 1) as u64;
                bars[i] = Some(Bar::Io { base, size });
            } else {
                // Memory BAR
                let bar_type_bits = (bar_value >> 1) & 0x03;
                let prefetchable = (bar_value & 0x08) != 0;

                match bar_type_bits {
                    0b00 => {
                        // 32-bit Memory
                        let base = (bar_value & !0x0F) as u64;
                        let size = (!(size_mask & !0x0F) + 1) as u64;
                        bars[i] = Some(Bar::Memory32 { base, size, prefetchable });
                    }
                    0b10 => {
                        // 64-bit Memory
                        if i + 1 < 6 {
                            let next_bar_offset = config_regs::BAR0 + ((i + 1) as u16 * 4);
                            let high = self.accessor.read32(bdf, next_bar_offset) as u64;
                            let low = (bar_value & !0x0F) as u64;
                            let base = (high << 32) | low;

                            // サイズ計算
                            self.accessor.write32(bdf, next_bar_offset, 0xFFFF_FFFF);
                            let high_size = self.accessor.read32(bdf, next_bar_offset) as u64;
                            self.accessor.write32(bdf, next_bar_offset, high as u32);

                            let size_64 = ((high_size << 32) | ((size_mask & !0x0F) as u64));
                            let size = !size_64 + 1;

                            bars[i] = Some(Bar::Memory64 { base, size, prefetchable });
                            i += 1; // 次のBARをスキップ
                        }
                    }
                    _ => {}
                }
            }

            i += 1;
        }

        bars
    }

    /// ケーパビリティを読み取り
    fn read_capabilities(&self, bdf: BdfAddress) -> (Vec<(CapabilityId, u8)>, Option<u8>, Option<u8>, Option<u8>) {
        let mut capabilities = Vec::new();
        let mut msi_cap_offset = None;
        let mut msix_cap_offset = None;
        let mut pcie_cap_offset = None;

        // ステータスレジスタでケーパビリティリストがあるか確認
        let status = self.accessor.read16(bdf, config_regs::STATUS);
        if (status & status_bits::CAPABILITIES_LIST) == 0 {
            return (capabilities, msi_cap_offset, msix_cap_offset, pcie_cap_offset);
        }

        // ケーパビリティポインタ取得
        let mut cap_ptr = self.accessor.read8(bdf, config_regs::CAPABILITIES_PTR) & 0xFC;

        // ケーパビリティチェーンを走査
        let mut visited = 0u8;
        while cap_ptr != 0 && visited < 48 {
            let cap_id_raw = self.accessor.read8(bdf, cap_ptr as u16);
            let next_ptr = self.accessor.read8(bdf, cap_ptr as u16 + 1);

            if let Some(cap_id) = CapabilityId::from_u8(cap_id_raw) {
                capabilities.push((cap_id, cap_ptr));

                match cap_id {
                    CapabilityId::Msi => msi_cap_offset = Some(cap_ptr),
                    CapabilityId::MsiX => msix_cap_offset = Some(cap_ptr),
                    CapabilityId::PciExpress => pcie_cap_offset = Some(cap_ptr),
                    _ => {}
                }
            }

            cap_ptr = next_ptr & 0xFC;
            visited += 1;
        }

        (capabilities, msi_cap_offset, msix_cap_offset, pcie_cap_offset)
    }

    /// 全バスをスキャン
    pub fn scan_all(&self) -> Vec<PciDeviceInfo> {
        let mut devices = Vec::new();

        for bus in 0..=255u8 {
            self.scan_bus(bus, &mut devices);
        }

        devices
    }

    /// 指定したバスをスキャン
    pub fn scan_bus(&self, bus: u8, devices: &mut Vec<PciDeviceInfo>) {
        for device in 0..32u8 {
            self.scan_device(bus, device, devices);
        }
    }

    /// 指定したデバイスをスキャン
    pub fn scan_device(&self, bus: u8, device: u8, devices: &mut Vec<PciDeviceInfo>) {
        let bdf = BdfAddress::new(bus, device, 0);

        if let Some(info) = self.read_device(bdf) {
            let is_multifunction = info.is_multifunction();
            devices.push(info);

            // マルチファンクションの場合、他のファンクションもスキャン
            if is_multifunction {
                for function in 1..8u8 {
                    let func_bdf = BdfAddress::new(bus, device, function);
                    if let Some(func_info) = self.read_device(func_bdf) {
                        devices.push(func_info);
                    }
                }
            }
        }
    }

    /// 特定のクラス/サブクラスのデバイスを検索
    pub fn find_by_class(&self, class: u8, subclass: u8) -> Vec<PciDeviceInfo> {
        self.scan_all()
            .into_iter()
            .filter(|d| d.class_code.class == class && d.class_code.subclass == subclass)
            .collect()
    }

    /// 特定のベンダー/デバイスIDを持つデバイスを検索
    pub fn find_by_id(&self, vendor_id: u16, device_id: u16) -> Vec<PciDeviceInfo> {
        self.scan_all()
            .into_iter()
            .filter(|d| d.vendor_id.0 == vendor_id && d.device_id.0 == device_id)
            .collect()
    }
}

// ============================================================================
// Device Class Names
// ============================================================================

impl ClassCode {
    /// クラス名を取得
    pub fn class_name(&self) -> &'static str {
        match self.class {
            0x00 => "Unclassified",
            0x01 => "Mass Storage Controller",
            0x02 => "Network Controller",
            0x03 => "Display Controller",
            0x04 => "Multimedia Controller",
            0x05 => "Memory Controller",
            0x06 => "Bridge",
            0x07 => "Simple Communication Controller",
            0x08 => "Base System Peripheral",
            0x09 => "Input Device Controller",
            0x0A => "Docking Station",
            0x0B => "Processor",
            0x0C => "Serial Bus Controller",
            0x0D => "Wireless Controller",
            0x0E => "Intelligent Controller",
            0x0F => "Satellite Communication Controller",
            0x10 => "Encryption Controller",
            0x11 => "Signal Processing Controller",
            0x12 => "Processing Accelerators",
            0x13 => "Non-Essential Instrumentation",
            0x40 => "Co-Processor",
            0xFF => "Unassigned",
            _ => "Unknown",
        }
    }

    /// サブクラス名を取得
    pub fn subclass_name(&self) -> &'static str {
        match (self.class, self.subclass) {
            // Mass Storage
            (0x01, 0x00) => "SCSI Bus Controller",
            (0x01, 0x01) => "IDE Controller",
            (0x01, 0x02) => "Floppy Disk Controller",
            (0x01, 0x03) => "IPI Bus Controller",
            (0x01, 0x04) => "RAID Controller",
            (0x01, 0x05) => "ATA Controller",
            (0x01, 0x06) => "SATA Controller",
            (0x01, 0x07) => "Serial Attached SCSI Controller",
            (0x01, 0x08) => "NVMe Controller",
            // Network
            (0x02, 0x00) => "Ethernet Controller",
            (0x02, 0x01) => "Token Ring Controller",
            (0x02, 0x02) => "FDDI Controller",
            (0x02, 0x03) => "ATM Controller",
            (0x02, 0x04) => "ISDN Controller",
            (0x02, 0x05) => "WorldFip Controller",
            (0x02, 0x06) => "PICMG 2.14 Multi Computing",
            (0x02, 0x07) => "Infiniband Controller",
            (0x02, 0x08) => "Fabric Controller",
            // Display
            (0x03, 0x00) => "VGA Compatible Controller",
            (0x03, 0x01) => "XGA Controller",
            (0x03, 0x02) => "3D Controller",
            // Bridge
            (0x06, 0x00) => "Host Bridge",
            (0x06, 0x01) => "ISA Bridge",
            (0x06, 0x02) => "EISA Bridge",
            (0x06, 0x03) => "MCA Bridge",
            (0x06, 0x04) => "PCI-to-PCI Bridge",
            (0x06, 0x05) => "PCMCIA Bridge",
            (0x06, 0x06) => "NuBus Bridge",
            (0x06, 0x07) => "CardBus Bridge",
            (0x06, 0x08) => "RACEway Bridge",
            (0x06, 0x09) => "PCI-to-PCI Bridge (Semi-Transparent)",
            (0x06, 0x0A) => "InfiniBand-to-PCI Host Bridge",
            // Serial Bus
            (0x0C, 0x00) => "FireWire (IEEE 1394) Controller",
            (0x0C, 0x01) => "ACCESS Bus Controller",
            (0x0C, 0x02) => "SSA Controller",
            (0x0C, 0x03) => "USB Controller",
            (0x0C, 0x04) => "Fibre Channel Controller",
            (0x0C, 0x05) => "SMBus Controller",
            (0x0C, 0x06) => "InfiniBand Controller",
            (0x0C, 0x07) => "IPMI Interface",
            (0x0C, 0x08) => "SERCOS Interface",
            (0x0C, 0x09) => "CANbus Controller",
            _ => "Unknown Subclass",
        }
    }
}
