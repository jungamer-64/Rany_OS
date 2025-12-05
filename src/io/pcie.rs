// ============================================================================
// src/io/pcie.rs - PCIe (PCI Express) Subsystem
// ============================================================================
//!
//! # PCIe サブシステム
//!
//! PCI Express デバイスの検出、設定、管理を提供。
//!
//! ## 機能
//! - PCIe Configuration Space (ECAM) アクセス
//! - デバイス列挙とケーパビリティ解析
//! - MSI/MSI-X割り込み設定
//! - Power Management
//! - Advanced Error Reporting (AER)
//!
//! ## 型安全性
//! - Newtype パターンによる BDF (Bus/Device/Function) 管理
//! - ケーパビリティの型レベル表現

#![allow(dead_code)]

use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;

// Import legacy PCI functions for backward compatibility
use crate::io::pci_compat::{pci_read, pci_read8, pci_read16, pci_write};

// ============================================================================
// Type-Safe Identifiers (Newtype Pattern)
// ============================================================================

/// PCIバス番号 (0-255)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BusNumber(pub u8);

impl BusNumber {
    pub const fn new(bus: u8) -> Self {
        Self(bus)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// PCIデバイス番号 (0-31)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceNumber(pub u8);

impl DeviceNumber {
    pub const fn new(device: u8) -> Self {
        Self(device & 0x1F)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// PCIファンクション番号 (0-7)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionNumber(pub u8);

impl FunctionNumber {
    pub const fn new(function: u8) -> Self {
        Self(function & 0x07)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// BDF (Bus/Device/Function) アドレス
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BdfAddress {
    pub bus: BusNumber,
    pub device: DeviceNumber,
    pub function: FunctionNumber,
}

impl BdfAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus: BusNumber::new(bus),
            device: DeviceNumber::new(device),
            function: FunctionNumber::new(function),
        }
    }

    /// 16ビットBDF表現を取得
    pub const fn to_u16(&self) -> u16 {
        ((self.bus.0 as u16) << 8) | ((self.device.0 as u16) << 3) | (self.function.0 as u16)
    }

    /// ECAM オフセットを計算
    pub fn ecam_offset(&self, register: u16) -> u64 {
        ((self.bus.0 as u64) << 20)
            | ((self.device.0 as u64) << 15)
            | ((self.function.0 as u64) << 12)
            | ((register as u64) & 0xFFF)
    }
}

/// レジスタオフセット
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterOffset(pub u16);

impl RegisterOffset {
    pub const fn new(offset: u16) -> Self {
        Self(offset & 0xFFF)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

// ============================================================================
// PCIe Configuration Space Registers
// ============================================================================

/// 標準PCI Configuration Space レジスタオフセット
pub mod config_regs {
    pub const VENDOR_ID: u16 = 0x00;
    pub const DEVICE_ID: u16 = 0x02;
    pub const COMMAND: u16 = 0x04;
    pub const STATUS: u16 = 0x06;
    pub const REVISION_ID: u16 = 0x08;
    pub const CLASS_CODE: u16 = 0x09;
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

/// コマンドレジスタビット
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

/// ステータスレジスタビット
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
// PCIe Capability IDs
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

/// 拡張ケーパビリティID (PCIe)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtendedCapabilityId {
    AdvancedErrorReporting = 0x0001,
    VirtualChannel = 0x0002,
    DeviceSerialNumber = 0x0003,
    PowerBudgeting = 0x0004,
    RootComplexLinkDeclaration = 0x0005,
    RootComplexInternalLinkControl = 0x0006,
    RootComplexEventCollector = 0x0007,
    MultiFunction = 0x0008,
    VirtualChannelMultifunction = 0x0009,
    RootComplexRegisterBlock = 0x000A,
    VendorSpecificExtended = 0x000B,
    ConfigurationAccessCorrelation = 0x000C,
    AccessControlServices = 0x000D,
    AlternativeRouting = 0x000E,
    AddressTranslationServices = 0x000F,
    SingleRootIOVirtualization = 0x0010,
    MultiRootIOVirtualization = 0x0011,
    Multicast = 0x0012,
    PageRequestInterface = 0x0013,
    AmdReserved = 0x0014,
    ResizableBar = 0x0015,
    DynamicPowerAllocation = 0x0016,
    TphRequester = 0x0017,
    LatencyToleranceReporting = 0x0018,
    SecondaryPciExpress = 0x0019,
    ProtocolMultiplexing = 0x001A,
    ProcessAddressSpaceId = 0x001B,
    LnRequester = 0x001C,
    DownstreamPortContainment = 0x001D,
    L1PmSubstates = 0x001E,
    PrecisionTimeMeasurement = 0x001F,
    PciExpressOverMphy = 0x0020,
    FrsQueueing = 0x0021,
    ReadinessTimeReporting = 0x0022,
    DesignatedVendorSpecificExtended = 0x0023,
    VfResizableBar = 0x0024,
    DataLinkFeature = 0x0025,
    PhysicalLayerGen16 = 0x0026,
    LaneMarging = 0x0027,
    HierarchyId = 0x0028,
    NativePcieEnclosure = 0x0029,
    PhysicalLayerGen32 = 0x002A,
    AlternateProtocol = 0x002B,
    SystemFirmwareIntermediatary = 0x002C,
}

// ============================================================================
// BAR (Base Address Register)
// ============================================================================

/// BARタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarType {
    /// メモリマップドI/O (32ビット)
    Memory32 { prefetchable: bool },
    /// メモリマップドI/O (64ビット) - BAR n と n+1 を使用
    Memory64 { prefetchable: bool },
    /// I/Oポートマップド
    Io,
    /// 未使用
    Unused,
}

/// BAR情報
#[derive(Clone, Copy, Debug)]
pub struct BarInfo {
    /// BAR番号 (0-5)
    pub bar_number: u8,
    /// BARタイプ
    pub bar_type: BarType,
    /// ベースアドレス
    pub base_address: u64,
    /// サイズ（バイト）
    pub size: u64,
}

impl BarInfo {
    /// BARから情報を解析
    pub fn parse(bar_number: u8, bar_value: u32, bar_size: u32, next_bar: Option<u32>) -> Self {
        if bar_value == 0 {
            return Self {
                bar_number,
                bar_type: BarType::Unused,
                base_address: 0,
                size: 0,
            };
        }

        let is_io = (bar_value & 0x01) != 0;

        if is_io {
            // I/O BAR
            let base = (bar_value & !0x03) as u64;
            let size = (!bar_size + 1) as u64;
            Self {
                bar_number,
                bar_type: BarType::Io,
                base_address: base,
                size,
            }
        } else {
            // Memory BAR
            let bar_type_bits = (bar_value >> 1) & 0x03;
            let prefetchable = (bar_value & 0x08) != 0;

            match bar_type_bits {
                0b00 => {
                    // 32-bit
                    let base = (bar_value & !0x0F) as u64;
                    let size = (!bar_size + 1) as u64;
                    Self {
                        bar_number,
                        bar_type: BarType::Memory32 { prefetchable },
                        base_address: base,
                        size,
                    }
                }
                0b10 => {
                    // 64-bit
                    let low = (bar_value & !0x0F) as u64;
                    let high = next_bar.unwrap_or(0) as u64;
                    let base = (high << 32) | low;
                    let size = (!((bar_size as u64) | (0xFFFFFFFF << 32)) + 1) as u64;
                    Self {
                        bar_number,
                        bar_type: BarType::Memory64 { prefetchable },
                        base_address: base,
                        size,
                    }
                }
                _ => Self {
                    bar_number,
                    bar_type: BarType::Unused,
                    base_address: 0,
                    size: 0,
                },
            }
        }
    }
}

// ============================================================================
// Device Class
// ============================================================================

/// デバイスクラス
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceClass {
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

impl DeviceClass {
    pub fn new(class_code: u32) -> Self {
        Self {
            class: ((class_code >> 16) & 0xFF) as u8,
            subclass: ((class_code >> 8) & 0xFF) as u8,
            prog_if: (class_code & 0xFF) as u8,
        }
    }

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

// ============================================================================
// PCIe Device
// ============================================================================

/// PCIeデバイス
#[derive(Clone, Debug)]
pub struct PcieDevice {
    /// BDFアドレス
    pub bdf: BdfAddress,
    /// ベンダーID
    pub vendor_id: u16,
    /// デバイスID
    pub device_id: u16,
    /// リビジョンID
    pub revision_id: u8,
    /// デバイスクラス
    pub class: DeviceClass,
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
    /// BARs
    pub bars: [Option<BarInfo>; 6],
    /// ケーパビリティオフセットのリスト
    pub capabilities: Vec<(CapabilityId, u8)>,
    /// PCIeケーパビリティオフセット
    pub pcie_cap_offset: Option<u8>,
    /// MSIケーパビリティオフセット  
    pub msi_cap_offset: Option<u8>,
    /// MSI-Xケーパビリティオフセット
    pub msix_cap_offset: Option<u8>,
}

impl PcieDevice {
    /// デバイスがマルチファンクションかどうか
    pub fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }

    /// ヘッダタイプ（0x7Fマスク）
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
// PCIe Link Info
// ============================================================================

/// PCIeリンク速度
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcieLinkSpeed {
    Gen1_2_5GT,
    Gen2_5_0GT,
    Gen3_8_0GT,
    Gen4_16_0GT,
    Gen5_32_0GT,
    Gen6_64_0GT,
    Unknown,
}

impl PcieLinkSpeed {
    pub fn from_speed_encoding(speed: u8) -> Self {
        match speed {
            1 => Self::Gen1_2_5GT,
            2 => Self::Gen2_5_0GT,
            3 => Self::Gen3_8_0GT,
            4 => Self::Gen4_16_0GT,
            5 => Self::Gen5_32_0GT,
            6 => Self::Gen6_64_0GT,
            _ => Self::Unknown,
        }
    }

    pub fn bandwidth_gbps(&self) -> f32 {
        match self {
            Self::Gen1_2_5GT => 2.5,
            Self::Gen2_5_0GT => 5.0,
            Self::Gen3_8_0GT => 8.0,
            Self::Gen4_16_0GT => 16.0,
            Self::Gen5_32_0GT => 32.0,
            Self::Gen6_64_0GT => 64.0,
            Self::Unknown => 0.0,
        }
    }
}

/// PCIeリンク幅
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcieLinkWidth {
    X1,
    X2,
    X4,
    X8,
    X12,
    X16,
    X32,
    Unknown,
}

impl PcieLinkWidth {
    pub fn from_width_encoding(width: u8) -> Self {
        match width {
            0x01 => Self::X1,
            0x02 => Self::X2,
            0x04 => Self::X4,
            0x08 => Self::X8,
            0x0C => Self::X12,
            0x10 => Self::X16,
            0x20 => Self::X32,
            _ => Self::Unknown,
        }
    }

    pub fn lanes(&self) -> u8 {
        match self {
            Self::X1 => 1,
            Self::X2 => 2,
            Self::X4 => 4,
            Self::X8 => 8,
            Self::X12 => 12,
            Self::X16 => 16,
            Self::X32 => 32,
            Self::Unknown => 0,
        }
    }
}

/// PCIeリンク情報
#[derive(Clone, Copy, Debug)]
pub struct PcieLinkInfo {
    pub current_speed: PcieLinkSpeed,
    pub max_speed: PcieLinkSpeed,
    pub current_width: PcieLinkWidth,
    pub max_width: PcieLinkWidth,
}

// ============================================================================
// MSI / MSI-X Configuration
// ============================================================================

/// MSI設定
#[derive(Clone, Debug)]
pub struct MsiConfig {
    /// ケーパビリティオフセット
    pub cap_offset: u8,
    /// メッセージアドレス
    pub address: u64,
    /// メッセージデータ
    pub data: u16,
    /// 64ビット対応
    pub is_64bit: bool,
    /// 要求されたベクタ数（2のべき乗）
    pub vectors_requested: u8,
    /// 有効なベクタ数
    pub vectors_enabled: u8,
    /// 有効かどうか
    pub enabled: bool,
}

/// MSI-Xテーブルエントリ
#[derive(Clone, Copy, Debug)]
pub struct MsixTableEntry {
    pub address_low: u32,
    pub address_high: u32,
    pub data: u32,
    pub control: u32,
}

impl MsixTableEntry {
    /// マスクされているか
    pub fn is_masked(&self) -> bool {
        (self.control & 0x01) != 0
    }

    /// 64ビットアドレスを取得
    pub fn address(&self) -> u64 {
        ((self.address_high as u64) << 32) | (self.address_low as u64)
    }
}

/// MSI-X設定
#[derive(Clone, Debug)]
pub struct MsixConfig {
    /// ケーパビリティオフセット
    pub cap_offset: u8,
    /// テーブルサイズ（エントリ数）
    pub table_size: u16,
    /// テーブルBAR
    pub table_bar: u8,
    /// テーブルオフセット
    pub table_offset: u32,
    /// PBAのBAR
    pub pba_bar: u8,
    /// PBAオフセット
    pub pba_offset: u32,
    /// 有効かどうか
    pub enabled: bool,
    /// ファンクションマスク
    pub function_mask: bool,
}

// ============================================================================
// Power Management
// ============================================================================

/// 電源状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerState {
    D0,     // フルパワー
    D1,     // 軽度省電力
    D2,     // 中度省電力
    D3Hot,  // ソフトオフ
    D3Cold, // ハードオフ
}

impl PowerState {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::D0,
            1 => Self::D1,
            2 => Self::D2,
            3 => Self::D3Hot,
            _ => Self::D0,
        }
    }

    pub fn to_bits(self) -> u8 {
        match self {
            Self::D0 => 0,
            Self::D1 => 1,
            Self::D2 => 2,
            Self::D3Hot | Self::D3Cold => 3,
        }
    }
}

// ============================================================================
// ECAM Access
// ============================================================================

/// ECAM（Enhanced Configuration Access Mechanism）
pub struct Ecam {
    /// ECAMベースアドレス
    base_address: u64,
    /// セグメント番号
    segment: u16,
    /// 開始バス番号
    start_bus: u8,
    /// 終了バス番号
    end_bus: u8,
}

impl Ecam {
    /// 新しいECAMを作成
    pub fn new(base_address: u64, segment: u16, start_bus: u8, end_bus: u8) -> Self {
        Self {
            base_address,
            segment,
            start_bus,
            end_bus,
        }
    }

    /// 設定空間へのアドレスを計算
    fn config_address(&self, bdf: &BdfAddress, offset: u16) -> Option<u64> {
        if bdf.bus.0 < self.start_bus || bdf.bus.0 > self.end_bus {
            return None;
        }
        Some(self.base_address + bdf.ecam_offset(offset))
    }

    /// 8ビット読み取り
    pub fn read8(&self, bdf: &BdfAddress, offset: u16) -> Option<u8> {
        let addr = self.config_address(bdf, offset)?;
        Some(unsafe { ptr::read_volatile(addr as *const u8) })
    }

    /// 16ビット読み取り
    pub fn read16(&self, bdf: &BdfAddress, offset: u16) -> Option<u16> {
        let addr = self.config_address(bdf, offset & !1)?;
        Some(unsafe { ptr::read_volatile(addr as *const u16) })
    }

    /// 32ビット読み取り
    pub fn read32(&self, bdf: &BdfAddress, offset: u16) -> Option<u32> {
        let addr = self.config_address(bdf, offset & !3)?;
        Some(unsafe { ptr::read_volatile(addr as *const u32) })
    }

    /// 8ビット書き込み
    pub fn write8(&self, bdf: &BdfAddress, offset: u16, value: u8) -> Option<()> {
        let addr = self.config_address(bdf, offset)?;
        unsafe { ptr::write_volatile(addr as *mut u8, value) };
        Some(())
    }

    /// 16ビット書き込み
    pub fn write16(&self, bdf: &BdfAddress, offset: u16, value: u16) -> Option<()> {
        let addr = self.config_address(bdf, offset & !1)?;
        unsafe { ptr::write_volatile(addr as *mut u16, value) };
        Some(())
    }

    /// 32ビット書き込み
    pub fn write32(&self, bdf: &BdfAddress, offset: u16, value: u32) -> Option<()> {
        let addr = self.config_address(bdf, offset & !3)?;
        unsafe { ptr::write_volatile(addr as *mut u32, value) };
        Some(())
    }
}

// ============================================================================
// PCIe Manager
// ============================================================================

/// PCIe結果型
pub type PcieResult<T> = Result<T, PcieError>;

/// PCIeエラー
#[derive(Clone, Debug)]
pub enum PcieError {
    DeviceNotFound,
    InvalidBdf,
    ConfigAccessFailed,
    CapabilityNotFound,
    MsiNotSupported,
    MsixNotSupported,
    InvalidBar,
    AllocationFailed,
}

/// PCIeマネージャ
pub struct PcieManager {
    /// ECAMリスト（セグメントごと）
    ecams: Vec<Ecam>,
    /// 検出されたデバイス
    devices: Vec<PcieDevice>,
    /// 統計情報
    stats: PcieStats,
}

/// PCIe統計
#[derive(Clone, Default)]
pub struct PcieStats {
    pub devices_found: u32,
    pub pcie_devices: u32,
    pub msi_capable: u32,
    pub msix_capable: u32,
}

impl PcieManager {
    /// 新しいPCIeマネージャを作成
    pub fn new() -> Self {
        Self {
            ecams: Vec::new(),
            devices: Vec::new(),
            stats: PcieStats::default(),
        }
    }

    /// ECAMを追加
    pub fn add_ecam(&mut self, ecam: Ecam) {
        self.ecams.push(ecam);
    }

    /// レガシーPCIアクセス（IO ポート）で初期化
    pub fn init_legacy(&mut self) {
        // レガシーPCIアクセスを使用してデバイスをスキャン
        self.scan_all_buses_legacy();
    }

    /// すべてのバスをスキャン（レガシー）
    fn scan_all_buses_legacy(&mut self) {
        for bus in 0..=255u8 {
            self.scan_bus_legacy(bus);
        }
    }

    /// 単一バスをスキャン（レガシー）
    fn scan_bus_legacy(&mut self, bus: u8) {
        for device in 0..32u8 {
            self.scan_device_legacy(bus, device);
        }
    }

    /// 単一デバイスをスキャン（レガシー）
    fn scan_device_legacy(&mut self, bus: u8, device: u8) {
        let vendor_id = pci_read16(bus, device, 0, config_regs::VENDOR_ID as u8);
        if vendor_id == 0xFFFF {
            return;
        }

        // ファンクション0をプローブ
        if let Some(pcie_device) = self.probe_function_legacy(bus, device, 0) {
            let is_multifunction = pcie_device.is_multifunction();
            self.add_device(pcie_device);

            // マルチファンクションデバイスの場合、残りのファンクションもプローブ
            if is_multifunction {
                for function in 1..8u8 {
                    if let Some(dev) = self.probe_function_legacy(bus, device, function) {
                        self.add_device(dev);
                    }
                }
            }
        }
    }

    /// ファンクションをプローブ（レガシー）
    fn probe_function_legacy(&mut self, bus: u8, device: u8, function: u8) -> Option<PcieDevice> {
        let vendor_id =
            pci_read16(bus, device, function, config_regs::VENDOR_ID as u8);
        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id =
            pci_read16(bus, device, function, config_regs::DEVICE_ID as u8);
        let revision_id =
            pci_read8(bus, device, function, config_regs::REVISION_ID as u8);
        let class_code =
            pci_read(bus, device, function, config_regs::CLASS_CODE as u8) >> 8;
        let header_type =
            pci_read8(bus, device, function, config_regs::HEADER_TYPE as u8);

        let subsystem_vendor_id = pci_read16(
            bus,
            device,
            function,
            config_regs::SUBSYSTEM_VENDOR_ID as u8,
        );
        let subsystem_id =
            pci_read16(bus, device, function, config_regs::SUBSYSTEM_ID as u8);
        let interrupt_line =
            pci_read8(bus, device, function, config_regs::INTERRUPT_LINE as u8);
        let interrupt_pin =
            pci_read8(bus, device, function, config_regs::INTERRUPT_PIN as u8);

        // ケーパビリティを列挙
        let status = pci_read16(bus, device, function, config_regs::STATUS as u8);
        let mut capabilities = Vec::new();
        let mut pcie_cap_offset = None;
        let mut msi_cap_offset = None;
        let mut msix_cap_offset = None;

        if (status & status_bits::CAPABILITIES_LIST) != 0 {
            let mut cap_ptr = pci_read8(
                bus,
                device,
                function,
                config_regs::CAPABILITIES_PTR as u8,
            );
            cap_ptr &= 0xFC; // 下位2ビットをマスク

            while cap_ptr != 0 {
                let cap_id = pci_read8(bus, device, function, cap_ptr);
                let next_ptr = pci_read8(bus, device, function, cap_ptr + 1);

                if let Some(cap_type) = CapabilityId::from_u8(cap_id) {
                    capabilities.push((cap_type, cap_ptr));

                    match cap_type {
                        CapabilityId::PciExpress => pcie_cap_offset = Some(cap_ptr),
                        CapabilityId::Msi => msi_cap_offset = Some(cap_ptr),
                        CapabilityId::MsiX => msix_cap_offset = Some(cap_ptr),
                        _ => {}
                    }
                }

                cap_ptr = next_ptr & 0xFC;
            }
        }

        // BARsを読み取り（Type 0ヘッダのみ）
        let mut bars: [Option<BarInfo>; 6] = [None, None, None, None, None, None];
        if (header_type & 0x7F) == 0 {
            let mut bar_idx = 0;
            while bar_idx < 6 {
                let bar_offset = (config_regs::BAR0 + bar_idx as u16 * 4) as u8;
                let bar_value = pci_read(bus, device, function, bar_offset);

                if bar_value != 0 {
                    // サイズを決定するためにall-1を書き込み
                    pci_write(bus, device, function, bar_offset, 0xFFFFFFFF);
                    let bar_size = pci_read(bus, device, function, bar_offset);
                    pci_write(bus, device, function, bar_offset, bar_value);

                    let next_bar = if bar_idx < 5 {
                        Some(pci_read(
                            bus,
                            device,
                            function,
                            bar_offset + 4,
                        ))
                    } else {
                        None
                    };

                    let bar_info = BarInfo::parse(bar_idx as u8, bar_value, bar_size, next_bar);

                    // 64ビットBARの場合は次のBARをスキップ
                    if matches!(bar_info.bar_type, BarType::Memory64 { .. }) {
                        bars[bar_idx] = Some(bar_info);
                        bar_idx += 2;
                        continue;
                    }

                    bars[bar_idx] = Some(bar_info);
                }
                bar_idx += 1;
            }
        }

        Some(PcieDevice {
            bdf: BdfAddress::new(bus, device, function),
            vendor_id,
            device_id,
            revision_id,
            class: DeviceClass::new(class_code),
            header_type,
            subsystem_vendor_id,
            subsystem_id,
            interrupt_line,
            interrupt_pin,
            bars,
            capabilities,
            pcie_cap_offset,
            msi_cap_offset,
            msix_cap_offset,
        })
    }

    /// デバイスを追加
    fn add_device(&mut self, device: PcieDevice) {
        self.stats.devices_found += 1;
        if device.is_pcie() {
            self.stats.pcie_devices += 1;
        }
        if device.supports_msi() {
            self.stats.msi_capable += 1;
        }
        if device.supports_msix() {
            self.stats.msix_capable += 1;
        }
        self.devices.push(device);
    }

    /// デバイスを検索（ベンダー/デバイスID）
    pub fn find_device(&self, vendor_id: u16, device_id: u16) -> Option<&PcieDevice> {
        self.devices
            .iter()
            .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
    }

    /// クラスでデバイスを検索
    pub fn find_devices_by_class(&self, class: u8, subclass: u8) -> Vec<&PcieDevice> {
        self.devices
            .iter()
            .filter(|d| d.class.class == class && d.class.subclass == subclass)
            .collect()
    }

    /// すべてのデバイスを取得
    pub fn devices(&self) -> &[PcieDevice] {
        &self.devices
    }

    /// 統計を取得
    pub fn stats(&self) -> &PcieStats {
        &self.stats
    }

    /// MSIを設定
    pub fn configure_msi(
        &self,
        device: &PcieDevice,
        address: u64,
        data: u16,
        vector_count: u8,
    ) -> PcieResult<()> {
        let cap_offset = device.msi_cap_offset.ok_or(PcieError::MsiNotSupported)?;
        let bdf = &device.bdf;

        // MSI Control レジスタを読み取り
        let control =
            pci_read16(bdf.bus.0, bdf.device.0, bdf.function.0, cap_offset + 2);

        let is_64bit = (control & 0x80) != 0;

        // アドレスを書き込み
        pci_write(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            cap_offset + 4,
            address as u32,
        );

        if is_64bit {
            pci_write(
                bdf.bus.0,
                bdf.device.0,
                bdf.function.0,
                cap_offset + 8,
                (address >> 32) as u32,
            );
            // データを書き込み
            let data_offset = cap_offset + 12;
            let current =
                pci_read(bdf.bus.0, bdf.device.0, bdf.function.0, data_offset);
            pci_write(
                bdf.bus.0,
                bdf.device.0,
                bdf.function.0,
                data_offset,
                (current & 0xFFFF0000) | (data as u32),
            );
        } else {
            // データを書き込み
            let data_offset = cap_offset + 8;
            let current =
                pci_read(bdf.bus.0, bdf.device.0, bdf.function.0, data_offset);
            pci_write(
                bdf.bus.0,
                bdf.device.0,
                bdf.function.0,
                data_offset,
                (current & 0xFFFF0000) | (data as u32),
            );
        }

        // ベクタ数を設定してMSIを有効化
        let vector_bits = (vector_count.trailing_zeros() as u16) & 0x07;
        let new_control = (control & 0xFF8E) | (vector_bits << 4) | 0x0001; // Enable MSI
        let control_dword =
            pci_read(bdf.bus.0, bdf.device.0, bdf.function.0, cap_offset);
        pci_write(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            cap_offset,
            (control_dword & 0xFFFF) | ((new_control as u32) << 16),
        );

        Ok(())
    }

    /// バスマスタを有効化
    pub fn enable_bus_master(&self, device: &PcieDevice) {
        let bdf = &device.bdf;
        let command = pci_read16(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            config_regs::COMMAND as u8,
        );
        let new_command = command | command_bits::BUS_MASTER | command_bits::MEMORY_SPACE;

        let command_dword = pci_read(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            config_regs::COMMAND as u8,
        );
        pci_write(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            config_regs::COMMAND as u8,
            (command_dword & 0xFFFF0000) | (new_command as u32),
        );
    }

    /// メモリ空間を有効化
    pub fn enable_memory_space(&self, device: &PcieDevice) {
        let bdf = &device.bdf;
        let command = pci_read16(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            config_regs::COMMAND as u8,
        );
        let new_command = command | command_bits::MEMORY_SPACE;

        let command_dword = pci_read(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            config_regs::COMMAND as u8,
        );
        pci_write(
            bdf.bus.0,
            bdf.device.0,
            bdf.function.0,
            config_regs::COMMAND as u8,
            (command_dword & 0xFFFF0000) | (new_command as u32),
        );
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルPCIeマネージャ
static PCIE_MANAGER: Mutex<Option<PcieManager>> = Mutex::new(None);

/// PCIeサブシステムを初期化
pub fn init() {
    let mut manager = PcieManager::new();
    manager.init_legacy();

    // 統計を表示
    let _stats = manager.stats();
    // log::info!("PCIe: {} devices found ({} PCIe, {} MSI, {} MSI-X)",
    //     stats.devices_found, stats.pcie_devices, stats.msi_capable, stats.msix_capable);

    *PCIE_MANAGER.lock() = Some(manager);
}

/// PCIeマネージャにアクセス
pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&PcieManager) -> R,
{
    PCIE_MANAGER.lock().as_ref().map(f)
}

/// PCIeマネージャにミュータブルアクセス
pub fn with_manager_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut PcieManager) -> R,
{
    PCIE_MANAGER.lock().as_mut().map(f)
}

/// デバイスを検索
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PcieDevice> {
    with_manager(|m| m.find_device(vendor_id, device_id).cloned()).flatten()
}

/// クラスでデバイスを検索
pub fn find_devices_by_class(class: u8, subclass: u8) -> Vec<PcieDevice> {
    with_manager(|m| {
        m.find_devices_by_class(class, subclass)
            .into_iter()
            .cloned()
            .collect()
    })
    .unwrap_or_default()
}
