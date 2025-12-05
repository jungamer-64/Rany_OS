// ============================================================================
// src/io/pci/types.rs - PCI Type Definitions
// ============================================================================
//!
//! PCI/PCIe 共通型定義
//!
//! Newtype パターンによる型安全なBDF管理とレジスタ定義。

use core::fmt;

// ============================================================================
// Type-Safe Identifiers (Newtype Pattern)
// ============================================================================

/// PCIバス番号 (0-255)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BusNumber(pub u8);

impl BusNumber {
    pub const fn new(bus: u8) -> Self {
        Self(bus)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for BusNumber {
    fn from(bus: u8) -> Self {
        Self(bus)
    }
}

/// PCIデバイス番号 (0-31)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DeviceNumber(pub u8);

impl DeviceNumber {
    pub const fn new(device: u8) -> Self {
        Self(device & 0x1F)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for DeviceNumber {
    fn from(device: u8) -> Self {
        Self::new(device)
    }
}

/// PCIファンクション番号 (0-7)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FunctionNumber(pub u8);

impl FunctionNumber {
    pub const fn new(function: u8) -> Self {
        Self(function & 0x07)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for FunctionNumber {
    fn from(function: u8) -> Self {
        Self::new(function)
    }
}

/// BDF (Bus/Device/Function) アドレス
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
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

    /// 16ビットBDF表現から作成
    pub const fn from_u16(bdf: u16) -> Self {
        Self {
            bus: BusNumber((bdf >> 8) as u8),
            device: DeviceNumber(((bdf >> 3) & 0x1F) as u8),
            function: FunctionNumber((bdf & 0x07) as u8),
        }
    }

    /// Legacy I/O アドレスを計算
    pub fn legacy_address(&self, offset: u8) -> u32 {
        ((self.bus.0 as u32) << 16)
            | ((self.device.0 as u32) << 11)
            | ((self.function.0 as u32) << 8)
            | ((offset as u32) & 0xFC)
            | 0x80000000 // Enable bit
    }

    /// ECAM オフセットを計算
    pub fn ecam_offset(&self, register: u16) -> u64 {
        ((self.bus.0 as u64) << 20)
            | ((self.device.0 as u64) << 15)
            | ((self.function.0 as u64) << 12)
            | ((register as u64) & 0xFFF)
    }
}

impl fmt::Display for BdfAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{:x}",
            self.bus.0, self.device.0, self.function.0
        )
    }
}

// ============================================================================
// Configuration Space Registers
// ============================================================================

/// 標準PCI Configuration Space レジスタオフセット
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

/// コマンドレジスタビット
pub mod command_bits {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MWI_ENABLE: u16 = 1 << 4;
    pub const VGA_SNOOP: u16 = 1 << 5;
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
    pub const DEVSEL_TIMING_MASK: u16 = 0x3 << 9;
    pub const SIGNALED_TARGET_ABORT: u16 = 1 << 11;
    pub const RECEIVED_TARGET_ABORT: u16 = 1 << 12;
    pub const RECEIVED_MASTER_ABORT: u16 = 1 << 13;
    pub const SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
    pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
}

// ============================================================================
// Capability IDs
// ============================================================================

/// PCI ケーパビリティ ID
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CapabilityId {
    /// Power Management
    PowerManagement = 0x01,
    /// AGP
    Agp = 0x02,
    /// VPD (Vital Product Data)
    Vpd = 0x03,
    /// Slot Identification
    SlotId = 0x04,
    /// MSI (Message Signaled Interrupts)
    Msi = 0x05,
    /// CompactPCI Hot Swap
    CompactPciHotSwap = 0x06,
    /// PCI-X
    PciX = 0x07,
    /// HyperTransport
    HyperTransport = 0x08,
    /// Vendor Specific
    VendorSpecific = 0x09,
    /// Debug Port
    DebugPort = 0x0A,
    /// CompactPCI Resource Control
    CompactPciResourceControl = 0x0B,
    /// Hot Plug
    HotPlug = 0x0C,
    /// Bridge Subsystem Vendor ID
    BridgeSubsystemVendorId = 0x0D,
    /// AGP 8x
    Agp8x = 0x0E,
    /// Secure Device
    SecureDevice = 0x0F,
    /// PCI Express
    PciExpress = 0x10,
    /// MSI-X
    MsiX = 0x11,
    /// SATA Configuration
    SataConfig = 0x12,
    /// Advanced Features
    AdvancedFeatures = 0x13,
    /// Enhanced Allocation
    EnhancedAllocation = 0x14,
    /// Flattening Portal Bridge
    FlatteningPortalBridge = 0x15,
}

impl TryFrom<u8> for CapabilityId {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(CapabilityId::PowerManagement),
            0x02 => Ok(CapabilityId::Agp),
            0x03 => Ok(CapabilityId::Vpd),
            0x04 => Ok(CapabilityId::SlotId),
            0x05 => Ok(CapabilityId::Msi),
            0x06 => Ok(CapabilityId::CompactPciHotSwap),
            0x07 => Ok(CapabilityId::PciX),
            0x08 => Ok(CapabilityId::HyperTransport),
            0x09 => Ok(CapabilityId::VendorSpecific),
            0x0A => Ok(CapabilityId::DebugPort),
            0x0B => Ok(CapabilityId::CompactPciResourceControl),
            0x0C => Ok(CapabilityId::HotPlug),
            0x0D => Ok(CapabilityId::BridgeSubsystemVendorId),
            0x0E => Ok(CapabilityId::Agp8x),
            0x0F => Ok(CapabilityId::SecureDevice),
            0x10 => Ok(CapabilityId::PciExpress),
            0x11 => Ok(CapabilityId::MsiX),
            0x12 => Ok(CapabilityId::SataConfig),
            0x13 => Ok(CapabilityId::AdvancedFeatures),
            0x14 => Ok(CapabilityId::EnhancedAllocation),
            0x15 => Ok(CapabilityId::FlatteningPortalBridge),
            _ => Err(value),
        }
    }
}

// ============================================================================
// PCIe Extended Capability IDs
// ============================================================================

/// PCIe 拡張ケーパビリティ ID
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtendedCapabilityId {
    /// Advanced Error Reporting
    Aer = 0x0001,
    /// Virtual Channel
    VirtualChannel = 0x0002,
    /// Device Serial Number
    DeviceSerialNumber = 0x0003,
    /// Power Budgeting
    PowerBudgeting = 0x0004,
    /// Root Complex Link Declaration
    RootComplexLinkDeclaration = 0x0005,
    /// Root Complex Internal Link Control
    RootComplexInternalLinkControl = 0x0006,
    /// Root Complex Event Collector Endpoint Association
    RootComplexEventCollector = 0x0007,
    /// Multi-Function Virtual Channel
    MfvcExtended = 0x0008,
    /// Virtual Channel (VC9)
    VirtualChannel9 = 0x0009,
    /// Root Complex Register Block
    Rcrb = 0x000A,
    /// Vendor Specific Extended
    VendorSpecificExtended = 0x000B,
    /// Configuration Access Correlation
    Cac = 0x000C,
    /// Access Control Services
    Acs = 0x000D,
    /// Alternative Routing-ID Interpretation
    Ari = 0x000E,
    /// Address Translation Services
    Ats = 0x000F,
    /// Single Root I/O Virtualization
    SrIov = 0x0010,
    /// Multi-Root I/O Virtualization
    MrIov = 0x0011,
    /// Multicast
    Multicast = 0x0012,
    /// Page Request Interface
    Pri = 0x0013,
    /// Resizable BAR
    ResizableBar = 0x0015,
    /// Dynamic Power Allocation
    Dpa = 0x0016,
    /// TPH Requester
    TphRequester = 0x0017,
    /// Latency Tolerance Reporting
    Ltr = 0x0018,
    /// Secondary PCI Express
    SecondaryPcie = 0x0019,
    /// Protocol Multiplexing
    ProtocolMultiplexing = 0x001A,
    /// Process Address Space ID
    Pasid = 0x001B,
    /// LN Requester
    LnRequester = 0x001C,
    /// Downstream Port Containment
    Dpc = 0x001D,
    /// L1 PM Substates
    L1PmSubstates = 0x001E,
    /// Precision Time Measurement
    Ptm = 0x001F,
    /// PCI Express over M-PHY
    MPhyPcie = 0x0020,
    /// FRS Queueing
    FrsQueueing = 0x0021,
    /// Readiness Time Reporting
    Rtr = 0x0022,
    /// Designated Vendor-Specific
    DesignatedVendorSpecific = 0x0023,
    /// VF Resizable BAR
    VfResizableBar = 0x0024,
    /// Data Link Feature
    DataLinkFeature = 0x0025,
    /// Physical Layer 16.0 GT/s
    PhysicalLayer16 = 0x0026,
    /// Lane Margining at Receiver
    LaneMargining = 0x0027,
    /// Hierarchy ID
    HierarchyId = 0x0028,
    /// Native PCIe Enclosure Management
    Npem = 0x0029,
    /// Physical Layer 32.0 GT/s
    PhysicalLayer32 = 0x002A,
    /// Alternate Protocol
    AlternateProtocol = 0x002B,
    /// System Firmware Intermediary
    Sfi = 0x002C,
}

// ============================================================================
// PCI Class Codes
// ============================================================================

/// PCI device class codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciClass {
    /// Unclassified device
    Unclassified,
    /// Mass storage controller
    MassStorage,
    /// Network controller
    Network,
    /// Display controller
    Display,
    /// Multimedia controller
    Multimedia,
    /// Memory controller
    Memory,
    /// Bridge device
    Bridge,
    /// Simple communication controller
    SimpleCommunication,
    /// Base system peripheral
    BaseSystemPeripheral,
    /// Input device controller
    InputDevice,
    /// Docking station
    DockingStation,
    /// Processor
    Processor,
    /// Serial bus controller
    SerialBus,
    /// Wireless controller
    Wireless,
    /// Intelligent controller
    Intelligent,
    /// Satellite communication controller
    SatelliteCommunication,
    /// Encryption controller
    Encryption,
    /// Signal processing controller
    SignalProcessing,
    /// Processing accelerator
    ProcessingAccelerator,
    /// Non-essential instrumentation
    NonEssentialInstrumentation,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for PciClass {
    fn from(value: u8) -> Self {
        match value {
            0x00 => PciClass::Unclassified,
            0x01 => PciClass::MassStorage,
            0x02 => PciClass::Network,
            0x03 => PciClass::Display,
            0x04 => PciClass::Multimedia,
            0x05 => PciClass::Memory,
            0x06 => PciClass::Bridge,
            0x07 => PciClass::SimpleCommunication,
            0x08 => PciClass::BaseSystemPeripheral,
            0x09 => PciClass::InputDevice,
            0x0A => PciClass::DockingStation,
            0x0B => PciClass::Processor,
            0x0C => PciClass::SerialBus,
            0x0D => PciClass::Wireless,
            0x0E => PciClass::Intelligent,
            0x0F => PciClass::SatelliteCommunication,
            0x10 => PciClass::Encryption,
            0x11 => PciClass::SignalProcessing,
            0x12 => PciClass::ProcessingAccelerator,
            0x13 => PciClass::NonEssentialInstrumentation,
            _ => PciClass::Unknown(value),
        }
    }
}

// ============================================================================
// BAR Types
// ============================================================================

/// BAR タイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarType {
    /// Memory-mapped I/O (32-bit)
    Memory32 {
        prefetchable: bool,
    },
    /// Memory-mapped I/O (64-bit)
    Memory64 {
        prefetchable: bool,
    },
    /// I/O port
    Io,
    /// Unused/Invalid
    Unused,
}

/// BAR 情報
#[derive(Clone, Copy, Debug)]
pub struct BarInfo {
    /// BAR インデックス (0-5)
    pub index: u8,
    /// BAR タイプ
    pub bar_type: BarType,
    /// ベースアドレス
    pub base_address: u64,
    /// サイズ（バイト）
    pub size: u64,
}

impl BarInfo {
    /// BAR が有効かどうか
    pub fn is_valid(&self) -> bool {
        self.size > 0 && self.bar_type != BarType::Unused
    }

    /// プリフェッチ可能かどうか
    pub fn is_prefetchable(&self) -> bool {
        matches!(
            self.bar_type,
            BarType::Memory32 { prefetchable: true } | BarType::Memory64 { prefetchable: true }
        )
    }

    /// メモリマップドかどうか
    pub fn is_memory(&self) -> bool {
        matches!(self.bar_type, BarType::Memory32 { .. } | BarType::Memory64 { .. })
    }

    /// I/Oポートかどうか
    pub fn is_io(&self) -> bool {
        self.bar_type == BarType::Io
    }
}

// ============================================================================
// BAR Enum (Simpler Variant)
// ============================================================================

/// BAR (Base Address Register) - 簡易版
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    /// 32-bit メモリマップドI/O
    Memory32 {
        base: u64,
        size: u64,
        prefetchable: bool,
    },
    /// 64-bit メモリマップドI/O
    Memory64 {
        base: u64,
        size: u64,
        prefetchable: bool,
    },
    /// I/Oポート
    Io {
        base: u64,
        size: u64,
    },
}

impl Bar {
    /// ベースアドレスを取得
    pub fn base(&self) -> u64 {
        match self {
            Bar::Memory32 { base, .. } => *base,
            Bar::Memory64 { base, .. } => *base,
            Bar::Io { base, .. } => *base,
        }
    }

    /// サイズを取得
    pub fn size(&self) -> u64 {
        match self {
            Bar::Memory32 { size, .. } => *size,
            Bar::Memory64 { size, .. } => *size,
            Bar::Io { size, .. } => *size,
        }
    }

    /// メモリマップドかどうか
    pub fn is_memory(&self) -> bool {
        matches!(self, Bar::Memory32 { .. } | Bar::Memory64 { .. })
    }

    /// I/Oポートかどうか
    pub fn is_io(&self) -> bool {
        matches!(self, Bar::Io { .. })
    }

    /// プリフェッチ可能かどうか
    pub fn is_prefetchable(&self) -> bool {
        matches!(
            self,
            Bar::Memory32 { prefetchable: true, .. } | Bar::Memory64 { prefetchable: true, .. }
        )
    }
}

// ============================================================================
// Device Identifiers
// ============================================================================

/// ベンダーID
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct VendorId(pub u16);

impl VendorId {
    /// 無効なベンダーID（デバイスが存在しない）
    pub const INVALID: Self = Self(0xFFFF);

    /// 有効なベンダーIDかどうか
    pub fn is_valid(&self) -> bool {
        self.0 != 0xFFFF && self.0 != 0
    }
}

impl From<u16> for VendorId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// デバイスID
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct DeviceId(pub u16);

impl DeviceId {
    /// 無効なデバイスID
    pub const INVALID: Self = Self(0xFFFF);
}

impl From<u16> for DeviceId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

// ============================================================================
// Class Code
// ============================================================================

/// クラスコード（Class/Subclass/ProgIF）
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ClassCode {
    /// クラスコード
    pub class: u8,
    /// サブクラスコード
    pub subclass: u8,
    /// プログラミングインターフェース
    pub prog_if: u8,
}

impl ClassCode {
    /// 新しいクラスコードを作成
    pub const fn new(class: u8, subclass: u8, prog_if: u8) -> Self {
        Self { class, subclass, prog_if }
    }

    /// 32ビットクラスコードレジスタから作成
    pub fn from_register(class_reg: u32) -> Self {
        Self {
            class: ((class_reg >> 24) & 0xFF) as u8,
            subclass: ((class_reg >> 16) & 0xFF) as u8,
            prog_if: ((class_reg >> 8) & 0xFF) as u8,
        }
    }

    /// NVMeコントローラかどうか
    pub fn is_nvme(&self) -> bool {
        self.class == 0x01 && self.subclass == 0x08 && self.prog_if == 0x02
    }

    /// USB xHCIコントローラかどうか
    pub fn is_xhci(&self) -> bool {
        self.class == 0x0C && self.subclass == 0x03 && self.prog_if == 0x30
    }

    /// VirtIOデバイスかどうか
    pub fn is_virtio(&self) -> bool {
        self.class == 0xFF  // VirtIO uses vendor-specific class
    }

    /// ネットワークコントローラかどうか
    pub fn is_network(&self) -> bool {
        self.class == 0x02
    }

    /// ストレージコントローラかどうか
    pub fn is_storage(&self) -> bool {
        self.class == 0x01
    }

    /// ディスプレイコントローラかどうか
    pub fn is_display(&self) -> bool {
        self.class == 0x03
    }
}

impl fmt::Display for ClassCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{:02x}", self.class, self.subclass, self.prog_if)
    }
}
