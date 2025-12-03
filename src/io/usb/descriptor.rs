// ============================================================================
// src/io/usb/descriptor.rs - USB Descriptors
// ============================================================================
//!
//! # USB ディスクリプタ
//!
//! USBデバイスの構成を記述するディスクリプタの定義。
//!
//! ## 型安全性
//! - SafePackedRead による安全なパック構造体アクセス
//! - Newtype パターンによる ID/インデックス管理

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

// ============================================================================
// Descriptor Types
// ============================================================================

/// ディスクリプタタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType {
    Device = 1,
    Configuration = 2,
    String = 3,
    Interface = 4,
    Endpoint = 5,
    DeviceQualifier = 6,
    OtherSpeedConfiguration = 7,
    InterfacePower = 8,
    Otg = 9,
    Debug = 10,
    InterfaceAssociation = 11,
    Bos = 15,
    DeviceCapability = 16,
    SuperSpeedEndpointCompanion = 48,
    SuperSpeedPlusIsochEndpointCompanion = 49,
    // クラス固有
    HidReport = 0x22,
}

impl DescriptorType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(DescriptorType::Device),
            2 => Some(DescriptorType::Configuration),
            3 => Some(DescriptorType::String),
            4 => Some(DescriptorType::Interface),
            5 => Some(DescriptorType::Endpoint),
            6 => Some(DescriptorType::DeviceQualifier),
            7 => Some(DescriptorType::OtherSpeedConfiguration),
            8 => Some(DescriptorType::InterfacePower),
            9 => Some(DescriptorType::Otg),
            10 => Some(DescriptorType::Debug),
            11 => Some(DescriptorType::InterfaceAssociation),
            15 => Some(DescriptorType::Bos),
            16 => Some(DescriptorType::DeviceCapability),
            48 => Some(DescriptorType::SuperSpeedEndpointCompanion),
            49 => Some(DescriptorType::SuperSpeedPlusIsochEndpointCompanion),
            0x22 => Some(DescriptorType::HidReport),
            _ => None,
        }
    }
}

// ============================================================================
// Safe Packed Read Trait
// ============================================================================

/// パック構造体の安全な読み取りトレイト
pub trait SafePackedRead: Sized {
    /// バイト配列から構造体を作成
    fn from_bytes(data: &[u8]) -> Option<Self>;
}

/// フィールドの安全な読み取りマクロ
macro_rules! read_field {
    ($ptr:expr, $field:ident) => {{
        let field_ptr = unsafe { core::ptr::addr_of!((*$ptr).$field) };
        unsafe { core::ptr::read_unaligned(field_ptr) }
    }};
}

// ============================================================================
// Device Descriptor
// ============================================================================

/// デバイスディスクリプタ (18バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct DeviceDescriptor {
    /// 長さ (18)
    pub b_length: u8,
    /// タイプ (1)
    pub b_descriptor_type: u8,
    /// USB仕様バージョン (BCD)
    pub bcd_usb: u16,
    /// デバイスクラス
    pub b_device_class: u8,
    /// デバイスサブクラス
    pub b_device_sub_class: u8,
    /// デバイスプロトコル
    pub b_device_protocol: u8,
    /// 最大パケットサイズ (EP0)
    pub b_max_packet_size0: u8,
    /// ベンダーID
    pub id_vendor: u16,
    /// プロダクトID
    pub id_product: u16,
    /// デバイスバージョン (BCD)
    pub bcd_device: u16,
    /// 製造者文字列インデックス
    pub i_manufacturer: u8,
    /// 製品文字列インデックス
    pub i_product: u8,
    /// シリアル番号文字列インデックス
    pub i_serial_number: u8,
    /// コンフィグレーション数
    pub b_num_configurations: u8,
}

impl SafePackedRead for DeviceDescriptor {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }

        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            b_length: read_field!(ptr, b_length),
            b_descriptor_type: read_field!(ptr, b_descriptor_type),
            bcd_usb: read_field!(ptr, bcd_usb),
            b_device_class: read_field!(ptr, b_device_class),
            b_device_sub_class: read_field!(ptr, b_device_sub_class),
            b_device_protocol: read_field!(ptr, b_device_protocol),
            b_max_packet_size0: read_field!(ptr, b_max_packet_size0),
            id_vendor: read_field!(ptr, id_vendor),
            id_product: read_field!(ptr, id_product),
            bcd_device: read_field!(ptr, bcd_device),
            i_manufacturer: read_field!(ptr, i_manufacturer),
            i_product: read_field!(ptr, i_product),
            i_serial_number: read_field!(ptr, i_serial_number),
            b_num_configurations: read_field!(ptr, b_num_configurations),
        })
    }
}

impl DeviceDescriptor {
    /// USB バージョンを文字列で取得
    pub fn usb_version_string(&self) -> String {
        let major = (self.bcd_usb >> 8) & 0xFF;
        let minor = (self.bcd_usb >> 4) & 0x0F;
        let patch = self.bcd_usb & 0x0F;
        alloc::format!("{}.{}.{}", major, minor, patch)
    }

    /// デバイスバージョンを文字列で取得
    pub fn device_version_string(&self) -> String {
        let major = (self.bcd_device >> 8) & 0xFF;
        let minor = (self.bcd_device >> 4) & 0x0F;
        let patch = self.bcd_device & 0x0F;
        alloc::format!("{}.{}.{}", major, minor, patch)
    }
}

// ============================================================================
// Configuration Descriptor
// ============================================================================

/// コンフィグレーションディスクリプタ (9バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ConfigurationDescriptor {
    /// 長さ (9)
    pub b_length: u8,
    /// タイプ (2)
    pub b_descriptor_type: u8,
    /// 合計長さ
    pub w_total_length: u16,
    /// インターフェース数
    pub b_num_interfaces: u8,
    /// コンフィグレーション値
    pub b_configuration_value: u8,
    /// コンフィグレーション文字列インデックス
    pub i_configuration: u8,
    /// 属性
    pub bm_attributes: u8,
    /// 最大電力 (2mA単位)
    pub b_max_power: u8,
}

impl SafePackedRead for ConfigurationDescriptor {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None;
        }

        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            b_length: read_field!(ptr, b_length),
            b_descriptor_type: read_field!(ptr, b_descriptor_type),
            w_total_length: read_field!(ptr, w_total_length),
            b_num_interfaces: read_field!(ptr, b_num_interfaces),
            b_configuration_value: read_field!(ptr, b_configuration_value),
            i_configuration: read_field!(ptr, i_configuration),
            bm_attributes: read_field!(ptr, bm_attributes),
            b_max_power: read_field!(ptr, b_max_power),
        })
    }
}

impl ConfigurationDescriptor {
    /// セルフパワード?
    pub fn is_self_powered(&self) -> bool {
        (self.bm_attributes & 0x40) != 0
    }

    /// リモートウェイクアップ対応?
    pub fn supports_remote_wakeup(&self) -> bool {
        (self.bm_attributes & 0x20) != 0
    }

    /// 最大電力 (mA)
    pub fn max_power_ma(&self) -> u16 {
        (self.b_max_power as u16) * 2
    }
}

// ============================================================================
// Interface Descriptor
// ============================================================================

/// インターフェースディスクリプタ (9バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct InterfaceDescriptor {
    /// 長さ (9)
    pub b_length: u8,
    /// タイプ (4)
    pub b_descriptor_type: u8,
    /// インターフェース番号
    pub b_interface_number: u8,
    /// 代替設定
    pub b_alternate_setting: u8,
    /// エンドポイント数
    pub b_num_endpoints: u8,
    /// インターフェースクラス
    pub b_interface_class: u8,
    /// インターフェースサブクラス
    pub b_interface_sub_class: u8,
    /// インターフェースプロトコル
    pub b_interface_protocol: u8,
    /// インターフェース文字列インデックス
    pub i_interface: u8,
}

impl SafePackedRead for InterfaceDescriptor {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None;
        }

        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            b_length: read_field!(ptr, b_length),
            b_descriptor_type: read_field!(ptr, b_descriptor_type),
            b_interface_number: read_field!(ptr, b_interface_number),
            b_alternate_setting: read_field!(ptr, b_alternate_setting),
            b_num_endpoints: read_field!(ptr, b_num_endpoints),
            b_interface_class: read_field!(ptr, b_interface_class),
            b_interface_sub_class: read_field!(ptr, b_interface_sub_class),
            b_interface_protocol: read_field!(ptr, b_interface_protocol),
            i_interface: read_field!(ptr, i_interface),
        })
    }
}

/// USBクラスコード
pub mod class_code {
    pub const AUDIO: u8 = 0x01;
    pub const CDC: u8 = 0x02;
    pub const HID: u8 = 0x03;
    pub const PHYSICAL: u8 = 0x05;
    pub const IMAGE: u8 = 0x06;
    pub const PRINTER: u8 = 0x07;
    pub const MASS_STORAGE: u8 = 0x08;
    pub const HUB: u8 = 0x09;
    pub const CDC_DATA: u8 = 0x0A;
    pub const SMART_CARD: u8 = 0x0B;
    pub const CONTENT_SECURITY: u8 = 0x0D;
    pub const VIDEO: u8 = 0x0E;
    pub const PERSONAL_HEALTHCARE: u8 = 0x0F;
    pub const AUDIO_VIDEO: u8 = 0x10;
    pub const BILLBOARD: u8 = 0x11;
    pub const USB_TYPE_C_BRIDGE: u8 = 0x12;
    pub const DIAGNOSTIC: u8 = 0xDC;
    pub const WIRELESS: u8 = 0xE0;
    pub const MISCELLANEOUS: u8 = 0xEF;
    pub const APPLICATION_SPECIFIC: u8 = 0xFE;
    pub const VENDOR_SPECIFIC: u8 = 0xFF;
}

// ============================================================================
// Endpoint Descriptor
// ============================================================================

/// エンドポイントディスクリプタ (7バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct EndpointDescriptor {
    /// 長さ (7)
    pub b_length: u8,
    /// タイプ (5)
    pub b_descriptor_type: u8,
    /// エンドポイントアドレス
    pub b_endpoint_address: u8,
    /// 属性
    pub bm_attributes: u8,
    /// 最大パケットサイズ
    pub w_max_packet_size: u16,
    /// ポーリング間隔
    pub b_interval: u8,
}

impl SafePackedRead for EndpointDescriptor {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }

        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            b_length: read_field!(ptr, b_length),
            b_descriptor_type: read_field!(ptr, b_descriptor_type),
            b_endpoint_address: read_field!(ptr, b_endpoint_address),
            bm_attributes: read_field!(ptr, bm_attributes),
            w_max_packet_size: read_field!(ptr, w_max_packet_size),
            b_interval: read_field!(ptr, b_interval),
        })
    }
}

impl EndpointDescriptor {
    /// エンドポイント番号
    pub fn endpoint_number(&self) -> u8 {
        self.b_endpoint_address & 0x0F
    }

    /// IN方向?
    pub fn is_in(&self) -> bool {
        (self.b_endpoint_address & 0x80) != 0
    }

    /// 転送タイプ
    pub fn transfer_type(&self) -> super::TransferType {
        match self.bm_attributes & 0x03 {
            0 => super::TransferType::Control,
            1 => super::TransferType::Isochronous,
            2 => super::TransferType::Bulk,
            3 => super::TransferType::Interrupt,
            _ => unreachable!(),
        }
    }

    /// 最大パケットサイズ（追加トランザクション数を除く）
    pub fn max_packet_size(&self) -> u16 {
        self.w_max_packet_size & 0x07FF
    }

    /// 追加トランザクション数 (High-speed アイソクロナス用)
    pub fn additional_transactions(&self) -> u8 {
        ((self.w_max_packet_size >> 11) & 0x03) as u8
    }

    /// エンドポイントアドレスを取得
    pub fn address(&self) -> super::EndpointAddress {
        super::EndpointAddress(self.b_endpoint_address)
    }
}

// ============================================================================
// String Descriptor
// ============================================================================

/// 文字列ディスクリプタヘッダ
#[repr(C, packed)]
pub struct StringDescriptorHeader {
    pub b_length: u8,
    pub b_descriptor_type: u8,
}

/// 文字列ディスクリプタをパース
pub fn parse_string_descriptor(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let length = data[0] as usize;
    if length < 2 || length > data.len() {
        return None;
    }

    if data[1] != DescriptorType::String as u8 {
        return None;
    }

    // UTF-16LEからUTF-8に変換
    let utf16_data = &data[2..length];
    let mut utf16_chars = Vec::new();

    for i in (0..utf16_data.len()).step_by(2) {
        if i + 1 < utf16_data.len() {
            let c = u16::from_le_bytes([utf16_data[i], utf16_data[i + 1]]);
            utf16_chars.push(c);
        }
    }

    String::from_utf16(&utf16_chars).ok()
}

// ============================================================================
// SuperSpeed Endpoint Companion Descriptor
// ============================================================================

/// SuperSpeedエンドポイントコンパニオンディスクリプタ (6バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SsEndpointCompanionDescriptor {
    /// 長さ (6)
    pub b_length: u8,
    /// タイプ (48)
    pub b_descriptor_type: u8,
    /// 最大バースト
    pub b_max_burst: u8,
    /// 属性
    pub bm_attributes: u8,
    /// バイト/インターバル
    pub w_bytes_per_interval: u16,
}

impl SafePackedRead for SsEndpointCompanionDescriptor {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }

        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            b_length: read_field!(ptr, b_length),
            b_descriptor_type: read_field!(ptr, b_descriptor_type),
            b_max_burst: read_field!(ptr, b_max_burst),
            bm_attributes: read_field!(ptr, bm_attributes),
            w_bytes_per_interval: read_field!(ptr, w_bytes_per_interval),
        })
    }
}

// ============================================================================
// BOS Descriptor
// ============================================================================

/// BOSディスクリプタ (5バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct BosDescriptor {
    /// 長さ (5)
    pub b_length: u8,
    /// タイプ (15)
    pub b_descriptor_type: u8,
    /// 合計長さ
    pub w_total_length: u16,
    /// デバイスケイパビリティ数
    pub b_num_device_caps: u8,
}

impl SafePackedRead for BosDescriptor {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            b_length: read_field!(ptr, b_length),
            b_descriptor_type: read_field!(ptr, b_descriptor_type),
            w_total_length: read_field!(ptr, w_total_length),
            b_num_device_caps: read_field!(ptr, b_num_device_caps),
        })
    }
}

// ============================================================================
// Descriptor Parser
// ============================================================================

/// パースされたコンフィグレーション
#[derive(Debug, Clone)]
pub struct ParsedConfiguration {
    pub config: ConfigurationDescriptor,
    pub interfaces: Vec<ParsedInterface>,
}

/// パースされたインターフェース
#[derive(Debug, Clone)]
pub struct ParsedInterface {
    pub interface: InterfaceDescriptor,
    pub endpoints: Vec<EndpointDescriptor>,
    pub ss_companions: Vec<SsEndpointCompanionDescriptor>,
}

/// コンフィグレーションディスクリプタをパース
pub fn parse_configuration(data: &[u8]) -> Option<ParsedConfiguration> {
    if data.len() < 9 {
        return None;
    }

    let config = ConfigurationDescriptor::from_bytes(data)?;
    let total_length = config.w_total_length as usize;

    if data.len() < total_length {
        return None;
    }

    let mut interfaces = Vec::new();
    let mut current_interface: Option<ParsedInterface> = None;
    let mut offset = 9; // Skip configuration descriptor

    while offset < total_length {
        if offset + 2 > total_length {
            break;
        }

        let length = data[offset] as usize;
        let desc_type = data[offset + 1];

        if length < 2 || offset + length > total_length {
            break;
        }

        match DescriptorType::from_u8(desc_type) {
            Some(DescriptorType::Interface) => {
                // Save previous interface
                if let Some(iface) = current_interface.take() {
                    interfaces.push(iface);
                }

                if let Some(interface) = InterfaceDescriptor::from_bytes(&data[offset..]) {
                    current_interface = Some(ParsedInterface {
                        interface,
                        endpoints: Vec::new(),
                        ss_companions: Vec::new(),
                    });
                }
            }
            Some(DescriptorType::Endpoint) => {
                if let Some(ref mut iface) = current_interface {
                    if let Some(endpoint) = EndpointDescriptor::from_bytes(&data[offset..]) {
                        iface.endpoints.push(endpoint);
                    }
                }
            }
            Some(DescriptorType::SuperSpeedEndpointCompanion) => {
                if let Some(ref mut iface) = current_interface {
                    if let Some(companion) =
                        SsEndpointCompanionDescriptor::from_bytes(&data[offset..])
                    {
                        iface.ss_companions.push(companion);
                    }
                }
            }
            _ => {
                // Skip unknown descriptors
            }
        }

        offset += length;
    }

    // Save last interface
    if let Some(iface) = current_interface {
        interfaces.push(iface);
    }

    Some(ParsedConfiguration { config, interfaces })
}
