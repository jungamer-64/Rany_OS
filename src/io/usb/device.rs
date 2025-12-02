// ============================================================================
// src/io/usb/device.rs - USB Device Management
// ============================================================================
//!
//! # USBデバイス管理
//!
//! USBデバイスの列挙と管理機能。

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use super::{
    DeviceAddress, EndpointAddress, SetupPacket, SlotId, UsbDevice, UsbError, UsbResult, UsbSpeed,
};
use super::descriptor::{
    DeviceDescriptor, ConfigurationDescriptor, InterfaceDescriptor, EndpointDescriptor,
    parse_configuration, parse_string_descriptor, ParsedConfiguration, SafePackedRead,
};

// ============================================================================
// Device State
// ============================================================================

/// デバイス状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// 接続検出
    Attached,
    /// アドレス割り当て済み
    Addressed,
    /// コンフィグレーション設定済み
    Configured,
    /// サスペンド状態
    Suspended,
}

// ============================================================================
// Endpoint Configuration
// ============================================================================

/// エンドポイント設定
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// アドレス
    pub address: EndpointAddress,
    /// 転送タイプ
    pub transfer_type: super::TransferType,
    /// 最大パケットサイズ
    pub max_packet_size: u16,
    /// ポーリング間隔
    pub interval: u8,
}

impl From<&EndpointDescriptor> for EndpointConfig {
    fn from(desc: &EndpointDescriptor) -> Self {
        Self {
            address: desc.address(),
            transfer_type: desc.transfer_type(),
            max_packet_size: desc.max_packet_size(),
            interval: desc.b_interval,
        }
    }
}

// ============================================================================
// Interface Configuration
// ============================================================================

/// インターフェース設定
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// インターフェース番号
    pub number: u8,
    /// 代替設定
    pub alternate_setting: u8,
    /// クラス
    pub class: u8,
    /// サブクラス
    pub subclass: u8,
    /// プロトコル
    pub protocol: u8,
    /// エンドポイント
    pub endpoints: Vec<EndpointConfig>,
}

// ============================================================================
// Device Information
// ============================================================================

/// デバイス情報
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// デバイスアドレス
    pub address: DeviceAddress,
    /// ベンダーID
    pub vendor_id: u16,
    /// プロダクトID
    pub product_id: u16,
    /// デバイスクラス
    pub device_class: u8,
    /// デバイスサブクラス
    pub device_subclass: u8,
    /// デバイスプロトコル
    pub device_protocol: u8,
    /// USBバージョン
    pub usb_version: String,
    /// 製造者名
    pub manufacturer: Option<String>,
    /// 製品名
    pub product: Option<String>,
    /// シリアル番号
    pub serial_number: Option<String>,
    /// USB速度
    pub speed: UsbSpeed,
    /// コンフィグレーション数
    pub num_configurations: u8,
}

// ============================================================================
// Device Enumeration
// ============================================================================

/// デバイス列挙ヘルパー
pub struct DeviceEnumerator;

impl DeviceEnumerator {
    /// デバイスディスクリプタを取得
    pub async fn get_device_descriptor(device: &dyn UsbDevice) -> UsbResult<DeviceDescriptor> {
        let mut buffer = [0u8; 18];
        
        let setup = SetupPacket::get_descriptor(1, 0, 18); // Device descriptor
        device.control_transfer(&setup, Some(&mut buffer)).await?;

        DeviceDescriptor::from_bytes(&buffer)
            .ok_or(UsbError::InvalidParameter)
    }

    /// コンフィグレーションディスクリプタを取得
    pub async fn get_configuration_descriptor(
        device: &dyn UsbDevice,
        config_index: u8,
    ) -> UsbResult<ParsedConfiguration> {
        // まずヘッダだけ取得して全体サイズを確認
        let mut header = [0u8; 9];
        let setup = SetupPacket::get_descriptor(2, config_index, 9);
        device.control_transfer(&setup, Some(&mut header)).await?;

        let total_length = u16::from_le_bytes([header[2], header[3]]) as usize;

        // 全体を取得
        let mut buffer = alloc::vec![0u8; total_length];
        let setup = SetupPacket::get_descriptor(2, config_index, total_length as u16);
        device.control_transfer(&setup, Some(&mut buffer)).await?;

        parse_configuration(&buffer)
            .ok_or(UsbError::InvalidParameter)
    }

    /// 文字列ディスクリプタを取得
    pub async fn get_string_descriptor(
        device: &dyn UsbDevice,
        string_index: u8,
        lang_id: u16,
    ) -> UsbResult<String> {
        if string_index == 0 {
            return Err(UsbError::InvalidParameter);
        }

        let mut buffer = [0u8; 256];
        let setup = SetupPacket {
            bm_request_type: 0x80,
            b_request: 0x06,
            w_value: ((3 as u16) << 8) | (string_index as u16), // String descriptor
            w_index: lang_id,
            w_length: 256,
        };

        let len = device.control_transfer(&setup, Some(&mut buffer)).await?;

        parse_string_descriptor(&buffer[..len])
            .ok_or(UsbError::InvalidParameter)
    }

    /// サポートされている言語IDのリストを取得
    pub async fn get_supported_languages(device: &dyn UsbDevice) -> UsbResult<Vec<u16>> {
        let mut buffer = [0u8; 256];
        let setup = SetupPacket::get_descriptor(3, 0, 256); // String descriptor index 0

        let len = device.control_transfer(&setup, Some(&mut buffer)).await?;

        if len < 4 {
            return Ok(Vec::new());
        }

        let mut languages = Vec::new();
        for i in (2..len).step_by(2) {
            if i + 1 < len {
                languages.push(u16::from_le_bytes([buffer[i], buffer[i + 1]]));
            }
        }

        Ok(languages)
    }

    /// デバイスを設定
    pub async fn set_configuration(
        device: &dyn UsbDevice,
        config_value: u8,
    ) -> UsbResult<()> {
        let setup = SetupPacket::set_configuration(config_value);
        device.control_transfer(&setup, None).await?;
        Ok(())
    }

    /// デバイス情報を収集
    pub async fn gather_device_info(device: &dyn UsbDevice) -> UsbResult<DeviceInfo> {
        let desc = Self::get_device_descriptor(device).await?;

        // 文字列ディスクリプタを取得（英語）
        let lang_id = 0x0409; // English (US)

        let manufacturer = if desc.i_manufacturer != 0 {
            Self::get_string_descriptor(device, desc.i_manufacturer, lang_id).await.ok()
        } else {
            None
        };

        let product = if desc.i_product != 0 {
            Self::get_string_descriptor(device, desc.i_product, lang_id).await.ok()
        } else {
            None
        };

        let serial_number = if desc.i_serial_number != 0 {
            Self::get_string_descriptor(device, desc.i_serial_number, lang_id).await.ok()
        } else {
            None
        };

        Ok(DeviceInfo {
            address: device.address(),
            vendor_id: desc.id_vendor,
            product_id: desc.id_product,
            device_class: desc.b_device_class,
            device_subclass: desc.b_device_sub_class,
            device_protocol: desc.b_device_protocol,
            usb_version: desc.usb_version_string(),
            manufacturer,
            product,
            serial_number,
            speed: device.speed(),
            num_configurations: desc.b_num_configurations,
        })
    }
}

// ============================================================================
// Standard USB Requests
// ============================================================================

/// 標準USBリクエスト
pub struct StandardRequests;

impl StandardRequests {
    /// デバイスステータスを取得
    pub async fn get_status(device: &dyn UsbDevice) -> UsbResult<u16> {
        let mut buffer = [0u8; 2];
        let setup = SetupPacket::get_status();
        device.control_transfer(&setup, Some(&mut buffer)).await?;
        Ok(u16::from_le_bytes(buffer))
    }

    /// フィーチャーをクリア
    pub async fn clear_feature(device: &dyn UsbDevice, feature: u16) -> UsbResult<()> {
        let setup = SetupPacket::clear_feature(feature);
        device.control_transfer(&setup, None).await?;
        Ok(())
    }

    /// エンドポイントのSTALLをクリア
    pub async fn clear_endpoint_halt(
        device: &dyn UsbDevice,
        endpoint: EndpointAddress,
    ) -> UsbResult<()> {
        let setup = SetupPacket {
            bm_request_type: 0x02, // Host-to-device, Standard, Endpoint
            b_request: 0x01,       // CLEAR_FEATURE
            w_value: 0,            // ENDPOINT_HALT
            w_index: endpoint.0 as u16,
            w_length: 0,
        };
        device.control_transfer(&setup, None).await?;
        Ok(())
    }

    /// インターフェースの代替設定を設定
    pub async fn set_interface(
        device: &dyn UsbDevice,
        interface: u8,
        alternate_setting: u8,
    ) -> UsbResult<()> {
        let setup = SetupPacket {
            bm_request_type: 0x01, // Host-to-device, Standard, Interface
            b_request: 0x0B,       // SET_INTERFACE
            w_value: alternate_setting as u16,
            w_index: interface as u16,
            w_length: 0,
        };
        device.control_transfer(&setup, None).await?;
        Ok(())
    }

    /// 現在のインターフェース設定を取得
    pub async fn get_interface(
        device: &dyn UsbDevice,
        interface: u8,
    ) -> UsbResult<u8> {
        let mut buffer = [0u8; 1];
        let setup = SetupPacket {
            bm_request_type: 0x81, // Device-to-host, Standard, Interface
            b_request: 0x0A,       // GET_INTERFACE
            w_value: 0,
            w_index: interface as u16,
            w_length: 1,
        };
        device.control_transfer(&setup, Some(&mut buffer)).await?;
        Ok(buffer[0])
    }
}

// ============================================================================
// USB Hub Support
// ============================================================================

/// ハブクラスリクエスト
pub mod hub_class {
    use super::*;

    /// ハブディスクリプタ
    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct HubDescriptor {
        pub b_desc_length: u8,
        pub b_descriptor_type: u8,
        pub b_nbr_ports: u8,
        pub w_hub_characteristics: u16,
        pub b_pwr_on_2_pwr_good: u8,
        pub b_hub_contr_current: u8,
    }

    /// ハブディスクリプタを取得
    pub async fn get_hub_descriptor(device: &dyn UsbDevice) -> UsbResult<HubDescriptor> {
        let mut buffer = [0u8; 8];
        let setup = SetupPacket::class_request(
            true,  // IN
            0,     // Device
            0x06,  // GET_DESCRIPTOR
            (0x29 << 8), // Hub descriptor type
            0,
            8,
        );
        device.control_transfer(&setup, Some(&mut buffer)).await?;

        // パースは実際には SafePackedRead を実装すべき
        unsafe {
            Ok(core::ptr::read_unaligned(buffer.as_ptr() as *const HubDescriptor))
        }
    }

    /// ポートフィーチャーを設定
    pub async fn set_port_feature(
        device: &dyn UsbDevice,
        port: u8,
        feature: u16,
    ) -> UsbResult<()> {
        let setup = SetupPacket::class_request(
            false, // OUT
            3,     // Other (port)
            0x03,  // SET_FEATURE
            feature,
            port as u16,
            0,
        );
        device.control_transfer(&setup, None).await?;
        Ok(())
    }

    /// ポートフィーチャーをクリア
    pub async fn clear_port_feature(
        device: &dyn UsbDevice,
        port: u8,
        feature: u16,
    ) -> UsbResult<()> {
        let setup = SetupPacket::class_request(
            false, // OUT
            3,     // Other (port)
            0x01,  // CLEAR_FEATURE
            feature,
            port as u16,
            0,
        );
        device.control_transfer(&setup, None).await?;
        Ok(())
    }

    /// ポートステータスを取得
    pub async fn get_port_status(device: &dyn UsbDevice, port: u8) -> UsbResult<u32> {
        let mut buffer = [0u8; 4];
        let setup = SetupPacket::class_request(
            true,  // IN
            3,     // Other (port)
            0x00,  // GET_STATUS
            0,
            port as u16,
            4,
        );
        device.control_transfer(&setup, Some(&mut buffer)).await?;
        Ok(u32::from_le_bytes(buffer))
    }

    // ポートフィーチャー定数
    pub const PORT_RESET: u16 = 4;
    pub const PORT_POWER: u16 = 8;
    pub const C_PORT_CONNECTION: u16 = 16;
    pub const C_PORT_ENABLE: u16 = 17;
    pub const C_PORT_RESET: u16 = 20;
}
