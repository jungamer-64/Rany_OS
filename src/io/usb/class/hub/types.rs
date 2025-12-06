// ============================================================================
// src/io/usb/class/hub/types.rs - USB Hub Types and Constants
// ============================================================================
//!
//! # USB Hub 型定義と定数

#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// Hub Constants
// ============================================================================

/// Hub クラスコード
pub const HUB_CLASS: u8 = 0x09;

/// Hub サブクラス
pub const HUB_SUBCLASS: u8 = 0x00;

/// USB 2.0 Hub プロトコル: Full/Low Speed
pub const HUB_PROTOCOL_FS: u8 = 0x00;
/// USB 2.0 Hub プロトコル: High Speed Single TT
pub const HUB_PROTOCOL_HS_SINGLE_TT: u8 = 0x01;
/// USB 2.0 Hub プロトコル: High Speed Multiple TT
pub const HUB_PROTOCOL_HS_MULTI_TT: u8 = 0x02;
/// USB 3.0 Hub プロトコル
pub const HUB_PROTOCOL_SS: u8 = 0x03;

// ============================================================================
// Hub Request Codes
// ============================================================================

/// GET_STATUS
pub const HUB_GET_STATUS: u8 = 0x00;
/// CLEAR_FEATURE
pub const HUB_CLEAR_FEATURE: u8 = 0x01;
/// SET_FEATURE
pub const HUB_SET_FEATURE: u8 = 0x03;
/// GET_DESCRIPTOR
pub const HUB_GET_DESCRIPTOR: u8 = 0x06;
/// SET_DESCRIPTOR
pub const HUB_SET_DESCRIPTOR: u8 = 0x07;
/// CLEAR_TT_BUFFER
pub const HUB_CLEAR_TT_BUFFER: u8 = 0x08;
/// RESET_TT
pub const HUB_RESET_TT: u8 = 0x09;
/// GET_TT_STATE
pub const HUB_GET_TT_STATE: u8 = 0x0A;
/// STOP_TT
pub const HUB_STOP_TT: u8 = 0x0B;
/// SET_HUB_DEPTH (USB 3.0)
pub const HUB_SET_HUB_DEPTH: u8 = 0x0C;
/// GET_PORT_ERR_COUNT (USB 3.0)
pub const HUB_GET_PORT_ERR_COUNT: u8 = 0x0D;

// ============================================================================
// Hub Features
// ============================================================================

/// Hub Local Power Change
pub const HUB_C_HUB_LOCAL_POWER: u16 = 0;
/// Hub Over-Current Change
pub const HUB_C_HUB_OVER_CURRENT: u16 = 1;

// ============================================================================
// Port Features
// ============================================================================

/// Port Connection
pub const PORT_CONNECTION: u16 = 0;
/// Port Enable
pub const PORT_ENABLE: u16 = 1;
/// Port Suspend
pub const PORT_SUSPEND: u16 = 2;
/// Port Over-current
pub const PORT_OVER_CURRENT: u16 = 3;
/// Port Reset
pub const PORT_RESET: u16 = 4;
/// Port Link State (USB 3.0)
pub const PORT_LINK_STATE: u16 = 5;
/// Port Power
pub const PORT_POWER: u16 = 8;
/// Port Low Speed
pub const PORT_LOW_SPEED: u16 = 9;
/// Port High Speed (USB 2.0)
pub const PORT_HIGH_SPEED: u16 = 10;
/// Port Test Mode
pub const PORT_TEST: u16 = 11;
/// Port Indicator
pub const PORT_INDICATOR: u16 = 12;
/// Port Remote Wake Mask (USB 3.0)
pub const PORT_REMOTE_WAKE_MASK: u16 = 27;
/// BH Port Reset (USB 3.0)
pub const BH_PORT_RESET: u16 = 28;
/// Force Link PM Accept (USB 3.0)
pub const FORCE_LINKPM_ACCEPT: u16 = 30;

// Port Change Features
/// Port Connection Change
pub const C_PORT_CONNECTION: u16 = 16;
/// Port Enable Change
pub const C_PORT_ENABLE: u16 = 17;
/// Port Suspend Change
pub const C_PORT_SUSPEND: u16 = 18;
/// Port Over-Current Change
pub const C_PORT_OVER_CURRENT: u16 = 19;
/// Port Reset Change
pub const C_PORT_RESET: u16 = 20;
/// BH Port Reset Change (USB 3.0)
pub const C_BH_PORT_RESET: u16 = 29;
/// Port Link State Change (USB 3.0)
pub const C_PORT_LINK_STATE: u16 = 25;
/// Port Config Error Change (USB 3.0)
pub const C_PORT_CONFIG_ERROR: u16 = 26;

// ============================================================================
// Hub Descriptor Types
// ============================================================================

/// USB 2.0 Hub Descriptor Type
pub const HUB_DESCRIPTOR_TYPE_20: u8 = 0x29;
/// USB 3.0 Hub Descriptor Type
pub const HUB_DESCRIPTOR_TYPE_30: u8 = 0x2A;

// ============================================================================
// Hub Speed
// ============================================================================

/// ハブ速度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubSpeed {
    /// USB 1.x Full Speed
    FullSpeed,
    /// USB 2.0 High Speed (Single TT)
    HighSpeedSingleTT,
    /// USB 2.0 High Speed (Multiple TT)
    HighSpeedMultiTT,
    /// USB 3.x Super Speed
    SuperSpeed,
}

impl HubSpeed {
    pub fn from_protocol(protocol: u8) -> Self {
        match protocol {
            0x00 => Self::FullSpeed,
            0x01 => Self::HighSpeedSingleTT,
            0x02 => Self::HighSpeedMultiTT,
            0x03 => Self::SuperSpeed,
            _ => Self::FullSpeed,
        }
    }
    
    /// USB 3.x かどうか
    pub fn is_usb3(&self) -> bool {
        matches!(self, Self::SuperSpeed)
    }
}

// ============================================================================
// Hub Descriptor
// ============================================================================

/// Hub ディスクリプタ (USB 2.0)
#[derive(Debug, Clone)]
pub struct HubDescriptor {
    /// ポート数
    pub num_ports: u8,
    /// 特性
    pub characteristics: HubCharacteristics,
    /// 電源投入からポートが使えるまでの時間 (2ms単位)
    pub power_on_to_power_good: u8,
    /// ハブコントローラの最大消費電流 (mA)
    pub hub_controller_current: u8,
    /// デバイス着脱可能ビットマップ
    pub device_removable: Vec<u8>,
    /// ポートパワーコントロールマスク
    pub port_power_control_mask: Vec<u8>,
}

impl HubDescriptor {
    /// バイト配列からパース
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }
        
        let num_ports = data[2];
        let characteristics = HubCharacteristics::from_u16(
            u16::from_le_bytes([data[3], data[4]])
        );
        let power_on_to_power_good = data[5];
        let hub_controller_current = data[6];
        
        // DeviceRemovable と PortPowerCtrlMask は可変長
        let bitmap_bytes = (num_ports as usize + 7) / 8;
        let device_removable = if data.len() > 7 {
            data[7..(7 + bitmap_bytes).min(data.len())].to_vec()
        } else {
            vec![0; bitmap_bytes]
        };
        
        let port_power_control_mask = if data.len() > 7 + bitmap_bytes {
            data[(7 + bitmap_bytes)..].to_vec()
        } else {
            vec![0xFF; bitmap_bytes]
        };
        
        Some(Self {
            num_ports,
            characteristics,
            power_on_to_power_good,
            hub_controller_current,
            device_removable,
            port_power_control_mask,
        })
    }
    
    /// ポートがリムーバブルか
    pub fn is_port_removable(&self, port: u8) -> bool {
        if port == 0 || port > self.num_ports {
            return false;
        }
        let byte_index = ((port - 1) / 8) as usize;
        let bit_index = (port - 1) % 8;
        if byte_index < self.device_removable.len() {
            (self.device_removable[byte_index] & (1 << bit_index)) == 0
        } else {
            true
        }
    }
}

/// Hub 特性
#[derive(Debug, Clone, Copy)]
pub struct HubCharacteristics {
    /// 電源切り替えモード (0: ganged, 1: individual)
    pub power_switching_mode: u8,
    /// コンパウンドデバイス
    pub compound_device: bool,
    /// 過電流保護モード (0: global, 1: individual)
    pub over_current_protection_mode: u8,
    /// TT Think Time (USB 2.0)
    pub tt_think_time: u8,
    /// ポートインジケータサポート
    pub port_indicators: bool,
}

impl HubCharacteristics {
    pub fn from_u16(value: u16) -> Self {
        Self {
            power_switching_mode: (value & 0x03) as u8,
            compound_device: (value & 0x04) != 0,
            over_current_protection_mode: ((value >> 3) & 0x03) as u8,
            tt_think_time: ((value >> 5) & 0x03) as u8,
            port_indicators: (value & 0x80) != 0,
        }
    }
}

// ============================================================================
// Device Speed
// ============================================================================

/// デバイス速度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSpeed {
    /// Low Speed (1.5 Mbps)
    Low,
    /// Full Speed (12 Mbps)
    Full,
    /// High Speed (480 Mbps)
    High,
    /// Super Speed (5 Gbps)
    Super,
    /// Super Speed Plus (10+ Gbps)
    SuperPlus,
}

// ============================================================================
// Hub Port Status
// ============================================================================

/// Hub ポートステータス
#[derive(Debug, Clone, Copy, Default)]
pub struct HubPortStatus {
    /// ステータスビット
    pub status: u16,
    /// 変更ビット
    pub change: u16,
}

impl HubPortStatus {
    /// バイト配列からパース
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Self::default();
        }
        Self {
            status: u16::from_le_bytes([data[0], data[1]]),
            change: u16::from_le_bytes([data[2], data[3]]),
        }
    }
    
    /// デバイスが接続されているか
    pub fn connected(&self) -> bool {
        (self.status & (1 << PORT_CONNECTION)) != 0
    }
    
    /// ポートが有効か
    pub fn enabled(&self) -> bool {
        (self.status & (1 << PORT_ENABLE)) != 0
    }
    
    /// サスペンド中か
    pub fn suspended(&self) -> bool {
        (self.status & (1 << PORT_SUSPEND)) != 0
    }
    
    /// 過電流状態か
    pub fn over_current(&self) -> bool {
        (self.status & (1 << PORT_OVER_CURRENT)) != 0
    }
    
    /// リセット中か
    pub fn resetting(&self) -> bool {
        (self.status & (1 << PORT_RESET)) != 0
    }
    
    /// 電源がオンか
    pub fn powered(&self) -> bool {
        (self.status & (1 << PORT_POWER)) != 0
    }
    
    /// Low Speed デバイスか
    pub fn low_speed(&self) -> bool {
        (self.status & (1 << PORT_LOW_SPEED)) != 0
    }
    
    /// High Speed デバイスか (USB 2.0)
    pub fn high_speed(&self) -> bool {
        (self.status & (1 << PORT_HIGH_SPEED)) != 0
    }
    
    /// 接続変更があったか
    pub fn connection_changed(&self) -> bool {
        (self.change & (1 << (C_PORT_CONNECTION - 16))) != 0
    }
    
    /// リセット完了か
    pub fn reset_changed(&self) -> bool {
        (self.change & (1 << (C_PORT_RESET - 16))) != 0
    }
    
    /// デバイス速度を判定
    pub fn device_speed(&self) -> DeviceSpeed {
        if self.high_speed() {
            DeviceSpeed::High
        } else if self.low_speed() {
            DeviceSpeed::Low
        } else {
            DeviceSpeed::Full
        }
    }
}
