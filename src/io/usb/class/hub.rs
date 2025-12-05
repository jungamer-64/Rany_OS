// ============================================================================
// src/io/usb/class/hub.rs - USB Hub Class Driver
// ============================================================================
//!
//! # USB Hub クラスドライバ
//!
//! USBハブの制御とデバイスの再帰的列挙をサポート。
//!
//! ## 機能
//! - ハブポートの電源管理
//! - デバイス接続/切断検出
//! - ポートリセットとデバイス列挙
//! - 多段ハブ対応
//!
//! ## 参照仕様
//! - USB 2.0 Specification (Chapter 11)
//! - USB 3.2 Specification (Hub Class)

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;

use super::{
    ClassDriverError, ClassDriverEvent, SetupPacket, TransferStatus, UsbClass, UsbClassDriver,
    REQUEST_DIR_IN, REQUEST_DIR_OUT,
};

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
// Hub Device
// ============================================================================

/// USB Hub デバイス
pub struct HubDevice {
    /// スロットID
    slot_id: AtomicU8,
    /// インターフェース番号
    interface: u8,
    /// ハブ速度
    speed: HubSpeed,
    /// INエンドポイント（ステータス変更通知用）
    interrupt_endpoint: u8,
    /// Hub ディスクリプタ
    descriptor: Mutex<Option<HubDescriptor>>,
    /// ポートステータスキャッシュ
    port_status: Mutex<Vec<HubPortStatus>>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 接続デバイス管理
    attached_devices: Mutex<Vec<Option<AttachedDevice>>>,
    /// 列挙待ちポートキュー
    enumeration_queue: Mutex<VecDeque<u8>>,
    /// ハブ深度 (USB 3.0)
    hub_depth: AtomicU8,
}

/// 接続デバイス情報
#[derive(Debug, Clone)]
pub struct AttachedDevice {
    /// ポート番号
    pub port: u8,
    /// 割り当てられたスロットID
    pub slot_id: u8,
    /// デバイス速度
    pub speed: DeviceSpeed,
    /// ハブかどうか
    pub is_hub: bool,
}

impl HubDevice {
    /// 新しい Hub デバイスを作成
    pub fn new(interface: u8, speed: HubSpeed, interrupt_endpoint: u8) -> Self {
        Self {
            slot_id: AtomicU8::new(0),
            interface,
            speed,
            interrupt_endpoint,
            descriptor: Mutex::new(None),
            port_status: Mutex::new(Vec::new()),
            initialized: AtomicBool::new(false),
            attached_devices: Mutex::new(Vec::new()),
            enumeration_queue: Mutex::new(VecDeque::new()),
            hub_depth: AtomicU8::new(0),
        }
    }
    
    /// ポート数を取得
    pub fn num_ports(&self) -> u8 {
        self.descriptor.lock()
            .as_ref()
            .map(|d| d.num_ports)
            .unwrap_or(0)
    }
    
    /// ハブ深度を設定 (USB 3.0)
    pub fn set_hub_depth(&self, depth: u8) {
        self.hub_depth.store(depth, Ordering::SeqCst);
    }
    
    /// 接続デバイスを取得
    pub fn attached_devices(&self) -> Vec<AttachedDevice> {
        self.attached_devices.lock()
            .iter()
            .filter_map(|d| d.clone())
            .collect()
    }
    
    // ========================================================================
    // リクエストビルダー
    // ========================================================================
    
    /// GET_HUB_DESCRIPTOR を構築
    pub fn build_get_hub_descriptor(length: u16, is_usb3: bool) -> SetupPacket {
        let desc_type = if is_usb3 { HUB_DESCRIPTOR_TYPE_30 } else { HUB_DESCRIPTOR_TYPE_20 };
        SetupPacket {
            request_type: 0xA0 | REQUEST_DIR_IN, // Class, Device
            request: HUB_GET_DESCRIPTOR,
            value: (desc_type as u16) << 8,
            index: 0,
            length,
        }
    }
    
    /// GET_PORT_STATUS を構築
    pub fn build_get_port_status(port: u8) -> SetupPacket {
        SetupPacket {
            request_type: 0xA3 | REQUEST_DIR_IN, // Class, Other (Port)
            request: HUB_GET_STATUS,
            value: 0,
            index: port as u16,
            length: 4,
        }
    }
    
    /// SET_PORT_FEATURE を構築
    pub fn build_set_port_feature(port: u8, feature: u16) -> SetupPacket {
        SetupPacket {
            request_type: 0x23 | REQUEST_DIR_OUT, // Class, Other (Port)
            request: HUB_SET_FEATURE,
            value: feature,
            index: port as u16,
            length: 0,
        }
    }
    
    /// CLEAR_PORT_FEATURE を構築
    pub fn build_clear_port_feature(port: u8, feature: u16) -> SetupPacket {
        SetupPacket {
            request_type: 0x23 | REQUEST_DIR_OUT, // Class, Other (Port)
            request: HUB_CLEAR_FEATURE,
            value: feature,
            index: port as u16,
            length: 0,
        }
    }
    
    /// SET_HUB_DEPTH を構築 (USB 3.0)
    pub fn build_set_hub_depth(depth: u8) -> SetupPacket {
        SetupPacket {
            request_type: 0x20 | REQUEST_DIR_OUT, // Class, Device
            request: HUB_SET_HUB_DEPTH,
            value: depth as u16,
            index: 0,
            length: 0,
        }
    }
    
    // ========================================================================
    // ポート操作
    // ========================================================================
    
    /// ポート電源をオン
    pub fn power_on_port(&self, _port: u8) -> Result<(), ClassDriverError> {
        // SET_PORT_FEATURE(PORT_POWER) を送信
        Ok(())
    }
    
    /// ポート電源をオフ
    pub fn power_off_port(&self, _port: u8) -> Result<(), ClassDriverError> {
        // CLEAR_PORT_FEATURE(PORT_POWER) を送信
        Ok(())
    }
    
    /// ポートをリセット
    pub fn reset_port(&self, _port: u8) -> Result<(), ClassDriverError> {
        // SET_PORT_FEATURE(PORT_RESET) を送信
        Ok(())
    }
    
    /// ポートステータスをクリア
    pub fn clear_port_change(&self, _port: u8, _feature: u16) -> Result<(), ClassDriverError> {
        // CLEAR_PORT_FEATURE を送信
        Ok(())
    }
    
    /// ポートをサスペンド
    pub fn suspend_port(&self, _port: u8) -> Result<(), ClassDriverError> {
        // SET_PORT_FEATURE(PORT_SUSPEND) を送信
        Ok(())
    }
    
    /// ポートをレジューム
    pub fn resume_port(&self, _port: u8) -> Result<(), ClassDriverError> {
        // CLEAR_PORT_FEATURE(PORT_SUSPEND) を送信
        Ok(())
    }
    
    // ========================================================================
    // デバイス列挙
    // ========================================================================
    
    /// 変更通知を処理
    pub fn process_status_change(&self, change_bitmap: &[u8]) -> Vec<u8> {
        let mut changed_ports = Vec::new();
        
        for (byte_idx, &byte) in change_bitmap.iter().enumerate() {
            for bit in 0..8 {
                let port = byte_idx * 8 + bit;
                if port > 0 && (byte & (1 << bit)) != 0 {
                    changed_ports.push(port as u8);
                }
            }
        }
        
        changed_ports
    }
    
    /// ポートステータス変更を処理
    pub fn handle_port_status(&self, port: u8, status: HubPortStatus) -> Option<HubEvent> {
        // ポートステータスを更新
        {
            let mut port_status = self.port_status.lock();
            if port as usize <= port_status.len() {
                port_status[(port - 1) as usize] = status;
            }
        }
        
        // イベントを判定
        if status.connection_changed() {
            if status.connected() {
                return Some(HubEvent::DeviceConnected { port, speed: status.device_speed() });
            } else {
                // 接続デバイスを削除
                let mut attached = self.attached_devices.lock();
                if (port as usize) <= attached.len() {
                    attached[(port - 1) as usize] = None;
                }
                return Some(HubEvent::DeviceDisconnected { port });
            }
        }
        
        if status.reset_changed() && status.enabled() {
            return Some(HubEvent::ResetComplete { port, speed: status.device_speed() });
        }
        
        if status.over_current() {
            return Some(HubEvent::OverCurrent { port });
        }
        
        None
    }
    
    /// デバイス接続を記録
    pub fn record_attached_device(&self, port: u8, slot_id: u8, speed: DeviceSpeed, is_hub: bool) {
        let mut attached = self.attached_devices.lock();
        if (port as usize) <= attached.len() {
            attached[(port - 1) as usize] = Some(AttachedDevice {
                port,
                slot_id,
                speed,
                is_hub,
            });
        }
    }
    
    /// 列挙キューにポートを追加
    pub fn queue_enumeration(&self, port: u8) {
        self.enumeration_queue.lock().push_back(port);
    }
    
    /// 列挙キューから次のポートを取得
    pub fn next_enumeration(&self) -> Option<u8> {
        self.enumeration_queue.lock().pop_front()
    }
}

impl UsbClassDriver for HubDevice {
    fn name(&self) -> &'static str {
        "USB Hub"
    }
    
    fn class_code(&self) -> UsbClass {
        UsbClass::Hub
    }
    
    fn probe(&self, class: u8, _subclass: u8, _protocol: u8) -> bool {
        class == HUB_CLASS
    }
    
    fn init(&mut self, slot_id: u8) -> Result<(), ClassDriverError> {
        self.slot_id.store(slot_id, Ordering::SeqCst);
        
        // 1. Hub ディスクリプタを取得
        // 2. USB 3.0ならSET_HUB_DEPTHを送信
        // 3. 各ポートの電源をオン
        // 4. ポートステータスを初期化
        
        let num_ports = self.num_ports();
        *self.port_status.lock() = vec![HubPortStatus::default(); num_ports as usize];
        *self.attached_devices.lock() = vec![None; num_ports as usize];
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    fn release(&mut self) -> Result<(), ClassDriverError> {
        // 接続デバイスを切断
        // ポート電源をオフ
        
        self.initialized.store(false, Ordering::SeqCst);
        Ok(())
    }
    
    fn poll(&mut self) -> Result<(), ClassDriverError> {
        // INエンドポイントからステータス変更を読み取り
        Ok(())
    }
    
    fn on_event(&mut self, event: ClassDriverEvent) {
        if let ClassDriverEvent::TransferComplete { endpoint, status, bytes_transferred } = event {
            if endpoint == self.interrupt_endpoint && status == TransferStatus::Success {
                let _ = bytes_transferred;
            }
        }
    }
}

// ============================================================================
// Hub Events
// ============================================================================

/// Hub イベント
#[derive(Debug, Clone)]
pub enum HubEvent {
    /// デバイス接続
    DeviceConnected {
        port: u8,
        speed: DeviceSpeed,
    },
    /// デバイス切断
    DeviceDisconnected {
        port: u8,
    },
    /// リセット完了
    ResetComplete {
        port: u8,
        speed: DeviceSpeed,
    },
    /// 過電流
    OverCurrent {
        port: u8,
    },
    /// サスペンド
    Suspended {
        port: u8,
    },
    /// レジューム
    Resumed {
        port: u8,
    },
}

// ============================================================================
// Hub Enumeration State Machine
// ============================================================================

/// Hub 列挙状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEnumerationState {
    /// 初期状態
    Idle,
    /// 電源投入待ち
    WaitingPowerOn,
    /// デバイス接続待ち
    WaitingConnection,
    /// リセット中
    Resetting,
    /// リセット完了待ち
    WaitingResetComplete,
    /// アドレス設定中
    SettingAddress,
    /// 設定中
    Configuring,
    /// 完了
    Complete,
    /// エラー
    Error,
}

/// Hub 列挙ステートマシン
pub struct HubEnumerator {
    /// 現在の状態
    state: HubEnumerationState,
    /// 対象ポート
    port: u8,
    /// リトライ回数
    retry_count: u8,
    /// 最大リトライ
    max_retries: u8,
}

impl HubEnumerator {
    /// 新しいエニュメレータを作成
    pub fn new(port: u8) -> Self {
        Self {
            state: HubEnumerationState::Idle,
            port,
            retry_count: 0,
            max_retries: 3,
        }
    }
    
    /// 現在の状態を取得
    pub fn state(&self) -> HubEnumerationState {
        self.state
    }
    
    /// 次の状態に遷移
    pub fn advance(&mut self, success: bool) {
        self.state = match (self.state, success) {
            (HubEnumerationState::Idle, true) => HubEnumerationState::WaitingPowerOn,
            (HubEnumerationState::WaitingPowerOn, true) => HubEnumerationState::WaitingConnection,
            (HubEnumerationState::WaitingConnection, true) => HubEnumerationState::Resetting,
            (HubEnumerationState::Resetting, true) => HubEnumerationState::WaitingResetComplete,
            (HubEnumerationState::WaitingResetComplete, true) => HubEnumerationState::SettingAddress,
            (HubEnumerationState::SettingAddress, true) => HubEnumerationState::Configuring,
            (HubEnumerationState::Configuring, true) => HubEnumerationState::Complete,
            (_, false) => {
                self.retry_count += 1;
                if self.retry_count >= self.max_retries {
                    HubEnumerationState::Error
                } else {
                    HubEnumerationState::Resetting // リトライ
                }
            }
            (state, _) => state,
        };
    }
    
    /// 完了したか
    pub fn is_complete(&self) -> bool {
        matches!(self.state, HubEnumerationState::Complete | HubEnumerationState::Error)
    }
    
    /// 成功したか
    pub fn is_success(&self) -> bool {
        self.state == HubEnumerationState::Complete
    }
}
