// ============================================================================
// src/io/usb/class/hub/device.rs - USB Hub Device
// ============================================================================
//!
//! # USB Hub デバイス実装

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;

use super::super::{
    ClassDriverError, ClassDriverEvent, SetupPacket, TransferStatus, UsbClass, UsbClassDriver,
    REQUEST_DIR_IN, REQUEST_DIR_OUT,
};
use super::types::{
    DeviceSpeed, HubDescriptor, HubPortStatus, HubSpeed,
    HUB_CLASS, HUB_CLEAR_FEATURE, HUB_DESCRIPTOR_TYPE_20, HUB_DESCRIPTOR_TYPE_30,
    HUB_GET_DESCRIPTOR, HUB_GET_STATUS, HUB_SET_FEATURE, HUB_SET_HUB_DEPTH,
    C_PORT_CONNECTION, C_PORT_RESET, PORT_POWER, PORT_RESET,
};
use super::events::HubEvent;

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
