// ============================================================================
// src/io/usb/xhci/port_manager.rs - xHCI Port Management
// ============================================================================
//!
//! # xHCI ポート管理
//!
//! ルートハブポートの監視、リセット、状態管理を担当。
//! USB 2.0/3.0ポートの自動検出とデバイス接続処理。

#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use spin::Mutex;

// ============================================================================
// Port Register Offsets
// ============================================================================

/// PORTSC レジスタオフセット（ポートnの場合: 0x400 + 0x10 * (n-1)）
pub const PORTSC_BASE: usize = 0x400;
pub const PORTSC_STRIDE: usize = 0x10;

/// PORTPMSC レジスタオフセット
pub const PORTPMSC_OFFSET: usize = 0x04;

/// PORTLI レジスタオフセット
pub const PORTLI_OFFSET: usize = 0x08;

/// PORTHLPMC レジスタオフセット (USB3.0のみ)
pub const PORTHLPMC_OFFSET: usize = 0x0C;

// ============================================================================
// PORTSC Bits
// ============================================================================

/// Current Connect Status
pub const PORTSC_CCS: u32 = 1 << 0;
/// Port Enabled/Disabled
pub const PORTSC_PED: u32 = 1 << 1;
/// Over-current Active
pub const PORTSC_OCA: u32 = 1 << 3;
/// Port Reset
pub const PORTSC_PR: u32 = 1 << 4;
/// Port Link State (bits 5-8)
pub const PORTSC_PLS_MASK: u32 = 0xF << 5;
pub const PORTSC_PLS_SHIFT: u32 = 5;
/// Port Power
pub const PORTSC_PP: u32 = 1 << 9;
/// Port Speed (bits 10-13)
pub const PORTSC_SPEED_MASK: u32 = 0xF << 10;
pub const PORTSC_SPEED_SHIFT: u32 = 10;
/// Port Indicator Control (bits 14-15)
pub const PORTSC_PIC_MASK: u32 = 0x3 << 14;
/// Link State Write Strobe
pub const PORTSC_LWS: u32 = 1 << 16;
/// Connect Status Change
pub const PORTSC_CSC: u32 = 1 << 17;
/// Port Enabled/Disabled Change
pub const PORTSC_PEC: u32 = 1 << 18;
/// Warm Port Reset Change (USB3 only)
pub const PORTSC_WRC: u32 = 1 << 19;
/// Over-current Change
pub const PORTSC_OCC: u32 = 1 << 20;
/// Port Reset Change
pub const PORTSC_PRC: u32 = 1 << 21;
/// Port Link State Change
pub const PORTSC_PLC: u32 = 1 << 22;
/// Port Config Error Change
pub const PORTSC_CEC: u32 = 1 << 23;
/// Cold Attach Status (USB3 only)
pub const PORTSC_CAS: u32 = 1 << 24;
/// Wake on Connect Enable
pub const PORTSC_WCE: u32 = 1 << 25;
/// Wake on Disconnect Enable
pub const PORTSC_WDE: u32 = 1 << 26;
/// Wake on Over-current Enable
pub const PORTSC_WOE: u32 = 1 << 27;
/// Device Removable
pub const PORTSC_DR: u32 = 1 << 30;
/// Warm Port Reset (USB3 only)
pub const PORTSC_WPR: u32 = 1 << 31;

/// Write-1-to-clear ビット
pub const PORTSC_W1C_BITS: u32 = PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC 
    | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

/// 保持すべきビット（読み取り後の書き戻し時）
pub const PORTSC_PRESERVE_BITS: u32 = PORTSC_PP | PORTSC_PIC_MASK;

// ============================================================================
// Port Link State
// ============================================================================

/// ポートリンク状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PortLinkState {
    /// U0 - Active
    U0 = 0,
    /// U1 - Low power state (USB3)
    U1 = 1,
    /// U2 - Deeper low power (USB3)
    U2 = 2,
    /// U3 - Suspended
    U3 = 3,
    /// Disabled
    Disabled = 4,
    /// RxDetect
    RxDetect = 5,
    /// Inactive
    Inactive = 6,
    /// Polling
    Polling = 7,
    /// Recovery
    Recovery = 8,
    /// Hot Reset
    HotReset = 9,
    /// Compliance Mode
    ComplianceMode = 10,
    /// Test Mode
    TestMode = 11,
    /// Resume
    Resume = 15,
}

impl PortLinkState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::U0),
            1 => Some(Self::U1),
            2 => Some(Self::U2),
            3 => Some(Self::U3),
            4 => Some(Self::Disabled),
            5 => Some(Self::RxDetect),
            6 => Some(Self::Inactive),
            7 => Some(Self::Polling),
            8 => Some(Self::Recovery),
            9 => Some(Self::HotReset),
            10 => Some(Self::ComplianceMode),
            11 => Some(Self::TestMode),
            15 => Some(Self::Resume),
            _ => None,
        }
    }
}

// ============================================================================
// Port Speed
// ============================================================================

/// ポート速度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PortSpeed {
    /// Full Speed (12 Mbps)
    FullSpeed = 1,
    /// Low Speed (1.5 Mbps)
    LowSpeed = 2,
    /// High Speed (480 Mbps)
    HighSpeed = 3,
    /// Super Speed (5 Gbps)
    SuperSpeed = 4,
    /// Super Speed Plus (10+ Gbps)
    SuperSpeedPlus = 5,
}

impl PortSpeed {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::FullSpeed),
            2 => Some(Self::LowSpeed),
            3 => Some(Self::HighSpeed),
            4 => Some(Self::SuperSpeed),
            5 => Some(Self::SuperSpeedPlus),
            _ => None,
        }
    }
    
    /// 速度をMbps単位で取得
    pub fn mbps(&self) -> u32 {
        match self {
            Self::LowSpeed => 1,
            Self::FullSpeed => 12,
            Self::HighSpeed => 480,
            Self::SuperSpeed => 5000,
            Self::SuperSpeedPlus => 10000,
        }
    }
    
    /// USB 3.xかどうか
    pub fn is_usb3(&self) -> bool {
        matches!(self, Self::SuperSpeed | Self::SuperSpeedPlus)
    }
}

// ============================================================================
// Port Protocol
// ============================================================================

/// ポートプロトコル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocol {
    /// USB 2.0
    Usb2,
    /// USB 3.0 / 3.1 / 3.2
    Usb3,
}

// ============================================================================
// Port State
// ============================================================================

/// ポート状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// デバイス未接続
    Disconnected,
    /// デバイス接続済み、リセット待ち
    Attached,
    /// リセット中
    Resetting,
    /// 有効（アドレス割り当て可能）
    Enabled,
    /// サスペンド中
    Suspended,
    /// エラー状態
    Error,
    /// 過電流
    OverCurrent,
}

// ============================================================================
// Port Info
// ============================================================================

/// ポート情報
#[derive(Debug, Clone)]
pub struct PortInfo {
    /// ポート番号（1-based）
    pub port_number: u8,
    /// プロトコル
    pub protocol: PortProtocol,
    /// 現在の状態
    pub state: PortState,
    /// 現在の速度
    pub speed: Option<PortSpeed>,
    /// リンク状態
    pub link_state: PortLinkState,
    /// 電源状態
    pub powered: bool,
    /// 割り当てられたスロットID
    pub slot_id: Option<u8>,
}

// ============================================================================
// Port Manager
// ============================================================================

/// xHCI ポートマネージャ
pub struct XhciPortManager {
    /// 操作用ベースアドレス
    operational_base: u64,
    /// ポート数
    num_ports: u8,
    /// USB 2.0 ポート範囲
    usb2_port_start: u8,
    usb2_port_count: u8,
    /// USB 3.0 ポート範囲
    usb3_port_start: u8,
    usb3_port_count: u8,
    /// ポートごとのスロットID割り当て
    port_slots: Mutex<Vec<Option<u8>>>,
    /// ポート状態キャッシュ
    port_states: Mutex<Vec<PortState>>,
}

impl XhciPortManager {
    /// 新しいポートマネージャを作成
    pub fn new(
        operational_base: u64,
        num_ports: u8,
        usb2_port_start: u8,
        usb2_port_count: u8,
        usb3_port_start: u8,
        usb3_port_count: u8,
    ) -> Self {
        let port_slots = (0..num_ports).map(|_| None).collect();
        let port_states = (0..num_ports).map(|_| PortState::Disconnected).collect();
        
        Self {
            operational_base,
            num_ports,
            usb2_port_start,
            usb2_port_count,
            usb3_port_start,
            usb3_port_count,
            port_slots: Mutex::new(port_slots),
            port_states: Mutex::new(port_states),
        }
    }
    
    // ========================================================================
    // レジスタアクセス
    // ========================================================================
    
    /// PORTSCレジスタのアドレスを計算
    fn portsc_address(&self, port: u8) -> u64 {
        debug_assert!(port >= 1 && port <= self.num_ports);
        self.operational_base + PORTSC_BASE as u64 + (port as u64 - 1) * PORTSC_STRIDE as u64
    }
    
    /// PORTSCを読み取る
    pub fn read_portsc(&self, port: u8) -> u32 {
        if port < 1 || port > self.num_ports {
            return 0;
        }
        unsafe {
            let addr = self.portsc_address(port) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }
    
    /// PORTSCに書き込む
    fn write_portsc(&self, port: u8, value: u32) {
        if port < 1 || port > self.num_ports {
            return;
        }
        unsafe {
            let addr = self.portsc_address(port) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }
    
    /// PORTSCの変更ビットをクリア
    pub fn clear_port_change_bits(&self, port: u8) {
        let portsc = self.read_portsc(port);
        // W1Cビットをクリア、他のビットは保持
        let clear_value = (portsc & PORTSC_PRESERVE_BITS) | PORTSC_W1C_BITS;
        self.write_portsc(port, clear_value);
    }
    
    // ========================================================================
    // ポート情報取得
    // ========================================================================
    
    /// ポート情報を取得
    pub fn get_port_info(&self, port: u8) -> Option<PortInfo> {
        if port < 1 || port > self.num_ports {
            return None;
        }
        
        let portsc = self.read_portsc(port);
        let protocol = self.get_port_protocol(port);
        let state = self.interpret_port_state(portsc);
        let speed = if (portsc & PORTSC_PED) != 0 {
            let speed_val = ((portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;
            PortSpeed::from_u8(speed_val)
        } else {
            None
        };
        let link_state = {
            let pls = ((portsc & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT) as u8;
            PortLinkState::from_u8(pls).unwrap_or(PortLinkState::Disabled)
        };
        let powered = (portsc & PORTSC_PP) != 0;
        let slot_id = self.port_slots.lock()[(port - 1) as usize];
        
        Some(PortInfo {
            port_number: port,
            protocol,
            state,
            speed,
            link_state,
            powered,
            slot_id,
        })
    }
    
    /// ポートプロトコルを取得
    pub fn get_port_protocol(&self, port: u8) -> PortProtocol {
        if port >= self.usb3_port_start && port < self.usb3_port_start + self.usb3_port_count {
            PortProtocol::Usb3
        } else {
            PortProtocol::Usb2
        }
    }
    
    /// PORTSCから状態を解釈
    fn interpret_port_state(&self, portsc: u32) -> PortState {
        if (portsc & PORTSC_OCA) != 0 {
            PortState::OverCurrent
        } else if (portsc & PORTSC_PR) != 0 {
            PortState::Resetting
        } else if (portsc & PORTSC_PED) != 0 {
            let pls = ((portsc & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT) as u8;
            if pls == PortLinkState::U3 as u8 {
                PortState::Suspended
            } else {
                PortState::Enabled
            }
        } else if (portsc & PORTSC_CCS) != 0 {
            PortState::Attached
        } else {
            PortState::Disconnected
        }
    }
    
    /// 全ポート情報を取得
    pub fn get_all_ports(&self) -> Vec<PortInfo> {
        (1..=self.num_ports)
            .filter_map(|p| self.get_port_info(p))
            .collect()
    }
    
    /// 接続済みポートを取得
    pub fn get_connected_ports(&self) -> Vec<u8> {
        (1..=self.num_ports)
            .filter(|&p| {
                let portsc = self.read_portsc(p);
                (portsc & PORTSC_CCS) != 0
            })
            .collect()
    }
    
    // ========================================================================
    // ポート制御
    // ========================================================================
    
    /// ポートをリセット
    pub fn reset_port(&self, port: u8) -> Result<(), PortError> {
        if port < 1 || port > self.num_ports {
            return Err(PortError::InvalidPort);
        }
        
        let portsc = self.read_portsc(port);
        
        // デバイスが接続されているか確認
        if (portsc & PORTSC_CCS) == 0 {
            return Err(PortError::NoDevice);
        }
        
        // リセットを発行
        let protocol = self.get_port_protocol(port);
        if protocol == PortProtocol::Usb3 {
            // USB 3.0: Warm Reset or Hot Reset
            let reset_value = (portsc & PORTSC_PRESERVE_BITS) | PORTSC_PR;
            self.write_portsc(port, reset_value);
        } else {
            // USB 2.0: Port Reset
            let reset_value = (portsc & PORTSC_PRESERVE_BITS) | PORTSC_PR;
            self.write_portsc(port, reset_value);
        }
        
        self.port_states.lock()[(port - 1) as usize] = PortState::Resetting;
        Ok(())
    }
    
    /// ポートリセット完了を待機（ポーリング版）
    pub fn wait_reset_complete(&self, port: u8, timeout_ms: u32) -> Result<PortSpeed, PortError> {
        if port < 1 || port > self.num_ports {
            return Err(PortError::InvalidPort);
        }
        
        // 簡易的なポーリング待機（実際はタイマー使用）
        for _ in 0..timeout_ms * 100 {
            let portsc = self.read_portsc(port);
            
            // リセット完了をチェック
            if (portsc & PORTSC_PR) == 0 {
                // リセット完了
                if (portsc & PORTSC_PED) != 0 {
                    // ポート有効
                    let speed_val = ((portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;
                    if let Some(speed) = PortSpeed::from_u8(speed_val) {
                        self.port_states.lock()[(port - 1) as usize] = PortState::Enabled;
                        // 変更ビットをクリア
                        self.clear_port_change_bits(port);
                        return Ok(speed);
                    }
                }
                return Err(PortError::ResetFailed);
            }
            
            // 短い遅延
            core::hint::spin_loop();
        }
        
        Err(PortError::Timeout)
    }
    
    /// ポート電源をオン
    pub fn power_on(&self, port: u8) {
        if port < 1 || port > self.num_ports {
            return;
        }
        let portsc = self.read_portsc(port);
        if (portsc & PORTSC_PP) == 0 {
            self.write_portsc(port, portsc | PORTSC_PP);
        }
    }
    
    /// ポート電源をオフ
    pub fn power_off(&self, port: u8) {
        if port < 1 || port > self.num_ports {
            return;
        }
        let portsc = self.read_portsc(port);
        if (portsc & PORTSC_PP) != 0 {
            self.write_portsc(port, portsc & !PORTSC_PP);
        }
    }
    
    /// ポートをサスペンド
    pub fn suspend_port(&self, port: u8) -> Result<(), PortError> {
        if port < 1 || port > self.num_ports {
            return Err(PortError::InvalidPort);
        }
        
        let portsc = self.read_portsc(port);
        if (portsc & PORTSC_PED) == 0 {
            return Err(PortError::PortDisabled);
        }
        
        // Link State を U3 (Suspended) に設定
        let new_portsc = (portsc & !PORTSC_PLS_MASK) 
            | ((PortLinkState::U3 as u32) << PORTSC_PLS_SHIFT)
            | PORTSC_LWS;
        self.write_portsc(port, new_portsc);
        
        self.port_states.lock()[(port - 1) as usize] = PortState::Suspended;
        Ok(())
    }
    
    /// ポートをレジューム
    pub fn resume_port(&self, port: u8) -> Result<(), PortError> {
        if port < 1 || port > self.num_ports {
            return Err(PortError::InvalidPort);
        }
        
        let portsc = self.read_portsc(port);
        
        // Link State を U0 (Active) に設定
        let new_portsc = (portsc & !PORTSC_PLS_MASK) 
            | ((PortLinkState::U0 as u32) << PORTSC_PLS_SHIFT)
            | PORTSC_LWS;
        self.write_portsc(port, new_portsc);
        
        self.port_states.lock()[(port - 1) as usize] = PortState::Enabled;
        Ok(())
    }
    
    // ========================================================================
    // スロット管理
    // ========================================================================
    
    /// ポートにスロットを割り当て
    pub fn assign_slot(&self, port: u8, slot_id: u8) {
        if port >= 1 && port <= self.num_ports {
            self.port_slots.lock()[(port - 1) as usize] = Some(slot_id);
        }
    }
    
    /// ポートのスロット割り当てを解除
    pub fn release_slot(&self, port: u8) {
        if port >= 1 && port <= self.num_ports {
            self.port_slots.lock()[(port - 1) as usize] = None;
        }
    }
    
    /// スロットIDからポートを検索
    pub fn find_port_by_slot(&self, slot_id: u8) -> Option<u8> {
        let slots = self.port_slots.lock();
        for (idx, &slot) in slots.iter().enumerate() {
            if slot == Some(slot_id) {
                return Some((idx + 1) as u8);
            }
        }
        None
    }
    
    // ========================================================================
    // イベント処理
    // ========================================================================
    
    /// ポート状態変更イベントを処理
    pub fn handle_port_status_change(&self, port: u8) -> PortChangeEvent {
        if port < 1 || port > self.num_ports {
            return PortChangeEvent::None;
        }
        
        let portsc = self.read_portsc(port);
        let mut event = PortChangeEvent::None;
        
        // 接続状態変更
        if (portsc & PORTSC_CSC) != 0 {
            event = if (portsc & PORTSC_CCS) != 0 {
                self.port_states.lock()[(port - 1) as usize] = PortState::Attached;
                PortChangeEvent::Connected
            } else {
                self.port_states.lock()[(port - 1) as usize] = PortState::Disconnected;
                self.port_slots.lock()[(port - 1) as usize] = None;
                PortChangeEvent::Disconnected
            };
        }
        
        // リセット完了
        if (portsc & PORTSC_PRC) != 0 {
            if (portsc & PORTSC_PED) != 0 {
                self.port_states.lock()[(port - 1) as usize] = PortState::Enabled;
                event = PortChangeEvent::ResetComplete;
            }
        }
        
        // 過電流
        if (portsc & PORTSC_OCC) != 0 {
            if (portsc & PORTSC_OCA) != 0 {
                self.port_states.lock()[(port - 1) as usize] = PortState::OverCurrent;
                event = PortChangeEvent::OverCurrent;
            }
        }
        
        // 変更ビットをクリア
        self.clear_port_change_bits(port);
        
        event
    }
    
    /// 全ポートの変更をスキャン
    pub fn scan_all_ports(&self) -> Vec<(u8, PortChangeEvent)> {
        let mut changes = Vec::new();
        
        for port in 1..=self.num_ports {
            let portsc = self.read_portsc(port);
            if (portsc & PORTSC_W1C_BITS) != 0 {
                let event = self.handle_port_status_change(port);
                if event != PortChangeEvent::None {
                    changes.push((port, event));
                }
            }
        }
        
        changes
    }
}

// ============================================================================
// Port Events
// ============================================================================

/// ポート変更イベント
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortChangeEvent {
    /// 変更なし
    None,
    /// デバイス接続
    Connected,
    /// デバイス切断
    Disconnected,
    /// リセット完了
    ResetComplete,
    /// 過電流検出
    OverCurrent,
    /// サスペンド開始
    Suspended,
    /// レジューム完了
    Resumed,
}

// ============================================================================
// Errors
// ============================================================================

/// ポートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// 無効なポート番号
    InvalidPort,
    /// デバイスなし
    NoDevice,
    /// ポート無効
    PortDisabled,
    /// リセット失敗
    ResetFailed,
    /// タイムアウト
    Timeout,
    /// 過電流
    OverCurrent,
}
