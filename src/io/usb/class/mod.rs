// ============================================================================
// src/io/usb/class/mod.rs - USB Class Drivers
// ============================================================================
//!
//! # USB クラスドライバ
//!
//! USB デバイスクラス仕様に基づくドライバ実装。
//!
//! ## サポートするクラス
//! - HID (Human Interface Device) - キーボード、マウス等
//! - MSC (Mass Storage Class) - USBメモリ、外付けHDD等
//! - Hub - USBハブ
//!
//! ## クラスドライバインターフェース
//! 各クラスドライバは `UsbClassDriver` トレイトを実装し、
//! デバイスの初期化、データ転送、イベント処理を行う。

#![allow(dead_code)]

pub mod hid;
pub mod hub;
pub mod msc;

use alloc::boxed::Box;
use alloc::vec::Vec;

// Re-exports
pub use hid::{HidDevice, HidProtocol, HidReport, HidSubclass, UsbKeyboard, UsbMouse};
pub use hub::{HubCharacteristics, HubDescriptor, HubDevice, HubPortStatus, HubSpeed};
pub use msc::{MscDevice, MscProtocol, MscSubclass, ScsiCommand, ScsiSense};

// ============================================================================
// USB Class Codes
// ============================================================================

/// USB クラスコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbClass {
    /// インターフェースで定義
    PerInterface = 0x00,
    /// オーディオ
    Audio = 0x01,
    /// CDC (Communications Device Class)
    Cdc = 0x02,
    /// HID (Human Interface Device)
    Hid = 0x03,
    /// Physical
    Physical = 0x05,
    /// イメージ
    Image = 0x06,
    /// プリンター
    Printer = 0x07,
    /// Mass Storage
    MassStorage = 0x08,
    /// ハブ
    Hub = 0x09,
    /// CDC-Data
    CdcData = 0x0A,
    /// スマートカード
    SmartCard = 0x0B,
    /// コンテントセキュリティ
    ContentSecurity = 0x0D,
    /// ビデオ
    Video = 0x0E,
    /// パーソナルヘルスケア
    PersonalHealthcare = 0x0F,
    /// オーディオ/ビデオ
    AudioVideo = 0x10,
    /// Billboard
    Billboard = 0x11,
    /// USB Type-C Bridge
    TypeCBridge = 0x12,
    /// 診断
    Diagnostic = 0xDC,
    /// ワイヤレス
    Wireless = 0xE0,
    /// その他
    Miscellaneous = 0xEF,
    /// アプリケーション固有
    ApplicationSpecific = 0xFE,
    /// ベンダー固有
    VendorSpecific = 0xFF,
}

impl UsbClass {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::PerInterface),
            0x01 => Some(Self::Audio),
            0x02 => Some(Self::Cdc),
            0x03 => Some(Self::Hid),
            0x05 => Some(Self::Physical),
            0x06 => Some(Self::Image),
            0x07 => Some(Self::Printer),
            0x08 => Some(Self::MassStorage),
            0x09 => Some(Self::Hub),
            0x0A => Some(Self::CdcData),
            0x0B => Some(Self::SmartCard),
            0x0D => Some(Self::ContentSecurity),
            0x0E => Some(Self::Video),
            0x0F => Some(Self::PersonalHealthcare),
            0x10 => Some(Self::AudioVideo),
            0x11 => Some(Self::Billboard),
            0x12 => Some(Self::TypeCBridge),
            0xDC => Some(Self::Diagnostic),
            0xE0 => Some(Self::Wireless),
            0xEF => Some(Self::Miscellaneous),
            0xFE => Some(Self::ApplicationSpecific),
            0xFF => Some(Self::VendorSpecific),
            _ => None,
        }
    }
}

// ============================================================================
// Class Driver Interface
// ============================================================================

/// USB クラスドライバトレイト
pub trait UsbClassDriver: Send + Sync {
    /// ドライバ名を取得
    fn name(&self) -> &'static str;
    
    /// クラスコードを取得
    fn class_code(&self) -> UsbClass;
    
    /// このドライバがデバイスに対応しているか判定
    fn probe(&self, class: u8, subclass: u8, protocol: u8) -> bool;
    
    /// デバイスを初期化
    fn init(&mut self, slot_id: u8) -> Result<(), ClassDriverError>;
    
    /// デバイスを解放
    fn release(&mut self) -> Result<(), ClassDriverError>;
    
    /// ポーリング処理（非割り込みモード用）
    fn poll(&mut self) -> Result<(), ClassDriverError>;
    
    /// イベント通知を受信
    fn on_event(&mut self, event: ClassDriverEvent);
}

/// クラスドライバイベント
#[derive(Debug, Clone)]
pub enum ClassDriverEvent {
    /// 転送完了
    TransferComplete {
        endpoint: u8,
        status: TransferStatus,
        bytes_transferred: usize,
    },
    /// 接続状態変更
    ConnectionChange {
        connected: bool,
    },
    /// サスペンド/レジューム
    PowerStateChange {
        suspended: bool,
    },
    /// その他
    Custom(u32),
}

/// 転送ステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// 成功
    Success,
    /// STALL
    Stall,
    /// バッファエラー
    BufferError,
    /// バブルエラー
    BabbleError,
    /// CRCエラー
    CrcError,
    /// タイムアウト
    Timeout,
    /// その他のエラー
    Error(u8),
}

/// クラスドライバエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassDriverError {
    /// 初期化失敗
    InitFailed,
    /// デバイスなし
    NoDevice,
    /// 非対応デバイス
    UnsupportedDevice,
    /// 転送エラー
    TransferError(TransferStatus),
    /// タイムアウト
    Timeout,
    /// プロトコルエラー
    ProtocolError,
    /// リソース不足
    NoResources,
    /// 無効なパラメータ
    InvalidParameter,
    /// ドライバが既にバインド済み
    AlreadyBound,
    /// 内部エラー
    Internal,
}

// ============================================================================
// Class Driver Registry
// ============================================================================

/// クラスドライバレジストリ
pub struct ClassDriverRegistry {
    /// 登録済みドライバ
    drivers: Vec<Box<dyn UsbClassDriver>>,
}

impl ClassDriverRegistry {
    /// 新しいレジストリを作成
    pub fn new() -> Self {
        Self {
            drivers: Vec::new(),
        }
    }
    
    /// ドライバを登録
    pub fn register(&mut self, driver: Box<dyn UsbClassDriver>) {
        self.drivers.push(driver);
    }
    
    /// デバイスに対応するドライバを検索
    pub fn find_driver(&self, class: u8, subclass: u8, protocol: u8) -> Option<usize> {
        for (idx, driver) in self.drivers.iter().enumerate() {
            if driver.probe(class, subclass, protocol) {
                return Some(idx);
            }
        }
        None
    }
    
    /// インデックスでドライバを取得
    pub fn get(&self, index: usize) -> Option<&dyn UsbClassDriver> {
        self.drivers.get(index).map(|d| d.as_ref())
    }
    
    /// インデックスで可変参照を取得
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Box<dyn UsbClassDriver>> {
        self.drivers.get_mut(index)
    }
    
    /// 登録ドライバ数
    pub fn count(&self) -> usize {
        self.drivers.len()
    }
}

impl Default for ClassDriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Endpoint Helper
// ============================================================================

/// エンドポイントヘルパー
pub struct EndpointHelper;

impl EndpointHelper {
    /// エンドポイントアドレスから番号を取得
    pub fn endpoint_number(addr: u8) -> u8 {
        addr & 0x0F
    }
    
    /// エンドポイントアドレスがIN方向か判定
    pub fn is_in(addr: u8) -> bool {
        (addr & 0x80) != 0
    }
    
    /// エンドポイントアドレスを作成
    pub fn make_address(number: u8, direction_in: bool) -> u8 {
        if direction_in {
            number | 0x80
        } else {
            number
        }
    }
    
    /// DCI (Device Context Index) を計算
    pub fn to_dci(addr: u8) -> u8 {
        let ep_num = Self::endpoint_number(addr);
        if ep_num == 0 {
            1 // Control endpoint 0
        } else if Self::is_in(addr) {
            ep_num * 2 + 1
        } else {
            ep_num * 2
        }
    }
}

// ============================================================================
// Standard USB Requests for Class Drivers
// ============================================================================

/// クラス固有リクエストタイプ
pub const REQUEST_TYPE_CLASS: u8 = 0x20;
pub const REQUEST_TYPE_CLASS_INTERFACE: u8 = 0x21;
pub const REQUEST_TYPE_CLASS_ENDPOINT: u8 = 0x22;

/// 方向ビット
pub const REQUEST_DIR_IN: u8 = 0x80;
pub const REQUEST_DIR_OUT: u8 = 0x00;

/// リクエストビルダー
pub struct ClassRequest;

impl ClassRequest {
    /// GET_DESCRIPTOR (Class) を構築
    pub fn get_descriptor(descriptor_type: u8, index: u8, length: u16) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_IN,
            request: 0x06, // GET_DESCRIPTOR
            value: ((descriptor_type as u16) << 8) | (index as u16),
            index: 0,
            length,
        }
    }
    
    /// SET_DESCRIPTOR (Class) を構築
    pub fn set_descriptor(descriptor_type: u8, index: u8, length: u16) -> SetupPacket {
        SetupPacket {
            request_type: REQUEST_TYPE_CLASS_INTERFACE | REQUEST_DIR_OUT,
            request: 0x07, // SET_DESCRIPTOR
            value: ((descriptor_type as u16) << 8) | (index as u16),
            index: 0,
            length,
        }
    }
}

/// セットアップパケット
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
    /// バイト配列に変換
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.request_type;
        bytes[1] = self.request;
        bytes[2..4].copy_from_slice(&self.value.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.index.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.length.to_le_bytes());
        bytes
    }
    
    /// バイト配列から作成
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        Self {
            request_type: bytes[0],
            request: bytes[1],
            value: u16::from_le_bytes([bytes[2], bytes[3]]),
            index: u16::from_le_bytes([bytes[4], bytes[5]]),
            length: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }
}
