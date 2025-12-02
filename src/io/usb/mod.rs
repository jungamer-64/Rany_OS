// ============================================================================
// src/io/usb/mod.rs - USB Subsystem
// ============================================================================
//!
//! # USBサブシステム
//!
//! USB (Universal Serial Bus) デバイスのサポート。
//! xHCI (USB 3.x) コントローラを中心とした実装。
//!
//! ## アーキテクチャ
//! - xHCI ホストコントローラドライバ
//! - USB デバイスの列挙と管理
//! - USB クラスドライバ（HID、Mass Storage等）
//!
//! ## 型安全性
//! - Newtype パターンによるスロット/エンドポイント管理
//! - 状態機械による安全な状態遷移

#![allow(dead_code)]

pub mod xhci;
pub mod descriptor;
pub mod device;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use spin::RwLock;

// ============================================================================
// USB Constants
// ============================================================================

/// USB 速度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    /// Low Speed (1.5 Mbps)
    Low,
    /// Full Speed (12 Mbps)
    Full,
    /// High Speed (480 Mbps)
    High,
    /// Super Speed (5 Gbps)
    Super,
    /// Super Speed+ (10 Gbps)
    SuperPlus,
}

impl UsbSpeed {
    /// 速度コードから変換
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(UsbSpeed::Full),
            2 => Some(UsbSpeed::Low),
            3 => Some(UsbSpeed::High),
            4 => Some(UsbSpeed::Super),
            5 => Some(UsbSpeed::SuperPlus),
            _ => None,
        }
    }

    /// xHCI スロットコンテキスト用の速度値
    pub fn to_slot_speed(&self) -> u8 {
        match self {
            UsbSpeed::Low => 2,
            UsbSpeed::Full => 1,
            UsbSpeed::High => 3,
            UsbSpeed::Super => 4,
            UsbSpeed::SuperPlus => 5,
        }
    }

    /// 最大パケットサイズ（コントロールエンドポイント）
    pub fn default_max_packet_size(&self) -> u16 {
        match self {
            UsbSpeed::Low => 8,
            UsbSpeed::Full => 64,
            UsbSpeed::High => 64,
            UsbSpeed::Super | UsbSpeed::SuperPlus => 512,
        }
    }
}

// ============================================================================
// Type-Safe Identifiers
// ============================================================================

/// USBデバイスアドレス (型安全)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceAddress(pub u8);

impl DeviceAddress {
    pub const UNASSIGNED: Self = Self(0);
    
    pub fn is_valid(&self) -> bool {
        self.0 > 0 && self.0 <= 127
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// xHCIスロットID (型安全)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(pub u8);

impl SlotId {
    pub const INVALID: Self = Self(0);

    pub fn is_valid(&self) -> bool {
        self.0 > 0
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// エンドポイントアドレス (型安全)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointAddress(pub u8);

impl EndpointAddress {
    /// コントロールエンドポイント
    pub const CONTROL: Self = Self(0);

    /// エンドポイント番号を取得 (0-15)
    pub fn number(&self) -> u8 {
        self.0 & 0x0F
    }

    /// 方向を取得 (true = IN, false = OUT)
    pub fn is_in(&self) -> bool {
        (self.0 & 0x80) != 0
    }

    /// INエンドポイントを作成
    pub fn in_endpoint(num: u8) -> Self {
        Self(0x80 | (num & 0x0F))
    }

    /// OUTエンドポイントを作成
    pub fn out_endpoint(num: u8) -> Self {
        Self(num & 0x0F)
    }

    /// xHCI DCI (Device Context Index) に変換
    pub fn to_dci(&self) -> u8 {
        let num = self.number();
        if num == 0 {
            1 // Control endpoint
        } else if self.is_in() {
            num * 2 + 1
        } else {
            num * 2
        }
    }
}

/// ポート番号 (型安全)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortNumber(pub u8);

impl PortNumber {
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// 1-indexed ポート番号（xHCI用）
    pub fn one_indexed(&self) -> usize {
        (self.0 + 1) as usize
    }
}

// ============================================================================
// USB Transfer Types
// ============================================================================

/// USB転送タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    /// コントロール転送
    Control,
    /// バルク転送
    Bulk,
    /// インタラプト転送
    Interrupt,
    /// アイソクロナス転送
    Isochronous,
}

/// USB転送方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// ホストからデバイス
    Out,
    /// デバイスからホスト
    In,
}

/// USB転送のステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// 成功
    Success,
    /// 処理中
    Pending,
    /// STALLエラー
    Stalled,
    /// バッファエラー
    BufferError,
    /// バブルエラー
    BabbleError,
    /// USBトランザクションエラー
    TransactionError,
    /// TRBエラー
    TrbError,
    /// タイムアウト
    Timeout,
    /// ショートパケット
    ShortPacket,
    /// その他のエラー
    Error(u8),
}

// ============================================================================
// USB Setup Packet
// ============================================================================

/// USBセットアップパケット (8バイト)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SetupPacket {
    /// リクエストタイプ
    pub bm_request_type: u8,
    /// リクエスト
    pub b_request: u8,
    /// 値
    pub w_value: u16,
    /// インデックス
    pub w_index: u16,
    /// 長さ
    pub w_length: u16,
}

impl SetupPacket {
    /// GET_DESCRIPTOR リクエスト
    pub fn get_descriptor(desc_type: u8, desc_index: u8, length: u16) -> Self {
        Self {
            bm_request_type: 0x80, // Device-to-host, Standard, Device
            b_request: 0x06,       // GET_DESCRIPTOR
            w_value: ((desc_type as u16) << 8) | (desc_index as u16),
            w_index: 0,
            w_length: length,
        }
    }

    /// SET_ADDRESS リクエスト
    pub fn set_address(address: DeviceAddress) -> Self {
        Self {
            bm_request_type: 0x00, // Host-to-device, Standard, Device
            b_request: 0x05,       // SET_ADDRESS
            w_value: address.as_u8() as u16,
            w_index: 0,
            w_length: 0,
        }
    }

    /// SET_CONFIGURATION リクエスト
    pub fn set_configuration(config: u8) -> Self {
        Self {
            bm_request_type: 0x00,
            b_request: 0x09, // SET_CONFIGURATION
            w_value: config as u16,
            w_index: 0,
            w_length: 0,
        }
    }

    /// GET_STATUS リクエスト
    pub fn get_status() -> Self {
        Self {
            bm_request_type: 0x80,
            b_request: 0x00, // GET_STATUS
            w_value: 0,
            w_index: 0,
            w_length: 2,
        }
    }

    /// CLEAR_FEATURE リクエスト
    pub fn clear_feature(feature: u16) -> Self {
        Self {
            bm_request_type: 0x00,
            b_request: 0x01, // CLEAR_FEATURE
            w_value: feature,
            w_index: 0,
            w_length: 0,
        }
    }

    /// クラス固有のリクエスト
    pub fn class_request(
        direction_in: bool,
        recipient: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Self {
        let bm_request_type = 
            (if direction_in { 0x80 } else { 0x00 }) |  // Direction
            0x20 |                                       // Class
            (recipient & 0x1F);                          // Recipient
        
        Self {
            bm_request_type,
            b_request: request,
            w_value: value,
            w_index: index,
            w_length: length,
        }
    }
}

// ============================================================================
// USB Error Types
// ============================================================================

/// USBエラー
#[derive(Debug, Clone)]
pub enum UsbError {
    /// デバイスが見つからない
    DeviceNotFound,
    /// エンドポイントが見つからない
    EndpointNotFound,
    /// 転送エラー
    TransferError(TransferStatus),
    /// STALLエラー
    Stalled,
    /// タイムアウト
    Timeout,
    /// バッファサイズエラー
    BufferSize,
    /// 無効なパラメータ
    InvalidParameter,
    /// リソース不足
    NoResources,
    /// xHCIエラー
    XhciError(String),
    /// その他
    Other(String),
}

pub type UsbResult<T> = Result<T, UsbError>;

// ============================================================================
// USB Device Trait
// ============================================================================

/// USBデバイストレイト
pub trait UsbDevice: Send + Sync {
    /// デバイスアドレスを取得
    fn address(&self) -> DeviceAddress;

    /// ベンダーIDを取得
    fn vendor_id(&self) -> u16;

    /// プロダクトIDを取得
    fn product_id(&self) -> u16;

    /// デバイスクラスを取得
    fn device_class(&self) -> u8;

    /// デバイスサブクラスを取得
    fn device_subclass(&self) -> u8;

    /// デバイスプロトコルを取得
    fn device_protocol(&self) -> u8;

    /// USB速度を取得
    fn speed(&self) -> UsbSpeed;

    /// コントロール転送を実行
    fn control_transfer(
        &self,
        setup: &SetupPacket,
        data: Option<&mut [u8]>,
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>>;

    /// バルクIN転送
    fn bulk_in(
        &self,
        endpoint: EndpointAddress,
        buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>>;

    /// バルクOUT転送
    fn bulk_out(
        &self,
        endpoint: EndpointAddress,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>>;

    /// インタラプトIN転送
    fn interrupt_in(
        &self,
        endpoint: EndpointAddress,
        buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>>;

    /// インタラプトOUT転送
    fn interrupt_out(
        &self,
        endpoint: EndpointAddress,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>>;
}

// ============================================================================
// USB Class Driver Trait
// ============================================================================

/// USBクラスドライバトレイト
pub trait UsbClassDriver: Send + Sync {
    /// ドライバ名
    fn name(&self) -> &str;

    /// このデバイスをサポートするか判定
    fn supports(&self, device: &dyn UsbDevice) -> bool;

    /// デバイスを初期化
    fn probe(&self, device: Arc<dyn UsbDevice>) -> UsbResult<()>;

    /// デバイスを切断
    fn disconnect(&self, device: Arc<dyn UsbDevice>);
}

// ============================================================================
// USB Hub Port Status
// ============================================================================

/// ハブポートステータス
#[derive(Debug, Clone, Copy, Default)]
pub struct PortStatus {
    /// 現在の接続状態
    pub connected: bool,
    /// 有効状態
    pub enabled: bool,
    /// サスペンド状態
    pub suspended: bool,
    /// オーバーカレント
    pub overcurrent: bool,
    /// リセット中
    pub reset: bool,
    /// 電源供給中
    pub powered: bool,
    /// 接続変化
    pub connect_change: bool,
    /// 有効変化
    pub enable_change: bool,
    /// リセット完了
    pub reset_change: bool,
    /// ポート速度
    pub speed: Option<UsbSpeed>,
}

// ============================================================================
// USB Manager
// ============================================================================

/// USBマネージャー
pub struct UsbManager {
    /// 登録されたクラスドライバ
    class_drivers: RwLock<Vec<Arc<dyn UsbClassDriver>>>,
    /// 接続されたデバイス
    devices: RwLock<Vec<Arc<dyn UsbDevice>>>,
}

impl UsbManager {
    /// 新しいUSBマネージャーを作成
    pub const fn new() -> Self {
        Self {
            class_drivers: RwLock::new(Vec::new()),
            devices: RwLock::new(Vec::new()),
        }
    }

    /// クラスドライバを登録
    pub fn register_class_driver(&self, driver: Arc<dyn UsbClassDriver>) {
        self.class_drivers.write().push(driver);
    }

    /// デバイスを登録
    pub fn register_device(&self, device: Arc<dyn UsbDevice>) -> UsbResult<()> {
        // マッチするクラスドライバを探す
        let drivers = self.class_drivers.read();
        for driver in drivers.iter() {
            if driver.supports(device.as_ref()) {
                driver.probe(device.clone())?;
            }
        }

        self.devices.write().push(device);
        Ok(())
    }

    /// デバイスを削除
    pub fn unregister_device(&self, address: DeviceAddress) {
        let mut devices = self.devices.write();
        if let Some(pos) = devices.iter().position(|d| d.address() == address) {
            let device = devices.remove(pos);
            
            // クラスドライバに通知
            let drivers = self.class_drivers.read();
            for driver in drivers.iter() {
                if driver.supports(device.as_ref()) {
                    driver.disconnect(device.clone());
                }
            }
        }
    }

    /// 全デバイスを取得
    pub fn devices(&self) -> Vec<Arc<dyn UsbDevice>> {
        self.devices.read().clone()
    }

    /// アドレスでデバイスを検索
    pub fn find_device(&self, address: DeviceAddress) -> Option<Arc<dyn UsbDevice>> {
        self.devices.read()
            .iter()
            .find(|d| d.address() == address)
            .cloned()
    }

    /// VID/PIDでデバイスを検索
    pub fn find_device_by_vid_pid(&self, vendor_id: u16, product_id: u16) -> Option<Arc<dyn UsbDevice>> {
        self.devices.read()
            .iter()
            .find(|d| d.vendor_id() == vendor_id && d.product_id() == product_id)
            .cloned()
    }
}

// ============================================================================
// Global USB Manager
// ============================================================================

static USB_MANAGER: UsbManager = UsbManager::new();

/// グローバルUSBマネージャーを取得
pub fn usb_manager() -> &'static UsbManager {
    &USB_MANAGER
}

/// USBサブシステムを初期化
pub fn init() {
    // xHCIコントローラの初期化はPCIスキャン時に行われる
    // Note: logging handled by caller
}
