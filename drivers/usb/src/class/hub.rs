// ============================================================================
// src/io/usb/class/hub.rs - USB Hub Class Driver
// ============================================================================
//!
//! # USB Hub クラスドライバ
//!
//! USBハブの管理、ポートの制御、デバイスの列挙を担当。
//!
//! ## 機能
//! - ハブの初期化と構成
//! - ポートの電源制御
//! - ポート状態の監視（ステータス変更通知）
//! - デバイスの接続/切断検出
//!
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;

use super::{ClassDriverError, ClassDriverEvent, TransferStatus, UsbClass, UsbClassDriver};
use crate::{SetupPacket, UsbDevice, descriptor::SafePackedRead};

/// フィールドの安全な読み取りマクロ
macro_rules! read_field {
    ($ptr:expr, $field:ident) => {{
        // SAFETY: We rely on the caller to ensure $ptr is valid for the struct type.
        // The addr_of! is safe, but dereferencing field_ptr requires it to be valid.
        // Since we are reading from unaligned packed struct, we use read_unaligned.
        let field_ptr = unsafe { core::ptr::addr_of!((*$ptr).$field) };
        unsafe { core::ptr::read_unaligned(field_ptr) }
    }};
}

// ============================================================================
// Hub Constants
// ============================================================================

/// Hub クラスコード
pub const HUB_CLASS: u8 = 0x09;
/// Hub サブクラス (None)
pub const HUB_SUBCLASS_NONE: u8 = 0x00;
/// Hub プロトコル: Full Speed Hub
pub const HUB_PROTOCOL_FS: u8 = 0x00;
/// Hub プロトコル: Hi-speed Hub with single TT
pub const HUB_PROTOCOL_HS_SINGLE_TT: u8 = 0x01;
/// Hub プロトコル: Hi-speed Hub with multiple TTs
pub const HUB_PROTOCOL_HS_MULTI_TT: u8 = 0x02;

/// Hub ディスクリプタタイプ
pub const DESCRIPTOR_TYPE_HUB: u8 = 0x29;

// ============================================================================
// Hub Requests
// ============================================================================

pub const HUB_REQ_GET_STATUS: u8 = 0;
pub const HUB_REQ_CLEAR_FEATURE: u8 = 1;
pub const HUB_REQ_SET_FEATURE: u8 = 3;
pub const HUB_REQ_GET_DESCRIPTOR: u8 = 6;
pub const HUB_REQ_SET_DESCRIPTOR: u8 = 7;
pub const HUB_REQ_CLEAR_TT_BUFFER: u8 = 8;
pub const HUB_REQ_RESET_TT: u8 = 9;
pub const HUB_REQ_GET_TT_STATE: u8 = 10;
pub const HUB_REQ_STOP_TT: u8 = 11;

// ============================================================================
// Hub/Port Features
// ============================================================================

/// Hub Features
pub const C_HUB_LOCAL_POWER: u16 = 0;
pub const C_HUB_OVER_CURRENT: u16 = 1;

/// Port Features
pub const PORT_CONNECTION: u16 = 0;
pub const PORT_ENABLE: u16 = 1;
pub const PORT_SUSPEND: u16 = 2;
pub const PORT_OVER_CURRENT: u16 = 3;
pub const PORT_RESET: u16 = 4;
pub const PORT_POWER: u16 = 8;
pub const PORT_LOW_SPEED: u16 = 9;
pub const C_PORT_CONNECTION: u16 = 16;
pub const C_PORT_ENABLE: u16 = 17;
pub const C_PORT_SUSPEND: u16 = 18;
pub const C_PORT_OVER_CURRENT: u16 = 19;
pub const C_PORT_RESET: u16 = 20;
pub const PORT_TEST: u16 = 21;
pub const PORT_INDICATOR: u16 = 22;

// ============================================================================
// Hub Structures
// ============================================================================

/// Hub Characteristics
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct HubCharacteristics(u16);

impl HubCharacteristics {
    /// 電源スイッチングモード
    /// 00: Global, 01: Individual, 10: None, 11: Reserved
    pub fn power_switching_mode(&self) -> u8 {
        (self.0 & 0x03) as u8
    }

    /// 複合デバイスか
    pub fn is_compound(&self) -> bool {
        (self.0 & 0x04) != 0
    }

    /// 過電流保護モード
    /// 00: Global, 01: Individual, 10: None, 11: Reserved
    pub fn over_current_protection_mode(&self) -> u8 {
        ((self.0 >> 3) & 0x03) as u8
    }

    /// TT Think Time
    pub fn tt_think_time(&self) -> u8 {
        ((self.0 >> 5) & 0x03) as u8
    }

    /// ポートインジケータ対応
    pub fn port_indicators_supported(&self) -> bool {
        (self.0 & 0x80) != 0
    }
}

/// Hub Descriptor Header (Fixed Part)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct HubDescriptorHeader {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_nbr_ports: u8,
    pub w_hub_characteristics: u16,
    pub b_pwr_on_2_pwr_good: u8,
    pub b_hub_contr_current: u8,
    // Variable length fields follow: DeviceRemovable, PortPwrCtrlMask
}

impl SafePackedRead for HubDescriptorHeader {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }
        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            b_length: read_field!(ptr, b_length),
            b_descriptor_type: read_field!(ptr, b_descriptor_type),
            b_nbr_ports: read_field!(ptr, b_nbr_ports),
            w_hub_characteristics: read_field!(ptr, w_hub_characteristics),
            b_pwr_on_2_pwr_good: read_field!(ptr, b_pwr_on_2_pwr_good),
            b_hub_contr_current: read_field!(ptr, b_hub_contr_current),
        })
    }
}

/// 完全なハブディスクリプタ情報
#[derive(Clone, Debug)]
pub struct HubDescriptor {
    pub header: HubDescriptorHeader,
    pub device_removable: Vec<u8>,
    pub port_pwr_ctrl_mask: Vec<u8>,
}

impl HubDescriptor {
    /// 特性を取得
    pub fn characteristics(&self) -> HubCharacteristics {
        HubCharacteristics(self.header.w_hub_characteristics)
    }

    /// ポート数
    pub fn num_ports(&self) -> u8 {
        self.header.b_nbr_ports
    }
}

/// Port Status & Change
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HubPortStatus {
    pub w_port_status: u16,
    pub w_port_change: u16,
}

impl SafePackedRead for HubPortStatus {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let ptr = data.as_ptr() as *const Self;
        Some(Self {
            w_port_status: read_field!(ptr, w_port_status),
            w_port_change: read_field!(ptr, w_port_change),
        })
    }
}

impl HubPortStatus {
    pub fn is_connected(&self) -> bool {
        (self.w_port_status & 0x0001) != 0
    }
    pub fn is_enabled(&self) -> bool {
        (self.w_port_status & 0x0002) != 0
    }
    pub fn is_suspended(&self) -> bool {
        (self.w_port_status & 0x0004) != 0
    }
    pub fn is_over_current(&self) -> bool {
        (self.w_port_status & 0x0008) != 0
    }
    pub fn is_reset(&self) -> bool {
        (self.w_port_status & 0x0010) != 0
    }
    pub fn is_powered(&self) -> bool {
        (self.w_port_status & 0x0100) != 0
    }
    pub fn is_low_speed(&self) -> bool {
        (self.w_port_status & 0x0200) != 0
    }
    pub fn is_high_speed(&self) -> bool {
        (self.w_port_status & 0x0400) != 0
    }

    // Change bits
    pub fn connect_change(&self) -> bool {
        (self.w_port_change & 0x0001) != 0
    }
    pub fn enable_change(&self) -> bool {
        (self.w_port_change & 0x0002) != 0
    }
}

// ============================================================================
// Hub Device Driver
// ============================================================================

/// Hub Device
pub struct HubDevice {
    /// スロットID
    slot_id: AtomicU8,
    /// ステータス変更通知用エンドポイント (Interrupt IN)
    status_endpoint: u8,
    /// 制御対象のUSBデバイス
    device: Mutex<Option<Arc<dyn UsbDevice>>>,
    /// 最新のハブディスクリプタ
    descriptor: Mutex<Option<HubDescriptor>>,
    /// 初期化フラグ
    initialized: AtomicBool,
}

impl HubDevice {
    pub fn new(status_endpoint: u8) -> Self {
        Self {
            slot_id: AtomicU8::new(0),
            status_endpoint,
            device: Mutex::new(None),
            descriptor: Mutex::new(None),
            initialized: AtomicBool::new(false),
        }
    }

    /// デバイスをアタッチ
    pub fn attach_device(&self, device: Arc<dyn UsbDevice>) {
        *self.device.lock() = Some(device);
    }

    /// ハブディスクリプタを取得
    pub async fn get_hub_descriptor(&self) -> Result<HubDescriptor, ClassDriverError> {
        let device = self
            .device
            .lock()
            .as_ref()
            .cloned()
            .ok_or(ClassDriverError::NoDevice)?;

        // まずヘッダ部分(7バイト)を取得して長さを知る
        let mut header_buf = [0u8; 7];
        let setup = SetupPacket::class_request(
            true, // IN
            0,    // Device (Hub)
            HUB_REQ_GET_DESCRIPTOR,
            (DESCRIPTOR_TYPE_HUB as u16) << 8,
            0,
            7,
        );

        let len = device
            .control_transfer(&setup, Some(&mut header_buf))
            .await
            .map_err(|_| ClassDriverError::TransferError(TransferStatus::Error(0)))?;

        if len != 7 {
            return Err(ClassDriverError::TransferError(TransferStatus::Error(0)));
        }

        let header =
            HubDescriptorHeader::from_bytes(&header_buf).ok_or(ClassDriverError::ProtocolError)?;

        // 全体を読み込む
        let total_len = header.b_length as usize;
        let mut full_buf = vec![0u8; total_len];
        let setup_full = SetupPacket::class_request(
            true, // IN
            0,    // Device (Hub)
            HUB_REQ_GET_DESCRIPTOR,
            (DESCRIPTOR_TYPE_HUB as u16) << 8,
            0,
            total_len as u16,
        );

        let len_full = device
            .control_transfer(&setup_full, Some(&mut full_buf))
            .await
            .map_err(|_| ClassDriverError::TransferError(TransferStatus::Error(0)))?;

        if len_full != total_len {
            return Err(ClassDriverError::TransferError(TransferStatus::Error(0)));
        }

        // Parse variable fields
        // DeviceRemovable: requires enough bits for bNbrPorts
        let num_ports = header.b_nbr_ports as usize;
        let param_bytes = (num_ports + 1 + 7) / 8;

        if 7 + param_bytes * 2 > total_len {
            return Err(ClassDriverError::ProtocolError);
        }

        let device_removable = full_buf[7..7 + param_bytes].to_vec();
        let port_pwr_ctrl_mask = full_buf[7 + param_bytes..7 + param_bytes * 2].to_vec();

        let descriptor = HubDescriptor {
            header,
            device_removable,
            port_pwr_ctrl_mask,
        };

        *self.descriptor.lock() = Some(descriptor.clone());

        Ok(descriptor)
    }

    /// ポートステータスを取得
    pub async fn get_port_status(&self, port: u8) -> Result<HubPortStatus, ClassDriverError> {
        let device = self
            .device
            .lock()
            .as_ref()
            .cloned()
            .ok_or(ClassDriverError::NoDevice)?;

        let mut buf = [0u8; 4];
        let setup = SetupPacket::class_request(
            true, // IN
            3,    // Other (Port)
            HUB_REQ_GET_STATUS,
            0,
            port as u16,
            4,
        );

        let len = device
            .control_transfer(&setup, Some(&mut buf))
            .await
            .map_err(|_| ClassDriverError::TransferError(TransferStatus::Error(0)))?;

        if len != 4 {
            return Err(ClassDriverError::TransferError(TransferStatus::Error(0)));
        }

        HubPortStatus::from_bytes(&buf).ok_or(ClassDriverError::ProtocolError)
    }

    /// ポート機能を設定
    pub async fn set_port_feature(&self, port: u8, feature: u16) -> Result<(), ClassDriverError> {
        let device = self
            .device
            .lock()
            .as_ref()
            .cloned()
            .ok_or(ClassDriverError::NoDevice)?;

        let setup = SetupPacket::class_request(
            false, // OUT
            3,     // Other (Port)
            HUB_REQ_SET_FEATURE,
            feature,
            port as u16,
            0,
        );

        device
            .control_transfer(&setup, None)
            .await
            .map_err(|_| ClassDriverError::TransferError(TransferStatus::Error(0)))?;

        Ok(())
    }

    /// ポート機能をクリア
    pub async fn clear_port_feature(&self, port: u8, feature: u16) -> Result<(), ClassDriverError> {
        let device = self
            .device
            .lock()
            .as_ref()
            .cloned()
            .ok_or(ClassDriverError::NoDevice)?;

        let setup = SetupPacket::class_request(
            false, // OUT
            3,     // Other (Port)
            HUB_REQ_CLEAR_FEATURE,
            feature,
            port as u16,
            0,
        );

        device
            .control_transfer(&setup, None)
            .await
            .map_err(|_| ClassDriverError::TransferError(TransferStatus::Error(0)))?;

        Ok(())
    }

    /// ポート電源を投入
    pub async fn power_on_port(&self, port: u8) -> Result<(), ClassDriverError> {
        self.set_port_feature(port, PORT_POWER).await
    }
}

impl UsbClassDriver for HubDevice {
    fn name(&self) -> &'static str {
        "USB Hub"
    }

    fn class_code(&self) -> UsbClass {
        UsbClass::Hub
    }

    fn probe(&self, class: u8, subclass: u8, _protocol: u8) -> bool {
        class == HUB_CLASS && subclass == HUB_SUBCLASS_NONE
    }

    fn init(&mut self, slot_id: u8) -> Result<(), ClassDriverError> {
        self.slot_id.store(slot_id, Ordering::SeqCst);

        // TODO:
        // 1. Get Hub Descriptor to find number of ports
        // 2. Power on all ports
        // 3. Start interrupt transfer for status change notification

        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn release(&mut self) -> Result<(), ClassDriverError> {
        self.initialized.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn poll(&mut self) -> Result<(), ClassDriverError> {
        Ok(())
    }

    fn on_event(&mut self, event: ClassDriverEvent) {
        if let ClassDriverEvent::TransferComplete {
            endpoint, status, ..
        } = event
        {
            if endpoint == self.status_endpoint && status == TransferStatus::Success {
                // TODO: Handle status change bitmap
                // Bitmap indicates which port has a status change
            }
        }
    }
}
