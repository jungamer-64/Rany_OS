// ============================================================================
// drivers/usb/src/lib.rs - USB Subsystem
// ============================================================================
//!
//! # USBサブシステム
//!
//! USB (Universal Serial Bus) デバイスのサポート。
//!
//! ## Core Modules (kernel-independent)
//! - Core types: UsbSpeed, DeviceAddress, EndpointAddress, TransferType
//! - SetupPacket, UsbError, PortStatus
//! - Descriptor parsing
//!
//! ## Kernel-Dependent (excluded)
//! - device, class, xhci modules (require kernel async runtime)

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;

// ============================================================================
// USB Constants
// ============================================================================

/// USB 速度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    Low,
    Full,
    High,
    Super,
    SuperPlus,
}

impl UsbSpeed {
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

    pub fn default_max_packet_size(&self) -> u16 {
        match self {
            UsbSpeed::Low => 8,
            UsbSpeed::Full => 64,
            UsbSpeed::High => 64,
            UsbSpeed::Super | UsbSpeed::SuperPlus => 512,
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
}

// ============================================================================
// Type-Safe Identifiers
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceAddress(pub u8);

impl DeviceAddress {
    pub const UNASSIGNED: Self = Self(0);
    pub fn is_valid(&self) -> bool { self.0 > 0 && self.0 <= 127 }
    pub fn as_u8(&self) -> u8 { self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(pub u8);
impl SlotId {
    pub const INVALID: Self = Self(0);
    pub fn is_valid(&self) -> bool { self.0 > 0 }
    pub fn as_u8(&self) -> u8 { self.0 }
    pub fn as_usize(&self) -> usize { self.0 as usize }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointAddress(pub u8);

impl EndpointAddress {
    pub const CONTROL: Self = Self(0);
    pub fn number(&self) -> u8 { self.0 & 0x0F }
    pub fn is_in(&self) -> bool { (self.0 & 0x80) != 0 }
    pub fn in_endpoint(num: u8) -> Self { Self(0x80 | (num & 0x0F)) }
    pub fn out_endpoint(num: u8) -> Self { Self(num & 0x0F) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortNumber(pub u8);
impl PortNumber {
    pub fn as_u8(&self) -> u8 { self.0 }
    pub fn as_usize(&self) -> usize { self.0 as usize }
    pub fn one_indexed(&self) -> usize { (self.0 + 1) as usize }
}

// ============================================================================
// USB Transfer Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    Control,
    Bulk,
    Interrupt,
    Isochronous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Out,
    In,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Success,
    Pending,
    Stalled,
    BufferError,
    BabbleError,
    TransactionError,
    TrbError,
    Timeout,
    ShortPacket,
    Error(u8),
}

// ============================================================================
// USB Setup Packet
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SetupPacket {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

impl SetupPacket {
    pub fn get_descriptor(desc_type: u8, desc_index: u8, length: u16) -> Self {
        Self {
            bm_request_type: 0x80,
            b_request: 0x06,
            w_value: ((desc_type as u16) << 8) | (desc_index as u16),
            w_index: 0,
            w_length: length,
        }
    }

    pub fn set_address(address: DeviceAddress) -> Self {
        Self {
            bm_request_type: 0x00,
            b_request: 0x05,
            w_value: address.as_u8() as u16,
            w_index: 0,
            w_length: 0,
        }
    }

    pub fn set_configuration(config: u8) -> Self {
        Self {
            bm_request_type: 0x00,
            b_request: 0x09,
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
        let bm_request_type = (if direction_in { 0x80 } else { 0x00 }) |  // Direction
            0x20 |                                       // Class
            (recipient & 0x1F); // Recipient

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

#[derive(Debug, Clone)]
pub enum UsbError {
    DeviceNotFound,
    EndpointNotFound,
    TransferError(TransferStatus),
    Stalled,
    Timeout,
    BufferSize,
    InvalidParameter,
    NoResources,
    XhciError(String),
    Other(String),
}

pub type UsbResult<T> = Result<T, UsbError>;

// ============================================================================
// Port Status
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
pub struct PortStatus {
    pub connected: bool,
    pub enabled: bool,
    pub suspended: bool,
    pub overcurrent: bool,
    pub reset: bool,
    pub powered: bool,
    pub connect_change: bool,
    pub enable_change: bool,
    pub reset_change: bool,
    pub speed: Option<UsbSpeed>,
}

// Include descriptor module
pub mod descriptor;

// Re-export descriptor types
pub use descriptor::{
    DescriptorType, SafePackedRead,
    DeviceDescriptor, ConfigurationDescriptor, InterfaceDescriptor, EndpointDescriptor,
    BosDescriptor, SsEndpointCompanionDescriptor, StringDescriptorHeader,
    ParsedConfiguration, ParsedInterface,
    parse_string_descriptor, parse_configuration,
    class_code,
};
