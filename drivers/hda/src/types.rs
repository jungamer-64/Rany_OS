// ============================================================================
// drivers/hda/src/types.rs - HDA types and errors
// ============================================================================

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// Error Types
#[derive(Debug, Clone)]
pub enum HdaError {
    NoDevice,
    InitFailed(String),
    InvalidBar,
    ResetFailed,
    NoCodec,
    Timeout,
    InvalidResponse,
    AllocFailed,
    StreamError(String),
}

pub type HdaResult<T> = Result<T, HdaError>;

#[inline]
pub fn make_corb_entry(codec_addr: u8, node_id: u8, verb: u32) -> u32 {
    ((codec_addr as u32 & 0x0F) << 28) | ((node_id as u32) << 20) | (verb & 0xFFFFF)
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RirbEntry {
    pub response: u32,
    pub response_ex: u32,
}

impl RirbEntry {
    pub fn codec_addr(&self) -> u8 {
        (self.response_ex & 0x0F) as u8
    }

    pub fn is_unsolicited(&self) -> bool {
        (self.response_ex & 0x10) != 0
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct BdlEntry {
    pub addr_lo: u32,
    pub addr_hi: u32,
    pub length: u32,
    pub ioc: u32,
}

impl BdlEntry {
    pub fn new(addr: u64, length: u32, ioc: bool) -> Self {
        Self {
            addr_lo: addr as u32,
            addr_hi: (addr >> 32) as u32,
            length,
            ioc: if ioc { 1 } else { 0 },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Root,
    AudioFunctionGroup,
    AudioOutput,
    AudioInput,
    AudioMixer,
    AudioSelector,
    PinComplex,
    PowerWidget,
    VolumeKnob,
    BeepGenerator,
    VendorDefined,
    Unknown(u8),
}

impl From<u8> for NodeType {
    fn from(v: u8) -> Self {
        match v {
            4 => NodeType::AudioOutput,
            5 => NodeType::AudioInput,
            6 => NodeType::AudioMixer,
            7 => NodeType::AudioSelector,
            8 => NodeType::PinComplex,
            2 => NodeType::PowerWidget,
            3 => NodeType::VolumeKnob,
            9 => NodeType::BeepGenerator,
            10 => NodeType::VendorDefined,
            _ => NodeType::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WidgetCaps {
    pub widget_type: NodeType,
    pub conn_list: bool,
    pub out_amp: bool,
    pub in_amp: bool,
    pub format_override: bool,
    pub stereo: bool,
}

impl From<u32> for WidgetCaps {
    fn from(caps: u32) -> Self {
        let widget_type = NodeType::from(((caps >> 20) & 0x0F) as u8);
        Self {
            widget_type,
            conn_list: (caps & (1 << 8)) != 0,
            out_amp: (caps & (1 << 2)) != 0,
            in_amp: (caps & (1 << 1)) != 0,
            format_override: (caps & (1 << 4)) != 0,
            stereo: (caps & (1 << 0)) != 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodecInfo {
    pub address: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub afg_node: Option<u8>,
    pub output_nodes: Vec<u8>,
    pub input_nodes: Vec<u8>,
    pub pin_nodes: Vec<u8>,
    pub beep_node: Option<u8>,
}

impl fmt::Display for HdaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HDA error: {:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_corb_entry() {
        let entry = make_corb_entry(3, 5, 0x12345);
        assert_eq!(entry, ((3u32 & 0x0F) << 28) | ((5u32) << 20) | (0x12345 & 0xFFFFF));
    }

    #[test]
    fn test_rirb_entry_fields() {
        let e = RirbEntry { response: 0x11223344, response_ex: 0x0000000F };
        assert_eq!(e.codec_addr(), 0x0F);
        assert_eq!(e.is_unsolicited(), false);

        let e2 = RirbEntry { response: 0, response_ex: 0x10 };
        assert!(e2.is_unsolicited());
    }

    #[test]
    fn test_bdl_entry_new() {
        let be = BdlEntry::new(0x12345678_9ABCDEF0, 0x1000, true);
        assert_eq!(be.addr_lo, 0x9ABCDEF0u32);
        assert_eq!(be.addr_hi, 0x12345678u32);
        assert_eq!(be.length, 0x1000);
        assert_eq!(be.ioc, 1);
    }
}

