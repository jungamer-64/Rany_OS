// ============================================================================
// src/io/audio/hda/types.rs - HDA Types and Data Structures
// ============================================================================
//!
//! HDA ドライバで使用される型定義。
//!
//! - エラー型
//! - CORB/RIRBエントリ
//! - BDLエントリ
//! - コーデック/ノード情報

use alloc::string::String;
use alloc::vec::Vec;

use super::regs::*;

// ============================================================================
// Error Types
// ============================================================================

/// HDA Driver Error
#[derive(Debug, Clone)]
pub enum HdaError {
    /// No HDA device found
    NoDevice,
    /// Device initialization failed
    InitFailed(String),
    /// Invalid BAR configuration
    InvalidBar,
    /// Controller reset failed
    ResetFailed,
    /// Codec not found
    NoCodec,
    /// Command timeout
    Timeout,
    /// Invalid response
    InvalidResponse,
    /// Memory allocation failed
    AllocFailed,
    /// Stream configuration failed
    StreamError(String),
}

pub type HdaResult<T> = Result<T, HdaError>;

// ============================================================================
// CORB Entry
// ============================================================================

/// Build a CORB command entry
/// Format: [Codec Address (4)] [Node ID (8)] [Verb (20)]
#[inline]
pub fn make_corb_entry(codec_addr: u8, node_id: u8, verb: u32) -> u32 {
    ((codec_addr as u32 & 0x0F) << 28) | ((node_id as u32) << 20) | (verb & 0xFFFFF)
}

// ============================================================================
// RIRB Entry
// ============================================================================

/// RIRB Response Entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RirbEntry {
    /// Response data
    pub response: u32,
    /// Response extended (codec address, unsolicited flag)
    pub response_ex: u32,
}

impl RirbEntry {
    /// Get codec address from response
    pub fn codec_addr(&self) -> u8 {
        (self.response_ex & 0x0F) as u8
    }

    /// Check if this is an unsolicited response
    pub fn is_unsolicited(&self) -> bool {
        (self.response_ex & 0x10) != 0
    }
}

// ============================================================================
// Buffer Descriptor List Entry
// ============================================================================

/// Buffer Descriptor List entry for audio DMA
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct BdlEntry {
    /// Buffer address (lower 32 bits)
    pub addr_lo: u32,
    /// Buffer address (upper 32 bits)
    pub addr_hi: u32,
    /// Buffer length in bytes
    pub length: u32,
    /// Interrupt on completion flag
    pub ioc: u32,
}

impl BdlEntry {
    /// Create a new BDL entry
    pub fn new(addr: u64, length: u32, ioc: bool) -> Self {
        Self {
            addr_lo: addr as u32,
            addr_hi: (addr >> 32) as u32,
            length,
            ioc: if ioc { BDL_IOC } else { 0 },
        }
    }
}

// ============================================================================
// Codec Node Information
// ============================================================================

/// Codec node type
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
            WIDGET_TYPE_AUDIO_OUTPUT => NodeType::AudioOutput,
            WIDGET_TYPE_AUDIO_INPUT => NodeType::AudioInput,
            WIDGET_TYPE_AUDIO_MIXER => NodeType::AudioMixer,
            WIDGET_TYPE_AUDIO_SELECTOR => NodeType::AudioSelector,
            WIDGET_TYPE_PIN_COMPLEX => NodeType::PinComplex,
            WIDGET_TYPE_POWER => NodeType::PowerWidget,
            WIDGET_TYPE_VOLUME_KNOB => NodeType::VolumeKnob,
            WIDGET_TYPE_BEEP_GEN => NodeType::BeepGenerator,
            WIDGET_TYPE_VENDOR => NodeType::VendorDefined,
            _ => NodeType::Unknown(v),
        }
    }
}

/// Audio widget capabilities
#[derive(Debug, Clone, Copy)]
pub struct WidgetCaps {
    /// Widget type
    pub widget_type: NodeType,
    /// Has connection list
    pub conn_list: bool,
    /// Has output amplifier
    pub out_amp: bool,
    /// Has input amplifier
    pub in_amp: bool,
    /// Supports format override
    pub format_override: bool,
    /// Stereo capability
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

/// Codec information
#[derive(Debug, Clone)]
pub struct CodecInfo {
    /// Codec address (0-14)
    pub address: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Revision ID
    pub revision: u8,
    /// Audio Function Group node ID
    pub afg_node: Option<u8>,
    /// Output converter nodes
    pub output_nodes: Vec<u8>,
    /// Input converter nodes
    pub input_nodes: Vec<u8>,
    /// Pin complex nodes
    pub pin_nodes: Vec<u8>,
    /// Beep generator node
    pub beep_node: Option<u8>,
}
