// ============================================================================
// drivers/hda - Intel High Definition Audio (HDA) driver components
// ============================================================================
#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod codec;
pub mod stream;
pub mod types;
pub mod regs;

// Re-export commonly used types and helpers
pub use types::{BdlEntry, CodecInfo, HdaError, HdaResult, NodeType, RirbEntry, WidgetCaps, make_corb_entry};
pub use codec::configure_codec_output;
pub use stream::{StreamConfig, StreamError, StreamResult};
