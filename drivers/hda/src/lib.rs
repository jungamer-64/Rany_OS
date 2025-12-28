// ============================================================================
// drivers/hda - Intel High Definition Audio (HDA) driver components
// ============================================================================
#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod codec;
pub mod hda;
pub mod regs;
pub mod stream;
pub mod types;

// Re-export commonly used types and helpers
pub use codec::configure_codec_output;
pub use stream::{StreamConfig, StreamError, StreamResult};
pub use types::{
    BdlEntry, CodecInfo, HdaError, HdaResult, NodeType, RirbEntry, WidgetCaps, make_corb_entry,
};
