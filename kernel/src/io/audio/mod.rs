// ============================================================================
// src/io/audio/mod.rs - Audio Subsystem Module
// ============================================================================
//!
//! # オーディオサブシステム
//!
//! Intel HD Audioドライバを含むオーディオ機能を提供。
//!
//! ## サポートデバイス
//! - Intel HD Audio (HDA) - QEMU intel-hda 互換
//!
//! ## モジュール
//! - `hda`: Intel HD Audio ドライバ
//! - `mixer`: ソフトウェアオーディオミキサー
//! - `regs`: HDA レジスタ定義

pub mod hda;
pub mod mixer;
pub mod regs;

// Re-export main types
pub use hda::{
    BdlEntry, CodecInfo, HdaController, HdaError, HdaResult, NodeType, RirbEntry, WidgetCaps,
};
pub use mixer::{
    BitDepth, ChannelConfig, Mixer, MixerConfig, MixerError, MixerResult,
};

// Re-export functions
pub use hda::{beep, init, play_tone, test_beep, with_driver, with_driver_mut};
pub use hda::{
    handle_interrupt as hda_handle_interrupt,
    get_irq as hda_get_irq,
    enable_irq as hda_enable_irq,
    disable_irq as hda_disable_irq,
    get_interrupt_count as hda_get_interrupt_count,
    clear_interrupt_pending as hda_clear_interrupt_pending,
};
pub use mixer::{
    add_channel as mixer_add_channel,
    init as mixer_init,
    mix_output_i16,
    submit_i16 as mixer_submit_i16,
    with_mixer,
    with_mixer_mut,
};
