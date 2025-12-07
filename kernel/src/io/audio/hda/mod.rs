// ============================================================================
// src/io/audio/hda/mod.rs - Intel High Definition Audio Driver
// ============================================================================
//!
//! # Intel HD Audio ドライバ
//!
//! QEMUの intel-hda デバイス用のHDAドライバ実装。
//! CORB/RIRBを使用したコーデック通信と基本的なオーディオ出力をサポート。
//!
//! ## 機能
//! - PCIデバイス検出
//! - CORB/RIRB初期化
//! - コーデック検出
//! - ビープ音生成
//!
//! ## モジュール構成
//! - `types` - エラー型、データ構造定義
//! - `controller` - HdaController の実装
//! - `codec` - コーデック検出・設定
//! - `stream` - オーディオストリーム管理
//! - `global` - グローバルインスタンスと公開API
//! - `regs` - レジスタ定義（親モジュールから）

#![allow(dead_code)]

// サブモジュール
mod codec;
mod controller;
mod global;
mod stream;
mod types;

// 親モジュールのレジスタ定義を使用
use super::regs;

// 型の再エクスポート
pub use types::{
    make_corb_entry, BdlEntry, CodecInfo, HdaError, HdaResult, NodeType, RirbEntry, WidgetCaps,
};

// コントローラの再エクスポート
pub use controller::HdaController;

// 公開API関数の再エクスポート
pub use global::{
    beep, clear_interrupt_pending, disable_irq, enable_irq, get_interrupt_count, get_irq,
    handle_interrupt, init, play_tone, test_beep, with_driver, with_driver_mut,
};

// コーデック設定関数の再エクスポート
pub use codec::configure_codec_output;
