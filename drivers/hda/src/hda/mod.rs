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

// サブモジュール (controller/global remain kernel-local; core codec/types/stream moved to driver crate)
mod controller;
// mod global; // Kernel-specific

// Use driver-provided modules
pub use crate::codec;
pub use crate::types;
// mod stream; // Use crate::stream
pub use crate::regs;
pub use crate::stream;

// 型の再エクスポート
pub use types::{
    BdlEntry, CodecInfo, HdaError, HdaResult, NodeType, RirbEntry, WidgetCaps, make_corb_entry,
};

// コントローラの再エクスポート
pub use controller::HdaController;

// 公開API関数の再エクスポート
// Global APIs removed from driver crate (moved to kernel)

// コーデック設定関数の再エクスポート
pub use codec::configure_codec_output;
