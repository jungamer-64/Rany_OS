// ============================================================================
// src/application/games/mod.rs - Demo Games
// ============================================================================
//!
//! # OS Demo Games
//!
//! このモジュールはOSの機能デモとして3つのゲームを提供します：
//!
//! - **マインスイーパー**: 再帰的な探索アルゴリズムとGUIイベント処理のテスト
//! - **ブロック崩し**: 物理演算と描画パフォーマンスのベンチマーク
//! - **ソリティア**: ドラッグ＆ドロップ機能のデモンストレーション

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod minesweeper;
pub mod breakout;
pub mod solitaire;

pub use minesweeper::Minesweeper;
pub use breakout::Breakout;
pub use solitaire::Solitaire;
