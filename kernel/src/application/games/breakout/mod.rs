// ============================================================================
// src/application/games/breakout/mod.rs - Breakout Game Module
// ============================================================================
//!
//! # ブロック崩し
//!
//! 物理演算と描画パフォーマンスのベンチマークとして実装

mod types;
mod game;
mod logic;
mod input;
mod render;

// Re-export public items
pub use types::{
    GameState, Ball, Paddle, Block, PowerUp, PowerUpType,
    FIELD_WIDTH, FIELD_HEIGHT,
    sin_approx, cos_approx, sqrt_approx,
};
pub use game::Breakout;
