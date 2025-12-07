// ============================================================================
// src/application/games/solitaire/mod.rs - Module Entry Point
// ============================================================================
//!
//! # ソリティア（クロンダイク）
//!
//! ウィンドウシステムのドラッグ＆ドロップ機能のデモとして実装。
//!
//! ## 機能
//! - 52枚のカードデッキ
//! - ドラッグ＆ドロップによるカード移動
//! - クロンダイクルール（タブロー、組札、山札）
//! - 自動完了機能

mod types;
mod game;
mod logic;
mod input;
mod render;
mod drawing;

// Re-export public types and constants
pub use types::{
    // Math functions
    sin_approx,
    cos_approx,
    sqrt_approx,
    
    // Card constants
    CARD_WIDTH,
    CARD_HEIGHT,
    CARD_OVERLAP_FACE_UP,
    CARD_OVERLAP_FACE_DOWN,
    
    // Field constants
    FIELD_WIDTH,
    FIELD_HEIGHT,
    
    // Card types
    Suit,
    Rank,
    Card,
    
    // Game types
    GameState,
    DragState,
    CardLocation,
};

// Re-export game structure
pub use game::Solitaire;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify basic exports work
        let game = Solitaire::new();
        assert_eq!(game.state(), GameState::Playing);
        assert_eq!(game.moves(), 0);
        assert_eq!(game.window_width(), FIELD_WIDTH);
        assert_eq!(game.window_height(), FIELD_HEIGHT);
    }
}
