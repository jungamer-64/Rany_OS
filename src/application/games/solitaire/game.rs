// ============================================================================
// src/application/games/solitaire/game.rs - Solitaire Game Structure
// ============================================================================
//!
//! ソリティアゲームの構造体定義と基本メソッド

extern crate alloc;

use alloc::vec::Vec;
use super::types::{
    Card, Suit, Rank, GameState, DragState,
    FIELD_WIDTH, FIELD_HEIGHT,
};

// ============================================================================
// Solitaire Game - 構造体定義
// ============================================================================

/// ソリティアゲーム
pub struct Solitaire {
    /// 山札
    pub(crate) stock: Vec<Card>,
    /// 捨て札
    pub(crate) waste: Vec<Card>,
    /// タブロー（7列）
    pub(crate) tableau: [Vec<Card>; 7],
    /// 組札（4つ）
    pub(crate) foundation: [Vec<Card>; 4],
    /// ゲーム状態
    pub(crate) state: GameState,
    /// ドラッグ状態
    pub(crate) drag: Option<DragState>,
    /// 移動回数
    pub(crate) moves: u32,
    /// 乱数シード
    pub(crate) rng_seed: u64,
}

impl Solitaire {
    /// 新しいゲームを作成
    pub fn new() -> Self {
        let mut game = Self {
            stock: Vec::new(),
            waste: Vec::new(),
            tableau: Default::default(),
            foundation: Default::default(),
            state: GameState::Playing,
            drag: None,
            moves: 0,
            rng_seed: 12345,
        };
        game.deal();
        game
    }

    /// 乱数生成
    pub(crate) fn rand(&mut self) -> u64 {
        self.rng_seed = self.rng_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.rng_seed
    }

    /// カードをシャッフル
    pub(crate) fn shuffle(&mut self, cards: &mut Vec<Card>) {
        let n = cards.len();
        for i in (1..n).rev() {
            let j = (self.rand() % (i as u64 + 1)) as usize;
            cards.swap(i, j);
        }
    }

    /// カードを配る
    pub(crate) fn deal(&mut self) {
        // デッキを作成
        let mut deck = Vec::with_capacity(52);
        for suit_idx in 0..4 {
            if let Some(suit) = Suit::from_index(suit_idx) {
                for rank_idx in 1..=13 {
                    if let Some(rank) = Rank::from_index(rank_idx) {
                        deck.push(Card::new(suit, rank));
                    }
                }
            }
        }

        // シャッフル
        self.shuffle(&mut deck);

        // タブローに配る
        for i in 0..7 {
            self.tableau[i].clear();
            for j in 0..=i {
                if let Some(mut card) = deck.pop() {
                    if j == i {
                        card.face_up = true;
                    }
                    self.tableau[i].push(card);
                }
            }
        }

        // 残りは山札へ
        self.stock = deck;
        self.waste.clear();
        for i in 0..4 {
            self.foundation[i].clear();
        }

        self.state = GameState::Playing;
        self.moves = 0;
    }

    /// ゲームをリセット
    pub fn reset(&mut self) {
        self.deal();
    }

    /// ゲーム状態を取得
    pub fn state(&self) -> GameState {
        self.state
    }

    /// 移動回数を取得
    pub fn moves(&self) -> u32 {
        self.moves
    }

    /// ウィンドウの幅を取得
    pub fn window_width(&self) -> u32 {
        FIELD_WIDTH
    }

    /// ウィンドウの高さを取得
    pub fn window_height(&self) -> u32 {
        FIELD_HEIGHT
    }
}

impl Default for Solitaire {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_game() {
        let game = Solitaire::new();
        assert_eq!(game.state, GameState::Playing);
        assert_eq!(game.moves, 0);

        // タブローの確認
        for (i, pile) in game.tableau.iter().enumerate() {
            assert_eq!(pile.len(), i + 1);
            // 最後のカードのみ表向き
            for (j, card) in pile.iter().enumerate() {
                assert_eq!(card.face_up, j == i);
            }
        }
    }
}
