// ============================================================================
// src/application/games/solitaire/logic.rs - Game Logic
// ============================================================================
//!
//! ソリティアゲームのロジック（移動判定、勝利判定、座標計算）

use super::game::Solitaire;
use super::types::{
    Card, Suit, Rank, GameState, CardLocation,
    CARD_WIDTH, CARD_HEIGHT, CARD_OVERLAP_FACE_UP, CARD_OVERLAP_FACE_DOWN,
    TABLEAU_START_X, TABLEAU_START_Y, TABLEAU_GAP,
    FOUNDATION_START_X, FOUNDATION_Y,
    STOCK_X, STOCK_Y, WASTE_X,
};

// ============================================================================
// Solitaire Game - ゲームロジック
// ============================================================================

impl Solitaire {
    // ========================================================================
    // カード移動ロジック
    // ========================================================================

    /// 山札をクリック
    pub(crate) fn click_stock(&mut self) {
        if self.stock.is_empty() {
            // 捨て札を山札に戻す
            while let Some(mut card) = self.waste.pop() {
                card.face_up = false;
                self.stock.push(card);
            }
        } else {
            // 山札から捨て札へ
            if let Some(mut card) = self.stock.pop() {
                card.face_up = true;
                self.waste.push(card);
            }
        }
    }

    /// タブローの一番上のカードを表にする
    pub(crate) fn flip_top_tableau(&mut self, col: usize) {
        if let Some(card) = self.tableau[col].last_mut() {
            if !card.face_up {
                card.face_up = true;
            }
        }
    }

    /// カードをタブローに移動できるか
    pub(crate) fn can_move_to_tableau(&self, card: &Card, col: usize) -> bool {
        if let Some(top) = self.tableau[col].last() {
            card.can_place_on_tableau(top)
        } else {
            // 空のタブローにはKingのみ
            card.rank == Rank::King
        }
    }

    /// カードを組札に移動できるか
    pub(crate) fn can_move_to_foundation(&self, card: &Card, foundation_idx: usize) -> bool {
        let suit = match Suit::from_index(foundation_idx as u8) {
            Some(s) => s,
            None => return false,
        };
        let top = self.foundation[foundation_idx].last();
        card.can_place_on_foundation(top, suit)
    }

    /// 捨て札からカードを移動
    pub(crate) fn move_from_waste(&mut self, target: CardLocation) -> bool {
        let card = match self.waste.last() {
            Some(c) => *c,
            None => return false,
        };

        match target {
            CardLocation::Tableau(col) => {
                if self.can_move_to_tableau(&card, col) {
                    self.waste.pop();
                    self.tableau[col].push(card);
                    self.moves += 1;
                    return true;
                }
            }
            CardLocation::Foundation(idx) => {
                if self.can_move_to_foundation(&card, idx) {
                    self.waste.pop();
                    self.foundation[idx].push(card);
                    self.moves += 1;
                    self.check_win();
                    return true;
                }
            }
            _ => {}
        }
        false
    }

    /// タブローからカードを移動
    pub(crate) fn move_from_tableau(&mut self, src_col: usize, card_idx: usize, target: CardLocation) -> bool {
        if card_idx >= self.tableau[src_col].len() {
            return false;
        }

        // 移動するカードを取得
        let cards: alloc::vec::Vec<Card> = self.tableau[src_col][card_idx..].to_vec();
        if cards.is_empty() {
            return false;
        }

        let first_card = cards[0];

        match target {
            CardLocation::Tableau(dst_col) => {
                if src_col == dst_col {
                    return false;
                }
                if self.can_move_to_tableau(&first_card, dst_col) {
                    // カードを移動
                    self.tableau[src_col].truncate(card_idx);
                    self.tableau[dst_col].extend(cards);
                    self.flip_top_tableau(src_col);
                    self.moves += 1;
                    return true;
                }
            }
            CardLocation::Foundation(idx) => {
                // 組札には1枚のみ移動可能
                if cards.len() == 1 && self.can_move_to_foundation(&first_card, idx) {
                    self.tableau[src_col].pop();
                    self.foundation[idx].push(first_card);
                    self.flip_top_tableau(src_col);
                    self.moves += 1;
                    self.check_win();
                    return true;
                }
            }
            _ => {}
        }
        false
    }

    /// 勝利判定
    pub(crate) fn check_win(&mut self) {
        let total: usize = self.foundation.iter().map(|f| f.len()).sum();
        if total == 52 {
            self.state = GameState::Won;
        }
    }

    /// 自動で組札に移動できるカードを移動
    pub fn auto_move_to_foundation(&mut self) -> bool {
        // 捨て札から
        if let Some(card) = self.waste.last() {
            for i in 0..4 {
                if self.can_move_to_foundation(card, i) {
                    return self.move_from_waste(CardLocation::Foundation(i));
                }
            }
        }

        // タブローから
        for col in 0..7 {
            if let Some(card) = self.tableau[col].last() {
                if card.face_up {
                    for i in 0..4 {
                        if self.can_move_to_foundation(card, i) {
                            let idx = self.tableau[col].len() - 1;
                            return self.move_from_tableau(col, idx, CardLocation::Foundation(i));
                        }
                    }
                }
            }
        }

        false
    }

    // ========================================================================
    // 座標計算
    // ========================================================================

    /// タブロー列のX座標
    pub(crate) fn tableau_x(&self, col: usize) -> u32 {
        TABLEAU_START_X + col as u32 * (CARD_WIDTH + TABLEAU_GAP)
    }

    /// タブロー内のカードのY座標
    pub(crate) fn tableau_card_y(&self, col: usize, card_idx: usize) -> u32 {
        let mut y = TABLEAU_START_Y;
        for i in 0..card_idx {
            if i < self.tableau[col].len() {
                if self.tableau[col][i].face_up {
                    y += CARD_OVERLAP_FACE_UP;
                } else {
                    y += CARD_OVERLAP_FACE_DOWN;
                }
            }
        }
        y
    }

    /// 組札のX座標
    pub(crate) fn foundation_x(&self, idx: usize) -> u32 {
        FOUNDATION_START_X + idx as u32 * (CARD_WIDTH + TABLEAU_GAP)
    }

    /// 座標からカードの場所を取得
    pub(crate) fn location_at(&self, x: i32, y: i32) -> Option<(CardLocation, usize)> {
        // 山札
        if x >= STOCK_X as i32
            && x < (STOCK_X + CARD_WIDTH) as i32
            && y >= STOCK_Y as i32
            && y < (STOCK_Y + CARD_HEIGHT) as i32
        {
            return Some((CardLocation::Stock, 0));
        }

        // 捨て札
        if x >= WASTE_X as i32
            && x < (WASTE_X + CARD_WIDTH) as i32
            && y >= STOCK_Y as i32
            && y < (STOCK_Y + CARD_HEIGHT) as i32
        {
            if !self.waste.is_empty() {
                return Some((CardLocation::Waste, self.waste.len() - 1));
            }
        }

        // 組札
        for i in 0..4 {
            let fx = self.foundation_x(i) as i32;
            if x >= fx
                && x < fx + CARD_WIDTH as i32
                && y >= FOUNDATION_Y as i32
                && y < (FOUNDATION_Y + CARD_HEIGHT) as i32
            {
                return Some((CardLocation::Foundation(i), 
                    self.foundation[i].len().saturating_sub(1)));
            }
        }

        // タブロー
        for col in 0..7 {
            let tx = self.tableau_x(col) as i32;
            if x >= tx && x < tx + CARD_WIDTH as i32 {
                // Y座標からカードを特定（下から上へ）
                for card_idx in (0..self.tableau[col].len()).rev() {
                    let cy = self.tableau_card_y(col, card_idx) as i32;
                    let ch = if card_idx == self.tableau[col].len() - 1 {
                        CARD_HEIGHT
                    } else if self.tableau[col][card_idx].face_up {
                        CARD_OVERLAP_FACE_UP
                    } else {
                        CARD_OVERLAP_FACE_DOWN
                    };

                    if y >= cy && y < cy + ch as i32 {
                        return Some((CardLocation::Tableau(col), card_idx));
                    }
                }
                // 空のタブロー
                if self.tableau[col].is_empty()
                    && y >= TABLEAU_START_Y as i32
                    && y < (TABLEAU_START_Y + CARD_HEIGHT) as i32
                {
                    return Some((CardLocation::Tableau(col), 0));
                }
            }
        }

        None
    }
}
