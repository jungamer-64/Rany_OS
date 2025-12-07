// ============================================================================
// src/application/games/solitaire/input.rs - Mouse Event Handling
// ============================================================================
//!
//! ソリティアゲームのマウスイベント処理

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use super::game::Solitaire;
use super::types::{
    Card, GameState, DragState, CardLocation,
    STOCK_Y, WASTE_X, FOUNDATION_Y,
};

// ============================================================================
// Solitaire Game - マウスイベント
// ============================================================================

impl Solitaire {
    /// マウスボタン押下
    pub fn on_mouse_down(&mut self, x: u32, y: u32) {
        if self.state == GameState::Won {
            return;
        }

        let loc = self.location_at(x as i32, y as i32);

        match loc {
            Some((CardLocation::Stock, _)) => {
                self.click_stock();
            }
            Some((CardLocation::Waste, _)) => {
                // 捨て札からドラッグ開始
                if let Some(card) = self.waste.last().cloned() {
                    self.drag = Some(DragState {
                        cards: vec![card],
                        source: CardLocation::Waste,
                        x: x as i32,
                        y: y as i32,
                        offset_x: x as i32 - WASTE_X as i32,
                        offset_y: y as i32 - STOCK_Y as i32,
                    });
                }
            }
            Some((CardLocation::Tableau(col), card_idx)) => {
                // タブローからドラッグ開始
                if card_idx < self.tableau[col].len() 
                    && self.tableau[col][card_idx].face_up 
                {
                    let cards: Vec<Card> = self.tableau[col][card_idx..].to_vec();
                    let card_y = self.tableau_card_y(col, card_idx);
                    self.drag = Some(DragState {
                        cards,
                        source: CardLocation::Tableau(col),
                        x: x as i32,
                        y: y as i32,
                        offset_x: x as i32 - self.tableau_x(col) as i32,
                        offset_y: y as i32 - card_y as i32,
                    });
                }
            }
            Some((CardLocation::Foundation(idx), _)) => {
                // 組札からドラッグ（上級者向け）
                if let Some(card) = self.foundation[idx].last().cloned() {
                    self.drag = Some(DragState {
                        cards: vec![card],
                        source: CardLocation::Foundation(idx),
                        x: x as i32,
                        y: y as i32,
                        offset_x: x as i32 - self.foundation_x(idx) as i32,
                        offset_y: y as i32 - FOUNDATION_Y as i32,
                    });
                }
            }
            None => {}
        }
    }

    /// マウス移動
    pub fn on_mouse_move(&mut self, x: u32, y: u32) {
        if let Some(ref mut drag) = self.drag {
            drag.x = x as i32;
            drag.y = y as i32;
        }
    }

    /// マウスボタン解放
    pub fn on_mouse_up(&mut self, x: u32, y: u32) {
        let drag = match self.drag.take() {
            Some(d) => d,
            None => return,
        };

        if drag.cards.is_empty() {
            return;
        }

        // ドロップ先を検出
        let target = self.location_at(x as i32, y as i32);

        let moved = match (drag.source, target) {
            (CardLocation::Waste, Some((target_loc, _))) => {
                self.move_from_waste(target_loc)
            }
            (CardLocation::Tableau(src_col), Some((target_loc, _))) => {
                let card_idx = self.tableau[src_col].len()
                    .saturating_sub(drag.cards.len());
                self.move_from_tableau(src_col, card_idx, target_loc)
            }
            (CardLocation::Foundation(idx), Some((CardLocation::Tableau(col), _))) => {
                // 組札からタブローへ
                if let Some(card) = self.foundation[idx].last().cloned() {
                    if self.can_move_to_tableau(&card, col) {
                        self.foundation[idx].pop();
                        self.tableau[col].push(card);
                        self.moves += 1;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };

        if !moved {
            // 元の場所に戻す（何もしない - カードはまだそこにある）
        }
    }

    /// ダブルクリック
    pub fn on_double_click(&mut self, x: u32, y: u32) {
        if self.state == GameState::Won {
            self.reset();
            return;
        }

        // ダブルクリックで自動的に組札へ移動
        let loc = self.location_at(x as i32, y as i32);

        match loc {
            Some((CardLocation::Waste, _)) => {
                if let Some(card) = self.waste.last().cloned() {
                    for i in 0..4 {
                        if self.can_move_to_foundation(&card, i) {
                            self.move_from_waste(CardLocation::Foundation(i));
                            break;
                        }
                    }
                }
            }
            Some((CardLocation::Tableau(col), card_idx)) => {
                if card_idx == self.tableau[col].len().saturating_sub(1) {
                    if let Some(card) = self.tableau[col].last().cloned() {
                        for i in 0..4 {
                            if self.can_move_to_foundation(&card, i) {
                                self.move_from_tableau(col, card_idx, CardLocation::Foundation(i));
                                break;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
