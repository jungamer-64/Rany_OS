// ============================================================================
// src/application/games/solitaire/render.rs - Rendering
// ============================================================================
//!
//! ソリティアゲームのレンダリング

extern crate alloc;

use alloc::format;
use crate::graphics::{Color, image::Image};
use super::game::Solitaire;
use super::types::{
    GameState, CardLocation,
    CARD_WIDTH, CARD_HEIGHT, CARD_OVERLAP_FACE_UP,
    FIELD_WIDTH, FIELD_HEIGHT,
    TABLEAU_START_Y,
    FOUNDATION_Y,
    STOCK_X, STOCK_Y, WASTE_X,
    BG_COLOR, CARD_WHITE,
};

// ============================================================================
// Solitaire Game - レンダリング
// ============================================================================

impl Solitaire {
    /// 描画
    pub fn render(&self, image: &mut Image) {
        // 背景
        self.fill_rect(image, 0, 0, FIELD_WIDTH, FIELD_HEIGHT, BG_COLOR);

        // 山札
        self.render_stock(image);

        // 捨て札
        self.render_waste(image);

        // 組札
        self.render_foundations(image);

        // タブロー
        self.render_tableau(image);

        // ドラッグ中のカード
        self.render_drag(image);

        // ヘッダー（移動回数）
        self.render_header(image);

        // 勝利メッセージ
        if self.state == GameState::Won {
            self.render_win_message(image);
        }
    }

    /// 山札を描画
    pub(crate) fn render_stock(&self, image: &mut Image) {
        if self.stock.is_empty() {
            // 空のスロット（クリックで戻す）
            self.draw_empty_slot(image, STOCK_X, STOCK_Y);
            // リサイクルマーク
            self.draw_recycle_icon(image, STOCK_X, STOCK_Y);
        } else {
            // カードの裏面
            self.draw_card_back(image, STOCK_X, STOCK_Y);
        }
    }

    /// 捨て札を描画
    pub(crate) fn render_waste(&self, image: &mut Image) {
        if let Some(card) = self.waste.last() {
            let is_dragging = self.drag.as_ref()
                .map(|d| d.source == CardLocation::Waste)
                .unwrap_or(false);
            if !is_dragging {
                self.draw_card(image, WASTE_X, STOCK_Y, card);
            }
        }
    }

    /// 組札を描画
    pub(crate) fn render_foundations(&self, image: &mut Image) {
        for i in 0..4 {
            let x = self.foundation_x(i);
            let is_dragging = self.drag.as_ref()
                .map(|d| d.source == CardLocation::Foundation(i))
                .unwrap_or(false);

            if let Some(card) = self.foundation[i].last() {
                if !is_dragging {
                    self.draw_card(image, x, FOUNDATION_Y, card);
                } else if self.foundation[i].len() > 1 {
                    // ドラッグ中は下のカードを表示
                    let below = &self.foundation[i][self.foundation[i].len() - 2];
                    self.draw_card(image, x, FOUNDATION_Y, below);
                } else {
                    self.draw_empty_slot(image, x, FOUNDATION_Y);
                    self.draw_suit_icon(image, x, FOUNDATION_Y, i);
                }
            } else {
                self.draw_empty_slot(image, x, FOUNDATION_Y);
                self.draw_suit_icon(image, x, FOUNDATION_Y, i);
            }
        }
    }

    /// タブローを描画
    pub(crate) fn render_tableau(&self, image: &mut Image) {
        for col in 0..7 {
            let x = self.tableau_x(col);

            if self.tableau[col].is_empty() {
                self.draw_empty_slot(image, x, TABLEAU_START_Y);
                continue;
            }

            // ドラッグ中のカード数を取得
            let drag_count = self.drag.as_ref()
                .filter(|d| d.source == CardLocation::Tableau(col))
                .map(|d| d.cards.len())
                .unwrap_or(0);

            let visible_count = self.tableau[col].len().saturating_sub(drag_count);

            for (i, card) in self.tableau[col].iter().take(visible_count).enumerate() {
                let y = self.tableau_card_y(col, i);
                if card.face_up {
                    self.draw_card(image, x, y, card);
                } else {
                    self.draw_card_back(image, x, y);
                }
            }
        }
    }

    /// ドラッグ中のカードを描画
    pub(crate) fn render_drag(&self, image: &mut Image) {
        if let Some(ref drag) = self.drag {
            let base_x = drag.x - drag.offset_x;
            let base_y = drag.y - drag.offset_y;

            for (i, card) in drag.cards.iter().enumerate() {
                let y = base_y + (i as i32 * CARD_OVERLAP_FACE_UP as i32);
                self.draw_card(image, base_x as u32, y as u32, card);
            }
        }
    }

    /// ヘッダーを描画
    pub(crate) fn render_header(&self, image: &mut Image) {
        let moves_text = format!("Moves: {}", self.moves);
        self.draw_text(image, &moves_text, 200, 10, CARD_WHITE);
    }

    /// 勝利メッセージを描画
    pub(crate) fn render_win_message(&self, image: &mut Image) {
        let box_w = 200u32;
        let box_h = 60u32;
        let box_x = (FIELD_WIDTH - box_w) / 2;
        let box_y = (FIELD_HEIGHT - box_h) / 2;

        // 背景
        self.fill_rect(image, box_x, box_y, box_w, box_h, 
            Color { red: 0, green: 0, blue: 0, alpha: 200 });

        // 枠
        for dx in 0..box_w {
            image.set_pixel(box_x + dx, box_y, CARD_WHITE);
            image.set_pixel(box_x + dx, box_y + box_h - 1, CARD_WHITE);
        }
        for dy in 0..box_h {
            image.set_pixel(box_x, box_y + dy, CARD_WHITE);
            image.set_pixel(box_x + box_w - 1, box_y + dy, CARD_WHITE);
        }

        self.draw_text(image, "YOU WIN!", box_x + 70, box_y + 15, CARD_WHITE);
        let moves_text = format!("Moves: {}", self.moves);
        self.draw_text(image, &moves_text, box_x + 70, box_y + 35, CARD_WHITE);
    }
}
