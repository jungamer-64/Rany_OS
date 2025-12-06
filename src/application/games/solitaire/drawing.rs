// ============================================================================
// src/application/games/solitaire/drawing.rs - Card Drawing & Utilities
// ============================================================================
//!
//! カード描画とユーティリティ関数

extern crate alloc;

use alloc::string::String;
use crate::graphics::{Color, image::Image};
use super::game::Solitaire;
use super::types::{
    Card, Suit,
    CARD_WIDTH, CARD_HEIGHT,
    BG_COLOR, CARD_WHITE, CARD_BACK, CARD_BORDER, EMPTY_SLOT,
    cos_approx, sin_approx,
};

// ============================================================================
// Solitaire Game - カード描画
// ============================================================================

impl Solitaire {
    /// カードを描画
    pub(crate) fn draw_card(&self, image: &mut Image, x: u32, y: u32, card: &Card) {
        // カードの背景
        self.fill_rect(image, x, y, CARD_WIDTH, CARD_HEIGHT, CARD_WHITE);

        // 枠線
        for dx in 0..CARD_WIDTH {
            image.set_pixel(x + dx, y, CARD_BORDER);
            image.set_pixel(x + dx, y + CARD_HEIGHT - 1, CARD_BORDER);
        }
        for dy in 0..CARD_HEIGHT {
            image.set_pixel(x, y + dy, CARD_BORDER);
            image.set_pixel(x + CARD_WIDTH - 1, y + dy, CARD_BORDER);
        }

        // 角を丸くする
        image.set_pixel(x, y, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y, BG_COLOR);
        image.set_pixel(x, y + CARD_HEIGHT - 1, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y + CARD_HEIGHT - 1, BG_COLOR);

        // ランクとスート
        let color = card.suit.color();
        let rank_str = card.rank.symbol();
        let suit_char = card.suit.symbol();

        // 左上にランク
        self.draw_text(image, rank_str, x + 4, y + 4, color);

        // 左上にスート
        self.draw_text(image, &String::from(suit_char), x + 4, y + 14, color);

        // 中央にスート（大きく）
        self.draw_large_suit(image, x + CARD_WIDTH / 2 - 10, y + CARD_HEIGHT / 2 - 10, card.suit);

        // 右下にランク（逆さ）
        self.draw_text(image, rank_str, x + CARD_WIDTH - 14, y + CARD_HEIGHT - 14, color);
    }

    /// カードの裏面を描画
    pub(crate) fn draw_card_back(&self, image: &mut Image, x: u32, y: u32) {
        // 青い背景
        self.fill_rect(image, x, y, CARD_WIDTH, CARD_HEIGHT, CARD_BACK);

        // 枠線
        for dx in 0..CARD_WIDTH {
            image.set_pixel(x + dx, y, CARD_BORDER);
            image.set_pixel(x + dx, y + CARD_HEIGHT - 1, CARD_BORDER);
        }
        for dy in 0..CARD_HEIGHT {
            image.set_pixel(x, y + dy, CARD_BORDER);
            image.set_pixel(x + CARD_WIDTH - 1, y + dy, CARD_BORDER);
        }

        // 角を丸くする
        image.set_pixel(x, y, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y, BG_COLOR);
        image.set_pixel(x, y + CARD_HEIGHT - 1, BG_COLOR);
        image.set_pixel(x + CARD_WIDTH - 1, y + CARD_HEIGHT - 1, BG_COLOR);

        // 模様（格子）
        let pattern_color = Color { red: 0, green: 0, blue: 140, alpha: 255 };
        for dy in (4..CARD_HEIGHT - 4).step_by(6) {
            for dx in (4..CARD_WIDTH - 4).step_by(6) {
                if (dx / 6 + dy / 6) % 2 == 0 {
                    self.fill_rect(image, x + dx, y + dy, 4, 4, pattern_color);
                }
            }
        }
    }

    /// 空のスロットを描画
    pub(crate) fn draw_empty_slot(&self, image: &mut Image, x: u32, y: u32) {
        self.fill_rect(image, x, y, CARD_WIDTH, CARD_HEIGHT, EMPTY_SLOT);

        // 枠線（点線風）
        for dx in (0..CARD_WIDTH).step_by(4) {
            image.set_pixel(x + dx, y, CARD_BORDER);
            image.set_pixel(x + dx, y + CARD_HEIGHT - 1, CARD_BORDER);
        }
        for dy in (0..CARD_HEIGHT).step_by(4) {
            image.set_pixel(x, y + dy, CARD_BORDER);
            image.set_pixel(x + CARD_WIDTH - 1, y + dy, CARD_BORDER);
        }
    }

    /// リサイクルアイコンを描画
    pub(crate) fn draw_recycle_icon(&self, image: &mut Image, x: u32, y: u32) {
        let cx = x + CARD_WIDTH / 2;
        let cy = y + CARD_HEIGHT / 2;
        let r = 15u32;
        let color = Color { red: 100, green: 150, blue: 100, alpha: 255 };

        // 簡易的な円形矢印
        for angle in 0..360 {
            let rad = (angle as f32) * 3.14159 / 180.0;
            let px = cx as i32 + (r as f32 * cos_approx(rad)) as i32;
            let py = cy as i32 + (r as f32 * sin_approx(rad)) as i32;
            if px >= 0 && py >= 0 {
                image.set_pixel(px as u32, py as u32, color);
            }
        }
    }

    /// スートアイコンを描画
    pub(crate) fn draw_suit_icon(&self, image: &mut Image, x: u32, y: u32, suit_idx: usize) {
        if let Some(suit) = Suit::from_index(suit_idx as u8) {
            let cx = x + CARD_WIDTH / 2;
            let cy = y + CARD_HEIGHT / 2;
            let color = Color { red: 60, green: 100, blue: 60, alpha: 255 };
            self.draw_text(image, &String::from(suit.symbol()), cx - 4, cy - 4, color);
        }
    }

    /// 大きなスートを描画
    pub(crate) fn draw_large_suit(&self, image: &mut Image, x: u32, y: u32, suit: Suit) {
        let color = suit.color();
        
        match suit {
            Suit::Hearts => {
                // ハート
                for dy in 0..20u32 {
                    for dx in 0..20u32 {
                        let fx = dx as f32 / 10.0 - 1.0;
                        let fy = dy as f32 / 10.0 - 1.0;
                        let fx2 = fx * fx;
                        let fy2 = fy * fy;
                        let fy3 = fy2 * fy;
                        let heart = (fx2 + fy2 - 1.0) * (fx2 + fy2 - 1.0) * (fx2 + fy2 - 1.0) - fx2 * fy3;
                        if heart < 0.0 {
                            image.set_pixel(x + dx, y + dy, color);
                        }
                    }
                }
            }
            Suit::Diamonds => {
                // ダイヤ
                for dy in 0..20u32 {
                    for dx in 0..20u32 {
                        let cx = 10i32;
                        let cy = 10i32;
                        let dist = (dx as i32 - cx).abs() + (dy as i32 - cy).abs();
                        if dist < 10 {
                            image.set_pixel(x + dx, y + dy, color);
                        }
                    }
                }
            }
            Suit::Clubs => {
                // クラブ（3つの円と茎）
                self.fill_circle(image, x + 10, y + 6, 5, color);
                self.fill_circle(image, x + 5, y + 12, 5, color);
                self.fill_circle(image, x + 15, y + 12, 5, color);
                self.fill_rect(image, x + 8, y + 14, 4, 6, color);
            }
            Suit::Spades => {
                // スペード（逆ハート+茎）
                for dy in 0..14u32 {
                    for dx in 0..20u32 {
                        let fx = dx as f32 / 10.0 - 1.0;
                        let fy = 1.0 - dy as f32 / 7.0;
                        let fx2 = fx * fx;
                        let fy2 = fy * fy;
                        let fy3 = fy2 * fy;
                        let heart = (fx2 + fy2 - 1.0) * (fx2 + fy2 - 1.0) * (fx2 + fy2 - 1.0) - fx2 * fy3;
                        if heart < 0.0 {
                            image.set_pixel(x + dx, y + dy, color);
                        }
                    }
                }
                self.fill_rect(image, x + 8, y + 12, 4, 8, color);
            }
        }
    }

    /// 円を塗りつぶす
    pub(crate) fn fill_circle(&self, image: &mut Image, cx: u32, cy: u32, r: u32, color: Color) {
        let r_sq = (r * r) as i32;
        for dy in 0..r * 2 {
            for dx in 0..r * 2 {
                let px = dx as i32 - r as i32;
                let py = dy as i32 - r as i32;
                if px * px + py * py <= r_sq {
                    let x = cx + dx - r;
                    let y = cy + dy - r;
                    if x < image.width() && y < image.height() {
                        image.set_pixel(x, y, color);
                    }
                }
            }
        }
    }

    // ========================================================================
    // 描画ユーティリティ
    // ========================================================================

    /// 矩形を塗りつぶす
    pub(crate) fn fill_rect(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32, color: Color) {
        for dy in 0..h {
            for dx in 0..w {
                if x + dx < image.width() && y + dy < image.height() {
                    image.set_pixel(x + dx, y + dy, color);
                }
            }
        }
    }

    /// 簡易テキスト描画
    pub(crate) fn draw_text(&self, image: &mut Image, text: &str, x: u32, y: u32, color: Color) {
        static FONT_4X6: [[u8; 6]; 95] = [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0], // Space
            [0x4, 0x4, 0x4, 0x0, 0x4, 0x0], // !
            [0xA, 0xA, 0x0, 0x0, 0x0, 0x0], // "
            [0xA, 0xF, 0xA, 0xF, 0xA, 0x0], // #
            [0x4, 0xE, 0xC, 0x6, 0xE, 0x4], // $
            [0x9, 0x2, 0x4, 0x8, 0x9, 0x0], // %
            [0x4, 0xA, 0x4, 0xA, 0x5, 0x0], // &
            [0x4, 0x4, 0x0, 0x0, 0x0, 0x0], // '
            [0x2, 0x4, 0x4, 0x4, 0x2, 0x0], // (
            [0x4, 0x2, 0x2, 0x2, 0x4, 0x0], // )
            [0x0, 0xA, 0x4, 0xA, 0x0, 0x0], // *
            [0x0, 0x4, 0xE, 0x4, 0x0, 0x0], // +
            [0x0, 0x0, 0x0, 0x4, 0x4, 0x8], // ,
            [0x0, 0x0, 0xE, 0x0, 0x0, 0x0], // -
            [0x0, 0x0, 0x0, 0x0, 0x4, 0x0], // .
            [0x1, 0x2, 0x4, 0x8, 0x8, 0x0], // /
            [0x6, 0x9, 0x9, 0x9, 0x6, 0x0], // 0
            [0x4, 0xC, 0x4, 0x4, 0xE, 0x0], // 1
            [0x6, 0x9, 0x2, 0x4, 0xF, 0x0], // 2
            [0xE, 0x1, 0x6, 0x1, 0xE, 0x0], // 3
            [0x2, 0x6, 0xA, 0xF, 0x2, 0x0], // 4
            [0xF, 0x8, 0xE, 0x1, 0xE, 0x0], // 5
            [0x6, 0x8, 0xE, 0x9, 0x6, 0x0], // 6
            [0xF, 0x1, 0x2, 0x4, 0x4, 0x0], // 7
            [0x6, 0x9, 0x6, 0x9, 0x6, 0x0], // 8
            [0x6, 0x9, 0x7, 0x1, 0x6, 0x0], // 9
            [0x0, 0x4, 0x0, 0x4, 0x0, 0x0], // :
            [0x0, 0x4, 0x0, 0x4, 0x4, 0x8], // ;
            [0x1, 0x2, 0x4, 0x2, 0x1, 0x0], // <
            [0x0, 0xE, 0x0, 0xE, 0x0, 0x0], // =
            [0x4, 0x2, 0x1, 0x2, 0x4, 0x0], // >
            [0x6, 0x9, 0x2, 0x0, 0x2, 0x0], // ?
            [0x6, 0x9, 0xB, 0x8, 0x6, 0x0], // @
            [0x6, 0x9, 0xF, 0x9, 0x9, 0x0], // A
            [0xE, 0x9, 0xE, 0x9, 0xE, 0x0], // B
            [0x6, 0x9, 0x8, 0x9, 0x6, 0x0], // C
            [0xE, 0x9, 0x9, 0x9, 0xE, 0x0], // D
            [0xF, 0x8, 0xE, 0x8, 0xF, 0x0], // E
            [0xF, 0x8, 0xE, 0x8, 0x8, 0x0], // F
            [0x6, 0x8, 0xB, 0x9, 0x6, 0x0], // G
            [0x9, 0x9, 0xF, 0x9, 0x9, 0x0], // H
            [0xE, 0x4, 0x4, 0x4, 0xE, 0x0], // I
            [0x7, 0x2, 0x2, 0xA, 0x4, 0x0], // J
            [0x9, 0xA, 0xC, 0xA, 0x9, 0x0], // K
            [0x8, 0x8, 0x8, 0x8, 0xF, 0x0], // L
            [0x9, 0xF, 0xF, 0x9, 0x9, 0x0], // M
            [0x9, 0xD, 0xB, 0x9, 0x9, 0x0], // N
            [0x6, 0x9, 0x9, 0x9, 0x6, 0x0], // O
            [0xE, 0x9, 0xE, 0x8, 0x8, 0x0], // P
            [0x6, 0x9, 0x9, 0xA, 0x5, 0x0], // Q
            [0xE, 0x9, 0xE, 0xA, 0x9, 0x0], // R
            [0x6, 0x8, 0x6, 0x1, 0xE, 0x0], // S
            [0xE, 0x4, 0x4, 0x4, 0x4, 0x0], // T
            [0x9, 0x9, 0x9, 0x9, 0x6, 0x0], // U
            [0x9, 0x9, 0x9, 0x6, 0x6, 0x0], // V
            [0x9, 0x9, 0xF, 0xF, 0x9, 0x0], // W
            [0x9, 0x9, 0x6, 0x9, 0x9, 0x0], // X
            [0x9, 0x9, 0x6, 0x4, 0x4, 0x0], // Y
            [0xF, 0x1, 0x6, 0x8, 0xF, 0x0], // Z
            [0x6, 0x4, 0x4, 0x4, 0x6, 0x0], // [
            [0x8, 0x8, 0x4, 0x2, 0x1, 0x0], // \
            [0x6, 0x2, 0x2, 0x2, 0x6, 0x0], // ]
            [0x4, 0xA, 0x0, 0x0, 0x0, 0x0], // ^
            [0x0, 0x0, 0x0, 0x0, 0xF, 0x0], // _
            [0x4, 0x2, 0x0, 0x0, 0x0, 0x0], // `
            [0x0, 0x6, 0xA, 0xA, 0x5, 0x0], // a
            [0x8, 0xE, 0x9, 0x9, 0xE, 0x0], // b
            [0x0, 0x6, 0x8, 0x8, 0x6, 0x0], // c
            [0x1, 0x7, 0x9, 0x9, 0x7, 0x0], // d
            [0x0, 0x6, 0xF, 0x8, 0x6, 0x0], // e
            [0x2, 0x4, 0xE, 0x4, 0x4, 0x0], // f
            [0x0, 0x7, 0x9, 0x7, 0x1, 0x6], // g
            [0x8, 0xE, 0x9, 0x9, 0x9, 0x0], // h
            [0x4, 0x0, 0x4, 0x4, 0x4, 0x0], // i
            [0x2, 0x0, 0x2, 0x2, 0xA, 0x4], // j
            [0x8, 0xA, 0xC, 0xA, 0x9, 0x0], // k
            [0x4, 0x4, 0x4, 0x4, 0x2, 0x0], // l
            [0x0, 0xA, 0xF, 0x9, 0x9, 0x0], // m
            [0x0, 0xE, 0x9, 0x9, 0x9, 0x0], // n
            [0x0, 0x6, 0x9, 0x9, 0x6, 0x0], // o
            [0x0, 0xE, 0x9, 0xE, 0x8, 0x8], // p
            [0x0, 0x7, 0x9, 0x7, 0x1, 0x1], // q
            [0x0, 0xE, 0x9, 0x8, 0x8, 0x0], // r
            [0x0, 0x6, 0xC, 0x2, 0xC, 0x0], // s
            [0x4, 0xE, 0x4, 0x4, 0x2, 0x0], // t
            [0x0, 0x9, 0x9, 0x9, 0x6, 0x0], // u
            [0x0, 0x9, 0x9, 0x6, 0x6, 0x0], // v
            [0x0, 0x9, 0x9, 0xF, 0x6, 0x0], // w
            [0x0, 0x9, 0x6, 0x6, 0x9, 0x0], // x
            [0x0, 0x9, 0x9, 0x7, 0x1, 0x6], // y
            [0x0, 0xF, 0x2, 0x4, 0xF, 0x0], // z
            [0x2, 0x4, 0x8, 0x4, 0x2, 0x0], // {
            [0x4, 0x4, 0x4, 0x4, 0x4, 0x0], // |
            [0x8, 0x4, 0x2, 0x4, 0x8, 0x0], // }
            [0x0, 0x5, 0xA, 0x0, 0x0, 0x0], // ~
        ];

        let mut cx = x;
        for ch in text.chars() {
            let code = ch as u32;
            if code >= 0x20 && code <= 0x7E {
                let glyph = &FONT_4X6[(code - 0x20) as usize];
                for (row, &bits) in glyph.iter().enumerate() {
                    for col in 0..4 {
                        if (bits >> (3 - col)) & 1 == 1 {
                            let px = cx + col;
                            let py = y + row as u32;
                            if px < image.width() && py < image.height() {
                                image.set_pixel(px, py, color);
                            }
                        }
                    }
                }
            }
            cx += 5;
        }
    }
}
