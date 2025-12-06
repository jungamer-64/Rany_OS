// ============================================================================
// src/application/games/breakout/render.rs - Rendering
// ============================================================================
//!
//! ブロック崩しゲームの描画処理

extern crate alloc;

use alloc::format;
use alloc::string::String;

use crate::graphics::{Color, image::Image};

use super::types::*;
use super::game::Breakout;

// ============================================================================
// Rendering
// ============================================================================

impl Breakout {
    /// 描画
    pub fn render(&self, image: &mut Image) {
        // 背景
        self.fill_rect(image, 0, 0, FIELD_WIDTH, FIELD_HEIGHT, BG_COLOR);

        // ヘッダー
        self.render_header(image);

        // 壁
        self.fill_rect(image, 0, HEADER_HEIGHT, 4, FIELD_HEIGHT - HEADER_HEIGHT, WALL_COLOR);
        self.fill_rect(image, FIELD_WIDTH - 4, HEADER_HEIGHT, 4, FIELD_HEIGHT - HEADER_HEIGHT, WALL_COLOR);
        self.fill_rect(image, 0, HEADER_HEIGHT, FIELD_WIDTH, 4, WALL_COLOR);

        // ブロック
        for block in &self.blocks {
            if block.health > 0 {
                self.render_block(image, block);
            }
        }

        // パワーアップ
        for powerup in &self.powerups {
            self.render_powerup(image, powerup);
        }

        // パドル
        self.render_paddle(image);

        // ボール
        for ball in &self.balls {
            if ball.active || self.state == GameState::Ready {
                self.render_ball(image, ball);
            }
        }

        // ゲームオーバー/クリア表示
        if self.state == GameState::GameOver {
            self.render_message(image, "GAME OVER", "Click to restart");
        } else if self.state == GameState::Cleared {
            self.render_message(image, "LEVEL CLEAR!", "Click to continue");
        } else if self.state == GameState::Paused {
            self.render_message(image, "PAUSED", "Press P to continue");
        } else if self.state == GameState::Ready {
            self.draw_text(image, "Click or Space to start", 
                FIELD_WIDTH / 2 - 90, FIELD_HEIGHT / 2, TEXT_COLOR);
        }
    }

    /// ヘッダーを描画
    fn render_header(&self, image: &mut Image) {
        self.fill_rect(image, 0, 0, FIELD_WIDTH, HEADER_HEIGHT, WALL_COLOR);

        // スコア
        let score_text = format!("Score: {}", self.score);
        self.draw_text(image, &score_text, 10, 8, TEXT_COLOR);

        // レベル
        let level_text = format!("Level: {}", self.level);
        self.draw_text(image, &level_text, FIELD_WIDTH / 2 - 30, 8, TEXT_COLOR);

        // ライフ
        let lives_text = format!("Lives: {}", self.lives);
        self.draw_text(image, &lives_text, FIELD_WIDTH - 80, 8, TEXT_COLOR);
    }

    /// ブロックを描画
    fn render_block(&self, image: &mut Image, block: &Block) {
        self.fill_rect(image, block.x, block.y, block.width, block.height, block.color);

        // ハイライト
        let highlight = Color {
            red: (block.color.red as u16 + 40).min(255) as u8,
            green: (block.color.green as u16 + 40).min(255) as u8,
            blue: (block.color.blue as u16 + 40).min(255) as u8,
            alpha: 255,
        };
        for dx in 0..block.width {
            image.set_pixel(block.x + dx, block.y, highlight);
        }
        for dy in 0..block.height {
            image.set_pixel(block.x, block.y + dy, highlight);
        }

        // 影
        let shadow = Color {
            red: block.color.red.saturating_sub(40),
            green: block.color.green.saturating_sub(40),
            blue: block.color.blue.saturating_sub(40),
            alpha: 255,
        };
        for dx in 0..block.width {
            image.set_pixel(block.x + dx, block.y + block.height - 1, shadow);
        }
        for dy in 0..block.height {
            image.set_pixel(block.x + block.width - 1, block.y + dy, shadow);
        }
    }

    /// パドルを描画
    fn render_paddle(&self, image: &mut Image) {
        let x = self.paddle.x as u32;
        let y = self.paddle.y as u32;
        let w = self.paddle.width;
        let h = self.paddle.height;

        self.fill_rect(image, x, y, w, h, PADDLE_COLOR);

        // ハイライト
        let highlight = Color { red: 240, green: 240, blue: 240, alpha: 255 };
        for dx in 0..w {
            image.set_pixel(x + dx, y, highlight);
        }

        // 影
        let shadow = Color { red: 128, green: 128, blue: 128, alpha: 255 };
        for dx in 0..w {
            image.set_pixel(x + dx, y + h - 1, shadow);
        }
    }

    /// ボールを描画
    fn render_ball(&self, image: &mut Image, ball: &Ball) {
        let cx = ball.x as i32;
        let cy = ball.y as i32;
        let r = ball.radius as i32;

        // 円形描画（塗りつぶし）
        for dy in -r..=r {
            for dx in -r..=r {
                if dx * dx + dy * dy <= r * r {
                    let px = (cx + dx) as u32;
                    let py = (cy + dy) as u32;
                    if px < image.width() && py < image.height() {
                        image.set_pixel(px, py, BALL_COLOR);
                    }
                }
            }
        }
    }

    /// パワーアップを描画
    fn render_powerup(&self, image: &mut Image, powerup: &PowerUp) {
        let x = powerup.x as u32;
        let y = powerup.y as u32;
        let color = powerup.color();

        // 小さな四角形
        for dy in 0..12u32 {
            for dx in 0..12u32 {
                if x.saturating_sub(6) + dx < image.width() && y.saturating_sub(6) + dy < image.height() {
                    image.set_pixel(x.saturating_sub(6) + dx, y.saturating_sub(6) + dy, color);
                }
            }
        }
    }

    /// メッセージを描画
    fn render_message(&self, image: &mut Image, title: &str, subtitle: &str) {
        let box_width = 200u32;
        let box_height = 60u32;
        let box_x = (FIELD_WIDTH - box_width) / 2;
        let box_y = (FIELD_HEIGHT - box_height) / 2;

        // 半透明の背景
        let bg = Color { red: 0, green: 0, blue: 0, alpha: 200 };
        self.fill_rect(image, box_x, box_y, box_width, box_height, bg);

        // 枠線
        let border = Color { red: 255, green: 255, blue: 255, alpha: 255 };
        for dx in 0..box_width {
            image.set_pixel(box_x + dx, box_y, border);
            image.set_pixel(box_x + dx, box_y + box_height - 1, border);
        }
        for dy in 0..box_height {
            image.set_pixel(box_x, box_y + dy, border);
            image.set_pixel(box_x + box_width - 1, box_y + dy, border);
        }

        // テキスト
        self.draw_text(image, title, box_x + 10, box_y + 15, TEXT_COLOR);
        self.draw_text(image, subtitle, box_x + 10, box_y + 35, TEXT_COLOR);
    }

    // ========================================================================
    // 描画ユーティリティ
    // ========================================================================

    /// 矩形を塗りつぶす
    fn fill_rect(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32, color: Color) {
        for dy in 0..h {
            for dx in 0..w {
                if x + dx < image.width() && y + dy < image.height() {
                    image.set_pixel(x + dx, y + dy, color);
                }
            }
        }
    }

    /// 簡易テキスト描画
    fn draw_text(&self, image: &mut Image, text: &str, x: u32, y: u32, color: Color) {
        // 簡易的な4x6ピクセルフォント
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

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::game::Breakout;
    use super::super::types::*;

    #[test]
    fn test_new_game() {
        let game = Breakout::new();
        assert_eq!(game.state(), GameState::Ready);
        assert_eq!(game.lives(), 3);
        assert_eq!(game.score(), 0);
    }

    #[test]
    fn test_paddle_movement() {
        let mut paddle = Paddle::new();
        paddle.move_to(100.0);
        assert!((paddle.center_x() - 100.0).abs() < 1.0);

        paddle.move_to(0.0);
        assert!(paddle.x >= 0.0);

        paddle.move_to(FIELD_WIDTH as f32);
        assert!(paddle.x + paddle.width as f32 <= FIELD_WIDTH as f32);
    }

    #[test]
    fn test_ball_launch() {
        let mut ball = Ball::new(100.0, 100.0);
        assert!(!ball.active);

        ball.launch(1.0);
        assert!(ball.active);
        assert!(ball.speed() > 0.0);
    }
}
