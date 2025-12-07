// ============================================================================
// src/application/games/breakout/input.rs - Input Handling
// ============================================================================
//!
//! ブロック崩しゲームの入力処理

use super::types::*;
use super::game::Breakout;

// ============================================================================
// Input Handling
// ============================================================================

impl Breakout {
    /// マウス移動
    pub fn on_mouse_move(&mut self, x: u32, _y: u32) {
        if self.state == GameState::Playing || self.state == GameState::Ready {
            self.paddle.move_to(x as f32);

            // 発射前はボールもパドルに追従
            if self.state == GameState::Ready {
                for ball in self.balls.iter_mut() {
                    if !ball.active {
                        ball.x = self.paddle.center_x();
                    }
                }
            }
        }
    }

    /// マウスクリック
    pub fn on_mouse_click(&mut self, _x: u32, _y: u32) {
        match self.state {
            GameState::Ready => self.start(),
            GameState::GameOver | GameState::Cleared => self.reset(),
            _ => {}
        }
    }

    /// キー押下
    pub fn on_key_down(&mut self, key: char) {
        match key {
            'a' | 'A' => self.key_left = true,
            'd' | 'D' => self.key_right = true,
            ' ' => {
                if self.state == GameState::Ready {
                    self.start();
                }
            }
            'p' | 'P' => {
                if self.state == GameState::Playing {
                    self.pause();
                } else if self.state == GameState::Paused {
                    self.start();
                }
            }
            'r' | 'R' => self.reset(),
            _ => {}
        }
    }

    /// キー解放
    pub fn on_key_up(&mut self, key: char) {
        match key {
            'a' | 'A' => self.key_left = false,
            'd' | 'D' => self.key_right = false,
            _ => {}
        }
    }
}
