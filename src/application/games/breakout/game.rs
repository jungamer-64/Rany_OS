// ============================================================================
// src/application/games/breakout/game.rs - Breakout Game Structure
// ============================================================================
//!
//! ブロック崩しゲームの構造体定義と基本実装

extern crate alloc;

use alloc::vec::Vec;

use super::types::*;

// ============================================================================
// Breakout Game
// ============================================================================

/// ブロック崩しゲーム
pub struct Breakout {
    /// ボール（複数可能）
    pub(crate) balls: Vec<Ball>,
    /// パドル
    pub(crate) paddle: Paddle,
    /// ブロック
    pub(crate) blocks: Vec<Block>,
    /// パワーアップ
    pub(crate) powerups: Vec<PowerUp>,
    /// ゲーム状態
    pub(crate) state: GameState,
    /// スコア
    pub(crate) score: u32,
    /// ハイスコア
    pub(crate) high_score: u32,
    /// 残りライフ
    pub(crate) lives: u32,
    /// 現在のレベル
    pub(crate) level: u32,
    /// フレームカウント
    pub(crate) frame_count: u64,
    /// 乱数シード
    pub(crate) rng_seed: u64,
    /// キー入力状態
    pub(crate) key_left: bool,
    pub(crate) key_right: bool,
}

impl Breakout {
    /// 新しいゲームを作成
    pub fn new() -> Self {
        let mut game = Self {
            balls: Vec::new(),
            paddle: Paddle::new(),
            blocks: Vec::new(),
            powerups: Vec::new(),
            state: GameState::Ready,
            score: 0,
            high_score: 0,
            lives: 3,
            level: 1,
            frame_count: 0,
            rng_seed: 12345,
            key_left: false,
            key_right: false,
        };

        game.setup_level(1);
        game
    }

    /// レベルをセットアップ
    pub(crate) fn setup_level(&mut self, level: u32) {
        self.level = level;
        self.blocks.clear();
        self.powerups.clear();
        self.balls.clear();

        // ボールをパドル上に配置
        let ball = Ball::new(
            self.paddle.center_x(),
            self.paddle.y - BALL_RADIUS as f32 - 2.0,
        );
        self.balls.push(ball);

        // ブロックを配置
        let start_x = (FIELD_WIDTH - (BLOCK_COLS as u32 * (BLOCK_WIDTH + BLOCK_GAP))) / 2;

        for row in 0..BLOCK_ROWS {
            let color = BLOCK_COLORS[row % BLOCK_COLORS.len()];
            let health = match row {
                0 => 2,  // 最上段は耐久2
                1 => 2,
                _ => 1,
            };

            for col in 0..BLOCK_COLS {
                // レベルによってブロックのパターンを変える
                let skip = match level % 3 {
                    1 => false,
                    2 => (row + col) % 2 == 0,
                    _ => (row + col) % 3 == 0,
                };

                if !skip {
                    let x = start_x + col as u32 * (BLOCK_WIDTH + BLOCK_GAP);
                    let y = BLOCK_TOP + row as u32 * (BLOCK_HEIGHT + BLOCK_GAP);
                    self.blocks.push(Block::new(x, y, color, health));
                }
            }
        }

        self.state = GameState::Ready;
    }

    /// 乱数生成
    pub(crate) fn rand(&mut self) -> u64 {
        self.rng_seed = self.rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.rng_seed
    }

    /// 0.0〜1.0の乱数
    pub(crate) fn rand_float(&mut self) -> f32 {
        (self.rand() % 10000) as f32 / 10000.0
    }

    /// ゲームをリセット
    pub fn reset(&mut self) {
        self.score = 0;
        self.lives = 3;
        self.paddle = Paddle::new();
        self.setup_level(1);
    }

    /// ゲームを開始/再開
    pub fn start(&mut self) {
        if self.state == GameState::Ready {
            // ボールを発射（ランダムな角度）
            let angle = 1.0 + (self.rand_float() - 0.5) * 0.5; // 約45〜135度
            if let Some(ball) = self.balls.first_mut() {
                ball.launch(angle);
            }
            self.state = GameState::Playing;
        } else if self.state == GameState::Paused {
            self.state = GameState::Playing;
        }
    }

    /// ポーズ
    pub fn pause(&mut self) {
        if self.state == GameState::Playing {
            self.state = GameState::Paused;
        }
    }

    // ========================================================================
    // アクセサ
    // ========================================================================

    /// ゲーム状態を取得
    pub fn state(&self) -> GameState {
        self.state
    }

    /// スコアを取得
    pub fn score(&self) -> u32 {
        self.score
    }

    /// ハイスコアを取得
    pub fn high_score(&self) -> u32 {
        self.high_score
    }

    /// 残りライフを取得
    pub fn lives(&self) -> u32 {
        self.lives
    }

    /// 現在のレベルを取得
    pub fn level(&self) -> u32 {
        self.level
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

impl Default for Breakout {
    fn default() -> Self {
        Self::new()
    }
}
