// ============================================================================
// src/application/games/breakout.rs - Breakout Game
// ============================================================================
//!
//! # ブロック崩し
//!
//! 物理演算と描画パフォーマンスのベンチマークとして実装。
//!
//! ## 機能
//! - ボールの反射物理
//! - ブロックとの衝突判定
//! - パドル操作（マウス/キーボード）
//! - スコアとレベルシステム
//! - パワーアップアイテム

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;
use core::cmp::{min, max};

use crate::graphics::{Color, image::Image, Rect};

// ============================================================================
// Constants
// ============================================================================

/// ゲームフィールドの幅
pub const FIELD_WIDTH: u32 = 640;
/// ゲームフィールドの高さ
pub const FIELD_HEIGHT: u32 = 480;

/// パドルの幅
const PADDLE_WIDTH: u32 = 80;
/// パドルの高さ
const PADDLE_HEIGHT: u32 = 12;
/// パドルのY位置
const PADDLE_Y: u32 = FIELD_HEIGHT - 40;

/// ボールの半径
const BALL_RADIUS: u32 = 6;
/// ボールの初期速度
const BALL_SPEED: f32 = 4.0;
/// ボールの最大速度
const BALL_MAX_SPEED: f32 = 12.0;

/// ブロックの幅
const BLOCK_WIDTH: u32 = 50;
/// ブロックの高さ
const BLOCK_HEIGHT: u32 = 20;
/// ブロックの行数
const BLOCK_ROWS: usize = 6;
/// ブロックの列数
const BLOCK_COLS: usize = 12;
/// ブロック領域の上端
const BLOCK_TOP: u32 = 60;
/// ブロック間の隙間
const BLOCK_GAP: u32 = 2;

/// ヘッダー高さ（スコア表示）
const HEADER_HEIGHT: u32 = 30;

// ============================================================================
// Colors
// ============================================================================

/// 背景色
const BG_COLOR: Color = Color { red: 20, green: 20, blue: 40, alpha: 255 };
/// パドル色
const PADDLE_COLOR: Color = Color { red: 200, green: 200, blue: 200, alpha: 255 };
/// ボール色
const BALL_COLOR: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
/// 壁色
const WALL_COLOR: Color = Color { red: 80, green: 80, blue: 100, alpha: 255 };
/// テキスト色
const TEXT_COLOR: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };

/// ブロック色（行ごと）
const BLOCK_COLORS: [Color; 6] = [
    Color { red: 255, green: 0, blue: 0, alpha: 255 },     // 赤
    Color { red: 255, green: 128, blue: 0, alpha: 255 },   // オレンジ
    Color { red: 255, green: 255, blue: 0, alpha: 255 },   // 黄
    Color { red: 0, green: 255, blue: 0, alpha: 255 },     // 緑
    Color { red: 0, green: 128, blue: 255, alpha: 255 },   // 青
    Color { red: 128, green: 0, blue: 255, alpha: 255 },   // 紫
];

// ============================================================================
// Game Types
// ============================================================================

/// ゲームの状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameState {
    /// 開始待ち
    Ready,
    /// プレイ中
    Playing,
    /// ポーズ中
    Paused,
    /// ゲームオーバー
    GameOver,
    /// クリア
    Cleared,
}

/// ボール
#[derive(Clone, Copy, Debug)]
pub struct Ball {
    /// X座標（中心）
    pub x: f32,
    /// Y座標（中心）
    pub y: f32,
    /// X方向速度
    pub vx: f32,
    /// Y方向速度
    pub vy: f32,
    /// 半径
    pub radius: u32,
    /// アクティブかどうか
    pub active: bool,
}

impl Ball {
    /// 新しいボールを作成
    pub fn new(x: f32, y: f32) -> Self {
        Self {
            x,
            y,
            vx: 0.0,
            vy: 0.0,
            radius: BALL_RADIUS,
            active: false,
        }
    }

    /// ボールを発射
    pub fn launch(&mut self, angle: f32) {
        self.vx = BALL_SPEED * angle.cos();
        self.vy = -BALL_SPEED * angle.sin();
        self.active = true;
    }

    /// ボールを更新
    pub fn update(&mut self) {
        if self.active {
            self.x += self.vx;
            self.y += self.vy;
        }
    }

    /// 速度を正規化
    pub fn normalize_speed(&mut self, speed: f32) {
        let current = (self.vx * self.vx + self.vy * self.vy).sqrt();
        if current > 0.0 {
            self.vx = self.vx / current * speed;
            self.vy = self.vy / current * speed;
        }
    }

    /// 現在の速度を取得
    pub fn speed(&self) -> f32 {
        (self.vx * self.vx + self.vy * self.vy).sqrt()
    }
}

/// パドル
#[derive(Clone, Copy, Debug)]
pub struct Paddle {
    /// X座標（左端）
    pub x: f32,
    /// Y座標
    pub y: f32,
    /// 幅
    pub width: u32,
    /// 高さ
    pub height: u32,
}

impl Paddle {
    /// 新しいパドルを作成
    pub fn new() -> Self {
        Self {
            x: (FIELD_WIDTH / 2 - PADDLE_WIDTH / 2) as f32,
            y: PADDLE_Y as f32,
            width: PADDLE_WIDTH,
            height: PADDLE_HEIGHT,
        }
    }

    /// パドルを移動
    pub fn move_to(&mut self, target_x: f32) {
        self.x = target_x - (self.width as f32 / 2.0);
        self.x = self.x.max(0.0).min((FIELD_WIDTH - self.width) as f32);
    }

    /// パドルを左に移動
    pub fn move_left(&mut self, speed: f32) {
        self.x = (self.x - speed).max(0.0);
    }

    /// パドルを右に移動
    pub fn move_right(&mut self, speed: f32) {
        self.x = (self.x + speed).min((FIELD_WIDTH - self.width) as f32);
    }

    /// 中心X座標
    pub fn center_x(&self) -> f32 {
        self.x + self.width as f32 / 2.0
    }
}

impl Default for Paddle {
    fn default() -> Self {
        Self::new()
    }
}

/// ブロック
#[derive(Clone, Copy, Debug)]
pub struct Block {
    /// X座標
    pub x: u32,
    /// Y座標
    pub y: u32,
    /// 幅
    pub width: u32,
    /// 高さ
    pub height: u32,
    /// 色
    pub color: Color,
    /// 耐久度（0で消滅）
    pub health: u8,
    /// ポイント
    pub points: u32,
}

impl Block {
    /// 新しいブロックを作成
    pub fn new(x: u32, y: u32, color: Color, health: u8) -> Self {
        Self {
            x,
            y,
            width: BLOCK_WIDTH,
            height: BLOCK_HEIGHT,
            color,
            health,
            points: health as u32 * 10,
        }
    }

    /// ダメージを受ける
    pub fn hit(&mut self) -> bool {
        if self.health > 0 {
            self.health -= 1;
            // 色を暗くする
            self.color = Color {
                red: self.color.red.saturating_sub(30),
                green: self.color.green.saturating_sub(30),
                blue: self.color.blue.saturating_sub(30),
                alpha: self.color.alpha,
            };
        }
        self.health == 0
    }

    /// 矩形を取得
    pub fn rect(&self) -> Rect {
        Rect::new(self.x as i32, self.y as i32, self.width, self.height)
    }
}

/// パワーアップの種類
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerUpType {
    /// パドル拡大
    ExpandPaddle,
    /// パドル縮小
    ShrinkPaddle,
    /// マルチボール
    MultiBall,
    /// スローボール
    SlowBall,
    /// ファストボール
    FastBall,
    /// ライフ追加
    ExtraLife,
}

/// パワーアップアイテム
#[derive(Clone, Copy, Debug)]
pub struct PowerUp {
    /// X座標
    pub x: f32,
    /// Y座標
    pub y: f32,
    /// 種類
    pub power_type: PowerUpType,
    /// 落下速度
    pub speed: f32,
}

impl PowerUp {
    /// 新しいパワーアップを作成
    pub fn new(x: f32, y: f32, power_type: PowerUpType) -> Self {
        Self {
            x,
            y,
            power_type,
            speed: 2.0,
        }
    }

    /// 更新
    pub fn update(&mut self) {
        self.y += self.speed;
    }

    /// 色を取得
    pub fn color(&self) -> Color {
        match self.power_type {
            PowerUpType::ExpandPaddle => Color { red: 0, green: 255, blue: 0, alpha: 255 },
            PowerUpType::ShrinkPaddle => Color { red: 255, green: 0, blue: 0, alpha: 255 },
            PowerUpType::MultiBall => Color { red: 255, green: 255, blue: 0, alpha: 255 },
            PowerUpType::SlowBall => Color { red: 0, green: 128, blue: 255, alpha: 255 },
            PowerUpType::FastBall => Color { red: 255, green: 128, blue: 0, alpha: 255 },
            PowerUpType::ExtraLife => Color { red: 255, green: 0, blue: 255, alpha: 255 },
        }
    }
}

// ============================================================================
// Breakout Game
// ============================================================================

/// ブロック崩しゲーム
pub struct Breakout {
    /// ボール（複数可能）
    balls: Vec<Ball>,
    /// パドル
    paddle: Paddle,
    /// ブロック
    blocks: Vec<Block>,
    /// パワーアップ
    powerups: Vec<PowerUp>,
    /// ゲーム状態
    state: GameState,
    /// スコア
    score: u32,
    /// ハイスコア
    high_score: u32,
    /// 残りライフ
    lives: u32,
    /// 現在のレベル
    level: u32,
    /// フレームカウント
    frame_count: u64,
    /// 乱数シード
    rng_seed: u64,
    /// キー入力状態
    key_left: bool,
    key_right: bool,
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
    fn setup_level(&mut self, level: u32) {
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
    fn rand(&mut self) -> u64 {
        self.rng_seed = self.rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.rng_seed
    }

    /// 0.0〜1.0の乱数
    fn rand_float(&mut self) -> f32 {
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

    /// ゲームを更新
    pub fn update(&mut self) {
        if self.state != GameState::Playing {
            return;
        }

        self.frame_count += 1;

        // キー入力によるパドル移動
        let paddle_speed = 8.0;
        if self.key_left {
            self.paddle.move_left(paddle_speed);
        }
        if self.key_right {
            self.paddle.move_right(paddle_speed);
        }

        // ボール更新
        let mut balls_to_remove = Vec::new();
        for (i, ball) in self.balls.iter_mut().enumerate() {
            if !ball.active {
                continue;
            }

            ball.update();

            // 壁との衝突
            if ball.x - ball.radius as f32 <= 0.0 {
                ball.x = ball.radius as f32;
                ball.vx = ball.vx.abs();
            }
            if ball.x + ball.radius as f32 >= FIELD_WIDTH as f32 {
                ball.x = FIELD_WIDTH as f32 - ball.radius as f32;
                ball.vx = -ball.vx.abs();
            }
            if ball.y - ball.radius as f32 <= HEADER_HEIGHT as f32 {
                ball.y = HEADER_HEIGHT as f32 + ball.radius as f32;
                ball.vy = ball.vy.abs();
            }

            // 落下判定
            if ball.y > FIELD_HEIGHT as f32 + ball.radius as f32 {
                balls_to_remove.push(i);
            }
        }

        // 落下したボールを削除
        for i in balls_to_remove.into_iter().rev() {
            self.balls.remove(i);
        }

        // 全ボールが落下した場合
        if self.balls.is_empty() || self.balls.iter().all(|b| !b.active) {
            self.lives = self.lives.saturating_sub(1);
            if self.lives == 0 {
                self.state = GameState::GameOver;
                if self.score > self.high_score {
                    self.high_score = self.score;
                }
            } else {
                // ボールをリセット
                self.balls.clear();
                let ball = Ball::new(
                    self.paddle.center_x(),
                    self.paddle.y - BALL_RADIUS as f32 - 2.0,
                );
                self.balls.push(ball);
                self.state = GameState::Ready;
            }
            return;
        }

        // パドルとの衝突
        for ball in self.balls.iter_mut() {
            if !ball.active {
                continue;
            }

            if ball.vy > 0.0 {
                let paddle_rect = Rect::new(
                    self.paddle.x as i32,
                    self.paddle.y as i32,
                    self.paddle.width,
                    self.paddle.height,
                );

                if self.ball_rect_collision(ball, &paddle_rect) {
                    // パドルの中心からの距離で反射角度を決定
                    let hit_pos = (ball.x - self.paddle.center_x()) / (self.paddle.width as f32 / 2.0);
                    let angle = 1.57 - hit_pos * 1.2; // 約30度〜150度
                    
                    let speed = ball.speed().min(BALL_MAX_SPEED);
                    ball.vx = speed * angle.cos();
                    ball.vy = -speed * angle.sin().abs();
                    ball.y = self.paddle.y - ball.radius as f32 - 1.0;
                }
            }
        }

        // ブロックとの衝突
        let mut blocks_to_remove = Vec::new();
        let mut spawn_powerup: Option<(f32, f32)> = None;

        for ball in self.balls.iter_mut() {
            if !ball.active {
                continue;
            }

            for (i, block) in self.blocks.iter_mut().enumerate() {
                if block.health == 0 {
                    continue;
                }

                if self.ball_rect_collision(ball, &block.rect()) {
                    // 反射方向を決定
                    let ball_center_x = ball.x;
                    let ball_center_y = ball.y;
                    let block_center_x = block.x as f32 + block.width as f32 / 2.0;
                    let block_center_y = block.y as f32 + block.height as f32 / 2.0;

                    let dx = ball_center_x - block_center_x;
                    let dy = ball_center_y - block_center_y;

                    // アスペクト比を考慮
                    let dx_ratio = dx / (block.width as f32 / 2.0);
                    let dy_ratio = dy / (block.height as f32 / 2.0);

                    if dx_ratio.abs() > dy_ratio.abs() {
                        ball.vx = -ball.vx;
                    } else {
                        ball.vy = -ball.vy;
                    }

                    // ブロックにダメージ
                    if block.hit() {
                        blocks_to_remove.push(i);
                        self.score += block.points;

                        // パワーアップのドロップ（10%の確率）
                        if self.rand() % 10 == 0 {
                            spawn_powerup = Some((
                                block.x as f32 + block.width as f32 / 2.0,
                                block.y as f32 + block.height as f32 / 2.0,
                            ));
                        }
                    }

                    break; // 1フレームに1ブロックのみ
                }
            }
        }

        // 壊れたブロックを削除
        for i in blocks_to_remove.into_iter().rev() {
            self.blocks.remove(i);
        }

        // パワーアップをスポーン
        if let Some((x, y)) = spawn_powerup {
            let power_type = match self.rand() % 6 {
                0 => PowerUpType::ExpandPaddle,
                1 => PowerUpType::ShrinkPaddle,
                2 => PowerUpType::MultiBall,
                3 => PowerUpType::SlowBall,
                4 => PowerUpType::FastBall,
                _ => PowerUpType::ExtraLife,
            };
            self.powerups.push(PowerUp::new(x, y, power_type));
        }

        // パワーアップの更新
        let mut powerups_to_remove = Vec::new();
        for (i, powerup) in self.powerups.iter_mut().enumerate() {
            powerup.update();

            // パドルとの衝突判定
            if powerup.y >= self.paddle.y
                && powerup.x >= self.paddle.x
                && powerup.x <= self.paddle.x + self.paddle.width as f32
            {
                self.apply_powerup(powerup.power_type);
                powerups_to_remove.push(i);
            }
            // 画面外に落下
            else if powerup.y > FIELD_HEIGHT as f32 {
                powerups_to_remove.push(i);
            }
        }

        for i in powerups_to_remove.into_iter().rev() {
            self.powerups.remove(i);
        }

        // クリア判定
        if self.blocks.iter().all(|b| b.health == 0) || self.blocks.is_empty() {
            self.setup_level(self.level + 1);
        }
    }

    /// ボールと矩形の衝突判定
    fn ball_rect_collision(&self, ball: &Ball, rect: &Rect) -> bool {
        let closest_x = ball.x.max(rect.x as f32).min(rect.right() as f32);
        let closest_y = ball.y.max(rect.y as f32).min(rect.bottom() as f32);

        let dx = ball.x - closest_x;
        let dy = ball.y - closest_y;

        (dx * dx + dy * dy) < (ball.radius * ball.radius) as f32
    }

    /// パワーアップを適用
    fn apply_powerup(&mut self, power_type: PowerUpType) {
        match power_type {
            PowerUpType::ExpandPaddle => {
                self.paddle.width = (self.paddle.width + 20).min(160);
            }
            PowerUpType::ShrinkPaddle => {
                self.paddle.width = (self.paddle.width.saturating_sub(20)).max(40);
            }
            PowerUpType::MultiBall => {
                // 現在のボールを複製
                if let Some(ball) = self.balls.first().cloned() {
                    let mut new_ball1 = ball;
                    let mut new_ball2 = ball;
                    new_ball1.vx = ball.vx + 1.0;
                    new_ball2.vx = ball.vx - 1.0;
                    new_ball1.normalize_speed(ball.speed());
                    new_ball2.normalize_speed(ball.speed());
                    self.balls.push(new_ball1);
                    self.balls.push(new_ball2);
                }
            }
            PowerUpType::SlowBall => {
                for ball in self.balls.iter_mut() {
                    let speed = (ball.speed() * 0.7).max(2.0);
                    ball.normalize_speed(speed);
                }
            }
            PowerUpType::FastBall => {
                for ball in self.balls.iter_mut() {
                    let speed = (ball.speed() * 1.3).min(BALL_MAX_SPEED);
                    ball.normalize_speed(speed);
                }
            }
            PowerUpType::ExtraLife => {
                self.lives = (self.lives + 1).min(5);
            }
        }
    }

    // ========================================================================
    // 入力処理
    // ========================================================================

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

    // ========================================================================
    // レンダリング
    // ========================================================================

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

        // 円を描画（塗りつぶし）
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

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_game() {
        let game = Breakout::new();
        assert_eq!(game.state, GameState::Ready);
        assert_eq!(game.lives, 3);
        assert_eq!(game.score, 0);
        assert!(!game.blocks.is_empty());
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
