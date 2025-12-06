// ============================================================================
// src/application/games/breakout/types.rs - Types and Constants
// ============================================================================
//!
//! ブロック崩しゲームの型定義と定数

use crate::graphics::{Color, Rect};

// ============================================================================
// no_std Math Functions
// ============================================================================

/// 簡易的なsin関数（Taylor展開による近似）
pub fn sin_approx(x: f32) -> f32 {
    const PI: f32 = 3.14159265;
    let mut x = x % (2.0 * PI);
    if x > PI { x -= 2.0 * PI; }
    if x < -PI { x += 2.0 * PI; }
    
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    x - x3 / 6.0 + x5 / 120.0
}

/// 簡易的なcos関数
pub fn cos_approx(x: f32) -> f32 {
    sin_approx(x + 3.14159265 / 2.0)
}

/// 簡易的なsqrt関数（Newton法）
pub fn sqrt_approx(x: f32) -> f32 {
    if x <= 0.0 { return 0.0; }
    let mut guess = x / 2.0;
    for _ in 0..10 {
        guess = (guess + x / guess) / 2.0;
    }
    guess
}

/// ボールと矩形の衝突判定
pub fn ball_rect_collision(ball: &Ball, rect: &Rect) -> bool {
    let closest_x = ball.x.max(rect.x as f32).min(rect.right() as f32);
    let closest_y = ball.y.max(rect.y as f32).min(rect.bottom() as f32);

    let dx = ball.x - closest_x;
    let dy = ball.y - closest_y;

    (dx * dx + dy * dy) < (ball.radius * ball.radius) as f32
}

// ============================================================================
// Constants
// ============================================================================

/// ゲームフィールドの幅
pub const FIELD_WIDTH: u32 = 640;
/// ゲームフィールドの高さ
pub const FIELD_HEIGHT: u32 = 480;

/// パドルの幅
pub const PADDLE_WIDTH: u32 = 80;
/// パドルの高さ
pub const PADDLE_HEIGHT: u32 = 12;
/// パドルのY位置
pub const PADDLE_Y: u32 = FIELD_HEIGHT - 40;

/// ボールの半径
pub const BALL_RADIUS: u32 = 6;
/// ボールの初期速度
pub const BALL_SPEED: f32 = 4.0;
/// ボールの最大速度
pub const BALL_MAX_SPEED: f32 = 12.0;

/// ブロックの幅
pub const BLOCK_WIDTH: u32 = 50;
/// ブロックの高さ
pub const BLOCK_HEIGHT: u32 = 20;
/// ブロックの行数
pub const BLOCK_ROWS: usize = 6;
/// ブロックの列数
pub const BLOCK_COLS: usize = 12;
/// ブロック領域の上端
pub const BLOCK_TOP: u32 = 60;
/// ブロック間の隙間
pub const BLOCK_GAP: u32 = 2;

/// ヘッダー高さ（スコア表示）
pub const HEADER_HEIGHT: u32 = 30;

// ============================================================================
// Colors
// ============================================================================

/// 背景色
pub const BG_COLOR: Color = Color { red: 20, green: 20, blue: 40, alpha: 255 };
/// パドル色
pub const PADDLE_COLOR: Color = Color { red: 200, green: 200, blue: 200, alpha: 255 };
/// ボール色
pub const BALL_COLOR: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
/// 壁色
pub const WALL_COLOR: Color = Color { red: 80, green: 80, blue: 100, alpha: 255 };
/// テキスト色
pub const TEXT_COLOR: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };

/// ブロック色（行ごと）
pub const BLOCK_COLORS: [Color; 6] = [
    Color { red: 255, green: 0, blue: 0, alpha: 255 },     // 赤
    Color { red: 255, green: 128, blue: 0, alpha: 255 },   // オレンジ
    Color { red: 255, green: 255, blue: 0, alpha: 255 },   // 黄
    Color { red: 0, green: 255, blue: 0, alpha: 255 },     // 緑
    Color { red: 0, green: 128, blue: 255, alpha: 255 },   // 青
    Color { red: 128, green: 0, blue: 255, alpha: 255 },   // 紫
];

// ============================================================================
// Game State
// ============================================================================

/// ゲームの状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameState {
    /// 開始前
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

// ============================================================================
// Ball
// ============================================================================

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
        self.vx = BALL_SPEED * cos_approx(angle);
        self.vy = -BALL_SPEED * sin_approx(angle);
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
        let current = sqrt_approx(self.vx * self.vx + self.vy * self.vy);
        if current > 0.0 {
            self.vx = self.vx / current * speed;
            self.vy = self.vy / current * speed;
        }
    }

    /// 現在の速度を取得
    pub fn speed(&self) -> f32 {
        sqrt_approx(self.vx * self.vx + self.vy * self.vy)
    }
}

// ============================================================================
// Paddle
// ============================================================================

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

// ============================================================================
// Block
// ============================================================================

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
    /// 耐久力（0で消滅）
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

// ============================================================================
// Power Up
// ============================================================================

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
