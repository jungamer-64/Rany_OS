// ============================================================================
// src/application/games/breakout/logic.rs - Game Logic
// ============================================================================
//!
//! ブロック崩しゲームのロジック

extern crate alloc;

use alloc::vec::Vec;

use crate::graphics::Rect;

use super::types::*;
use super::game::Breakout;

// ============================================================================
// Game Logic
// ============================================================================

impl Breakout {
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
        self.handle_paddle_collision();

        // ブロックとの衝突
        self.handle_block_collision();

        // パワーアップの更新
        self.update_powerups();

        // クリア判定
        if self.blocks.iter().all(|b| b.health == 0) || self.blocks.is_empty() {
            self.setup_level(self.level + 1);
        }
    }

    /// パドルとの衝突処理
    fn handle_paddle_collision(&mut self) {
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

                if ball_rect_collision(ball, &paddle_rect) {
                    // パドルの中心からの距離で反射角度を決定
                    let hit_pos = (ball.x - self.paddle.center_x()) / (self.paddle.width as f32 / 2.0);
                    let angle = 1.57 - hit_pos * 1.2; // 約30度〜150度
                    
                    let speed = ball.speed().min(BALL_MAX_SPEED);
                    ball.vx = speed * cos_approx(angle);
                    ball.vy = -sin_approx(angle).abs() * speed;
                    ball.y = self.paddle.y - ball.radius as f32 - 1.0;
                }
            }
        }
    }

    /// ブロックとの衝突処理
    fn handle_block_collision(&mut self) {
        let mut blocks_to_remove = Vec::new();
        let mut spawn_powerup: Option<(f32, f32)> = None;
        let mut score_add = 0u32;

        for ball in self.balls.iter_mut() {
            if !ball.active {
                continue;
            }

            for (i, block) in self.blocks.iter_mut().enumerate() {
                if block.health == 0 {
                    continue;
                }

                if ball_rect_collision(ball, &block.rect()) {
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
                        score_add += block.points;

                        // パワーアップのドロップ候補
                        if spawn_powerup.is_none() {
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

        // スコアを加算
        self.score += score_add;

        // 壊れたブロックを削除
        for i in blocks_to_remove.into_iter().rev() {
            self.blocks.remove(i);
        }

        // パワーアップをスポーン（10%の確率）
        if let Some((x, y)) = spawn_powerup {
            if self.rand() % 10 == 0 {
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
        }
    }

    /// パワーアップの更新
    fn update_powerups(&mut self) {
        let mut powerups_to_remove = Vec::new();
        let mut powerups_to_apply = Vec::new();
        
        for (i, powerup) in self.powerups.iter_mut().enumerate() {
            powerup.update();

            // パドルとの衝突判定
            if powerup.y >= self.paddle.y
                && powerup.x >= self.paddle.x
                && powerup.x <= self.paddle.x + self.paddle.width as f32
            {
                powerups_to_apply.push(powerup.power_type);
                powerups_to_remove.push(i);
            }
            // 画面外に落ちた
            else if powerup.y > FIELD_HEIGHT as f32 {
                powerups_to_remove.push(i);
            }
        }

        // パワーアップを適用
        for power_type in powerups_to_apply {
            self.apply_powerup(power_type);
        }

        for i in powerups_to_remove.into_iter().rev() {
            self.powerups.remove(i);
        }
    }

    /// パワーアップを適用
    pub(crate) fn apply_powerup(&mut self, power_type: PowerUpType) {
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
}
