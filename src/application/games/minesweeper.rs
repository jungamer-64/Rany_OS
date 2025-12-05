// ============================================================================
// src/application/games/minesweeper.rs - Minesweeper Game
// ============================================================================
//!
//! # マインスイーパー
//!
//! 再帰的な探索アルゴリズム（Flood Fill）とGUIイベント処理のデモ。
//!
//! ## 機能
//! - 地雷のランダム配置
//! - 再帰的なセル探索
//! - 左クリック: セルを開く
//! - 右クリック: 旗を立てる
//! - 難易度選択（初級/中級/上級）

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

/// セルのサイズ（ピクセル）
const CELL_SIZE: u32 = 24;
/// ヘッダーの高さ
const HEADER_HEIGHT: u32 = 50;
/// パディング
const PADDING: u32 = 10;

// ============================================================================
// Colors
// ============================================================================

/// 背景色
const BG_COLOR: Color = Color { red: 192, green: 192, blue: 192, alpha: 255 };
/// 未開のセル色
const CELL_CLOSED: Color = Color { red: 180, green: 180, blue: 180, alpha: 255 };
/// 開いたセル色
const CELL_OPENED: Color = Color { red: 220, green: 220, blue: 220, alpha: 255 };
/// セルのハイライト色
const CELL_HIGHLIGHT: Color = Color { red: 230, green: 230, blue: 230, alpha: 255 };
/// セルの影色
const CELL_SHADOW: Color = Color { red: 128, green: 128, blue: 128, alpha: 255 };
/// 地雷の色
const MINE_COLOR: Color = Color { red: 0, green: 0, blue: 0, alpha: 255 };
/// 旗の色
const FLAG_COLOR: Color = Color { red: 255, green: 0, blue: 0, alpha: 255 };
/// 爆発した地雷の背景
const MINE_EXPLODED_BG: Color = Color { red: 255, green: 0, blue: 0, alpha: 255 };

/// 数字の色（1〜8）
const NUMBER_COLORS: [Color; 8] = [
    Color { red: 0, green: 0, blue: 255, alpha: 255 },     // 1: 青
    Color { red: 0, green: 128, blue: 0, alpha: 255 },     // 2: 緑
    Color { red: 255, green: 0, blue: 0, alpha: 255 },     // 3: 赤
    Color { red: 0, green: 0, blue: 128, alpha: 255 },     // 4: 紺
    Color { red: 128, green: 0, blue: 0, alpha: 255 },     // 5: 茶
    Color { red: 0, green: 128, blue: 128, alpha: 255 },   // 6: シアン
    Color { red: 0, green: 0, blue: 0, alpha: 255 },       // 7: 黒
    Color { red: 128, green: 128, blue: 128, alpha: 255 }, // 8: グレー
];

// ============================================================================
// Game Types
// ============================================================================

/// ゲームの難易度
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Difficulty {
    /// 初級: 9x9, 10地雷
    Beginner,
    /// 中級: 16x16, 40地雷
    Intermediate,
    /// 上級: 30x16, 99地雷
    Expert,
}

impl Difficulty {
    /// グリッドの幅を取得
    pub fn width(&self) -> usize {
        match self {
            Difficulty::Beginner => 9,
            Difficulty::Intermediate => 16,
            Difficulty::Expert => 30,
        }
    }

    /// グリッドの高さを取得
    pub fn height(&self) -> usize {
        match self {
            Difficulty::Beginner => 9,
            Difficulty::Intermediate => 16,
            Difficulty::Expert => 16,
        }
    }

    /// 地雷の数を取得
    pub fn mines(&self) -> usize {
        match self {
            Difficulty::Beginner => 10,
            Difficulty::Intermediate => 40,
            Difficulty::Expert => 99,
        }
    }
}

/// ゲームの状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameState {
    /// 開始待ち
    Ready,
    /// プレイ中
    Playing,
    /// 勝利
    Won,
    /// 敗北
    Lost,
}

/// セルの状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellState {
    /// 未開
    Closed,
    /// 開いている
    Opened,
    /// 旗が立っている
    Flagged,
    /// クエスチョンマーク
    Question,
}

/// セル
#[derive(Clone, Copy, Debug)]
pub struct Cell {
    /// 地雷かどうか
    pub is_mine: bool,
    /// 状態
    pub state: CellState,
    /// 周囲の地雷数
    pub adjacent_mines: u8,
}

impl Cell {
    /// 新しいセルを作成
    pub fn new() -> Self {
        Self {
            is_mine: false,
            state: CellState::Closed,
            adjacent_mines: 0,
        }
    }
}

impl Default for Cell {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Minesweeper Game
// ============================================================================

/// マインスイーパーゲーム
pub struct Minesweeper {
    /// グリッド
    cells: Vec<Vec<Cell>>,
    /// 幅
    width: usize,
    /// 高さ
    height: usize,
    /// 地雷の数
    mine_count: usize,
    /// ゲーム状態
    state: GameState,
    /// 開始時刻
    start_time: u64,
    /// 経過時間
    elapsed_time: u64,
    /// 残り旗数
    flags_remaining: i32,
    /// 難易度
    difficulty: Difficulty,
    /// ホバー中のセル
    hover_cell: Option<(usize, usize)>,
    /// 乱数シード
    rng_seed: u64,
}

impl Minesweeper {
    /// 新しいゲームを作成
    pub fn new(difficulty: Difficulty) -> Self {
        let width = difficulty.width();
        let height = difficulty.height();
        let mine_count = difficulty.mines();

        let mut game = Self {
            cells: vec![vec![Cell::new(); width]; height],
            width,
            height,
            mine_count,
            state: GameState::Ready,
            start_time: 0,
            elapsed_time: 0,
            flags_remaining: mine_count as i32,
            difficulty,
            hover_cell: None,
            rng_seed: 12345, // 初期シード
        };

        game
    }

    /// ゲームをリセット
    pub fn reset(&mut self) {
        self.cells = vec![vec![Cell::new(); self.width]; self.height];
        self.state = GameState::Ready;
        self.start_time = 0;
        self.elapsed_time = 0;
        self.flags_remaining = self.mine_count as i32;
    }

    /// 難易度を変更
    pub fn set_difficulty(&mut self, difficulty: Difficulty) {
        self.difficulty = difficulty;
        self.width = difficulty.width();
        self.height = difficulty.height();
        self.mine_count = difficulty.mines();
        self.reset();
    }

    /// 乱数シードを設定
    pub fn set_seed(&mut self, seed: u64) {
        self.rng_seed = seed;
    }

    /// 簡易乱数生成器 (Linear Congruential Generator)
    fn rand(&mut self) -> u64 {
        self.rng_seed = self.rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.rng_seed
    }

    /// 範囲内の乱数を生成
    fn rand_range(&mut self, min: usize, max: usize) -> usize {
        if max <= min {
            return min;
        }
        min + (self.rand() as usize % (max - min))
    }

    /// 地雷を配置（最初のクリック位置を除く）
    fn place_mines(&mut self, exclude_x: usize, exclude_y: usize) {
        let mut placed = 0;

        while placed < self.mine_count {
            let x = self.rand_range(0, self.width);
            let y = self.rand_range(0, self.height);

            // 除外範囲チェック（最初のクリック周辺3x3）
            let dx = (x as i32 - exclude_x as i32).abs();
            let dy = (y as i32 - exclude_y as i32).abs();
            if dx <= 1 && dy <= 1 {
                continue;
            }

            // 既に地雷がある場所はスキップ
            if self.cells[y][x].is_mine {
                continue;
            }

            self.cells[y][x].is_mine = true;
            placed += 1;
        }

        // 周囲の地雷数を計算
        self.calculate_adjacent_mines();
    }

    /// 全セルの周囲地雷数を計算
    fn calculate_adjacent_mines(&mut self) {
        for y in 0..self.height {
            for x in 0..self.width {
                if self.cells[y][x].is_mine {
                    continue;
                }

                let mut count = 0u8;
                for dy in -1i32..=1 {
                    for dx in -1i32..=1 {
                        if dx == 0 && dy == 0 {
                            continue;
                        }
                        let nx = x as i32 + dx;
                        let ny = y as i32 + dy;
                        if nx >= 0 && nx < self.width as i32 && ny >= 0 && ny < self.height as i32 {
                            if self.cells[ny as usize][nx as usize].is_mine {
                                count += 1;
                            }
                        }
                    }
                }
                self.cells[y][x].adjacent_mines = count;
            }
        }
    }

    /// セルを開く（再帰的フラッドフィル）
    fn open_cell(&mut self, x: usize, y: usize) {
        if x >= self.width || y >= self.height {
            return;
        }

        let cell = &mut self.cells[y][x];

        // 既に開いている、または旗が立っているセルはスキップ
        if cell.state != CellState::Closed {
            return;
        }

        cell.state = CellState::Opened;

        // 地雷を踏んだ
        if cell.is_mine {
            self.state = GameState::Lost;
            self.reveal_all_mines();
            return;
        }

        // 周囲に地雷がない場合、再帰的に開く
        if cell.adjacent_mines == 0 {
            for dy in -1i32..=1 {
                for dx in -1i32..=1 {
                    if dx == 0 && dy == 0 {
                        continue;
                    }
                    let nx = x as i32 + dx;
                    let ny = y as i32 + dy;
                    if nx >= 0 && nx < self.width as i32 && ny >= 0 && ny < self.height as i32 {
                        self.open_cell(nx as usize, ny as usize);
                    }
                }
            }
        }
    }

    /// 全ての地雷を表示
    fn reveal_all_mines(&mut self) {
        for y in 0..self.height {
            for x in 0..self.width {
                if self.cells[y][x].is_mine {
                    self.cells[y][x].state = CellState::Opened;
                }
            }
        }
    }

    /// 勝利判定
    fn check_win(&mut self) {
        let mut unopened = 0;
        for y in 0..self.height {
            for x in 0..self.width {
                if self.cells[y][x].state != CellState::Opened {
                    unopened += 1;
                }
            }
        }

        if unopened == self.mine_count {
            self.state = GameState::Won;
            // 全ての地雷に旗を立てる
            for y in 0..self.height {
                for x in 0..self.width {
                    if self.cells[y][x].is_mine {
                        self.cells[y][x].state = CellState::Flagged;
                    }
                }
            }
        }
    }

    /// 左クリック処理
    pub fn left_click(&mut self, x: usize, y: usize) {
        if self.state == GameState::Won || self.state == GameState::Lost {
            return;
        }

        // 最初のクリックで地雷を配置
        if self.state == GameState::Ready {
            self.place_mines(x, y);
            self.state = GameState::Playing;
        }

        self.open_cell(x, y);

        if self.state == GameState::Playing {
            self.check_win();
        }
    }

    /// 右クリック処理（旗を立てる）
    pub fn right_click(&mut self, x: usize, y: usize) {
        if self.state != GameState::Playing && self.state != GameState::Ready {
            return;
        }

        if x >= self.width || y >= self.height {
            return;
        }

        let cell = &mut self.cells[y][x];

        match cell.state {
            CellState::Closed => {
                cell.state = CellState::Flagged;
                self.flags_remaining -= 1;
            }
            CellState::Flagged => {
                cell.state = CellState::Question;
                self.flags_remaining += 1;
            }
            CellState::Question => {
                cell.state = CellState::Closed;
            }
            CellState::Opened => {}
        }
    }

    /// 両ボタンクリック（コード機能）
    pub fn chord_click(&mut self, x: usize, y: usize) {
        if self.state != GameState::Playing {
            return;
        }

        if x >= self.width || y >= self.height {
            return;
        }

        let cell = &self.cells[y][x];
        if cell.state != CellState::Opened || cell.adjacent_mines == 0 {
            return;
        }

        // 周囲の旗の数をカウント
        let mut flag_count = 0u8;
        for dy in -1i32..=1 {
            for dx in -1i32..=1 {
                if dx == 0 && dy == 0 {
                    continue;
                }
                let nx = x as i32 + dx;
                let ny = y as i32 + dy;
                if nx >= 0 && nx < self.width as i32 && ny >= 0 && ny < self.height as i32 {
                    if self.cells[ny as usize][nx as usize].state == CellState::Flagged {
                        flag_count += 1;
                    }
                }
            }
        }

        // 旗の数が周囲の地雷数と一致したら周囲を開く
        if flag_count == cell.adjacent_mines {
            for dy in -1i32..=1 {
                for dx in -1i32..=1 {
                    if dx == 0 && dy == 0 {
                        continue;
                    }
                    let nx = x as i32 + dx;
                    let ny = y as i32 + dy;
                    if nx >= 0 && nx < self.width as i32 && ny >= 0 && ny < self.height as i32 {
                        self.open_cell(nx as usize, ny as usize);
                    }
                }
            }

            if self.state == GameState::Playing {
                self.check_win();
            }
        }
    }

    /// 時間を更新
    pub fn update_time(&mut self, current_tick: u64) {
        if self.state == GameState::Playing {
            if self.start_time == 0 {
                self.start_time = current_tick;
            }
            self.elapsed_time = (current_tick - self.start_time) / 1000; // ミリ秒→秒
        }
    }

    // ========================================================================
    // マウスイベント処理
    // ========================================================================

    /// マウス座標からセル座標を計算
    pub fn pixel_to_cell(&self, px: u32, py: u32) -> Option<(usize, usize)> {
        if py < HEADER_HEIGHT + PADDING {
            return None;
        }

        let grid_x = px.saturating_sub(PADDING) / CELL_SIZE;
        let grid_y = (py - HEADER_HEIGHT - PADDING) / CELL_SIZE;

        if grid_x < self.width as u32 && grid_y < self.height as u32 {
            Some((grid_x as usize, grid_y as usize))
        } else {
            None
        }
    }

    /// マウス移動
    pub fn on_mouse_move(&mut self, x: u32, y: u32) {
        self.hover_cell = self.pixel_to_cell(x, y);
    }

    /// マウスクリック
    pub fn on_mouse_click(&mut self, x: u32, y: u32, right_button: bool) {
        // リセットボタンチェック
        let window_width = self.window_width();
        let reset_btn_x = (window_width / 2).saturating_sub(15);
        let reset_btn_y = 10;
        if x >= reset_btn_x && x < reset_btn_x + 30 && y >= reset_btn_y && y < reset_btn_y + 30 {
            self.reset();
            return;
        }

        // セルクリック
        if let Some((cx, cy)) = self.pixel_to_cell(x, y) {
            if right_button {
                self.right_click(cx, cy);
            } else {
                self.left_click(cx, cy);
            }
        }
    }

    // ========================================================================
    // レンダリング
    // ========================================================================

    /// ウィンドウの幅を取得
    pub fn window_width(&self) -> u32 {
        (self.width as u32 * CELL_SIZE) + PADDING * 2
    }

    /// ウィンドウの高さを取得
    pub fn window_height(&self) -> u32 {
        (self.height as u32 * CELL_SIZE) + HEADER_HEIGHT + PADDING * 2
    }

    /// 描画
    pub fn render(&self, image: &mut Image) {
        // 背景
        self.fill_rect(image, 0, 0, image.width(), image.height(), BG_COLOR);

        // ヘッダー
        self.render_header(image);

        // グリッド
        self.render_grid(image);
    }

    /// ヘッダーを描画
    fn render_header(&self, image: &mut Image) {
        let width = self.window_width();

        // 3D風の凹みパネル
        self.draw_inset_rect(image, 5, 5, width - 10, 40);

        // 残り地雷数（左）
        let mines_str = format!("{:03}", max(0, self.flags_remaining));
        self.draw_7segment(image, 15, 12, &mines_str);

        // リセットボタン（中央）
        let btn_x = (width / 2).saturating_sub(15);
        self.draw_button(image, btn_x, 10, 30, 30);
        self.draw_face(image, btn_x + 7, 17);

        // 経過時間（右）
        let time_str = format!("{:03}", min(self.elapsed_time, 999));
        self.draw_7segment(image, width - 55, 12, &time_str);
    }

    /// グリッドを描画
    fn render_grid(&self, image: &mut Image) {
        for y in 0..self.height {
            for x in 0..self.width {
                let px = PADDING + (x as u32 * CELL_SIZE);
                let py = HEADER_HEIGHT + PADDING + (y as u32 * CELL_SIZE);
                self.render_cell(image, x, y, px, py);
            }
        }
    }

    /// セルを描画
    fn render_cell(&self, image: &mut Image, x: usize, y: usize, px: u32, py: u32) {
        let cell = &self.cells[y][x];
        let is_hover = self.hover_cell == Some((x, y));

        match cell.state {
            CellState::Closed => {
                if is_hover && (self.state == GameState::Ready || self.state == GameState::Playing) {
                    self.draw_button_pressed(image, px, py, CELL_SIZE, CELL_SIZE);
                } else {
                    self.draw_button(image, px, py, CELL_SIZE, CELL_SIZE);
                }
            }
            CellState::Opened => {
                self.fill_rect(image, px, py, CELL_SIZE, CELL_SIZE, CELL_OPENED);
                self.draw_border(image, px, py, CELL_SIZE, CELL_SIZE, CELL_SHADOW);

                if cell.is_mine {
                    // 爆発した地雷
                    if self.state == GameState::Lost {
                        self.fill_rect(image, px + 1, py + 1, CELL_SIZE - 2, CELL_SIZE - 2, MINE_EXPLODED_BG);
                    }
                    self.draw_mine(image, px + 4, py + 4);
                } else if cell.adjacent_mines > 0 {
                    self.draw_number(image, px, py, cell.adjacent_mines);
                }
            }
            CellState::Flagged => {
                self.draw_button(image, px, py, CELL_SIZE, CELL_SIZE);
                self.draw_flag(image, px + 6, py + 4);
            }
            CellState::Question => {
                self.draw_button(image, px, py, CELL_SIZE, CELL_SIZE);
                self.draw_question(image, px + 8, py + 4);
            }
        }
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

    /// 枠線を描画
    fn draw_border(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32, color: Color) {
        // 上辺
        for dx in 0..w {
            if x + dx < image.width() && y < image.height() {
                image.set_pixel(x + dx, y, color);
            }
        }
        // 左辺
        for dy in 0..h {
            if x < image.width() && y + dy < image.height() {
                image.set_pixel(x, y + dy, color);
            }
        }
    }

    /// 3Dボタンを描画
    fn draw_button(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32) {
        self.fill_rect(image, x, y, w, h, CELL_CLOSED);

        // ハイライト（上、左）
        for dx in 0..w {
            if x + dx < image.width() {
                image.set_pixel(x + dx, y, CELL_HIGHLIGHT);
                image.set_pixel(x + dx, y + 1, CELL_HIGHLIGHT);
            }
        }
        for dy in 0..h {
            if y + dy < image.height() {
                image.set_pixel(x, y + dy, CELL_HIGHLIGHT);
                image.set_pixel(x + 1, y + dy, CELL_HIGHLIGHT);
            }
        }

        // 影（下、右）
        for dx in 0..w {
            if x + dx < image.width() && y + h - 1 < image.height() {
                image.set_pixel(x + dx, y + h - 1, CELL_SHADOW);
                image.set_pixel(x + dx, y + h - 2, CELL_SHADOW);
            }
        }
        for dy in 0..h {
            if x + w - 1 < image.width() && y + dy < image.height() {
                image.set_pixel(x + w - 1, y + dy, CELL_SHADOW);
                image.set_pixel(x + w - 2, y + dy, CELL_SHADOW);
            }
        }
    }

    /// 押されたボタンを描画
    fn draw_button_pressed(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32) {
        self.fill_rect(image, x, y, w, h, CELL_OPENED);
        self.draw_border(image, x, y, w, h, CELL_SHADOW);
    }

    /// 凹みパネルを描画
    fn draw_inset_rect(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32) {
        self.fill_rect(image, x, y, w, h, BG_COLOR);

        // 影（上、左）
        for dx in 0..w {
            if x + dx < image.width() {
                image.set_pixel(x + dx, y, CELL_SHADOW);
            }
        }
        for dy in 0..h {
            if y + dy < image.height() {
                image.set_pixel(x, y + dy, CELL_SHADOW);
            }
        }

        // ハイライト（下、右）
        for dx in 0..w {
            if x + dx < image.width() && y + h - 1 < image.height() {
                image.set_pixel(x + dx, y + h - 1, CELL_HIGHLIGHT);
            }
        }
        for dy in 0..h {
            if x + w - 1 < image.width() && y + dy < image.height() {
                image.set_pixel(x + w - 1, y + dy, CELL_HIGHLIGHT);
            }
        }
    }

    /// 地雷を描画
    fn draw_mine(&self, image: &mut Image, x: u32, y: u32) {
        // 中心の円
        let pattern = [
            "  ####  ",
            " ###### ",
            "########",
            "########",
            "########",
            "########",
            " ###### ",
            "  ####  ",
        ];

        for (dy, row) in pattern.iter().enumerate() {
            for (dx, ch) in row.chars().enumerate() {
                if ch == '#' {
                    if x + dx as u32 < image.width() && y + dy as u32 < image.height() {
                        image.set_pixel(x + dx as u32, y + dy as u32, MINE_COLOR);
                    }
                }
            }
        }

        // 十字の線
        for i in 0..16u32 {
            if x + 8 < image.width() && y.saturating_sub(2) + i < image.height() {
                if i < 12 {
                    image.set_pixel(x + 8, y.saturating_sub(2) + i, MINE_COLOR);
                }
            }
            if x.saturating_sub(2) + i < image.width() && y + 4 < image.height() {
                if i < 12 {
                    image.set_pixel(x.saturating_sub(2) + i, y + 4, MINE_COLOR);
                }
            }
        }
    }

    /// 旗を描画
    fn draw_flag(&self, image: &mut Image, x: u32, y: u32) {
        // 旗の三角形
        for row in 0..6u32 {
            for col in 0..(6 - row) {
                if x + col < image.width() && y + row < image.height() {
                    image.set_pixel(x + col, y + row, FLAG_COLOR);
                }
            }
        }

        // ポール
        for dy in 0..12u32 {
            if x < image.width() && y + dy < image.height() {
                image.set_pixel(x, y + dy, MINE_COLOR);
            }
        }

        // 土台
        for dx in 0..8u32 {
            if x.saturating_sub(3) + dx < image.width() && y + 12 < image.height() {
                image.set_pixel(x.saturating_sub(3) + dx, y + 12, MINE_COLOR);
            }
        }
    }

    /// クエスチョンマークを描画
    fn draw_question(&self, image: &mut Image, x: u32, y: u32) {
        let pattern = [
            " ### ",
            "#   #",
            "    #",
            "   # ",
            "  #  ",
            "     ",
            "  #  ",
        ];

        for (dy, row) in pattern.iter().enumerate() {
            for (dx, ch) in row.chars().enumerate() {
                if ch == '#' {
                    if x + dx as u32 < image.width() && y + dy as u32 * 2 < image.height() {
                        image.set_pixel(x + dx as u32, y + dy as u32 * 2, MINE_COLOR);
                        image.set_pixel(x + dx as u32, y + dy as u32 * 2 + 1, MINE_COLOR);
                    }
                }
            }
        }
    }

    /// 数字を描画
    fn draw_number(&self, image: &mut Image, x: u32, y: u32, num: u8) {
        if num == 0 || num > 8 {
            return;
        }

        let color = NUMBER_COLORS[(num - 1) as usize];
        let patterns: [&[&str]; 8] = [
            &["  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "], // 1
            &[" ### ", "    #", " ### ", "#    ", " ### "], // 2
            &[" ### ", "    #", " ### ", "    #", " ### "], // 3
            &["#   #", "#   #", " ### ", "    #", "    #"], // 4
            &[" ### ", "#    ", " ### ", "    #", " ### "], // 5
            &[" ### ", "#    ", " ### ", "#   #", " ### "], // 6
            &[" ### ", "    #", "   # ", "  #  ", "  #  "], // 7
            &[" ### ", "#   #", " ### ", "#   #", " ### "], // 8
        ];

        let pattern = patterns[(num - 1) as usize];
        let offset_y = (CELL_SIZE - pattern.len() as u32 * 3) / 2;
        let offset_x = (CELL_SIZE - 5 * 2) / 2;

        for (dy, row) in pattern.iter().enumerate() {
            for (dx, ch) in row.chars().enumerate() {
                if ch == '#' {
                    let px = x + offset_x + dx as u32 * 2;
                    let py = y + offset_y + dy as u32 * 3;
                    for sy in 0..2u32 {
                        for sx in 0..2u32 {
                            if px + sx < image.width() && py + sy < image.height() {
                                image.set_pixel(px + sx, py + sy, color);
                            }
                        }
                    }
                }
            }
        }
    }

    /// 7セグメント表示を描画
    fn draw_7segment(&self, image: &mut Image, x: u32, y: u32, text: &str) {
        let digit_width = 13u32;
        let bg_color = Color { red: 80, green: 0, blue: 0, alpha: 255 };
        let fg_color = Color { red: 255, green: 0, blue: 0, alpha: 255 };

        // 背景
        self.fill_rect(image, x, y, text.len() as u32 * digit_width + 4, 23, Color::BLACK);

        for (i, ch) in text.chars().enumerate() {
            let dx = x + 2 + i as u32 * digit_width;
            self.draw_7segment_digit(image, dx, y + 2, ch, fg_color, bg_color);
        }
    }

    /// 7セグメントの1桁を描画
    fn draw_7segment_digit(&self, image: &mut Image, x: u32, y: u32, digit: char, fg: Color, bg: Color) {
        // セグメント: a(上), b(右上), c(右下), d(下), e(左下), f(左上), g(中央)
        let segments: u8 = match digit {
            '0' => 0b1111110,
            '1' => 0b0110000,
            '2' => 0b1101101,
            '3' => 0b1111001,
            '4' => 0b0110011,
            '5' => 0b1011011,
            '6' => 0b1011111,
            '7' => 0b1110000,
            '8' => 0b1111111,
            '9' => 0b1111011,
            '-' => 0b0000001,
            _ => 0,
        };

        // 各セグメントを描画
        // a - 上の横線
        let a = if segments & 0b1000000 != 0 { fg } else { bg };
        self.fill_rect(image, x + 2, y, 7, 2, a);

        // b - 右上の縦線
        let b = if segments & 0b0100000 != 0 { fg } else { bg };
        self.fill_rect(image, x + 9, y + 2, 2, 7, b);

        // c - 右下の縦線
        let c = if segments & 0b0010000 != 0 { fg } else { bg };
        self.fill_rect(image, x + 9, y + 11, 2, 7, c);

        // d - 下の横線
        let d = if segments & 0b0001000 != 0 { fg } else { bg };
        self.fill_rect(image, x + 2, y + 17, 7, 2, d);

        // e - 左下の縦線
        let e = if segments & 0b0000100 != 0 { fg } else { bg };
        self.fill_rect(image, x, y + 11, 2, 7, e);

        // f - 左上の縦線
        let f = if segments & 0b0000010 != 0 { fg } else { bg };
        self.fill_rect(image, x, y + 2, 2, 7, f);

        // g - 中央の横線
        let g = if segments & 0b0000001 != 0 { fg } else { bg };
        self.fill_rect(image, x + 2, y + 9, 7, 2, g);
    }

    /// 顔を描画（リセットボタン用）
    fn draw_face(&self, image: &mut Image, x: u32, y: u32) {
        let face_color = Color { red: 255, green: 255, blue: 0, alpha: 255 };
        let eye_color = Color::BLACK;

        // 顔の輪郭（円）
        let pattern = [
            "  ######  ",
            " ######## ",
            "##########",
            "##########",
            "##########",
            "##########",
            "##########",
            "##########",
            " ######## ",
            "  ######  ",
        ];

        for (dy, row) in pattern.iter().enumerate() {
            for (dx, ch) in row.chars().enumerate() {
                if ch == '#' {
                    if x + dx as u32 < image.width() && y + dy as u32 < image.height() {
                        image.set_pixel(x + dx as u32, y + dy as u32, face_color);
                    }
                }
            }
        }

        // 目
        image.set_pixel(x + 3, y + 3, eye_color);
        image.set_pixel(x + 6, y + 3, eye_color);

        // 口（状態による）
        match self.state {
            GameState::Won => {
                // スマイル
                image.set_pixel(x + 2, y + 6, eye_color);
                image.set_pixel(x + 3, y + 7, eye_color);
                image.set_pixel(x + 4, y + 7, eye_color);
                image.set_pixel(x + 5, y + 7, eye_color);
                image.set_pixel(x + 6, y + 7, eye_color);
                image.set_pixel(x + 7, y + 6, eye_color);
            }
            GameState::Lost => {
                // 悲しい顔
                image.set_pixel(x + 3, y + 7, eye_color);
                image.set_pixel(x + 4, y + 6, eye_color);
                image.set_pixel(x + 5, y + 6, eye_color);
                image.set_pixel(x + 6, y + 7, eye_color);
            }
            _ => {
                // 普通の顔
                for dx in 3..7u32 {
                    image.set_pixel(x + dx, y + 7, eye_color);
                }
            }
        }
    }

    // ========================================================================
    // アクセサ
    // ========================================================================

    /// ゲーム状態を取得
    pub fn state(&self) -> GameState {
        self.state
    }

    /// 難易度を取得
    pub fn difficulty(&self) -> Difficulty {
        self.difficulty
    }

    /// 経過時間を取得
    pub fn elapsed_time(&self) -> u64 {
        self.elapsed_time
    }

    /// 残り旗数を取得
    pub fn flags_remaining(&self) -> i32 {
        self.flags_remaining
    }
}

impl Default for Minesweeper {
    fn default() -> Self {
        Self::new(Difficulty::Beginner)
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
        let game = Minesweeper::new(Difficulty::Beginner);
        assert_eq!(game.width, 9);
        assert_eq!(game.height, 9);
        assert_eq!(game.mine_count, 10);
        assert_eq!(game.state, GameState::Ready);
    }

    #[test]
    fn test_difficulty_settings() {
        assert_eq!(Difficulty::Beginner.width(), 9);
        assert_eq!(Difficulty::Intermediate.width(), 16);
        assert_eq!(Difficulty::Expert.width(), 30);
    }

    #[test]
    fn test_first_click_safe() {
        let mut game = Minesweeper::new(Difficulty::Beginner);
        game.set_seed(42);
        game.left_click(4, 4);
        
        // 最初のクリック位置は地雷ではないはず
        assert!(!game.cells[4][4].is_mine);
        assert_eq!(game.state, GameState::Playing);
    }

    #[test]
    fn test_flag_toggle() {
        let mut game = Minesweeper::new(Difficulty::Beginner);
        game.state = GameState::Playing;
        
        assert_eq!(game.cells[0][0].state, CellState::Closed);
        
        game.right_click(0, 0);
        assert_eq!(game.cells[0][0].state, CellState::Flagged);
        
        game.right_click(0, 0);
        assert_eq!(game.cells[0][0].state, CellState::Question);
        
        game.right_click(0, 0);
        assert_eq!(game.cells[0][0].state, CellState::Closed);
    }
}
