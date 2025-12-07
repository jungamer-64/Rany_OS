// ============================================================================
// src/graphics/compositor/cursor.rs - Mouse Cursor
// ============================================================================

//! マウスカーソル管理

extern crate alloc;

use alloc::collections::BTreeMap;

use crate::graphics::{Color, Rect};
use crate::graphics::image::Image;

// ============================================================================
// Cursor Type
// ============================================================================

/// カーソルタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CursorType {
    Arrow,
    Hand,
    IBeam,
    ResizeNS,
    ResizeEW,
    ResizeNESW,
    ResizeNWSE,
    Move,
    Wait,
    Crosshair,
    NotAllowed,
    Hidden,
}

// ============================================================================
// Mouse Cursor
// ============================================================================

/// マウスカーソル
pub struct MouseCursor {
    /// 現在のカーソルタイプ
    cursor_type: CursorType,
    /// カーソル位置
    x: i32,
    y: i32,
    /// カーソル画像
    images: BTreeMap<CursorType, Image>,
    /// ホットスポット（クリック点）
    hotspots: BTreeMap<CursorType, (i32, i32)>,
    /// 可視性
    visible: bool,
    /// 前回の位置（ダーティ領域用）
    prev_x: i32,
    prev_y: i32,
}

impl MouseCursor {
    pub fn new() -> Self {
        let mut cursor = Self {
            cursor_type: CursorType::Arrow,
            x: 0,
            y: 0,
            images: BTreeMap::new(),
            hotspots: BTreeMap::new(),
            visible: true,
            prev_x: 0,
            prev_y: 0,
        };

        // デフォルトカーソルを生成
        cursor.create_default_cursors();
        cursor
    }

    /// デフォルトカーソルを生成
    fn create_default_cursors(&mut self) {
        // Arrow cursor (16x24)
        self.images
            .insert(CursorType::Arrow, create_arrow_cursor());
        self.hotspots.insert(CursorType::Arrow, (0, 0));

        // Hand cursor
        self.images.insert(CursorType::Hand, create_hand_cursor());
        self.hotspots.insert(CursorType::Hand, (5, 0));

        // I-Beam cursor
        self.images.insert(CursorType::IBeam, create_ibeam_cursor());
        self.hotspots.insert(CursorType::IBeam, (4, 8));

        // Resize cursors
        self.images
            .insert(CursorType::ResizeNS, create_resize_ns_cursor());
        self.hotspots.insert(CursorType::ResizeNS, (4, 8));

        self.images
            .insert(CursorType::ResizeEW, create_resize_ew_cursor());
        self.hotspots.insert(CursorType::ResizeEW, (8, 4));
    }

    /// カーソル位置を設定
    pub fn set_position(&mut self, x: i32, y: i32) {
        self.prev_x = self.x;
        self.prev_y = self.y;
        self.x = x;
        self.y = y;
    }

    /// カーソル位置を取得
    #[allow(dead_code)]
    pub fn position(&self) -> (i32, i32) {
        (self.x, self.y)
    }

    /// カーソルタイプを設定
    pub fn set_cursor_type(&mut self, cursor_type: CursorType) {
        self.cursor_type = cursor_type;
    }

    /// カーソルタイプを取得
    #[allow(dead_code)]
    pub fn cursor_type(&self) -> CursorType {
        self.cursor_type
    }

    /// 可視性を設定
    #[allow(dead_code)]
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// 可視性を取得
    #[allow(dead_code)]
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// カーソルの矩形を取得
    pub fn get_rect(&self) -> Rect {
        if let Some(image) = self.images.get(&self.cursor_type) {
            let (hx, hy) = self.hotspots.get(&self.cursor_type).copied().unwrap_or((0, 0));
            Rect::new(
                self.x - hx,
                self.y - hy,
                image.width(),
                image.height(),
            )
        } else {
            Rect::new(self.x, self.y, 16, 24)
        }
    }

    /// 前回位置の矩形を取得
    #[allow(dead_code)]
    pub fn get_prev_rect(&self) -> Rect {
        if let Some(image) = self.images.get(&self.cursor_type) {
            let (hx, hy) = self.hotspots.get(&self.cursor_type).copied().unwrap_or((0, 0));
            Rect::new(
                self.prev_x - hx,
                self.prev_y - hy,
                image.width(),
                image.height(),
            )
        } else {
            Rect::new(self.prev_x, self.prev_y, 16, 24)
        }
    }

    /// カーソルを画像に描画
    pub fn draw(&self, target: &mut Image) {
        if !self.visible || self.cursor_type == CursorType::Hidden {
            return;
        }

        if let Some(cursor_image) = self.images.get(&self.cursor_type) {
            let (hx, hy) = self.hotspots.get(&self.cursor_type).copied().unwrap_or((0, 0));
            target.blit(cursor_image, self.x - hx, self.y - hy);
        }
    }
}

impl Default for MouseCursor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Cursor Image Generators
// ============================================================================

/// 矢印カーソルを生成
fn create_arrow_cursor() -> Image {
    let mut img = Image::new(16, 24);
    let white = Color::WHITE;
    let black = Color::BLACK;

    // 矢印パターン
    let pattern = [
        "X               ",
        "XX              ",
        "X.X             ",
        "X..X            ",
        "X...X           ",
        "X....X          ",
        "X.....X         ",
        "X......X        ",
        "X.......X       ",
        "X........X      ",
        "X.........X     ",
        "X..........X    ",
        "X......XXXXX    ",
        "X...X..X        ",
        "X..X X..X       ",
        "X.X  X..X       ",
        "XX    X..X      ",
        "X     X..X      ",
        "       X..X     ",
        "       X..X     ",
        "        XX      ",
        "                ",
        "                ",
        "                ",
    ];

    for (y, row) in pattern.iter().enumerate() {
        for (x, ch) in row.chars().enumerate() {
            let color = match ch {
                'X' => black,
                '.' => white,
                _ => continue,
            };
            img.set_pixel(x as u32, y as u32, color);
        }
    }

    img
}

/// ハンドカーソルを生成
fn create_hand_cursor() -> Image {
    let mut img = Image::new(16, 24);
    let white = Color::WHITE;
    let black = Color::BLACK;

    let pattern = [
        "     XX         ",
        "    X..X        ",
        "    X..X        ",
        "    X..X        ",
        "    X..XXX      ",
        "    X..X..XXX   ",
        " XX X..X..X..X  ",
        "X..XX..X..X..X  ",
        "X...X........X  ",
        " X...........X  ",
        "  X..........X  ",
        "  X..........X  ",
        "   X........X   ",
        "   X........X   ",
        "    X......X    ",
        "    X......X    ",
        "     X....X     ",
        "     X....X     ",
        "     XXXXXX     ",
        "                ",
        "                ",
        "                ",
        "                ",
        "                ",
    ];

    for (y, row) in pattern.iter().enumerate() {
        for (x, ch) in row.chars().enumerate() {
            let color = match ch {
                'X' => black,
                '.' => white,
                _ => continue,
            };
            img.set_pixel(x as u32, y as u32, color);
        }
    }

    img
}

/// I-Beamカーソルを生成
fn create_ibeam_cursor() -> Image {
    let mut img = Image::new(9, 16);
    let black = Color::BLACK;

    let pattern = [
        "XXX X XXX",
        "   X X   ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "    X    ",
        "   X X   ",
        "XXX X XXX",
        "         ",
    ];

    for (y, row) in pattern.iter().enumerate() {
        for (x, ch) in row.chars().enumerate() {
            if ch == 'X' {
                img.set_pixel(x as u32, y as u32, black);
            }
        }
    }

    img
}

/// 縦リサイズカーソルを生成
fn create_resize_ns_cursor() -> Image {
    let mut img = Image::new(9, 16);
    let white = Color::WHITE;
    let black = Color::BLACK;

    let pattern = [
        "    X    ",
        "   X.X   ",
        "  X...X  ",
        " X.....X ",
        "XXXXXXXXX",
        "   X.X   ",
        "   X.X   ",
        "   X.X   ",
        "   X.X   ",
        "   X.X   ",
        "XXXXXXXXX",
        " X.....X ",
        "  X...X  ",
        "   X.X   ",
        "    X    ",
        "         ",
    ];

    for (y, row) in pattern.iter().enumerate() {
        for (x, ch) in row.chars().enumerate() {
            let color = match ch {
                'X' => black,
                '.' => white,
                _ => continue,
            };
            img.set_pixel(x as u32, y as u32, color);
        }
    }

    img
}

/// 横リサイズカーソルを生成
fn create_resize_ew_cursor() -> Image {
    let mut img = Image::new(16, 9);
    let white = Color::WHITE;
    let black = Color::BLACK;

    let pattern = [
        "    X    X      ",
        "   XX    XX     ",
        "  X.X    X.X    ",
        " X..XXXXXX..X   ",
        "X............X  ",
        " X..XXXXXX..X   ",
        "  X.X    X.X    ",
        "   XX    XX     ",
        "    X    X      ",
    ];

    for (y, row) in pattern.iter().enumerate() {
        for (x, ch) in row.chars().enumerate() {
            let color = match ch {
                'X' => black,
                '.' => white,
                _ => continue,
            };
            img.set_pixel(x as u32, y as u32, color);
        }
    }

    img
}
