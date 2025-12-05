// ============================================================================
// src/graphics/compositor.rs - Window Compositor with Dirty Rectangles
// ============================================================================
//!
//! # ウィンドウコンポジタ
//!
//! 本格的なウィンドウ合成エンジン
//!
//! ## 機能
//! - ダーティ矩形による部分再描画
//! - マウスカーソルオーバーレイ合成
//! - ウィンドウのドラッグ・リサイズ
//! - アクリル効果（ガウシアンブラー + SIMD）
//! - Z-order管理
//!
//! ## アーキテクチャ
//! ```
//! +-------------------+
//! |   Compositor      |
//! +-------------------+
//! | - windows[]       |
//! | - dirty_regions[] |
//! | - cursor          |
//! | - back_buffer     |
//! +-------------------+
//!         |
//!         v
//! +-------------------+
//! |   Framebuffer     |
//! +-------------------+
//! ```

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use super::image::Image;
use super::{Color, Framebuffer, Point, Rect};

// ============================================================================
// Constants
// ============================================================================

/// 最大ダーティ矩形数（これを超えると全画面再描画）
const MAX_DIRTY_RECTS: usize = 32;

/// タイトルバーの高さ
const TITLE_BAR_HEIGHT: u32 = 28;

/// ウィンドウ境界線の幅
const BORDER_WIDTH: u32 = 1;

/// リサイズハンドルのサイズ
const RESIZE_HANDLE_SIZE: u32 = 8;

/// シャドウサイズ
const SHADOW_SIZE: u32 = 8;

/// ブラー半径（アクリル効果用）
const BLUR_RADIUS: usize = 15;

// ============================================================================
// Dirty Rectangle
// ============================================================================

/// ダーティ矩形（再描画が必要な領域）
#[derive(Clone, Copy, Debug)]
pub struct DirtyRect {
    pub rect: Rect,
    /// 優先度（高いほど先に処理）
    pub priority: u8,
}

impl DirtyRect {
    pub fn new(rect: Rect) -> Self {
        Self { rect, priority: 0 }
    }

    pub fn with_priority(rect: Rect, priority: u8) -> Self {
        Self { rect, priority }
    }
}

/// ダーティリージョンマネージャ
pub struct DirtyRegionManager {
    /// ダーティ矩形リスト
    regions: Vec<DirtyRect>,
    /// 画面サイズ
    screen_width: u32,
    screen_height: u32,
    /// 全画面再描画フラグ
    full_redraw: bool,
}

impl DirtyRegionManager {
    pub fn new(screen_width: u32, screen_height: u32) -> Self {
        Self {
            regions: Vec::with_capacity(MAX_DIRTY_RECTS),
            screen_width,
            screen_height,
            full_redraw: true, // 初回は全画面再描画
        }
    }

    /// ダーティ矩形を追加
    pub fn add_dirty(&mut self, rect: Rect) {
        if self.full_redraw {
            return;
        }

        // 画面外は無視
        let screen_rect = Rect::new(0, 0, self.screen_width, self.screen_height);
        let Some(clipped) = rect.intersection(&screen_rect) else {
            return;
        };

        // 既存の矩形とマージを試みる
        for region in &mut self.regions {
            if let Some(merged) = try_merge_rects(&region.rect, &clipped) {
                region.rect = merged;
                return;
            }
        }

        // 新規追加
        if self.regions.len() < MAX_DIRTY_RECTS {
            self.regions.push(DirtyRect::new(clipped));
        } else {
            // 上限を超えたら全画面再描画
            self.full_redraw = true;
        }
    }

    /// 全画面を無効化
    pub fn invalidate_all(&mut self) {
        self.full_redraw = true;
        self.regions.clear();
    }

    /// ダーティ領域をクリア
    pub fn clear(&mut self) {
        self.regions.clear();
        self.full_redraw = false;
    }

    /// 全画面再描画が必要か
    pub fn needs_full_redraw(&self) -> bool {
        self.full_redraw
    }

    /// ダーティ領域を取得
    pub fn get_dirty_regions(&self) -> &[DirtyRect] {
        &self.regions
    }

    /// 指定矩形と交差するダーティ領域があるか
    pub fn intersects(&self, rect: &Rect) -> bool {
        if self.full_redraw {
            return true;
        }
        self.regions.iter().any(|r| r.rect.intersects(rect))
    }

    /// ダーティ領域を最適化（重複を統合）
    pub fn optimize(&mut self) {
        if self.full_redraw || self.regions.len() <= 1 {
            return;
        }

        let mut optimized = Vec::with_capacity(self.regions.len());
        let mut used = vec![false; self.regions.len()];

        for i in 0..self.regions.len() {
            if used[i] {
                continue;
            }

            let mut current = self.regions[i].rect;
            used[i] = true;

            // 他の矩形とマージを試みる
            loop {
                let mut merged = false;
                for j in 0..self.regions.len() {
                    if used[j] {
                        continue;
                    }

                    if let Some(m) = try_merge_rects(&current, &self.regions[j].rect) {
                        current = m;
                        used[j] = true;
                        merged = true;
                    }
                }

                if !merged {
                    break;
                }
            }

            optimized.push(DirtyRect::new(current));
        }

        self.regions = optimized;
    }
}

/// 2つの矩形をマージ（近い場合のみ）
fn try_merge_rects(a: &Rect, b: &Rect) -> Option<Rect> {
    // 交差または隣接している場合はマージ
    let gap = 16; // マージ許容ギャップ

    let a_right = a.x + a.width as i32;
    let a_bottom = a.y + a.height as i32;
    let b_right = b.x + b.width as i32;
    let b_bottom = b.y + b.height as i32;

    // 隣接チェック（ギャップを考慮）
    if a_right + gap < b.x || b_right + gap < a.x {
        return None;
    }
    if a_bottom + gap < b.y || b_bottom + gap < a.y {
        return None;
    }

    // マージした矩形を計算
    let x = a.x.min(b.x);
    let y = a.y.min(b.y);
    let right = a_right.max(b_right);
    let bottom = a_bottom.max(b_bottom);

    // マージ後のサイズが妥当かチェック（無駄な領域が増えすぎないように）
    let merged_area = (right - x) * (bottom - y);
    let original_area = (a.width * a.height + b.width * b.height) as i32;

    if merged_area <= original_area * 2 {
        Some(Rect::new(x, y, (right - x) as u32, (bottom - y) as u32))
    } else {
        None
    }
}

// ============================================================================
// Window ID
// ============================================================================

/// コンポジタウィンドウID
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompositorWindowId(pub u32);

impl CompositorWindowId {
    pub const INVALID: Self = Self(0);
    pub const ROOT: Self = Self(u32::MAX);

    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn is_valid(&self) -> bool {
        self.0 != 0 && self.0 != u32::MAX
    }
}

// ============================================================================
// Z-Order
// ============================================================================

/// Z-Order（描画順序）
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZOrder(pub i32);

impl ZOrder {
    pub const BACKGROUND: Self = Self(-1000);
    pub const NORMAL: Self = Self(0);
    pub const ABOVE_NORMAL: Self = Self(100);
    pub const TOPMOST: Self = Self(1000);
    pub const SYSTEM: Self = Self(10000);
    pub const CURSOR: Self = Self(i32::MAX);
}

// ============================================================================
// Window Style
// ============================================================================

/// ウィンドウスタイル
#[derive(Clone, Copy, Debug)]
pub struct CompositorWindowStyle {
    /// 境界線を表示
    pub border: bool,
    /// タイトルバーを表示
    pub title_bar: bool,
    /// 閉じるボタン
    pub close_button: bool,
    /// 最小化ボタン
    pub minimize_button: bool,
    /// 最大化ボタン
    pub maximize_button: bool,
    /// リサイズ可能
    pub resizable: bool,
    /// 常に最前面
    pub topmost: bool,
    /// シャドウを表示
    pub shadow: bool,
    /// アクリル効果（背景ぼかし）
    pub acrylic: bool,
    /// 透明度
    pub opacity: u8,
}

impl Default for CompositorWindowStyle {
    fn default() -> Self {
        Self {
            border: true,
            title_bar: true,
            close_button: true,
            minimize_button: true,
            maximize_button: true,
            resizable: true,
            topmost: false,
            shadow: true,
            acrylic: false,
            opacity: 255,
        }
    }
}

impl CompositorWindowStyle {
    /// ボーダーレスウィンドウ
    pub fn borderless() -> Self {
        Self {
            border: false,
            title_bar: false,
            close_button: false,
            minimize_button: false,
            maximize_button: false,
            resizable: false,
            topmost: false,
            shadow: false,
            acrylic: false,
            opacity: 255,
        }
    }

    /// ダイアログスタイル
    pub fn dialog() -> Self {
        Self {
            border: true,
            title_bar: true,
            close_button: true,
            minimize_button: false,
            maximize_button: false,
            resizable: false,
            topmost: false,
            shadow: true,
            acrylic: false,
            opacity: 255,
        }
    }

    /// アクリルウィンドウ
    pub fn acrylic() -> Self {
        Self {
            border: true,
            title_bar: true,
            close_button: true,
            minimize_button: true,
            maximize_button: true,
            resizable: true,
            topmost: false,
            shadow: true,
            acrylic: true,
            opacity: 220,
        }
    }
}

// ============================================================================
// Window State
// ============================================================================

/// ウィンドウ状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositorWindowState {
    Normal,
    Minimized,
    Maximized,
    Hidden,
}

// ============================================================================
// Mouse Cursor
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
    pub fn position(&self) -> (i32, i32) {
        (self.x, self.y)
    }

    /// カーソルタイプを設定
    pub fn set_cursor_type(&mut self, cursor_type: CursorType) {
        self.cursor_type = cursor_type;
    }

    /// カーソルタイプを取得
    pub fn cursor_type(&self) -> CursorType {
        self.cursor_type
    }

    /// 可視性を設定
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// 可視性を取得
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

// ============================================================================
// Compositor Window
// ============================================================================

/// コンポジタウィンドウ
pub struct CompositorWindow {
    /// ウィンドウID
    id: CompositorWindowId,
    /// タイトル
    title: alloc::string::String,
    /// ウィンドウ矩形（装飾含む）
    rect: Rect,
    /// クライアント領域
    client_rect: Rect,
    /// スタイル
    style: CompositorWindowStyle,
    /// 状態
    state: CompositorWindowState,
    /// Z-Order
    z_order: ZOrder,
    /// コンテンツバッファ
    content: Image,
    /// 合成済みバッファ（装飾含む）
    composed: Image,
    /// ダーティフラグ
    dirty: bool,
    /// 装飾ダーティフラグ
    decoration_dirty: bool,
    /// 可視性
    visible: bool,
    /// 前回の矩形（移動・リサイズ時のダーティ領域用）
    prev_rect: Rect,
    /// 最小サイズ
    min_size: (u32, u32),
    /// 最大サイズ
    max_size: (u32, u32),
    /// リストア用サイズ（最大化前）
    restore_rect: Option<Rect>,
}

impl CompositorWindow {
    /// 新しいウィンドウを作成
    pub fn new(
        id: CompositorWindowId,
        title: &str,
        rect: Rect,
        style: CompositorWindowStyle,
    ) -> Self {
        let client_rect = Self::calculate_client_rect(&rect, &style);
        let content = Image::filled(client_rect.width, client_rect.height, Color::WHITE);
        let composed = Image::new(rect.width, rect.height);

        Self {
            id,
            title: alloc::string::String::from(title),
            rect,
            client_rect,
            style,
            state: CompositorWindowState::Normal,
            z_order: if style.topmost {
                ZOrder::TOPMOST
            } else {
                ZOrder::NORMAL
            },
            content,
            composed,
            dirty: true,
            decoration_dirty: true,
            visible: true,
            prev_rect: rect,
            min_size: (100, 50),
            max_size: (u32::MAX, u32::MAX),
            restore_rect: None,
        }
    }

    /// クライアント領域を計算
    fn calculate_client_rect(rect: &Rect, style: &CompositorWindowStyle) -> Rect {
        let mut x = rect.x;
        let mut y = rect.y;
        let mut width = rect.width;
        let mut height = rect.height;

        if style.border {
            x += BORDER_WIDTH as i32;
            y += BORDER_WIDTH as i32;
            width = width.saturating_sub(BORDER_WIDTH * 2);
            height = height.saturating_sub(BORDER_WIDTH * 2);
        }

        if style.title_bar {
            y += TITLE_BAR_HEIGHT as i32;
            height = height.saturating_sub(TITLE_BAR_HEIGHT);
        }

        Rect::new(x, y, width.max(1), height.max(1))
    }

    // Accessor methods
    pub fn id(&self) -> CompositorWindowId {
        self.id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn set_title(&mut self, title: &str) {
        self.title = alloc::string::String::from(title);
        self.decoration_dirty = true;
    }

    pub fn rect(&self) -> Rect {
        self.rect
    }

    pub fn client_rect(&self) -> Rect {
        self.client_rect
    }

    pub fn style(&self) -> &CompositorWindowStyle {
        &self.style
    }

    pub fn state(&self) -> CompositorWindowState {
        self.state
    }

    pub fn z_order(&self) -> ZOrder {
        self.z_order
    }

    pub fn set_z_order(&mut self, z_order: ZOrder) {
        self.z_order = z_order;
    }

    pub fn is_visible(&self) -> bool {
        self.visible && self.state != CompositorWindowState::Hidden
    }

    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    pub fn content(&self) -> &Image {
        &self.content
    }

    pub fn content_mut(&mut self) -> &mut Image {
        self.dirty = true;
        &mut self.content
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty || self.decoration_dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false;
        self.decoration_dirty = false;
    }

    pub fn invalidate(&mut self) {
        self.dirty = true;
    }

    /// ウィンドウを移動
    pub fn move_to(&mut self, x: i32, y: i32) {
        self.prev_rect = self.rect;
        self.rect.x = x;
        self.rect.y = y;
        self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);
    }

    /// ウィンドウをリサイズ
    pub fn resize(&mut self, width: u32, height: u32) {
        let width = width.clamp(self.min_size.0, self.max_size.0);
        let height = height.clamp(self.min_size.1, self.max_size.1);

        self.prev_rect = self.rect;
        self.rect.width = width;
        self.rect.height = height;
        self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);

        // コンテンツバッファをリサイズ
        let new_content = Image::filled(
            self.client_rect.width,
            self.client_rect.height,
            Color::WHITE,
        );
        // 古いコンテンツをコピー（可能な範囲で）
        self.content = new_content;
        self.dirty = true;
        self.decoration_dirty = true;
    }

    /// 点がウィンドウ内にあるか
    pub fn contains(&self, x: i32, y: i32) -> bool {
        self.rect.contains(Point::new(x, y))
    }

    /// 点がタイトルバー内にあるか
    pub fn title_bar_contains(&self, x: i32, y: i32) -> bool {
        if !self.style.title_bar {
            return false;
        }

        let title_bar = Rect::new(
            self.rect.x + BORDER_WIDTH as i32,
            self.rect.y + BORDER_WIDTH as i32,
            self.rect.width - BORDER_WIDTH * 2,
            TITLE_BAR_HEIGHT,
        );

        title_bar.contains(Point::new(x, y))
    }

    /// リサイズエッジを検出
    pub fn get_resize_edge(&self, x: i32, y: i32) -> Option<ResizeEdge> {
        if !self.style.resizable {
            return None;
        }

        let r = &self.rect;
        let handle = RESIZE_HANDLE_SIZE as i32;

        let on_left = x >= r.x && x < r.x + handle;
        let on_right = x >= r.right() - handle && x < r.right();
        let on_top = y >= r.y && y < r.y + handle;
        let on_bottom = y >= r.bottom() - handle && y < r.bottom();

        match (on_left, on_right, on_top, on_bottom) {
            (true, false, true, false) => Some(ResizeEdge::TopLeft),
            (false, true, true, false) => Some(ResizeEdge::TopRight),
            (true, false, false, true) => Some(ResizeEdge::BottomLeft),
            (false, true, false, true) => Some(ResizeEdge::BottomRight),
            (true, false, false, false) => Some(ResizeEdge::Left),
            (false, true, false, false) => Some(ResizeEdge::Right),
            (false, false, true, false) => Some(ResizeEdge::Top),
            (false, false, false, true) => Some(ResizeEdge::Bottom),
            _ => None,
        }
    }

    /// 閉じるボタンの矩形を取得
    pub fn close_button_rect(&self) -> Option<Rect> {
        if !self.style.close_button || !self.style.title_bar {
            return None;
        }

        Some(Rect::new(
            self.rect.right() - BORDER_WIDTH as i32 - 32,
            self.rect.y + BORDER_WIDTH as i32 + 2,
            28,
            24,
        ))
    }

    /// 最大化
    pub fn maximize(&mut self, screen_width: u32, screen_height: u32) {
        if self.state == CompositorWindowState::Maximized {
            return;
        }

        self.restore_rect = Some(self.rect);
        self.state = CompositorWindowState::Maximized;
        self.prev_rect = self.rect;
        self.rect = Rect::new(0, 0, screen_width, screen_height);
        self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);

        let new_content = Image::filled(
            self.client_rect.width,
            self.client_rect.height,
            Color::WHITE,
        );
        self.content = new_content;
        self.dirty = true;
        self.decoration_dirty = true;
    }

    /// 通常サイズに戻す
    pub fn restore(&mut self) {
        if let Some(rect) = self.restore_rect.take() {
            self.prev_rect = self.rect;
            self.rect = rect;
            self.state = CompositorWindowState::Normal;
            self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);

            let new_content = Image::filled(
                self.client_rect.width,
                self.client_rect.height,
                Color::WHITE,
            );
            self.content = new_content;
            self.dirty = true;
            self.decoration_dirty = true;
        }
    }

    /// スクリーン座標をクライアント座標に変換
    pub fn screen_to_client(&self, x: i32, y: i32) -> (i32, i32) {
        (x - self.client_rect.x, y - self.client_rect.y)
    }
}

// ============================================================================
// Resize Edge
// ============================================================================

/// リサイズエッジ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeEdge {
    Top,
    Bottom,
    Left,
    Right,
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
}

impl ResizeEdge {
    /// エッジに対応するカーソルタイプ
    pub fn cursor_type(&self) -> CursorType {
        match self {
            ResizeEdge::Top | ResizeEdge::Bottom => CursorType::ResizeNS,
            ResizeEdge::Left | ResizeEdge::Right => CursorType::ResizeEW,
            ResizeEdge::TopLeft | ResizeEdge::BottomRight => CursorType::ResizeNWSE,
            ResizeEdge::TopRight | ResizeEdge::BottomLeft => CursorType::ResizeNESW,
        }
    }
}

// ============================================================================
// Drag State
// ============================================================================

/// ドラッグ状態
#[derive(Clone, Copy, Debug)]
pub enum DragState {
    /// ドラッグなし
    None,
    /// ウィンドウ移動中
    Moving {
        window_id: CompositorWindowId,
        offset_x: i32,
        offset_y: i32,
    },
    /// ウィンドウリサイズ中
    Resizing {
        window_id: CompositorWindowId,
        edge: ResizeEdge,
        start_rect: Rect,
        start_x: i32,
        start_y: i32,
    },
}

// ============================================================================
// Compositor
// ============================================================================

/// ウィンドウコンポジタ
pub struct Compositor {
    /// ウィンドウマップ
    windows: BTreeMap<CompositorWindowId, CompositorWindow>,
    /// Z-orderリスト（下から上へ）
    z_order_list: Vec<CompositorWindowId>,
    /// 次のウィンドウID
    next_id: AtomicU32,
    /// フォーカスを持つウィンドウ
    focused: Option<CompositorWindowId>,
    /// ドラッグ状態
    drag_state: DragState,
    /// マウスカーソル
    cursor: MouseCursor,
    /// ダーティリージョンマネージャ
    dirty_manager: DirtyRegionManager,
    /// バックバッファ
    back_buffer: Image,
    /// 壁紙
    wallpaper: Option<Image>,
    /// デスクトップ色
    desktop_color: Color,
    /// 画面サイズ
    screen_width: u32,
    screen_height: u32,
    /// ブラー用一時バッファ
    blur_buffer: Image,
}

impl Compositor {
    /// 新しいコンポジタを作成
    pub fn new(screen_width: u32, screen_height: u32) -> Self {
        Self {
            windows: BTreeMap::new(),
            z_order_list: Vec::new(),
            next_id: AtomicU32::new(1),
            focused: None,
            drag_state: DragState::None,
            cursor: MouseCursor::new(),
            dirty_manager: DirtyRegionManager::new(screen_width, screen_height),
            back_buffer: Image::new(screen_width, screen_height),
            wallpaper: None,
            desktop_color: Color::new(0, 120, 215),
            screen_width,
            screen_height,
            blur_buffer: Image::new(screen_width, screen_height),
        }
    }

    /// ウィンドウを作成
    pub fn create_window(
        &mut self,
        title: &str,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        style: CompositorWindowStyle,
    ) -> CompositorWindowId {
        let id = CompositorWindowId::new(self.next_id.fetch_add(1, Ordering::SeqCst));
        let rect = Rect::new(x, y, width, height);
        let window = CompositorWindow::new(id, title, rect, style);

        // ダーティ領域に追加
        self.dirty_manager.add_dirty(rect);

        self.windows.insert(id, window);
        self.insert_z_order(id);
        self.focused = Some(id);

        id
    }

    /// ウィンドウを破棄
    pub fn destroy_window(&mut self, id: CompositorWindowId) {
        if let Some(window) = self.windows.remove(&id) {
            // ダーティ領域に追加
            self.dirty_manager.add_dirty(window.rect());
        }

        self.z_order_list.retain(|&wid| wid != id);

        if self.focused == Some(id) {
            self.focused = self.z_order_list.last().copied();
        }

        if let DragState::Moving { window_id, .. } | DragState::Resizing { window_id, .. } =
            self.drag_state
        {
            if window_id == id {
                self.drag_state = DragState::None;
            }
        }
    }

    /// Z-orderリストに挿入
    fn insert_z_order(&mut self, id: CompositorWindowId) {
        let z_order = self.windows.get(&id).map(|w| w.z_order()).unwrap_or(ZOrder::NORMAL);

        // 適切な位置を見つける
        let mut insert_pos = self.z_order_list.len();
        for (i, &other_id) in self.z_order_list.iter().enumerate() {
            if let Some(other) = self.windows.get(&other_id) {
                if other.z_order() > z_order {
                    insert_pos = i;
                    break;
                }
            }
        }

        self.z_order_list.insert(insert_pos, id);
    }

    /// ウィンドウを取得
    pub fn get_window(&self, id: CompositorWindowId) -> Option<&CompositorWindow> {
        self.windows.get(&id)
    }

    /// ウィンドウをミュータブルに取得
    pub fn get_window_mut(&mut self, id: CompositorWindowId) -> Option<&mut CompositorWindow> {
        self.windows.get_mut(&id)
    }

    /// フォーカスウィンドウを取得
    pub fn focused_window(&self) -> Option<CompositorWindowId> {
        self.focused
    }

    /// フォーカスを設定
    pub fn set_focus(&mut self, id: CompositorWindowId) {
        if !self.windows.contains_key(&id) {
            return;
        }

        self.focused = Some(id);
        self.bring_to_front(id);
    }

    /// ウィンドウを最前面に
    pub fn bring_to_front(&mut self, id: CompositorWindowId) {
        // 既存の位置から削除
        self.z_order_list.retain(|&wid| wid != id);

        // 再挿入（同じZ-orderの最後に）
        if let Some(window) = self.windows.get(&id) {
            let z_order = window.z_order();

            let mut insert_pos = self.z_order_list.len();
            for (i, &other_id) in self.z_order_list.iter().enumerate() {
                if let Some(other) = self.windows.get(&other_id) {
                    if other.z_order() > z_order {
                        insert_pos = i;
                        break;
                    }
                }
            }

            self.z_order_list.insert(insert_pos, id);

            // ダーティ領域に追加
            self.dirty_manager.add_dirty(window.rect());
        }
    }

    /// 点の下にあるウィンドウを検索（上から）
    pub fn window_at(&self, x: i32, y: i32) -> Option<CompositorWindowId> {
        for &id in self.z_order_list.iter().rev() {
            if let Some(window) = self.windows.get(&id) {
                if window.is_visible() && window.contains(x, y) {
                    return Some(id);
                }
            }
        }
        None
    }

    /// 壁紙を設定
    pub fn set_wallpaper(&mut self, wallpaper: Image) {
        self.wallpaper = Some(wallpaper.resize_bilinear(self.screen_width, self.screen_height));
        self.dirty_manager.invalidate_all();
    }

    /// デスクトップ色を設定
    pub fn set_desktop_color(&mut self, color: Color) {
        self.desktop_color = color;
        self.dirty_manager.invalidate_all();
    }

    /// マウスカーソルを取得
    pub fn cursor(&self) -> &MouseCursor {
        &self.cursor
    }

    /// マウスカーソルをミュータブルに取得
    pub fn cursor_mut(&mut self) -> &mut MouseCursor {
        &mut self.cursor
    }

    // ========================================================================
    // Input Handling
    // ========================================================================

    /// マウス移動を処理
    pub fn handle_mouse_move(&mut self, x: i32, y: i32) {
        // 前回のカーソル位置をダーティに
        self.dirty_manager.add_dirty(self.cursor.get_rect());

        // カーソル位置を更新
        self.cursor.set_position(x, y);

        // 新しいカーソル位置をダーティに
        self.dirty_manager.add_dirty(self.cursor.get_rect());

        // ドラッグ処理
        match self.drag_state {
            DragState::Moving {
                window_id,
                offset_x,
                offset_y,
            } => {
                if let Some(window) = self.windows.get_mut(&window_id) {
                    // 前の位置をダーティに
                    self.dirty_manager.add_dirty(window.rect());

                    window.move_to(x - offset_x, y - offset_y);

                    // 新しい位置をダーティに
                    self.dirty_manager.add_dirty(window.rect());
                }
                return;
            }
            DragState::Resizing {
                window_id,
                edge,
                start_rect,
                start_x,
                start_y,
            } => {
                self.do_resize(window_id, edge, start_rect, x - start_x, y - start_y);
                return;
            }
            DragState::None => {}
        }

        // カーソルタイプを更新
        if let Some(id) = self.window_at(x, y) {
            if let Some(window) = self.windows.get(&id) {
                if let Some(edge) = window.get_resize_edge(x, y) {
                    self.cursor.set_cursor_type(edge.cursor_type());
                } else if window.title_bar_contains(x, y) {
                    self.cursor.set_cursor_type(CursorType::Arrow);
                } else {
                    self.cursor.set_cursor_type(CursorType::Arrow);
                }
            }
        } else {
            self.cursor.set_cursor_type(CursorType::Arrow);
        }
    }

    /// マウスボタン押下を処理
    pub fn handle_mouse_down(&mut self, x: i32, y: i32, button: u8) {
        if button != 0 {
            // 左クリック以外
            return;
        }

        if let Some(id) = self.window_at(x, y) {
            self.set_focus(id);

            if let Some(window) = self.windows.get(&id) {
                // リサイズエッジのチェック
                if let Some(edge) = window.get_resize_edge(x, y) {
                    self.drag_state = DragState::Resizing {
                        window_id: id,
                        edge,
                        start_rect: window.rect(),
                        start_x: x,
                        start_y: y,
                    };
                    return;
                }

                // 閉じるボタンのチェック
                if let Some(close_rect) = window.close_button_rect() {
                    if close_rect.contains(Point::new(x, y)) {
                        self.destroy_window(id);
                        return;
                    }
                }

                // タイトルバードラッグ
                if window.title_bar_contains(x, y) {
                    let rect = window.rect();
                    self.drag_state = DragState::Moving {
                        window_id: id,
                        offset_x: x - rect.x,
                        offset_y: y - rect.y,
                    };
                    return;
                }
            }
        }
    }

    /// マウスボタン解放を処理
    pub fn handle_mouse_up(&mut self, _x: i32, _y: i32, _button: u8) {
        self.drag_state = DragState::None;
    }

    /// リサイズを実行
    fn do_resize(
        &mut self,
        window_id: CompositorWindowId,
        edge: ResizeEdge,
        start_rect: Rect,
        dx: i32,
        dy: i32,
    ) {
        if let Some(window) = self.windows.get_mut(&window_id) {
            // 前の位置をダーティに
            self.dirty_manager.add_dirty(window.rect());

            let mut new_rect = start_rect;

            match edge {
                ResizeEdge::Top => {
                    new_rect.y += dy;
                    new_rect.height = (start_rect.height as i32 - dy).max(50) as u32;
                }
                ResizeEdge::Bottom => {
                    new_rect.height = (start_rect.height as i32 + dy).max(50) as u32;
                }
                ResizeEdge::Left => {
                    new_rect.x += dx;
                    new_rect.width = (start_rect.width as i32 - dx).max(100) as u32;
                }
                ResizeEdge::Right => {
                    new_rect.width = (start_rect.width as i32 + dx).max(100) as u32;
                }
                ResizeEdge::TopLeft => {
                    new_rect.x += dx;
                    new_rect.y += dy;
                    new_rect.width = (start_rect.width as i32 - dx).max(100) as u32;
                    new_rect.height = (start_rect.height as i32 - dy).max(50) as u32;
                }
                ResizeEdge::TopRight => {
                    new_rect.y += dy;
                    new_rect.width = (start_rect.width as i32 + dx).max(100) as u32;
                    new_rect.height = (start_rect.height as i32 - dy).max(50) as u32;
                }
                ResizeEdge::BottomLeft => {
                    new_rect.x += dx;
                    new_rect.width = (start_rect.width as i32 - dx).max(100) as u32;
                    new_rect.height = (start_rect.height as i32 + dy).max(50) as u32;
                }
                ResizeEdge::BottomRight => {
                    new_rect.width = (start_rect.width as i32 + dx).max(100) as u32;
                    new_rect.height = (start_rect.height as i32 + dy).max(50) as u32;
                }
            }

            window.prev_rect = window.rect();
            window.rect = new_rect;
            window.client_rect =
                CompositorWindow::calculate_client_rect(&new_rect, &window.style);

            // コンテンツバッファをリサイズ
            window.content = Image::filled(
                window.client_rect.width,
                window.client_rect.height,
                Color::WHITE,
            );
            window.dirty = true;
            window.decoration_dirty = true;

            // 新しい位置をダーティに
            self.dirty_manager.add_dirty(window.rect());
        }
    }

    // ========================================================================
    // Composition
    // ========================================================================

    /// フレームバッファに合成（ダーティ矩形最適化版）
    pub fn compose(&mut self, fb: &mut Framebuffer) {
        // ダーティ領域を最適化
        self.dirty_manager.optimize();

        if self.dirty_manager.needs_full_redraw() {
            // 全画面再描画
            self.compose_full(fb);
        } else {
            // 部分再描画
            self.compose_partial(fb);
        }

        // ダーティ領域をクリア
        self.dirty_manager.clear();

        // ウィンドウのダーティフラグをクリア
        for window in self.windows.values_mut() {
            window.mark_clean();
        }
    }

    /// 全画面再描画
    fn compose_full(&mut self, fb: &mut Framebuffer) {
        // デスクトップ背景を描画
        self.draw_desktop();

        // ウィンドウをZ-order順に描画
        for &id in &self.z_order_list.clone() {
            if let Some(window) = self.windows.get(&id) {
                if window.is_visible() {
                    self.draw_window_to_back_buffer(id);
                }
            }
        }

        // マウスカーソルを描画
        self.cursor.draw(&mut self.back_buffer);

        // バックバッファをフレームバッファにコピー
        self.copy_to_framebuffer(fb, None);
    }

    /// 部分再描画
    fn compose_partial(&mut self, fb: &mut Framebuffer) {
        let dirty_regions: Vec<DirtyRect> = self.dirty_manager.get_dirty_regions().to_vec();

        for dirty in &dirty_regions {
            // 各ダーティ領域について、影響するウィンドウを再描画
            self.draw_desktop_region(dirty.rect);

            for &id in &self.z_order_list.clone() {
                if let Some(window) = self.windows.get(&id) {
                    if window.is_visible() && window.rect().intersects(&dirty.rect) {
                        self.draw_window_region_to_back_buffer(id, dirty.rect);
                    }
                }
            }
        }

        // マウスカーソルを描画
        self.cursor.draw(&mut self.back_buffer);

        // ダーティ領域のみをフレームバッファにコピー
        for dirty in &dirty_regions {
            self.copy_to_framebuffer(fb, Some(dirty.rect));
        }

        // カーソル領域もコピー
        self.copy_to_framebuffer(fb, Some(self.cursor.get_rect()));
    }

    /// デスクトップ背景を描画
    fn draw_desktop(&mut self) {
        if let Some(ref wallpaper) = self.wallpaper {
            self.back_buffer.blit(wallpaper, 0, 0);
        } else {
            self.back_buffer
                .fill_rect(Rect::new(0, 0, self.screen_width, self.screen_height), self.desktop_color);
        }
    }

    /// デスクトップ背景の一部を描画
    fn draw_desktop_region(&mut self, region: Rect) {
        if let Some(ref wallpaper) = self.wallpaper {
            // 壁紙から領域をコピー
            for y in region.y.max(0)..(region.y + region.height as i32).min(self.screen_height as i32)
            {
                for x in region.x.max(0)..(region.x + region.width as i32).min(self.screen_width as i32)
                {
                    let color = wallpaper.get_pixel(x as u32, y as u32);
                    self.back_buffer.set_pixel(x as u32, y as u32, color);
                }
            }
        } else {
            self.back_buffer.fill_rect(region, self.desktop_color);
        }
    }

    /// ウィンドウをバックバッファに描画
    fn draw_window_to_back_buffer(&mut self, id: CompositorWindowId) {
        // ウィンドウデータを取得
        let (rect, client_rect, style, is_focused, title, content_clone, acrylic) = {
            let window = match self.windows.get(&id) {
                Some(w) => w,
                None => return,
            };
            (
                window.rect(),
                window.client_rect(),
                *window.style(),
                self.focused == Some(id),
                window.title.clone(),
                window.content.clone(),
                window.style.acrylic,
            )
        };

        // シャドウを描画
        if style.shadow {
            self.draw_shadow(rect);
        }

        // アクリル効果
        if acrylic {
            self.apply_acrylic_effect(rect);
        }

        // ウィンドウ装飾を描画
        self.draw_window_decoration(rect, &style, is_focused, &title);

        // コンテンツを描画
        self.back_buffer.blit(&content_clone, client_rect.x, client_rect.y);
    }

    /// ウィンドウの一部をバックバッファに描画
    fn draw_window_region_to_back_buffer(&mut self, id: CompositorWindowId, region: Rect) {
        // 簡略化: 領域と交差するウィンドウ全体を再描画
        self.draw_window_to_back_buffer(id);
    }

    /// ウィンドウ装飾を描画
    fn draw_window_decoration(&mut self, rect: Rect, style: &CompositorWindowStyle, is_focused: bool, title: &str) {
        let title_bar_color = if is_focused {
            Color::new(0, 120, 215) // アクティブ（青）
        } else {
            Color::new(128, 128, 128) // 非アクティブ（灰色）
        };

        let border_color = Color::new(100, 100, 100);
        let bg_color = Color::new(240, 240, 240);

        // 境界線
        if style.border {
            // 外枠
            for x in rect.x..(rect.x + rect.width as i32) {
                self.back_buffer.set_pixel(x as u32, rect.y as u32, border_color);
                self.back_buffer
                    .set_pixel(x as u32, (rect.y + rect.height as i32 - 1) as u32, border_color);
            }
            for y in rect.y..(rect.y + rect.height as i32) {
                self.back_buffer.set_pixel(rect.x as u32, y as u32, border_color);
                self.back_buffer
                    .set_pixel((rect.x + rect.width as i32 - 1) as u32, y as u32, border_color);
            }
        }

        // タイトルバー
        if style.title_bar {
            let title_rect = Rect::new(
                rect.x + BORDER_WIDTH as i32,
                rect.y + BORDER_WIDTH as i32,
                rect.width - BORDER_WIDTH * 2,
                TITLE_BAR_HEIGHT,
            );
            self.back_buffer.fill_rect(title_rect, title_bar_color);

            // 閉じるボタン
            if style.close_button {
                let btn_x = rect.x + rect.width as i32 - BORDER_WIDTH as i32 - 32;
                let btn_y = rect.y + BORDER_WIDTH as i32 + 2;
                let btn_rect = Rect::new(btn_x, btn_y, 28, 24);

                // ボタン背景（ホバー時は赤）
                self.back_buffer.fill_rect(btn_rect, Color::new(196, 43, 28));

                // X マーク
                let cx = btn_x + 14;
                let cy = btn_y + 12;
                let white = Color::WHITE;
                for i in -5..=5 {
                    self.back_buffer.set_pixel((cx + i) as u32, (cy + i) as u32, white);
                    self.back_buffer.set_pixel((cx + i) as u32, (cy - i) as u32, white);
                }
            }
        }

        // クライアント領域の背景
        let client_bg_rect = Rect::new(
            rect.x + BORDER_WIDTH as i32,
            rect.y + BORDER_WIDTH as i32 + if style.title_bar { TITLE_BAR_HEIGHT as i32 } else { 0 },
            rect.width - BORDER_WIDTH * 2,
            rect.height - BORDER_WIDTH * 2 - if style.title_bar { TITLE_BAR_HEIGHT } else { 0 },
        );
        // アクリル効果がない場合のみ背景を描画
        if !style.acrylic {
            self.back_buffer.fill_rect(client_bg_rect, bg_color);
        }
    }

    /// シャドウを描画
    fn draw_shadow(&mut self, rect: Rect) {
        let shadow_color_base = Color::new(0, 0, 0);

        // 右側と下側にシャドウ
        for i in 1..=SHADOW_SIZE as i32 {
            let alpha = (255 * (SHADOW_SIZE as i32 - i) / SHADOW_SIZE as i32) as u8 / 3;
            let shadow_color = Color::new(
                shadow_color_base.red,
                shadow_color_base.green,
                shadow_color_base.blue,
            );
            // 実際はアルファブレンディングが必要だが、簡略化
            let dimmed = Color::new(
                (shadow_color.red as u32 * alpha as u32 / 255) as u8,
                (shadow_color.green as u32 * alpha as u32 / 255) as u8,
                (shadow_color.blue as u32 * alpha as u32 / 255) as u8,
            );

            // 右側
            for y in rect.y..(rect.y + rect.height as i32 + i) {
                let x = rect.x + rect.width as i32 + i - 1;
                if x >= 0 && y >= 0 {
                    self.back_buffer.blend_pixel(x as u32, y as u32, dimmed);
                }
            }

            // 下側
            for x in rect.x..(rect.x + rect.width as i32 + i) {
                let y = rect.y + rect.height as i32 + i - 1;
                if x >= 0 && y >= 0 {
                    self.back_buffer.blend_pixel(x as u32, y as u32, dimmed);
                }
            }
        }
    }

    /// バックバッファをフレームバッファにコピー
    fn copy_to_framebuffer(&self, fb: &mut Framebuffer, region: Option<Rect>) {
        let region = region.unwrap_or(Rect::new(0, 0, self.screen_width, self.screen_height));

        // 画面範囲にクリップ
        let x_start = region.x.max(0) as u32;
        let y_start = region.y.max(0) as u32;
        let x_end = (region.x + region.width as i32).min(self.screen_width as i32) as u32;
        let y_end = (region.y + region.height as i32).min(self.screen_height as i32) as u32;

        for y in y_start..y_end {
            for x in x_start..x_end {
                let color = self.back_buffer.get_pixel(x, y);
                fb.set_pixel(x as i32, y as i32, color);
            }
        }
    }

    /// 全画面を無効化
    pub fn invalidate_all(&mut self) {
        self.dirty_manager.invalidate_all();
    }

    /// 画面サイズを取得
    pub fn screen_size(&self) -> (u32, u32) {
        (self.screen_width, self.screen_height)
    }

    // ========================================================================
    // Acrylic Effect (Gaussian Blur with SIMD)
    // ========================================================================

    /// アクリル効果を適用
    fn apply_acrylic_effect(&mut self, rect: Rect) {
        // 背景領域をブラーバッファにコピー
        let clipped = rect.intersection(&Rect::new(0, 0, self.screen_width, self.screen_height));
        let Some(region) = clipped else { return };

        // 領域をブラーバッファにコピー
        for y in region.y.max(0)..(region.y + region.height as i32).min(self.screen_height as i32) {
            for x in region.x.max(0)..(region.x + region.width as i32).min(self.screen_width as i32) {
                let color = self.back_buffer.get_pixel(x as u32, y as u32);
                self.blur_buffer.set_pixel(x as u32, y as u32, color);
            }
        }

        // ガウシアンブラーを適用
        self.gaussian_blur_region(region);

        // ブラー結果をバックバッファにコピー（半透明で重ねる）
        let tint = Color::new(255, 255, 255); // 白いティント
        let tint_alpha = 180u8;

        for y in region.y.max(0)..(region.y + region.height as i32).min(self.screen_height as i32) {
            for x in region.x.max(0)..(region.x + region.width as i32).min(self.screen_width as i32) {
                let blurred = self.blur_buffer.get_pixel(x as u32, y as u32);
                
                // ティントとブレンド
                let r = ((blurred.red as u32 * (255 - tint_alpha) as u32
                    + tint.red as u32 * tint_alpha as u32)
                    / 255) as u8;
                let g = ((blurred.green as u32 * (255 - tint_alpha) as u32
                    + tint.green as u32 * tint_alpha as u32)
                    / 255) as u8;
                let b = ((blurred.blue as u32 * (255 - tint_alpha) as u32
                    + tint.blue as u32 * tint_alpha as u32)
                    / 255) as u8;

                self.back_buffer.set_pixel(x as u32, y as u32, Color::new(r, g, b));
            }
        }
    }

    /// ガウシアンブラーを領域に適用
    fn gaussian_blur_region(&mut self, region: Rect) {
        // 高速近似: Box blur を3回適用（ガウシアンに近似）
        for _ in 0..3 {
            self.box_blur_horizontal(region);
            self.box_blur_vertical(region);
        }
    }

    /// 水平方向ボックスブラー
    fn box_blur_horizontal(&mut self, region: Rect) {
        let radius = BLUR_RADIUS as i32;
        let diameter = radius * 2 + 1;

        let y_start = region.y.max(0);
        let y_end = (region.y + region.height as i32).min(self.screen_height as i32);
        let x_start = region.x.max(0);
        let x_end = (region.x + region.width as i32).min(self.screen_width as i32);

        // 一時バッファ（行ごとに処理）
        let mut row_buffer: Vec<Color> = vec![Color::BLACK; self.screen_width as usize];

        for y in y_start..y_end {
            // 累積和を計算
            let mut sum_r: i32 = 0;
            let mut sum_g: i32 = 0;
            let mut sum_b: i32 = 0;

            // 初期ウィンドウ
            for x in (x_start - radius)..(x_start + radius + 1) {
                let sx = x.clamp(0, self.screen_width as i32 - 1);
                let c = self.blur_buffer.get_pixel(sx as u32, y as u32);
                sum_r += c.red as i32;
                sum_g += c.green as i32;
                sum_b += c.blue as i32;
            }

            for x in x_start..x_end {
                // 平均を計算
                row_buffer[x as usize] = Color::new(
                    (sum_r / diameter) as u8,
                    (sum_g / diameter) as u8,
                    (sum_b / diameter) as u8,
                );

                // スライディングウィンドウ更新
                let left = (x - radius).clamp(0, self.screen_width as i32 - 1);
                let right = (x + radius + 1).clamp(0, self.screen_width as i32 - 1);
                let c_left = self.blur_buffer.get_pixel(left as u32, y as u32);
                let c_right = self.blur_buffer.get_pixel(right as u32, y as u32);

                sum_r += c_right.red as i32 - c_left.red as i32;
                sum_g += c_right.green as i32 - c_left.green as i32;
                sum_b += c_right.blue as i32 - c_left.blue as i32;
            }

            // 結果を書き戻し
            for x in x_start..x_end {
                self.blur_buffer.set_pixel(x as u32, y as u32, row_buffer[x as usize]);
            }
        }
    }

    /// 垂直方向ボックスブラー
    fn box_blur_vertical(&mut self, region: Rect) {
        let radius = BLUR_RADIUS as i32;
        let diameter = radius * 2 + 1;

        let y_start = region.y.max(0);
        let y_end = (region.y + region.height as i32).min(self.screen_height as i32);
        let x_start = region.x.max(0);
        let x_end = (region.x + region.width as i32).min(self.screen_width as i32);

        // 一時バッファ（列ごとに処理）
        let mut col_buffer: Vec<Color> = vec![Color::BLACK; self.screen_height as usize];

        for x in x_start..x_end {
            // 累積和を計算
            let mut sum_r: i32 = 0;
            let mut sum_g: i32 = 0;
            let mut sum_b: i32 = 0;

            // 初期ウィンドウ
            for y in (y_start - radius)..(y_start + radius + 1) {
                let sy = y.clamp(0, self.screen_height as i32 - 1);
                let c = self.blur_buffer.get_pixel(x as u32, sy as u32);
                sum_r += c.red as i32;
                sum_g += c.green as i32;
                sum_b += c.blue as i32;
            }

            for y in y_start..y_end {
                // 平均を計算
                col_buffer[y as usize] = Color::new(
                    (sum_r / diameter) as u8,
                    (sum_g / diameter) as u8,
                    (sum_b / diameter) as u8,
                );

                // スライディングウィンドウ更新
                let top = (y - radius).clamp(0, self.screen_height as i32 - 1);
                let bottom = (y + radius + 1).clamp(0, self.screen_height as i32 - 1);
                let c_top = self.blur_buffer.get_pixel(x as u32, top as u32);
                let c_bottom = self.blur_buffer.get_pixel(x as u32, bottom as u32);

                sum_r += c_bottom.red as i32 - c_top.red as i32;
                sum_g += c_bottom.green as i32 - c_top.green as i32;
                sum_b += c_bottom.blue as i32 - c_top.blue as i32;
            }

            // 結果を書き戻し
            for y in y_start..y_end {
                self.blur_buffer.set_pixel(x as u32, y as u32, col_buffer[y as usize]);
            }
        }
    }
}

// ============================================================================
// SIMD Gaussian Blur (x86_64 SSE2/AVX2) - 将来の最適化用
// ============================================================================

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod simd_blur {
    //! SIMD最適化されたブラー処理（将来の最適化用）
    //! 
    //! 現在は標準のスカラー実装を使用。
    //! SSE2/AVX2が利用可能な環境では、この実装に切り替えることで
    //! 大幅なパフォーマンス向上が期待できる。

    use super::*;

    /// SSE2を使用した高速ボックスブラー（将来実装予定）
    #[allow(unused)]
    pub fn box_blur_optimized(
        _src: &[u8],
        _dst: &mut [u8],
        _width: usize,
        _height: usize,
        _radius: usize,
    ) {
        // TODO: SSE2/AVX2最適化版を実装
        // 現在はスカラー版を使用
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルコンポジタ
static COMPOSITOR: Mutex<Option<Compositor>> = Mutex::new(None);

/// コンポジタを初期化
pub fn init(screen_width: u32, screen_height: u32) {
    *COMPOSITOR.lock() = Some(Compositor::new(screen_width, screen_height));
}

/// コンポジタにアクセス
pub fn with_compositor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&Compositor) -> R,
{
    COMPOSITOR.lock().as_ref().map(f)
}

/// コンポジタにミュータブルアクセス
pub fn with_compositor_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Compositor) -> R,
{
    COMPOSITOR.lock().as_mut().map(f)
}

/// ウィンドウを作成
pub fn create_window(
    title: &str,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    style: CompositorWindowStyle,
) -> Option<CompositorWindowId> {
    with_compositor_mut(|c| c.create_window(title, x, y, width, height, style))
}

/// ウィンドウを破棄
pub fn destroy_window(id: CompositorWindowId) {
    with_compositor_mut(|c| c.destroy_window(id));
}

/// フレームバッファに合成
pub fn compose(fb: &mut Framebuffer) {
    with_compositor_mut(|c| c.compose(fb));
}

/// マウス移動を処理
pub fn handle_mouse_move(x: i32, y: i32) {
    with_compositor_mut(|c| c.handle_mouse_move(x, y));
}

/// マウスボタン押下を処理
pub fn handle_mouse_down(x: i32, y: i32, button: u8) {
    with_compositor_mut(|c| c.handle_mouse_down(x, y, button));
}

/// マウスボタン解放を処理
pub fn handle_mouse_up(x: i32, y: i32, button: u8) {
    with_compositor_mut(|c| c.handle_mouse_up(x, y, button));
}

