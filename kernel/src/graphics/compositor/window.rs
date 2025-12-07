// ============================================================================
// src/graphics/compositor/window.rs - Compositor Window
// ============================================================================

//! コンポジタウィンドウ

extern crate alloc;

use alloc::string::String;

use crate::graphics::{Color, Point, Rect};
use crate::graphics::image::Image;

use super::constants::{BORDER_WIDTH, RESIZE_HANDLE_SIZE, TITLE_BAR_HEIGHT};
use super::types::{
    CompositorWindowId, CompositorWindowState, CompositorWindowStyle, ResizeEdge, ZOrder,
};

// ============================================================================
// Compositor Window
// ============================================================================

/// コンポジタウィンドウ
pub struct CompositorWindow {
    /// ウィンドウID
    id: CompositorWindowId,
    /// タイトル
    pub(crate) title: String,
    /// ウィンドウ矩形（装飾含む）
    pub(crate) rect: Rect,
    /// クライアント領域
    pub(crate) client_rect: Rect,
    /// スタイル
    pub(crate) style: CompositorWindowStyle,
    /// 状態
    state: CompositorWindowState,
    /// Z-Order
    z_order: ZOrder,
    /// コンテンツバッファ
    pub(crate) content: Image,
    /// 合成済みバッファ（装飾含む）
    #[allow(dead_code)]
    composed: Image,
    /// ダーティフラグ
    pub(crate) dirty: bool,
    /// 装飾ダーティフラグ
    pub(crate) decoration_dirty: bool,
    /// 可視性
    visible: bool,
    /// 前回の矩形（移動・リサイズ時のダーティ領域用）
    pub(crate) prev_rect: Rect,
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
            title: String::from(title),
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
    pub fn calculate_client_rect(rect: &Rect, style: &CompositorWindowStyle) -> Rect {
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

    #[allow(dead_code)]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[allow(dead_code)]
    pub fn set_title(&mut self, title: &str) {
        self.title = String::from(title);
        self.decoration_dirty = true;
    }

    pub fn rect(&self) -> Rect {
        self.rect
    }

    #[allow(dead_code)]
    pub fn client_rect(&self) -> Rect {
        self.client_rect
    }

    pub fn style(&self) -> &CompositorWindowStyle {
        &self.style
    }

    #[allow(dead_code)]
    pub fn state(&self) -> CompositorWindowState {
        self.state
    }

    pub fn z_order(&self) -> ZOrder {
        self.z_order
    }

    #[allow(dead_code)]
    pub fn set_z_order(&mut self, z_order: ZOrder) {
        self.z_order = z_order;
    }

    pub fn is_visible(&self) -> bool {
        self.visible && self.state != CompositorWindowState::Hidden
    }

    #[allow(dead_code)]
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    #[allow(dead_code)]
    pub fn content(&self) -> &Image {
        &self.content
    }

    #[allow(dead_code)]
    pub fn content_mut(&mut self) -> &mut Image {
        self.dirty = true;
        &mut self.content
    }

    #[allow(dead_code)]
    pub fn is_dirty(&self) -> bool {
        self.dirty || self.decoration_dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false;
        self.decoration_dirty = false;
    }

    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn screen_to_client(&self, x: i32, y: i32) -> (i32, i32) {
        (x - self.client_rect.x, y - self.client_rect.y)
    }
}
