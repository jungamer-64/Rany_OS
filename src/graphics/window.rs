// ============================================================================
// src/graphics/window.rs - Window System and Compositor
// ============================================================================
//!
//! # ウィンドウシステム
//!
//! 基本的なウィンドウ管理とコンポジティングを提供。
//!
//! ## 機能
//! - ウィンドウ作成・破棄
//! - Z-order管理
//! - イベント配信
//! - 合成（コンポジティング）

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::{Color, Framebuffer, Rect, Point};
use super::image::Image;

// ============================================================================
// Type-Safe Identifiers
// ============================================================================

/// ウィンドウID
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WindowId(pub u32);

impl WindowId {
    pub const INVALID: Self = Self(u32::MAX);
    pub const ROOT: Self = Self(0);

    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn is_valid(self) -> bool {
        self != Self::INVALID
    }
}

/// Zオーダー（レイヤー）
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZOrder(pub i32);

impl ZOrder {
    pub const BACKGROUND: Self = Self(-1000);
    pub const NORMAL: Self = Self(0);
    pub const ABOVE_NORMAL: Self = Self(100);
    pub const TOPMOST: Self = Self(1000);
    pub const SYSTEM: Self = Self(10000);

    pub const fn new(order: i32) -> Self {
        Self(order)
    }
}

// ============================================================================
// Window Types
// ============================================================================

/// ウィンドウスタイル
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowStyle {
    /// 境界線を描画
    pub border: bool,
    /// タイトルバーを描画
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
    /// ツールウィンドウ（タスクバーに表示しない）
    pub tool_window: bool,
}

impl Default for WindowStyle {
    fn default() -> Self {
        Self {
            border: true,
            title_bar: true,
            close_button: true,
            minimize_button: true,
            maximize_button: true,
            resizable: true,
            topmost: false,
            tool_window: false,
        }
    }
}

impl WindowStyle {
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
            tool_window: false,
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
            tool_window: false,
        }
    }

    /// ポップアップスタイル
    pub fn popup() -> Self {
        Self {
            border: true,
            title_bar: false,
            close_button: false,
            minimize_button: false,
            maximize_button: false,
            resizable: false,
            topmost: true,
            tool_window: true,
        }
    }
}

/// ウィンドウ状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowState {
    Normal,
    Minimized,
    Maximized,
    Hidden,
}

// ============================================================================
// Window Events
// ============================================================================

/// マウスボタン
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

/// キーコード
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCode(pub u8);

impl KeyCode {
    pub const ESCAPE: Self = Self(0x01);
    pub const ENTER: Self = Self(0x1C);
    pub const SPACE: Self = Self(0x39);
    pub const BACKSPACE: Self = Self(0x0E);
    pub const TAB: Self = Self(0x0F);
    pub const LEFT: Self = Self(0x4B);
    pub const RIGHT: Self = Self(0x4D);
    pub const UP: Self = Self(0x48);
    pub const DOWN: Self = Self(0x50);
}

/// 修飾キー
#[derive(Clone, Copy, Debug, Default)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub win: bool,
}

/// ウィンドウイベント
#[derive(Clone, Debug)]
pub enum WindowEvent {
    /// マウス移動
    MouseMove { x: i32, y: i32 },
    /// マウスボタン押下
    MouseButtonDown { button: MouseButton, x: i32, y: i32 },
    /// マウスボタン解放
    MouseButtonUp { button: MouseButton, x: i32, y: i32 },
    /// マウスホイール
    MouseWheel { delta: i32, x: i32, y: i32 },
    /// キー押下
    KeyDown { key: KeyCode, modifiers: Modifiers },
    /// キー解放
    KeyUp { key: KeyCode, modifiers: Modifiers },
    /// 文字入力
    CharInput { c: char },
    /// ウィンドウリサイズ
    Resize { width: u32, height: u32 },
    /// ウィンドウ移動
    Move { x: i32, y: i32 },
    /// フォーカス取得
    FocusGained,
    /// フォーカス喪失
    FocusLost,
    /// 閉じる要求
    CloseRequested,
    /// 再描画要求
    Redraw,
}

// ============================================================================
// Window
// ============================================================================

/// ウィンドウ
pub struct Window {
    /// ウィンドウID
    id: WindowId,
    /// 親ウィンドウ
    parent: Option<WindowId>,
    /// タイトル
    title: String,
    /// 位置とサイズ
    rect: Rect,
    /// クライアント領域
    client_rect: Rect,
    /// スタイル
    style: WindowStyle,
    /// 状態
    state: WindowState,
    /// Zオーダー
    z_order: ZOrder,
    /// 背景色
    background: Color,
    /// コンテンツバッファ
    content: Image,
    /// 再描画が必要
    dirty: bool,
    /// 可視
    visible: bool,
    /// イベントキュー
    events: Vec<WindowEvent>,
}

impl Window {
    /// タイトルバーの高さ
    const TITLE_BAR_HEIGHT: u32 = 24;
    /// 境界線の幅
    const BORDER_WIDTH: u32 = 1;

    /// 新しいウィンドウを作成
    fn new(id: WindowId, title: String, rect: Rect, style: WindowStyle) -> Self {
        let client_rect = Self::calculate_client_rect(&rect, &style);
        let content = Image::filled(client_rect.width, client_rect.height, Color::WHITE);

        Self {
            id,
            parent: None,
            title,
            rect,
            client_rect,
            style,
            state: WindowState::Normal,
            z_order: if style.topmost { ZOrder::TOPMOST } else { ZOrder::NORMAL },
            background: Color::WHITE,
            content,
            dirty: true,
            visible: true,
            events: Vec::new(),
        }
    }

    /// クライアント領域を計算
    fn calculate_client_rect(rect: &Rect, style: &WindowStyle) -> Rect {
        let mut x = rect.x;
        let mut y = rect.y;
        let mut width = rect.width;
        let mut height = rect.height;

        if style.border {
            x += Self::BORDER_WIDTH as i32;
            y += Self::BORDER_WIDTH as i32;
            width -= Self::BORDER_WIDTH * 2;
            height -= Self::BORDER_WIDTH * 2;
        }

        if style.title_bar {
            y += Self::TITLE_BAR_HEIGHT as i32;
            height -= Self::TITLE_BAR_HEIGHT;
        }

        Rect::new(x, y, width, height)
    }

    /// ウィンドウIDを取得
    pub fn id(&self) -> WindowId {
        self.id
    }

    /// タイトルを取得
    pub fn title(&self) -> &str {
        &self.title
    }

    /// タイトルを設定
    pub fn set_title(&mut self, title: String) {
        self.title = title;
        self.dirty = true;
    }

    /// 位置とサイズを取得
    pub fn rect(&self) -> Rect {
        self.rect
    }

    /// クライアント領域を取得
    pub fn client_rect(&self) -> Rect {
        self.client_rect
    }

    /// 状態を取得
    pub fn state(&self) -> WindowState {
        self.state
    }

    /// 状態を設定
    pub fn set_state(&mut self, state: WindowState) {
        self.state = state;
        self.visible = state != WindowState::Hidden && state != WindowState::Minimized;
    }

    /// 可視性を取得
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// 可視性を設定
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// コンテンツバッファを取得
    pub fn content(&self) -> &Image {
        &self.content
    }

    /// コンテンツバッファをミュータブルに取得
    pub fn content_mut(&mut self) -> &mut Image {
        self.dirty = true;
        &mut self.content
    }

    /// 再描画が必要かどうか
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 再描画完了をマーク
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// 無効化（再描画を要求）
    pub fn invalidate(&mut self) {
        self.dirty = true;
    }

    /// ウィンドウを移動
    pub fn move_to(&mut self, x: i32, y: i32) {
        self.rect.x = x;
        self.rect.y = y;
        self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);
        self.dirty = true;
    }

    /// ウィンドウをリサイズ
    pub fn resize(&mut self, width: u32, height: u32) {
        self.rect.width = width;
        self.rect.height = height;
        self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);
        self.content = Image::filled(self.client_rect.width, self.client_rect.height, self.background);
        self.dirty = true;
        self.events.push(WindowEvent::Resize { width: self.client_rect.width, height: self.client_rect.height });
    }

    /// イベントをプッシュ
    pub fn push_event(&mut self, event: WindowEvent) {
        self.events.push(event);
    }

    /// イベントをポップ
    pub fn pop_event(&mut self) -> Option<WindowEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    /// 点がウィンドウ内にあるか
    pub fn contains(&self, x: i32, y: i32) -> bool {
        self.rect.contains(Point::new(x, y))
    }

    /// 点がクライアント領域内にあるか
    pub fn client_contains(&self, x: i32, y: i32) -> bool {
        self.client_rect.contains(Point::new(x, y))
    }

    /// 点がタイトルバー内にあるか
    pub fn title_bar_contains(&self, x: i32, y: i32) -> bool {
        if !self.style.title_bar {
            return false;
        }

        let title_bar_rect = Rect::new(
            self.rect.x + Self::BORDER_WIDTH as i32,
            self.rect.y + Self::BORDER_WIDTH as i32,
            self.rect.width - Self::BORDER_WIDTH * 2,
            Self::TITLE_BAR_HEIGHT,
        );

        title_bar_rect.contains(Point::new(x, y))
    }

    /// スクリーン座標をクライアント座標に変換
    pub fn screen_to_client(&self, x: i32, y: i32) -> (i32, i32) {
        (x - self.client_rect.x, y - self.client_rect.y)
    }
}

// ============================================================================
// Window Manager
// ============================================================================

/// ウィンドウマネージャ
pub struct WindowManager {
    /// ウィンドウマップ
    windows: BTreeMap<WindowId, Window>,
    /// Zオーダーリスト（下から上へ）
    z_order_list: Vec<WindowId>,
    /// 次のウィンドウID
    next_id: AtomicU32,
    /// フォーカスを持つウィンドウ
    focused: Option<WindowId>,
    /// ドラッグ中のウィンドウ
    dragging: Option<(WindowId, i32, i32)>,
    /// リサイズ中のウィンドウ
    resizing: Option<(WindowId, ResizeEdge)>,
    /// 画面サイズ
    screen_width: u32,
    screen_height: u32,
    /// 壁紙
    wallpaper: Option<Image>,
    /// デスクトップ色
    desktop_color: Color,
}

/// リサイズエッジ
#[derive(Clone, Copy, Debug)]
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

impl WindowManager {
    /// 新しいウィンドウマネージャを作成
    pub fn new(screen_width: u32, screen_height: u32) -> Self {
        Self {
            windows: BTreeMap::new(),
            z_order_list: Vec::new(),
            next_id: AtomicU32::new(1),
            focused: None,
            dragging: None,
            resizing: None,
            screen_width,
            screen_height,
            wallpaper: None,
            desktop_color: Color::new(0, 120, 215), // Windows青
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
        style: WindowStyle,
    ) -> WindowId {
        let id = WindowId::new(self.next_id.fetch_add(1, Ordering::SeqCst));
        let rect = Rect::new(x, y, width, height);
        let window = Window::new(id, String::from(title), rect, style);

        self.windows.insert(id, window);
        self.z_order_list.push(id);
        self.focused = Some(id);

        id
    }

    /// ウィンドウを破棄
    pub fn destroy_window(&mut self, id: WindowId) {
        self.windows.remove(&id);
        self.z_order_list.retain(|&wid| wid != id);

        if self.focused == Some(id) {
            self.focused = self.z_order_list.last().copied();
        }

        if let Some((dragging_id, _, _)) = self.dragging {
            if dragging_id == id {
                self.dragging = None;
            }
        }
    }

    /// ウィンドウを取得
    pub fn get_window(&self, id: WindowId) -> Option<&Window> {
        self.windows.get(&id)
    }

    /// ウィンドウをミュータブルに取得
    pub fn get_window_mut(&mut self, id: WindowId) -> Option<&mut Window> {
        self.windows.get_mut(&id)
    }

    /// フォーカスを持つウィンドウを取得
    pub fn focused_window(&self) -> Option<WindowId> {
        self.focused
    }

    /// フォーカスを設定
    pub fn set_focus(&mut self, id: WindowId) {
        if !self.windows.contains_key(&id) {
            return;
        }

        // 前のフォーカスウィンドウにイベントを送信
        if let Some(old_focused) = self.focused {
            if old_focused != id {
                if let Some(window) = self.windows.get_mut(&old_focused) {
                    window.push_event(WindowEvent::FocusLost);
                }
            }
        }

        self.focused = Some(id);
        self.bring_to_front(id);

        // 新しいフォーカスウィンドウにイベントを送信
        if let Some(window) = self.windows.get_mut(&id) {
            window.push_event(WindowEvent::FocusGained);
        }
    }

    /// ウィンドウを最前面に
    pub fn bring_to_front(&mut self, id: WindowId) {
        self.z_order_list.retain(|&wid| wid != id);
        self.z_order_list.push(id);
    }

    /// 点の下にあるウィンドウを検索
    pub fn window_at(&self, x: i32, y: i32) -> Option<WindowId> {
        // Z-orderの逆順（上から）で検索
        for &id in self.z_order_list.iter().rev() {
            if let Some(window) = self.windows.get(&id) {
                if window.is_visible() && window.contains(x, y) {
                    return Some(id);
                }
            }
        }
        None
    }

    /// マウス移動を処理
    pub fn handle_mouse_move(&mut self, x: i32, y: i32) {
        // ドラッグ処理
        if let Some((id, offset_x, offset_y)) = self.dragging {
            if let Some(window) = self.windows.get_mut(&id) {
                window.move_to(x - offset_x, y - offset_y);
            }
            return;
        }

        // ホバーウィンドウにイベントを送信
        if let Some(id) = self.window_at(x, y) {
            if let Some(window) = self.windows.get_mut(&id) {
                let (cx, cy) = window.screen_to_client(x, y);
                window.push_event(WindowEvent::MouseMove { x: cx, y: cy });
            }
        }
    }

    /// マウスボタン押下を処理
    pub fn handle_mouse_down(&mut self, button: MouseButton, x: i32, y: i32) {
        if let Some(id) = self.window_at(x, y) {
            self.set_focus(id);

            if let Some(window) = self.windows.get_mut(&id) {
                // タイトルバーのドラッグ開始
                if button == MouseButton::Left && window.title_bar_contains(x, y) {
                    let offset_x = x - window.rect().x;
                    let offset_y = y - window.rect().y;
                    self.dragging = Some((id, offset_x, offset_y));
                    return;
                }

                // クライアント領域へのイベント
                if window.client_contains(x, y) {
                    let (cx, cy) = window.screen_to_client(x, y);
                    window.push_event(WindowEvent::MouseButtonDown { button, x: cx, y: cy });
                }
            }
        }
    }

    /// マウスボタン解放を処理
    pub fn handle_mouse_up(&mut self, button: MouseButton, x: i32, y: i32) {
        // ドラッグ終了
        self.dragging = None;
        self.resizing = None;

        // ウィンドウにイベントを送信
        if let Some(id) = self.window_at(x, y) {
            if let Some(window) = self.windows.get_mut(&id) {
                if window.client_contains(x, y) {
                    let (cx, cy) = window.screen_to_client(x, y);
                    window.push_event(WindowEvent::MouseButtonUp { button, x: cx, y: cy });
                }
            }
        }
    }

    /// キー押下を処理
    pub fn handle_key_down(&mut self, key: KeyCode, modifiers: Modifiers) {
        if let Some(id) = self.focused {
            if let Some(window) = self.windows.get_mut(&id) {
                window.push_event(WindowEvent::KeyDown { key, modifiers });
            }
        }
    }

    /// キー解放を処理
    pub fn handle_key_up(&mut self, key: KeyCode, modifiers: Modifiers) {
        if let Some(id) = self.focused {
            if let Some(window) = self.windows.get_mut(&id) {
                window.push_event(WindowEvent::KeyUp { key, modifiers });
            }
        }
    }

    /// 壁紙を設定
    pub fn set_wallpaper(&mut self, wallpaper: Image) {
        // 画面サイズにリサイズ
        self.wallpaper = Some(wallpaper.resize_bilinear(self.screen_width, self.screen_height));
    }

    /// デスクトップ色を設定
    pub fn set_desktop_color(&mut self, color: Color) {
        self.desktop_color = color;
    }

    /// フレームバッファに合成
    pub fn compose(&self, fb: &mut Framebuffer) {
        // デスクトップ背景を描画
        if let Some(ref wallpaper) = self.wallpaper {
            wallpaper.draw_to_framebuffer(fb, 0, 0);
        } else {
            fb.clear(self.desktop_color);
        }

        // ウィンドウをZ-order順に描画
        for &id in &self.z_order_list {
            if let Some(window) = self.windows.get(&id) {
                if window.is_visible() {
                    self.draw_window(fb, window);
                }
            }
        }
    }

    /// 単一ウィンドウを描画
    fn draw_window(&self, fb: &mut Framebuffer, window: &Window) {
        let rect = window.rect();
        let is_focused = self.focused == Some(window.id());

        // ウィンドウの装飾色
        let title_bar_color = if is_focused {
            Color::new(0, 120, 215) // アクティブ（青）
        } else {
            Color::new(128, 128, 128) // 非アクティブ（灰色）
        };
        let border_color = Color::DARK_GRAY;

        // 境界線を描画
        if window.style.border {
            fb.draw_rect(rect, border_color);
        }

        // タイトルバーを描画
        if window.style.title_bar {
            let title_bar_rect = Rect::new(
                rect.x + Window::BORDER_WIDTH as i32,
                rect.y + Window::BORDER_WIDTH as i32,
                rect.width - Window::BORDER_WIDTH * 2,
                Window::TITLE_BAR_HEIGHT,
            );
            fb.fill_rect(title_bar_rect, title_bar_color);

            // タイトルテキスト（簡易）
            // 実際の実装ではBitmapFontを使用
        }

        // コンテンツを描画
        let client = window.client_rect();
        window.content().draw_to_framebuffer(fb, client.x, client.y);
    }

    /// すべてのダーティウィンドウをクリア
    pub fn clear_dirty(&mut self) {
        for window in self.windows.values_mut() {
            window.mark_clean();
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルウィンドウマネージャ
static WINDOW_MANAGER: Mutex<Option<WindowManager>> = Mutex::new(None);

/// ウィンドウマネージャを初期化
pub fn init(screen_width: u32, screen_height: u32) {
    *WINDOW_MANAGER.lock() = Some(WindowManager::new(screen_width, screen_height));
}

/// ウィンドウマネージャにアクセス
pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&WindowManager) -> R,
{
    WINDOW_MANAGER.lock().as_ref().map(f)
}

/// ウィンドウマネージャにミュータブルアクセス
pub fn with_manager_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut WindowManager) -> R,
{
    WINDOW_MANAGER.lock().as_mut().map(f)
}

/// ウィンドウを作成
pub fn create_window(
    title: &str,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    style: WindowStyle,
) -> Option<WindowId> {
    with_manager_mut(|wm| wm.create_window(title, x, y, width, height, style))
}

/// ウィンドウを破棄
pub fn destroy_window(id: WindowId) {
    with_manager_mut(|wm| wm.destroy_window(id));
}

/// フレームバッファに合成
pub fn compose(fb: &mut Framebuffer) {
    with_manager(|wm| wm.compose(fb));
}
