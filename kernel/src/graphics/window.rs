// ============================================================================
// src/graphics/window.rs - Window System and Compositor
// ============================================================================
//!
//! # ウィンドウシステム
//!
//! 基本的なウィンドウ管理とコンポジティングを提供。

#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::image::Image;
use super::{Color, Framebuffer, Point, Rect};

// ============================================================================
// Type-Safe Identifiers
// ============================================================================

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowStyle {
    pub border: bool,
    pub title_bar: bool,
    pub close_button: bool,
    pub minimize_button: bool,
    pub maximize_button: bool,
    pub resizable: bool,
    pub topmost: bool,
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

#[derive(Clone, Copy, Debug, Default)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub win: bool,
}

#[derive(Clone, Debug)]
pub enum WindowEvent {
    KeyDown { key: KeyCode, modifiers: Modifiers },
    KeyUp { key: KeyCode, modifiers: Modifiers },
    CharInput { c: char },
    Resize { width: u32, height: u32 },
    Move { x: i32, y: i32 },
    FocusGained,
    FocusLost,
    CloseRequested,
    Redraw,
}

// ============================================================================
// Window
// ============================================================================

pub struct Window {
    id: WindowId,
    parent: Option<WindowId>,
    title: String,
    rect: Rect,
    client_rect: Rect,
    style: WindowStyle,
    state: WindowState,
    z_order: ZOrder,
    background: Color,
    content: Image,
    dirty: bool,
    visible: bool,
    events: Vec<WindowEvent>,
}

impl Window {
    const TITLE_BAR_HEIGHT: u32 = 24;
    const BORDER_WIDTH: u32 = 1;

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
            z_order: if style.topmost {
                ZOrder::TOPMOST
            } else {
                ZOrder::NORMAL
            },
            background: Color::WHITE,
            content,
            dirty: true,
            visible: true,
            events: Vec::new(),
        }
    }

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

    pub fn id(&self) -> WindowId {
        self.id
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn set_title(&mut self, title: String) {
        self.title = title;
        self.dirty = true;
    }
    pub fn rect(&self) -> Rect {
        self.rect
    }
    pub fn client_rect(&self) -> Rect {
        self.client_rect
    }
    pub fn state(&self) -> WindowState {
        self.state
    }
    pub fn set_state(&mut self, state: WindowState) {
        self.state = state;
        self.visible = state != WindowState::Hidden && state != WindowState::Minimized;
    }
    pub fn is_visible(&self) -> bool {
        self.visible
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
        self.dirty
    }
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }
    pub fn invalidate(&mut self) {
        self.dirty = true;
    }
    pub fn move_to(&mut self, x: i32, y: i32) {
        self.rect.x = x;
        self.rect.y = y;
        self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);
        self.dirty = true;
    }
    pub fn resize(&mut self, width: u32, height: u32) {
        self.rect.width = width;
        self.rect.height = height;
        self.client_rect = Self::calculate_client_rect(&self.rect, &self.style);
        self.content = Image::filled(
            self.client_rect.width,
            self.client_rect.height,
            self.background,
        );
        self.dirty = true;
        self.events.push(WindowEvent::Resize {
            width: self.client_rect.width,
            height: self.client_rect.height,
        });
    }
    pub fn push_event(&mut self, event: WindowEvent) {
        self.events.push(event);
    }
    pub fn pop_event(&mut self) -> Option<WindowEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }
    pub fn contains(&self, x: i32, y: i32) -> bool {
        self.rect.contains(Point::new(x, y))
    }
    pub fn client_contains(&self, x: i32, y: i32) -> bool {
        self.client_rect.contains(Point::new(x, y))
    }
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
    pub fn screen_to_client(&self, x: i32, y: i32) -> (i32, i32) {
        (x - self.client_rect.x, y - self.client_rect.y)
    }
}

// ============================================================================
// Window Manager
// ============================================================================

pub struct WindowManager {
    windows: BTreeMap<WindowId, Window>,
    z_order_list: Vec<WindowId>,
    next_id: AtomicU32,
    focused: Option<WindowId>,
    screen_width: u32,
    screen_height: u32,
    wallpaper: Option<Image>,
    desktop_color: Color,
}

impl WindowManager {
    pub fn new(screen_width: u32, screen_height: u32) -> Self {
        Self {
            windows: BTreeMap::new(),
            z_order_list: Vec::new(),
            next_id: AtomicU32::new(1),
            focused: None,
            screen_width,
            screen_height,
            wallpaper: None,
            desktop_color: Color::new(0, 120, 215),
        }
    }

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

    pub fn destroy_window(&mut self, id: WindowId) {
        self.windows.remove(&id);
        self.z_order_list.retain(|&wid| wid != id);
        if self.focused == Some(id) {
            self.focused = self.z_order_list.last().copied();
        }
    }

    pub fn get_window(&self, id: WindowId) -> Option<&Window> {
        self.windows.get(&id)
    }
    pub fn get_window_mut(&mut self, id: WindowId) -> Option<&mut Window> {
        self.windows.get_mut(&id)
    }
    pub fn focused_window(&self) -> Option<WindowId> {
        self.focused
    }

    pub fn set_focus(&mut self, id: WindowId) {
        if !self.windows.contains_key(&id) {
            return;
        }
        if let Some(old_focused) = self.focused {
            if old_focused != id {
                if let Some(window) = self.windows.get_mut(&old_focused) {
                    window.push_event(WindowEvent::FocusLost);
                }
            }
        }
        self.focused = Some(id);
        self.bring_to_front(id);
        if let Some(window) = self.windows.get_mut(&id) {
            window.push_event(WindowEvent::FocusGained);
        }
    }

    pub fn bring_to_front(&mut self, id: WindowId) {
        self.z_order_list.retain(|&wid| wid != id);
        self.z_order_list.push(id);
    }

    pub fn window_at(&self, x: i32, y: i32) -> Option<WindowId> {
        for &id in self.z_order_list.iter().rev() {
            if let Some(window) = self.windows.get(&id) {
                if window.is_visible() && window.contains(x, y) {
                    return Some(id);
                }
            }
        }
        None
    }

    pub fn handle_key_down(&mut self, key: KeyCode, modifiers: Modifiers) {
        if let Some(id) = self.focused {
            if let Some(window) = self.windows.get_mut(&id) {
                window.push_event(WindowEvent::KeyDown { key, modifiers });
            }
        }
    }

    pub fn handle_key_up(&mut self, key: KeyCode, modifiers: Modifiers) {
        if let Some(id) = self.focused {
            if let Some(window) = self.windows.get_mut(&id) {
                window.push_event(WindowEvent::KeyUp { key, modifiers });
            }
        }
    }

    pub fn set_wallpaper(&mut self, wallpaper: Image) {
        self.wallpaper = Some(wallpaper.resize_bilinear(self.screen_width, self.screen_height));
    }
    pub fn set_desktop_color(&mut self, color: Color) {
        self.desktop_color = color;
    }

    pub fn compose(&self, fb: &mut Framebuffer) {
        if let Some(ref wallpaper) = self.wallpaper {
            fb.draw_image(wallpaper, 0, 0);
        } else {
            fb.clear(self.desktop_color);
        }
        for &id in &self.z_order_list {
            if let Some(window) = self.windows.get(&id) {
                if window.is_visible() {
                    self.draw_window(fb, window);
                }
            }
        }
    }

    fn draw_window(&self, fb: &mut Framebuffer, window: &Window) {
        let rect = window.rect();
        let is_focused = self.focused == Some(window.id());
        let title_bar_color = if is_focused {
            Color::new(0, 120, 215)
        } else {
            Color::new(128, 128, 128)
        };
        let border_color = Color::DARK_GRAY;
        if window.style.border {
            fb.draw_rect(rect, border_color);
        }
        if window.style.title_bar {
            let title_bar_rect = Rect::new(
                rect.x + Window::BORDER_WIDTH as i32,
                rect.y + Window::BORDER_WIDTH as i32,
                rect.width - Window::BORDER_WIDTH * 2,
                Window::TITLE_BAR_HEIGHT,
            );
            fb.fill_rect(title_bar_rect, title_bar_color);
        }
        let client = window.client_rect();
        fb.draw_image(window.content(), client.x, client.y);
    }

    pub fn clear_dirty(&mut self) {
        for window in self.windows.values_mut() {
            window.mark_clean();
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static WINDOW_MANAGER: PoisonLock<Option<WindowManager>> = PoisonLock::new(None);

pub fn init(screen_width: u32, screen_height: u32) {
    *WINDOW_MANAGER.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(WindowManager::new(screen_width, screen_height));
}

pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&WindowManager) -> R,
{
    WINDOW_MANAGER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(f)
}

pub fn with_manager_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut WindowManager) -> R,
{
    WINDOW_MANAGER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .map(f)
}

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

pub fn destroy_window(id: WindowId) {
    with_manager_mut(|wm| wm.destroy_window(id));
}
pub fn compose(fb: &mut Framebuffer) {
    with_manager(|wm| wm.compose(fb));
}
