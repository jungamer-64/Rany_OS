// ============================================================================
// src/graphics/compositor/compositor.rs - Main Compositor
// ============================================================================

//! ウィンドウコンポジタ本体

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::graphics::{Color, Framebuffer, Point, Rect};
use crate::graphics::image::Image;

use super::constants::{BLUR_RADIUS, BORDER_WIDTH, SHADOW_SIZE, TITLE_BAR_HEIGHT};
use super::cursor::{CursorType, MouseCursor};
use super::dirty_rect::{DirtyRect, DirtyRegionManager};
use super::types::{
    CompositorWindowId, CompositorWindowStyle, DragState, ResizeEdge, ZOrder,
};
use super::window::CompositorWindow;

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
    #[allow(dead_code)]
    pub fn get_window(&self, id: CompositorWindowId) -> Option<&CompositorWindow> {
        self.windows.get(&id)
    }

    /// ウィンドウをミュータブルに取得
    #[allow(dead_code)]
    pub fn get_window_mut(&mut self, id: CompositorWindowId) -> Option<&mut CompositorWindow> {
        self.windows.get_mut(&id)
    }

    /// フォーカスウィンドウを取得
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn set_wallpaper(&mut self, wallpaper: Image) {
        self.wallpaper = Some(wallpaper.resize_bilinear(self.screen_width, self.screen_height));
        self.dirty_manager.invalidate_all();
    }

    /// デスクトップ色を設定
    #[allow(dead_code)]
    pub fn set_desktop_color(&mut self, color: Color) {
        self.desktop_color = color;
        self.dirty_manager.invalidate_all();
    }

    /// マウスカーソルを取得
    #[allow(dead_code)]
    pub fn cursor(&self) -> &MouseCursor {
        &self.cursor
    }

    /// マウスカーソルをミュータブルに取得
    #[allow(dead_code)]
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

            window.prev_rect = window.rect;
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
            self.dirty_manager.add_dirty(window.rect);
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
                window.client_rect,
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
    fn draw_window_region_to_back_buffer(&mut self, id: CompositorWindowId, _region: Rect) {
        // 簡略化: 領域と交差するウィンドウ全体を再描画
        self.draw_window_to_back_buffer(id);
    }

    /// ウィンドウ装飾を描画
    fn draw_window_decoration(&mut self, rect: Rect, style: &CompositorWindowStyle, is_focused: bool, _title: &str) {
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
    #[allow(dead_code)]
    pub fn screen_size(&self) -> (u32, u32) {
        (self.screen_width, self.screen_height)
    }

    // ========================================================================
    // Acrylic Effect (Gaussian Blur)
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
