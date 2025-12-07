// ============================================================================
// src/application/browser/browser.rs - Browser Application
// ============================================================================
//!
//! # ブラウザアプリケーション
//!
//! URLバーと戻るボタンを持つシンプルなWebブラウザ。

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;

use crate::graphics::image::Image;
use crate::graphics::Color;

use super::dom::Node;
use super::html::HtmlParser;
use super::css::{Stylesheet, CssParser};
use super::style::style_tree;
use super::layout::{layout_tree, Dimensions, Rect};
use super::render::{build_display_list, paint, DisplayList};

// ============================================================================
// Constants
// ============================================================================

/// ブラウザウィンドウの幅
pub const BROWSER_WIDTH: u32 = 800;
/// ブラウザウィンドウの高さ
pub const BROWSER_HEIGHT: u32 = 600;

/// ツールバーの高さ
const TOOLBAR_HEIGHT: u32 = 36;
/// URLバーのパディング
const URL_BAR_PADDING: u32 = 4;
/// ボタンサイズ
const BUTTON_SIZE: u32 = 28;

// Colors
const TOOLBAR_BG: Color = Color { red: 240, green: 240, blue: 240, alpha: 255 };
const URL_BAR_BG: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
const URL_BAR_BORDER: Color = Color { red: 180, green: 180, blue: 180, alpha: 255 };
const BUTTON_BG: Color = Color { red: 220, green: 220, blue: 220, alpha: 255 };
const BUTTON_HOVER: Color = Color { red: 200, green: 200, blue: 200, alpha: 255 };
const TEXT_COLOR: Color = Color { red: 0, green: 0, blue: 0, alpha: 255 };
const CONTENT_BG: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
const LINK_COLOR: Color = Color { red: 0, green: 0, blue: 238, alpha: 255 };

// ============================================================================
// Browser State
// ============================================================================

/// ブラウザの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserState {
    /// 待機中
    Idle,
    /// 読み込み中
    Loading,
    /// エラー
    Error,
}

/// ブラウザアプリケーション
pub struct Browser {
    /// 現在のURL
    url: String,
    /// URL入力中のテキスト
    url_input: String,
    /// 履歴
    history: Vec<String>,
    /// 履歴の現在位置
    history_pos: usize,
    /// DOMツリー
    dom: Option<Node>,
    /// スタイルシート
    stylesheet: Stylesheet,
    /// 描画リスト
    display_list: DisplayList,
    /// 状態
    state: BrowserState,
    /// エラーメッセージ
    error_message: Option<String>,
    /// スクロール位置
    scroll_y: f32,
    /// コンテンツの高さ
    content_height: f32,
    /// 戻るボタンがホバー中か
    back_hover: bool,
    /// 進むボタンがホバー中か
    forward_hover: bool,
    /// URLバーにフォーカスがあるか
    url_focused: bool,
    /// カーソル位置
    cursor_pos: usize,
}

impl Browser {
    /// 新しいブラウザを作成
    pub fn new() -> Self {
        let mut browser = Self {
            url: String::new(),
            url_input: String::from("http://"),
            history: Vec::new(),
            history_pos: 0,
            dom: None,
            stylesheet: Stylesheet::default(),
            display_list: Vec::new(),
            state: BrowserState::Idle,
            error_message: None,
            scroll_y: 0.0,
            content_height: 0.0,
            back_hover: false,
            forward_hover: false,
            url_focused: true,
            cursor_pos: 7,
        };

        // デフォルトページを表示
        browser.load_default_page();
        browser
    }

    /// デフォルトページを読み込む
    fn load_default_page(&mut self) {
        let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Rany Browser</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        h1 { color: #333; }
        p { line-height: 1.5; }
        a { color: #0066cc; }
    </style>
</head>
<body>
    <h1>Welcome to Rany Browser</h1>
    <p>This is a simple web browser engine built for Rany OS.</p>
    <p>Enter a URL in the address bar above to navigate.</p>
    <hr>
    <h2>Supported Features</h2>
    <p>Basic HTML tags: div, p, h1-h6, a, span, strong, em, ul, ol, li</p>
    <p>Basic CSS: color, background-color, font-size, margin, padding</p>
    <hr>
    <h2>Example Sites</h2>
    <p>Try loading http://example.com</p>
</body>
</html>
"#;
        self.load_html(html);
        self.url = "about:home".into();
        self.url_input = "about:home".into();
        self.cursor_pos = self.url_input.len();
    }

    /// HTMLを読み込む
    pub fn load_html(&mut self, html: &str) {
        self.state = BrowserState::Loading;

        // HTMLをパース
        let dom = HtmlParser::parse(html);

        // CSSを抽出してパース
        let css = self.extract_css(&dom);
        let stylesheet = CssParser::parse(&css);

        // スタイルツリーを構築
        let style_tree = style_tree(&dom, &stylesheet);

        // レイアウトツリーを構築
        let viewport = Dimensions {
            content: Rect::new(
                0.0,
                0.0,
                (BROWSER_WIDTH - 20) as f32,  // マージン分を引く
                (BROWSER_HEIGHT - TOOLBAR_HEIGHT - 20) as f32,
            ),
            ..Default::default()
        };
        let layout_tree = layout_tree(&style_tree, viewport);

        // 描画リストを生成
        self.display_list = build_display_list(&layout_tree);
        self.content_height = self.calculate_content_height();

        // DOMを保存
        self.dom = Some(dom);
        self.stylesheet = stylesheet;
        self.state = BrowserState::Idle;
        self.scroll_y = 0.0;
    }

    /// CSSを抽出
    fn extract_css(&self, dom: &Node) -> String {
        let mut css = String::new();

        // <style>タグからCSSを取得
        for style_node in dom.find_elements_by_tag("style") {
            css.push_str(&style_node.inner_text());
            css.push('\n');
        }

        // デフォルトスタイル
        css.push_str(DEFAULT_USER_AGENT_CSS);

        css
    }

    /// コンテンツの高さを計算
    fn calculate_content_height(&self) -> f32 {
        let mut max_y = 0.0f32;
        for cmd in &self.display_list {
            match cmd {
                super::render::DisplayCommand::SolidColor(_, rect) => {
                    max_y = max_y.max(rect.bottom());
                }
                super::render::DisplayCommand::Text(_, _, _, y, size) => {
                    max_y = max_y.max(y + size * 1.2);
                }
                _ => {}
            }
        }
        max_y
    }

    /// URLに移動
    pub fn navigate(&mut self, url: &str) {
        self.url = url.into();
        self.url_input = url.into();
        self.cursor_pos = url.len();

        // 履歴に追加
        if self.history_pos < self.history.len() {
            self.history.truncate(self.history_pos);
        }
        self.history.push(url.into());
        self.history_pos = self.history.len();

        // URLに基づいてコンテンツを読み込む
        if url == "about:home" || url.is_empty() {
            self.load_default_page();
        } else if url.starts_with("http://example.com") || url.starts_with("https://example.com") {
            self.load_example_com();
        } else {
            self.load_error_page(&format!("Cannot load: {}", url));
        }
    }

    /// example.com を読み込む（シミュレート）
    fn load_example_com(&mut self) {
        let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Example Domain</title>
    <style>
        body {
            background-color: #f0f0f2;
            margin: 0;
            padding: 0;
            font-family: sans-serif;
        }
        div {
            width: 600px;
            margin: 50px auto 40px auto;
            padding: 50px;
            background-color: #fff;
        }
        h1 {
            font-size: 32px;
            margin: 0 0 20px 0;
        }
        p {
            margin: 20px 0;
            line-height: 1.4;
        }
        a {
            color: #38488f;
        }
    </style>
</head>
<body>
    <div>
        <h1>Example Domain</h1>
        <p>This domain is for use in illustrative examples in documents.</p>
        <p>You may use this domain in literature without prior coordination or asking for permission.</p>
        <p>
            <a href="https://www.iana.org/domains/example">More information...</a>
        </p>
    </div>
</body>
</html>
"#;
        self.load_html(html);
    }

    /// エラーページを読み込む
    fn load_error_page(&mut self, message: &str) {
        let html = format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {{
            font-family: sans-serif;
            margin: 40px;
            background-color: #fff;
        }}
        h1 {{
            color: #d00;
        }}
        p {{
            color: #666;
        }}
    </style>
</head>
<body>
    <h1>Page Not Found</h1>
    <p>{}</p>
    <p>The requested page could not be loaded.</p>
    <p>Note: This browser can only display built-in pages.</p>
</body>
</html>
"#,
            message
        );
        self.load_html(&html);
        self.state = BrowserState::Error;
        self.error_message = Some(message.into());
    }

    /// 戻る
    pub fn go_back(&mut self) {
        if self.history_pos > 1 {
            self.history_pos -= 1;
            let url = self.history[self.history_pos - 1].clone();
            self.url = url.clone();
            self.url_input = url.clone();
            self.cursor_pos = url.len();

            if url == "about:home" {
                self.load_default_page();
            } else if url.contains("example.com") {
                self.load_example_com();
            }
        }
    }

    /// 進む
    pub fn go_forward(&mut self) {
        if self.history_pos < self.history.len() {
            self.history_pos += 1;
            let url = self.history[self.history_pos - 1].clone();
            self.url = url.clone();
            self.url_input = url.clone();
            self.cursor_pos = url.len();

            if url == "about:home" {
                self.load_default_page();
            } else if url.contains("example.com") {
                self.load_example_com();
            }
        }
    }

    /// 戻れるか
    pub fn can_go_back(&self) -> bool {
        self.history_pos > 1
    }

    /// 進めるか
    pub fn can_go_forward(&self) -> bool {
        self.history_pos < self.history.len()
    }

    /// ウィンドウサイズを取得
    pub fn window_width(&self) -> u32 {
        BROWSER_WIDTH
    }

    pub fn window_height(&self) -> u32 {
        BROWSER_HEIGHT
    }

    // ========================================================================
    // イベント処理
    // ========================================================================

    /// マウスクリック
    pub fn on_mouse_click(&mut self, x: u32, y: u32) {
        // 戻るボタン
        if self.is_in_back_button(x, y) && self.can_go_back() {
            self.go_back();
            return;
        }

        // 進むボタン
        if self.is_in_forward_button(x, y) && self.can_go_forward() {
            self.go_forward();
            return;
        }

        // URLバー
        if self.is_in_url_bar(x, y) {
            self.url_focused = true;
            // カーソル位置を設定（簡易）
            let url_bar_x = BUTTON_SIZE * 2 + URL_BAR_PADDING * 3;
            let char_width = 6u32;
            let click_offset = x.saturating_sub(url_bar_x + 4);
            self.cursor_pos = (click_offset / char_width) as usize;
            self.cursor_pos = self.cursor_pos.min(self.url_input.len());
            return;
        }

        // コンテンツ領域クリックでURLバーのフォーカスを外す
        if y > TOOLBAR_HEIGHT {
            self.url_focused = false;
        }
    }

    /// マウス移動
    pub fn on_mouse_move(&mut self, x: u32, y: u32) {
        self.back_hover = self.is_in_back_button(x, y) && self.can_go_back();
        self.forward_hover = self.is_in_forward_button(x, y) && self.can_go_forward();
    }

    /// キー入力
    pub fn on_key_press(&mut self, key: char) {
        if !self.url_focused {
            return;
        }

        if key == '\n' || key == '\r' {
            // Enterでナビゲート
            let url = self.url_input.clone();
            self.navigate(&url);
        } else if key == '\x08' {
            // Backspace
            if self.cursor_pos > 0 {
                self.url_input.remove(self.cursor_pos - 1);
                self.cursor_pos -= 1;
            }
        } else if key >= ' ' && key <= '~' {
            // 印字可能文字
            self.url_input.insert(self.cursor_pos, key);
            self.cursor_pos += 1;
        }
    }

    /// スクロール
    pub fn on_scroll(&mut self, delta: i32) {
        let max_scroll = (self.content_height - (BROWSER_HEIGHT - TOOLBAR_HEIGHT) as f32).max(0.0);
        self.scroll_y = (self.scroll_y - delta as f32 * 20.0).clamp(0.0, max_scroll);
    }

    /// 戻るボタンの範囲か
    fn is_in_back_button(&self, x: u32, y: u32) -> bool {
        x >= URL_BAR_PADDING
            && x < URL_BAR_PADDING + BUTTON_SIZE
            && y >= URL_BAR_PADDING
            && y < URL_BAR_PADDING + BUTTON_SIZE
    }

    /// 進むボタンの範囲か
    fn is_in_forward_button(&self, x: u32, y: u32) -> bool {
        let fx = URL_BAR_PADDING + BUTTON_SIZE + 2;
        x >= fx && x < fx + BUTTON_SIZE && y >= URL_BAR_PADDING && y < URL_BAR_PADDING + BUTTON_SIZE
    }

    /// URLバーの範囲か
    fn is_in_url_bar(&self, x: u32, y: u32) -> bool {
        let url_x = BUTTON_SIZE * 2 + URL_BAR_PADDING * 3;
        let url_w = BROWSER_WIDTH - url_x - URL_BAR_PADDING;
        x >= url_x && x < url_x + url_w && y >= URL_BAR_PADDING && y < TOOLBAR_HEIGHT - URL_BAR_PADDING
    }

    // ========================================================================
    // レンダリング
    // ========================================================================

    /// 描画
    pub fn render(&self, image: &mut Image) {
        // 背景をクリア
        self.fill_rect(image, 0, 0, BROWSER_WIDTH, BROWSER_HEIGHT, CONTENT_BG);

        // コンテンツを描画
        self.render_content(image);

        // ツールバーを描画
        self.render_toolbar(image);
    }

    /// ツールバーを描画
    fn render_toolbar(&self, image: &mut Image) {
        // 背景
        self.fill_rect(image, 0, 0, BROWSER_WIDTH, TOOLBAR_HEIGHT, TOOLBAR_BG);

        // 戻るボタン
        let back_color = if self.back_hover { BUTTON_HOVER } else { BUTTON_BG };
        self.draw_button(image, URL_BAR_PADDING, URL_BAR_PADDING, BUTTON_SIZE, back_color);
        let back_text_color = if self.can_go_back() { TEXT_COLOR } else { URL_BAR_BORDER };
        self.draw_text(image, "<", URL_BAR_PADDING + 10, URL_BAR_PADDING + 8, back_text_color);

        // 進むボタン
        let forward_x = URL_BAR_PADDING + BUTTON_SIZE + 2;
        let forward_color = if self.forward_hover { BUTTON_HOVER } else { BUTTON_BG };
        self.draw_button(image, forward_x, URL_BAR_PADDING, BUTTON_SIZE, forward_color);
        let forward_text_color = if self.can_go_forward() { TEXT_COLOR } else { URL_BAR_BORDER };
        self.draw_text(image, ">", forward_x + 10, URL_BAR_PADDING + 8, forward_text_color);

        // URLバー
        let url_x = BUTTON_SIZE * 2 + URL_BAR_PADDING * 3;
        let url_w = BROWSER_WIDTH - url_x - URL_BAR_PADDING;
        let url_h = TOOLBAR_HEIGHT - URL_BAR_PADDING * 2;
        
        // 背景
        self.fill_rect(image, url_x, URL_BAR_PADDING, url_w, url_h, URL_BAR_BG);
        
        // 枠
        self.draw_rect_border(image, url_x, URL_BAR_PADDING, url_w, url_h, URL_BAR_BORDER);

        // URL テキスト
        self.draw_text(image, &self.url_input, url_x + 4, URL_BAR_PADDING + 8, TEXT_COLOR);

        // カーソル（フォーカス時）
        if self.url_focused {
            let cursor_x = url_x + 4 + (self.cursor_pos as u32) * 6;
            self.fill_rect(image, cursor_x, URL_BAR_PADDING + 4, 1, url_h - 8, TEXT_COLOR);
        }

        // ツールバーの下線
        self.fill_rect(image, 0, TOOLBAR_HEIGHT - 1, BROWSER_WIDTH, 1, URL_BAR_BORDER);
    }

    /// コンテンツを描画
    fn render_content(&self, image: &mut Image) {
        let content_top = TOOLBAR_HEIGHT as f32;
        let viewport = Rect::new(
            10.0,
            content_top + 10.0 - self.scroll_y,
            (BROWSER_WIDTH - 20) as f32,
            (BROWSER_HEIGHT - TOOLBAR_HEIGHT - 20) as f32,
        );

        // クリッピング領域を設定
        let clip_y = TOOLBAR_HEIGHT;

        // 描画リストをレンダリング
        for cmd in &self.display_list {
            self.render_command(image, cmd, viewport, clip_y);
        }
    }

    /// 描画コマンドを実行
    fn render_command(&self, image: &mut Image, cmd: &super::render::DisplayCommand, viewport: Rect, clip_y: u32) {
        match cmd {
            super::render::DisplayCommand::SolidColor(color, rect) => {
                let gfx_color = Color {
                    red: color.r,
                    green: color.g,
                    blue: color.b,
                    alpha: color.a,
                };
                let x = (rect.x + viewport.x) as u32;
                let y = (rect.y + viewport.y) as u32;
                if y >= clip_y && y < BROWSER_HEIGHT {
                    self.fill_rect(image, x, y, rect.width as u32, rect.height as u32, gfx_color);
                }
            }
            super::render::DisplayCommand::Text(text, color, x, y, font_size) => {
                let gfx_color = Color {
                    red: color.r,
                    green: color.g,
                    blue: color.b,
                    alpha: color.a,
                };
                let px = (*x + viewport.x) as u32;
                let py = (*y + viewport.y) as u32;
                if py >= clip_y && py < BROWSER_HEIGHT {
                    let scale = (*font_size / 6.0).max(1.0) as u32;
                    self.draw_text_scaled(image, text, px, py, gfx_color, scale);
                }
            }
            super::render::DisplayCommand::HorizontalRule(color, x, y, width) => {
                let gfx_color = Color {
                    red: color.r,
                    green: color.g,
                    blue: color.b,
                    alpha: color.a,
                };
                let px = (*x + viewport.x) as u32;
                let py = (*y + viewport.y) as u32;
                if py >= clip_y && py < BROWSER_HEIGHT {
                    self.fill_rect(image, px, py, *width as u32, 1, gfx_color);
                }
            }
            _ => {}
        }
    }

    // ========================================================================
    // 描画ユーティリティ
    // ========================================================================

    fn fill_rect(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32, color: Color) {
        for dy in 0..h {
            for dx in 0..w {
                let px = x + dx;
                let py = y + dy;
                if px < image.width() && py < image.height() {
                    image.set_pixel(px, py, color);
                }
            }
        }
    }

    fn draw_rect_border(&self, image: &mut Image, x: u32, y: u32, w: u32, h: u32, color: Color) {
        for dx in 0..w {
            if x + dx < image.width() {
                if y < image.height() {
                    image.set_pixel(x + dx, y, color);
                }
                if y + h - 1 < image.height() {
                    image.set_pixel(x + dx, y + h - 1, color);
                }
            }
        }
        for dy in 0..h {
            if y + dy < image.height() {
                if x < image.width() {
                    image.set_pixel(x, y + dy, color);
                }
                if x + w - 1 < image.width() {
                    image.set_pixel(x + w - 1, y + dy, color);
                }
            }
        }
    }

    fn draw_button(&self, image: &mut Image, x: u32, y: u32, size: u32, bg_color: Color) {
        self.fill_rect(image, x, y, size, size, bg_color);
        self.draw_rect_border(image, x, y, size, size, URL_BAR_BORDER);
    }

    fn draw_text(&self, image: &mut Image, text: &str, x: u32, y: u32, color: Color) {
        self.draw_text_scaled(image, text, x, y, color, 2);
    }

    fn draw_text_scaled(&self, image: &mut Image, text: &str, x: u32, y: u32, color: Color, scale: u32) {
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
                            for sy in 0..scale {
                                for sx in 0..scale {
                                    let px = cx + col * scale + sx;
                                    let py = y + (row as u32) * scale + sy;
                                    if px < image.width() && py < image.height() {
                                        image.set_pixel(px, py, color);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            cx += 5 * scale + 1;
        }
    }
}

impl Default for Browser {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Default User Agent CSS
// ============================================================================

const DEFAULT_USER_AGENT_CSS: &str = r#"
html, body { display: block; }
head { display: none; }
div, section, article, header, footer, nav, aside, main { display: block; }
h1, h2, h3, h4, h5, h6, p { display: block; }
ul, ol, li { display: block; }
a { display: inline; color: #0000EE; }
span, strong, em, b, i { display: inline; }
"#;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_creation() {
        let browser = Browser::new();
        assert_eq!(browser.state, BrowserState::Idle);
    }

    #[test]
    fn test_history() {
        let mut browser = Browser::new();
        browser.navigate("http://example.com");
        
        assert!(browser.can_go_back());
        assert!(!browser.can_go_forward());
        
        browser.go_back();
        assert!(!browser.can_go_back());
        assert!(browser.can_go_forward());
    }
}
