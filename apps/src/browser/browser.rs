// ============================================================================
// apps/src/browser/browser.rs - Browser Application
// ============================================================================
//!
//! # Browser Application
//!
//! A web browser with URL bar and navigation buttons.

#![allow(unused_imports)]
#![allow(dead_code)]

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use graphic_types::{Color, Image};

use super::css::{CssColor, CssParser, Stylesheet};
use super::dom::Node;
use super::html::HtmlParser;
use super::layout::{layout_tree, Dimensions, Rect};
use super::render::{build_display_list, DisplayCommand, DisplayList};
use super::style::style_tree;

// ============================================================================
// Constants
// ============================================================================

/// Browser window width
pub const BROWSER_WIDTH: u32 = 800;
/// Browser window height
pub const BROWSER_HEIGHT: u32 = 600;

/// Toolbar height
const TOOLBAR_HEIGHT: u32 = 36;
/// URL bar padding
const URL_BAR_PADDING: u32 = 4;
/// Button size
const BUTTON_SIZE: u32 = 28;

// Colors
const TOOLBAR_BG: Color = Color {
    red: 240,
    green: 240,
    blue: 240,
    alpha: 255,
};
const URL_BAR_BG: Color = Color {
    red: 255,
    green: 255,
    blue: 255,
    alpha: 255,
};
const URL_BAR_BORDER: Color = Color {
    red: 180,
    green: 180,
    blue: 180,
    alpha: 255,
};
const BUTTON_BG: Color = Color {
    red: 220,
    green: 220,
    blue: 220,
    alpha: 255,
};
const BUTTON_HOVER: Color = Color {
    red: 200,
    green: 200,
    blue: 200,
    alpha: 255,
};
const TEXT_COLOR: Color = Color {
    red: 0,
    green: 0,
    blue: 0,
    alpha: 255,
};
const CONTENT_BG: Color = Color {
    red: 255,
    green: 255,
    blue: 255,
    alpha: 255,
};
const LINK_COLOR: Color = Color {
    red: 0,
    green: 0,
    blue: 238,
    alpha: 255,
};

// ============================================================================
// Browser State
// ============================================================================

/// Browser state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserState {
    /// Idle
    Idle,
    /// Loading
    Loading,
    /// Error
    Error,
}

/// Browser application
pub struct Browser {
    /// Current URL
    url: String,
    /// URL input text
    url_input: String,
    /// History
    history: Vec<String>,
    /// History position
    history_pos: usize,
    /// DOM tree
    dom: Option<Node>,
    /// Stylesheet
    stylesheet: Stylesheet,
    /// Display list
    display_list: DisplayList,
    /// State
    state: BrowserState,
    /// Error message
    error_message: Option<String>,
    /// Scroll position Y
    scroll_y: f32,
    /// Content height
    content_height: f32,
    /// Back button hover
    back_hover: bool,
    /// Forward button hover
    forward_hover: bool,
    /// URL bar focused
    url_focused: bool,
    /// Cursor position
    cursor_pos: usize,
}

impl Browser {
    /// Create new browser
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
        browser.load_default_page();

        // Record the initial page in history so navigation works as expected
        // (i.e. the user can go back to the welcome page after navigating
        //  somewhere else).
        browser.history.push(browser.url.clone());
        browser.history_pos = browser.history.len();

        browser
    }

    /// Load default welcome page
    fn load_default_page(&mut self) {
        let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Rany Browser</title>
</head>
<body>
    <h1>Welcome to Rany Browser</h1>
    <p>This is a simple web browser engine built for Rany OS.</p>
    <p>Enter a URL in the address bar above to navigate.</p>
    <hr>
    <h2>Supported Features</h2>
    <p>Basic HTML tags: div, p, h1-h6, a, span</p>
    <p>Basic CSS: color, background-color, font-size</p>
</body>
</html>
"#;
        self.load_html(html);
        self.url = "about:home".into();
        self.url_input = "about:home".into();
        self.cursor_pos = self.url_input.len();
    }

    /// Load HTML content
    pub fn load_html(&mut self, html: &str) {
        self.state = BrowserState::Loading;

        // Parse HTML
        let dom = HtmlParser::parse(html);

        // Parse CSS
        let stylesheet = CssParser::parse("");

        // Build style tree
        let style_tree = style_tree(&dom, &stylesheet);

        // Build layout tree
        let viewport = Dimensions {
            content: Rect::new(
                0.0,
                0.0,
                (BROWSER_WIDTH - 20) as f32,
                (BROWSER_HEIGHT - TOOLBAR_HEIGHT - 20) as f32,
            ),
            ..Default::default()
        };
        let _layout_tree = layout_tree(&style_tree, viewport);

        // Build display list
        self.display_list = Vec::new();
        self.content_height = 0.0;

        // Store DOM
        self.dom = Some(dom);
        self.stylesheet = stylesheet;
        self.state = BrowserState::Idle;
        self.scroll_y = 0.0;
    }

    /// Navigate to URL
    pub fn navigate(&mut self, url: &str) {
        self.url = url.into();
        self.url_input = url.into();
        self.cursor_pos = url.len();

        // Add to history
        if self.history_pos < self.history.len() {
            self.history.truncate(self.history_pos);
        }
        self.history.push(url.into());
        self.history_pos = self.history.len();

        // Load content based on URL
        if url == "about:home" || url.is_empty() {
            self.load_default_page();
        } else {
            self.load_error_page(&format!("Cannot load: {}", url));
        }
    }

    /// Load error page
    fn load_error_page(&mut self, message: &str) {
        let html = format!(
            r#"
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Page Not Found</h1>
    <p>{}</p>
    <p>The requested page could not be loaded.</p>
</body>
</html>
"#,
            message
        );
        self.load_html(&html);
        self.state = BrowserState::Error;
        self.error_message = Some(message.into());
    }

    /// Go back in history
    pub fn go_back(&mut self) {
        if self.history_pos > 1 {
            self.history_pos -= 1;
            let url = self.history[self.history_pos - 1].clone();
            self.url = url.clone();
            self.url_input = url;
        }
    }

    /// Go forward in history
    pub fn go_forward(&mut self) {
        if self.history_pos < self.history.len() {
            self.history_pos += 1;
            let url = self.history[self.history_pos - 1].clone();
            self.url = url.clone();
            self.url_input = url;
        }
    }

    /// Can go back?
    pub fn can_go_back(&self) -> bool {
        self.history_pos > 1
    }

    /// Can go forward?
    pub fn can_go_forward(&self) -> bool {
        self.history_pos < self.history.len()
    }

    /// Get window width
    pub fn window_width(&self) -> u32 {
        BROWSER_WIDTH
    }

    /// Get window height
    pub fn window_height(&self) -> u32 {
        BROWSER_HEIGHT
    }

    // ========================================================================
    // Event Handling
    // ========================================================================

    /// Handle mouse click
    pub fn on_mouse_click(&mut self, x: u32, y: u32) {
        // Back button
        if self.is_in_back_button(x, y) && self.can_go_back() {
            self.go_back();
            return;
        }

        // Forward button
        if self.is_in_forward_button(x, y) && self.can_go_forward() {
            self.go_forward();
            return;
        }

        // URL bar
        if self.is_in_url_bar(x, y) {
            self.url_focused = true;
            return;
        }

        // Content area click removes URL focus
        if y > TOOLBAR_HEIGHT {
            self.url_focused = false;
        }
    }

    /// Handle mouse move
    pub fn on_mouse_move(&mut self, x: u32, y: u32) {
        self.back_hover = self.is_in_back_button(x, y) && self.can_go_back();
        self.forward_hover = self.is_in_forward_button(x, y) && self.can_go_forward();
    }

    /// Handle key press
    pub fn on_key_press(&mut self, key: char) {
        if !self.url_focused {
            return;
        }

        if key == '\n' || key == '\r' {
            let url = self.url_input.clone();
            self.navigate(&url);
        } else if key == '\x08' {
            // Backspace
            if self.cursor_pos > 0 {
                self.url_input.remove(self.cursor_pos - 1);
                self.cursor_pos -= 1;
            }
        } else if key >= ' ' && key <= '~' {
            self.url_input.insert(self.cursor_pos, key);
            self.cursor_pos += 1;
        }
    }

    /// Handle scroll
    pub fn on_scroll(&mut self, delta: i32) {
        let max_scroll = (self.content_height - (BROWSER_HEIGHT - TOOLBAR_HEIGHT) as f32).max(0.0);
        self.scroll_y = (self.scroll_y - delta as f32 * 20.0).clamp(0.0, max_scroll);
    }

    fn is_in_back_button(&self, x: u32, y: u32) -> bool {
        x >= URL_BAR_PADDING
            && x < URL_BAR_PADDING + BUTTON_SIZE
            && y >= URL_BAR_PADDING
            && y < URL_BAR_PADDING + BUTTON_SIZE
    }

    fn is_in_forward_button(&self, x: u32, y: u32) -> bool {
        let fx = URL_BAR_PADDING + BUTTON_SIZE + 2;
        x >= fx && x < fx + BUTTON_SIZE && y >= URL_BAR_PADDING && y < URL_BAR_PADDING + BUTTON_SIZE
    }

    fn is_in_url_bar(&self, x: u32, y: u32) -> bool {
        let url_x = BUTTON_SIZE * 2 + URL_BAR_PADDING * 3;
        let url_w = BROWSER_WIDTH - url_x - URL_BAR_PADDING;
        x >= url_x
            && x < url_x + url_w
            && y >= URL_BAR_PADDING
            && y < TOOLBAR_HEIGHT - URL_BAR_PADDING
    }

    // ========================================================================
    // Rendering
    // ========================================================================

    /// Render browser to image
    pub fn render(&self, image: &mut Image) {
        // Clear background
        self.fill_rect(image, 0, 0, BROWSER_WIDTH, BROWSER_HEIGHT, CONTENT_BG);

        // Render content
        self.render_content(image);

        // Render toolbar
        self.render_toolbar(image);
    }

    fn render_toolbar(&self, image: &mut Image) {
        // Background
        self.fill_rect(image, 0, 0, BROWSER_WIDTH, TOOLBAR_HEIGHT, TOOLBAR_BG);

        // Back button
        let back_color = if self.back_hover {
            BUTTON_HOVER
        } else {
            BUTTON_BG
        };
        self.draw_button(
            image,
            URL_BAR_PADDING,
            URL_BAR_PADDING,
            BUTTON_SIZE,
            back_color,
        );

        // Forward button
        let forward_x = URL_BAR_PADDING + BUTTON_SIZE + 2;
        let forward_color = if self.forward_hover {
            BUTTON_HOVER
        } else {
            BUTTON_BG
        };
        self.draw_button(
            image,
            forward_x,
            URL_BAR_PADDING,
            BUTTON_SIZE,
            forward_color,
        );

        // URL bar
        let url_x = BUTTON_SIZE * 2 + URL_BAR_PADDING * 3;
        let url_w = BROWSER_WIDTH - url_x - URL_BAR_PADDING;
        let url_h = TOOLBAR_HEIGHT - URL_BAR_PADDING * 2;
        self.fill_rect(image, url_x, URL_BAR_PADDING, url_w, url_h, URL_BAR_BG);
        self.draw_rect_border(image, url_x, URL_BAR_PADDING, url_w, url_h, URL_BAR_BORDER);

        // Toolbar bottom border
        self.fill_rect(
            image,
            0,
            TOOLBAR_HEIGHT - 1,
            BROWSER_WIDTH,
            1,
            URL_BAR_BORDER,
        );
    }

    fn render_content(&self, _image: &mut Image) {
        // Stub - render display list to image
    }

    // ========================================================================
    // Drawing Utilities
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
                if y + h > 0 && y + h - 1 < image.height() {
                    image.set_pixel(x + dx, y + h - 1, color);
                }
            }
        }
        for dy in 0..h {
            if y + dy < image.height() {
                if x < image.width() {
                    image.set_pixel(x, y + dy, color);
                }
                if x + w > 0 && x + w - 1 < image.width() {
                    image.set_pixel(x + w - 1, y + dy, color);
                }
            }
        }
    }

    fn draw_button(&self, image: &mut Image, x: u32, y: u32, size: u32, bg_color: Color) {
        self.fill_rect(image, x, y, size, size, bg_color);
        self.draw_rect_border(image, x, y, size, size, URL_BAR_BORDER);
    }
}

impl Default for Browser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn browser_creation_smoke() -> bool {
        let browser = Browser::new();
        browser.state == BrowserState::Idle
    }

    pub fn history_smoke() -> bool {
        let mut browser = Browser::new();
        browser.navigate("http://example.com");

        if !browser.can_go_back() || browser.can_go_forward() {
            return false;
        }

        browser.go_back();
        !browser.can_go_back() && browser.can_go_forward()
    }
}
