// ============================================================================
// src/application/browser/render.rs - Rendering
// ============================================================================
//!
//! # レンダリング
//!
//! レイアウトツリーを走査し、描画コマンドを生成。

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::layout::{LayoutBox, BoxType, Rect, Dimensions};
use super::css::{Color, Value};
use super::dom::NodeType;

// ============================================================================
// Display Commands
// ============================================================================

/// 描画コマンド
#[derive(Debug, Clone)]
pub enum DisplayCommand {
    /// 矩形を塗りつぶす
    SolidColor(Color, Rect),
    /// 矩形の枠線
    Border(Color, f32, Rect),
    /// テキストを描画
    Text(String, Color, f32, f32, f32), // text, color, x, y, font_size
    /// 画像を描画
    Image(String, Rect), // src, rect
    /// 水平線
    HorizontalRule(Color, f32, f32, f32), // color, x, y, width
}

/// 描画リスト
pub type DisplayList = Vec<DisplayCommand>;

// ============================================================================
// Rendering
// ============================================================================

/// レイアウトツリーから描画リストを生成
pub fn build_display_list(layout_root: &LayoutBox) -> DisplayList {
    let mut list = Vec::new();
    render_layout_box(&mut list, layout_root);
    list
}

/// 単一のレイアウトボックスをレンダリング
fn render_layout_box(list: &mut DisplayList, layout_box: &LayoutBox) {
    render_background(list, layout_box);
    render_borders(list, layout_box);
    render_text(list, layout_box);

    for child in &layout_box.children {
        render_layout_box(list, child);
    }
}

/// 背景を描画
fn render_background(list: &mut DisplayList, layout_box: &LayoutBox) {
    let style = match layout_box.styled_node {
        Some(s) => s,
        None => return,
    };

    let color = match style.color("background-color") {
        Some(c) if c.a > 0 => c,
        _ => return,
    };

    list.push(DisplayCommand::SolidColor(
        color,
        layout_box.dimensions.border_box(),
    ));
}

/// 枠線を描画
fn render_borders(list: &mut DisplayList, layout_box: &LayoutBox) {
    let style = match layout_box.styled_node {
        Some(s) => s,
        None => return,
    };

    let color = match style.color("border-color") {
        Some(c) => c,
        None => {
            // デフォルトは currentColor (テキスト色)
            style.color("color").unwrap_or(Color::BLACK)
        }
    };

    let d = &layout_box.dimensions;
    let border_box = d.border_box();

    // 上
    if d.border.top > 0.0 {
        list.push(DisplayCommand::SolidColor(
            color,
            Rect::new(
                border_box.x,
                border_box.y,
                border_box.width,
                d.border.top,
            ),
        ));
    }

    // 下
    if d.border.bottom > 0.0 {
        list.push(DisplayCommand::SolidColor(
            color,
            Rect::new(
                border_box.x,
                border_box.y + border_box.height - d.border.bottom,
                border_box.width,
                d.border.bottom,
            ),
        ));
    }

    // 左
    if d.border.left > 0.0 {
        list.push(DisplayCommand::SolidColor(
            color,
            Rect::new(
                border_box.x,
                border_box.y,
                d.border.left,
                border_box.height,
            ),
        ));
    }

    // 右
    if d.border.right > 0.0 {
        list.push(DisplayCommand::SolidColor(
            color,
            Rect::new(
                border_box.x + border_box.width - d.border.right,
                border_box.y,
                d.border.right,
                border_box.height,
            ),
        ));
    }

    // <hr> 要素の特殊処理
    if let Some(styled) = layout_box.styled_node {
        if styled.node.tag_name() == Some("hr") {
            list.push(DisplayCommand::HorizontalRule(
                Color::new(128, 128, 128),
                d.content.x,
                d.content.y + d.content.height / 2.0,
                d.content.width,
            ));
        }
    }
}

/// テキストを描画
fn render_text(list: &mut DisplayList, layout_box: &LayoutBox) {
    let style = match layout_box.styled_node {
        Some(s) => s,
        None => return,
    };

    // テキストノードのみ
    let text = match &style.node.node_type {
        NodeType::Text(s) => s,
        _ => return,
    };

    // 空白のみのテキストはスキップ
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }

    let color = style.color("color").unwrap_or(Color::BLACK);
    let font_size = style.length_px("font-size").max(16.0);

    let d = &layout_box.dimensions;

    list.push(DisplayCommand::Text(
        trimmed.into(),
        color,
        d.content.x,
        d.content.y,
        font_size,
    ));
}

// ============================================================================
// Rendering to Image
// ============================================================================

use crate::graphics::image::Image;
use crate::graphics::Color as GraphicsColor;

/// 描画リストを画像にレンダリング
pub fn paint(display_list: &DisplayList, bounds: Rect, image: &mut Image) {
    for command in display_list {
        paint_command(command, bounds, image);
    }
}

/// 単一コマンドを描画
fn paint_command(command: &DisplayCommand, _bounds: Rect, image: &mut Image) {
    match command {
        DisplayCommand::SolidColor(color, rect) => {
            paint_solid_color(image, color, rect);
        }
        DisplayCommand::Border(color, width, rect) => {
            paint_border(image, color, *width, rect);
        }
        DisplayCommand::Text(text, color, x, y, font_size) => {
            paint_text(image, text, color, *x, *y, *font_size);
        }
        DisplayCommand::Image(_src, _rect) => {
            // 画像レンダリングは未実装
        }
        DisplayCommand::HorizontalRule(color, x, y, width) => {
            paint_horizontal_rule(image, color, *x, *y, *width);
        }
    }
}

/// 塗りつぶし矩形を描画
fn paint_solid_color(image: &mut Image, color: &Color, rect: &Rect) {
    let gfx_color = GraphicsColor {
        red: color.r,
        green: color.g,
        blue: color.b,
        alpha: color.a,
    };

    let x0 = rect.x.max(0.0) as u32;
    let y0 = rect.y.max(0.0) as u32;
    let x1 = rect.right().min(image.width() as f32) as u32;
    let y1 = rect.bottom().min(image.height() as f32) as u32;

    for y in y0..y1 {
        for x in x0..x1 {
            if color.a == 255 {
                image.set_pixel(x, y, gfx_color);
            } else {
                // アルファブレンド
                let existing = image.get_pixel(x, y);
                let alpha = color.a as f32 / 255.0;
                let blended = GraphicsColor {
                    red: (color.r as f32 * alpha + existing.red as f32 * (1.0 - alpha)) as u8,
                    green: (color.g as f32 * alpha + existing.green as f32 * (1.0 - alpha)) as u8,
                    blue: (color.b as f32 * alpha + existing.blue as f32 * (1.0 - alpha)) as u8,
                    alpha: 255,
                };
                image.set_pixel(x, y, blended);
            }
        }
    }
}

/// 枠線を描画
fn paint_border(image: &mut Image, color: &Color, width: f32, rect: &Rect) {
    let gfx_color = GraphicsColor {
        red: color.r,
        green: color.g,
        blue: color.b,
        alpha: color.a,
    };

    let x0 = rect.x.max(0.0) as u32;
    let y0 = rect.y.max(0.0) as u32;
    let x1 = rect.right().min(image.width() as f32) as u32;
    let y1 = rect.bottom().min(image.height() as f32) as u32;
    let w = width as u32;

    // 上
    for y in y0..y0.saturating_add(w).min(y1) {
        for x in x0..x1 {
            image.set_pixel(x, y, gfx_color);
        }
    }

    // 下
    for y in y1.saturating_sub(w).max(y0)..y1 {
        for x in x0..x1 {
            image.set_pixel(x, y, gfx_color);
        }
    }

    // 左
    for x in x0..x0.saturating_add(w).min(x1) {
        for y in y0..y1 {
            image.set_pixel(x, y, gfx_color);
        }
    }

    // 右
    for x in x1.saturating_sub(w).max(x0)..x1 {
        for y in y0..y1 {
            image.set_pixel(x, y, gfx_color);
        }
    }
}

/// 水平線を描画
fn paint_horizontal_rule(image: &mut Image, color: &Color, x: f32, y: f32, width: f32) {
    let gfx_color = GraphicsColor {
        red: color.r,
        green: color.g,
        blue: color.b,
        alpha: color.a,
    };

    let x0 = x.max(0.0) as u32;
    let y0 = y.max(0.0) as u32;
    let x1 = (x + width).min(image.width() as f32) as u32;

    if y0 < image.height() {
        for px in x0..x1 {
            image.set_pixel(px, y0, gfx_color);
        }
    }
}

/// テキストを描画
fn paint_text(image: &mut Image, text: &str, color: &Color, x: f32, y: f32, font_size: f32) {
    let gfx_color = GraphicsColor {
        red: color.r,
        green: color.g,
        blue: color.b,
        alpha: color.a,
    };

    // 簡易フォントレンダリング（ビットマップフォント）
    let scale = (font_size / 6.0).max(1.0) as u32;
    let mut cx = x as u32;
    let cy = y as u32;

    for ch in text.chars() {
        draw_char(image, ch, cx, cy, scale, gfx_color);
        cx += 5 * scale + 1;
    }
}

/// 文字を描画（4x6 ビットマップフォント）
fn draw_char(image: &mut Image, ch: char, x: u32, y: u32, scale: u32, color: GraphicsColor) {
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

    let code = ch as u32;
    if code < 0x20 || code > 0x7E {
        return;
    }

    let glyph = &FONT_4X6[(code - 0x20) as usize];

    for (row, &bits) in glyph.iter().enumerate() {
        for col in 0..4 {
            if (bits >> (3 - col)) & 1 == 1 {
                for sy in 0..scale {
                    for sx in 0..scale {
                        let px = x + col * scale + sx;
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

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_command() {
        let cmd = DisplayCommand::SolidColor(
            Color::RED,
            Rect::new(10.0, 20.0, 100.0, 50.0),
        );
        
        match cmd {
            DisplayCommand::SolidColor(c, r) => {
                assert_eq!(c.r, 255);
                assert_eq!(r.width, 100.0);
            }
            _ => panic!("Expected SolidColor"),
        }
    }
}
