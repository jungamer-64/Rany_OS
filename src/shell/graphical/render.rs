// ============================================================================
// src/shell/graphical/render.rs - Graphical Shell Rendering
// ============================================================================
//!
//! # グラフィカルシェル描画

#![allow(dead_code)]

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use crate::graphics::Color;

use super::shell::GraphicalShell;
use super::types::ConsoleLine;

impl GraphicalShell {
    /// 画面を再描画
    pub fn redraw(&mut self) {
        unsafe {
            (*self.fb).clear(self.theme.background);
        }

        let max_visible_lines = (self.rows - 2) as usize; // 最後の2行は入力用
        let total_lines = self.output_lines.len();
        
        // 表示開始行を計算
        let start_line = if total_lines > max_visible_lines {
            total_lines - max_visible_lines - self.scroll_offset
        } else {
            0
        };

        // 出力行を収集（借用を解消）
        let lines_to_draw: Vec<(alloc::string::String, Color)> = self.output_lines
            .iter()
            .skip(start_line)
            .take(max_visible_lines)
            .map(|line| (line.text.clone(), line.color))
            .collect();

        // 出力行を描画
        let mut y = 0i32;
        for (text, color) in lines_to_draw {
            self.draw_text(0, y, &text, color);
            y += self.font.height() as i32;
        }

        // 入力行を描画
        let input_y = (self.rows - 2) as i32 * self.font.height() as i32;
        
        // プロンプトを描画（ローカルコピー）
        let prompt = self.prompt.clone();
        let prompt_color = self.theme.prompt;
        self.draw_text(0, input_y, &prompt, prompt_color);
        
        // 入力バッファを描画（ローカルコピー）
        let prompt_width = prompt.len() as i32 * self.font.width() as i32;
        let input_text = self.input_buffer.as_str().to_string();
        let input_color = self.theme.input;
        self.draw_text(prompt_width, input_y, &input_text, input_color);

        // カーソルを描画
        if self.cursor_visible {
            let cursor_x = prompt_width + (self.input_buffer.cursor as i32 * self.font.width() as i32);
            self.draw_cursor(cursor_x, input_y);
        }

        // 補完候補を表示
        if !self.completions.is_empty() {
            let comp_y = input_y + self.font.height() as i32;
            let mut comp_text = alloc::string::String::from("  ");
            for (i, comp) in self.completions.iter().enumerate().take(5) {
                if i == self.completion_index {
                    comp_text.push_str(&format!("[{}] ", comp));
                } else {
                    comp_text.push_str(&format!("{} ", comp));
                }
            }
            if self.completions.len() > 5 {
                comp_text.push_str(&format!("... (+{})", self.completions.len() - 5));
            }
            self.draw_text(0, comp_y, &comp_text, self.theme.info);
        }
    }

    /// テキストを描画
    pub fn draw_text(&mut self, x: i32, y: i32, text: &str, color: Color) {
        unsafe {
            self.font.draw_string(&mut *self.fb, x, y, text, color, Some(self.theme.background));
        }
    }

    /// カーソルを描画
    pub fn draw_cursor(&mut self, x: i32, y: i32) {
        // ブロックカーソル
        let cursor_width = self.font.width() as i32;
        let cursor_height = self.font.height() as i32;
        
        unsafe {
            for dy in 0..cursor_height {
                for dx in 0..cursor_width {
                    (*self.fb).set_pixel(x + dx, y + dy, self.theme.cursor);
                }
            }
        }
        
        // カーソル位置の文字を反転色で描画
        let c = self.input_buffer.content.chars().nth(self.input_buffer.cursor).unwrap_or(' ');
        unsafe {
            self.font.draw_char(&mut *self.fb, x, y, c, self.theme.background, None);
        }
    }

    /// マウスカーソルを描画（シンプルな十字）
    pub fn draw_mouse_cursor(&mut self) {
        let fb = unsafe { &mut *self.fb };
        let x = self.mouse.x;
        let y = self.mouse.y;
        
        // カーソル色（白）
        let color = Color::WHITE;
        
        // 簡単な十字カーソル（5x5）
        for i in 0..5i32 {
            // 横線
            fb.set_pixel(x + i - 2, y, color);
        }
        for i in 0..5i32 {
            // 縦線
            fb.set_pixel(x, y + i - 2, color);
        }
    }
    
    /// マウスカーソルを消去（背景色で上書き）
    pub fn erase_mouse_cursor(&mut self, x: i32, y: i32) {
        let fb = unsafe { &mut *self.fb };
        
        // 背景色で上書き
        let bg = self.theme.background;
        
        // 十字カーソル領域を消去
        for i in 0..5i32 {
            fb.set_pixel(x + i - 2, y, bg);
        }
        for i in 0..5i32 {
            fb.set_pixel(x, y + i - 2, bg);
        }
    }
}
