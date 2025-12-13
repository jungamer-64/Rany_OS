// ============================================================================
// src/shell/graphical/input.rs - Graphical Shell Input Handling
// ============================================================================
//!
//! # グラフィカルシェル入力処理
//!
//! 入力変更時にカーソルキャッシュを更新
//! Split Borrows リファクタリング対応

#![allow(dead_code)]

use crate::graphics::Framebuffer;
use crate::io::hid::{InputKeyCode, InputKeyEvent, InputKeyState, KeyEventExt, MouseEvt};

use super::shell::GraphicalShell;

impl GraphicalShell {
    /// キーイベントを処理
    pub fn handle_key(&mut self, event: InputKeyEvent, fb: &mut Framebuffer) {
        if event.state != InputKeyState::Pressed {
            return;
        }

        // カーソルを表示
        self.state.cursor_visible = true;
        self.state.last_cursor_toggle = crate::task::timer::current_tick();

        // Ctrl修飾キーの処理
        if event.modifiers().ctrl {
            match event.key {
                InputKeyCode::C => {
                    self.state.input_buffer.clear();
                    self.update_cursor_cache();
                    self.print("^C\n");
                    self.draw_prompt(fb);
                    return;
                }
                InputKeyCode::L => {
                    self.clear_screen();
                    self.draw_prompt(fb);
                    return;
                }
                InputKeyCode::A => {
                    self.state.input_buffer.move_home();
                    self.update_cursor_cache();
                    self.redraw(fb);
                    return;
                }
                InputKeyCode::E => {
                    self.state.input_buffer.move_end();
                    self.update_cursor_cache();
                    self.redraw(fb);
                    return;
                }
                InputKeyCode::K => {
                    self.state.input_buffer.clear_to_end();
                    self.update_cursor_cache();
                    self.redraw(fb);
                    return;
                }
                InputKeyCode::U => {
                    self.state.input_buffer.clear_to_start();
                    self.update_cursor_cache();
                    self.redraw(fb);
                    return;
                }
                InputKeyCode::W => {
                    self.state.input_buffer.delete_word();
                    self.update_cursor_cache();
                    self.redraw(fb);
                    return;
                }
                _ => {}
            }
        }

        // Alt修飾キーの処理
        if event.modifiers().alt {
            match event.key {
                InputKeyCode::Left => {
                    self.state.input_buffer.move_word_left();
                    self.update_cursor_cache();
                    self.redraw(fb);
                    return;
                }
                InputKeyCode::Right => {
                    self.state.input_buffer.move_word_right();
                    self.update_cursor_cache();
                    self.redraw(fb);
                    return;
                }
                _ => {}
            }
        }

        // 通常キー処理
        match event.key {
            InputKeyCode::Enter => {
                self.submit_input(fb);
            }
            InputKeyCode::Backspace => {
                self.state.completions.clear();
                self.state.input_buffer.backspace();
                self.update_cursor_cache();
                self.redraw_input_only(fb); // 入力行のみ再描画（高速化）
            }
            InputKeyCode::Delete => {
                self.state.completions.clear();
                self.state.input_buffer.delete();
                self.update_cursor_cache();
                self.redraw_input_only(fb);
            }
            InputKeyCode::Left => {
                self.state.input_buffer.move_left();
                self.update_cursor_cache();
                self.redraw_cursor_only(fb); // カーソルのみ移動（高速化）
            }
            InputKeyCode::Right => {
                self.state.input_buffer.move_right();
                self.update_cursor_cache();
                self.redraw_cursor_only(fb);
            }
            InputKeyCode::Home => {
                self.state.input_buffer.move_home();
                self.update_cursor_cache();
                self.redraw_input_only(fb);
            }
            InputKeyCode::End => {
                self.state.input_buffer.move_end();
                self.update_cursor_cache();
                self.redraw_input_only(fb);
            }
            InputKeyCode::Up => {
                self.history_prev(fb);
            }
            InputKeyCode::Down => {
                self.history_next(fb);
            }
            InputKeyCode::Tab => {
                self.handle_tab(fb);
            }
            InputKeyCode::PageUp => {
                self.scroll_up(fb);
            }
            InputKeyCode::PageDown => {
                self.scroll_down(fb);
            }
            InputKeyCode::Escape => {
                self.state.completions.clear();
                self.redraw(fb);
            }
            InputKeyCode::Insert => {}
            InputKeyCode::CapsLock | InputKeyCode::NumLock | InputKeyCode::ScrollLock => {}
            _ => {
                if let Some(c) = event.to_char() {
                    if c >= ' ' && c <= '~' {
                        self.state.completions.clear();
                        self.state.input_buffer.insert(c);
                        self.update_cursor_cache();
                        self.redraw_input_only(fb);
                    }
                }
            }
        }
    }

    /// マウスイベントを処理（最適化版）
    ///
    /// マウス移動時は全画面再描画ではなく、古い位置と新しい位置の
    /// 2領域のみを更新することで、高解像度環境でのパフォーマンスを向上。
    #[cfg(feature = "mouse")]
    pub fn handle_mouse(&mut self, event: MouseEvt, fb: &mut Framebuffer) {
        let max_x = self.resources.fb_width as i32;
        let max_y = self.resources.fb_height as i32;

        // 移動前のマウス領域を保存
        let old_rect = self.state.mouse_rect();
        let old_x = self.state.mouse.x;
        let old_y = self.state.mouse.y;

        // マウス状態を更新
        self.state.mouse.update(&event, max_x, max_y);

        // マウス位置が変わった場合のみ再描画
        if self.state.show_mouse_cursor
            && (self.state.mouse.x != old_x || self.state.mouse.y != old_y)
        {
            // 最適化: 古い位置と新しい位置の2領域のみ再描画
            // - 古い位置: 背景を復元するため
            // - 新しい位置: 新しいカーソルを描画するため
            // full redraw() より大幅に高速
            self.redraw_mouse_region(fb, old_rect);
        }

        // 左クリックでスクロール（画面上部）
        if event.left_down && self.state.mouse.y < 20 {
            let max_scroll = self.state.output_lines.len().saturating_sub(1);
            if self.state.scroll_offset < max_scroll {
                self.state.scroll_offset += 1;
                self.redraw(fb);
            }
        }
        // 右クリックで逆スクロール（画面下部）
        else if event.right_down && self.state.mouse.y > max_y - 20 {
            if self.state.scroll_offset > 0 {
                self.state.scroll_offset -= 1;
                self.redraw(fb);
            }
        }
    }
}
