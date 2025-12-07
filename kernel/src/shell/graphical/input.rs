// ============================================================================
// src/shell/graphical/input.rs - Graphical Shell Input Handling
// ============================================================================
//!
//! # グラフィカルシェル入力処理

#![allow(dead_code)]

use crate::io::hid::{InputKeyCode, InputKeyState, InputKeyEvent, MouseEvt};

use super::shell::GraphicalShell;

impl GraphicalShell {
    /// キーイベントを処理
    pub fn handle_key(&mut self, event: InputKeyEvent) {
        if event.state != InputKeyState::Pressed {
            return;
        }

        // カーソルを表示
        self.cursor_visible = true;
        self.last_cursor_toggle = crate::task::timer::current_tick();

        // Ctrl修飾キーの処理
        if event.modifiers().ctrl {
            match event.key {
                InputKeyCode::C => {
                    // Ctrl+C: 入力をキャンセル
                    self.input_buffer.clear();
                    self.print("^C\n");
                    self.draw_prompt();
                    return;
                }
                InputKeyCode::L => {
                    // Ctrl+L: 画面クリア
                    self.clear_screen();
                    self.draw_prompt();
                    return;
                }
                InputKeyCode::A => {
                    // Ctrl+A: 行頭へ
                    self.input_buffer.move_home();
                    self.redraw();
                    return;
                }
                InputKeyCode::E => {
                    // Ctrl+E: 行末へ
                    self.input_buffer.move_end();
                    self.redraw();
                    return;
                }
                InputKeyCode::K => {
                    // Ctrl+K: 行末まで削除
                    self.input_buffer.clear_to_end();
                    self.redraw();
                    return;
                }
                InputKeyCode::U => {
                    // Ctrl+U: 行頭まで削除
                    self.input_buffer.clear_to_start();
                    self.redraw();
                    return;
                }
                InputKeyCode::W => {
                    // Ctrl+W: 単語削除
                    self.input_buffer.delete_word();
                    self.redraw();
                    return;
                }
                _ => {}
            }
        }

        // Alt修飾キーの処理
        if event.modifiers().alt {
            match event.key {
                InputKeyCode::Left => {
                    self.input_buffer.move_word_left();
                    self.redraw();
                    return;
                }
                InputKeyCode::Right => {
                    self.input_buffer.move_word_right();
                    self.redraw();
                    return;
                }
                _ => {}
            }
        }

        // 通常キー処理
        match event.key {
            InputKeyCode::Enter => {
                self.submit_input();
            }
            InputKeyCode::Backspace => {
                self.completions.clear();
                self.input_buffer.backspace();
                self.redraw();
            }
            InputKeyCode::Delete => {
                self.completions.clear();
                self.input_buffer.delete();
                self.redraw();
            }
            InputKeyCode::Left => {
                self.input_buffer.move_left();
                self.redraw();
            }
            InputKeyCode::Right => {
                self.input_buffer.move_right();
                self.redraw();
            }
            InputKeyCode::Home => {
                self.input_buffer.move_home();
                self.redraw();
            }
            InputKeyCode::End => {
                self.input_buffer.move_end();
                self.redraw();
            }
            InputKeyCode::Up => {
                self.history_prev();
            }
            InputKeyCode::Down => {
                self.history_next();
            }
            InputKeyCode::Tab => {
                self.handle_tab();
            }
            InputKeyCode::PageUp => {
                self.scroll_up();
            }
            InputKeyCode::PageDown => {
                self.scroll_down();
            }
            InputKeyCode::Escape => {
                // 補完をキャンセル
                self.completions.clear();
                self.redraw();
            }
            InputKeyCode::Insert => {
                // インサートモード切り替え（現在は無視）
            }
            InputKeyCode::CapsLock | InputKeyCode::NumLock | InputKeyCode::ScrollLock => {
                // ロックキーは無視（修飾キー状態は自動更新される）
            }
            _ => {
                // 文字入力
                if let Some(c) = event.to_char() {
                    // 印刷可能なASCII文字をすべて受け入れる（空白0x20から~0x7E）
                    if c >= ' ' && c <= '~' {
                        self.completions.clear();
                        self.input_buffer.insert(c);
                        self.redraw();
                    }
                }
            }
        }
    }

    /// マウスイベントを処理
    pub fn handle_mouse(&mut self, event: MouseEvt) {
        let fb = unsafe { &*self.fb };
        let max_x = fb.width() as i32;
        let max_y = fb.height() as i32;
        
        // 古いカーソル位置を保存（再描画用）
        let old_x = self.mouse.x;
        let old_y = self.mouse.y;
        
        // マウス状態を更新
        self.mouse.update(&event, max_x, max_y);
        
        // マウスカーソルが表示されている場合、描画を更新
        if self.show_mouse_cursor {
            // 古いカーソル位置を消去（背景色で塗りつぶし）
            self.erase_mouse_cursor(old_x, old_y);
            
            // 新しいカーソル位置を描画
            self.draw_mouse_cursor();
        }
        
        // クリックによるスクロール操作など（将来拡張用）
        if event.left_down && self.mouse.y < 20 {
            // 画面上部クリックでスクロールアップ
            if self.scroll_offset < self.output_lines.len().saturating_sub(1) {
                self.scroll_offset += 1;
                self.redraw();
            }
        } else if event.right_down && self.mouse.y > max_y - 20 {
            // 画面下部右クリックでスクロールダウン
            if self.scroll_offset > 0 {
                self.scroll_offset -= 1;
                self.redraw();
            }
        }
    }
}
