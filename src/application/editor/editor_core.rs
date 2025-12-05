// ============================================================================
// src/application/editor/editor_core.rs - Main Editor Struct
// ============================================================================
//!
//! # Editor - メインエディタ構造体

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::min;

use crate::fs::memfs::{read_file_content, write_file_content};
use crate::graphics::{Color, image::Image};

use super::buffer::TextBuffer;
use super::cursor::{Cursor, Selection};
use super::syntax::SyntaxHighlighter;
use super::font::get_char_bitmap;
use super::types::{EditorMode, ToolbarButton};
use super::constants::*;

/// 特殊キー
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialKey {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
}

/// テキストエディタ
pub struct Editor {
    /// テキストバッファ
    buffer: TextBuffer,
    /// カーソル
    cursor: Cursor,
    /// 選択範囲
    selection: Option<Selection>,
    /// スクロール位置（行）
    scroll_line: usize,
    /// スクロール位置（カラム）
    scroll_col: usize,
    /// エディタモード
    mode: EditorMode,
    /// シンタックスハイライター
    highlighter: SyntaxHighlighter,
    /// カーソル表示フラグ
    cursor_visible: bool,
    /// 最後のカーソル点滅時刻
    last_blink: u64,
    /// ホバー中のボタン
    hover_button: Option<ToolbarButton>,
    /// ダイアログ入力バッファ
    dialog_input: String,
    /// Undo履歴
    undo_stack: Vec<(String, usize)>,
    /// Redo履歴
    redo_stack: Vec<(String, usize)>,
    /// 現在のワーキングディレクトリ
    cwd: String,
}

impl Editor {
    /// 新しいエディタを作成
    pub fn new() -> Self {
        Self {
            buffer: TextBuffer::new(),
            cursor: Cursor::new(),
            selection: None,
            scroll_line: 0,
            scroll_col: 0,
            mode: EditorMode::Normal,
            highlighter: SyntaxHighlighter::new(),
            cursor_visible: true,
            last_blink: 0,
            hover_button: None,
            dialog_input: String::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            cwd: String::from("/"),
        }
    }

    /// ファイルからエディタを作成
    pub fn from_file(path: &str, cwd: &str) -> Result<Self, &'static str> {
        let mut editor = Self::new();
        editor.cwd = String::from(cwd);
        editor.open_file(path)?;
        Ok(editor)
    }

    /// ファイルを開く
    pub fn open_file(&mut self, path: &str) -> Result<(), &'static str> {
        match read_file_content(path, &self.cwd) {
            Ok(content) => {
                let text = String::from_utf8_lossy(&content);
                self.buffer = TextBuffer::from_str(&text);
                self.buffer.set_path(path);
                self.buffer.mark_saved();
                self.cursor = Cursor::new();
                self.selection = None;
                self.scroll_line = 0;
                self.scroll_col = 0;
                self.undo_stack.clear();
                self.redo_stack.clear();
                Ok(())
            }
            Err(_) => Err("Failed to open file"),
        }
    }

    /// ファイルを保存
    pub fn save_file(&mut self) -> Result<(), &'static str> {
        let path = match self.buffer.path() {
            Some(p) => p.clone(),
            None => return Err("No file path set"),
        };
        self.save_file_as(&path)
    }

    /// 名前を付けて保存
    pub fn save_file_as(&mut self, path: &str) -> Result<(), &'static str> {
        let content = self.buffer.text();
        match write_file_content(path, &self.cwd, content.as_bytes()) {
            Ok(_) => {
                self.buffer.set_path(path);
                self.buffer.mark_saved();
                Ok(())
            }
            Err(_) => Err("Failed to save file"),
        }
    }

    /// カーソルを表示範囲内に保つ
    fn ensure_cursor_visible(&mut self) {
        let line = self.cursor.line(&self.buffer);
        let col = self.cursor.column(&self.buffer);

        // 垂直スクロール
        if line < self.scroll_line {
            self.scroll_line = line;
        } else if line >= self.scroll_line + VISIBLE_LINES {
            self.scroll_line = line - VISIBLE_LINES + 1;
        }

        // 水平スクロール
        if col < self.scroll_col {
            self.scroll_col = col;
        } else if col >= self.scroll_col + VISIBLE_COLS {
            self.scroll_col = col - VISIBLE_COLS + 1;
        }
    }

    /// 現在の状態をUndo履歴に保存
    fn save_undo_state(&mut self) {
        let text = self.buffer.text();
        let pos = self.cursor.position;
        self.undo_stack.push((text, pos));
        self.redo_stack.clear();
        
        // 履歴のサイズ制限
        if self.undo_stack.len() > 100 {
            self.undo_stack.remove(0);
        }
    }

    /// Undo
    pub fn undo(&mut self) {
        if let Some((text, pos)) = self.undo_stack.pop() {
            // 現在の状態をRedo履歴に保存
            let current_text = self.buffer.text();
            let current_pos = self.cursor.position;
            self.redo_stack.push((current_text, current_pos));
            
            self.buffer = TextBuffer::from_str(&text);
            self.cursor.set_position(pos, &self.buffer);
            self.ensure_cursor_visible();
        }
    }

    /// Redo
    pub fn redo(&mut self) {
        if let Some((text, pos)) = self.redo_stack.pop() {
            // 現在の状態をUndo履歴に保存
            let current_text = self.buffer.text();
            let current_pos = self.cursor.position;
            self.undo_stack.push((current_text, current_pos));
            
            self.buffer = TextBuffer::from_str(&text);
            self.cursor.set_position(pos, &self.buffer);
            self.ensure_cursor_visible();
        }
    }

    /// 文字を挿入
    pub fn insert_char(&mut self, ch: char) {
        self.save_undo_state();
        self.delete_selection();
        
        if ch == '\n' {
            self.buffer.insert_char(self.cursor.position, '\n');
            self.cursor.position += 1;
        } else if ch == '\t' {
            // タブをスペースに変換
            let col = self.cursor.column(&self.buffer);
            let spaces = TAB_WIDTH - (col % TAB_WIDTH);
            for _ in 0..spaces {
                self.buffer.insert_char(self.cursor.position, ' ');
                self.cursor.position += 1;
            }
        } else {
            self.buffer.insert_char(self.cursor.position, ch);
            self.cursor.position += 1;
        }
        
        self.cursor.target_column = self.cursor.column(&self.buffer);
        self.ensure_cursor_visible();
    }

    /// バックスペース
    pub fn backspace(&mut self) {
        if self.delete_selection() {
            return;
        }
        
        if self.cursor.position > 0 {
            self.save_undo_state();
            self.cursor.position -= 1;
            self.buffer.delete_char(self.cursor.position);
            self.cursor.target_column = self.cursor.column(&self.buffer);
            self.ensure_cursor_visible();
        }
    }

    /// Delete
    pub fn delete(&mut self) {
        if self.delete_selection() {
            return;
        }
        
        if self.cursor.position < self.buffer.len() {
            self.save_undo_state();
            self.buffer.delete_char(self.cursor.position);
        }
    }

    /// 選択範囲を削除
    fn delete_selection(&mut self) -> bool {
        if let Some(sel) = self.selection.take() {
            if !sel.is_empty() {
                self.save_undo_state();
                let start = sel.start();
                let end = sel.end();
                for _ in start..end {
                    self.buffer.delete_char(start);
                }
                self.cursor.set_position(start, &self.buffer);
                self.ensure_cursor_visible();
                return true;
            }
        }
        false
    }

    /// 選択範囲のテキストを取得
    pub fn get_selection_text(&self) -> Option<String> {
        self.selection.as_ref().map(|sel| sel.get_text(&self.buffer))
    }

    /// カット
    pub fn cut(&mut self) -> Option<String> {
        if let Some(sel) = &self.selection {
            let text = sel.get_text(&self.buffer);
            self.delete_selection();
            Some(text)
        } else {
            None
        }
    }

    /// コピー
    pub fn copy(&self) -> Option<String> {
        self.get_selection_text()
    }

    /// ペースト
    pub fn paste(&mut self, text: &str) {
        self.save_undo_state();
        self.delete_selection();
        
        for ch in text.chars() {
            self.buffer.insert_char(self.cursor.position, ch);
            self.cursor.position += 1;
        }
        
        self.cursor.target_column = self.cursor.column(&self.buffer);
        self.ensure_cursor_visible();
    }

    /// 全選択
    pub fn select_all(&mut self) {
        self.selection = Some(Selection::new(0, self.buffer.len()));
        self.cursor.set_position(self.buffer.len(), &self.buffer);
    }

    /// 行を選択
    pub fn select_line(&mut self) {
        let line = self.cursor.line(&self.buffer);
        let start = self.buffer.line_start(line);
        let end = if line + 1 < self.buffer.line_count() {
            self.buffer.line_start(line + 1)
        } else {
            self.buffer.len()
        };
        self.selection = Some(Selection::new(start, end));
        self.cursor.set_position(end, &self.buffer);
    }

    // ========================================================================
    // キーボード入力処理
    // ========================================================================

    /// キー入力を処理
    pub fn handle_key(&mut self, key: char, ctrl: bool, shift: bool, _alt: bool) {
        // ダイアログモード
        if self.mode != EditorMode::Normal {
            self.handle_dialog_key(key, ctrl);
            return;
        }

        // Ctrl+キー
        if ctrl {
            match key {
                'n' | 'N' => self.new_file(),
                'o' | 'O' => self.mode = EditorMode::OpenDialog,
                's' | 'S' => {
                    if shift {
                        self.mode = EditorMode::SaveDialog;
                    } else {
                        let _ = self.save_file();
                    }
                }
                'z' | 'Z' => {
                    if shift {
                        self.redo();
                    } else {
                        self.undo();
                    }
                }
                'y' | 'Y' => self.redo(),
                'a' | 'A' => self.select_all(),
                'l' | 'L' => self.select_line(),
                'd' | 'D' => self.duplicate_line(),
                _ => {}
            }
            return;
        }

        // 通常のキー入力
        match key {
            '\x08' => self.backspace(),  // Backspace
            '\x7F' => self.delete(),      // Delete
            '\r' | '\n' => self.insert_char('\n'),
            '\t' => self.insert_char('\t'),
            '\x1B' => self.selection = None, // Escape
            _ if key >= ' ' => self.insert_char(key),
            _ => {}
        }
    }

    /// スペシャルキー入力を処理
    pub fn handle_special_key(&mut self, key: SpecialKey, shift: bool, ctrl: bool) {
        let extend_selection = shift;

        if extend_selection && self.selection.is_none() {
            self.selection = Some(Selection::new(self.cursor.position, self.cursor.position));
        }

        match key {
            SpecialKey::Up => {
                if ctrl {
                    self.scroll_up(1);
                } else {
                    self.cursor.move_up(&self.buffer);
                }
            }
            SpecialKey::Down => {
                if ctrl {
                    self.scroll_down(1);
                } else {
                    self.cursor.move_down(&self.buffer);
                }
            }
            SpecialKey::Left => {
                if ctrl {
                    self.cursor.move_word_left(&self.buffer);
                } else {
                    self.cursor.move_left(&self.buffer);
                }
            }
            SpecialKey::Right => {
                if ctrl {
                    self.cursor.move_word_right(&self.buffer);
                } else {
                    self.cursor.move_right(&self.buffer);
                }
            }
            SpecialKey::Home => {
                if ctrl {
                    self.cursor.move_to_start();
                } else {
                    self.cursor.move_to_line_start(&self.buffer);
                }
            }
            SpecialKey::End => {
                if ctrl {
                    self.cursor.move_to_end(&self.buffer);
                } else {
                    self.cursor.move_to_line_end(&self.buffer);
                }
            }
            SpecialKey::PageUp => self.cursor.page_up(&self.buffer, VISIBLE_LINES),
            SpecialKey::PageDown => self.cursor.page_down(&self.buffer, VISIBLE_LINES),
        }

        if extend_selection {
            if let Some(sel) = &mut self.selection {
                sel.cursor = self.cursor.position;
            }
        } else if !extend_selection {
            self.selection = None;
        }

        self.ensure_cursor_visible();
    }

    /// ダイアログのキー入力を処理
    fn handle_dialog_key(&mut self, key: char, ctrl: bool) {
        match key {
            '\x1B' => {
                // Escape - ダイアログを閉じる
                self.mode = EditorMode::Normal;
                self.dialog_input.clear();
            }
            '\r' | '\n' => {
                // Enter - 確定
                let input = self.dialog_input.clone();
                match self.mode {
                    EditorMode::OpenDialog => {
                        let _ = self.open_file(&input);
                    }
                    EditorMode::SaveDialog => {
                        let _ = self.save_file_as(&input);
                    }
                    _ => {}
                }
                self.mode = EditorMode::Normal;
                self.dialog_input.clear();
            }
            '\x08' => {
                // Backspace
                self.dialog_input.pop();
            }
            _ if key >= ' ' && !ctrl => {
                self.dialog_input.push(key);
            }
            _ => {}
        }
    }

    /// 新規ファイル
    pub fn new_file(&mut self) {
        self.buffer = TextBuffer::new();
        self.cursor = Cursor::new();
        self.selection = None;
        self.scroll_line = 0;
        self.scroll_col = 0;
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// 行を複製
    pub fn duplicate_line(&mut self) {
        self.save_undo_state();
        
        let line = self.cursor.line(&self.buffer);
        let line_start = self.buffer.line_start(line);
        let line_end = self.buffer.line_end(line);
        
        // 行のテキストを取得
        let text = self.buffer.text();
        let line_text: String = text.chars()
            .skip(line_start)
            .take(line_end - line_start)
            .collect();
        
        // 行末に移動して改行と行を挿入
        self.cursor.set_position(line_end, &self.buffer);
        self.buffer.insert_char(self.cursor.position, '\n');
        self.cursor.position += 1;
        
        for ch in line_text.chars() {
            self.buffer.insert_char(self.cursor.position, ch);
            self.cursor.position += 1;
        }
        
        self.ensure_cursor_visible();
    }

    /// スクロールアップ
    pub fn scroll_up(&mut self, lines: usize) {
        self.scroll_line = self.scroll_line.saturating_sub(lines);
    }

    /// スクロールダウン
    pub fn scroll_down(&mut self, lines: usize) {
        let max_scroll = self.buffer.line_count().saturating_sub(1);
        self.scroll_line = min(self.scroll_line + lines, max_scroll);
    }

    // ========================================================================
    // マウス入力処理
    // ========================================================================

    /// マウスクリックを処理
    pub fn handle_mouse_click(&mut self, x: u32, y: u32, shift: bool) {
        // ツールバー領域
        if y < TOOLBAR_HEIGHT {
            self.handle_toolbar_click(x);
            return;
        }

        // 行番号領域
        if x < EDIT_AREA_X {
            // 行選択
            let click_line = self.scroll_line + ((y - TOOLBAR_HEIGHT) / CHAR_HEIGHT) as usize;
            self.select_line_at(click_line);
            return;
        }

        // 編集エリア
        let click_col = self.scroll_col + ((x - EDIT_AREA_X) / CHAR_WIDTH) as usize;
        let click_line = self.scroll_line + ((y - TOOLBAR_HEIGHT) / CHAR_HEIGHT) as usize;
        let pos = self.buffer.pos_from_line_col(click_line, click_col);

        if shift && self.selection.is_some() {
            // Shift+クリックで選択範囲を拡張
            if let Some(sel) = &mut self.selection {
                sel.cursor = pos;
            }
        } else if shift {
            // 新しい選択を開始
            self.selection = Some(Selection::new(self.cursor.position, pos));
        } else {
            self.selection = None;
        }

        self.cursor.set_position(pos, &self.buffer);
    }

    /// ツールバークリックを処理
    fn handle_toolbar_click(&mut self, x: u32) {
        // ボタンの位置を計算（各ボタン60px幅、5px間隔）
        let button_width = 60u32;
        let button_spacing = 5u32;
        let button_index = x / (button_width + button_spacing);

        match button_index {
            0 => self.new_file(),
            1 => self.mode = EditorMode::OpenDialog,
            2 => { let _ = self.save_file(); }
            3 => self.mode = EditorMode::SaveDialog,
            4 => self.undo(),
            5 => self.redo(),
            _ => {}
        }
    }

    /// 指定行を選択
    fn select_line_at(&mut self, line: usize) {
        let line = min(line, self.buffer.line_count().saturating_sub(1));
        let start = self.buffer.line_start(line);
        let end = if line + 1 < self.buffer.line_count() {
            self.buffer.line_start(line + 1)
        } else {
            self.buffer.len()
        };
        self.selection = Some(Selection::new(start, end));
        self.cursor.set_position(end, &self.buffer);
    }

    /// マウスドラッグを処理
    pub fn handle_mouse_drag(&mut self, x: u32, y: u32) {
        if y < TOOLBAR_HEIGHT || x < EDIT_AREA_X {
            return;
        }

        let drag_col = self.scroll_col + ((x - EDIT_AREA_X) / CHAR_WIDTH) as usize;
        let drag_line = self.scroll_line + ((y - TOOLBAR_HEIGHT) / CHAR_HEIGHT) as usize;
        let pos = self.buffer.pos_from_line_col(drag_line, drag_col);

        if let Some(sel) = &mut self.selection {
            sel.cursor = pos;
        } else {
            self.selection = Some(Selection::new(self.cursor.position, pos));
        }

        self.cursor.set_position(pos, &self.buffer);
        self.ensure_cursor_visible();
    }

    /// マウスホバーを処理
    pub fn handle_mouse_move(&mut self, x: u32, y: u32) {
        if y < TOOLBAR_HEIGHT {
            let button_width = 60u32;
            let button_spacing = 5u32;
            let button_index = x / (button_width + button_spacing);
            
            self.hover_button = match button_index {
                0 => Some(ToolbarButton::New),
                1 => Some(ToolbarButton::Open),
                2 => Some(ToolbarButton::Save),
                3 => Some(ToolbarButton::SaveAs),
                4 => Some(ToolbarButton::Undo),
                5 => Some(ToolbarButton::Redo),
                _ => None,
            };
        } else {
            self.hover_button = None;
        }
    }

    /// マウスホイールを処理
    pub fn handle_mouse_wheel(&mut self, delta: i32) {
        if delta > 0 {
            self.scroll_up(3);
        } else {
            self.scroll_down(3);
        }
    }

    // ========================================================================
    // レンダリング
    // ========================================================================

    /// エディタを描画
    pub fn render(&mut self, image: &mut Image) {
        // カーソル点滅の更新
        #[cfg(feature = "timer")]
        {
            let now = crate::task::current_tick();
            if now - self.last_blink > 500 {
                self.cursor_visible = !self.cursor_visible;
                self.last_blink = now;
            }
        }

        // 背景をクリア
        self.fill_rect(image, 0, 0, EDITOR_WIDTH, EDITOR_HEIGHT, BG_COLOR);

        // ツールバーを描画
        self.render_toolbar(image);

        // 行番号エリアの背景
        self.fill_rect(image, 0, TOOLBAR_HEIGHT, EDIT_AREA_X, EDIT_AREA_HEIGHT, LINE_NUMBER_BG);

        // テキストと行番号を描画
        self.render_text(image);

        // カーソルを描画
        if self.cursor_visible && self.mode == EditorMode::Normal {
            self.render_cursor(image);
        }

        // ダイアログを描画
        if self.mode != EditorMode::Normal {
            self.render_dialog(image);
        }
    }

    /// ツールバーを描画
    fn render_toolbar(&self, image: &mut Image) {
        self.fill_rect(image, 0, 0, EDITOR_WIDTH, TOOLBAR_HEIGHT, TOOLBAR_BG);

        let buttons = [
            ("New", ToolbarButton::New),
            ("Open", ToolbarButton::Open),
            ("Save", ToolbarButton::Save),
            ("SaveAs", ToolbarButton::SaveAs),
            ("Undo", ToolbarButton::Undo),
            ("Redo", ToolbarButton::Redo),
        ];

        let button_width = 60u32;
        let button_height = 20u32;
        let button_spacing = 5u32;
        let button_y = (TOOLBAR_HEIGHT - button_height) / 2;

        for (i, (label, btn)) in buttons.iter().enumerate() {
            let x = button_spacing + i as u32 * (button_width + button_spacing);
            let color = if self.hover_button == Some(*btn) {
                BUTTON_HOVER_COLOR
            } else {
                BUTTON_COLOR
            };

            self.fill_rect(image, x, button_y, button_width, button_height, color);
            self.draw_text(image, label, x + 4, button_y + 2, TEXT_COLOR);
        }

        // ファイル名を表示
        let file_info = match self.buffer.path() {
            Some(path) => {
                let modified = if self.buffer.is_modified() { " *" } else { "" };
                format!("{}{}", path, modified)
            }
            None => {
                let modified = if self.buffer.is_modified() { " *" } else { "" };
                format!("Untitled{}", modified)
            }
        };
        
        let info_x = 400u32;
        self.draw_text(image, &file_info, info_x, button_y + 2, TEXT_COLOR);
    }

    /// テキストを描画
    fn render_text(&mut self, image: &mut Image) {
        self.highlighter.reset();

        let text = self.buffer.text();
        let lines: Vec<&str> = text.split('\n').collect();

        for i in 0..VISIBLE_LINES {
            let line_idx = self.scroll_line + i;
            if line_idx >= lines.len() {
                break;
            }

            let y = TOOLBAR_HEIGHT + i as u32 * CHAR_HEIGHT;

            // 現在行のハイライト
            if line_idx == self.cursor.line(&self.buffer) {
                self.fill_rect(image, EDIT_AREA_X, y, EDIT_AREA_WIDTH, CHAR_HEIGHT, CURRENT_LINE_BG);
            }

            // 行番号を描画
            let line_num = format!("{:>4} ", line_idx + 1);
            self.draw_text(image, &line_num, 0, y, LINE_NUMBER_COLOR);

            // 行のテキストを描画（シンタックスハイライト付き）
            let line = lines[line_idx];
            let tokens = self.highlighter.highlight_line(line);

            let mut col = 0usize;

            for token in tokens {
                for ch in token.text.chars() {
                    if col >= self.scroll_col && col < self.scroll_col + VISIBLE_COLS {
                        let char_x = EDIT_AREA_X + ((col - self.scroll_col) as u32 * CHAR_WIDTH);
                        let pos = self.buffer.pos_from_line_col(line_idx, col);

                        // 選択範囲のハイライト
                        if let Some(sel) = &self.selection {
                            if sel.contains(pos) {
                                self.fill_rect(image, char_x, y, CHAR_WIDTH, CHAR_HEIGHT, SELECTION_COLOR);
                            }
                        }

                        // 文字を描画
                        let color = SyntaxHighlighter::color_for_token(token.token_type);
                        self.draw_char(image, ch, char_x, y, color);
                    }
                    col += 1;
                }
            }
        }
    }

    /// カーソルを描画
    fn render_cursor(&self, image: &mut Image) {
        let cursor_line = self.cursor.line(&self.buffer);
        let cursor_col = self.cursor.column(&self.buffer);

        if cursor_line >= self.scroll_line
            && cursor_line < self.scroll_line + VISIBLE_LINES
            && cursor_col >= self.scroll_col
            && cursor_col < self.scroll_col + VISIBLE_COLS
        {
            let x = EDIT_AREA_X + ((cursor_col - self.scroll_col) as u32 * CHAR_WIDTH);
            let y = TOOLBAR_HEIGHT + ((cursor_line - self.scroll_line) as u32 * CHAR_HEIGHT);

            // 縦線カーソル
            self.fill_rect(image, x, y, 2, CHAR_HEIGHT, CURSOR_COLOR);
        }
    }

    /// ダイアログを描画
    fn render_dialog(&self, image: &mut Image) {
        let dialog_width = 400u32;
        let dialog_height = 100u32;
        let dialog_x = (EDITOR_WIDTH - dialog_width) / 2;
        let dialog_y = (EDITOR_HEIGHT - dialog_height) / 2;

        // ダイアログ背景
        self.fill_rect(image, dialog_x, dialog_y, dialog_width, dialog_height, TOOLBAR_BG);

        // 枠線
        let border_color = Color { red: 100, green: 100, blue: 100, alpha: 255 };
        self.draw_rect_border(image, dialog_x, dialog_y, dialog_width, dialog_height, border_color);

        // タイトル
        let title = match self.mode {
            EditorMode::OpenDialog => "Open File",
            EditorMode::SaveDialog => "Save File As",
            EditorMode::Normal => "",
        };
        self.draw_text(image, title, dialog_x + 10, dialog_y + 10, TEXT_COLOR);

        // 入力フィールド
        let input_x = dialog_x + 10;
        let input_y = dialog_y + 40;
        let input_width = dialog_width - 20;
        let input_height = 24u32;

        self.fill_rect(image, input_x, input_y, input_width, input_height, BG_COLOR);
        self.draw_rect_border(image, input_x, input_y, input_width, input_height, border_color);
        
        // 入力テキスト
        self.draw_text(image, &self.dialog_input, input_x + 4, input_y + 4, TEXT_COLOR);

        // カーソル
        let cursor_x = input_x + 4 + self.dialog_input.len() as u32 * CHAR_WIDTH;
        self.fill_rect(image, cursor_x, input_y + 4, 2, CHAR_HEIGHT, CURSOR_COLOR);

        // ヒント
        self.draw_text(image, "Press Enter to confirm, Escape to cancel", dialog_x + 10, dialog_y + 75, LINE_NUMBER_COLOR);
    }

    /// 矩形を塗りつぶす
    fn fill_rect(&self, image: &mut Image, x: u32, y: u32, width: u32, height: u32, color: Color) {
        for dy in 0..height {
            for dx in 0..width {
                let px = x + dx;
                let py = y + dy;
                if px < image.width() && py < image.height() {
                    image.set_pixel(px, py, color);
                }
            }
        }
    }

    /// 矩形の枠線を描画
    fn draw_rect_border(&self, image: &mut Image, x: u32, y: u32, width: u32, height: u32, color: Color) {
        // 上辺
        for dx in 0..width {
            if x + dx < image.width() && y < image.height() {
                image.set_pixel(x + dx, y, color);
            }
        }
        // 下辺
        for dx in 0..width {
            if x + dx < image.width() && y + height - 1 < image.height() {
                image.set_pixel(x + dx, y + height - 1, color);
            }
        }
        // 左辺
        for dy in 0..height {
            if x < image.width() && y + dy < image.height() {
                image.set_pixel(x, y + dy, color);
            }
        }
        // 右辺
        for dy in 0..height {
            if x + width - 1 < image.width() && y + dy < image.height() {
                image.set_pixel(x + width - 1, y + dy, color);
            }
        }
    }

    /// 文字を描画
    fn draw_char(&self, image: &mut Image, ch: char, x: u32, y: u32, color: Color) {
        if let Some(bitmap) = get_char_bitmap(ch) {
            for (row, &bits) in bitmap.iter().enumerate() {
                for col in 0..8 {
                    if (bits >> (7 - col)) & 1 == 1 {
                        let px = x + col;
                        let py = y + row as u32;
                        if px < image.width() && py < image.height() {
                            image.set_pixel(px, py, color);
                        }
                    }
                }
            }
        }
    }

    /// テキストを描画
    fn draw_text(&self, image: &mut Image, text: &str, x: u32, y: u32, color: Color) {
        let mut cx = x;
        for ch in text.chars() {
            self.draw_char(image, ch, cx, y, color);
            cx += CHAR_WIDTH;
        }
    }

    // ========================================================================
    // アクセサ
    // ========================================================================

    /// バッファへの参照を取得
    pub fn buffer(&self) -> &TextBuffer {
        &self.buffer
    }

    /// カーソル位置を取得
    pub fn cursor_position(&self) -> usize {
        self.cursor.position
    }

    /// カーソルの行を取得
    pub fn cursor_line(&self) -> usize {
        self.cursor.line(&self.buffer)
    }

    /// カーソルの列を取得
    pub fn cursor_column(&self) -> usize {
        self.cursor.column(&self.buffer)
    }

    /// 選択範囲があるかどうか
    pub fn has_selection(&self) -> bool {
        self.selection.map(|s| !s.is_empty()).unwrap_or(false)
    }

    /// 変更されているかどうか
    pub fn is_modified(&self) -> bool {
        self.buffer.is_modified()
    }

    /// ファイルパスを取得
    pub fn file_path(&self) -> Option<&str> {
        self.buffer.path().map(|s| s.as_str())
    }
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_new() {
        let editor = Editor::new();
        assert_eq!(editor.cursor_position(), 0);
        assert!(!editor.is_modified());
    }

    #[test]
    fn test_editor_insert() {
        let mut editor = Editor::new();
        editor.insert_char('H');
        editor.insert_char('i');
        
        assert_eq!(editor.buffer().text(), "Hi");
        assert!(editor.is_modified());
    }

    #[test]
    fn test_editor_undo_redo() {
        let mut editor = Editor::new();
        editor.insert_char('A');
        editor.insert_char('B');
        
        assert_eq!(editor.buffer().text(), "AB");
        
        editor.undo();
        assert_eq!(editor.buffer().text(), "A");
        
        editor.redo();
        assert_eq!(editor.buffer().text(), "AB");
    }
}
