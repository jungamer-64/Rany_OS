// ============================================================================
// src/application/terminal/terminal.rs - Terminal Emulator Core
// ============================================================================
//!
//! ターミナルエミュレータ本体

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::graphics::{Color, image::Image, Rect};
use crate::task::current_tick;

use super::ansi::{AnsiParser, ParseAction};
use super::buffer::TerminalBuffer;
use super::cell::Cell;
use super::constants::*;
use super::font::get_char_bitmap_8x16;
use super::history::LineEditor;
use super::keys::SpecialKey;
use super::selection::Selection;

// ============================================================================
// Terminal
// ============================================================================

/// ターミナルエミュレータ
pub struct Terminal {
    /// ターミナルバッファ
    pub(crate) buffer: TerminalBuffer,
    /// ANSIパーサー
    parser: AnsiParser,
    /// カーソルX位置 (0-indexed)
    cursor_col: usize,
    /// カーソルY位置 (0-indexed)
    cursor_row: usize,
    /// 保存されたカーソル位置
    saved_cursor: (usize, usize),
    /// 現在の前景色
    current_fg: Color,
    /// 現在の背景色
    current_bg: Color,
    /// 太字フラグ
    bold: bool,
    /// 下線フラグ
    underline: bool,
    /// 反転フラグ
    inverse: bool,
    /// カーソル表示フラグ
    cursor_visible: bool,
    /// カーソル点滅状態
    cursor_blink_on: bool,
    /// 最終カーソル点滅更新時刻
    last_blink_tick: u64,
    /// ウィンドウタイトル
    title: String,
    /// 入力バッファ (シェルへの入力)
    input_buffer: String,
    /// 出力バッファ (シェルからの出力待ち)
    output_queue: Vec<char>,
    /// 実行中フラグ
    running: AtomicBool,
    /// ダーティフラグ
    dirty: bool,
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminal {
    /// 新しいターミナルを作成
    pub fn new() -> Self {
        Self {
            buffer: TerminalBuffer::new(),
            parser: AnsiParser::new(),
            cursor_col: 0,
            cursor_row: 0,
            saved_cursor: (0, 0),
            current_fg: DEFAULT_FG,
            current_bg: DEFAULT_BG,
            bold: false,
            underline: false,
            inverse: false,
            cursor_visible: true,
            cursor_blink_on: true,
            last_blink_tick: 0,
            title: String::from("Terminal"),
            input_buffer: String::new(),
            output_queue: Vec::new(),
            running: AtomicBool::new(true),
            dirty: true,
        }
    }

    /// ターミナルを開始
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
    }

    /// ターミナルを停止
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 実行中かどうか
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// ダーティかどうか
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// ダーティフラグをクリア
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// タイトルを取得
    pub fn title(&self) -> &str {
        &self.title
    }

    /// カーソル位置を取得
    pub fn cursor_position(&self) -> (usize, usize) {
        (self.cursor_col, self.cursor_row)
    }

    /// 入力バッファを取得
    pub fn input_buffer(&self) -> &str {
        &self.input_buffer
    }

    /// 入力バッファをクリア
    pub fn clear_input_buffer(&mut self) -> String {
        core::mem::take(&mut self.input_buffer)
    }

    // ========================================================================
    // Cursor Blinking
    // ========================================================================

    /// カーソル点滅を更新
    pub fn update_cursor_blink(&mut self) {
        let now = current_tick();
        if now.saturating_sub(self.last_blink_tick) >= CURSOR_BLINK_INTERVAL_MS {
            self.cursor_blink_on = !self.cursor_blink_on;
            self.last_blink_tick = now;
            self.dirty = true;
        }
    }

    // ========================================================================
    // Input Handling
    // ========================================================================

    /// キー入力を処理
    pub fn handle_key(&mut self, ch: char) {
        match ch {
            '\r' | '\n' => {
                self.input_buffer.push('\n');
                self.write_char('\r');
                self.write_char('\n');
            }
            '\x08' | '\x7f' => {
                if !self.input_buffer.is_empty() {
                    self.input_buffer.pop();
                    self.write_char('\x08');
                    self.write_char(' ');
                    self.write_char('\x08');
                }
            }
            '\x03' => {
                self.write_str("^C\r\n");
                self.input_buffer.clear();
            }
            '\x04' => {
                if self.input_buffer.is_empty() {
                    self.write_str("^D\r\n");
                }
            }
            '\x0c' => {
                self.clear_screen();
            }
            _ if ch >= ' ' && ch <= '~' => {
                self.input_buffer.push(ch);
                self.write_char(ch);
            }
            _ => {}
        }
    }

    /// 特殊キー入力を処理 (矢印キーなど)
    pub fn handle_special_key(&mut self, key: SpecialKey) {
        let seq = match key {
            SpecialKey::Up => "\x1b[A",
            SpecialKey::Down => "\x1b[B",
            SpecialKey::Right => "\x1b[C",
            SpecialKey::Left => "\x1b[D",
            SpecialKey::Home => "\x1b[H",
            SpecialKey::End => "\x1b[F",
            SpecialKey::PageUp => "\x1b[5~",
            SpecialKey::PageDown => "\x1b[6~",
            SpecialKey::Insert => "\x1b[2~",
            SpecialKey::Delete => "\x1b[3~",
            SpecialKey::F1 => "\x1bOP",
            SpecialKey::F2 => "\x1bOQ",
            SpecialKey::F3 => "\x1bOR",
            SpecialKey::F4 => "\x1bOS",
            SpecialKey::F5 => "\x1b[15~",
            SpecialKey::F6 => "\x1b[17~",
            SpecialKey::F7 => "\x1b[18~",
            SpecialKey::F8 => "\x1b[19~",
            SpecialKey::F9 => "\x1b[20~",
            SpecialKey::F10 => "\x1b[21~",
            SpecialKey::F11 => "\x1b[23~",
            SpecialKey::F12 => "\x1b[24~",
        };
        for ch in seq.chars() {
            self.input_buffer.push(ch);
        }
    }

    // ========================================================================
    // Output Handling
    // ========================================================================

    /// 文字列を書き込む
    pub fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            self.write_char(ch);
        }
    }

    /// 1文字を書き込む
    pub fn write_char(&mut self, ch: char) {
        let action = self.parser.feed(ch);
        self.execute_action(action);
    }

    /// バイト列を書き込む
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_char(b as char);
        }
    }

    /// パーサーアクションを実行
    fn execute_action(&mut self, action: ParseAction) {
        match action {
            ParseAction::None => {}
            ParseAction::Print(ch) => self.put_char(ch),
            ParseAction::NewLine => self.new_line(),
            ParseAction::CarriageReturn => self.carriage_return(),
            ParseAction::Backspace => self.backspace(),
            ParseAction::Tab => self.tab(),
            ParseAction::Bell => { /* ベル音は無視 */ }
            ParseAction::Reset => self.reset_terminal(),
            ParseAction::CursorUp(n) => self.cursor_up(n as usize),
            ParseAction::CursorDown(n) => self.cursor_down(n as usize),
            ParseAction::CursorForward(n) => self.cursor_forward(n as usize),
            ParseAction::CursorBack(n) => self.cursor_back(n as usize),
            ParseAction::CursorPosition(row, col) => {
                self.set_cursor_position((row as usize).saturating_sub(1), 
                                          (col as usize).saturating_sub(1));
            }
            ParseAction::EraseDisplay(mode) => self.erase_display(mode),
            ParseAction::EraseLine(mode) => self.erase_line(mode),
            ParseAction::ScrollUp(n) => {
                for _ in 0..n {
                    self.scroll_up();
                }
            }
            ParseAction::ScrollDown(n) => {
                for _ in 0..n {
                    self.scroll_down();
                }
            }
            ParseAction::Sgr(params) => self.apply_sgr(&params),
            ParseAction::SaveCursor => self.save_cursor(),
            ParseAction::RestoreCursor => self.restore_cursor(),
            ParseAction::Index => self.index(),
            ParseAction::ReverseIndex => self.reverse_index(),
            ParseAction::SetTitle(title) => self.title = title,
            ParseAction::DeviceStatusReport(n) => {
                if n == 6 {
                    let report = format!("\x1b[{};{}R", 
                                         self.cursor_row + 1, 
                                         self.cursor_col + 1);
                    for ch in report.chars() {
                        self.output_queue.push(ch);
                    }
                }
            }
        }
        self.dirty = true;
    }

    // ========================================================================
    // Cursor Movement
    // ========================================================================

    /// 文字を現在位置に配置
    fn put_char(&mut self, ch: char) {
        let line = self.buffer.get_line_mut(self.cursor_row);
        let cell = Cell {
            ch,
            fg: self.current_fg,
            bg: self.current_bg,
            bold: self.bold,
            underline: self.underline,
            inverse: self.inverse,
        };
        line.set(self.cursor_col, cell);

        self.cursor_col += 1;
        if self.cursor_col >= TERM_COLS {
            self.cursor_col = 0;
            self.new_line();
        }
    }

    /// 改行
    fn new_line(&mut self) {
        self.cursor_row += 1;
        if self.cursor_row >= TERM_ROWS {
            self.scroll_up();
            self.cursor_row = TERM_ROWS - 1;
        }
    }

    /// キャリッジリターン
    fn carriage_return(&mut self) {
        self.cursor_col = 0;
    }

    /// バックスペース
    fn backspace(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        }
    }

    /// タブ
    fn tab(&mut self) {
        let next_tab = ((self.cursor_col / 8) + 1) * 8;
        self.cursor_col = next_tab.min(TERM_COLS - 1);
    }

    /// カーソル上移動
    fn cursor_up(&mut self, n: usize) {
        self.cursor_row = self.cursor_row.saturating_sub(n);
    }

    /// カーソル下移動
    fn cursor_down(&mut self, n: usize) {
        self.cursor_row = (self.cursor_row + n).min(TERM_ROWS - 1);
    }

    /// カーソル右移動
    pub fn cursor_forward(&mut self, n: usize) {
        self.cursor_col = (self.cursor_col + n).min(TERM_COLS - 1);
    }

    /// カーソル左移動
    fn cursor_back(&mut self, n: usize) {
        self.cursor_col = self.cursor_col.saturating_sub(n);
    }

    /// カーソル位置設定
    fn set_cursor_position(&mut self, row: usize, col: usize) {
        self.cursor_row = row.min(TERM_ROWS - 1);
        self.cursor_col = col.min(TERM_COLS - 1);
    }

    /// カーソル保存
    fn save_cursor(&mut self) {
        self.saved_cursor = (self.cursor_col, self.cursor_row);
    }

    /// カーソル復帰
    fn restore_cursor(&mut self) {
        self.cursor_col = self.saved_cursor.0;
        self.cursor_row = self.saved_cursor.1;
    }

    /// インデックス (下移動 + スクロール)
    fn index(&mut self) {
        if self.cursor_row >= TERM_ROWS - 1 {
            self.scroll_up();
        } else {
            self.cursor_row += 1;
        }
    }

    /// リバースインデックス (上移動 + スクロール)
    fn reverse_index(&mut self) {
        if self.cursor_row == 0 {
            self.scroll_down();
        } else {
            self.cursor_row -= 1;
        }
    }

    // ========================================================================
    // Scrolling
    // ========================================================================

    /// 上にスクロール
    fn scroll_up(&mut self) {
        self.buffer.scroll_up();
    }

    /// 下にスクロール
    fn scroll_down(&mut self) {
        for row in (1..TERM_ROWS).rev() {
            let prev = self.buffer.get_line(row - 1).clone();
            *self.buffer.get_line_mut(row) = prev;
        }
        self.buffer.get_line_mut(0).clear();
    }

    /// スクロールバックを上に移動
    pub fn scroll_back_up(&mut self, lines: usize) {
        self.buffer.scroll_back_up(lines);
        self.dirty = true;
    }

    /// スクロールバックを下に移動
    pub fn scroll_back_down(&mut self, lines: usize) {
        self.buffer.scroll_back_down(lines);
        self.dirty = true;
    }

    // ========================================================================
    // Screen Clearing
    // ========================================================================

    /// 画面消去
    fn erase_display(&mut self, mode: u32) {
        match mode {
            0 => {
                self.erase_line(0);
                for row in (self.cursor_row + 1)..TERM_ROWS {
                    self.buffer.get_line_mut(row).clear();
                }
            }
            1 => {
                self.erase_line(1);
                for row in 0..self.cursor_row {
                    self.buffer.get_line_mut(row).clear();
                }
            }
            2 | 3 => {
                self.clear_screen();
            }
            _ => {}
        }
    }

    /// 行消去
    fn erase_line(&mut self, mode: u32) {
        let line = self.buffer.get_line_mut(self.cursor_row);
        match mode {
            0 => line.clear_from(self.cursor_col),
            1 => line.clear_to(self.cursor_col),
            2 => line.clear(),
            _ => {}
        }
    }

    /// 画面クリア
    pub fn clear_screen(&mut self) {
        self.buffer.clear_all();
        self.cursor_col = 0;
        self.cursor_row = 0;
        self.dirty = true;
    }

    /// ターミナルリセット
    fn reset_terminal(&mut self) {
        self.clear_screen();
        self.current_fg = DEFAULT_FG;
        self.current_bg = DEFAULT_BG;
        self.bold = false;
        self.underline = false;
        self.inverse = false;
        self.parser.reset();
    }

    // ========================================================================
    // SGR (Select Graphic Rendition)
    // ========================================================================

    /// SGRパラメータを適用
    fn apply_sgr(&mut self, params: &[u32]) {
        if params.is_empty() {
            self.current_fg = DEFAULT_FG;
            self.current_bg = DEFAULT_BG;
            self.bold = false;
            self.underline = false;
            self.inverse = false;
            return;
        }

        let mut i = 0;
        while i < params.len() {
            match params[i] {
                0 => {
                    self.current_fg = DEFAULT_FG;
                    self.current_bg = DEFAULT_BG;
                    self.bold = false;
                    self.underline = false;
                    self.inverse = false;
                }
                1 => self.bold = true,
                4 => self.underline = true,
                7 => self.inverse = true,
                22 => self.bold = false,
                24 => self.underline = false,
                27 => self.inverse = false,
                30..=37 => {
                    let idx = (params[i] - 30) as usize;
                    self.current_fg = if self.bold {
                        ANSI_BRIGHT_COLORS[idx]
                    } else {
                        ANSI_COLORS[idx]
                    };
                }
                39 => self.current_fg = DEFAULT_FG,
                40..=47 => {
                    let idx = (params[i] - 40) as usize;
                    self.current_bg = ANSI_COLORS[idx];
                }
                49 => self.current_bg = DEFAULT_BG,
                90..=97 => {
                    let idx = (params[i] - 90) as usize;
                    self.current_fg = ANSI_BRIGHT_COLORS[idx];
                }
                100..=107 => {
                    let idx = (params[i] - 100) as usize;
                    self.current_bg = ANSI_BRIGHT_COLORS[idx];
                }
                38 => {
                    if i + 2 < params.len() && params[i + 1] == 5 {
                        let n = params[i + 2] as usize;
                        self.current_fg = color_from_256(n);
                        i += 2;
                    }
                }
                48 => {
                    if i + 2 < params.len() && params[i + 1] == 5 {
                        let n = params[i + 2] as usize;
                        self.current_bg = color_from_256(n);
                        i += 2;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    // ========================================================================
    // Rendering
    // ========================================================================

    /// ターミナルをバッファに描画
    pub fn render(&self, buffer: &mut Image) {
        let full_rect = Rect::new(0, 0, buffer.width(), buffer.height());
        buffer.fill_rect(full_rect, DEFAULT_BG);

        for row in 0..TERM_ROWS {
            self.render_line(buffer, row);
        }

        if self.cursor_visible && self.cursor_blink_on {
            self.render_cursor(buffer);
        }
    }

    /// 1行を描画
    fn render_line(&self, buffer: &mut Image, row: usize) {
        let line = self.buffer.get_line(row);
        let y = (row as u32) * CHAR_HEIGHT;

        for col in 0..TERM_COLS {
            let cell = line.get(col);
            let x = (col as u32) * CHAR_WIDTH;
            
            let (fg, bg) = cell.effective_colors();
            
            let bg_rect = Rect::new(x as i32, y as i32, CHAR_WIDTH, CHAR_HEIGHT);
            buffer.fill_rect(bg_rect, bg);
            
            if cell.ch != ' ' {
                self.draw_char(buffer, x as i32, y as i32, cell.ch, fg);
            }
            
            if cell.underline {
                let underline_y = y + CHAR_HEIGHT - 2;
                for px in x..(x + CHAR_WIDTH) {
                    buffer.set_pixel(px, underline_y, fg);
                }
            }
        }
    }

    /// カーソルを描画
    fn render_cursor(&self, buffer: &mut Image) {
        let x = (self.cursor_col as u32) * CHAR_WIDTH;
        let y = (self.cursor_row as u32) * CHAR_HEIGHT;
        
        let cursor_rect = Rect::new(x as i32, y as i32, CHAR_WIDTH, CHAR_HEIGHT);
        
        let line = self.buffer.get_line(self.cursor_row);
        let cell = line.get(self.cursor_col);
        
        buffer.fill_rect(cursor_rect, CURSOR_COLOR);
        
        if cell.ch != ' ' {
            self.draw_char(buffer, x as i32, y as i32, cell.ch, DEFAULT_BG);
        }
    }

    /// 文字を描画 (8x16フォント)
    fn draw_char(&self, buffer: &mut Image, x: i32, y: i32, ch: char, color: Color) {
        if let Some(bitmap) = get_char_bitmap_8x16(ch) {
            for (row, bits) in bitmap.iter().enumerate() {
                for col in 0..8 {
                    if (bits >> (7 - col)) & 1 == 1 {
                        let px = x + col;
                        let py = y + row as i32;
                        if px >= 0 && py >= 0 {
                            buffer.set_pixel(px as u32, py as u32, color);
                        }
                    }
                }
            }
        }
    }

    /// プロンプトを表示
    pub fn show_prompt(&mut self, prompt: &str) {
        self.write_str(prompt);
    }

    /// 選択範囲のテキストを取得
    pub fn get_selected_text(&self, selection: &Selection) -> String {
        let norm = selection.normalized();
        let mut text = String::new();
        
        for row in norm.start.1..=norm.end.1 {
            let line = self.buffer.get_line(row);
            let start_col = if row == norm.start.1 { norm.start.0 } else { 0 };
            let end_col = if row == norm.end.1 { norm.end.0 } else { TERM_COLS - 1 };
            
            for col in start_col..=end_col {
                let cell = line.get(col);
                if cell.ch != '\0' {
                    text.push(cell.ch);
                }
            }
            
            if row < norm.end.1 {
                text.push('\n');
            }
        }
        
        let trimmed = text.trim_end();
        String::from(trimmed)
    }

    /// 選択範囲を描画
    pub fn render_with_selection(&self, buffer: &mut Image, selection: Option<&Selection>) {
        let full_rect = Rect::new(0, 0, buffer.width(), buffer.height());
        buffer.fill_rect(full_rect, DEFAULT_BG);

        for row in 0..TERM_ROWS {
            self.render_line_with_selection(buffer, row, selection);
        }

        if self.cursor_visible && self.cursor_blink_on {
            self.render_cursor(buffer);
        }
    }

    /// 選択範囲を考慮して1行を描画
    fn render_line_with_selection(&self, buffer: &mut Image, row: usize, selection: Option<&Selection>) {
        let line = self.buffer.get_line(row);
        let y = (row as u32) * CHAR_HEIGHT;

        for col in 0..TERM_COLS {
            let cell = line.get(col);
            let x = (col as u32) * CHAR_WIDTH;
            
            let is_selected = selection.map(|s| s.contains(col, row)).unwrap_or(false);
            
            let (fg, bg) = if is_selected {
                let (f, b) = cell.effective_colors();
                (b, f)
            } else {
                cell.effective_colors()
            };
            
            let bg_rect = Rect::new(x as i32, y as i32, CHAR_WIDTH, CHAR_HEIGHT);
            buffer.fill_rect(bg_rect, bg);
            
            if cell.ch != ' ' {
                self.draw_char(buffer, x as i32, y as i32, cell.ch, fg);
            }
            
            if cell.underline {
                let underline_y = y + CHAR_HEIGHT - 2;
                for px in x..(x + CHAR_WIDTH) {
                    buffer.set_pixel(px, underline_y, fg);
                }
            }
        }
    }

    /// ウェルカムメッセージを表示
    pub fn show_welcome(&mut self) {
        self.write_str("\x1b[1;36m");
        self.write_str("╔════════════════════════════════════════════════════════════════╗\r\n");
        self.write_str("║                                                                ║\r\n");
        self.write_str("║     ██████╗  █████╗ ███╗   ██╗██╗   ██╗     ██████╗ ███████╗   ║\r\n");
        self.write_str("║     ██╔══██╗██╔══██╗████╗  ██║╚██╗ ██╔╝    ██╔═══██╗██╔════╝   ║\r\n");
        self.write_str("║     ██████╔╝███████║██╔██╗ ██║ ╚████╔╝     ██║   ██║███████╗   ║\r\n");
        self.write_str("║     ██╔══██╗██╔══██║██║╚██╗██║  ╚██╔╝      ██║   ██║╚════██║   ║\r\n");
        self.write_str("║     ██║  ██║██║  ██║██║ ╚████║   ██║       ╚██████╔╝███████║   ║\r\n");
        self.write_str("║     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝        ╚═════╝ ╚══════╝   ║\r\n");
        self.write_str("║                                                                ║\r\n");
        self.write_str("╚════════════════════════════════════════════════════════════════╝\r\n");
        self.write_str("\x1b[0m");
        self.write_str("\r\n");
        self.write_str("\x1b[1;33mWelcome to Rany OS Terminal!\x1b[0m\r\n");
        self.write_str("Type '\x1b[1;32mhelp\x1b[0m' for available commands.\r\n");
        self.write_str("\r\n");
    }

    // ========================================================================
    // Line Editor Integration
    // ========================================================================

    /// ラインエディタを使用した入力処理
    pub fn process_line_edit(&mut self, editor: &mut LineEditor, ch: char) -> Option<String> {
        match ch {
            '\r' | '\n' => {
                self.write_str("\r\n");
                Some(editor.submit())
            }
            '\x08' | '\x7f' => {
                if editor.cursor() > 0 {
                    editor.backspace();
                    self.write_str("\x08 \x08");
                    let remaining = &editor.buffer()[editor.cursor()..];
                    if !remaining.is_empty() {
                        self.write_str(remaining);
                        self.write_str(" ");
                        for _ in 0..=remaining.len() {
                            self.write_str("\x08");
                        }
                    }
                }
                None
            }
            '\x01' => {
                let moves = editor.cursor();
                editor.move_home();
                for _ in 0..moves {
                    self.write_str("\x08");
                }
                None
            }
            '\x05' => {
                let moves = editor.buffer().len() - editor.cursor();
                editor.move_end();
                for _ in 0..moves {
                    self.cursor_forward(1);
                }
                None
            }
            '\x0B' => {
                let killed = editor.kill_to_end();
                self.write_str("\x1b[K");
                let _ = killed;
                None
            }
            '\x15' => {
                let killed = editor.kill_to_start();
                self.write_str("\r");
                self.write_str("\x1b[K");
                self.write_str(editor.buffer());
                let _ = killed;
                None
            }
            '\x17' => {
                let old_cursor = editor.cursor();
                let killed = editor.kill_word();
                for _ in 0..(old_cursor - editor.cursor()) {
                    self.write_str("\x08");
                }
                self.write_str(&editor.buffer()[editor.cursor()..]);
                self.write_str(" ");
                for _ in editor.cursor()..old_cursor {
                    self.write_str("\x08");
                }
                let _ = killed;
                None
            }
            '\x03' => {
                self.write_str("^C\r\n");
                editor.clear();
                None
            }
            '\x0C' => {
                self.clear_screen();
                None
            }
            _ if ch >= ' ' && ch <= '~' => {
                editor.insert(ch);
                self.write_char(ch);
                let remaining = &editor.buffer()[editor.cursor()..];
                if !remaining.is_empty() {
                    self.write_str(remaining);
                    for _ in 0..remaining.len() {
                        self.write_str("\x08");
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// 特殊キーを使用した入力処理
    pub fn process_special_key(&mut self, editor: &mut LineEditor, key: SpecialKey) -> bool {
        match key {
            SpecialKey::Left => {
                if editor.cursor() > 0 {
                    editor.move_left();
                    self.write_str("\x1b[D");
                }
                false
            }
            SpecialKey::Right => {
                if editor.cursor() < editor.buffer().len() {
                    editor.move_right();
                    self.write_str("\x1b[C");
                }
                false
            }
            SpecialKey::Up => {
                if editor.history_previous() {
                    self.write_str("\r\x1b[K");
                    self.write_str(editor.buffer());
                }
                false
            }
            SpecialKey::Down => {
                editor.history_next();
                self.write_str("\r\x1b[K");
                self.write_str(editor.buffer());
                false
            }
            SpecialKey::Home => {
                let moves = editor.cursor();
                editor.move_home();
                if moves > 0 {
                    self.write_str(&format!("\x1b[{}D", moves));
                }
                false
            }
            SpecialKey::End => {
                let moves = editor.buffer().len() - editor.cursor();
                editor.move_end();
                if moves > 0 {
                    self.write_str(&format!("\x1b[{}C", moves));
                }
                false
            }
            SpecialKey::Delete => {
                if editor.cursor() < editor.buffer().len() {
                    editor.delete();
                    self.write_str(&editor.buffer()[editor.cursor()..]);
                    self.write_str(" ");
                    let moves = editor.buffer().len() - editor.cursor() + 1;
                    for _ in 0..moves {
                        self.write_str("\x08");
                    }
                }
                false
            }
            _ => false,
        }
    }
}
