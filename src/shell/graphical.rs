// ============================================================================
// src/shell/graphical.rs - Graphical Shell Implementation
// ============================================================================
//!
//! # グラフィカルシェル
//!
//! フレームバッファ上で動作するグラフィカルなシェル環境。
//! テキストコンソールとExoShellを統合し、視覚的なREPL体験を提供。
//!
//! ## 機能
//! - フレームバッファへのテキスト描画
//! - 行編集（カーソル移動、削除、挿入）
//! - コマンド履歴（上下キー）
//! - Tab補完
//! - ANSIカラーサポート
//! - スクロールバック

#![allow(dead_code)]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::fmt::Write;

use crate::graphics::{Color, Framebuffer, BitmapFont};
use crate::input::{KeyCode, KeyState, KeyEvent, poll_event};
use crate::shell::exoshell::{ExoShell, ExoValue};

// フォント定数
const FONT_WIDTH: usize = 8;
const FONT_HEIGHT: usize = 16;

// ============================================================================
// Configuration
// ============================================================================

/// 最大履歴エントリ数
const MAX_HISTORY: usize = 100;

/// 最大行バッファサイズ
const MAX_LINE_LENGTH: usize = 256;

/// スクロールバック行数
const SCROLLBACK_LINES: usize = 500;

/// カーソル点滅間隔（ミリ秒）
const CURSOR_BLINK_MS: u64 = 500;

// ============================================================================
// Theme Colors
// ============================================================================

/// シェルのカラーテーマ
#[derive(Clone, Copy)]
pub struct ShellTheme {
    /// 背景色
    pub background: Color,
    /// 通常テキスト色
    pub foreground: Color,
    /// プロンプト色
    pub prompt: Color,
    /// 入力テキスト色
    pub input: Color,
    /// エラー色
    pub error: Color,
    /// 成功色
    pub success: Color,
    /// 情報色
    pub info: Color,
    /// 警告色
    pub warning: Color,
    /// カーソル色
    pub cursor: Color,
    /// 選択色
    pub selection: Color,
}

impl Default for ShellTheme {
    fn default() -> Self {
        Self {
            background: Color::new(24, 24, 32),      // ダークブルーグレー
            foreground: Color::new(220, 220, 220),   // ライトグレー
            prompt: Color::new(80, 200, 255),        // シアン
            input: Color::WHITE,                     // 白
            error: Color::new(255, 80, 80),          // 赤
            success: Color::new(80, 255, 80),        // 緑
            info: Color::new(100, 180, 255),         // 青
            warning: Color::new(255, 200, 80),       // オレンジ
            cursor: Color::new(255, 255, 255),       // 白
            selection: Color::new(60, 80, 120),      // 選択背景
        }
    }
}

// ============================================================================
// Line Buffer
// ============================================================================

/// 行バッファ（編集中の入力）
#[derive(Clone)]
struct LineBuffer {
    /// バッファ内容
    content: String,
    /// カーソル位置（文字単位）
    cursor: usize,
}

impl LineBuffer {
    fn new() -> Self {
        Self {
            content: String::new(),
            cursor: 0,
        }
    }

    fn clear(&mut self) {
        self.content.clear();
        self.cursor = 0;
    }

    fn insert(&mut self, c: char) {
        if self.content.len() < MAX_LINE_LENGTH {
            self.content.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    fn insert_str(&mut self, s: &str) {
        for c in s.chars() {
            self.insert(c);
        }
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.content.remove(self.cursor);
        }
    }

    fn delete(&mut self) {
        if self.cursor < self.content.len() {
            self.content.remove(self.cursor);
        }
    }

    fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    fn move_right(&mut self) {
        if self.cursor < self.content.len() {
            self.cursor += 1;
        }
    }

    fn move_home(&mut self) {
        self.cursor = 0;
    }

    fn move_end(&mut self) {
        self.cursor = self.content.len();
    }

    fn move_word_left(&mut self) {
        // 空白をスキップ
        while self.cursor > 0 && self.content.chars().nth(self.cursor - 1) == Some(' ') {
            self.cursor -= 1;
        }
        // 単語の先頭まで移動
        while self.cursor > 0 && self.content.chars().nth(self.cursor - 1) != Some(' ') {
            self.cursor -= 1;
        }
    }

    fn move_word_right(&mut self) {
        let len = self.content.len();
        // 単語の終わりまで移動
        while self.cursor < len && self.content.chars().nth(self.cursor) != Some(' ') {
            self.cursor += 1;
        }
        // 空白をスキップ
        while self.cursor < len && self.content.chars().nth(self.cursor) == Some(' ') {
            self.cursor += 1;
        }
    }

    fn delete_word(&mut self) {
        let start = self.cursor;
        self.move_word_left();
        let end = self.cursor;
        if start > end {
            self.content.drain(end..start);
        }
    }

    fn clear_to_end(&mut self) {
        self.content.truncate(self.cursor);
    }

    fn clear_to_start(&mut self) {
        self.content = self.content[self.cursor..].to_string();
        self.cursor = 0;
    }

    fn set(&mut self, s: &str) {
        self.content = s.to_string();
        self.cursor = self.content.len();
    }

    fn as_str(&self) -> &str {
        &self.content
    }

    fn len(&self) -> usize {
        self.content.len()
    }

    fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

// ============================================================================
// Console Line
// ============================================================================

/// コンソール行（表示用）
#[derive(Clone)]
struct ConsoleLine {
    /// テキスト内容
    text: String,
    /// 色
    color: Color,
}

impl ConsoleLine {
    fn new(text: String, color: Color) -> Self {
        Self { text, color }
    }
}

// ============================================================================
// Graphical Shell
// ============================================================================

/// グラフィカルシェル
pub struct GraphicalShell {
    /// フレームバッファへのポインタ
    fb: *mut Framebuffer,
    /// フォント
    font: BitmapFont,
    /// テーマ
    theme: ShellTheme,
    /// コンソール幅（文字数）
    cols: u32,
    /// コンソール高さ（行数）
    rows: u32,
    /// 出力行バッファ
    output_lines: VecDeque<ConsoleLine>,
    /// 現在の入力バッファ
    input_buffer: LineBuffer,
    /// コマンド履歴
    history: Vec<String>,
    /// 履歴インデックス（-1 = 現在の入力）
    history_index: isize,
    /// 履歴検索中の元の入力
    history_search_buffer: Option<String>,
    /// スクロールオフセット
    scroll_offset: usize,
    /// カーソル表示フラグ
    cursor_visible: bool,
    /// 最後のカーソル更新時刻
    last_cursor_toggle: u64,
    /// ExoShell
    shell: ExoShell,
    /// プロンプト文字列
    prompt: String,
    /// Tab補完候補
    completions: Vec<String>,
    /// 補完インデックス
    completion_index: usize,
}

unsafe impl Send for GraphicalShell {}
unsafe impl Sync for GraphicalShell {}

impl GraphicalShell {
    /// 新しいグラフィカルシェルを作成
    pub fn new(fb: &mut Framebuffer) -> Self {
        let font = BitmapFont::default_8x16();
        let cols = fb.width() / font.width();
        let rows = fb.height() / font.height();

        let shell = ExoShell::new();
        let prompt = shell.prompt();

        Self {
            fb,
            font,
            theme: ShellTheme::default(),
            cols,
            rows,
            output_lines: VecDeque::with_capacity(SCROLLBACK_LINES),
            input_buffer: LineBuffer::new(),
            history: Vec::with_capacity(MAX_HISTORY),
            history_index: -1,
            history_search_buffer: None,
            scroll_offset: 0,
            cursor_visible: true,
            last_cursor_toggle: 0,
            shell,
            prompt,
            completions: Vec::new(),
            completion_index: 0,
        }
    }

    /// テーマを設定
    pub fn set_theme(&mut self, theme: ShellTheme) {
        self.theme = theme;
    }

    /// シェルを開始（ウェルカムメッセージ表示）
    pub fn start(&mut self) {
        self.clear_screen();
        
        // ウェルカムメッセージ
        self.print_colored("╔══════════════════════════════════════════════════════════════╗\n", self.theme.info);
        self.print_colored("║                                                              ║\n", self.theme.info);
        self.print_colored("║     ", self.theme.info);
        self.print_colored("RanyOS ExoShell v0.3.0", self.theme.success);
        self.print_colored("                                   ║\n", self.theme.info);
        self.print_colored("║     ", self.theme.info);
        self.print_colored("Graphical REPL Environment", self.theme.foreground);
        self.print_colored("                              ║\n", self.theme.info);
        self.print_colored("║                                                              ║\n", self.theme.info);
        self.print_colored("║     ", self.theme.info);
        self.print_colored("Type 'help' for available commands", self.theme.warning);
        self.print_colored("                     ║\n", self.theme.info);
        self.print_colored("║                                                              ║\n", self.theme.info);
        self.print_colored("╚══════════════════════════════════════════════════════════════╝\n", self.theme.info);
        self.print("\n");
        
        // プロンプトを表示
        self.draw_prompt();
    }

    /// 画面をクリア
    pub fn clear_screen(&mut self) {
        unsafe {
            (*self.fb).clear(self.theme.background);
        }
        self.output_lines.clear();
        self.scroll_offset = 0;
    }

    /// テキストを出力
    pub fn print(&mut self, text: &str) {
        self.print_colored(text, self.theme.foreground);
    }

    /// 色付きテキストを出力
    pub fn print_colored(&mut self, text: &str, color: Color) {
        for line in text.split('\n') {
            if !line.is_empty() || text.contains('\n') {
                self.output_lines.push_back(ConsoleLine::new(line.to_string(), color));
                
                // スクロールバック制限
                while self.output_lines.len() > SCROLLBACK_LINES {
                    self.output_lines.pop_front();
                }
            }
        }
        self.redraw();
    }

    /// プロンプトを表示
    fn draw_prompt(&mut self) {
        self.prompt = self.shell.prompt();
        self.redraw();
    }

    /// 画面を再描画
    fn redraw(&mut self) {
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
        let lines_to_draw: Vec<(String, Color)> = self.output_lines
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
            let mut comp_text = String::from("  ");
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
    fn draw_text(&mut self, x: i32, y: i32, text: &str, color: Color) {
        unsafe {
            self.font.draw_string(&mut *self.fb, x, y, text, color, Some(self.theme.background));
        }
    }

    /// カーソルを描画
    fn draw_cursor(&mut self, x: i32, y: i32) {
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

    /// カーソルの点滅を更新
    pub fn update_cursor(&mut self, current_time: u64) {
        if current_time - self.last_cursor_toggle >= CURSOR_BLINK_MS {
            self.cursor_visible = !self.cursor_visible;
            self.last_cursor_toggle = current_time;
            self.redraw();
        }
    }

    /// キーイベントを処理
    pub fn handle_key(&mut self, event: KeyEvent) {
        if event.state != KeyState::Pressed {
            return;
        }

        // カーソルを表示
        self.cursor_visible = true;
        self.last_cursor_toggle = crate::task::timer::current_tick();

        // Ctrl修飾キーの処理
        if event.modifiers.ctrl {
            match event.key {
                KeyCode::C => {
                    // Ctrl+C: 入力をキャンセル
                    self.input_buffer.clear();
                    self.print("^C\n");
                    self.draw_prompt();
                    return;
                }
                KeyCode::L => {
                    // Ctrl+L: 画面クリア
                    self.clear_screen();
                    self.draw_prompt();
                    return;
                }
                KeyCode::A => {
                    // Ctrl+A: 行頭へ
                    self.input_buffer.move_home();
                    self.redraw();
                    return;
                }
                KeyCode::E => {
                    // Ctrl+E: 行末へ
                    self.input_buffer.move_end();
                    self.redraw();
                    return;
                }
                KeyCode::K => {
                    // Ctrl+K: 行末まで削除
                    self.input_buffer.clear_to_end();
                    self.redraw();
                    return;
                }
                KeyCode::U => {
                    // Ctrl+U: 行頭まで削除
                    self.input_buffer.clear_to_start();
                    self.redraw();
                    return;
                }
                KeyCode::W => {
                    // Ctrl+W: 単語削除
                    self.input_buffer.delete_word();
                    self.redraw();
                    return;
                }
                _ => {}
            }
        }

        // Alt修飾キーの処理
        if event.modifiers.alt {
            match event.key {
                KeyCode::Left => {
                    self.input_buffer.move_word_left();
                    self.redraw();
                    return;
                }
                KeyCode::Right => {
                    self.input_buffer.move_word_right();
                    self.redraw();
                    return;
                }
                _ => {}
            }
        }

        // 通常キー処理
        match event.key {
            KeyCode::Enter => {
                self.submit_input();
            }
            KeyCode::Backspace => {
                self.completions.clear();
                self.input_buffer.backspace();
                self.redraw();
            }
            KeyCode::Delete => {
                self.completions.clear();
                self.input_buffer.delete();
                self.redraw();
            }
            KeyCode::Left => {
                self.input_buffer.move_left();
                self.redraw();
            }
            KeyCode::Right => {
                self.input_buffer.move_right();
                self.redraw();
            }
            KeyCode::Home => {
                self.input_buffer.move_home();
                self.redraw();
            }
            KeyCode::End => {
                self.input_buffer.move_end();
                self.redraw();
            }
            KeyCode::Up => {
                self.history_prev();
            }
            KeyCode::Down => {
                self.history_next();
            }
            KeyCode::Tab => {
                self.handle_tab();
            }
            KeyCode::PageUp => {
                self.scroll_up();
            }
            KeyCode::PageDown => {
                self.scroll_down();
            }
            KeyCode::Escape => {
                // 補完をキャンセル
                self.completions.clear();
                self.redraw();
            }
            _ => {
                // 文字入力
                if let Some(c) = event.char {
                    if c >= ' ' && c <= '~' {
                        self.completions.clear();
                        self.input_buffer.insert(c);
                        self.redraw();
                    }
                }
            }
        }
    }

    /// 入力を確定
    fn submit_input(&mut self) {
        let input = self.input_buffer.as_str().to_string();
        
        // 入力行を出力に追加
        let full_line = format!("{}{}", self.prompt, input);
        self.output_lines.push_back(ConsoleLine::new(full_line, self.theme.input));
        
        // 入力バッファをクリア
        self.input_buffer.clear();
        self.completions.clear();
        self.history_search_buffer = None;
        
        // 空でなければ履歴に追加
        if !input.trim().is_empty() {
            // 重複を避ける
            if self.history.last() != Some(&input) {
                self.history.push(input.clone());
                if self.history.len() > MAX_HISTORY {
                    self.history.remove(0);
                }
            }
            self.history_index = self.history.len() as isize;
        }

        // コマンドを実行
        self.execute_command(&input);
        
        // プロンプトを再表示
        self.draw_prompt();
    }

    /// コマンドを実行
    fn execute_command(&mut self, input: &str) {
        let input = input.trim();
        
        if input.is_empty() {
            return;
        }

        // 特殊コマンド
        match input {
            "clear" | "cls" => {
                self.clear_screen();
                return;
            }
            "exit" | "quit" => {
                self.print_colored("Goodbye!\n", self.theme.success);
                return;
            }
            _ => {}
        }

        // ExoShellで評価（同期的に）
        // Note: async evalは使用できないため、同期的な代替を使用
        let result = self.shell.eval_sync(input);
        
        // 結果を表示
        let output = format!("{}\n", result);
        if output.starts_with("Error") {
            self.print_colored(&output, self.theme.error);
        } else {
            self.print_colored(&output, self.theme.foreground);
        }
    }

    /// 履歴を前に
    fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }

        // 最初のナビゲーションで現在の入力を保存
        if self.history_search_buffer.is_none() {
            self.history_search_buffer = Some(self.input_buffer.as_str().to_string());
        }

        if self.history_index > 0 {
            self.history_index -= 1;
            let entry = self.history[self.history_index as usize].clone();
            self.input_buffer.set(&entry);
            self.redraw();
        }
    }

    /// 履歴を次に
    fn history_next(&mut self) {
        if self.history.is_empty() {
            return;
        }

        if self.history_index < self.history.len() as isize - 1 {
            self.history_index += 1;
            let entry = self.history[self.history_index as usize].clone();
            self.input_buffer.set(&entry);
        } else {
            // 履歴の最後を超えたら、保存した入力に戻る
            self.history_index = self.history.len() as isize;
            if let Some(ref saved) = self.history_search_buffer {
                self.input_buffer.set(saved);
            } else {
                self.input_buffer.clear();
            }
            self.history_search_buffer = None;
        }
        self.redraw();
    }

    /// Tab補完処理
    fn handle_tab(&mut self) {
        let input = self.input_buffer.as_str();
        
        if self.completions.is_empty() {
            // 新しい補完を取得
            self.completions = self.shell.complete(input);
            self.completion_index = 0;
            
            if self.completions.len() == 1 {
                // 1つだけなら自動適用
                self.input_buffer.set(&self.completions[0]);
                self.completions.clear();
            }
        } else {
            // 次の候補へ
            self.completion_index = (self.completion_index + 1) % self.completions.len();
            self.input_buffer.set(&self.completions[self.completion_index]);
        }
        
        self.redraw();
    }

    /// 上にスクロール
    fn scroll_up(&mut self) {
        let max_scroll = self.output_lines.len().saturating_sub((self.rows - 2) as usize);
        if self.scroll_offset < max_scroll {
            self.scroll_offset += 3;
            self.scroll_offset = self.scroll_offset.min(max_scroll);
            self.redraw();
        }
    }

    /// 下にスクロール
    fn scroll_down(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset = self.scroll_offset.saturating_sub(3);
            self.redraw();
        }
    }

    /// メインループの1イテレーション（ポーリングベース）
    pub fn poll(&mut self) {
        // キーイベントを処理
        while let Some(event) = poll_event() {
            self.handle_key(event);
        }
        
        // カーソル点滅を更新
        let current_time = crate::task::timer::current_tick();
        self.update_cursor(current_time);
    }

    /// シェルが実行中かどうか
    pub fn is_running(&self) -> bool {
        true // 終了条件を追加する場合はここで判定
    }
}

// ============================================================================
// ExoShell Synchronous Evaluation Extension
// ============================================================================

impl ExoShell {
    /// 同期的にコマンドを評価
    /// Note: async evalの代替として、簡易的な同期評価を提供
    pub fn eval_sync(&mut self, input: &str) -> String {
        use crate::shell::exoshell::*;
        use alloc::format;

        let input = input.trim();
        
        if input.is_empty() {
            return String::new();
        }

        // help コマンド
        if input == "help" {
            return self.help().to_string();
        }

        // 変数参照
        if input.starts_with('$') {
            let var_name = &input[1..];
            if var_name == "_" {
                return format!("{}", self.last_result());
            }
            if let Some(val) = self.get_binding(var_name) {
                return format!("{}", val);
            }
            return format!("Variable '{}' not found", var_name);
        }

        // let 式（同期版では非対応）
        if input.starts_with("let ") {
            return String::from("let expressions require async context");
        }

        // 名前空間メソッド呼び出しを解析
        if let Some(dot_pos) = input.find('.') {
            let namespace = &input[..dot_pos];
            let rest = &input[dot_pos + 1..];
            
            match namespace {
                "sys" => return self.eval_sys_sync(rest),
                "net" => return self.eval_net_sync(rest),
                "proc" => return self.eval_proc_sync(rest),
                "cap" => return self.eval_cap_sync(rest),
                "fs" => return format!("fs operations require async context. Use aliases: ls, cd, pwd, cat"),
                _ => return format!("Unknown namespace: {}", namespace),
            }
        }

        // エイリアスの同期評価
        self.eval_alias_sync(input)
    }

    fn eval_sys_sync(&self, method_call: &str) -> String {
        use crate::shell::exoshell::SysNamespace;

        // メソッド名を抽出
        let method = if let Some(paren) = method_call.find('(') {
            &method_call[..paren]
        } else {
            method_call
        };

        let result = match method {
            "info" => SysNamespace::info(),
            "memory" => SysNamespace::memory(),
            "time" => SysNamespace::time(),
            "monitor" => SysNamespace::monitor(),
            "dashboard" => SysNamespace::monitor_dashboard(),
            "thermal" => SysNamespace::thermal(),
            "watchdog" => SysNamespace::watchdog(),
            "power" => SysNamespace::power(),
            "shutdown" => SysNamespace::shutdown(),
            "reboot" => SysNamespace::reboot(),
            _ => return format!("Unknown sys method: {}", method),
        };

        format!("{}", result)
    }

    fn eval_net_sync(&self, method_call: &str) -> String {
        use crate::shell::exoshell::NetNamespace;

        let method = if let Some(paren) = method_call.find('(') {
            &method_call[..paren]
        } else {
            method_call
        };

        let result = match method {
            "config" => NetNamespace::config(),
            "stats" => NetNamespace::stats(),
            "arp" | "arp_cache" => NetNamespace::arp_cache(),
            _ => return format!("Unknown net method: {} (ping requires async)", method),
        };

        format!("{}", result)
    }

    fn eval_proc_sync(&self, method_call: &str) -> String {
        use crate::shell::exoshell::ProcNamespace;

        let method = if let Some(paren) = method_call.find('(') {
            &method_call[..paren]
        } else {
            method_call
        };

        let result = match method {
            "list" => ProcNamespace::list(),
            _ => return format!("Unknown proc method: {}", method),
        };

        format!("{}", result)
    }

    fn eval_cap_sync(&self, method_call: &str) -> String {
        use crate::shell::exoshell::CapNamespace;

        let method = if let Some(paren) = method_call.find('(') {
            &method_call[..paren]
        } else {
            method_call
        };

        let result = match method {
            "list" => CapNamespace::list(),
            _ => return format!("Unknown cap method: {}", method),
        };

        format!("{}", result)
    }

    fn eval_alias_sync(&mut self, cmd: &str) -> String {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return String::new();
        }

        match parts[0] {
            "ls" => {
                let path = parts.get(1).unwrap_or(&".");
                let p = if *path == "." { self.cwd().to_string() } else { path.to_string() };
                match crate::fs::list_directory(&p, "/") {
                    Ok(entries) => {
                        let mut out = String::new();
                        for e in entries {
                            let type_char = match e.file_type {
                                crate::fs::FileType::Directory => 'd',
                                crate::fs::FileType::Symlink => 'l',
                                _ => '-',
                            };
                            out.push_str(&format!("{} {}\n", type_char, e.name));
                        }
                        out
                    }
                    Err(e) => format!("Error: {:?}", e),
                }
            }
            "cd" => {
                if let Some(path) = parts.get(1) {
                    self.set_cwd(path);
                }
                self.cwd().to_string()
            }
            "pwd" => self.cwd().to_string(),
            "cat" => {
                if let Some(path) = parts.get(1) {
                    match crate::fs::read_file_content(path, "/") {
                        Ok(content) => {
                            String::from_utf8_lossy(&content).to_string()
                        }
                        Err(e) => format!("Error: {:?}", e),
                    }
                } else {
                    String::from("Usage: cat <file>")
                }
            }
            "mkdir" => {
                if let Some(path) = parts.get(1) {
                    match crate::fs::make_directory(path, "/") {
                        Ok(()) => format!("Created directory: {}", path),
                        Err(e) => format!("Error: {:?}", e),
                    }
                } else {
                    String::from("Usage: mkdir <dir>")
                }
            }
            "rm" => {
                if let Some(path) = parts.get(1) {
                    match crate::fs::remove_file(path, "/") {
                        Ok(()) => format!("Removed: {}", path),
                        Err(_) => {
                            match crate::fs::remove_directory(path, "/") {
                                Ok(()) => format!("Removed directory: {}", path),
                                Err(e) => format!("Error: {:?}", e),
                            }
                        }
                    }
                } else {
                    String::from("Usage: rm <path>")
                }
            }
            "ps" => format!("{}", crate::shell::exoshell::ProcNamespace::list()),
            "ifconfig" => format!("{}", crate::shell::exoshell::NetNamespace::config()),
            "arp" => format!("{}", crate::shell::exoshell::NetNamespace::arp_cache()),
            "uname" => format!("{}", crate::shell::exoshell::SysNamespace::info()),
            "free" => format!("{}", crate::shell::exoshell::SysNamespace::memory()),
            "uptime" => format!("{}", crate::shell::exoshell::SysNamespace::time()),
            "echo" => {
                parts[1..].join(" ")
            }
            _ => format!(
                "Unknown command: '{}'\nTry 'help' or use ExoShell syntax: sys.info(), net.config(), etc.",
                cmd
            ),
        }
    }

    /// 最後の結果を取得
    fn last_result(&self) -> &ExoValue {
        static NIL: ExoValue = ExoValue::Nil;
        self.bindings.get("_").unwrap_or(&NIL)
    }

    /// 変数バインディングを取得
    fn get_binding(&self, name: &str) -> Option<&ExoValue> {
        self.bindings.get(name)
    }

    /// カレントディレクトリを設定
    fn set_cwd(&mut self, path: &str) {
        if path.starts_with('/') {
            self.cwd = path.to_string();
        } else if path == ".." {
            let mut segs: Vec<&str> = self.cwd.split('/').filter(|s| !s.is_empty()).collect();
            segs.pop();
            if segs.is_empty() {
                self.cwd = String::from("/");
            } else {
                self.cwd = format!("/{}", segs.join("/"));
            }
        } else {
            if self.cwd == "/" {
                self.cwd = format!("/{}", path);
            } else {
                self.cwd = format!("{}/{}", self.cwd, path);
            }
        }
    }
}

// ============================================================================
// Global Instance
// ============================================================================

use spin::Mutex;

static GRAPHICAL_SHELL: Mutex<Option<GraphicalShell>> = Mutex::new(None);

/// グラフィカルシェルを初期化
pub fn init() {
    use log::info;
    
    info!(target: "gshell", "Initializing graphical shell...");
    
    // フレームバッファを取得
    let fb = crate::graphics::framebuffer();
    if fb.is_none() {
        info!(target: "gshell", "No framebuffer available - skipping graphical shell");
        return;
    }
    
    info!(target: "gshell", "Framebuffer found, creating shell...");

    // グラフィカルシェルを作成
    let shell = crate::graphics::with_framebuffer(|fb| {
        GraphicalShell::new(fb)
    });

    if let Some(shell) = shell {
        *GRAPHICAL_SHELL.lock() = Some(shell);
        info!(target: "gshell", "Graphical shell created successfully");
    } else {
        info!(target: "gshell", "Failed to create graphical shell");
    }
}

/// グラフィカルシェルを開始
pub fn start() {
    use log::info;
    
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.start();
        info!(target: "gshell", "Graphical shell started");
    } else {
        info!(target: "gshell", "Cannot start - no shell instance");
    }
}

/// グラフィカルシェルにアクセス
pub fn with_shell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut GraphicalShell) -> R,
{
    GRAPHICAL_SHELL.lock().as_mut().map(f)
}

/// ポーリング処理
pub fn poll() {
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.poll();
    }
}

/// テキストを出力
pub fn print(text: &str) {
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.print(text);
    }
}

/// 色付きテキストを出力
pub fn print_colored(text: &str, color: Color) {
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.print_colored(text, color);
    }
}
