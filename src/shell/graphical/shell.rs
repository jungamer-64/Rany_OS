// ============================================================================
// src/shell/graphical/shell.rs - Graphical Shell Core
// ============================================================================
//!
//! # グラフィカルシェル本体

#![allow(dead_code)]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::collections::VecDeque;

use crate::graphics::{Color, Framebuffer, BitmapFont};
use crate::io::hid::{poll_input_event, poll_mouse_event};
use crate::shell::exoshell::ExoShell;

use super::types::{
    ShellTheme, LineBuffer, ConsoleLine, MouseState,
    MAX_HISTORY, SCROLLBACK_LINES, CURSOR_BLINK_MS,
};
use super::async_runtime::submit_command;

// ============================================================================
// Graphical Shell
// ============================================================================

/// グラフィカルシェル
pub struct GraphicalShell {
    /// フレームバッファへのポインタ
    pub(crate) fb: *mut Framebuffer,
    /// フォント
    pub(crate) font: BitmapFont,
    /// テーマ
    pub theme: ShellTheme,
    /// コンソール幅（文字数）
    pub(crate) cols: u32,
    /// コンソール高さ（行数）
    pub(crate) rows: u32,
    /// 出力行バッファ
    pub(crate) output_lines: VecDeque<ConsoleLine>,
    /// 現在の入力バッファ
    pub(crate) input_buffer: LineBuffer,
    /// コマンド履歴
    pub(crate) history: Vec<String>,
    /// 履歴インデックス（-1 = 現在の入力）
    pub(crate) history_index: isize,
    /// 履歴検索中の元の入力
    pub(crate) history_search_buffer: Option<String>,
    /// スクロールオフセット
    pub(crate) scroll_offset: usize,
    /// カーソル表示フラグ
    pub(crate) cursor_visible: bool,
    /// 最後のカーソル更新時刻
    pub(crate) last_cursor_toggle: u64,
    /// ExoShell
    pub(crate) shell: ExoShell,
    /// プロンプト文字列
    pub(crate) prompt: String,
    /// Tab補完候補
    pub(crate) completions: Vec<String>,
    /// 補完インデックス
    pub(crate) completion_index: usize,
    /// 現在実行中のコマンドがあるか
    pub(crate) is_executing: bool,
    /// マウス状態
    pub(crate) mouse: MouseState,
    /// マウスカーソル表示フラグ
    pub(crate) show_mouse_cursor: bool,
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
            is_executing: false,
            mouse: MouseState::new(),
            show_mouse_cursor: true,
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
    pub fn draw_prompt(&mut self) {
        self.prompt = self.shell.prompt();
        self.redraw();
    }

    /// カーソルの点滅を更新
    pub fn update_cursor(&mut self, current_time: u64) {
        if current_time - self.last_cursor_toggle >= CURSOR_BLINK_MS {
            self.cursor_visible = !self.cursor_visible;
            self.last_cursor_toggle = current_time;
            self.redraw();
        }
    }

    /// 入力を確定
    pub(crate) fn submit_input(&mut self) {
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

        // コマンドを非同期キューに追加
        self.queue_command(&input);
        
        // プロンプトを再表示
        self.draw_prompt();
    }

    /// コマンドを非同期キューに追加
    pub(crate) fn queue_command(&mut self, input: &str) {
        let input = input.trim();
        
        if input.is_empty() {
            return;
        }

        // 特殊コマンド（即時実行）
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

        // 既にコマンド実行中の場合は警告を表示して拒否
        if self.is_executing {
            self.print_colored("(waiting for previous command...)\n", self.theme.warning);
            return;
        }

        // グローバルキューにコマンドを追加（非同期タスクで処理される）
        let _request_id = submit_command(input.to_string());
        self.is_executing = true;
    }

    /// 履歴を前に
    pub(crate) fn history_prev(&mut self) {
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
    pub(crate) fn history_next(&mut self) {
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
    pub(crate) fn handle_tab(&mut self) {
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
    pub(crate) fn scroll_up(&mut self) {
        let max_scroll = self.output_lines.len().saturating_sub((self.rows - 2) as usize);
        if self.scroll_offset < max_scroll {
            self.scroll_offset += 3;
            self.scroll_offset = self.scroll_offset.min(max_scroll);
            self.redraw();
        }
    }

    /// 下にスクロール
    pub(crate) fn scroll_down(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset = self.scroll_offset.saturating_sub(3);
            self.redraw();
        }
    }

    /// メインループの1イテレーション（ポーリングベース）
    pub fn poll(&mut self) {
        // キーイベントを処理
        while let Some(event) = poll_input_event() {
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
