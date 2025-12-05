// ============================================================================
// src/application/terminal/app.rs - Terminal Application
// ============================================================================
//!
//! 完全なターミナルアプリケーション

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

use crate::graphics::image::Image;

use super::completer::TabCompleter;
use super::constants::*;
use super::history::LineEditor;
use super::keys::SpecialKey;
use super::selection::{Selection, CLIPBOARD};
use super::terminal::Terminal;

// ============================================================================
// TerminalApp
// ============================================================================

/// 完全なターミナルアプリケーション
pub struct TerminalApp {
    /// ターミナルエミュレータ
    terminal: Terminal,
    /// ラインエディタ
    editor: LineEditor,
    /// タブ補完
    completer: TabCompleter,
    /// 現在の選択
    selection: Option<Selection>,
    /// 選択開始位置
    selection_start: Option<(usize, usize)>,
    /// マウスドラッグ中
    is_selecting: bool,
    /// 描画バッファ
    buffer: Image,
    /// シェルコールバック (コマンド実行)
    shell_callback: Option<fn(&str) -> String>,
}

impl TerminalApp {
    /// 新しいターミナルアプリケーションを作成
    pub fn new() -> Self {
        Self {
            terminal: Terminal::new(),
            editor: LineEditor::new(),
            completer: TabCompleter::new(),
            selection: None,
            selection_start: None,
            is_selecting: false,
            buffer: Image::new(TERMINAL_WIDTH, TERMINAL_HEIGHT),
            shell_callback: None,
        }
    }

    /// シェルコールバックを設定
    pub fn set_shell_callback(&mut self, callback: fn(&str) -> String) {
        self.shell_callback = Some(callback);
    }

    /// ターミナルへの参照を取得
    pub fn terminal(&self) -> &Terminal {
        &self.terminal
    }

    /// ターミナルへの可変参照を取得
    pub fn terminal_mut(&mut self) -> &mut Terminal {
        &mut self.terminal
    }

    /// 文字入力を処理
    pub fn handle_char(&mut self, ch: char) {
        if ch == '\t' {
            self.handle_tab();
            return;
        }

        self.completer.reset();

        if let Some(command) = self.terminal.process_line_edit(&mut self.editor, ch) {
            self.execute_command(&command);
        }
    }

    /// 特殊キー入力を処理
    pub fn handle_special_key(&mut self, key: SpecialKey) {
        match key {
            SpecialKey::PageUp => {
                self.terminal.buffer.scroll_back_up(TERM_ROWS);
                return;
            }
            SpecialKey::PageDown => {
                self.terminal.buffer.scroll_back_down(TERM_ROWS);
                return;
            }
            _ => {}
        }

        self.completer.reset();
        self.terminal.process_special_key(&mut self.editor, key);
    }

    /// タブ補完を処理
    fn handle_tab(&mut self) {
        let input = self.editor.buffer();
        
        if self.completer.count() == 0 {
            let word_start = input.rfind(' ').map(|i| i + 1).unwrap_or(0);
            let word = &input[word_start..];
            
            let candidates = self.generate_completions(word);
            
            if candidates.len() == 1 {
                self.apply_completion(&candidates[0], word_start);
            } else if !candidates.is_empty() {
                self.completer.set_candidates(word, candidates);
                self.show_completions();
            }
        } else {
            if let Some(candidate) = self.completer.next() {
                let candidate = String::from(candidate);
                let word_start = self.editor.buffer().rfind(' ').map(|i| i + 1).unwrap_or(0);
                self.apply_completion(&candidate, word_start);
            }
        }
    }

    /// 補完候補を生成
    fn generate_completions(&self, prefix: &str) -> Vec<String> {
        let commands = [
            "help", "clear", "echo", "ls", "cd", "pwd", "cat",
            "mkdir", "rm", "cp", "mv", "date", "time", "uname",
            "ps", "kill", "top", "free", "df", "exit", "reboot",
            "shutdown", "history", "alias", "export", "env",
        ];
        
        commands
            .iter()
            .filter(|cmd| cmd.starts_with(prefix))
            .map(|s| String::from(*s))
            .collect()
    }

    /// 補完を適用
    fn apply_completion(&mut self, completion: &str, word_start: usize) {
        while self.editor.cursor() > word_start {
            self.editor.backspace();
            self.terminal.write_str("\x08 \x08");
        }
        
        self.editor.insert_str(completion);
        self.terminal.write_str(completion);
    }

    /// 補完候補を表示
    fn show_completions(&mut self) {
        self.terminal.write_str("\r\n");
        
        let candidates = self.completer.all_candidates();
        for (i, candidate) in candidates.iter().enumerate() {
            self.terminal.write_str(candidate);
            if i < candidates.len() - 1 {
                self.terminal.write_str("  ");
            }
        }
        
        self.terminal.write_str("\r\n");
        self.terminal.show_prompt(DEFAULT_PROMPT);
        self.terminal.write_str(self.editor.buffer());
    }

    /// コマンドを実行
    fn execute_command(&mut self, command: &str) {
        let cmd = command.trim();
        
        if cmd.is_empty() {
            self.terminal.show_prompt(DEFAULT_PROMPT);
            return;
        }

        if let Some(callback) = self.shell_callback {
            let output = callback(cmd);
            self.terminal.write_str(&output);
        } else {
            self.handle_builtin_command(cmd);
        }
        
        self.terminal.show_prompt(DEFAULT_PROMPT);
    }

    /// 組み込みコマンドを処理
    fn handle_builtin_command(&mut self, cmd: &str) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        match parts[0] {
            "help" => {
                self.terminal.write_str("\x1b[1;33mAvailable commands:\x1b[0m\r\n");
                self.terminal.write_str("  help     - Show this help message\r\n");
                self.terminal.write_str("  clear    - Clear the screen\r\n");
                self.terminal.write_str("  echo     - Print arguments\r\n");
                self.terminal.write_str("  history  - Show command history\r\n");
                self.terminal.write_str("  version  - Show terminal version\r\n");
                self.terminal.write_str("  colors   - Show color palette\r\n");
            }
            "clear" => {
                self.terminal.clear_screen();
            }
            "echo" => {
                let text = parts[1..].join(" ");
                self.terminal.write_str(&text);
                self.terminal.write_str("\r\n");
            }
            "history" => {
                let history = self.editor.history();
                for (i, entry) in history.entries().iter().enumerate() {
                    self.terminal.write_str(&format!("{:4}  {}\r\n", i + 1, entry));
                }
            }
            "version" => {
                self.terminal.write_str("\x1b[1;36mRany OS Terminal v1.0\x1b[0m\r\n");
                self.terminal.write_str("VT100/ANSI compatible terminal emulator\r\n");
            }
            "colors" => {
                self.terminal.write_str("\x1b[1mStandard colors:\x1b[0m\r\n");
                for i in 0..8 {
                    self.terminal.write_str(&format!("\x1b[48;5;{}m  \x1b[0m", i));
                }
                self.terminal.write_str("\r\n");
                
                self.terminal.write_str("\x1b[1mBright colors:\x1b[0m\r\n");
                for i in 8..16 {
                    self.terminal.write_str(&format!("\x1b[48;5;{}m  \x1b[0m", i));
                }
                self.terminal.write_str("\r\n");
                
                self.terminal.write_str("\x1b[1m216 colors:\x1b[0m\r\n");
                for row in 0..6 {
                    for col in 0..36 {
                        let color = 16 + row * 36 + col;
                        self.terminal.write_str(&format!("\x1b[48;5;{}m \x1b[0m", color));
                    }
                    self.terminal.write_str("\r\n");
                }
                
                self.terminal.write_str("\x1b[1mGrayscale:\x1b[0m\r\n");
                for i in 232..=255 {
                    self.terminal.write_str(&format!("\x1b[48;5;{}m \x1b[0m", i));
                }
                self.terminal.write_str("\r\n");
            }
            _ => {
                self.terminal.write_str("\x1b[1;31mUnknown command: ");
                self.terminal.write_str(parts[0]);
                self.terminal.write_str("\x1b[0m\r\n");
                self.terminal.write_str("Type 'help' for available commands.\r\n");
            }
        }
    }

    /// マウス押下
    pub fn handle_mouse_down(&mut self, x: u32, y: u32) {
        let col = (x / CHAR_WIDTH) as usize;
        let row = (y / CHAR_HEIGHT) as usize;
        
        if col < TERM_COLS && row < TERM_ROWS {
            self.selection_start = Some((col, row));
            self.selection = None;
            self.is_selecting = true;
        }
    }

    /// マウス移動
    pub fn handle_mouse_move(&mut self, x: u32, y: u32) {
        if !self.is_selecting {
            return;
        }

        if let Some(start) = self.selection_start {
            let col = (x / CHAR_WIDTH) as usize;
            let row = (y / CHAR_HEIGHT) as usize;
            
            let col = col.min(TERM_COLS - 1);
            let row = row.min(TERM_ROWS - 1);
            
            self.selection = Some(Selection::new(start, (col, row)));
        }
    }

    /// マウス離す
    pub fn handle_mouse_up(&mut self, x: u32, y: u32) {
        if self.is_selecting {
            self.handle_mouse_move(x, y);
            self.is_selecting = false;
            
            if let Some(ref selection) = self.selection {
                let text = self.terminal.get_selected_text(selection);
                if !text.is_empty() {
                    CLIPBOARD.copy(&text);
                }
            }
        }
    }

    /// ペースト
    pub fn paste(&mut self) {
        let text = CLIPBOARD.paste();
        for ch in text.chars() {
            if ch == '\n' {
                self.handle_char('\r');
            } else {
                self.handle_char(ch);
            }
        }
    }

    /// 描画
    pub fn render(&mut self) -> &Image {
        self.terminal.render_with_selection(&mut self.buffer, self.selection.as_ref());
        &self.buffer
    }

    /// 初期化
    pub fn init(&mut self) {
        self.terminal.show_welcome();
        self.terminal.show_prompt(DEFAULT_PROMPT);
    }

    /// バッファサイズを取得
    pub fn size(&self) -> (u32, u32) {
        (TERMINAL_WIDTH, TERMINAL_HEIGHT)
    }
}

impl Default for TerminalApp {
    fn default() -> Self {
        Self::new()
    }
}
