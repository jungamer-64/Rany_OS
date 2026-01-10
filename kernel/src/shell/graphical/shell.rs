// ============================================================================
// src/shell/graphical/shell.rs - Graphical Shell Core
// ============================================================================
//!
//! # グラフィカルシェル本体
//!
//! ## Split Borrows パターン
//! - `ShellState`: 可変データ（入力、出力、カーソル等）
//! - `ShellResources`: 不変データ（フォント、テーマ、サイズ）
//! - これにより描画時の clone() を排除

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::graphics::font::FontExt;
use crate::graphics::{BitmapFont, Color, Font, Framebuffer, Rect};
use crate::shell::exoshell::ExoShell;

use super::streams::submit_command;
#[cfg(feature = "mouse")]
use super::types::MouseState;
use super::types::{
    CURSOR_BLINK_MS, ConsoleLine, LineBuffer, SCROLLBACK_LINES, ShellResources,
    ShellState, ShellTheme,
};

// ============================================================================
// Graphical Shell (Split Borrows Design)
// ============================================================================

/// グラフィカルシェル
pub struct GraphicalShell {
    /// 可変状態データ
    pub state: ShellState,
    /// 不変リソース
    pub resources: ShellResources,
    /// ExoShell（コマンド実行エンジン）
    pub(crate) shell: ExoShell,
    /// フレームバッファ（所有）
    pub framebuffer: Framebuffer,
}

impl GraphicalShell {
    /// 新しいグラフィカルシェルを作成
    pub fn new(framebuffer: Framebuffer) -> Self {
        use log::info;
        let width = framebuffer.info().width;
        let height = framebuffer.info().height;
        info!(target: "gshell", "DEBUG: GraphicalShell::new called with {}x{}", width, height);

        let font: Box<dyn Font + Send + Sync> = Box::new(BitmapFont::default_8x16());
        let fb_width = width;
        let fb_height = height;
        let cols = fb_width / font.char_width(' ');
        let rows = fb_height / font.height();

        info!(target: "gshell", "DEBUG: Creating ExoShell instance...");
        let shell = ExoShell::new();
        let prompt = shell.prompt();
        info!(target: "gshell", "DEBUG: ExoShell created, prompt len={}", prompt.len());

        // プロンプト幅を事前計算
        let cached_prompt_end_x = font.iter_width(prompt.chars()) as i32;

        info!(target: "gshell", "DEBUG: Returning new GraphicalShell");

        Self {
            state: ShellState {
                output_lines: VecDeque::with_capacity(SCROLLBACK_LINES),
                input_buffer: LineBuffer::new(),
                history_navigator: crate::shell::exoshell::history::HistoryNavigator::new(),
                scroll_offset: 0,
                cursor_visible: true,
                last_cursor_toggle: 0,
                prompt,
                completions: Vec::new(),
                completion_index: 0,
                is_executing: false,
                #[cfg(feature = "mouse")]
                mouse: MouseState::new(),
                #[cfg(feature = "mouse")]
                show_mouse_cursor: true,

                // ゼロアロケーション用バッファ（十分な容量を確保）
                temp_fmt_buffer: String::with_capacity(4096),

                cached_prompt_end_x,
                cached_cursor_pixel_x: 0,
                cached_cursor_char: None,
                last_completion_rect: Rect::new(0, 0, 0, 0),
            },
            resources: ShellResources {
                font,
                theme: ShellTheme::default(),
                fb_width,
                fb_height,
                cols,
                rows,
            },
            shell,
            framebuffer,
        }
    }

    // ========================================================================
    // Convenience Accessors (既存コードとの互換性)
    // ========================================================================

    #[inline]
    pub(crate) fn fb_width(&self) -> u32 {
        self.resources.fb_width
    }
    #[inline]
    pub(crate) fn fb_height(&self) -> u32 {
        self.resources.fb_height
    }
    #[inline]
    pub(crate) fn cols(&self) -> u32 {
        self.resources.cols
    }
    #[inline]
    pub(crate) fn rows(&self) -> u32 {
        self.resources.rows
    }

    /// フォントを変更
    pub fn set_font(&mut self, font: Box<dyn Font + Send + Sync>) {
        self.resources.font = font;
        // レイアウト再計算
        let char_w = self.resources.font.char_width(' ');
        let char_h = self.resources.font.height();
        // 0除算防止
        if char_w > 0 && char_h > 0 {
            self.resources.cols = self.resources.fb_width / char_w;
            self.resources.rows = self.resources.fb_height / char_h;
        }
        // 画面クリア（サイズ変更対応）
        self.clear_screen();
        // 描画は呼び出し側で行うか、redrawを呼ぶ
    }

    /// 入力変更時にキャッシュを更新
    #[inline]
    pub(crate) fn update_cursor_cache(&mut self) {
        self.state.cached_cursor_pixel_x = self.resources.font.iter_width(
            self.state
                .input_buffer
                .content
                .chars()
                .take(self.state.input_buffer.cursor),
        ) as i32;
        self.state.cached_cursor_char = self
            .state
            .input_buffer
            .content
            .chars()
            .nth(self.state.input_buffer.cursor);
    }

    /// プロンプト変更時にキャッシュを更新
    #[inline]
    pub(crate) fn update_prompt_cache(&mut self) {
        self.state.cached_prompt_end_x =
            self.resources.font.iter_width(self.state.prompt.chars()) as i32;
    }

    // ========================================================================
    // Layout Helpers (DRY)
    // ========================================================================

    #[inline]
    pub(crate) fn input_line_y(&self) -> i32 {
        self.resources.input_line_y()
    }

    #[inline]
    pub(crate) fn cursor_x(&self) -> i32 {
        self.state.cursor_x()
    }

    #[inline]
    pub(crate) fn cursor_rect(&self) -> Rect {
        Rect::new(
            self.cursor_x(),
            self.input_line_y(),
            self.resources.font.char_width(' '),
            self.resources.font.height(),
        )
    }

    #[inline]
    pub(crate) fn input_line_rect(&self) -> Rect {
        Rect::new(
            0,
            self.input_line_y(),
            self.resources.fb_width,
            self.resources.font.height(),
        )
    }

    /// 表示すべき行のイテレータを返す（ロジックと描画の分離）
    pub(crate) fn visible_lines(&self) -> impl Iterator<Item = &ConsoleLine> {
        let max_visible = (self.resources.rows - 2) as usize;
        let total = self.state.output_lines.len();
        let start = if total > max_visible {
            total.saturating_sub(max_visible + self.state.scroll_offset)
        } else {
            0
        };
        self.state.output_lines.iter().skip(start).take(max_visible)
    }

    /// ピクセルを描画（画面外チェック付き）
    #[inline]
    pub fn put_pixel(&self, fb: &mut Framebuffer, x: i32, y: i32, color: Color) {
        let width = self.resources.fb_width as i32;
        let height = self.resources.fb_height as i32;

        if x >= 0 && x < width && y >= 0 && y < height {
            fb.set_pixel(x, y, color);
        }
    }

    /// ピクセルを取得（画面外チェック付き）
    #[inline]
    pub fn get_pixel(&self, fb: &Framebuffer, x: i32, y: i32) -> Color {
        let width = self.resources.fb_width as i32;
        let height = self.resources.fb_height as i32;

        if x >= 0 && x < width && y >= 0 && y < height {
            fb.get_pixel(x as u32, y as u32)
        } else {
            // 画面外は背景色扱い（または黒）
            Color::BLACK
        }
    }

    /// テーマを設定
    pub fn set_theme(&mut self, theme: ShellTheme) {
        self.resources.theme = theme;
    }

    /// シェルを開始（ウェルカムメッセージ表示）
    pub fn start(&mut self) {
        self.clear_screen();

        // ウェルカムメッセージ
        let theme = self.resources.theme;
        self.print_colored(
            "╔══════════════════════════════════════════════════════════════╗\n",
            theme.info,
        );
        self.print_colored(
            "║                                                              ║\n",
            theme.info,
        );
        self.print_colored("║     ", theme.info);
        self.print_colored("RanyOS ExoShell v0.3.0", theme.success);
        self.print_colored("                                   ║\n", theme.info);
        self.print_colored("║     ", theme.info);
        self.print_colored("Graphical REPL Environment", theme.foreground);
        self.print_colored("                              ║\n", theme.info);
        self.print_colored(
            "║                                                              ║\n",
            theme.info,
        );
        self.print_colored("║     ", theme.info);
        self.print_colored("Type 'help' for available commands", theme.warning);
        self.print_colored("                     ║\n", theme.info);
        self.print_colored(
            "║                                                              ║\n",
            theme.info,
        );
        self.print_colored(
            "╚══════════════════════════════════════════════════════════════╝\n",
            theme.info,
        );
        self.print("\n");

        // 初回描画（画面全体を更新してブートロゴを消去）
        self.redraw();
    }

    /// 画面をクリア（状態のみ更新、描画はredraw時）
    pub fn clear_screen(&mut self) {
        self.state.output_lines.clear();
        self.state.scroll_offset = 0;
        // 描画はredraw()で行われる
    }

    /// テキストを出力
    pub fn print(&mut self, text: &str) {
        let color = self.resources.theme.foreground;
        self.print_colored(text, color);
    }

    /// 色付きテキストを出力（状態更新のみ、描画はredraw時）
    pub fn print_colored(&mut self, text: &str, color: Color) {
        for line in text.split('\n') {
            if !line.is_empty() || text.contains('\n') {
                self.state
                    .output_lines
                    .push_back(ConsoleLine::new(line.to_string(), color));

                // スクロールバック制限
                while self.state.output_lines.len() > SCROLLBACK_LINES {
                    self.state.output_lines.pop_front();
                }
            }
        }
        // 注: 描画は呼び出し側でredraw()を呼ぶか、
        // イベントループ内で定期的にredraw()される
    }

    /// プロンプト領域を描画（実際には入力行再描画）
    pub fn draw_prompt(&mut self) {
        self.state.prompt = self.shell.prompt();
        self.redraw_input_line();
    }

    /// カーソルの点滅を更新（部分更新 - 効率的）
    pub fn update_cursor(&mut self, current_time: u64) {
        if current_time - self.state.last_cursor_toggle >= CURSOR_BLINK_MS {
            self.state.cursor_visible = !self.state.cursor_visible;
            self.state.last_cursor_toggle = current_time;
            self.redraw_cursor_only(); // 全画面ではなくカーソルのみ
        }
    }

    /// 入力を確定
    pub(crate) fn submit_input(&mut self) {
        let input = self.state.input_buffer.as_str().to_string();

        // 入力行を出力に追加
        let full_line = format!("{}{}", self.state.prompt, input);
        self.state
            .output_lines
            .push_back(ConsoleLine::new(full_line, self.resources.theme.input));

        // 入力バッファをクリア
        self.state.input_buffer.clear();
        self.state.completions.clear();
        self.state.completions.clear();

        // 空でなければ履歴に追加
        if !input.trim().is_empty() {
             self.shell.add_history(input.clone());
        }
        self.state.history_navigator.reset_navigation();

        // コマンドを非同期キューに追加
        self.queue_command(&input);

        // プロンプトを再表示（履歴更新のため全画面再描画）
        self.update_cursor_cache();
        self.redraw();
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
                let success = self.resources.theme.success;
                self.print_colored("Goodbye!\n", success);
                return;
            }
            s if s.starts_with("load_font ") => {
                let path = s["load_font ".len()..].trim();
                if path.is_empty() {
                    let err = self.resources.theme.error;
                    self.print_colored("Usage: load_font <path>\n", err);
                    return;
                }

                // ファイル読み込み (同期)
                use crate::fs::read_file_content;
                use crate::graphics::psf::PsfFont;

                match read_file_content(path, &self.shell.cwd) {
                    Ok(data) => {
                        // PsfFontとして解析試行
                        match PsfFont::new(data) {
                            Some(font) => {
                                self.set_font(Box::new(font));
                                let success = self.resources.theme.success;
                                self.print_colored("Font loaded successfully.\n", success);
                            }
                            None => {
                                let err = self.resources.theme.error;
                                self.print_colored("Invalid font file (PSF parsing failed)\n", err);
                            }
                        }
                    }
                    Err(e) => {
                        let err = self.resources.theme.error;
                        self.print_colored(&alloc::format!("Failed to read file: {:?}\n", e), err);
                    }
                }
                return;
            }
            "monitor" => {
                use crate::monitor;
                let snap = monitor::snapshot();
                let output = monitor::format_snapshot(&snap);
                // Print using theme colors if possible, but the formatter has its own structure.
                // Just print raw for now.
                self.print(&output);
                self.print("\n");
                return;
            }
            _ => {}
        }

        // 既にコマンド実行中の場合は警告を表示して拒否
        if self.state.is_executing {
            let warning = self.resources.theme.warning;
            self.print_colored("(waiting for previous command...)\n", warning);
            return;
        }

        // グローバルキューにコマンドを追加（非同期タスクで処理される）
        let _request_id = submit_command(input.to_string());
        self.state.is_executing = true;
    }

    /// 履歴を前に
    pub(crate) fn history_prev(&mut self) {
        if let Some(prev) = self.state.history_navigator.prev(
            self.shell.history(),
            self.state.input_buffer.as_str(),
        ) {
            self.state.input_buffer.set(&prev);
            self.update_cursor_cache();
            self.redraw();
        }
    }

    /// 履歴を次に
    pub(crate) fn history_next(&mut self) {
        if let Some(next) = self.state.history_navigator.next(self.shell.history()) {
            self.state.input_buffer.set(&next);
            self.update_cursor_cache();
            self.redraw();
        }
    }

    /// Tab補完処理
    pub(crate) fn handle_tab(&mut self) {
        // self.shell.complete内でselfを借用する可能性があるため、入力をコピー
        let input = self.state.input_buffer.as_str().to_string();

        if self.state.completions.is_empty() {
            self.state.completions = self.shell.complete(&input);
            self.state.completion_index = 0;

            if self.state.completions.len() == 1 {
                self.state.input_buffer.set(&self.state.completions[0]);
                self.state.completions.clear();
            }
        } else {
            self.state.completion_index =
                (self.state.completion_index + 1) % self.state.completions.len();
            self.state
                .input_buffer
                .set(&self.state.completions[self.state.completion_index]);
        }

        self.update_cursor_cache();
        self.redraw();
    }

    /// 上にスクロール
    pub(crate) fn scroll_up(&mut self) {
        let max_scroll = self
            .state
            .output_lines
            .len()
            .saturating_sub((self.resources.rows - 2) as usize);
        if self.state.scroll_offset < max_scroll {
            self.state.scroll_offset += 3;
            self.state.scroll_offset = self.state.scroll_offset.min(max_scroll);
            self.redraw();
        }
    }

    /// 下にスクロール
    pub(crate) fn scroll_down(&mut self) {
        if self.state.scroll_offset > 0 {
            self.state.scroll_offset = self.state.scroll_offset.saturating_sub(3);
            self.redraw();
        }
    }

    /// シェルが実行中かどうか
    pub fn is_running(&self) -> bool {
        true // 終了条件を追加する場合はここで判定
    }
}
