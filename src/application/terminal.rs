// ============================================================================
// src/application/terminal.rs - Terminal Emulator GUI Application
// ============================================================================
//!
//! # Terminal Emulator
//!
//! CompositorWindow を使用したGUIアプリケーションとして、
//! VT100/ANSI互換のターミナルエミュレータを実装
//!
//! ## 機能
//! - VT100/ANSIエスケープシーケンス: 色、カーソル移動、画面クリア
//! - スクロールバック: 1000行のリングバッファ
//! - カーソル点滅: タイマーベース
//! - シェル統合: ExoShellとの連携

#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::graphics::{Color, image::Image, Rect};
use crate::task::current_tick;

// ============================================================================
// Constants
// ============================================================================

/// ウィンドウの幅
pub const TERMINAL_WIDTH: u32 = 800;
/// ウィンドウの高さ
pub const TERMINAL_HEIGHT: u32 = 600;

/// 文字幅 (ピクセル)
const CHAR_WIDTH: u32 = 8;
/// 文字高さ (ピクセル)
const CHAR_HEIGHT: u32 = 16;

/// ターミナルのカラム数
const TERM_COLS: usize = (TERMINAL_WIDTH / CHAR_WIDTH) as usize;
/// ターミナルの行数
const TERM_ROWS: usize = (TERMINAL_HEIGHT / CHAR_HEIGHT) as usize;

/// スクロールバック行数
const SCROLLBACK_LINES: usize = 1000;

/// カーソル点滅間隔 (ミリ秒)
const CURSOR_BLINK_INTERVAL_MS: u64 = 500;

/// デフォルトのプロンプト
const DEFAULT_PROMPT: &str = "\x1b[1;32mrany\x1b[0m:\x1b[1;34m~\x1b[0m$ ";

// ============================================================================
// ANSI Colors
// ============================================================================

/// 標準ANSIカラー (0-7)
const ANSI_COLORS: [Color; 8] = [
    Color::new(0, 0, 0),       // 0: Black
    Color::new(205, 49, 49),   // 1: Red
    Color::new(13, 188, 121),  // 2: Green
    Color::new(229, 229, 16),  // 3: Yellow
    Color::new(36, 114, 200),  // 4: Blue
    Color::new(188, 63, 188),  // 5: Magenta
    Color::new(17, 168, 205),  // 6: Cyan
    Color::new(229, 229, 229), // 7: White
];

/// 高輝度ANSIカラー (8-15)
const ANSI_BRIGHT_COLORS: [Color; 8] = [
    Color::new(102, 102, 102), // 8: Bright Black (Gray)
    Color::new(241, 76, 76),   // 9: Bright Red
    Color::new(35, 209, 139),  // 10: Bright Green
    Color::new(245, 245, 67),  // 11: Bright Yellow
    Color::new(59, 142, 234),  // 12: Bright Blue
    Color::new(214, 112, 214), // 13: Bright Magenta
    Color::new(41, 184, 219),  // 14: Bright Cyan
    Color::new(255, 255, 255), // 15: Bright White
];

/// デフォルト前景色
const DEFAULT_FG: Color = Color::new(229, 229, 229);
/// デフォルト背景色
const DEFAULT_BG: Color = Color::new(30, 30, 30);
/// カーソル色
const CURSOR_COLOR: Color = Color::new(255, 255, 255);

// ============================================================================
// Cell - ターミナルセル
// ============================================================================

/// 文字セル
#[derive(Clone, Copy)]
pub struct Cell {
    /// 文字 (ASCIIまたはUnicode)
    pub ch: char,
    /// 前景色
    pub fg: Color,
    /// 背景色
    pub bg: Color,
    /// 太字
    pub bold: bool,
    /// 下線
    pub underline: bool,
    /// 反転
    pub inverse: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            bold: false,
            underline: false,
            inverse: false,
        }
    }
}

impl Cell {
    /// 新しいセルを作成
    pub fn new(ch: char, fg: Color, bg: Color) -> Self {
        Self {
            ch,
            fg,
            bg,
            bold: false,
            underline: false,
            inverse: false,
        }
    }

    /// 描画時の実際の前景色と背景色を取得
    pub fn effective_colors(&self) -> (Color, Color) {
        if self.inverse {
            (self.bg, self.fg)
        } else {
            (self.fg, self.bg)
        }
    }
}

// ============================================================================
// TerminalLine - ターミナル行
// ============================================================================

/// ターミナル1行分のデータ
#[derive(Clone)]
pub struct TerminalLine {
    /// セル配列
    cells: Vec<Cell>,
    /// 折り返しフラグ
    wrapped: bool,
}

impl Default for TerminalLine {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalLine {
    /// 新しい行を作成
    pub fn new() -> Self {
        Self {
            cells: vec![Cell::default(); TERM_COLS],
            wrapped: false,
        }
    }

    /// 指定位置のセルを取得 (コピーを返す)
    pub fn get(&self, col: usize) -> Cell {
        self.cells.get(col).copied().unwrap_or_default()
    }

    /// 指定位置のセルへの参照を取得
    pub fn get_ref(&self, col: usize) -> Option<&Cell> {
        self.cells.get(col)
    }

    /// 指定位置のセルを設定
    pub fn set(&mut self, col: usize, cell: Cell) {
        if col < self.cells.len() {
            self.cells[col] = cell;
        }
    }

    /// 行をクリア
    pub fn clear(&mut self) {
        for cell in &mut self.cells {
            *cell = Cell::default();
        }
        self.wrapped = false;
    }

    /// 指定位置以降をクリア
    pub fn clear_from(&mut self, col: usize) {
        for i in col..self.cells.len() {
            self.cells[i] = Cell::default();
        }
    }

    /// 指定位置以前をクリア
    pub fn clear_to(&mut self, col: usize) {
        for i in 0..=col.min(self.cells.len() - 1) {
            self.cells[i] = Cell::default();
        }
    }
}

// ============================================================================
// TerminalBuffer - リングバッファ
// ============================================================================

/// スクロールバック付きターミナルバッファ
pub struct TerminalBuffer {
    /// 行バッファ (リングバッファ)
    lines: Vec<TerminalLine>,
    /// バッファの先頭インデックス
    head: usize,
    /// 現在の表示行数
    line_count: usize,
    /// スクロール位置 (0 = 最新)
    scroll_offset: usize,
}

impl Default for TerminalBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalBuffer {
    /// 新しいバッファを作成
    pub fn new() -> Self {
        let mut lines = Vec::with_capacity(SCROLLBACK_LINES);
        for _ in 0..SCROLLBACK_LINES {
            lines.push(TerminalLine::new());
        }
        Self {
            lines,
            head: 0,
            line_count: TERM_ROWS,
            scroll_offset: 0,
        }
    }

    /// 論理行インデックスを物理インデックスに変換
    fn physical_index(&self, logical: usize) -> usize {
        (self.head + logical) % SCROLLBACK_LINES
    }

    /// 指定行を取得
    pub fn get_line(&self, row: usize) -> &TerminalLine {
        let idx = self.physical_index(row + self.scroll_offset);
        &self.lines[idx]
    }

    /// 指定行を取得 (可変)
    pub fn get_line_mut(&mut self, row: usize) -> &mut TerminalLine {
        let idx = self.physical_index(row);
        &mut self.lines[idx]
    }

    /// 新しい行を追加 (スクロール)
    pub fn scroll_up(&mut self) {
        // 新しい行を追加
        if self.line_count < SCROLLBACK_LINES {
            self.line_count += 1;
        } else {
            // バッファが満杯なので先頭を進める
            self.head = (self.head + 1) % SCROLLBACK_LINES;
        }
        
        // 最終行をクリア
        let last_idx = self.physical_index(self.line_count - 1);
        self.lines[last_idx].clear();
    }

    /// スクロールバックを上に移動
    pub fn scroll_back_up(&mut self, lines: usize) {
        let max_scroll = self.line_count.saturating_sub(TERM_ROWS);
        self.scroll_offset = (self.scroll_offset + lines).min(max_scroll);
    }

    /// スクロールバックを下に移動
    pub fn scroll_back_down(&mut self, lines: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(lines);
    }

    /// スクロールバックをリセット (最新に戻る)
    pub fn reset_scroll(&mut self) {
        self.scroll_offset = 0;
    }

    /// 全画面クリア
    pub fn clear_all(&mut self) {
        for line in &mut self.lines {
            line.clear();
        }
        self.head = 0;
        self.line_count = TERM_ROWS;
        self.scroll_offset = 0;
    }
}

// ============================================================================
// AnsiParser - エスケープシーケンスパーサー
// ============================================================================

/// パーサーの状態
#[derive(Clone, Copy, PartialEq, Eq)]
enum ParserState {
    /// 通常テキスト
    Normal,
    /// ESC受信後
    Escape,
    /// CSI受信後 (ESC [)
    Csi,
    /// OSC受信後 (ESC ])
    Osc,
}

/// ANSIエスケープシーケンスパーサー
pub struct AnsiParser {
    /// 現在の状態
    state: ParserState,
    /// CSIパラメータバッファ
    params: Vec<u32>,
    /// 現在のパラメータ値
    current_param: u32,
    /// パラメータ区切りがあったか
    param_started: bool,
    /// OSC文字列バッファ
    osc_buffer: String,
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AnsiParser {
    /// 新しいパーサーを作成
    pub fn new() -> Self {
        Self {
            state: ParserState::Normal,
            params: Vec::with_capacity(16),
            current_param: 0,
            param_started: false,
            osc_buffer: String::new(),
        }
    }

    /// 状態をリセット
    pub fn reset(&mut self) {
        self.state = ParserState::Normal;
        self.params.clear();
        self.current_param = 0;
        self.param_started = false;
        self.osc_buffer.clear();
    }

    /// 1文字を処理して、出力アクションを返す
    pub fn feed(&mut self, ch: char) -> ParseAction {
        match self.state {
            ParserState::Normal => self.handle_normal(ch),
            ParserState::Escape => self.handle_escape(ch),
            ParserState::Csi => self.handle_csi(ch),
            ParserState::Osc => self.handle_osc(ch),
        }
    }

    /// 通常状態での処理
    fn handle_normal(&mut self, ch: char) -> ParseAction {
        match ch {
            '\x1b' => {
                self.state = ParserState::Escape;
                ParseAction::None
            }
            '\n' => ParseAction::NewLine,
            '\r' => ParseAction::CarriageReturn,
            '\x08' => ParseAction::Backspace,
            '\t' => ParseAction::Tab,
            '\x07' => ParseAction::Bell,
            _ if ch >= ' ' => ParseAction::Print(ch),
            _ => ParseAction::None,
        }
    }

    /// ESC後の処理
    fn handle_escape(&mut self, ch: char) -> ParseAction {
        match ch {
            '[' => {
                self.state = ParserState::Csi;
                self.params.clear();
                self.current_param = 0;
                self.param_started = false;
                ParseAction::None
            }
            ']' => {
                self.state = ParserState::Osc;
                self.osc_buffer.clear();
                ParseAction::None
            }
            'c' => {
                self.reset();
                ParseAction::Reset
            }
            '7' => {
                self.reset();
                ParseAction::SaveCursor
            }
            '8' => {
                self.reset();
                ParseAction::RestoreCursor
            }
            'D' => {
                self.reset();
                ParseAction::Index
            }
            'M' => {
                self.reset();
                ParseAction::ReverseIndex
            }
            _ => {
                self.reset();
                ParseAction::None
            }
        }
    }

    /// CSI (Control Sequence Introducer) 処理
    fn handle_csi(&mut self, ch: char) -> ParseAction {
        match ch {
            '0'..='9' => {
                self.param_started = true;
                self.current_param = self.current_param * 10 + (ch as u32 - '0' as u32);
                ParseAction::None
            }
            ';' => {
                self.params.push(self.current_param);
                self.current_param = 0;
                self.param_started = false;
                ParseAction::None
            }
            'm' => {
                // SGR (Select Graphic Rendition)
                if self.param_started || !self.params.is_empty() {
                    self.params.push(self.current_param);
                }
                let action = ParseAction::Sgr(self.params.clone());
                self.reset();
                action
            }
            'A' => {
                // Cursor Up
                let n = if self.param_started { self.current_param.max(1) } else { 1 };
                self.reset();
                ParseAction::CursorUp(n)
            }
            'B' => {
                // Cursor Down
                let n = if self.param_started { self.current_param.max(1) } else { 1 };
                self.reset();
                ParseAction::CursorDown(n)
            }
            'C' => {
                // Cursor Forward
                let n = if self.param_started { self.current_param.max(1) } else { 1 };
                self.reset();
                ParseAction::CursorForward(n)
            }
            'D' => {
                // Cursor Back
                let n = if self.param_started { self.current_param.max(1) } else { 1 };
                self.reset();
                ParseAction::CursorBack(n)
            }
            'H' | 'f' => {
                // Cursor Position
                if self.param_started || !self.params.is_empty() {
                    self.params.push(self.current_param);
                }
                let row = self.params.first().copied().unwrap_or(1).max(1);
                let col = self.params.get(1).copied().unwrap_or(1).max(1);
                self.reset();
                ParseAction::CursorPosition(row, col)
            }
            'J' => {
                // Erase in Display
                let mode = if self.param_started { self.current_param } else { 0 };
                self.reset();
                ParseAction::EraseDisplay(mode)
            }
            'K' => {
                // Erase in Line
                let mode = if self.param_started { self.current_param } else { 0 };
                self.reset();
                ParseAction::EraseLine(mode)
            }
            'S' => {
                // Scroll Up
                let n = if self.param_started { self.current_param.max(1) } else { 1 };
                self.reset();
                ParseAction::ScrollUp(n)
            }
            'T' => {
                // Scroll Down
                let n = if self.param_started { self.current_param.max(1) } else { 1 };
                self.reset();
                ParseAction::ScrollDown(n)
            }
            's' => {
                // Save cursor position
                self.reset();
                ParseAction::SaveCursor
            }
            'u' => {
                // Restore cursor position
                self.reset();
                ParseAction::RestoreCursor
            }
            'n' => {
                // Device Status Report
                let n = if self.param_started { self.current_param } else { 0 };
                self.reset();
                ParseAction::DeviceStatusReport(n)
            }
            _ => {
                // 未知のシーケンス
                self.reset();
                ParseAction::None
            }
        }
    }

    /// OSC (Operating System Command) 処理
    fn handle_osc(&mut self, ch: char) -> ParseAction {
        match ch {
            '\x07' | '\x1b' => {
                // BEL または ESC で終了
                let title = self.osc_buffer.clone();
                self.reset();
                ParseAction::SetTitle(title)
            }
            _ => {
                if self.osc_buffer.len() < 256 {
                    self.osc_buffer.push(ch);
                }
                ParseAction::None
            }
        }
    }
}

/// パーサーのアクション
#[derive(Clone)]
pub enum ParseAction {
    /// 何もしない
    None,
    /// 文字を表示
    Print(char),
    /// 改行
    NewLine,
    /// キャリッジリターン
    CarriageReturn,
    /// バックスペース
    Backspace,
    /// タブ
    Tab,
    /// ベル
    Bell,
    /// リセット
    Reset,
    /// カーソル上移動
    CursorUp(u32),
    /// カーソル下移動
    CursorDown(u32),
    /// カーソル右移動
    CursorForward(u32),
    /// カーソル左移動
    CursorBack(u32),
    /// カーソル位置設定 (row, col) 1-indexed
    CursorPosition(u32, u32),
    /// ディスプレイクリア (0=below, 1=above, 2=all)
    EraseDisplay(u32),
    /// 行クリア (0=right, 1=left, 2=all)
    EraseLine(u32),
    /// スクロールアップ
    ScrollUp(u32),
    /// スクロールダウン
    ScrollDown(u32),
    /// SGR (色・属性設定)
    Sgr(Vec<u32>),
    /// カーソル保存
    SaveCursor,
    /// カーソル復帰
    RestoreCursor,
    /// インデックス (下移動+スクロール)
    Index,
    /// リバースインデックス (上移動+スクロール)
    ReverseIndex,
    /// タイトル設定
    SetTitle(String),
    /// デバイスステータスレポート
    DeviceStatusReport(u32),
}

// ============================================================================
// Terminal - ターミナルエミュレータ本体
// ============================================================================

/// ターミナルエミュレータ
pub struct Terminal {
    /// ターミナルバッファ
    buffer: TerminalBuffer,
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
                // Enterキー: 入力を確定してエコー
                self.input_buffer.push('\n');
                self.write_char('\r');
                self.write_char('\n');
            }
            '\x08' | '\x7f' => {
                // Backspace/Delete
                if !self.input_buffer.is_empty() {
                    self.input_buffer.pop();
                    // エコーバック
                    self.write_char('\x08');
                    self.write_char(' ');
                    self.write_char('\x08');
                }
            }
            '\x03' => {
                // Ctrl+C
                self.write_str("^C\r\n");
                self.input_buffer.clear();
            }
            '\x04' => {
                // Ctrl+D (EOF)
                if self.input_buffer.is_empty() {
                    self.write_str("^D\r\n");
                }
            }
            '\x0c' => {
                // Ctrl+L (Clear screen)
                self.clear_screen();
            }
            _ if ch >= ' ' && ch <= '~' => {
                // 通常の印字可能文字
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
                    // カーソル位置を報告
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
    fn cursor_forward(&mut self, n: usize) {
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
        // バッファ内の行を下にシフト
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
                // カーソル以降を消去
                self.erase_line(0);
                for row in (self.cursor_row + 1)..TERM_ROWS {
                    self.buffer.get_line_mut(row).clear();
                }
            }
            1 => {
                // カーソル以前を消去
                self.erase_line(1);
                for row in 0..self.cursor_row {
                    self.buffer.get_line_mut(row).clear();
                }
            }
            2 | 3 => {
                // 全画面消去
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
            // リセット
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
                    // リセット
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
                // 前景色 (30-37)
                30..=37 => {
                    let idx = (params[i] - 30) as usize;
                    self.current_fg = if self.bold {
                        ANSI_BRIGHT_COLORS[idx]
                    } else {
                        ANSI_COLORS[idx]
                    };
                }
                // 前景色デフォルト
                39 => self.current_fg = DEFAULT_FG,
                // 背景色 (40-47)
                40..=47 => {
                    let idx = (params[i] - 40) as usize;
                    self.current_bg = ANSI_COLORS[idx];
                }
                // 背景色デフォルト
                49 => self.current_bg = DEFAULT_BG,
                // 高輝度前景色 (90-97)
                90..=97 => {
                    let idx = (params[i] - 90) as usize;
                    self.current_fg = ANSI_BRIGHT_COLORS[idx];
                }
                // 高輝度背景色 (100-107)
                100..=107 => {
                    let idx = (params[i] - 100) as usize;
                    self.current_bg = ANSI_BRIGHT_COLORS[idx];
                }
                // 256色前景 (38;5;n)
                38 => {
                    if i + 2 < params.len() && params[i + 1] == 5 {
                        let n = params[i + 2] as usize;
                        self.current_fg = color_from_256(n);
                        i += 2;
                    }
                }
                // 256色背景 (48;5;n)
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
}

/// 特殊キー
#[derive(Clone, Copy, Debug)]
pub enum SpecialKey {
    Up,
    Down,
    Right,
    Left,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
}

/// 256色パレットから色を取得
fn color_from_256(n: usize) -> Color {
    match n {
        0..=7 => ANSI_COLORS[n],
        8..=15 => ANSI_BRIGHT_COLORS[n - 8],
        16..=231 => {
            // 216色キューブ (6x6x6)
            let n = n - 16;
            let r = ((n / 36) % 6) * 51;
            let g = ((n / 6) % 6) * 51;
            let b = (n % 6) * 51;
            Color::new(r as u8, g as u8, b as u8)
        }
        232..=255 => {
            // グレースケール (24段階)
            let gray = ((n - 232) * 10 + 8) as u8;
            Color::new(gray, gray, gray)
        }
        _ => DEFAULT_FG,
    }
}

// ============================================================================
// Terminal Rendering
// ============================================================================

impl Terminal {
    /// ターミナルをバッファに描画
    pub fn render(&self, buffer: &mut Image) {
        // 背景をクリア
        let full_rect = Rect::new(0, 0, buffer.width(), buffer.height());
        buffer.fill_rect(full_rect, DEFAULT_BG);

        // 各行を描画
        for row in 0..TERM_ROWS {
            self.render_line(buffer, row);
        }

        // カーソルを描画
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
            
            // 背景を描画
            let bg_rect = Rect::new(x as i32, y as i32, CHAR_WIDTH, CHAR_HEIGHT);
            buffer.fill_rect(bg_rect, bg);
            
            // 文字を描画
            if cell.ch != ' ' {
                self.draw_char(buffer, x as i32, y as i32, cell.ch, fg);
            }
            
            // 下線
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
        
        // ブロックカーソル
        let cursor_rect = Rect::new(x as i32, y as i32, CHAR_WIDTH, CHAR_HEIGHT);
        
        // カーソル位置の文字を取得
        let line = self.buffer.get_line(self.cursor_row);
        let cell = line.get(self.cursor_col);
        
        // カーソル背景
        buffer.fill_rect(cursor_rect, CURSOR_COLOR);
        
        // 反転した文字を描画
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
}

// ============================================================================
// 8x16 Bitmap Font
// ============================================================================

/// 8x16ビットマップフォント
fn get_char_bitmap_8x16(ch: char) -> Option<[u8; 16]> {
    Some(match ch {
        // 数字
        '0' => [0x00, 0x00, 0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        '1' => [0x00, 0x00, 0x18, 0x38, 0x78, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        '2' => [0x00, 0x00, 0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x66, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        '3' => [0x00, 0x00, 0x3C, 0x66, 0x06, 0x06, 0x1C, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        '4' => [0x00, 0x00, 0x0C, 0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x0C, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00],
        '5' => [0x00, 0x00, 0x7E, 0x60, 0x60, 0x7C, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        '6' => [0x00, 0x00, 0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        '7' => [0x00, 0x00, 0x7E, 0x66, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        '8' => [0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        '9' => [0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x0C, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00],
        
        // 大文字
        'A' => [0x00, 0x00, 0x18, 0x3C, 0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'B' => [0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'C' => [0x00, 0x00, 0x3C, 0x66, 0x66, 0x60, 0x60, 0x60, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'D' => [0x00, 0x00, 0x78, 0x6C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00],
        'E' => [0x00, 0x00, 0x7E, 0x60, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        'F' => [0x00, 0x00, 0x7E, 0x60, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00],
        'G' => [0x00, 0x00, 0x3C, 0x66, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x66, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00],
        'H' => [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'I' => [0x00, 0x00, 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        'J' => [0x00, 0x00, 0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x6C, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00],
        'K' => [0x00, 0x00, 0x66, 0x6C, 0x78, 0x70, 0x60, 0x70, 0x78, 0x6C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'L' => [0x00, 0x00, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        'M' => [0x00, 0x00, 0xC6, 0xEE, 0xFE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x00],
        'N' => [0x00, 0x00, 0x66, 0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'O' => [0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'P' => [0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00],
        'Q' => [0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x76, 0x6C, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00],
        'R' => [0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'S' => [0x00, 0x00, 0x3C, 0x66, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'T' => [0x00, 0x00, 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        'U' => [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'V' => [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        'W' => [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xD6, 0xFE, 0xEE, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x00],
        'X' => [0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'Y' => [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        'Z' => [0x00, 0x00, 0x7E, 0x06, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        
        // 小文字
        'a' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x66, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00],
        'b' => [0x00, 0x00, 0x60, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'c' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x60, 0x60, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'd' => [0x00, 0x00, 0x06, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00],
        'e' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'f' => [0x00, 0x00, 0x1C, 0x36, 0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00],
        'g' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00],
        'h' => [0x00, 0x00, 0x60, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'i' => [0x00, 0x00, 0x18, 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'j' => [0x00, 0x00, 0x0C, 0x0C, 0x00, 0x1C, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x6C, 0x38, 0x00, 0x00, 0x00],
        'k' => [0x00, 0x00, 0x60, 0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'l' => [0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'm' => [0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0xFE, 0xD6, 0xD6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x00],
        'n' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'o' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'p' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00],
        'q' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00],
        'r' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00],
        's' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x06, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00],
        't' => [0x00, 0x00, 0x30, 0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x36, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00],
        'u' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00],
        'v' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        'w' => [0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xD6, 0xFE, 0xEE, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x00],
        'x' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x3C, 0x3C, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        'y' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00],
        'z' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        
        // 記号
        ' ' => [0x00; 16],
        '!' => [0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        '"' => [0x00, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '#' => [0x00, 0x00, 0x36, 0x36, 0x7F, 0x36, 0x36, 0x36, 0x7F, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00],
        '$' => [0x00, 0x18, 0x3E, 0x60, 0x60, 0x3C, 0x06, 0x06, 0x7C, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        '%' => [0x00, 0x00, 0x62, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '&' => [0x00, 0x00, 0x38, 0x6C, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00],
        '\'' => [0x00, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '(' => [0x00, 0x00, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],
        ')' => [0x00, 0x00, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00],
        '*' => [0x00, 0x00, 0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '+' => [0x00, 0x00, 0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ',' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00],
        '-' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '/' => [0x00, 0x00, 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ':' => [0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ';' => [0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '<' => [0x00, 0x00, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00],
        '=' => [0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '>' => [0x00, 0x00, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00],
        '?' => [0x00, 0x00, 0x3C, 0x66, 0x06, 0x0C, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        '@' => [0x00, 0x00, 0x7C, 0xC6, 0xDE, 0xD6, 0xDE, 0xC0, 0xC0, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '[' => [0x00, 0x00, 0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        '\\' => [0x00, 0x00, 0x80, 0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ']' => [0x00, 0x00, 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        '^' => [0x00, 0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00],
        '`' => [0x00, 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '{' => [0x00, 0x00, 0x0E, 0x18, 0x18, 0x18, 0x70, 0x18, 0x18, 0x18, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00],
        '|' => [0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        '}' => [0x00, 0x00, 0x70, 0x18, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x18, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00],
        '~' => [0x00, 0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        
        _ => return None,
    })
}

// ============================================================================
// Command History - コマンド履歴
// ============================================================================

/// コマンド履歴の最大サイズ
const HISTORY_MAX_SIZE: usize = 100;

/// コマンド履歴
pub struct CommandHistory {
    /// 履歴エントリ
    entries: Vec<String>,
    /// 現在の位置 (None = 新規入力中)
    position: Option<usize>,
    /// 最大サイズ
    max_size: usize,
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandHistory {
    /// 新しい履歴を作成
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            position: None,
            max_size: HISTORY_MAX_SIZE,
        }
    }

    /// エントリを追加
    pub fn add(&mut self, command: &str) {
        let cmd = command.trim();
        if cmd.is_empty() {
            return;
        }
        
        // 重複を避ける (最後のエントリと同じなら追加しない)
        if self.entries.last().map(|s| s.as_str()) == Some(cmd) {
            return;
        }
        
        self.entries.push(String::from(cmd));
        
        // 最大サイズを超えたら古いエントリを削除
        if self.entries.len() > self.max_size {
            self.entries.remove(0);
        }
        
        // 位置をリセット
        self.position = None;
    }

    /// 前の履歴を取得 (↑キー)
    pub fn previous(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        
        let pos = match self.position {
            None => self.entries.len().saturating_sub(1),
            Some(p) => p.saturating_sub(1),
        };
        
        self.position = Some(pos);
        self.entries.get(pos).map(|s| s.as_str())
    }

    /// 次の履歴を取得 (↓キー)
    pub fn next(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        
        match self.position {
            None => None,
            Some(p) => {
                if p + 1 >= self.entries.len() {
                    self.position = None;
                    None
                } else {
                    self.position = Some(p + 1);
                    self.entries.get(p + 1).map(|s| s.as_str())
                }
            }
        }
    }

    /// 位置をリセット
    pub fn reset_position(&mut self) {
        self.position = None;
    }

    /// 履歴を検索
    pub fn search(&self, prefix: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.starts_with(prefix))
            .map(|s| s.as_str())
            .collect()
    }

    /// 履歴の件数
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 履歴が空かどうか
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 全履歴を取得
    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}

// ============================================================================
// Line Editor - ラインエディタ
// ============================================================================

/// ラインエディタ (readline風)
pub struct LineEditor {
    /// 現在の入力行
    buffer: String,
    /// カーソル位置 (文字数)
    cursor: usize,
    /// コマンド履歴
    history: CommandHistory,
    /// 一時保存された入力 (履歴ナビゲーション用)
    saved_input: Option<String>,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    /// 新しいラインエディタを作成
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            history: CommandHistory::new(),
            saved_input: None,
        }
    }

    /// 現在の入力を取得
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    /// カーソル位置を取得
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// 文字を挿入
    pub fn insert(&mut self, ch: char) {
        if self.cursor >= self.buffer.len() {
            self.buffer.push(ch);
        } else {
            self.buffer.insert(self.cursor, ch);
        }
        self.cursor += 1;
    }

    /// 文字列を挿入
    pub fn insert_str(&mut self, s: &str) {
        for ch in s.chars() {
            self.insert(ch);
        }
    }

    /// カーソル位置の文字を削除 (Delete)
    pub fn delete(&mut self) {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
        }
    }

    /// カーソル前の文字を削除 (Backspace)
    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.buffer.remove(self.cursor);
        }
    }

    /// カーソルを左に移動
    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    /// カーソルを右に移動
    pub fn move_right(&mut self) {
        if self.cursor < self.buffer.len() {
            self.cursor += 1;
        }
    }

    /// カーソルを行頭に移動 (Home / Ctrl+A)
    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    /// カーソルを行末に移動 (End / Ctrl+E)
    pub fn move_end(&mut self) {
        self.cursor = self.buffer.len();
    }

    /// 単語単位で左に移動 (Ctrl+←)
    pub fn move_word_left(&mut self) {
        // 空白をスキップ
        while self.cursor > 0 && self.buffer.chars().nth(self.cursor - 1) == Some(' ') {
            self.cursor -= 1;
        }
        // 単語の先頭まで移動
        while self.cursor > 0 && self.buffer.chars().nth(self.cursor - 1) != Some(' ') {
            self.cursor -= 1;
        }
    }

    /// 単語単位で右に移動 (Ctrl+→)
    pub fn move_word_right(&mut self) {
        let len = self.buffer.len();
        // 現在の単語をスキップ
        while self.cursor < len && self.buffer.chars().nth(self.cursor) != Some(' ') {
            self.cursor += 1;
        }
        // 空白をスキップ
        while self.cursor < len && self.buffer.chars().nth(self.cursor) == Some(' ') {
            self.cursor += 1;
        }
    }

    /// カーソルから行末までを削除 (Ctrl+K)
    pub fn kill_to_end(&mut self) -> String {
        let killed = String::from(&self.buffer[self.cursor..]);
        self.buffer.truncate(self.cursor);
        killed
    }

    /// カーソルから行頭までを削除 (Ctrl+U)
    pub fn kill_to_start(&mut self) -> String {
        let killed = String::from(&self.buffer[..self.cursor]);
        self.buffer = String::from(&self.buffer[self.cursor..]);
        self.cursor = 0;
        killed
    }

    /// 単語を削除 (Ctrl+W)
    pub fn kill_word(&mut self) -> String {
        let start = self.cursor;
        self.move_word_left();
        let killed = String::from(&self.buffer[self.cursor..start]);
        self.buffer = format!("{}{}", &self.buffer[..self.cursor], &self.buffer[start..]);
        killed
    }

    /// 行をクリア
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    /// 入力を確定して取得
    pub fn submit(&mut self) -> String {
        let line = core::mem::take(&mut self.buffer);
        self.cursor = 0;
        self.history.add(&line);
        self.history.reset_position();
        self.saved_input = None;
        line
    }

    /// 履歴の前へ (↑)
    pub fn history_previous(&mut self) -> bool {
        // 初回は現在の入力を保存
        if self.history.position.is_none() {
            self.saved_input = Some(self.buffer.clone());
        }
        
        if let Some(entry) = self.history.previous() {
            self.buffer = String::from(entry);
            self.cursor = self.buffer.len();
            true
        } else {
            false
        }
    }

    /// 履歴の次へ (↓)
    pub fn history_next(&mut self) -> bool {
        if let Some(entry) = self.history.next() {
            self.buffer = String::from(entry);
            self.cursor = self.buffer.len();
            true
        } else {
            // 履歴の最後を超えたら保存した入力を復元
            if let Some(saved) = self.saved_input.take() {
                self.buffer = saved;
                self.cursor = self.buffer.len();
            }
            false
        }
    }

    /// 履歴への参照を取得
    pub fn history(&self) -> &CommandHistory {
        &self.history
    }

    /// 履歴への可変参照を取得
    pub fn history_mut(&mut self) -> &mut CommandHistory {
        &mut self.history
    }
}

// ============================================================================
// Text Selection - テキスト選択
// ============================================================================

/// 選択範囲
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// 開始位置 (col, row)
    pub start: (usize, usize),
    /// 終了位置 (col, row)
    pub end: (usize, usize),
}

impl Selection {
    /// 新しい選択を作成
    pub fn new(start: (usize, usize), end: (usize, usize)) -> Self {
        Self { start, end }
    }

    /// 正規化された選択を取得 (start <= end)
    pub fn normalized(&self) -> Self {
        if self.start.1 > self.end.1 || 
           (self.start.1 == self.end.1 && self.start.0 > self.end.0) {
            Self { start: self.end, end: self.start }
        } else {
            *self
        }
    }

    /// 位置が選択範囲内かどうか
    pub fn contains(&self, col: usize, row: usize) -> bool {
        let norm = self.normalized();
        if row < norm.start.1 || row > norm.end.1 {
            return false;
        }
        if row == norm.start.1 && col < norm.start.0 {
            return false;
        }
        if row == norm.end.1 && col > norm.end.0 {
            return false;
        }
        true
    }
}

// ============================================================================
// Terminal with Enhanced Features
// ============================================================================

impl Terminal {
    /// ラインエディタを使用した入力処理
    pub fn process_line_edit(&mut self, editor: &mut LineEditor, ch: char) -> Option<String> {
        match ch {
            '\r' | '\n' => {
                // 改行: 入力を確定
                self.write_str("\r\n");
                Some(editor.submit())
            }
            '\x08' | '\x7f' => {
                // Backspace
                if editor.cursor() > 0 {
                    editor.backspace();
                    // カーソルを左に移動して文字を削除
                    self.write_str("\x08 \x08");
                    // 残りの文字を再描画
                    let remaining = &editor.buffer()[editor.cursor()..];
                    if !remaining.is_empty() {
                        self.write_str(remaining);
                        self.write_str(" ");
                        // カーソルを戻す
                        for _ in 0..=remaining.len() {
                            self.write_str("\x08");
                        }
                    }
                }
                None
            }
            '\x01' => {
                // Ctrl+A: 行頭へ
                let moves = editor.cursor();
                editor.move_home();
                for _ in 0..moves {
                    self.write_str("\x08");
                }
                None
            }
            '\x05' => {
                // Ctrl+E: 行末へ
                let moves = editor.buffer().len() - editor.cursor();
                editor.move_end();
                for _ in 0..moves {
                    self.cursor_forward(1);
                }
                None
            }
            '\x0B' => {
                // Ctrl+K: 行末まで削除
                let killed = editor.kill_to_end();
                // 画面上の文字を消去
                self.write_str("\x1b[K");
                let _ = killed; // TODO: クリップボードに保存
                None
            }
            '\x15' => {
                // Ctrl+U: 行頭まで削除
                let killed = editor.kill_to_start();
                // 画面をクリアして再描画
                self.write_str("\r");
                self.write_str("\x1b[K");
                self.write_str(editor.buffer());
                let _ = killed; // TODO: クリップボードに保存
                None
            }
            '\x17' => {
                // Ctrl+W: 単語削除
                let old_cursor = editor.cursor();
                let killed = editor.kill_word();
                // カーソルを移動して再描画
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
                // Ctrl+C: 中断
                self.write_str("^C\r\n");
                editor.clear();
                None
            }
            '\x0C' => {
                // Ctrl+L: 画面クリア
                self.clear_screen();
                // プロンプトと現在の入力を再表示
                None
            }
            _ if ch >= ' ' && ch <= '~' => {
                // 通常文字
                editor.insert(ch);
                self.write_char(ch);
                // 挿入位置より後ろを再描画
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
                // 履歴の前へ
                if editor.history_previous() {
                    // 現在の行をクリアして履歴を表示
                    self.write_str("\r\x1b[K");
                    self.write_str(editor.buffer());
                }
                false
            }
            SpecialKey::Down => {
                // 履歴の次へ
                editor.history_next();
                // 現在の行をクリアして表示
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
                    // 残りを再描画
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
        
        // 末尾の空白を削除
        let trimmed = text.trim_end();
        String::from(trimmed)
    }

    /// 選択範囲を描画
    pub fn render_with_selection(&self, buffer: &mut Image, selection: Option<&Selection>) {
        // 背景をクリア
        let full_rect = Rect::new(0, 0, buffer.width(), buffer.height());
        buffer.fill_rect(full_rect, DEFAULT_BG);

        // 各行を描画
        for row in 0..TERM_ROWS {
            self.render_line_with_selection(buffer, row, selection);
        }

        // カーソルを描画
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
            
            // 選択範囲内かどうかをチェック
            let is_selected = selection.map(|s| s.contains(col, row)).unwrap_or(false);
            
            let (fg, bg) = if is_selected {
                // 選択範囲は反転
                let (f, b) = cell.effective_colors();
                (b, f)
            } else {
                cell.effective_colors()
            };
            
            // 背景を描画
            let bg_rect = Rect::new(x as i32, y as i32, CHAR_WIDTH, CHAR_HEIGHT);
            buffer.fill_rect(bg_rect, bg);
            
            // 文字を描画
            if cell.ch != ' ' {
                self.draw_char(buffer, x as i32, y as i32, cell.ch, fg);
            }
            
            // 下線
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
        self.write_str("\x1b[1;36m"); // Bold Cyan
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
        self.write_str("\x1b[0m"); // Reset
        self.write_str("\r\n");
        self.write_str("\x1b[1;33mWelcome to Rany OS Terminal!\x1b[0m\r\n");
        self.write_str("Type '\x1b[1;32mhelp\x1b[0m' for available commands.\r\n");
        self.write_str("\r\n");
    }
}

// ============================================================================
// Tab Completion - タブ補完
// ============================================================================

/// タブ補完のコールバック型
pub type CompletionCallback = fn(&str) -> Vec<String>;

/// タブ補完ヘルパー
pub struct TabCompleter {
    /// 候補リスト
    candidates: Vec<String>,
    /// 現在のインデックス
    index: usize,
    /// 補完中のプレフィックス
    prefix: String,
}

impl Default for TabCompleter {
    fn default() -> Self {
        Self::new()
    }
}

impl TabCompleter {
    /// 新しいTabCompleterを作成
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
            index: 0,
            prefix: String::new(),
        }
    }

    /// 候補を設定
    pub fn set_candidates(&mut self, prefix: &str, candidates: Vec<String>) {
        self.prefix = String::from(prefix);
        self.candidates = candidates;
        self.index = 0;
    }

    /// 次の候補を取得
    pub fn next(&mut self) -> Option<&str> {
        if self.candidates.is_empty() {
            return None;
        }
        let result = self.candidates.get(self.index).map(|s| s.as_str());
        self.index = (self.index + 1) % self.candidates.len();
        result
    }

    /// 前の候補を取得
    pub fn previous(&mut self) -> Option<&str> {
        if self.candidates.is_empty() {
            return None;
        }
        if self.index == 0 {
            self.index = self.candidates.len() - 1;
        } else {
            self.index -= 1;
        }
        self.candidates.get(self.index).map(|s| s.as_str())
    }

    /// 候補数を取得
    pub fn count(&self) -> usize {
        self.candidates.len()
    }

    /// リセット
    pub fn reset(&mut self) {
        self.candidates.clear();
        self.index = 0;
        self.prefix.clear();
    }

    /// 補完中のプレフィックス
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// 全候補を取得
    pub fn all_candidates(&self) -> &[String] {
        &self.candidates
    }
}

// ============================================================================
// Clipboard - クリップボード
// ============================================================================

use spin::Mutex;

/// シンプルなクリップボード
pub struct Clipboard {
    /// 内容
    content: Mutex<String>,
}

impl Clipboard {
    /// 新しいクリップボードを作成
    pub const fn new() -> Self {
        Self {
            content: Mutex::new(String::new()),
        }
    }

    /// テキストをコピー
    pub fn copy(&self, text: &str) {
        let mut content = self.content.lock();
        content.clear();
        content.push_str(text);
    }

    /// テキストをペースト
    pub fn paste(&self) -> String {
        self.content.lock().clone()
    }

    /// クリア
    pub fn clear(&self) {
        self.content.lock().clear();
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.content.lock().is_empty()
    }
}

/// グローバルクリップボード
pub static CLIPBOARD: Clipboard = Clipboard::new();

// ============================================================================
// Terminal Application - 完全なターミナルアプリケーション
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
        // タブキー処理
        if ch == '\t' {
            self.handle_tab();
            return;
        }

        // 補完をリセット
        self.completer.reset();

        // ラインエディタで処理
        if let Some(command) = self.terminal.process_line_edit(&mut self.editor, ch) {
            // コマンドが確定された
            self.execute_command(&command);
        }
    }

    /// 特殊キー入力を処理
    pub fn handle_special_key(&mut self, key: SpecialKey) {
        // PageUp/PageDownでスクロール
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

        // 補完をリセット
        self.completer.reset();

        // ラインエディタで処理
        self.terminal.process_special_key(&mut self.editor, key);
    }

    /// タブ補完を処理
    fn handle_tab(&mut self) {
        let input = self.editor.buffer();
        
        // 最初のタブ: 候補を検索
        if self.completer.count() == 0 {
            // 単語の先頭を探す
            let word_start = input.rfind(' ').map(|i| i + 1).unwrap_or(0);
            let word = &input[word_start..];
            
            // 候補を生成 (簡易的な実装)
            let candidates = self.generate_completions(word);
            
            if candidates.len() == 1 {
                // 一つだけなら補完
                self.apply_completion(&candidates[0], word_start);
            } else if !candidates.is_empty() {
                // 複数なら候補を設定
                self.completer.set_candidates(word, candidates);
                self.show_completions();
            }
        } else {
            // 次の候補を適用
            if let Some(candidate) = self.completer.next() {
                let candidate = String::from(candidate);
                let word_start = self.editor.buffer().rfind(' ').map(|i| i + 1).unwrap_or(0);
                self.apply_completion(&candidate, word_start);
            }
        }
    }

    /// 補完候補を生成
    fn generate_completions(&self, prefix: &str) -> Vec<String> {
        // 基本的なコマンド一覧
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
        // カーソルを単語の先頭まで戻す
        while self.editor.cursor() > word_start {
            self.editor.backspace();
            self.terminal.write_str("\x08 \x08");
        }
        
        // 補完を挿入
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

        // シェルコールバックがあれば使用
        if let Some(callback) = self.shell_callback {
            let output = callback(cmd);
            self.terminal.write_str(&output);
        } else {
            // 簡易的な組み込みコマンド
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
                // 色パレットを表示
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
        
        // 範囲チェック
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
            
            // 範囲チェック
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
            
            // 選択テキストをクリップボードにコピー
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

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_creation() {
        let term = Terminal::new();
        assert!(term.is_running());
        assert_eq!(term.cursor_position(), (0, 0));
    }

    #[test]
    fn test_ansi_parser_colors() {
        let mut parser = AnsiParser::new();
        
        // ESC[31m (赤色)
        assert!(matches!(parser.feed('\x1b'), ParseAction::None));
        assert!(matches!(parser.feed('['), ParseAction::None));
        assert!(matches!(parser.feed('3'), ParseAction::None));
        assert!(matches!(parser.feed('1'), ParseAction::None));
        
        if let ParseAction::Sgr(params) = parser.feed('m') {
            assert_eq!(params, vec![31]);
        } else {
            panic!("Expected SGR action");
        }
    }

    #[test]
    fn test_ansi_parser_cursor() {
        let mut parser = AnsiParser::new();
        
        // ESC[5A (カーソルを5行上に)
        parser.feed('\x1b');
        parser.feed('[');
        parser.feed('5');
        
        if let ParseAction::CursorUp(n) = parser.feed('A') {
            assert_eq!(n, 5);
        } else {
            panic!("Expected CursorUp action");
        }
    }

    #[test]
    fn test_terminal_write() {
        let mut term = Terminal::new();
        
        term.write_str("Hello");
        assert_eq!(term.cursor_position(), (5, 0));
        
        term.write_char('\n');
        assert_eq!(term.cursor_position(), (5, 1));
        
        term.write_char('\r');
        assert_eq!(term.cursor_position(), (0, 1));
    }

    #[test]
    fn test_cell_default() {
        let cell = Cell::default();
        assert_eq!(cell.ch, ' ');
        assert!(!cell.bold);
        assert!(!cell.underline);
        assert!(!cell.inverse);
    }

    #[test]
    fn test_color_from_256() {
        // 標準色
        let c0 = color_from_256(0);
        assert_eq!(c0.red, ANSI_COLORS[0].red);
        
        // 高輝度色
        let c8 = color_from_256(8);
        assert_eq!(c8.red, ANSI_BRIGHT_COLORS[0].red);
        
        // グレースケール
        let gray = color_from_256(232);
        assert_eq!(gray.red, gray.green);
        assert_eq!(gray.green, gray.blue);
    }
}
