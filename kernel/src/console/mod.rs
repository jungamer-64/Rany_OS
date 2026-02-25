// ============================================================================
// src/console/mod.rs - 統合コンソールシステム
// ============================================================================
//!
//! # 統合コンソールシステム
//!
//! シェル、入力、グラフィックス、シリアルを統合した
//! 高機能コンソール。複数の仮想コンソール（VT）をサポート。
//!
//! ## 機能
//! - 複数の仮想ターミナル
//! - ANSI/VT100エスケープシーケンス
//! - スクロールバック
//! - コピー＆ペースト
//! - ログ出力統合

// Allow explicit Default impl for AnsiColor for clarity
#![allow(clippy::derivable_impls)]
#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

// ============================================================================
// Configuration
// ============================================================================

/// 最大仮想コンソール数
mod input;
pub use input::*;
mod impls;
pub use impls::*;
const MAX_VIRTUAL_CONSOLES: usize = 8;

/// スクロールバックバッファサイズ（行数）
const SCROLLBACK_LINES: usize = 1000;

/// デフォルトの列数
const DEFAULT_COLS: usize = 80;

/// デフォルトの行数
const DEFAULT_ROWS: usize = 25;

/// タブ幅
const TAB_WIDTH: usize = 8;

// ============================================================================
// ANSI Colors
// ============================================================================

/// ANSIカラーコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnsiColor {
    Black = 0,
    Red = 1,
    Green = 2,
    Yellow = 3,
    Blue = 4,
    Magenta = 5,
    Cyan = 6,
    White = 7,
    BrightBlack = 8,
    BrightRed = 9,
    BrightGreen = 10,
    BrightYellow = 11,
    BrightBlue = 12,
    BrightMagenta = 13,
    BrightCyan = 14,
    BrightWhite = 15,
}

impl Default for AnsiColor {
    fn default() -> Self {
        AnsiColor::White
    }
}

impl AnsiColor {
    /// 32ビットRGBに変換
    pub fn to_rgb(&self) -> u32 {
        match self {
            AnsiColor::Black => 0x000000,
            AnsiColor::Red => 0xAA0000,
            AnsiColor::Green => 0x00AA00,
            AnsiColor::Yellow => 0xAAAA00,
            AnsiColor::Blue => 0x0000AA,
            AnsiColor::Magenta => 0xAA00AA,
            AnsiColor::Cyan => 0x00AAAA,
            AnsiColor::White => 0xAAAAAA,
            AnsiColor::BrightBlack => 0x555555,
            AnsiColor::BrightRed => 0xFF5555,
            AnsiColor::BrightGreen => 0x55FF55,
            AnsiColor::BrightYellow => 0xFFFF55,
            AnsiColor::BrightBlue => 0x5555FF,
            AnsiColor::BrightMagenta => 0xFF55FF,
            AnsiColor::BrightCyan => 0x55FFFF,
            AnsiColor::BrightWhite => 0xFFFFFF,
        }
    }

    /// SGRコードから変換
    pub fn from_sgr(code: u8, bright: bool) -> Option<Self> {
        let base = match code {
            0 | 30 | 40 => AnsiColor::Black,
            1 | 31 | 41 => AnsiColor::Red,
            2 | 32 | 42 => AnsiColor::Green,
            3 | 33 | 43 => AnsiColor::Yellow,
            4 | 34 | 44 => AnsiColor::Blue,
            5 | 35 | 45 => AnsiColor::Magenta,
            6 | 36 | 46 => AnsiColor::Cyan,
            7 | 37 | 47 => AnsiColor::White,
            _ => return None,
        };

        if bright {
            Some(match base {
                AnsiColor::Black => AnsiColor::BrightBlack,
                AnsiColor::Red => AnsiColor::BrightRed,
                AnsiColor::Green => AnsiColor::BrightGreen,
                AnsiColor::Yellow => AnsiColor::BrightYellow,
                AnsiColor::Blue => AnsiColor::BrightBlue,
                AnsiColor::Magenta => AnsiColor::BrightMagenta,
                AnsiColor::Cyan => AnsiColor::BrightCyan,
                AnsiColor::White => AnsiColor::BrightWhite,
                _ => base,
            })
        } else {
            Some(base)
        }
    }
}

// ============================================================================
// Character Cell
// ============================================================================

/// 文字属性
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CharAttributes {
    pub fg_color: AnsiColor,
    pub bg_color: AnsiColor,
    pub bold: bool,
    pub underline: bool,
    pub blink: bool,
    pub inverse: bool,
}

impl CharAttributes {
    pub fn new() -> Self {
        Self {
            fg_color: AnsiColor::White,
            bg_color: AnsiColor::Black,
            ..Default::default()
        }
    }

    /// 反転を適用
    pub fn effective_colors(&self) -> (AnsiColor, AnsiColor) {
        if self.inverse {
            (self.bg_color, self.fg_color)
        } else {
            (self.fg_color, self.bg_color)
        }
    }
}

/// 文字セル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharCell {
    pub ch: char,
    pub attr: CharAttributes,
}

impl Default for CharCell {
    fn default() -> Self {
        Self {
            ch: ' ',
            attr: CharAttributes::new(),
        }
    }
}

// ============================================================================
// Terminal Buffer
// ============================================================================

/// ターミナルバッファ（スクロールバック付き）
pub struct TerminalBuffer {
    /// 現在の画面バッファ
    screen: Vec<CharCell>,
    /// スクロールバック
    scrollback: VecDeque<Vec<CharCell>>,
    /// 列数
    cols: usize,
    /// 行数
    rows: usize,
    /// カーソルX位置
    cursor_x: usize,
    /// カーソルY位置
    cursor_y: usize,
    /// スクロールバック表示オフセット
    scroll_offset: usize,
    /// 現在の属性
    current_attr: CharAttributes,
    /// カーソルの可視状態
    cursor_visible: bool,
}

impl TerminalBuffer {
    pub fn new(cols: usize, rows: usize) -> Self {
        Self {
            screen: vec![CharCell::default(); cols * rows],
            scrollback: VecDeque::with_capacity(SCROLLBACK_LINES),
            cols,
            rows,
            cursor_x: 0,
            cursor_y: 0,
            scroll_offset: 0,
            current_attr: CharAttributes::new(),
            cursor_visible: true,
        }
    }

    /// 次の行に進む（スクロールも含む）
    fn advance_to_next_line(&mut self) {
        self.cursor_x = 0;
        self.cursor_y += 1;
        if self.cursor_y >= self.rows {
            self.scroll_up();
            self.cursor_y = self.rows - 1;
        }
    }

    /// 通常の印字可能文字を書き込む
    fn write_printable_char(&mut self, ch: char) {
        if self.cursor_x >= self.cols {
            self.advance_to_next_line();
        }
        let idx = self.cursor_y * self.cols + self.cursor_x;
        if idx < self.screen.len() {
            self.screen[idx] = CharCell {
                ch,
                attr: self.current_attr,
            };
        }
        self.cursor_x += 1;
    }

    /// 文字を書き込む
    pub fn write_char(&mut self, ch: char) {
        match ch {
            '\n' => {
                self.advance_to_next_line();
            }
            '\r' => {
                self.cursor_x = 0;
            }
            '\t' => {
                let spaces = TAB_WIDTH - (self.cursor_x % TAB_WIDTH);
                for _ in 0..spaces {
                    self.write_char(' ');
                }
            }
            '\x08' => {
                // Backspace
                if self.cursor_x > 0 {
                    self.cursor_x -= 1;
                }
            }
            '\x07' => { // Bell
                 // ビープ音を鳴らす（実装依存）
            }
            _ => {
                self.write_printable_char(ch);
            }
        }

        // Reset scroll on input
        if self.scroll_offset > 0 {
            self.scroll_offset = 0;
        }
    }

    /// 文字列を書き込む
    pub fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            self.write_char(ch);
        }
    }

    /// 画面を上にスクロール
    fn scroll_up(&mut self) {
        // 最上行をスクロールバックに保存
        let top_line: Vec<CharCell> = self.screen[..self.cols].to_vec();
        self.scrollback.push_back(top_line);

        if self.scrollback.len() > SCROLLBACK_LINES {
            self.scrollback.pop_front();
        }

        // 行を上にシフト
        for y in 0..self.rows - 1 {
            let src_start = (y + 1) * self.cols;
            let _src_end = src_start + self.cols;
            let dst_start = y * self.cols;

            for i in 0..self.cols {
                self.screen[dst_start + i] = self.screen[src_start + i];
            }
        }

        // 最下行をクリア
        let last_row_start = (self.rows - 1) * self.cols;
        for i in 0..self.cols {
            self.screen[last_row_start + i] = CharCell::default();
        }
    }

    /// 画面をクリア
    pub fn clear(&mut self) {
        for cell in &mut self.screen {
            *cell = CharCell::default();
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    /// カーソル位置を設定
    pub fn set_cursor(&mut self, x: usize, y: usize) {
        self.cursor_x = x.min(self.cols - 1);
        self.cursor_y = y.min(self.rows - 1);
    }

    /// カーソル位置を取得
    pub fn cursor(&self) -> (usize, usize) {
        (self.cursor_x, self.cursor_y)
    }

    /// セルを取得
    pub fn get_cell(&self, x: usize, y: usize) -> Option<&CharCell> {
        if x < self.cols && y < self.rows {
            Some(&self.screen[y * self.cols + x])
        } else {
            None
        }
    }

    /// 属性を設定
    pub fn set_attributes(&mut self, attr: CharAttributes) {
        self.current_attr = attr;
    }

    /// 列数を取得
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// 行数を取得
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// 行をクリア
    pub fn clear_line(&mut self, mode: ClearMode) {
        let y = self.cursor_y;
        match mode {
            ClearMode::ToEnd => {
                for x in self.cursor_x..self.cols {
                    self.screen[y * self.cols + x] = CharCell::default();
                }
            }
            ClearMode::ToBeginning => {
                for x in 0..=self.cursor_x {
                    self.screen[y * self.cols + x] = CharCell::default();
                }
            }
            ClearMode::All => {
                for x in 0..self.cols {
                    self.screen[y * self.cols + x] = CharCell::default();
                }
            }
        }
    }

    /// 画面をクリア
    pub fn clear_screen(&mut self, mode: ClearMode) {
        match mode {
            ClearMode::ToEnd => {
                // カーソル位置から画面末尾まで
                let start = self.cursor_y * self.cols + self.cursor_x;
                for i in start..self.screen.len() {
                    self.screen[i] = CharCell::default();
                }
            }
            ClearMode::ToBeginning => {
                // 画面先頭からカーソル位置まで
                let end = self.cursor_y * self.cols + self.cursor_x;
                for i in 0..=end {
                    self.screen[i] = CharCell::default();
                }
            }
            ClearMode::All => {
                self.clear();
            }
        }
    }
    /// バッファ全体をスライスとして取得
    pub fn chars(&self) -> &[CharCell] {
        &self.screen
    }

    /// 表示用のセルを取得（スクロールバック考慮）
    pub fn get_display_cell(&self, x: usize, y: usize) -> Option<CharCell> {
        if x >= self.cols || y >= self.rows {
            return None;
        }

        if self.scroll_offset == 0 {
            return Some(self.screen[y * self.cols + x]);
        }

        // history index: 0 is oldest
        let history_len = self.scrollback.len();
        // The line index `y` relative to the top of the viewing window
        // Viewing window starts at: (Total Rows) - (Screen Rows) - scroll_offset
        // Total logical rows = history_len + self.rows

        let total_rows = history_len + self.rows;
        let view_start_row = total_rows.saturating_sub(self.rows + self.scroll_offset);
        let target_abs_row = view_start_row + y;

        if target_abs_row < history_len {
            // In history
            self.scrollback
                .get(target_abs_row)
                .and_then(|line| line.get(x).copied())
        } else {
            // In active screen
            let screen_y = target_abs_row - history_len;
            if screen_y < self.rows {
                Some(self.screen[screen_y * self.cols + x])
            } else {
                Some(CharCell::default())
            }
        }
    }

    /// 画面表示をスクロール
    /// delta > 0: View older lines (scroll Up)
    /// delta < 0: View newer lines (scroll Down)
    pub fn scroll_view(&mut self, delta: isize) {
        if delta > 0 {
            self.scroll_offset = (self.scroll_offset + delta as usize).min(self.scrollback.len());
        } else {
            self.scroll_offset = self.scroll_offset.saturating_sub((-delta) as usize);
        }
    }

    /// ビューをリセット（一番下へ）
    pub fn reset_view(&mut self) {
        self.scroll_offset = 0;
    }

    /// カーソル可視状態を設定
    pub fn set_cursor_visible(&mut self, visible: bool) {
        self.cursor_visible = visible;
    }

    /// カーソル可視状態を取得
    pub fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }
}

/// クリアモード
#[derive(Debug, Clone, Copy)]
pub enum ClearMode {
    ToEnd,
    ToBeginning,
    All,
}

// ============================================================================
// ANSI Escape Parser
// ============================================================================

/// パーサー状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {
    Normal,
    Escape,
    Csi,
    Osc,
}

/// ANSIエスケープシーケンスパーサー
pub struct AnsiParser {
    state: ParserState,
    params: Vec<u32>,
    current_param: u32,
    current_param_has_digits: bool,
    csi_trailing_separator: bool,
    private_marker: Option<u8>,
    intermediate: Vec<u8>,
    osc_escape_pending: bool,
}

impl AnsiParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::Normal,
            params: Vec::new(),
            current_param: 0,
            current_param_has_digits: false,
            csi_trailing_separator: false,
            private_marker: None,
            intermediate: Vec::new(),
            osc_escape_pending: false,
        }
    }

    /// 文字を処理
    pub fn feed(&mut self, ch: char) -> Option<AnsiAction> {
        match self.state {
            ParserState::Normal => {
                if ch == '\x1b' {
                    self.state = ParserState::Escape;
                    None
                } else {
                    Some(AnsiAction::Print(ch))
                }
            }
            ParserState::Escape => match ch {
                '[' => {
                    self.state = ParserState::Csi;
                    self.params.clear();
                    self.current_param = 0;
                    self.current_param_has_digits = false;
                    self.csi_trailing_separator = false;
                    self.private_marker = None;
                    self.intermediate.clear();
                    None
                }
                ']' => {
                    self.state = ParserState::Osc;
                    self.osc_escape_pending = false;
                    None
                }
                'c' => {
                    self.state = ParserState::Normal;
                    Some(AnsiAction::Reset)
                }
                _ => {
                    self.state = ParserState::Normal;
                    None
                }
            },
            ParserState::Csi => self.parse_csi(ch),
            ParserState::Osc => {
                // OSCシーケンス（タイトル設定など）
                if self.osc_escape_pending {
                    self.osc_escape_pending = false;
                    if ch == '\\' {
                        self.state = ParserState::Normal;
                    }
                    return None;
                }
                if ch == '\x07' {
                    self.state = ParserState::Normal;
                } else if ch == '\x1b' {
                    // ST (ESC \) の2文字終端を扱う
                    self.osc_escape_pending = true;
                }
                None
            }
        }
    }

    fn parse_csi(&mut self, ch: char) -> Option<AnsiAction> {
        match ch {
            '0'..='9' => {
                self.current_param = self.current_param * 10 + (ch as u32 - '0' as u32);
                self.current_param_has_digits = true;
                self.csi_trailing_separator = false;
                None
            }
            ';' => {
                self.params.push(if self.current_param_has_digits {
                    self.current_param
                } else {
                    0
                });
                self.current_param = 0;
                self.current_param_has_digits = false;
                self.csi_trailing_separator = true;
                None
            }
            '?' | '<' | '=' | '>' => {
                if self.params.is_empty()
                    && !self.current_param_has_digits
                    && self.intermediate.is_empty()
                    && self.private_marker.is_none()
                {
                    self.private_marker = Some(ch as u8);
                    None
                } else {
                    self.state = ParserState::Normal;
                    None
                }
            }
            ' '..='/' => {
                self.intermediate.push(ch as u8);
                None
            }
            '\u{40}'..='\u{7E}' => {
                if self.current_param_has_digits || self.csi_trailing_separator {
                    self.params.push(self.current_param);
                }
                self.state = ParserState::Normal;
                self.dispatch_csi(ch)
            }
            _ => {
                self.state = ParserState::Normal;
                None
            }
        }
    }

    fn dispatch_csi(&self, final_char: char) -> Option<AnsiAction> {
        let params = &self.params;
        let get = |i: usize, default: u32| params.get(i).copied().unwrap_or(default);
        let get_nonzero = |i: usize, default: u32| {
            let val = get(i, default);
            if val == 0 {
                default
            } else {
                val
            }
        };

        match final_char {
            'A' => Some(AnsiAction::CursorUp(get_nonzero(0, 1) as usize)),
            'B' => Some(AnsiAction::CursorDown(get_nonzero(0, 1) as usize)),
            'C' => Some(AnsiAction::CursorForward(get_nonzero(0, 1) as usize)),
            'D' => Some(AnsiAction::CursorBack(get_nonzero(0, 1) as usize)),
            'H' | 'f' => Some(AnsiAction::SetCursor {
                row: get_nonzero(0, 1).saturating_sub(1) as usize,
                col: get_nonzero(1, 1).saturating_sub(1) as usize,
            }),
            'J' => {
                let mode = match get(0, 0) {
                    0 => ClearMode::ToEnd,
                    1 => ClearMode::ToBeginning,
                    _ => ClearMode::All,
                };
                Some(AnsiAction::ClearScreen(mode))
            }
            'K' => {
                let mode = match get(0, 0) {
                    0 => ClearMode::ToEnd,
                    1 => ClearMode::ToBeginning,
                    _ => ClearMode::All,
                };
                Some(AnsiAction::ClearLine(mode))
            }
            'm' => {
                if params.is_empty() {
                    Some(AnsiAction::SetGraphics(vec![0]))
                } else {
                    Some(AnsiAction::SetGraphics(params.clone()))
                }
            }
            's' => Some(AnsiAction::SaveCursor),
            'u' => Some(AnsiAction::RestoreCursor),
            'n' => {
                if get(0, 0) == 6 {
                    Some(AnsiAction::ReportCursor)
                } else {
                    None
                }
            }
            'h' | 'l' => {
                if self.private_marker == Some(b'?') && get(0, 0) == 25 {
                    Some(AnsiAction::SetCursorVisible(final_char == 'h'))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// ANSIアクション
#[derive(Debug, Clone)]
pub enum AnsiAction {
    Print(char),
    CursorUp(usize),
    CursorDown(usize),
    CursorForward(usize),
    CursorBack(usize),
    SetCursor { row: usize, col: usize },
    ClearScreen(ClearMode),
    ClearLine(ClearMode),
    SetGraphics(Vec<u32>),
    SaveCursor,
    RestoreCursor,
    ReportCursor,
    SetCursorVisible(bool),
    Reset,
}

// ============================================================================
// Virtual Console
// ============================================================================

/// 仮想コンソール
pub struct VirtualConsole {
    /// コンソール番号
    pub id: u32,
    /// ターミナルバッファ
    buffer: TerminalBuffer,
    /// ANSIパーサー
    parser: AnsiParser,
    /// 保存されたカーソル位置
    saved_cursor: Option<(usize, usize)>,
    /// アクティブかどうか
    active: AtomicBool,
}
