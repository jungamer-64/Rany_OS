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

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

// ============================================================================
// Configuration
// ============================================================================

/// 最大仮想コンソール数
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
#[derive(Debug, Clone, Copy, Default)]
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
#[derive(Debug, Clone, Copy)]
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
        }
    }

    /// 文字を書き込む
    pub fn write_char(&mut self, ch: char) {
        match ch {
            '\n' => {
                self.cursor_x = 0;
                self.cursor_y += 1;
                if self.cursor_y >= self.rows {
                    self.scroll_up();
                    self.cursor_y = self.rows - 1;
                }
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
                if self.cursor_x >= self.cols {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                    if self.cursor_y >= self.rows {
                        self.scroll_up();
                        self.cursor_y = self.rows - 1;
                    }
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
            let src_end = src_start + self.cols;
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
    intermediate: Vec<u8>,
}

impl AnsiParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::Normal,
            params: Vec::new(),
            current_param: 0,
            intermediate: Vec::new(),
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
                    self.intermediate.clear();
                    None
                }
                ']' => {
                    self.state = ParserState::Osc;
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
                if ch == '\x07' || ch == '\x1b' {
                    self.state = ParserState::Normal;
                }
                None
            }
        }
    }

    fn parse_csi(&mut self, ch: char) -> Option<AnsiAction> {
        match ch {
            '0'..='9' => {
                self.current_param = self.current_param * 10 + (ch as u32 - '0' as u32);
                None
            }
            ';' => {
                self.params.push(self.current_param);
                self.current_param = 0;
                None
            }
            ' '..='/' => {
                self.intermediate.push(ch as u8);
                None
            }
            _ => {
                self.params.push(self.current_param);
                self.state = ParserState::Normal;
                self.dispatch_csi(ch)
            }
        }
    }

    fn dispatch_csi(&self, final_char: char) -> Option<AnsiAction> {
        let params = &self.params;
        let get = |i: usize, default: u32| params.get(i).copied().unwrap_or(default);

        match final_char {
            'A' => Some(AnsiAction::CursorUp(get(0, 1) as usize)),
            'B' => Some(AnsiAction::CursorDown(get(0, 1) as usize)),
            'C' => Some(AnsiAction::CursorForward(get(0, 1) as usize)),
            'D' => Some(AnsiAction::CursorBack(get(0, 1) as usize)),
            'H' | 'f' => Some(AnsiAction::SetCursor {
                row: get(0, 1).saturating_sub(1) as usize,
                col: get(1, 1).saturating_sub(1) as usize,
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
            'm' => Some(AnsiAction::SetGraphics(params.clone())),
            's' => Some(AnsiAction::SaveCursor),
            'u' => Some(AnsiAction::RestoreCursor),
            'n' => {
                if get(0, 0) == 6 {
                    Some(AnsiAction::ReportCursor)
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

impl VirtualConsole {
    pub fn new(id: u32, cols: usize, rows: usize) -> Self {
        Self {
            id,
            buffer: TerminalBuffer::new(cols, rows),
            parser: AnsiParser::new(),
            saved_cursor: None,
            active: AtomicBool::new(false),
        }
    }

    /// 文字列を書き込む
    pub fn write(&mut self, s: &str) {
        for ch in s.chars() {
            if let Some(action) = self.parser.feed(ch) {
                self.execute_action(action);
            }
        }
    }

    /// ANSIアクションを実行
    fn execute_action(&mut self, action: AnsiAction) {
        match action {
            AnsiAction::Print(ch) => {
                self.buffer.write_char(ch);
            }
            AnsiAction::CursorUp(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x, y.saturating_sub(n));
            }
            AnsiAction::CursorDown(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x, y + n);
            }
            AnsiAction::CursorForward(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x + n, y);
            }
            AnsiAction::CursorBack(n) => {
                let (x, y) = self.buffer.cursor();
                self.buffer.set_cursor(x.saturating_sub(n), y);
            }
            AnsiAction::SetCursor { row, col } => {
                self.buffer.set_cursor(col, row);
            }
            AnsiAction::ClearScreen(mode) => {
                self.buffer.clear_screen(mode);
            }
            AnsiAction::ClearLine(mode) => {
                self.buffer.clear_line(mode);
            }
            AnsiAction::SetGraphics(params) => {
                self.apply_sgr(&params);
            }
            AnsiAction::SaveCursor => {
                self.saved_cursor = Some(self.buffer.cursor());
            }
            AnsiAction::RestoreCursor => {
                if let Some((x, y)) = self.saved_cursor {
                    self.buffer.set_cursor(x, y);
                }
            }
            AnsiAction::ReportCursor => {
                // カーソル位置レポート（エコーバック用）
            }
            AnsiAction::Reset => {
                self.buffer.clear();
                self.buffer.set_attributes(CharAttributes::new());
            }
        }
    }

    /// SGRパラメータを適用
    fn apply_sgr(&mut self, params: &[u32]) {
        let mut attr = self.buffer.current_attr;
        let mut i = 0;

        while i < params.len() {
            match params[i] {
                0 => attr = CharAttributes::new(),
                1 => attr.bold = true,
                4 => attr.underline = true,
                5 => attr.blink = true,
                7 => attr.inverse = true,
                22 => attr.bold = false,
                24 => attr.underline = false,
                25 => attr.blink = false,
                27 => attr.inverse = false,
                30..=37 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 30) as u8, attr.bold) {
                        attr.fg_color = c;
                    }
                }
                40..=47 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 40) as u8, false) {
                        attr.bg_color = c;
                    }
                }
                90..=97 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 90) as u8, true) {
                        attr.fg_color = c;
                    }
                }
                100..=107 => {
                    if let Some(c) = AnsiColor::from_sgr((params[i] - 100) as u8, true) {
                        attr.bg_color = c;
                    }
                }
                _ => {}
            }
            i += 1;
        }

        self.buffer.set_attributes(attr);
    }

    /// バッファを取得
    pub fn buffer(&self) -> &TerminalBuffer {
        &self.buffer
    }

    /// アクティブ状態を設定
    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Release);
    }

    /// アクティブかどうか
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

// ============================================================================
// Console Manager
// ============================================================================

/// コンソールマネージャー
pub struct ConsoleManager {
    /// 仮想コンソール
    consoles: Vec<Mutex<VirtualConsole>>,
    /// 現在アクティブなコンソール
    active: AtomicU32,
    /// 列数
    cols: usize,
    /// 行数
    rows: usize,
}

impl ConsoleManager {
    pub fn new(cols: usize, rows: usize) -> Self {
        let mut consoles = Vec::with_capacity(MAX_VIRTUAL_CONSOLES);
        for i in 0..MAX_VIRTUAL_CONSOLES {
            let vc = VirtualConsole::new(i as u32, cols, rows);
            consoles.push(Mutex::new(vc));
        }

        // 最初のコンソールをアクティブに
        consoles[0].lock().set_active(true);

        Self {
            consoles,
            active: AtomicU32::new(0),
            cols,
            rows,
        }
    }

    /// アクティブなコンソールに書き込む
    pub fn write(&self, s: &str) {
        let active = self.active.load(Ordering::Acquire) as usize;
        if let Some(console) = self.consoles.get(active) {
            console.lock().write(s);
        }
    }

    /// 指定コンソールに書き込む
    pub fn write_to(&self, console_id: u32, s: &str) {
        if let Some(console) = self.consoles.get(console_id as usize) {
            console.lock().write(s);
        }
    }

    /// コンソールを切り替え
    pub fn switch_to(&self, console_id: u32) {
        let id = console_id as usize;
        if id >= self.consoles.len() {
            return;
        }

        let old_active = self.active.swap(console_id, Ordering::AcqRel) as usize;

        if let Some(old) = self.consoles.get(old_active) {
            old.lock().set_active(false);
        }

        if let Some(new) = self.consoles.get(id) {
            new.lock().set_active(true);
        }
    }

    /// 現在のコンソールIDを取得
    pub fn active_console(&self) -> u32 {
        self.active.load(Ordering::Acquire)
    }

    /// コンソールにアクセス
    pub fn with_console<F, R>(&self, console_id: u32, f: F) -> Option<R>
    where
        F: FnOnce(&mut VirtualConsole) -> R,
    {
        self.consoles
            .get(console_id as usize)
            .map(|c| f(&mut c.lock()))
    }

    /// 次のコンソールに切り替え
    pub fn switch_next(&self) {
        let current = self.active.load(Ordering::Acquire);
        let next = (current + 1) % (self.consoles.len() as u32);
        self.switch_to(next);
    }

    /// 前のコンソールに切り替え
    pub fn switch_prev(&self) {
        let current = self.active.load(Ordering::Acquire);
        let prev = if current == 0 {
            (self.consoles.len() - 1) as u32
        } else {
            current - 1
        };
        self.switch_to(prev);
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static CONSOLE_MANAGER: Mutex<Option<ConsoleManager>> = Mutex::new(None);

/// コンソールシステムを初期化
pub fn init(cols: usize, rows: usize) {
    *CONSOLE_MANAGER.lock() = Some(ConsoleManager::new(cols, rows));
}

/// デフォルト設定で初期化
pub fn init_default() {
    init(DEFAULT_COLS, DEFAULT_ROWS);
}

/// コンソールに書き込む
pub fn write(s: &str) {
    if let Some(ref manager) = *CONSOLE_MANAGER.lock() {
        manager.write(s);
    }
}

/// コンソールマネージャーにアクセス
pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&ConsoleManager) -> R,
{
    CONSOLE_MANAGER.lock().as_ref().map(f)
}

/// コンソールを切り替え
pub fn switch(console_id: u32) {
    if let Some(ref manager) = *CONSOLE_MANAGER.lock() {
        manager.switch_to(console_id);
    }
}

// ============================================================================
// Print Macros
// ============================================================================

/// コンソールにフォーマット出力
#[macro_export]
macro_rules! console_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        use alloc::string::ToString;
        let s = alloc::format!($($arg)*);
        $crate::console::write(&s);
    }};
}

/// コンソールにフォーマット出力（改行付き）
#[macro_export]
macro_rules! console_println {
    () => {
        $crate::console::write("\n");
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        use alloc::string::ToString;
        let s = alloc::format!($($arg)*);
        $crate::console::write(&s);
        $crate::console::write("\n");
    }};
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ansi_color_rgb() {
        assert_eq!(AnsiColor::Black.to_rgb(), 0x000000);
        assert_eq!(AnsiColor::White.to_rgb(), 0xAAAAAA);
        assert_eq!(AnsiColor::BrightWhite.to_rgb(), 0xFFFFFF);
    }

    #[test]
    fn test_terminal_buffer() {
        let mut buffer = TerminalBuffer::new(80, 25);
        buffer.write_str("Hello, World!");
        assert_eq!(buffer.cursor(), (13, 0));

        buffer.write_char('\n');
        assert_eq!(buffer.cursor(), (0, 1));
    }

    #[test]
    fn test_ansi_parser() {
        let mut parser = AnsiParser::new();

        // 通常文字
        let action = parser.feed('A');
        assert!(matches!(action, Some(AnsiAction::Print('A'))));

        // エスケープシーケンス開始
        assert!(parser.feed('\x1b').is_none());
        assert!(parser.feed('[').is_none());

        // カーソル移動
        let action = parser.feed('H');
        assert!(matches!(
            action,
            Some(AnsiAction::SetCursor { row: 0, col: 0 })
        ));
    }

    #[test]
    fn test_virtual_console() {
        let mut vc = VirtualConsole::new(0, 80, 25);
        vc.write("Hello\n");
        assert_eq!(vc.buffer().cursor(), (0, 1));

        // ANSIカラー
        vc.write("\x1b[31mRed\x1b[0m");
    }
}
