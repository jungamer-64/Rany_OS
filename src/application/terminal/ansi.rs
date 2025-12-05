// ============================================================================
// src/application/terminal/ansi.rs - ANSI Escape Sequence Parser
// ============================================================================
//!
//! VT100/ANSIエスケープシーケンスパーサー

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// ParserState
// ============================================================================

/// パーサーの状態
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParserState {
    /// 通常テキスト
    Normal,
    /// ESC受信後
    Escape,
    /// CSI受信後 (ESC [)
    Csi,
    /// OSC受信後 (ESC ])
    Osc,
}

// ============================================================================
// ParseAction
// ============================================================================

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
// AnsiParser
// ============================================================================

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
