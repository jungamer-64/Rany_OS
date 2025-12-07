// ============================================================================
// src/io/hid/keymap.rs - Keyboard Layout Abstraction
// フェーズ3: キーマップの分離と多言語対応基盤
// ============================================================================
//!
//! # キーマップ抽象化レイヤー
//!
//! キーコードから文字への変換ロジックを分離し、
//! 複数のキーボードレイアウト（US, JIS, Dvorakなど）をサポート可能にする。
//!
//! ## 設計原則
//! - **関心の分離**: ドライバ（スキャンコード処理）とキーマップ（文字変換）を分離
//! - **拡張性**: 新しいレイアウトはトレイト実装のみで追加可能
//! - **ゼロコスト抽象化**: static dispatchによる最適化

#![allow(dead_code)]

use super::KeyCode;

// ============================================================================
// 制御コード変換（Ctrl+文字）
// ============================================================================

/// Ctrl+文字の制御コード変換テーブル
///
/// キーマップ非依存の共通処理として分離。これにより：
/// - トレイトのデフォルト実装がシンプルに
/// - テスト容易性の向上
/// - 各キーマップで必要ならオーバーライド可能
///
/// # 制御コード対応表
///
/// | キー       | コード | 16進  | 用途                    |
/// |------------|--------|-------|-------------------------|
/// | Ctrl+A..Z  | SOH..SUB | 0x01..0x1A | 各種制御         |
/// | Ctrl+C     | ETX    | 0x03  | SIGINT (割り込み)       |
/// | Ctrl+D     | EOT    | 0x04  | EOF (入力終了)          |
/// | Ctrl+H     | BS     | 0x08  | Backspace               |
/// | Ctrl+I     | HT     | 0x09  | Tab                     |
/// | Ctrl+L     | FF     | 0x0C  | 画面クリア              |
/// | Ctrl+Q     | DC1    | 0x11  | XON (出力再開)          |
/// | Ctrl+S     | DC3    | 0x13  | XOFF (出力停止)         |
/// | Ctrl+U     | NAK    | 0x15  | 行削除                  |
/// | Ctrl+W     | ETB    | 0x17  | 単語削除                |
/// | Ctrl+Z     | SUB    | 0x1A  | SIGTSTP (一時停止)      |
/// | Ctrl+[     | ESC    | 0x1B  | エスケープ              |
/// | Ctrl+\\    | FS     | 0x1C  | SIGQUIT (強制終了)      |
/// | Ctrl+]     | GS     | 0x1D  | -                       |
/// | Ctrl+6 (^) | RS     | 0x1E  | -                       |
/// | Ctrl+- (_) | US     | 0x1F  | -                       |
/// | Ctrl+/ (?) | DEL    | 0x7F  | 削除                    |
#[inline]
pub fn ctrl_char_map(key: KeyCode) -> Option<char> {
    Some(match key {
        // Ctrl+A..Z = 0x01..0x1A
        KeyCode::A => '\x01',
        KeyCode::B => '\x02',
        KeyCode::C => '\x03',  // ETX (Ctrl+C) - SIGINT
        KeyCode::D => '\x04',  // EOT (Ctrl+D) - EOF
        KeyCode::E => '\x05',
        KeyCode::F => '\x06',
        KeyCode::G => '\x07',  // BEL
        KeyCode::H => '\x08',  // BS (Backspace)
        KeyCode::I => '\x09',  // HT (Tab)
        KeyCode::J => '\x0A',  // LF
        KeyCode::K => '\x0B',
        KeyCode::L => '\x0C',  // FF (Form Feed) - 画面クリア
        KeyCode::M => '\x0D',  // CR
        KeyCode::N => '\x0E',
        KeyCode::O => '\x0F',
        KeyCode::P => '\x10',
        KeyCode::Q => '\x11',  // DC1 (XON)
        KeyCode::R => '\x12',
        KeyCode::S => '\x13',  // DC3 (XOFF)
        KeyCode::T => '\x14',
        KeyCode::U => '\x15',  // NAK - 行削除
        KeyCode::V => '\x16',
        KeyCode::W => '\x17',  // ETB - 単語削除
        KeyCode::X => '\x18',
        KeyCode::Y => '\x19',
        KeyCode::Z => '\x1A',  // SUB (Ctrl+Z) - SIGTSTP
        // 特殊制御コード
        KeyCode::LeftBracket => '\x1B',   // ESC (0x1B)
        KeyCode::Backslash => '\x1C',     // FS (0x1C) - SIGQUIT
        KeyCode::RightBracket => '\x1D',  // GS (0x1D)
        KeyCode::Key6 => '\x1E',          // RS (0x1E) - Ctrl+^ (Shift+6)
        KeyCode::Minus => '\x1F',         // US (0x1F) - Ctrl+_
        KeyCode::Slash => '\x7F',         // DEL (0x7F) - Ctrl+?
        _ => return None,
    })
}

// ============================================================================
// Keymap トレイト
// ============================================================================

// Modifiersをインポート
use super::keyboard::Modifiers;

/// キーボードレイアウトを表すトレイト
///
/// # 責務
/// - **純粋な文字変換のみ**: キーコード → Unicode文字
/// - **制御コード（Ctrl+C等）は含まない**: それは端末制御層の責務
///
/// # 実装例
/// ```ignore
/// struct JisKeymap;
///
/// impl Keymap for JisKeymap {
///     fn to_char_raw(&self, key: KeyCode, shift: bool, caps_lock: bool) -> Option<char> {
///         // JIS配列の文字変換ロジック（Ctrl等の処理なし）
///     }
/// }
/// ```
///
/// # 設計理由
/// `Modifiers`構造体ごと渡すことで、将来的に以下の対応が可能:
/// - AltGr（欧州圏レイアウトの第3レベル文字）
/// - NumLockの状態に依存するテンキー入力
///
/// # Note
/// Ctrl+文字の制御コード変換は`to_char()`のデフォルト実装で共通処理として提供。
/// 各キーマップ実装は`to_char_raw()`のみをオーバーライドすればよい。
pub trait Keymap: Send + Sync {
    /// キーコードを文字に変換（制御コード処理なし）
    ///
    /// キーマップ実装者はこのメソッドのみを実装する。
    /// Ctrl+文字などの制御コード処理は`to_char()`で共通化されている。
    ///
    /// # Arguments
    /// * `key` - 変換対象のキーコード
    /// * `modifiers` - 現在のモディファイア状態（Shift, CapsLock, AltGr等）
    ///
    /// # Note (API変更履歴)
    /// 以前は`(key, shift, caps_lock, alt_gr)`の4引数でしたが、
    /// 拡張性のため`Modifiers`構造体に統一されました。
    fn to_char_raw(&self, key: KeyCode, modifiers: &Modifiers) -> Option<char>;

    /// CapsLockとShiftの組み合わせを適用（共通ユーティリティ）
    ///
    /// ASCII文字の大文字/小文字変換に使用。
    /// ShiftとCapsLockのXORで大文字/小文字を決定。
    ///
    /// # Examples
    /// ```ignore
    /// // Shift=false, CapsLock=false → 小文字
    /// assert_eq!(Self::apply_case(false, false, 'a'), 'a');
    /// // Shift=true,  CapsLock=false → 大文字
    /// assert_eq!(Self::apply_case(true, false, 'a'), 'A');
    /// // Shift=false, CapsLock=true  → 大文字
    /// assert_eq!(Self::apply_case(false, true, 'a'), 'A');
    /// // Shift=true,  CapsLock=true  → 小文字（XOR）
    /// assert_eq!(Self::apply_case(true, true, 'a'), 'a');
    /// ```
    #[inline]
    fn apply_case(shift: bool, caps_lock: bool, ch: char) -> char
    where
        Self: Sized,
    {
        if shift ^ caps_lock {
            ch.to_ascii_uppercase()
        } else {
            ch
        }
    }

    /// キーコードを文字に変換（制御コード処理込み）
    ///
    /// # Note
    /// 制御コード処理はここで共通化されているため、
    /// キーマップ実装者は`to_char_raw()`のみを実装すればよい。
    ///
    /// Ctrl+文字の変換は`ctrl_char_map()`関数に分離されており、
    /// 必要に応じてオーバーライド可能。
    fn to_char(&self, key: KeyCode, modifiers: &Modifiers) -> Option<char> {
        // Ctrl+文字の制御文字変換（全キーマップ共通）
        // Ctrlのみが押されている場合に制御コードを返す
        if modifiers.ctrl && !modifiers.shift && !modifiers.alt {
            if let Some(ctrl_char) = ctrl_char_map(key) {
                return Some(ctrl_char);
            }
        }

        // 通常の文字変換はキーマップ実装に委譲
        self.to_char_raw(key, modifiers)
    }

    /// レイアウト名を取得
    fn name(&self) -> &'static str;

    /// 簡易変換（後方互換性用）
    ///
    /// 新しいコードでは`to_char(key, modifiers)`を使用してください。
    #[deprecated(
        since = "0.2.0",
        note = "Use to_char(key, &Modifiers { shift, caps_lock, ..Default::default() }) instead"
    )]
    fn to_char_simple(&self, key: KeyCode, shift: bool, caps_lock: bool) -> Option<char> {
        let modifiers = Modifiers {
            shift,
            caps_lock,
            ..Default::default()
        };
        self.to_char(key, &modifiers)
    }
}

// ============================================================================
// US QWERTY キーマップ
// ============================================================================

/// US QWERTY配列キーマップ
///
/// 標準的なUS配列。デフォルトのキーマップとして使用される。
#[derive(Debug, Clone, Copy, Default)]
pub struct UsQwertyKeymap;

impl Keymap for UsQwertyKeymap {
    fn name(&self) -> &'static str {
        "US QWERTY"
    }

    fn to_char_raw(&self, key: KeyCode, modifiers: &Modifiers) -> Option<char> {
        let shift = modifiers.shift;
        let caps_lock = modifiers.caps_lock;
        // AltGr: USキーマップでは使用しない（将来の拡張用）
        // let _alt_gr = modifiers.alt_gr;

        // 数字キー（Shiftで記号）
        let ch = match key {
            KeyCode::Key1 => return Some(if shift { '!' } else { '1' }),
            KeyCode::Key2 => return Some(if shift { '@' } else { '2' }),
            KeyCode::Key3 => return Some(if shift { '#' } else { '3' }),
            KeyCode::Key4 => return Some(if shift { '$' } else { '4' }),
            KeyCode::Key5 => return Some(if shift { '%' } else { '5' }),
            KeyCode::Key6 => return Some(if shift { '^' } else { '6' }),
            KeyCode::Key7 => return Some(if shift { '&' } else { '7' }),
            KeyCode::Key8 => return Some(if shift { '*' } else { '8' }),
            KeyCode::Key9 => return Some(if shift { '(' } else { '9' }),
            KeyCode::Key0 => return Some(if shift { ')' } else { '0' }),

            // 記号キー
            KeyCode::Minus => return Some(if shift { '_' } else { '-' }),
            KeyCode::Equals => return Some(if shift { '+' } else { '=' }),
            KeyCode::LeftBracket => return Some(if shift { '{' } else { '[' }),
            KeyCode::RightBracket => return Some(if shift { '}' } else { ']' }),
            KeyCode::Semicolon => return Some(if shift { ':' } else { ';' }),
            KeyCode::Quote => return Some(if shift { '"' } else { '\'' }),
            KeyCode::BackTick => return Some(if shift { '~' } else { '`' }),
            KeyCode::Backslash => return Some(if shift { '|' } else { '\\' }),
            KeyCode::Comma => return Some(if shift { '<' } else { ',' }),
            KeyCode::Period => return Some(if shift { '>' } else { '.' }),
            KeyCode::Slash => return Some(if shift { '?' } else { '/' }),

            // 特殊キー
            KeyCode::Space => return Some(' '),
            KeyCode::Enter => return Some('\n'),
            KeyCode::Tab => return Some('\t'),
            KeyCode::Backspace => return Some('\x08'),

            // 文字キー（CapsLockとShiftの組み合わせで大文字/小文字）
            KeyCode::A => 'a',
            KeyCode::B => 'b',
            KeyCode::C => 'c',
            KeyCode::D => 'd',
            KeyCode::E => 'e',
            KeyCode::F => 'f',
            KeyCode::G => 'g',
            KeyCode::H => 'h',
            KeyCode::I => 'i',
            KeyCode::J => 'j',
            KeyCode::K => 'k',
            KeyCode::L => 'l',
            KeyCode::M => 'm',
            KeyCode::N => 'n',
            KeyCode::O => 'o',
            KeyCode::P => 'p',
            KeyCode::Q => 'q',
            KeyCode::R => 'r',
            KeyCode::S => 's',
            KeyCode::T => 't',
            KeyCode::U => 'u',
            KeyCode::V => 'v',
            KeyCode::W => 'w',
            KeyCode::X => 'x',
            KeyCode::Y => 'y',
            KeyCode::Z => 'z',

            // テンキー
            // NumLockの状態に関係なく常に数字/記号を返す
            // NumLockオフ時のナビゲーション機能はKeyCode自体が異なる
            KeyCode::NumPad0 => return Some('0'),
            KeyCode::NumPad1 => return Some('1'),
            KeyCode::NumPad2 => return Some('2'),
            KeyCode::NumPad3 => return Some('3'),
            KeyCode::NumPad4 => return Some('4'),
            KeyCode::NumPad5 => return Some('5'),
            KeyCode::NumPad6 => return Some('6'),
            KeyCode::NumPad7 => return Some('7'),
            KeyCode::NumPad8 => return Some('8'),
            KeyCode::NumPad9 => return Some('9'),
            KeyCode::NumPadDecimal => return Some('.'),
            KeyCode::NumPadEnter => return Some('\n'),
            KeyCode::NumPadPlus => return Some('+'),
            KeyCode::NumPadMinus => return Some('-'),
            KeyCode::NumPadMultiply => return Some('*'),
            KeyCode::NumPadDivide => return Some('/'),

            // その他のキーは文字に変換不可
            _ => return None,
        };

        // 文字キーの大文字/小文字変換
        // XOR: Shift と CapsLock の一方だけが有効なら大文字
        Some(if shift ^ caps_lock {
            ch.to_ascii_uppercase()
        } else {
            ch
        })
    }
}

// ============================================================================
// JIS配列キーマップ
// ============================================================================

/// JIS配列キーマップ
///
/// 日本語JIS配列（106/109キー）の実装。
/// USキーボードとの主な違い:
/// - 記号キーの配置が異なる
/// - `@`は`2`ではなくShift+2で`"`
/// - `^`は`6`ではなく独立キー
/// - `]`と`[`の位置が異なる
/// - `¥`キーと`_`キーが追加
///
/// # Note
/// この実装はPS/2スキャンコードSet 1に基づいています。
/// 実際のJISキーボードはUSキーボードとスキャンコードが異なる場合があります。
#[derive(Debug, Clone, Copy, Default)]
pub struct JisKeymap;

impl Keymap for JisKeymap {
    fn name(&self) -> &'static str {
        "JIS (Japanese)"
    }

    fn to_char_raw(&self, key: KeyCode, modifiers: &Modifiers) -> Option<char> {
        let shift = modifiers.shift;
        let caps_lock = modifiers.caps_lock;
        // AltGr: JISキーマップでは使用しない
        // let _alt_gr = modifiers.alt_gr;

        // JIS配列での記号キー配置
        // ほとんどのキーはUS配列と同じだが、一部の記号が異なる
        match key {
            // 数字キー上段の記号（JIS配列）
            KeyCode::Key1 => Some(if shift { '!' } else { '1' }),
            KeyCode::Key2 => Some(if shift { '"' } else { '2' }),  // USは@
            KeyCode::Key3 => Some(if shift { '#' } else { '3' }),
            KeyCode::Key4 => Some(if shift { '$' } else { '4' }),
            KeyCode::Key5 => Some(if shift { '%' } else { '5' }),
            KeyCode::Key6 => Some(if shift { '&' } else { '6' }),  // USは^
            KeyCode::Key7 => Some(if shift { '\'' } else { '7' }), // USは&
            KeyCode::Key8 => Some(if shift { '(' } else { '8' }),  // USは*
            KeyCode::Key9 => Some(if shift { ')' } else { '9' }),
            KeyCode::Key0 => Some(if shift { '~' } else { '0' }),  // USは)と0、JISは~と0

            // JIS特有のキー配置
            KeyCode::Minus => Some(if shift { '=' } else { '-' }),
            KeyCode::Equals => Some(if shift { '+' } else { '^' }),  // USの=位置にJISは^
            KeyCode::LeftBracket => Some(if shift { '{' } else { '@' }),  // USの[位置にJISは@
            KeyCode::RightBracket => Some(if shift { '}' } else { '[' }), // USの]位置にJISは[
            KeyCode::Backslash => Some(if shift { '|' } else { ']' }),    // USの\位置にJISは]
            KeyCode::Semicolon => Some(if shift { '+' } else { ';' }),
            KeyCode::Quote => Some(if shift { '*' } else { ':' }),   // USの'位置にJISは:
            KeyCode::BackTick => Some(if shift { '~' } else { '`' }),     // 半角/全角キーの代替

            // アルファベット（US配列と同じ）
            // トレイトの共通apply_case()を使用
            KeyCode::A => Some(Self::apply_case(shift, caps_lock, 'a')),
            KeyCode::B => Some(Self::apply_case(shift, caps_lock, 'b')),
            KeyCode::C => Some(Self::apply_case(shift, caps_lock, 'c')),
            KeyCode::D => Some(Self::apply_case(shift, caps_lock, 'd')),
            KeyCode::E => Some(Self::apply_case(shift, caps_lock, 'e')),
            KeyCode::F => Some(Self::apply_case(shift, caps_lock, 'f')),
            KeyCode::G => Some(Self::apply_case(shift, caps_lock, 'g')),
            KeyCode::H => Some(Self::apply_case(shift, caps_lock, 'h')),
            KeyCode::I => Some(Self::apply_case(shift, caps_lock, 'i')),
            KeyCode::J => Some(Self::apply_case(shift, caps_lock, 'j')),
            KeyCode::K => Some(Self::apply_case(shift, caps_lock, 'k')),
            KeyCode::L => Some(Self::apply_case(shift, caps_lock, 'l')),
            KeyCode::M => Some(Self::apply_case(shift, caps_lock, 'm')),
            KeyCode::N => Some(Self::apply_case(shift, caps_lock, 'n')),
            KeyCode::O => Some(Self::apply_case(shift, caps_lock, 'o')),
            KeyCode::P => Some(Self::apply_case(shift, caps_lock, 'p')),
            KeyCode::Q => Some(Self::apply_case(shift, caps_lock, 'q')),
            KeyCode::R => Some(Self::apply_case(shift, caps_lock, 'r')),
            KeyCode::S => Some(Self::apply_case(shift, caps_lock, 's')),
            KeyCode::T => Some(Self::apply_case(shift, caps_lock, 't')),
            KeyCode::U => Some(Self::apply_case(shift, caps_lock, 'u')),
            KeyCode::V => Some(Self::apply_case(shift, caps_lock, 'v')),
            KeyCode::W => Some(Self::apply_case(shift, caps_lock, 'w')),
            KeyCode::X => Some(Self::apply_case(shift, caps_lock, 'x')),
            KeyCode::Y => Some(Self::apply_case(shift, caps_lock, 'y')),
            KeyCode::Z => Some(Self::apply_case(shift, caps_lock, 'z')),

            // その他（US配列と共通）
            KeyCode::Space => Some(' '),
            KeyCode::Enter => Some('\n'),
            KeyCode::Tab => Some('\t'),
            KeyCode::Backspace => Some('\x08'),
            KeyCode::Comma => Some(if shift { '<' } else { ',' }),
            KeyCode::Period => Some(if shift { '>' } else { '.' }),
            KeyCode::Slash => Some(if shift { '?' } else { '/' }),

            // テンキー
            KeyCode::NumPad0 => Some('0'),
            KeyCode::NumPad1 => Some('1'),
            KeyCode::NumPad2 => Some('2'),
            KeyCode::NumPad3 => Some('3'),
            KeyCode::NumPad4 => Some('4'),
            KeyCode::NumPad5 => Some('5'),
            KeyCode::NumPad6 => Some('6'),
            KeyCode::NumPad7 => Some('7'),
            KeyCode::NumPad8 => Some('8'),
            KeyCode::NumPad9 => Some('9'),
            KeyCode::NumPadDecimal => Some('.'),
            KeyCode::NumPadEnter => Some('\n'),
            KeyCode::NumPadPlus => Some('+'),
            KeyCode::NumPadMinus => Some('-'),
            KeyCode::NumPadMultiply => Some('*'),
            KeyCode::NumPadDivide => Some('/'),

            _ => None,
        }
    }
}

// JisKeymap: apply_case()はトレイトのデフォルト実装を使用するため、
// 個別のimplブロックは不要になりました。

// ============================================================================
// Dvorak配列キーマップ
// ============================================================================

/// Dvorak配列キーマップ
///
/// Dvorak Simplified Keyboardの実装。
/// タイピング効率を最適化した配列で、母音を左手ホームポジションに配置。
///
/// # QWERTY → Dvorak マッピング
/// ```text
/// QWERTY: qwertyuiop[]
/// Dvorak: ',.pyfgcrl/=
///
/// QWERTY: asdfghjkl;'
/// Dvorak: aoeuidhtns-
///
/// QWERTY: zxcvbnm,./
/// Dvorak: ;qjkxbmwvz
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct DvorakKeymap;

impl Keymap for DvorakKeymap {
    fn name(&self) -> &'static str {
        "Dvorak"
    }

    fn to_char_raw(&self, key: KeyCode, modifiers: &Modifiers) -> Option<char> {
        let shift = modifiers.shift;
        let caps_lock = modifiers.caps_lock;
        // AltGr: Dvorakキーマップでは使用しない
        // let _alt_gr = modifiers.alt_gr;

        match key {
            // 数字キー上段（Dvorakでも通常は同じ）
            KeyCode::Key1 => Some(if shift { '!' } else { '1' }),
            KeyCode::Key2 => Some(if shift { '@' } else { '2' }),
            KeyCode::Key3 => Some(if shift { '#' } else { '3' }),
            KeyCode::Key4 => Some(if shift { '$' } else { '4' }),
            KeyCode::Key5 => Some(if shift { '%' } else { '5' }),
            KeyCode::Key6 => Some(if shift { '^' } else { '6' }),
            KeyCode::Key7 => Some(if shift { '&' } else { '7' }),
            KeyCode::Key8 => Some(if shift { '*' } else { '8' }),
            KeyCode::Key9 => Some(if shift { '(' } else { '9' }),
            KeyCode::Key0 => Some(if shift { ')' } else { '0' }),

            // 上段記号キー
            KeyCode::Minus => Some(if shift { '{' } else { '[' }),  // QWERTYの-位置
            KeyCode::Equals => Some(if shift { '}' } else { ']' }), // QWERTYの=位置

            // 上段アルファベット行（QWERTY QWERTYUIOP → Dvorak ',.PYFGCRL）
            // トレイトの共通apply_case()を使用
            KeyCode::Q => Some(if shift { '"' } else { '\'' }),   // ' "
            KeyCode::W => Some(if shift { '<' } else { ',' }),    // , <
            KeyCode::E => Some(if shift { '>' } else { '.' }),    // . >
            KeyCode::R => Some(Self::apply_case(shift, caps_lock, 'p')),
            KeyCode::T => Some(Self::apply_case(shift, caps_lock, 'y')),
            KeyCode::Y => Some(Self::apply_case(shift, caps_lock, 'f')),
            KeyCode::U => Some(Self::apply_case(shift, caps_lock, 'g')),
            KeyCode::I => Some(Self::apply_case(shift, caps_lock, 'c')),
            KeyCode::O => Some(Self::apply_case(shift, caps_lock, 'r')),
            KeyCode::P => Some(Self::apply_case(shift, caps_lock, 'l')),
            KeyCode::LeftBracket => Some(if shift { '?' } else { '/' }),   // / ?
            KeyCode::RightBracket => Some(if shift { '+' } else { '=' }), // = +

            // 中段アルファベット行（QWERTY ASDFGHJKL;' → Dvorak AOEUIDHTNS-）
            KeyCode::A => Some(Self::apply_case(shift, caps_lock, 'a')),
            KeyCode::S => Some(Self::apply_case(shift, caps_lock, 'o')),
            KeyCode::D => Some(Self::apply_case(shift, caps_lock, 'e')),
            KeyCode::F => Some(Self::apply_case(shift, caps_lock, 'u')),
            KeyCode::G => Some(Self::apply_case(shift, caps_lock, 'i')),
            KeyCode::H => Some(Self::apply_case(shift, caps_lock, 'd')),
            KeyCode::J => Some(Self::apply_case(shift, caps_lock, 'h')),
            KeyCode::K => Some(Self::apply_case(shift, caps_lock, 't')),
            KeyCode::L => Some(Self::apply_case(shift, caps_lock, 'n')),
            KeyCode::Semicolon => Some(Self::apply_case(shift, caps_lock, 's')),
            KeyCode::Quote => Some(if shift { '_' } else { '-' }),  // - _

            // 下段アルファベット行（QWERTY ZXCVBNM,./ → Dvorak ;QJKXBMWVZ）
            KeyCode::Z => Some(if shift { ':' } else { ';' }),    // ; :
            KeyCode::X => Some(Self::apply_case(shift, caps_lock, 'q')),
            KeyCode::C => Some(Self::apply_case(shift, caps_lock, 'j')),
            KeyCode::V => Some(Self::apply_case(shift, caps_lock, 'k')),
            KeyCode::B => Some(Self::apply_case(shift, caps_lock, 'x')),
            KeyCode::N => Some(Self::apply_case(shift, caps_lock, 'b')),
            KeyCode::M => Some(Self::apply_case(shift, caps_lock, 'm')),
            KeyCode::Comma => Some(Self::apply_case(shift, caps_lock, 'w')),
            KeyCode::Period => Some(Self::apply_case(shift, caps_lock, 'v')),
            KeyCode::Slash => Some(Self::apply_case(shift, caps_lock, 'z')),

            // バックスラッシュ/グレーブキー
            KeyCode::BackTick => Some(if shift { '~' } else { '`' }),
            KeyCode::Backslash => Some(if shift { '|' } else { '\\' }),

            // その他（共通）
            KeyCode::Space => Some(' '),
            KeyCode::Enter => Some('\n'),
            KeyCode::Tab => Some('\t'),
            KeyCode::Backspace => Some('\x08'),

            // テンキー
            KeyCode::NumPad0 => Some('0'),
            KeyCode::NumPad1 => Some('1'),
            KeyCode::NumPad2 => Some('2'),
            KeyCode::NumPad3 => Some('3'),
            KeyCode::NumPad4 => Some('4'),
            KeyCode::NumPad5 => Some('5'),
            KeyCode::NumPad6 => Some('6'),
            KeyCode::NumPad7 => Some('7'),
            KeyCode::NumPad8 => Some('8'),
            KeyCode::NumPad9 => Some('9'),
            KeyCode::NumPadDecimal => Some('.'),
            KeyCode::NumPadEnter => Some('\n'),
            KeyCode::NumPadPlus => Some('+'),
            KeyCode::NumPadMinus => Some('-'),
            KeyCode::NumPadMultiply => Some('*'),
            KeyCode::NumPadDivide => Some('/'),

            _ => None,
        }
    }
}

// DvorakKeymap: apply_case()はトレイトのデフォルト実装を使用するため、
// 個別のimplブロックは不要になりました。

// ============================================================================
// グローバルキーマップインスタンス
// ============================================================================

/// JISキーマップのグローバルインスタンス
pub static JIS_KEYMAP: JisKeymap = JisKeymap;

/// Dvorakキーマップのグローバルインスタンス
pub static DVORAK_KEYMAP: DvorakKeymap = DvorakKeymap;

// ============================================================================
// デフォルトキーマップ
// ============================================================================

/// グローバルデフォルトキーマップ
///
/// 静的ディスパッチのため、コンパイル時に決定される。
/// 動的なキーマップ切り替えが必要な場合は、`&dyn Keymap`を使用する。
pub static DEFAULT_KEYMAP: UsQwertyKeymap = UsQwertyKeymap;

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn mods(shift: bool, caps_lock: bool) -> Modifiers {
        Modifiers { shift, caps_lock, ..Default::default() }
    }

    fn mods_ctrl() -> Modifiers {
        Modifiers { ctrl: true, ..Default::default() }
    }

    #[test]
    fn test_us_qwerty_letters() {
        let keymap = UsQwertyKeymap;

        // 小文字
        assert_eq!(keymap.to_char(KeyCode::A, &mods(false, false)), Some('a'));
        assert_eq!(keymap.to_char(KeyCode::Z, &mods(false, false)), Some('z'));

        // Shift で大文字
        assert_eq!(keymap.to_char(KeyCode::A, &mods(true, false)), Some('A'));

        // CapsLock で大文字
        assert_eq!(keymap.to_char(KeyCode::A, &mods(false, true)), Some('A'));

        // Shift + CapsLock で小文字（XOR）
        assert_eq!(keymap.to_char(KeyCode::A, &mods(true, true)), Some('a'));
    }

    #[test]
    fn test_us_qwerty_numbers() {
        let keymap = UsQwertyKeymap;

        assert_eq!(keymap.to_char(KeyCode::Key1, &mods(false, false)), Some('1'));
        assert_eq!(keymap.to_char(KeyCode::Key1, &mods(true, false)), Some('!'));
        assert_eq!(keymap.to_char(KeyCode::Key2, &mods(true, false)), Some('@'));
    }

    #[test]
    fn test_us_qwerty_special() {
        let keymap = UsQwertyKeymap;

        assert_eq!(keymap.to_char(KeyCode::Space, &mods(false, false)), Some(' '));
        assert_eq!(keymap.to_char(KeyCode::Enter, &mods(false, false)), Some('\n'));
        assert_eq!(keymap.to_char(KeyCode::Tab, &mods(false, false)), Some('\t'));
    }

    #[test]
    fn test_non_printable_keys() {
        let keymap = UsQwertyKeymap;

        // ファンクションキーは文字に変換できない
        assert_eq!(keymap.to_char(KeyCode::F1, &mods(false, false)), None);
        assert_eq!(keymap.to_char(KeyCode::Escape, &mods(false, false)), None);
        assert_eq!(keymap.to_char(KeyCode::Up, &mods(false, false)), None);
    }

    #[test]
    fn test_ctrl_characters() {
        let keymap = UsQwertyKeymap;

        // Ctrl+C = ETX (0x03)
        assert_eq!(keymap.to_char(KeyCode::C, &mods_ctrl()), Some('\x03'));
        // Ctrl+D = EOT (0x04)
        assert_eq!(keymap.to_char(KeyCode::D, &mods_ctrl()), Some('\x04'));
        // Ctrl+Z = SUB (0x1A)
        assert_eq!(keymap.to_char(KeyCode::Z, &mods_ctrl()), Some('\x1A'));
    }

    // =========================================================================
    // JIS配列テスト (Phase 4)
    // =========================================================================

    #[test]
    fn test_jis_keymap_symbols() {
        let keymap = JisKeymap;

        // JIS: Shift+2 = " (USは@)
        assert_eq!(keymap.to_char(KeyCode::Key2, &mods(true, false)), Some('"'));

        // JIS: Shift+6 = & (USは^)
        assert_eq!(keymap.to_char(KeyCode::Key6, &mods(true, false)), Some('&'));

        // JIS: Shift+7 = ' (USは&)
        assert_eq!(keymap.to_char(KeyCode::Key7, &mods(true, false)), Some('\''));

        // JIS: [キー位置 = @ (USは[)
        assert_eq!(keymap.to_char(KeyCode::LeftBracket, &mods(false, false)), Some('@'));
        assert_eq!(keymap.to_char(KeyCode::LeftBracket, &mods(true, false)), Some('{'));
    }

    #[test]
    fn test_jis_keymap_letters() {
        let keymap = JisKeymap;

        // アルファベットはUSと同じ
        assert_eq!(keymap.to_char(KeyCode::A, &mods(false, false)), Some('a'));
        assert_eq!(keymap.to_char(KeyCode::A, &mods(true, false)), Some('A'));
        assert_eq!(keymap.to_char(KeyCode::Z, &mods(false, false)), Some('z'));
    }

    #[test]
    fn test_jis_keymap_ctrl() {
        let keymap = JisKeymap;

        // 制御文字は共通処理（全キーマップで同じ）
        assert_eq!(keymap.to_char(KeyCode::C, &mods_ctrl()), Some('\x03'));
        assert_eq!(keymap.to_char(KeyCode::D, &mods_ctrl()), Some('\x04'));
    }

    // =========================================================================
    // Dvorak配列テスト (Phase 4)
    // =========================================================================

    #[test]
    fn test_dvorak_keymap_home_row() {
        let keymap = DvorakKeymap;

        // Dvorak中段: AOEUIDHTNS (QWERTY: ASDFGHJKL;)
        assert_eq!(keymap.to_char(KeyCode::A, &mods(false, false)), Some('a'));
        assert_eq!(keymap.to_char(KeyCode::S, &mods(false, false)), Some('o'));
        assert_eq!(keymap.to_char(KeyCode::D, &mods(false, false)), Some('e'));
        assert_eq!(keymap.to_char(KeyCode::F, &mods(false, false)), Some('u'));
        assert_eq!(keymap.to_char(KeyCode::G, &mods(false, false)), Some('i'));
        assert_eq!(keymap.to_char(KeyCode::H, &mods(false, false)), Some('d'));
        assert_eq!(keymap.to_char(KeyCode::J, &mods(false, false)), Some('h'));
        assert_eq!(keymap.to_char(KeyCode::K, &mods(false, false)), Some('t'));
        assert_eq!(keymap.to_char(KeyCode::L, &mods(false, false)), Some('n'));
        assert_eq!(keymap.to_char(KeyCode::Semicolon, &mods(false, false)), Some('s'));
    }

    #[test]
    fn test_dvorak_keymap_top_row() {
        let keymap = DvorakKeymap;

        // Dvorak上段: ',.PYFGCRL (QWERTY: QWERTYUIOP)
        assert_eq!(keymap.to_char(KeyCode::Q, &mods(false, false)), Some('\''));
        assert_eq!(keymap.to_char(KeyCode::W, &mods(false, false)), Some(','));
        assert_eq!(keymap.to_char(KeyCode::E, &mods(false, false)), Some('.'));
        assert_eq!(keymap.to_char(KeyCode::R, &mods(false, false)), Some('p'));
        assert_eq!(keymap.to_char(KeyCode::T, &mods(false, false)), Some('y'));
        assert_eq!(keymap.to_char(KeyCode::Y, &mods(false, false)), Some('f'));
    }

    #[test]
    fn test_dvorak_keymap_bottom_row() {
        let keymap = DvorakKeymap;

        // Dvorak下段: ;QJKXBMWVZ (QWERTY: ZXCVBNM,./)
        assert_eq!(keymap.to_char(KeyCode::Z, &mods(false, false)), Some(';'));
        assert_eq!(keymap.to_char(KeyCode::X, &mods(false, false)), Some('q'));
        assert_eq!(keymap.to_char(KeyCode::C, &mods(false, false)), Some('j'));
        assert_eq!(keymap.to_char(KeyCode::Slash, &mods(false, false)), Some('z'));
    }

    #[test]
    fn test_dvorak_keymap_caps_lock() {
        let keymap = DvorakKeymap;

        // CapsLock動作確認
        assert_eq!(keymap.to_char(KeyCode::S, &mods(false, true)), Some('O'));  // CapsLock -> 大文字
        assert_eq!(keymap.to_char(KeyCode::S, &mods(true, true)), Some('o'));   // Shift+CapsLock -> 小文字
    }

    #[test]
    fn test_dvorak_keymap_ctrl() {
        let keymap = DvorakKeymap;

        // 制御文字は共通処理（Dvorakでも物理キー位置で判定）
        // 注: Dvorakでも物理的なCキー（QWERTY配置）でCtrl+C
        assert_eq!(keymap.to_char(KeyCode::C, &mods_ctrl()), Some('\x03'));
    }

    // =========================================================================
    // グローバルインスタンステスト
    // =========================================================================

    #[test]
    fn test_global_keymap_instances() {
        // グローバルインスタンスが正しく初期化されていることを確認
        assert_eq!(DEFAULT_KEYMAP.name(), "US QWERTY");
        assert_eq!(JIS_KEYMAP.name(), "JIS (Japanese)");
        assert_eq!(DVORAK_KEYMAP.name(), "Dvorak");
    }

    // =========================================================================
    // テンキーテスト
    // =========================================================================

    #[test]
    fn test_numpad_us_qwerty() {
        let keymap = UsQwertyKeymap;

        // テンキー数字
        assert_eq!(keymap.to_char(KeyCode::NumPad0, &mods(false, false)), Some('0'));
        assert_eq!(keymap.to_char(KeyCode::NumPad1, &mods(false, false)), Some('1'));
        assert_eq!(keymap.to_char(KeyCode::NumPad2, &mods(false, false)), Some('2'));
        assert_eq!(keymap.to_char(KeyCode::NumPad3, &mods(false, false)), Some('3'));
        assert_eq!(keymap.to_char(KeyCode::NumPad4, &mods(false, false)), Some('4'));
        assert_eq!(keymap.to_char(KeyCode::NumPad5, &mods(false, false)), Some('5'));
        assert_eq!(keymap.to_char(KeyCode::NumPad6, &mods(false, false)), Some('6'));
        assert_eq!(keymap.to_char(KeyCode::NumPad7, &mods(false, false)), Some('7'));
        assert_eq!(keymap.to_char(KeyCode::NumPad8, &mods(false, false)), Some('8'));
        assert_eq!(keymap.to_char(KeyCode::NumPad9, &mods(false, false)), Some('9'));

        // テンキー演算子
        assert_eq!(keymap.to_char(KeyCode::NumPadPlus, &mods(false, false)), Some('+'));
        assert_eq!(keymap.to_char(KeyCode::NumPadMinus, &mods(false, false)), Some('-'));
        assert_eq!(keymap.to_char(KeyCode::NumPadMultiply, &mods(false, false)), Some('*'));
        assert_eq!(keymap.to_char(KeyCode::NumPadDivide, &mods(false, false)), Some('/'));

        // テンキー特殊
        assert_eq!(keymap.to_char(KeyCode::NumPadDecimal, &mods(false, false)), Some('.'));
        assert_eq!(keymap.to_char(KeyCode::NumPadEnter, &mods(false, false)), Some('\n'));
    }

    #[test]
    fn test_numpad_jis() {
        let keymap = JisKeymap;

        // JISキーマップでもテンキーは同じ動作
        assert_eq!(keymap.to_char(KeyCode::NumPad0, &mods(false, false)), Some('0'));
        assert_eq!(keymap.to_char(KeyCode::NumPad5, &mods(false, false)), Some('5'));
        assert_eq!(keymap.to_char(KeyCode::NumPadPlus, &mods(false, false)), Some('+'));
        assert_eq!(keymap.to_char(KeyCode::NumPadEnter, &mods(false, false)), Some('\n'));
    }

    #[test]
    fn test_numpad_dvorak() {
        let keymap = DvorakKeymap;

        // Dvorakキーマップでもテンキーは同じ動作
        assert_eq!(keymap.to_char(KeyCode::NumPad0, &mods(false, false)), Some('0'));
        assert_eq!(keymap.to_char(KeyCode::NumPad5, &mods(false, false)), Some('5'));
        assert_eq!(keymap.to_char(KeyCode::NumPadMultiply, &mods(false, false)), Some('*'));
        assert_eq!(keymap.to_char(KeyCode::NumPadDivide, &mods(false, false)), Some('/'));
    }

    #[test]
    fn test_numpad_shift_ignored() {
        let keymap = UsQwertyKeymap;

        // テンキーはShiftの影響を受けない
        assert_eq!(keymap.to_char(KeyCode::NumPad0, &mods(true, false)), Some('0'));
        assert_eq!(keymap.to_char(KeyCode::NumPadPlus, &mods(true, false)), Some('+'));
    }
}
