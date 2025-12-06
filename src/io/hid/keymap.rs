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
    fn to_char_raw(&self, key: KeyCode, shift: bool, caps_lock: bool, alt_gr: bool) -> Option<char>;

    /// キーコードを文字に変換（制御コード処理込み）
    ///
    /// # Note
    /// 制御コード処理はここで共通化されているため、
    /// キーマップ実装者は`to_char_raw()`のみを実装すればよい。
    fn to_char(&self, key: KeyCode, modifiers: &Modifiers) -> Option<char> {
        // Ctrl+文字の制御文字変換（全キーマップ共通）
        // Ctrl+A = 0x01, Ctrl+B = 0x02, ... Ctrl+Z = 0x1A
        if modifiers.ctrl && !modifiers.shift && !modifiers.alt {
            return match key {
                KeyCode::A => Some('\x01'),
                KeyCode::B => Some('\x02'),
                KeyCode::C => Some('\x03'),  // ETX (Ctrl+C)
                KeyCode::D => Some('\x04'),  // EOT (Ctrl+D)
                KeyCode::E => Some('\x05'),
                KeyCode::F => Some('\x06'),
                KeyCode::G => Some('\x07'),  // BEL
                KeyCode::H => Some('\x08'),  // BS (Backspace)
                KeyCode::I => Some('\x09'),  // HT (Tab)
                KeyCode::J => Some('\x0A'),  // LF
                KeyCode::K => Some('\x0B'),
                KeyCode::L => Some('\x0C'),  // FF (Form Feed)
                KeyCode::M => Some('\x0D'),  // CR
                KeyCode::N => Some('\x0E'),
                KeyCode::O => Some('\x0F'),
                KeyCode::P => Some('\x10'),
                KeyCode::Q => Some('\x11'),
                KeyCode::R => Some('\x12'),
                KeyCode::S => Some('\x13'),
                KeyCode::T => Some('\x14'),
                KeyCode::U => Some('\x15'),
                KeyCode::V => Some('\x16'),
                KeyCode::W => Some('\x17'),
                KeyCode::X => Some('\x18'),
                KeyCode::Y => Some('\x19'),
                KeyCode::Z => Some('\x1A'),  // SUB (Ctrl+Z)
                KeyCode::LeftBracket => Some('\x1B'),  // ESC
                KeyCode::Backslash => Some('\x1C'),
                KeyCode::RightBracket => Some('\x1D'),
                _ => None,
            };
        }

        // 通常の文字変換はキーマップ実装に委譲
        self.to_char_raw(key, modifiers.shift, modifiers.caps_lock, modifiers.alt_gr)
    }

    /// レイアウト名を取得
    fn name(&self) -> &'static str;

    /// 簡易変換（後方互換性用）
    ///
    /// 新しいコードでは`to_char(key, modifiers)`を使用してください。
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

    fn to_char_raw(&self, key: KeyCode, shift: bool, caps_lock: bool, _alt_gr: bool) -> Option<char> {
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
// 将来の拡張用プレースホルダー
// ============================================================================

/// JIS配列キーマップ（未実装）
///
/// TODO: フェーズ4で実装予定
#[derive(Debug, Clone, Copy)]
pub struct JisKeymap;

impl Keymap for JisKeymap {
    fn name(&self) -> &'static str {
        "JIS (Japanese)"
    }

    fn to_char_raw(&self, key: KeyCode, shift: bool, caps_lock: bool, alt_gr: bool) -> Option<char> {
        // TODO: JIS配列の実装
        // 現時点ではUS配列にフォールバック
        UsQwertyKeymap.to_char_raw(key, shift, caps_lock, alt_gr)
    }
}

/// Dvorak配列キーマップ（未実装）
///
/// TODO: フェーズ4で実装予定
#[derive(Debug, Clone, Copy)]
pub struct DvorakKeymap;

impl Keymap for DvorakKeymap {
    fn name(&self) -> &'static str {
        "Dvorak"
    }

    fn to_char_raw(&self, key: KeyCode, shift: bool, caps_lock: bool, alt_gr: bool) -> Option<char> {
        // TODO: Dvorak配列の実装
        // 現時点ではUS配列にフォールバック
        UsQwertyKeymap.to_char_raw(key, shift, caps_lock, alt_gr)
    }
}

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
}
