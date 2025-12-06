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

/// キーボードレイアウトを表すトレイト
///
/// # 実装例
/// ```ignore
/// struct JisKeymap;
///
/// impl Keymap for JisKeymap {
///     fn to_char(&self, key: KeyCode, shift: bool, caps_lock: bool) -> Option<char> {
///         // JIS配列の変換ロジック
///     }
/// }
/// ```
pub trait Keymap: Send + Sync {
    /// キーコードを文字に変換
    ///
    /// # Arguments
    /// * `key` - 変換するキーコード
    /// * `shift` - Shiftキーが押されているか
    /// * `caps_lock` - CapsLockが有効か
    ///
    /// # Returns
    /// 対応する文字、または変換不可能な場合は`None`
    fn to_char(&self, key: KeyCode, shift: bool, caps_lock: bool) -> Option<char>;

    /// レイアウト名を取得
    fn name(&self) -> &'static str;
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

    fn to_char(&self, key: KeyCode, shift: bool, caps_lock: bool) -> Option<char> {
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

    fn to_char(&self, key: KeyCode, shift: bool, caps_lock: bool) -> Option<char> {
        // TODO: JIS配列の実装
        // 現時点ではUS配列にフォールバック
        UsQwertyKeymap.to_char(key, shift, caps_lock)
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

    fn to_char(&self, key: KeyCode, shift: bool, caps_lock: bool) -> Option<char> {
        // TODO: Dvorak配列の実装
        // 現時点ではUS配列にフォールバック
        UsQwertyKeymap.to_char(key, shift, caps_lock)
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

    #[test]
    fn test_us_qwerty_letters() {
        let keymap = UsQwertyKeymap;

        // 小文字
        assert_eq!(keymap.to_char(KeyCode::A, false, false), Some('a'));
        assert_eq!(keymap.to_char(KeyCode::Z, false, false), Some('z'));

        // Shift で大文字
        assert_eq!(keymap.to_char(KeyCode::A, true, false), Some('A'));

        // CapsLock で大文字
        assert_eq!(keymap.to_char(KeyCode::A, false, true), Some('A'));

        // Shift + CapsLock で小文字（XOR）
        assert_eq!(keymap.to_char(KeyCode::A, true, true), Some('a'));
    }

    #[test]
    fn test_us_qwerty_numbers() {
        let keymap = UsQwertyKeymap;

        assert_eq!(keymap.to_char(KeyCode::Key1, false, false), Some('1'));
        assert_eq!(keymap.to_char(KeyCode::Key1, true, false), Some('!'));
        assert_eq!(keymap.to_char(KeyCode::Key2, true, false), Some('@'));
    }

    #[test]
    fn test_us_qwerty_special() {
        let keymap = UsQwertyKeymap;

        assert_eq!(keymap.to_char(KeyCode::Space, false, false), Some(' '));
        assert_eq!(keymap.to_char(KeyCode::Enter, false, false), Some('\n'));
        assert_eq!(keymap.to_char(KeyCode::Tab, false, false), Some('\t'));
    }

    #[test]
    fn test_non_printable_keys() {
        let keymap = UsQwertyKeymap;

        // ファンクションキーは文字に変換できない
        assert_eq!(keymap.to_char(KeyCode::F1, false, false), None);
        assert_eq!(keymap.to_char(KeyCode::Escape, false, false), None);
        assert_eq!(keymap.to_char(KeyCode::Up, false, false), None);
    }
}
