// ============================================================================
// src/io/hid/ps2/keycode.rs - Keyboard Scancode and Events
// ============================================================================

/// キーコード（仮想キーコード）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCode(pub u8);

impl KeyCode {
    // 特殊キー
    pub const ESCAPE: Self = Self(0x01);
    pub const BACKSPACE: Self = Self(0x0E);
    pub const TAB: Self = Self(0x0F);
    pub const ENTER: Self = Self(0x1C);
    pub const LEFT_CTRL: Self = Self(0x1D);
    pub const LEFT_SHIFT: Self = Self(0x2A);
    pub const RIGHT_SHIFT: Self = Self(0x36);
    pub const LEFT_ALT: Self = Self(0x38);
    pub const SPACE: Self = Self(0x39);
    pub const CAPS_LOCK: Self = Self(0x3A);
    pub const F1: Self = Self(0x3B);
    pub const F2: Self = Self(0x3C);
    pub const F3: Self = Self(0x3D);
    pub const F4: Self = Self(0x3E);
    pub const F5: Self = Self(0x3F);
    pub const F6: Self = Self(0x40);
    pub const F7: Self = Self(0x41);
    pub const F8: Self = Self(0x42);
    pub const F9: Self = Self(0x43);
    pub const F10: Self = Self(0x44);
    pub const NUM_LOCK: Self = Self(0x45);
    pub const SCROLL_LOCK: Self = Self(0x46);
    pub const F11: Self = Self(0x57);
    pub const F12: Self = Self(0x58);

    // 拡張キー（E0プレフィックス）
    pub const INSERT: Self = Self(0x52);
    pub const DELETE: Self = Self(0x53);
    pub const HOME: Self = Self(0x47);
    pub const END: Self = Self(0x4F);
    pub const PAGE_UP: Self = Self(0x49);
    pub const PAGE_DOWN: Self = Self(0x51);
    pub const UP: Self = Self(0x48);
    pub const DOWN: Self = Self(0x50);
    pub const LEFT: Self = Self(0x4B);
    pub const RIGHT: Self = Self(0x4D);
    pub const RIGHT_CTRL: Self = Self(0x9D);
    pub const RIGHT_ALT: Self = Self(0xB8);
}

/// キーイベント
#[derive(Clone, Copy, Debug)]
pub struct KeyEvent {
    /// キーコード
    pub code: KeyCode,
    /// 押下（true）または解放（false）
    pub pressed: bool,
    /// 拡張キーか
    pub extended: bool,
}

/// 修飾キー状態
#[derive(Clone, Copy, Debug, Default)]
pub struct Modifiers {
    pub left_shift: bool,
    pub right_shift: bool,
    pub left_ctrl: bool,
    pub right_ctrl: bool,
    pub left_alt: bool,
    pub right_alt: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl Modifiers {
    pub fn shift(&self) -> bool {
        self.left_shift || self.right_shift
    }

    pub fn ctrl(&self) -> bool {
        self.left_ctrl || self.right_ctrl
    }

    pub fn alt(&self) -> bool {
        self.left_alt || self.right_alt
    }
}
