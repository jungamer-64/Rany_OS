// ============================================================================
// src/graphics/compositor/types.rs - Compositor Types
// ============================================================================

//! コンポジタで使用する基本型

// ============================================================================
// Window ID
// ============================================================================

/// コンポジタウィンドウID
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompositorWindowId(pub u32);

impl CompositorWindowId {
    pub const INVALID: Self = Self(0);
    pub const ROOT: Self = Self(u32::MAX);

    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn is_valid(&self) -> bool {
        self.0 != 0 && self.0 != u32::MAX
    }
}

// ============================================================================
// Z-Order
// ============================================================================

/// Z-Order（描画順序）
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZOrder(pub i32);

impl ZOrder {
    pub const BACKGROUND: Self = Self(-1000);
    pub const NORMAL: Self = Self(0);
    pub const ABOVE_NORMAL: Self = Self(100);
    pub const TOPMOST: Self = Self(1000);
    pub const SYSTEM: Self = Self(10000);
}

// ============================================================================
// Window Style
// ============================================================================

/// ウィンドウスタイル
#[derive(Clone, Copy, Debug)]
pub struct CompositorWindowStyle {
    /// 境界線を表示
    pub border: bool,
    /// タイトルバーを表示
    pub title_bar: bool,
    /// 閉じるボタン
    pub close_button: bool,
    /// 最小化ボタン
    pub minimize_button: bool,
    /// 最大化ボタン
    pub maximize_button: bool,
    /// リサイズ可能
    pub resizable: bool,
    /// 常に最前面
    pub topmost: bool,
    /// シャドウを表示
    pub shadow: bool,
    /// アクリル効果（背景ぼかし）
    pub acrylic: bool,
    /// 透明度
    pub opacity: u8,
}

impl Default for CompositorWindowStyle {
    fn default() -> Self {
        Self {
            border: true,
            title_bar: true,
            close_button: true,
            minimize_button: true,
            maximize_button: true,
            resizable: true,
            topmost: false,
            shadow: true,
            acrylic: false,
            opacity: 255,
        }
    }
}

impl CompositorWindowStyle {
    /// ボーダーレスウィンドウ
    pub fn borderless() -> Self {
        Self {
            border: false,
            title_bar: false,
            close_button: false,
            minimize_button: false,
            maximize_button: false,
            resizable: false,
            topmost: false,
            shadow: false,
            acrylic: false,
            opacity: 255,
        }
    }

    /// ダイアログスタイル
    pub fn dialog() -> Self {
        Self {
            border: true,
            title_bar: true,
            close_button: true,
            minimize_button: false,
            maximize_button: false,
            resizable: false,
            topmost: false,
            shadow: true,
            acrylic: false,
            opacity: 255,
        }
    }

    /// アクリルウィンドウ
    pub fn acrylic() -> Self {
        Self {
            border: true,
            title_bar: true,
            close_button: true,
            minimize_button: true,
            maximize_button: true,
            resizable: true,
            topmost: false,
            shadow: true,
            acrylic: true,
            opacity: 220,
        }
    }
}

// ============================================================================
// Window State
// ============================================================================

/// ウィンドウ状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositorWindowState {
    Normal,
    Minimized,
    Maximized,
    Hidden,
}






