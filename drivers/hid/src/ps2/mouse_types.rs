// ============================================================================
// src/io/hid/ps2/mouse_types.rs - Mouse Types and Events
// ============================================================================

/// マウスボタン
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Button4,
    Button5,
}

/// マウスイベント
#[derive(Clone, Copy, Debug)]
pub struct MouseEvent {
    /// X移動量
    pub dx: i16,
    /// Y移動量
    pub dy: i16,
    /// ホイール移動量
    pub wheel: i8,
    /// ボタン状態
    pub buttons: u8,
}

impl MouseEvent {
    /// ボタンが押されているか
    pub fn is_pressed(&self, button: MouseButton) -> bool {
        let bit = match button {
            MouseButton::Left => 0,
            MouseButton::Right => 1,
            MouseButton::Middle => 2,
            MouseButton::Button4 => 3,
            MouseButton::Button5 => 4,
        };
        (self.buttons & (1 << bit)) != 0
    }
}
