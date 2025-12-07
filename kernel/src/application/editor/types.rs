// ============================================================================
// src/application/editor/types.rs - Editor Types and Enums
// ============================================================================
//!
//! # Types - エディタ用の型定義とEnum

/// エディタの状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditorMode {
    /// 通常モード
    Normal,
    /// ファイルダイアログ（開く）
    OpenDialog,
    /// ファイルダイアログ（保存）
    SaveDialog,
}

/// ツールバーボタン
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolbarButton {
    New,
    Open,
    Save,
    SaveAs,
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
}

impl ToolbarButton {
    /// ボタンのラベルを取得
    pub fn label(&self) -> &'static str {
        match self {
            ToolbarButton::New => "New",
            ToolbarButton::Open => "Open",
            ToolbarButton::Save => "Save",
            ToolbarButton::SaveAs => "Save As",
            ToolbarButton::Undo => "Undo",
            ToolbarButton::Redo => "Redo",
            ToolbarButton::Cut => "Cut",
            ToolbarButton::Copy => "Copy",
            ToolbarButton::Paste => "Paste",
        }
    }

    /// すべてのボタンを返す
    pub fn all() -> &'static [ToolbarButton] {
        &[
            ToolbarButton::New,
            ToolbarButton::Open,
            ToolbarButton::Save,
            ToolbarButton::SaveAs,
            ToolbarButton::Undo,
            ToolbarButton::Redo,
            ToolbarButton::Cut,
            ToolbarButton::Copy,
            ToolbarButton::Paste,
        ]
    }
}

impl Default for EditorMode {
    fn default() -> Self {
        EditorMode::Normal
    }
}
