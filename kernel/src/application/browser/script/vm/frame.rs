// ============================================================================
// src/application/browser/script/vm/frame.rs - Call Frame and Loop Info
// ============================================================================
//!
//! 呼び出しフレームとループ情報。

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::super::value::ScriptValue;

// ============================================================================
// Call Frame
// ============================================================================

/// 呼び出しフレーム
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// 戻りアドレス
    pub return_addr: usize,
    /// ローカル変数のベースポインタ
    pub base_pointer: usize,
    /// 関数名（デバッグ用）
    pub function_name: String,
    /// キャプチャされた変数（クロージャ用）
    pub captures: BTreeMap<String, ScriptValue>,
}

// ============================================================================
// Loop Info
// ============================================================================

/// ループ情報
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// ループの開始位置
    pub start: usize,
    /// ループの終了位置（break時のジャンプ先）
    pub end: usize,
}
