// ============================================================================
// src/io/nvme/error.rs - NVMe Error Types
// ============================================================================
//!
//! # NVMeエラー型
//!
//! NVMeドライバで使用するエラー型の定義。

#![allow(dead_code)]

use super::commands::NvmeCompletion;

/// NVMeエラー型
#[derive(Debug, Clone)]
pub enum NvmeError {
    /// コマンドエラー
    CommandError(NvmeCompletion),
    /// キューが見つからない
    QueueNotFound,
    /// タイムアウト
    Timeout,
    /// キューがフル
    QueueFull,
    /// 未初期化
    NotInitialized,
    /// 無効なパラメータ
    InvalidParameter,
}

impl core::fmt::Display for NvmeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NvmeError::CommandError(cqe) => write!(
                f,
                "NVMe command error: SCT={}, SC={}",
                cqe.sct(),
                cqe.sc()
            ),
            NvmeError::QueueNotFound => write!(f, "NVMe queue not found"),
            NvmeError::Timeout => write!(f, "NVMe command timeout"),
            NvmeError::QueueFull => write!(f, "NVMe queue full"),
            NvmeError::NotInitialized => write!(f, "NVMe not initialized"),
            NvmeError::InvalidParameter => write!(f, "Invalid parameter"),
        }
    }
}
