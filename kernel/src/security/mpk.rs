// SPDX-License-Identifier: MIT
// ExoRust Kernel - Memory Protection Keys (MPK/PKEYs) Management
// 設計書 2.2: MPKによるドメイン分離, 設計書 8.3: 安全なコンテキストスイッチ
#![allow(dead_code)]

use crate::sync::{PoisonLock, PoisonLockGuard};
use core::sync::atomic::{AtomicBool, Ordering};

// ... (skipping constants and structures assumed present in the module)

/// グローバルMPKマネージャ
static MPK_MANAGER: PoisonLock<MpkManager> = PoisonLock::new(MpkManager::new());

/// MPKマネージャを取得
pub fn mpk_manager() -> PoisonLockGuard<'static, MpkManager> {
    MPK_MANAGER.lock().unwrap_or_else(|e| e.into_inner())
}

/// PKUが有効かどうかを確認
pub fn is_pku_enabled() -> bool {
    PKU_ENABLED.load(Ordering::Relaxed)
}

/// MPKサブシステムを初期化
pub fn init() {
    crate::io::log::early_print("[MPKDBG] init(): before lock\n");
    let mut manager = MPK_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    crate::io::log::early_print("[MPKDBG] init(): after lock\n");
    manager.init();
    crate::io::log::early_print("[MPKDBG] init(): after manager.init\n");
}

// ... (rest of the file remains unchanged)
