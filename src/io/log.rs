// ============================================================================
// src/io/log.rs - Minimal logging macros for I/O drivers
// ============================================================================
//! 
//! I/Oドライバ用の最小限のログマクロ。
//! 実際のログ出力は無効化されており、必要に応じて有効化可能。

#![allow(unused_macros)]

/// ダミーのinfo!マクロ（出力なし）
#[macro_export]
macro_rules! io_log_info {
    ($($arg:tt)*) => {
        // Disabled for now
        // $crate::println!("[INFO] {}", format_args!($($arg)*))
    };
}

/// ダミーのwarn!マクロ（出力なし）
#[macro_export]
macro_rules! io_log_warn {
    ($($arg:tt)*) => {
        // Disabled for now
        // $crate::println!("[WARN] {}", format_args!($($arg)*))
    };
}

/// ダミーのdebug!マクロ（出力なし）
#[macro_export]
macro_rules! io_log_debug {
    ($($arg:tt)*) => {
        // Disabled for now
    };
}

/// ダミーのerror!マクロ（出力なし）
#[macro_export]
macro_rules! io_log_error {
    ($($arg:tt)*) => {
        // Disabled for now
        // $crate::println!("[ERROR] {}", format_args!($($arg)*))
    };
}

/// ログモジュール (log::info! 形式のために)
pub mod log {
    /// Info log macro (no-op)
    #[macro_export]
    macro_rules! log_info {
        ($($arg:tt)*) => { };
    }

    /// Warn log macro (no-op)
    #[macro_export]
    macro_rules! log_warn {
        ($($arg:tt)*) => { };
    }

    /// Debug log macro (no-op)  
    #[macro_export]
    macro_rules! log_debug {
        ($($arg:tt)*) => { };
    }

    /// Error log macro (no-op)
    #[macro_export]
    macro_rules! log_error {
        ($($arg:tt)*) => { };
    }

    pub use log_info as info;
    pub use log_warn as warn;
    pub use log_debug as debug;
    pub use log_error as error;
}
