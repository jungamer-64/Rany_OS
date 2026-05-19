//! ブートログ永続化機能
//!
//! ブートログをUEFI変数に保存し、起動失敗時の診断に使用。
//! - ブート中ログのローテーションと保存

use crate::serial_println;
use alloc::string::String;
use core::fmt::Write;
use uefi::runtime::{self, VariableAttributes, VariableVendor};
use uefi::{CStr16, Guid, cstr16};

/// ブートログ専用GUID
/// {B6F9E4A1-5678-1234-ABCD-EF0123456789}
const BOOT_LOG_GUID: Guid = Guid::parse_or_panic("b6f9e4a1-5678-1234-abcd-ef0123456789");

/// ログ最大サイズ（UEFI変数サイズ制限を考慮）
pub const MAX_LOG_SIZE: usize = 8192;

/// 変数属性（Non-Volatile + Boot Service + Runtime Access）
const VAR_ATTRS: VariableAttributes = VariableAttributes::from_bits_truncate(
    VariableAttributes::NON_VOLATILE.bits()
        | VariableAttributes::BOOTSERVICE_ACCESS.bits()
        | VariableAttributes::RUNTIME_ACCESS.bits(),
);

/// UEFI変数名
const VAR_LOG_CURRENT: &CStr16 = cstr16!("ExoBootLog0");
const VAR_LOG_PREV1: &CStr16 = cstr16!("ExoBootLog1");
const VAR_LOG_PREV2: &CStr16 = cstr16!("ExoBootLog2");

/// カスタムVariableVendorを取得
fn get_vendor() -> &'static VariableVendor {
    static VENDOR: VariableVendor = VariableVendor(BOOT_LOG_GUID);
    &VENDOR
}

/// ブートログ記録用構造体
pub struct BootLogger {
    /// ログバッファ
    buffer: String,
    /// 最大サイズ
    max_size: usize,
    /// 初期化済みか
    initialized: bool,
}

impl BootLogger {
    /// 新しいロガーを作成
    pub const fn new() -> Self {
        Self {
            buffer: String::new(),
            max_size: MAX_LOG_SIZE,
            initialized: false,
        }
    }

    /// ロガーを初期化
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }

        // 前のログをローテーション
        rotate_logs();

        // バッファをクリア
        self.buffer.clear();

        // ヘッダを書き込み
        let _ = writeln!(self.buffer, "=== ExoRust Boot Log ===");
        let _ = writeln!(self.buffer, "Boot started");

        self.initialized = true;
        serial_println!("[BootLog] Logger initialized");
    }

    /// ログエントリを追加
    pub fn log(&mut self, message: &str) {
        if !self.initialized {
            return;
        }

        // サイズチェック
        let needed = message.len() + 1; // +1 for newline
        if self.buffer.len() + needed > self.max_size {
            // 古いエントリを削除して空きを作る
            self.truncate_old_entries(needed);
        }

        let _ = writeln!(self.buffer, "{}", message);
    }

    /// info レベルのログ
    pub fn info(&mut self, message: &str) {
        self.log(&alloc::format!("[INFO] {}", message));
    }

    /// warning レベルのログ
    pub fn warning(&mut self, message: &str) {
        self.log(&alloc::format!("[WARN] {}", message));
    }

    /// error レベルのログ
    pub fn error(&mut self, message: &str) {
        self.log(&alloc::format!("[ERROR] {}", message));
    }

    /// 古いエントリを削除してスペースを確保
    fn truncate_old_entries(&mut self, needed: usize) {
        // 先頭の行を削除していく
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.buffer.len() + needed > self.max_size {
            if let Some(pos) = self.buffer.find('\n') {
                self.buffer.drain(..=pos);
            } else {
                self.buffer.clear();
                break;
            }
        }
    }

    /// ログをUEFI変数に保存
    pub fn save(&self) {
        if !self.initialized || self.buffer.is_empty() {
            return;
        }

        let vendor = get_vendor();

        // 現在のログを保存
        match runtime::set_variable(VAR_LOG_CURRENT, vendor, VAR_ATTRS, self.buffer.as_bytes()) {
            Ok(_) => {
                serial_println!(
                    "[BootLog] Saved {} bytes to UEFI variable",
                    self.buffer.len()
                );
            }
            Err(_e) => {
                serial_println!("[BootLog] Failed to save log: {:?}", _e);
            }
        }
    }

    /// ログを保存して終了
    pub fn finalize(&mut self, success: bool) {
        if !self.initialized {
            return;
        }

        if success {
            let _ = writeln!(self.buffer, "[INFO] Boot sequence completed successfully");
        } else {
            let _ = writeln!(self.buffer, "[ERROR] Boot sequence failed");
        }
        let _ = writeln!(self.buffer, "=== End Boot Log ===");
    }
}

impl Write for BootLogger {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if self.initialized {
            // サイズチェック
            if self.buffer.len() + s.len() > self.max_size {
                self.truncate_old_entries(s.len());
            }
            self.buffer.push_str(s);
        }
        Ok(())
    }
}

/// ログをローテーション（現在→前回→前々回）
pub fn rotate_logs() {
    let vendor = get_vendor();

    // Log1 → Log2
    let mut buffer = [0u8; MAX_LOG_SIZE];
    if let Ok((_data, _attrs)) = runtime::get_variable(VAR_LOG_PREV1, vendor, &mut buffer) {
        // Find actual data length (scan for null or use full buffer)
        let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        let _ = runtime::set_variable(VAR_LOG_PREV2, vendor, VAR_ATTRS, &buffer[..len]);
    }

    // Log0 → Log1
    if let Ok((_data, _attrs)) = runtime::get_variable(VAR_LOG_CURRENT, vendor, &mut buffer) {
        let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        let _ = runtime::set_variable(VAR_LOG_PREV1, vendor, VAR_ATTRS, &buffer[..len]);
    }

    serial_println!("[BootLog] Logs rotated");
}
