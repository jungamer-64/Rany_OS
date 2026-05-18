//! ブートログ永続化機能
//!
//! ブートログをUEFI変数に保存し、起動失敗時の診断に使用。
//! - 複数世代のログローテーション
//! - 前回ブートログの取得
//! - カーネルからのアクセス

use alloc::string::String;
use core::fmt::Write;
use uefi::runtime::{self, VariableAttributes, VariableVendor};
use uefi::{CStr16, Guid, cstr16};
use crate::serial_println;

/// ブートログ専用GUID
/// {B6F9E4A1-5678-1234-ABCD-EF0123456789}
const BOOT_LOG_GUID: Guid = Guid::parse_or_panic("b6f9e4a1-5678-1234-abcd-ef0123456789");

/// ログ最大サイズ（UEFI変数サイズ制限を考慮）
pub const MAX_LOG_SIZE: usize = 8192;

/// 保持するログ世代数
pub const LOG_GENERATIONS: usize = 3;

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

    /// フォーマット付きログ
    pub fn log_fmt(&mut self, args: core::fmt::Arguments<'_>) {
        if !self.initialized {
            return;
        }

        // 一時バッファに書き込み
        let mut temp = String::new();
        if core::fmt::write(&mut temp, args).is_ok() {
            self.log(&temp);
        }
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

    /// 現在のログ内容を取得
    pub fn get_current_log(&self) -> &str {
        &self.buffer
    }

    /// ログサイズを取得
    pub fn log_size(&self) -> usize {
        self.buffer.len()
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

/// 前回のブートログを取得
pub fn get_previous_log(generation: usize) -> Option<String> {
    let vendor = get_vendor();

    let var_name = match generation {
        0 => VAR_LOG_CURRENT,
        1 => VAR_LOG_PREV1,
        2 => VAR_LOG_PREV2,
        _ => return None,
    };

    let mut buffer = [0u8; MAX_LOG_SIZE];
    match runtime::get_variable(var_name, vendor, &mut buffer) {
        Ok((_data, _attrs)) => {
            // Find actual data length
            let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
            // UTF-8として解釈
            String::from_utf8(buffer[..len].to_vec()).ok()
        }
        Err(_) => None,
    }
}

/// 前回のブートログをシリアルに出力
pub fn dump_previous_log() {
    serial_println!("[BootLog] === Previous Boot Log ===");

    if let Some(log) = get_previous_log(1) {
        for _line in log.lines() {
            serial_println!("  {}", _line);
        }
    } else {
        serial_println!("  (No previous log available)");
    }

    serial_println!("[BootLog] === End of Previous Log ===");
}

/// グローバルロガーインスタンス
static mut BOOT_LOGGER: BootLogger = BootLogger::new();

/// グローバルロガーを取得
///
/// # Safety
/// シングルスレッド環境（ブート時）でのみ使用可能
pub unsafe fn get_logger() -> &'static mut BootLogger {
    unsafe { &mut *(&raw mut BOOT_LOGGER) }
}

/// ロガーを初期化
///
/// # Safety
/// シングルスレッド環境（ブート時）でのみ使用可能
pub unsafe fn init_logger() {
    unsafe { (*(&raw mut BOOT_LOGGER)).init() };
}

/// ログを保存
///
/// # Safety
/// シングルスレッド環境（ブート時）でのみ使用可能
pub unsafe fn save_log() {
    unsafe { (*(&raw const BOOT_LOGGER)).save() };
}

/// ブートログマクロ
#[macro_export]
macro_rules! boot_log {
    ($($arg:tt)*) => {
        unsafe {
            if let logger = $crate::boot_log::get_logger() {
                logger.log_fmt(format_args!($($arg)*));
            }
        }
    };
}

/// ブート診断情報を収集
pub fn collect_boot_diagnostics() -> String {
    let mut diag = String::new();

    let _ = writeln!(diag, "=== Boot Diagnostics ===");

    // ファームウェア情報
    let st_ptr = uefi::table::system_table_raw().expect("No system table available");
    unsafe {
        let st = &*st_ptr.as_ptr();
        let fw_vendor = st.firmware_vendor;
        let fw_revision = st.firmware_revision;
        let _ = writeln!(diag, "Firmware: {:?} (rev {:?})", fw_vendor, fw_revision);

        // UEFI仕様バージョン
        let uefi_revision = st.header.revision;
        let _ = writeln!(diag, "UEFI Revision: {:?}", uefi_revision);
    }

    let _ = writeln!(diag, "=== End Diagnostics ===");

    diag
}

/// ブート診断をログに追加
pub fn log_boot_diagnostics() {
    let diag = collect_boot_diagnostics();
    unsafe {
        let logger = get_logger();
        for line in diag.lines() {
            logger.log(line);
        }
    }
}
