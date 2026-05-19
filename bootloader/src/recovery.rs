//! フォールバックカーネルとブート回復機能
//!
//! 起動失敗時の自動リカバリ機能を提供：
//! - 起動成功フラグ（UEFI変数）
//! - 連続失敗カウンター
//! - フォールバックカーネルへの自動切り替え
//! - リカバリモード

use crate::serial_println;
use uefi::runtime::{self, VariableAttributes, VariableVendor};
use uefi::{CStr16, Guid, cstr16};

/// ExoLoader専用UEFI変数GUID
/// {A5E8F3D2-1234-5678-9ABC-DEF012345678}
const EXOLOADER_VARIABLE_GUID: Guid = Guid::parse_or_panic("a5e8f3d2-1234-5678-9abc-def012345678");

/// 最大連続失敗回数（これを超えるとリカバリモード）
pub const MAX_BOOT_FAILURES: u8 = 3;

/// ブート状態情報
#[derive(Debug, Clone, Copy)]
pub struct BootState {
    /// 連続起動失敗回数
    pub failure_count: u8,
    /// 前回起動が成功したか
    pub last_boot_success: bool,
    /// リカバリモードが要求されているか
    pub recovery_requested: bool,
    /// 前回選択されたエントリインデックス
    pub last_entry_index: u8,
    /// ブート試行ID（インクリメンタル）
    pub boot_attempt_id: u32,
}

impl Default for BootState {
    fn default() -> Self {
        Self {
            failure_count: 0,
            last_boot_success: true,
            recovery_requested: false,
            last_entry_index: 0,
            boot_attempt_id: 0,
        }
    }
}

/// ブート回復情報（boot_protoに渡す）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootRecoveryInfo {
    /// 現在のブート試行ID
    pub boot_attempt_id: u32,
    /// 連続失敗回数
    pub failure_count: u8,
    /// リカバリモードで起動中か
    pub is_recovery_mode: bool,
    /// フォールバックカーネルで起動中か
    pub is_fallback: bool,
    /// 予約
    pub _reserved: u8,
    /// 前回のブート試行ID（成功確認用）
    pub expected_success_id: u32,
}

impl Default for BootRecoveryInfo {
    fn default() -> Self {
        Self {
            boot_attempt_id: 0,
            failure_count: 0,
            is_recovery_mode: false,
            is_fallback: false,
            _reserved: 0,
            expected_success_id: 0,
        }
    }
}

/// UEFI変数名
const VAR_FAILURE_COUNT: &CStr16 = cstr16!("ExoBootFailureCount");
const VAR_LAST_SUCCESS: &CStr16 = cstr16!("ExoBootLastSuccess");
const VAR_LAST_ENTRY: &CStr16 = cstr16!("ExoBootLastEntry");
const VAR_BOOT_ATTEMPT_ID: &CStr16 = cstr16!("ExoBootAttemptId");
const VAR_RECOVERY_REQUEST: &CStr16 = cstr16!("ExoBootRecoveryRequest");

/// 変数属性（Non-Volatile + Boot Service + Runtime Access）
const VAR_ATTRS: VariableAttributes = VariableAttributes::from_bits_truncate(
    VariableAttributes::NON_VOLATILE.bits()
        | VariableAttributes::BOOTSERVICE_ACCESS.bits()
        | VariableAttributes::RUNTIME_ACCESS.bits(),
);

/// カスタムVariableVendorを取得
fn get_vendor() -> &'static VariableVendor {
    static VENDOR: VariableVendor = VariableVendor(EXOLOADER_VARIABLE_GUID);
    &VENDOR
}

/// UEFI変数からブート状態を読み込む
pub fn load_boot_state() -> BootState {
    let mut state = BootState::default();
    let vendor = get_vendor();

    // 失敗カウンター読み込み
    let mut buffer = [0u8; 1];
    if runtime::get_variable(VAR_FAILURE_COUNT, vendor, &mut buffer).is_ok() {
        state.failure_count = buffer[0];
    }

    // 前回成功フラグ読み込み
    if runtime::get_variable(VAR_LAST_SUCCESS, vendor, &mut buffer).is_ok() {
        state.last_boot_success = buffer[0] != 0;
    }

    // 前回エントリインデックス読み込み
    if runtime::get_variable(VAR_LAST_ENTRY, vendor, &mut buffer).is_ok() {
        state.last_entry_index = buffer[0];
    }

    // ブート試行ID読み込み
    let mut id_buffer = [0u8; 4];
    if runtime::get_variable(VAR_BOOT_ATTEMPT_ID, vendor, &mut id_buffer).is_ok() {
        state.boot_attempt_id = u32::from_le_bytes(id_buffer);
    }

    // リカバリ要求フラグ読み込み
    if runtime::get_variable(VAR_RECOVERY_REQUEST, vendor, &mut buffer).is_ok() {
        state.recovery_requested = buffer[0] != 0;
    }

    state
}

/// ブート開始前の状態更新（失敗カウンターをインクリメント）
pub fn prepare_boot_attempt(state: &mut BootState, selected_entry: u8) -> BootRecoveryInfo {
    let vendor = get_vendor();

    // 前回起動が成功していなければ失敗カウンターをインクリメント
    if !state.last_boot_success {
        state.failure_count = state.failure_count.saturating_add(1);
        serial_println!(
            "[Recovery] Boot failure detected. Count: {}",
            state.failure_count
        );
    }

    // ブート試行IDをインクリメント
    state.boot_attempt_id = state.boot_attempt_id.wrapping_add(1);

    // 「成功」フラグを0にセット（カーネルが成功時に1にする）
    let _ = runtime::set_variable(VAR_LAST_SUCCESS, vendor, VAR_ATTRS, &[0u8]);

    // 失敗カウンターを保存
    let _ = runtime::set_variable(VAR_FAILURE_COUNT, vendor, VAR_ATTRS, &[state.failure_count]);

    // 選択エントリを保存
    let _ = runtime::set_variable(VAR_LAST_ENTRY, vendor, VAR_ATTRS, &[selected_entry]);

    // ブート試行IDを保存
    let _ = runtime::set_variable(
        VAR_BOOT_ATTEMPT_ID,
        vendor,
        VAR_ATTRS,
        &state.boot_attempt_id.to_le_bytes(),
    );

    // リカバリ要求をクリア
    let _ = runtime::set_variable(VAR_RECOVERY_REQUEST, vendor, VAR_ATTRS, &[0u8]);

    // 回復情報を構築
    let is_recovery = state.failure_count >= MAX_BOOT_FAILURES || state.recovery_requested;
    let is_fallback = state.failure_count > 0 && selected_entry != state.last_entry_index;

    BootRecoveryInfo {
        boot_attempt_id: state.boot_attempt_id,
        failure_count: state.failure_count,
        is_recovery_mode: is_recovery,
        is_fallback,
        _reserved: 0,
        expected_success_id: state.boot_attempt_id,
    }
}

/// Mark the current boot as successfully handed off to the kernel.
///
/// NOTE:
/// - This is called by ExoLoader immediately before `ExitBootServices`.
/// - Kernel-level "fully booted" acknowledgement is not implemented yet.
/// - We still keep the pre-boot pessimistic `last_success=0` in
///   `prepare_boot_attempt()`, so early bootloader failures are tracked.
pub fn mark_boot_handoff_success() {
    let vendor = get_vendor();

    // Successful handoff resets recovery pressure.
    let _ = runtime::set_variable(VAR_LAST_SUCCESS, vendor, VAR_ATTRS, &[1u8]);
    let _ = runtime::set_variable(VAR_FAILURE_COUNT, vendor, VAR_ATTRS, &[0u8]);

    serial_println!("[Recovery] Boot handoff marked successful");
}

/// フォールバックカーネルを使用すべきか判定
pub fn should_use_fallback(state: &BootState) -> bool {
    // 2回以上連続失敗したらフォールバックを試す
    state.failure_count >= 2 && !state.recovery_requested
}

/// リカバリモードに入るべきか判定
pub fn should_enter_recovery(state: &BootState) -> bool {
    state.failure_count >= MAX_BOOT_FAILURES || state.recovery_requested
}

/// ブート状態をシリアルに出力
pub fn log_boot_state(state: &BootState) {
    serial_println!("[Recovery] Boot state:");
    serial_println!("  Failure count: {}", state.failure_count);
    serial_println!("  Last boot success: {}", state.last_boot_success);
    serial_println!("  Recovery requested: {}", state.recovery_requested);
    serial_println!("  Last entry index: {}", state.last_entry_index);
    serial_println!("  Boot attempt ID: {}", state.boot_attempt_id);

    if should_enter_recovery(state) {
        serial_println!("  >>> ENTERING RECOVERY MODE <<<");
    } else if should_use_fallback(state) {
        serial_println!("  >>> USING FALLBACK KERNEL <<<");
    }
}
