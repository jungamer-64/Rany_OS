//! UEFI Secure Boot State Detection
//!
//! This module detects the current UEFI Secure Boot state by reading
//! UEFI authenticated variables. It provides information about:
//! - Whether Secure Boot is enabled
//! - Whether the system is in Setup Mode or User Mode
//! - Platform Key (PK) presence
//! - Key Exchange Key (KEK) presence
//! - Signature database (db/dbx) status

use log::info;
use uefi::CStr16;
use uefi::prelude::*;
use uefi::runtime::{self, VariableVendor};

/// UEFI Global Variable GUID
/// {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
const EFI_GLOBAL_VARIABLE_GUID: uefi::Guid = uefi::guid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");

/// Secure Boot state information
#[derive(Debug, Clone, Copy, Default)]
pub struct SecureBootInfo {
    /// Secure Boot is enabled (SecureBoot variable == 1)
    pub secure_boot_enabled: bool,
    /// System is in Setup Mode (SetupMode variable == 1)
    /// In Setup Mode, Secure Boot is not enforced
    pub setup_mode: bool,
    /// Platform Key (PK) is enrolled
    pub pk_present: bool,
    /// Key Exchange Key (KEK) is enrolled
    pub kek_present: bool,
    /// Signature database (db) is present
    pub db_present: bool,
    /// Forbidden signature database (dbx) is present
    pub dbx_present: bool,
    /// Audit mode is enabled
    pub audit_mode: bool,
    /// Deployed mode is enabled
    pub deployed_mode: bool,
    /// Vendor keys are present (OsIndicationsSupported)
    pub vendor_keys: bool,
}

/// Detect UEFI Secure Boot state
///
/// Reads UEFI authenticated variables to determine the current
/// Secure Boot configuration.
///
/// # Returns
/// SecureBootInfo containing the current Secure Boot state
pub fn detect_secure_boot_state() -> SecureBootInfo {
    let mut info = SecureBootInfo::default();
    read_boot_mode_variables(&mut info);
    check_key_variables(&mut info);
    log_secure_boot_summary(&info);
    info
}

/// ブートモード関連のUEFI変数を読み取る
fn read_boot_mode_variables(info: &mut SecureBootInfo) {
    if let Some(value) = read_u8_variable(cstr16!("SecureBoot")) {
        info.secure_boot_enabled = value == 1;
        info!("SecureBoot variable: {}", value);
    } else {
        info!("SecureBoot variable not found (Secure Boot not supported)");
    }

    if let Some(value) = read_u8_variable(cstr16!("SetupMode")) {
        info.setup_mode = value == 1;
        info!(
            "SetupMode: {} ({})",
            value,
            if value == 1 {
                "Setup Mode"
            } else {
                "User Mode"
            }
        );
    }

    if let Some(value) = read_u8_variable(cstr16!("AuditMode")) {
        info.audit_mode = value == 1;
        if value == 1 {
            info!("AuditMode enabled");
        }
    }

    if let Some(value) = read_u8_variable(cstr16!("DeployedMode")) {
        info.deployed_mode = value == 1;
        if value == 1 {
            info!("DeployedMode enabled");
        }
    }
}

/// キーデータベース変数の存在を確認する
fn check_key_variables(info: &mut SecureBootInfo) {
    info.pk_present = variable_exists(cstr16!("PK"));
    if info.pk_present {
        info!("Platform Key (PK) is enrolled");
    }

    info.kek_present = variable_exists(cstr16!("KEK"));
    if info.kek_present {
        info!("Key Exchange Key (KEK) is enrolled");
    }

    info.db_present = variable_exists(cstr16!("db"));
    if info.db_present {
        info!("Signature database (db) is present");
    }

    info.dbx_present = variable_exists(cstr16!("dbx"));
    if info.dbx_present {
        info!("Forbidden signature database (dbx) is present");
    }

    if let Some(value) = read_u8_variable(cstr16!("VendorKeys")) {
        info.vendor_keys = value == 1;
        if value == 1 {
            info!("Vendor keys present");
        }
    }
}

/// Secure Boot状態のサマリーをログ出力
fn log_secure_boot_summary(info: &SecureBootInfo) {
    if info.secure_boot_enabled {
        info!("Secure Boot: ENABLED (User Mode)");
    } else if info.setup_mode {
        info!("Secure Boot: DISABLED (Setup Mode - keys can be modified)");
    } else {
        info!("Secure Boot: DISABLED");
    }
}

/// Read a single byte UEFI variable
fn read_u8_variable(name: &CStr16) -> Option<u8> {
    let mut buffer = [0u8; 1];

    // Use the global variable vendor GUID
    let vendor = VariableVendor(EFI_GLOBAL_VARIABLE_GUID);

    match runtime::get_variable(name, &vendor, &mut buffer) {
        Ok(_) => Some(buffer[0]),
        Err(_) => None,
    }
}

/// Check if a UEFI variable exists (without reading its full contents)
fn variable_exists(name: &CStr16) -> bool {
    // Try to read with a small buffer - if the variable exists but is larger,
    // we'll get a buffer too small error, which still indicates the variable exists
    let mut buffer = [0u8; 1];
    let vendor = VariableVendor(EFI_GLOBAL_VARIABLE_GUID);

    match runtime::get_variable(name, &vendor, &mut buffer) {
        Ok(_) => true,
        Err(e) => {
            // BUFFER_TOO_SMALL means the variable exists but needs more space
            matches!(e.status(), Status::BUFFER_TOO_SMALL)
        }
    }
}

/// Check if the current boot was verified by Secure Boot
///
/// This is useful for determining if we're running as a trusted boot component.
/// Note: This only indicates the Secure Boot state, not whether this specific
/// bootloader binary was verified (that depends on whether we're signed and in db).
#[allow(dead_code)]
pub fn is_verified_boot(info: &SecureBootInfo) -> bool {
    info.secure_boot_enabled && !info.setup_mode && info.pk_present
}

/// Get a human-readable description of the Secure Boot state
pub fn get_secure_boot_status_string(info: &SecureBootInfo) -> &'static str {
    if info.secure_boot_enabled {
        if info.deployed_mode {
            "Secure Boot: Enabled (Deployed Mode)"
        } else {
            "Secure Boot: Enabled"
        }
    } else if info.setup_mode {
        "Secure Boot: Disabled (Setup Mode)"
    } else if info.audit_mode {
        "Secure Boot: Audit Mode"
    } else {
        "Secure Boot: Disabled"
    }
}

/// Secure Boot mode enumeration
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootMode {
    /// Secure Boot is not supported by the firmware
    NotSupported,
    /// Setup Mode - keys can be freely modified
    SetupMode,
    /// User Mode with Secure Boot disabled
    UserModeDisabled,
    /// User Mode with Secure Boot enabled
    UserModeEnabled,
    /// Audit Mode - violations are logged but not enforced
    AuditMode,
    /// Deployed Mode - strongest enforcement
    DeployedMode,
}

/// Get the current Secure Boot mode
#[allow(dead_code)]
pub fn get_secure_boot_mode(info: &SecureBootInfo) -> SecureBootMode {
    if !info.pk_present && !info.setup_mode && !info.secure_boot_enabled {
        SecureBootMode::NotSupported
    } else if info.setup_mode {
        SecureBootMode::SetupMode
    } else if info.audit_mode {
        SecureBootMode::AuditMode
    } else if info.deployed_mode {
        SecureBootMode::DeployedMode
    } else if info.secure_boot_enabled {
        SecureBootMode::UserModeEnabled
    } else {
        SecureBootMode::UserModeDisabled
    }
}
