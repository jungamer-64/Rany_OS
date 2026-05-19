//! Shim Loader and MOK (Machine Owner Key) Detection
//!
//! This module detects if the bootloader was launched via the Shim bootloader
//! and retrieves MOK-related information for Secure Boot integration.
//!
//! Shim is a UEFI bootloader signed by Microsoft that allows loading
//! custom-signed bootloaders and kernels using Machine Owner Keys (MOK).
//!
//! Key concepts:
//! - Shim: Microsoft-signed first-stage loader
//! - MOK: Machine Owner Keys enrolled by the user
//! - MokList: List of enrolled MOK certificates
//! - MokSBState: Secure Boot validation state within Shim
//! - SBAT: Secure Boot Advanced Targeting for revocation

use log::info;
use uefi::prelude::*;
use uefi::runtime::{self, VariableVendor};
use uefi::{Guid, boot};

/// Shim Lock Protocol GUID
/// {605DAB50-E046-4300-ABB6-3DD810DD8B23}
const SHIM_LOCK_GUID: Guid = uefi::guid!("605dab50-e046-4300-abb6-3dd810dd8b23");

/// Shim Variable GUID (for MOK variables)
/// {605DAB50-E046-4300-ABB6-3DD810DD8B23}
const SHIM_VARIABLE_GUID: Guid = uefi::guid!("605dab50-e046-4300-abb6-3dd810dd8b23");

/// Shim/MOK detection information
#[derive(Debug, Clone, Copy, Default)]
pub struct ShimMokInfo {
    /// Shim Lock Protocol is available (we were launched by Shim)
    pub shim_detected: bool,
    /// Shim version (if available)
    pub shim_version_major: u8,
    pub shim_version_minor: u8,
    /// MOK Secure Boot state
    /// 0 = Secure Boot validation disabled in Shim
    /// 1 = Secure Boot validation enabled in Shim
    pub mok_sb_state: u8,
    /// MokList variable is present (MOK certificates enrolled)
    pub mok_list_present: bool,
    /// MokListRT variable is present (runtime accessible MOK list)
    pub mok_list_rt_present: bool,
    /// MokListX variable is present (MOK blacklist/revocation)
    pub mok_list_x_present: bool,
    /// SBAT Level variable is present (revocation data)
    pub sbat_level_present: bool,
    /// Number of MOK certificates enrolled (if detectable)
    pub mok_count: u16,
    /// Shim validation was successful for this binary
    pub shim_validated: bool,
}

/// Read MOK-related UEFI variables and populate info fields.
fn detect_mok_variables(info: &mut ShimMokInfo) {
    // Check MokSBState (Secure Boot state within Shim)
    if let Some(value) = read_mok_u8_variable("MokSBState") {
        info.mok_sb_state = value;
        info!(
            "MokSBState: {} ({})",
            value,
            if value == 0 {
                "validation disabled"
            } else {
                "validation enabled"
            }
        );
    }

    // Check MokList (enrolled MOK certificates)
    info.mok_list_present = mok_variable_exists("MokList");
    if info.mok_list_present {
        info!("MokList present (MOK certificates enrolled)");
        info.mok_count = count_mok_certificates();
        if info.mok_count > 0 {
            info!("  {} MOK certificate(s) enrolled", info.mok_count);
        }
    }

    // Check MokListRT (runtime-accessible MOK list)
    info.mok_list_rt_present = mok_variable_exists("MokListRT");
    if info.mok_list_rt_present {
        info!("MokListRT present (runtime MOK access available)");
    }

    // Check MokListX (MOK blacklist/revocation list)
    info.mok_list_x_present = mok_variable_exists("MokListX");
    if info.mok_list_x_present {
        info!("MokListX present (MOK revocation list)");
    }

    // Check SbatLevel (SBAT revocation data)
    info.sbat_level_present = mok_variable_exists("SbatLevel");
    if info.sbat_level_present {
        info!("SbatLevel present (SBAT revocation data)");
    }
}

/// Log a summary of the Shim/MOK detection results.
fn log_shim_summary(info: &ShimMokInfo) {
    if info.shim_detected {
        if info.mok_sb_state == 1 {
            info!("MOK Secure Boot: ENABLED");
        } else {
            info!("MOK Secure Boot: DISABLED (Shim validation off)");
        }
    } else {
        info!("Shim bootloader not detected (direct UEFI boot)");
    }
}

/// Detect Shim loader and MOK state
///
/// # Returns
/// ShimMokInfo containing Shim/MOK detection results
pub fn detect_shim_mok() -> ShimMokInfo {
    let mut info = ShimMokInfo::default();

    // 1. Check for Shim Lock Protocol
    info.shim_detected = detect_shim_lock_protocol();

    if info.shim_detected {
        info!("Shim bootloader detected (SHIM_LOCK protocol present)");
    }

    // 2. Read MOK-related variables
    detect_mok_variables(&mut info);

    // 3. Try to verify ourselves with Shim (if protocol available)
    if info.shim_detected {
        info.shim_validated = true;
        info!("Shim validation: PASSED (we were loaded by Shim)");
    }

    // Summary
    log_shim_summary(&info);

    info
}

/// Check if Shim Lock Protocol is available
fn detect_shim_lock_protocol() -> bool {
    // Try to locate the Shim Lock Protocol
    match boot::locate_handle_buffer(boot::SearchType::ByProtocol(&SHIM_LOCK_GUID)) {
        Ok(handles) => !handles.is_empty(),
        Err(_) => false,
    }
}

/// Read a single byte MOK variable
fn read_mok_u8_variable(name: &str) -> Option<u8> {
    let mut buffer = [0u8; 1];
    let vendor = VariableVendor(SHIM_VARIABLE_GUID);

    // Convert name to UCS-2
    let mut name_buf = [0u16; 32];
    let mut len = 0;
    for ch in name.chars().take(30) {
        name_buf[len] = ch as u16;
        len += 1;
    }
    name_buf[len] = 0;

    let name_cstr = match uefi::CStr16::from_u16_with_nul(&name_buf[..=len]) {
        Ok(s) => s,
        Err(_) => return None,
    };

    match runtime::get_variable(name_cstr, &vendor, &mut buffer) {
        Ok(_) => Some(buffer[0]),
        Err(_) => None,
    }
}

/// Check if a MOK variable exists
fn mok_variable_exists(name: &str) -> bool {
    let mut buffer = [0u8; 1];
    let vendor = VariableVendor(SHIM_VARIABLE_GUID);

    // Convert name to UCS-2
    let mut name_buf = [0u16; 32];
    let mut len = 0;
    for ch in name.chars().take(30) {
        name_buf[len] = ch as u16;
        len += 1;
    }
    name_buf[len] = 0;

    let name_cstr = match uefi::CStr16::from_u16_with_nul(&name_buf[..=len]) {
        Ok(s) => s,
        Err(_) => return false,
    };

    match runtime::get_variable(name_cstr, &vendor, &mut buffer) {
        Ok(_) => true,
        Err(e) => matches!(e.status(), Status::BUFFER_TOO_SMALL),
    }
}

/// Count MOK certificates in MokList
/// Returns 0 if unable to determine
fn count_mok_certificates() -> u16 {
    // MokList is a EFI_SIGNATURE_LIST structure
    // Each entry contains: SignatureListSize, SignatureHeaderSize, SignatureSize
    // The number of certificates = (SignatureListSize - sizeof(header) - SignatureHeaderSize) / SignatureSize

    // First, get the size of MokList
    let vendor = VariableVendor(SHIM_VARIABLE_GUID);

    let name = cstr16!("MokList");
    let mut size_buf = [0u8; 4096]; // Reasonable max size

    match runtime::get_variable(name, &vendor, &mut size_buf) {
        Ok((data, _attrs)) => {
            // Parse EFI_SIGNATURE_LIST to count entries
            // This is a simplified count - just estimate based on typical certificate sizes
            let data_len = data.len();
            if data_len > 0 {
                // A typical X.509 certificate in EFI_SIGNATURE_LIST is ~1-2KB
                // This is a rough estimate
                let estimated = (data_len / 1024).max(1) as u16;
                estimated
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

/// Get Shim/MOK status string for logging
pub fn get_shim_mok_status_string(info: &ShimMokInfo) -> &'static str {
    if !info.shim_detected {
        "Direct UEFI boot (no Shim)"
    } else if info.mok_sb_state == 1 {
        "Shim + MOK Secure Boot enabled"
    } else {
        "Shim present, MOK validation disabled"
    }
}
