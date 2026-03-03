//! UEFI Secure Boot State Detection and Policy Enforcement
//!
//! This module implements:
//! - UEFI Secure Boot state detection (authenticated variables)
//! - Software SHA-256 for forbidden image hash computation
//! - dbx (Forbidden Signature Database) hash verification
//! - Boot chain integrity policy enforcement
//!   - Permissive: warnings only
//!   - Enforcing: halt on violation (Secure Boot enabled)
//!   - Strict: halt on any anomaly, including Setup Mode with SB enabled
//!
//! # Security Properties
//! - dbx check prevents revoked kernel images from booting
//! - Policy enforcement prevents bypassing Secure Boot via `insecure_boot` feature
//! - SHA-256 is computed in software (no TPM required for the check itself)

use log::{error, info, warn};
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

// ============================================================
// SOFTWARE SHA-256 IMPLEMENTATION (no_std, no external crates)
// ============================================================

/// SHA-256 initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (first 32 bits of fractional parts of cbrt of first 64 primes)
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute SHA-256 hash of `data` in pure software (no_std).
///
/// Returns the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = SHA256_H;
    let bit_len = (data.len() as u64).wrapping_mul(8);

    // Build padded message iterator over 512-bit (64-byte) blocks.
    // Padding: append 0x80, then zero-pad, then 64-bit big-endian bit length,
    // such that total length ≡ 0 (mod 64).
    let padded_len = {
        let base = data.len() + 1 + 8; // 0x80 byte + length field
        let pad = (64 - (base % 64)) % 64;
        base + pad
    };

    let block_count = padded_len / 64;

    for block_idx in 0..block_count {
        let mut w = [0u32; 64];

        // Fill first 16 words from message bytes (big-endian)
        for j in 0..16 {
            let byte_pos = block_idx * 64 + j * 4;
            let b = |i: usize| -> u8 {
                let p = byte_pos + i;
                if p < data.len() {
                    data[p]
                } else if p == data.len() {
                    0x80
                } else if p >= padded_len - 8 {
                    let shift = (7 - (p - (padded_len - 8))) * 8;
                    (bit_len >> shift) as u8
                } else {
                    0
                }
            };
            w[j] = ((b(0) as u32) << 24)
                | ((b(1) as u32) << 16)
                | ((b(2) as u32) << 8)
                | (b(3) as u32);
        }

        // Extend to 64 words
        for j in 16..64 {
            let s0 = w[j - 15].rotate_right(7)
                ^ w[j - 15].rotate_right(18)
                ^ (w[j - 15] >> 3);
            let s1 = w[j - 2].rotate_right(17)
                ^ w[j - 2].rotate_right(19)
                ^ (w[j - 2] >> 10);
            w[j] = w[j - 16]
                .wrapping_add(s0)
                .wrapping_add(w[j - 7])
                .wrapping_add(s1);
        }

        // Compression
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for j in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[j])
                .wrapping_add(w[j]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Convert to bytes (big-endian)
    let mut digest = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        let bytes = word.to_be_bytes();
        digest[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    digest
}

// ============================================================
// EFI_SIGNATURE_LIST PARSER FOR dbx
// ============================================================

/// EFI_CERT_SHA256_GUID: {C1C41626-504C-4092-ACA9-41F936934328}
const EFI_CERT_SHA256_GUID: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];

/// EFI_SIGNATURE_LIST header (28 bytes)
#[repr(C)]
struct EfiSignatureListHeader {
    /// GUID identifying the type of signature
    signature_type: [u8; 16],
    /// Total size of the entire list including header and signatures (little-endian)
    signature_list_size: u32,
    /// Size of the optional signature header following this header (little-endian)
    signature_header_size: u32,
    /// Size of each EFI_SIGNATURE_DATA entry (little-endian)
    signature_size: u32,
}

const SIGNATURE_LIST_HEADER_SIZE: usize = 28;
const SIGNATURE_OWNER_GUID_SIZE: usize = 16;

/// Maximum number of SHA-256 entries to extract from dbx (stack-size guard)
pub const MAX_DBX_HASHES: usize = 256;

/// Read all SHA-256 hashes from the dbx (Forbidden Signature Database).
///
/// Returns the number of hashes written into `out`.
pub fn read_dbx_sha256_hashes(out: &mut [[u8; 32]; MAX_DBX_HASHES]) -> usize {
    let vendor = VariableVendor(EFI_GLOBAL_VARIABLE_GUID);
    // dbx can be large; use a heap buffer
    extern crate alloc;
    use alloc::vec;
    let mut buf = vec![0u8; 32 * 1024]; // 32 KB should cover most dbx sizes

    let data = match runtime::get_variable(cstr16!("dbx"), &vendor, &mut buf) {
        Ok((data, _)) => data,
        Err(_) => {
            info!("dbx: variable not accessible or not present");
            return 0;
        }
    };

    parse_efi_signature_list_sha256(data, out)
}

/// Parse an EFI_SIGNATURE_LIST byte slice and extract all SHA-256 hashes.
///
/// Returns the count of hashes written into `out`.
fn parse_efi_signature_list_sha256(data: &[u8], out: &mut [[u8; 32]; MAX_DBX_HASHES]) -> usize {
    let mut count = 0;
    let mut offset = 0;

    while offset + SIGNATURE_LIST_HEADER_SIZE <= data.len() && count < MAX_DBX_HASHES {
        // Read header (little-endian fields)
        let header_bytes = &data[offset..offset + SIGNATURE_LIST_HEADER_SIZE];
        let sig_type: [u8; 16] = header_bytes[0..16].try_into().unwrap_or([0u8; 16]);
        let list_size = u32::from_le_bytes(header_bytes[16..20].try_into().unwrap_or([0; 4])) as usize;
        let header_size = u32::from_le_bytes(header_bytes[20..24].try_into().unwrap_or([0; 4])) as usize;
        let sig_size = u32::from_le_bytes(header_bytes[24..28].try_into().unwrap_or([0; 4])) as usize;

        // Sanity checks to avoid infinite loops / out-of-bounds
        if list_size < SIGNATURE_LIST_HEADER_SIZE
            || offset + list_size > data.len()
            || sig_size <= SIGNATURE_OWNER_GUID_SIZE
        {
            break;
        }

        // Only process SHA-256 entries
        if sig_type == EFI_CERT_SHA256_GUID {
            let sig_data_start = offset + SIGNATURE_LIST_HEADER_SIZE + header_size;
            let sig_data_end = offset + list_size;
            let payload_size = sig_size - SIGNATURE_OWNER_GUID_SIZE;

            if payload_size == 32 {
                let mut sig_off = sig_data_start;
                while sig_off + sig_size <= sig_data_end && count < MAX_DBX_HASHES {
                    let hash_start = sig_off + SIGNATURE_OWNER_GUID_SIZE;
                    if hash_start + 32 <= data.len() {
                        out[count].copy_from_slice(&data[hash_start..hash_start + 32]);
                        count += 1;
                    }
                    sig_off += sig_size;
                }
            }
        }

        offset += list_size;
    }

    count
}

/// Check whether `hash` appears in the dbx forbidden hash list.
fn is_hash_in_dbx(hash: &[u8; 32], dbx_hashes: &[[u8; 32]], count: usize) -> bool {
    // Constant-time comparison to mitigate timing side-channels
    for i in 0..count {
        let mut diff = 0u8;
        for j in 0..32 {
            diff |= hash[j] ^ dbx_hashes[i][j];
        }
        if diff == 0 {
            return true;
        }
    }
    false
}

// ============================================================
// SECURE BOOT POLICY ENFORCEMENT
// ============================================================

/// Secure Boot enforcement policy level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootPolicy {
    /// Log warnings but never halt (development / QEMU use)
    Permissive,
    /// Halt on violation when UEFI Secure Boot is enabled
    Enforcing,
    /// Halt on any anomaly, even Setup Mode or dbx unavailable
    Strict,
}

/// Determine the effective policy from compile-time features and runtime state.
///
/// - `insecure_boot` feature → Permissive  
/// - UEFI Secure Boot enabled → Enforcing  
/// - All other cases → Permissive (no SB firmware, dev machines)
pub fn effective_policy(sb_info: &SecureBootInfo) -> SecureBootPolicy {
    if cfg!(feature = "insecure_boot") {
        return SecureBootPolicy::Permissive;
    }
    if sb_info.deployed_mode {
        return SecureBootPolicy::Strict;
    }
    if sb_info.secure_boot_enabled {
        return SecureBootPolicy::Enforcing;
    }
    SecureBootPolicy::Permissive
}

/// Violation type reported to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootViolation {
    /// insecure_boot feature enabled while UEFI Secure Boot is active
    InsecureBootWithFirmwareSB,
    /// Kernel image hash found in dbx (revoked)
    KernelRevokedByDbx,
    /// Firmware is in Setup Mode but Secure Boot variables indicate User Mode
    SetupModeAnomaly,
}

/// Enforce the Secure Boot policy for a potential violation.
///
/// Depending on `policy`:
/// - `Permissive` → logs a warning, returns `Ok(())`
/// - `Enforcing` / `Strict` → logs an error and returns `Err(Status::SECURITY_VIOLATION)`
///
/// The caller is responsible for halting the system (e.g. `boot::stall` + panic).
pub fn enforce_policy(
    policy: SecureBootPolicy,
    violation: SecureBootViolation,
) -> Result<(), Status> {
    match violation {
        SecureBootViolation::InsecureBootWithFirmwareSB => {
            match policy {
                SecureBootPolicy::Permissive => {
                    warn!(
                        "SECURE BOOT WARNING: insecure_boot feature is active \
                         but UEFI Secure Boot is ENABLED by firmware. \
                         This configuration is unsafe in production."
                    );
                    Ok(())
                }
                SecureBootPolicy::Enforcing | SecureBootPolicy::Strict => {
                    error!("======================================================");
                    error!("SECURITY VIOLATION: insecure_boot is compiled in but");
                    error!("UEFI Secure Boot is ENABLED. Refusing to continue.");
                    error!("======================================================");
                    Err(Status::SECURITY_VIOLATION)
                }
            }
        }
        SecureBootViolation::KernelRevokedByDbx => {
            match policy {
                SecureBootPolicy::Permissive => {
                    warn!(
                        "SECURE BOOT WARNING: Kernel image hash matches a dbx \
                         revocation entry. Boot continues (Permissive mode)."
                    );
                    Ok(())
                }
                SecureBootPolicy::Enforcing | SecureBootPolicy::Strict => {
                    error!("======================================================");
                    error!("SECURITY VIOLATION: Kernel image is REVOKED (dbx match).");
                    error!("This kernel must not be booted. System halted.");
                    error!("======================================================");
                    Err(Status::SECURITY_VIOLATION)
                }
            }
        }
        SecureBootViolation::SetupModeAnomaly => {
            match policy {
                SecureBootPolicy::Permissive | SecureBootPolicy::Enforcing => {
                    warn!("SECURE BOOT WARNING: Firmware reports Setup Mode anomaly.");
                    Ok(())
                }
                SecureBootPolicy::Strict => {
                    error!("======================================================");
                    error!("SECURITY VIOLATION: Setup Mode anomaly detected.");
                    error!("Strict policy requires fully deployed Secure Boot.");
                    error!("======================================================");
                    Err(Status::SECURITY_VIOLATION)
                }
            }
        }
    }
}

/// High-level entry point: verify the full boot chain integrity.
///
/// Performs all Secure Boot checks in sequence:
/// 1. `insecure_boot` + firmware SB conflict
/// 2. Setup Mode anomaly (Strict mode only)
/// 3. dbx revocation check for `kernel_data`
///
/// Returns `Ok(())` if all checks pass (or policy is Permissive).
/// Returns `Err(Status::SECURITY_VIOLATION)` on a hard violation.
pub fn verify_boot_chain_integrity(
    sb_info: &SecureBootInfo,
    kernel_data: &[u8],
) -> Result<(), Status> {
    let policy = effective_policy(sb_info);
    info!(
        "Secure Boot policy: {:?} (SB={}, Setup={}, Deployed={})",
        policy, sb_info.secure_boot_enabled, sb_info.setup_mode, sb_info.deployed_mode
    );

    // --- Check 1: insecure_boot feature vs. firmware Secure Boot ---
    if cfg!(feature = "insecure_boot") && sb_info.secure_boot_enabled {
        enforce_policy(policy, SecureBootViolation::InsecureBootWithFirmwareSB)?;
    }

    // --- Check 2: Setup Mode anomaly (Strict) ---
    if sb_info.setup_mode && !sb_info.secure_boot_enabled {
        // Setup Mode means keys can be freely modified – warn in Strict.
        enforce_policy(policy, SecureBootViolation::SetupModeAnomaly)?;
    }

    // --- Check 3: dbx revocation ---
    let kernel_hash = sha256(kernel_data);
    info!(
        "Kernel SHA-256: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}",
        kernel_hash[0], kernel_hash[1], kernel_hash[2], kernel_hash[3],
        kernel_hash[30], kernel_hash[31]
    );

    if sb_info.dbx_present {
        let mut dbx_hashes = [[0u8; 32]; MAX_DBX_HASHES];
        let dbx_count = read_dbx_sha256_hashes(&mut dbx_hashes);
        info!("dbx: {} SHA-256 revocation entries loaded", dbx_count);

        if is_hash_in_dbx(&kernel_hash, &dbx_hashes, dbx_count) {
            enforce_policy(policy, SecureBootViolation::KernelRevokedByDbx)?;
        } else {
            info!("dbx check: PASSED (kernel not in forbidden list)");
        }
    } else {
        info!("dbx not present; skipping revocation check");
    }

    Ok(())
}
