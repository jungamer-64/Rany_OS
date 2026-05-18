//! AMD SME/SEV and Intel TDX Memory Encryption Detection
//!
//! This module detects hardware memory encryption features available
//! on the platform and provides information for secure memory handling.

use log::info;

/// Memory encryption capabilities
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryEncryptionInfo {
    /// SME (Secure Memory Encryption) is available
    pub sme_available: bool,
    /// SEV (Secure Encrypted Virtualization) is available
    pub sev_available: bool,
    /// SEV-ES (Encrypted State) is available
    pub sev_es_available: bool,
    /// SEV-SNP (Secure Nested Paging) is available
    pub sev_snp_available: bool,
    /// SME is currently enabled
    pub sme_enabled: bool,
    /// SEV is currently enabled (running in SEV guest)
    pub sev_enabled: bool,
    /// C-bit position in page table entries (AMD specific)
    /// This bit, when set, indicates the page should be encrypted
    pub c_bit_position: u8,
    /// Physical address reduction due to encryption
    /// (number of bits reduced from physical address space)
    pub phys_addr_reduction: u8,
    /// Encryption mask to apply to page table entries
    pub encryption_mask: u64,
    /// Intel TDX (Trust Domain Extensions) is available
    pub tdx_available: bool,
}

/// CPUID leaf for AMD SEV capabilities
const CPUID_AMD_SEV_LEAF: u32 = 0x8000_001F;

/// CPUID extended function to check maximum supported
const CPUID_EXTENDED_MAX: u32 = 0x8000_0000;

/// MSR for AMD SEV status
const MSR_AMD_SEV_STATUS: u32 = 0xC001_0131;

/// Detect memory encryption capabilities
///
/// Uses CPUID to detect AMD SME/SEV and Intel TDX support.
/// For AMD platforms, also reads MSR to check if encryption is enabled.
pub fn detect_memory_encryption() -> MemoryEncryptionInfo {
    let mut info = MemoryEncryptionInfo::default();

    let max_extended = cpuid(CPUID_EXTENDED_MAX).eax;
    if max_extended >= CPUID_AMD_SEV_LEAF {
        detect_amd_sev_capabilities(&mut info);
    }

    info.tdx_available = detect_intel_tdx();
    log_detected_encryption(&info);
    info
}

/// AMD SEV/SME 機能をCPUIDおよびMSRから検出
fn detect_amd_sev_capabilities(info: &mut MemoryEncryptionInfo) {
    let sev_cpuid = cpuid(CPUID_AMD_SEV_LEAF);

    info.sme_available = (sev_cpuid.eax & (1 << 0)) != 0;
    info.sev_available = (sev_cpuid.eax & (1 << 1)) != 0;
    info.sev_es_available = (sev_cpuid.eax & (1 << 3)) != 0;
    info.sev_snp_available = (sev_cpuid.eax & (1 << 4)) != 0;

    info.c_bit_position = (sev_cpuid.ebx & 0x3F) as u8;
    info.phys_addr_reduction = ((sev_cpuid.ebx >> 6) & 0x3F) as u8;

    if info.c_bit_position > 0 && info.c_bit_position < 64 {
        info.encryption_mask = 1u64 << info.c_bit_position;
    }

    if info.sme_available || info.sev_available {
        if let Some(msr_value) = read_sev_status_msr() {
            info.sev_enabled = (msr_value & (1 << 0)) != 0;
            info.sme_enabled = (msr_value & (1 << 23)) != 0;
        }
    }
}

/// 検出されたメモリ暗号化機能をログ出力
fn log_detected_encryption(info: &MemoryEncryptionInfo) {
    if info.sme_available {
        info!("AMD SME detected (C-bit position: {})", info.c_bit_position);
    }
    if info.sev_available {
        info!("AMD SEV detected (enabled: {})", info.sev_enabled);
    }
    if info.sev_es_available {
        info!("AMD SEV-ES detected");
    }
    if info.sev_snp_available {
        info!("AMD SEV-SNP detected");
    }
    if info.tdx_available {
        info!("Intel TDX detected");
    }
    let any = [info.sme_available, info.sev_available, info.tdx_available]
        .iter()
        .any(|&x| x);
    if !any {
        info!("No hardware memory encryption detected");
    }
}

/// CPUID result structure
#[derive(Debug, Clone, Copy)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

/// Execute CPUID instruction
fn cpuid(leaf: u32) -> CpuidResult {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    // Note: rbx/ebx is reserved by LLVM for PIC code, so we need to save/restore it
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            ebx_out = out(reg) ebx,
            inout("ecx") 0u32 => ecx,
            out("edx") edx,
        );
    }

    CpuidResult { eax, ebx, ecx, edx }
}

/// Read AMD SEV status MSR
/// Returns None if reading fails (e.g., on non-AMD platforms)
fn read_sev_status_msr() -> Option<u64> {
    // Only attempt on AMD platforms
    let vendor = cpuid(0);

    // Check for "AuthenticAMD"
    let is_amd = vendor.ebx == 0x6874_7541  // "Auth"
        && vendor.edx == 0x6974_6E65        // "enti"
        && vendor.ecx == 0x444D_4163; // "cAMD"

    if !is_amd {
        return None;
    }

    // Read MSR_AMD_SEV_STATUS
    let value: u64;
    unsafe {
        let low: u32;
        let high: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_AMD_SEV_STATUS,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
        value = ((high as u64) << 32) | (low as u64);
    }

    Some(value)
}

/// Detect Intel TDX (Trust Domain Extensions)
///
/// TDX detection is complex and typically involves:
/// 1. Checking CPUID leaf 0x21 for TDX signature
/// 2. Verifying we're running in a TD (Trust Domain)
fn detect_intel_tdx() -> bool {
    // Check for Intel vendor
    let vendor = cpuid(0);

    // Check for "GenuineIntel"
    let is_intel = vendor.ebx == 0x756E_6547  // "Genu"
        && vendor.edx == 0x4965_6E69          // "ineI"
        && vendor.ecx == 0x6C65_746E; // "ntel"

    if !is_intel {
        return false;
    }

    // Check if CPUID leaf 0x21 is available
    if vendor.eax < 0x21 {
        return false;
    }

    // Check for TDX signature in leaf 0x21
    let tdx_check = cpuid(0x21);

    // TDX CPUID signature: "IntelTDX    " in EBX:EDX:ECX
    // EBX = "Inte" = 0x6574_6E49
    // EDX = "lTDX" = 0x5844_546C
    // ECX = "    " = 0x2020_2020
    let is_tdx = tdx_check.ebx == 0x6574_6E49
        && tdx_check.edx == 0x5844_546C
        && tdx_check.ecx == 0x2020_2020;

    is_tdx
}

/// Get the encryption mask for page table entries
///
/// This mask should be OR'd with page table entries to mark
/// pages as encrypted when SME/SEV is enabled.
pub fn get_encryption_mask(info: &MemoryEncryptionInfo) -> u64 {
    if info.sme_enabled || info.sev_enabled {
        info.encryption_mask
    } else {
        0
    }
}
