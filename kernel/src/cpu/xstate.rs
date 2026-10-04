//! One x86 extended-state contract shared by the bootstrap and application CPUs.

use core::arch::x86_64::{__cpuid, __cpuid_count};

use crate::sync::InitOnce;

const X87: u64 = 1;
const SSE: u64 = 1 << 1;
const AVX: u64 = 1 << 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XStateConfiguration {
    Fxsave,
    Xsave { mask: u64, bytes: usize, avx2: bool },
}

/// The selected mask contains at most x87, SSE, and AVX state. The area is
/// deliberately fixed so context storage is reserved before task admission.
#[repr(C, align(64))]
pub(crate) struct XStateImage {
    bytes: [u8; 1024],
}

impl XStateImage {
    pub(crate) const fn initial() -> Self {
        let mut bytes = [0; 1024];
        // FXSAVE's initialized x87 control word and MXCSR. In XSAVE mode a
        // zero XSTATE_BV restores architectural init state for each component.
        bytes[0] = 0x7f;
        bytes[1] = 0x03;
        bytes[24] = 0x80;
        bytes[25] = 0x1f;
        Self { bytes }
    }
}

static CONFIGURATION: InitOnce<XStateConfiguration> = InitOnce::new();

pub(crate) fn configuration() -> XStateConfiguration {
    *CONFIGURATION
        .get()
        .unwrap_or_else(|| panic!("xstate policy was not initialized on the bootstrap CPU"))
}

/// Establishes the system-wide state mask before AP startup or task spawning.
pub(crate) fn initialize_boot_cpu() {
    let leaf1 = __cpuid(1);
    assert!(leaf1.edx & (1 << 26) != 0, "x86_64 kernel requires SSE2");
    let xsave = leaf1.ecx & (1 << 26) != 0;
    let avx = leaf1.ecx & (1 << 28) != 0;
    let supported = if xsave {
        __cpuid_count(0xD, 0)
    } else {
        __cpuid_count(0, 0)
    };
    let mask = X87
        | SSE
        | if avx && supported.eax & AVX as u32 != 0 {
            AVX
        } else {
            0
        };
    let mode = if xsave {
        assert!(u64::from(supported.eax) & (X87 | SSE) == X87 | SSE);
        configure_current_cpu(Some(mask));
        let size = __cpuid_count(0xD, 0).ebx as usize;
        assert!((576..=1024).contains(&size), "unsupported XSAVE area size");
        let avx2 = mask & AVX != 0 && __cpuid_count(7, 0).ebx & (1 << 5) != 0;
        XStateConfiguration::Xsave {
            mask,
            bytes: size,
            avx2,
        }
    } else {
        configure_current_cpu(None);
        XStateConfiguration::Fxsave
    };
    CONFIGURATION.call_once(|| mode);
    let simd = match mode {
        XStateConfiguration::Xsave { avx2: true, .. } => hal::mmio::simd_level::AVX2,
        XStateConfiguration::Xsave { mask, .. } if mask & AVX != 0 => hal::mmio::simd_level::AVX,
        _ => hal::mmio::simd_level::SSE2,
    };
    unsafe { hal::mmio::set_simd_level(simd) };
}

/// Returns false when a secondary CPU cannot honor the BSP's saved-state mask.
pub(crate) fn initialize_secondary_cpu() -> bool {
    let mode = configuration();
    let leaf1 = __cpuid(1);
    if leaf1.edx & (1 << 26) == 0 {
        return false;
    }
    match mode {
        XStateConfiguration::Fxsave => configure_current_cpu(None),
        XStateConfiguration::Xsave { mask, bytes, avx2 } => {
            if leaf1.ecx & (1 << 26) == 0
                || mask & AVX != 0 && leaf1.ecx & (1 << 28) == 0
                || u64::from(__cpuid_count(0xD, 0).eax) & mask != mask
                || avx2 && __cpuid_count(7, 0).ebx & (1 << 5) == 0
            {
                return false;
            }
            configure_current_cpu(Some(mask));
            if __cpuid_count(0xD, 0).ebx as usize > bytes {
                return false;
            }
        }
    }
    true
}

fn configure_current_cpu(mask: Option<u64>) {
    let mut cr0: u64;
    let mut cr4: u64;
    // SAFETY: bootstrap and AP startup execute at CPL0 before task execution.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        cr0 = (cr0 | (1 << 1)) & !((1 << 2) | (1 << 3));
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        cr4 |= (1 << 9) | (1 << 10);
        if mask.is_some() {
            cr4 |= 1 << 18;
        } else {
            cr4 &= !(1 << 18);
        }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));
        if let Some(mask) = mask {
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") mask as u32,
                in("edx") (mask >> 32) as u32,
                options(nomem, nostack),
            );
        }
        core::arch::asm!("fninit", options(nomem, nostack));
        let mxcsr: u32 = 0x1f80;
        core::arch::asm!("ldmxcsr [{}]", in(reg) &mxcsr, options(readonly, nostack));
    }
}
