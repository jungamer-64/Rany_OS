//! Firmware memory types are immutable while retained MMIO capabilities exist.
//! A secondary CPU joins only with the same PAT/MTRR interpretation as the BSP.

use crate::sync::InitOnce;

const FIXED_MSRS: [u32; 11] = [
    0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f,
];

#[derive(PartialEq, Eq)]
struct CachePolicy {
    capability: u64,
    default: u64,
    pat: u64,
    physical_mask: u64,
    variable: [(u64, u64); 256],
    fixed: [u64; 11],
}

static POLICY: InitOnce<CachePolicy> = InitOnce::new();

pub(crate) fn initialize_boot_cpu() {
    let mut policy = read_policy().unwrap_or_else(|| panic!("PAT/MTRR policy unavailable"));
    policy.pat = (policy.pat & !(255u64 << 40)) | (1u64 << 40);
    install_pat(policy.pat);
    POLICY.call_once(|| policy);
}

pub(crate) fn validate_secondary_cpu() -> bool {
    let Some(expected) = POLICY.get() else {
        return false;
    };
    let Some(mut observed) = read_policy() else {
        return false;
    };
    observed.pat = expected.pat;
    if &observed != expected {
        return false;
    }
    install_pat(expected.pat);
    read_policy().as_ref() == Some(expected)
}

/// Called with interrupts disabled, before this CPU can run tasks. Boot mappings
/// use PAT0..3, while WC uses kernel-owned PAT5. SDM Vol. 3A 13.12.4 requires
/// retirement of global TLB entries and cached lines around PAT changes.
fn install_pat(value: u64) {
    // SAFETY: boot executes at CPL0 before this CPU is admitted. This sequence
    // selects PCID zero before disabling PCIDE, preserves CR3/CR4, invalidates
    // all local translations, drains cached data, and
    // installs only the feature-validated legal WC encoding in PAT5. Compiler
    // memory ordering is retained by the asm block.
    unsafe {
        core::arch::asm!(
            "mov {root}, cr3", "mov {temporary}, {root}",
            "and {temporary}, {root_mask}", "mov cr3, {temporary}",
            "mov {saved}, cr4", "mov {temporary}, {saved}",
            "and {temporary}, {mask}", "mov cr4, {temporary}",
            "mov {temporary}, cr3", "mov cr3, {temporary}",
            "wbinvd", "wrmsr", "wbinvd", "mov cr4, {saved}",
            "mov cr3, {root}",
            root = out(reg) _, root_mask = in(reg) !4095u64,
            saved = out(reg) _, temporary = out(reg) _,
            mask = in(reg) !(1u64 << 7 | 1u64 << 17),
            in("ecx") 0x277u32, in("eax") value as u32, in("edx") (value >> 32) as u32,
            options(nostack),
        );
    }
}

fn read_policy() -> Option<CachePolicy> {
    let leaf = core::arch::x86_64::__cpuid(1);
    if leaf.edx & ((1 << 12) | (1 << 16)) != (1 << 12) | (1 << 16) {
        return None;
    }
    let extended = core::arch::x86_64::__cpuid(0x8000_0000);
    let bits = if extended.eax >= 0x8000_0008 {
        core::arch::x86_64::__cpuid(0x8000_0008).eax & 255
    } else {
        36
    };
    if !(32..=52).contains(&bits) {
        return None;
    }
    let capability = read_msr(0xfe);
    let mut policy = CachePolicy {
        capability,
        default: read_msr(0x2ff),
        pat: read_msr(0x277),
        physical_mask: ((1u64 << bits) - 1) & !4095,
        variable: [(0, 0); 256],
        fixed: [0; 11],
    };
    for (index, pair) in policy
        .variable
        .iter_mut()
        .take((capability & 255) as usize)
        .enumerate()
    {
        let msr = 0x200 + index as u32 * 2;
        *pair = (read_msr(msr), read_msr(msr + 1));
    }
    if capability & (1 << 8) != 0 {
        for (value, msr) in policy.fixed.iter_mut().zip(FIXED_MSRS) {
            *value = read_msr(msr);
        }
    }
    Some(policy)
}

fn read_msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: this private path runs at CPL0 and reads only feature-validated,
    // architecturally defined PAT/MTRR registers; it never modifies cache policy.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") index,
        out("eax") low, out("edx") high, options(nomem, nostack));
    }
    u64::from(low) | (u64::from(high) << 32)
}

/// Validates the effective type, not merely PCD or a BAR's prefetchability bit.
/// SDM Vol. 3A memory-cache control: PAT UC is UC; PAT WB combined with an
/// entirely UC MTRR aperture is UC. Other combinations are rejected here.
pub(crate) fn is_uncached(physical: u64, length: usize, pat_index: u8) -> bool {
    if length == 0 || pat_index > 7 {
        return false;
    }
    let Some(policy) = POLICY.get() else {
        return false;
    };
    let pat = (policy.pat >> (u32::from(pat_index) * 8)) & 255;
    if pat == 0 {
        return true;
    }
    if pat != 6 {
        return false;
    }
    let Some(end) = physical.checked_add(length as u64 - 1) else {
        return false;
    };
    let first_page = physical & !4095;
    let last_page = end & !4095;
    let pages = (last_page - first_page) / 4096 + 1;
    (0..pages).all(|page| policy.mtrr_type(first_page + page * 4096) == Some(0))
}

impl CachePolicy {
    fn mtrr_type(&self, physical: u64) -> Option<u8> {
        if self.default & (1 << 11) == 0 {
            return Some(0);
        }
        if physical < 0x10_0000 && self.default & (1 << 10) != 0 && self.capability & (1 << 8) != 0
        {
            let (register, lane) = if physical < 0x8_0000 {
                (0, physical / 0x1_0000)
            } else if physical < 0xc_0000 {
                (
                    1 + ((physical - 0x8_0000) / 0x2_0000) as usize,
                    (physical % 0x2_0000) / 0x4000,
                )
            } else {
                (
                    3 + ((physical - 0xc_0000) / 0x8000) as usize,
                    (physical % 0x8000) / 4096,
                )
            };
            return Some(((self.fixed[register] >> (lane * 8)) & 255) as u8);
        }
        let mut selected = None;
        let mut mixed = false;
        for &(base, mask) in &self.variable[..(self.capability & 255) as usize] {
            if mask & (1 << 11) == 0 {
                continue;
            }
            let address_mask = mask & self.physical_mask;
            if physical & address_mask != base & address_mask {
                continue;
            }
            let kind = (base & 255) as u8;
            if kind == 0 {
                return Some(0);
            }
            selected = match selected {
                None => Some(kind),
                Some(previous) if previous == kind => Some(kind),
                Some(4 | 6) if matches!(kind, 4 | 6) => Some(4),
                Some(previous) => {
                    mixed = true;
                    Some(previous)
                }
            };
        }
        if mixed {
            None
        } else {
            Some(selected.unwrap_or((self.default & 255) as u8))
        }
    }
}

/// PAT5 is WC and valid MTRR types combine with PAT WC as WC (SDM Table 13-7).
/// Unknown or conflicting firmware MTRRs are not admitted.
pub(crate) fn is_write_combining(physical: u64, length: usize, pat_index: u8) -> bool {
    let Some(policy) = POLICY.get() else {
        return false;
    };
    if length == 0 || pat_index > 7 || (policy.pat >> (u32::from(pat_index) * 8)) & 255 != 1 {
        return false;
    }
    let Some(last) = physical.checked_add(length as u64 - 1) else {
        return false;
    };
    let first = physical & !4095;
    (0..((last & !4095) - first) / 4096 + 1).all(|page| {
        matches!(
            policy.mtrr_type(first + page * 4096),
            Some(0 | 1 | 4 | 5 | 6)
        )
    })
}
