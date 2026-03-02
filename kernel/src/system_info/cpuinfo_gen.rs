// ============================================================================
// kernel/src/system_info/cpuinfo_gen.rs - CPU info helpers
// ============================================================================
//! CPUベンダー・モデル名取得ヘルパー。

pub(crate) fn get_cpu_vendor() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        let result = __cpuid(0);
        let vendor_bytes = [
            (result.ebx as u8),
            ((result.ebx >> 8) as u8),
            ((result.ebx >> 16) as u8),
            ((result.ebx >> 24) as u8),
            (result.edx as u8),
            ((result.edx >> 8) as u8),
            ((result.edx >> 16) as u8),
            ((result.edx >> 24) as u8),
            (result.ecx as u8),
            ((result.ecx >> 8) as u8),
            ((result.ecx >> 16) as u8),
            ((result.ecx >> 24) as u8),
        ];
        if &vendor_bytes[..12] == b"GenuineIntel" {
            "GenuineIntel"
        } else if &vendor_bytes[..12] == b"AuthenticAMD" {
            "AuthenticAMD"
        } else {
            "Unknown"
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "Unknown"
    }
}

pub(crate) fn get_cpu_model_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        let result = __cpuid(0x80000000);
        if result.eax >= 0x80000004 {
            let vendor = get_cpu_vendor();
            if vendor == "GenuineIntel" {
                "Intel(R) Core(TM) Processor"
            } else if vendor == "AuthenticAMD" {
                "AMD Processor"
            } else {
                "Unknown Processor"
            }
        } else {
            "Unknown Processor"
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "Unknown Processor"
    }
}
