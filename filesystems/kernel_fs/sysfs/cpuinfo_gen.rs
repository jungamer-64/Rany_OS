use crate::domain_system::list_domain_snapshots;
use alloc::string::String;
use core::sync::atomic::Ordering;


pub(crate) fn generate_cpuinfo() -> String {
    let cpu_count = crate::smp::cpu_count();
    let mut info = String::new();

    for cpu_id in 0..cpu_count {
        use core::fmt::Write;
        let _ = write!(
            info,
            "processor\t: {}\n\
             vendor_id\t: {}\n\
             cpu family\t: 6\n\
             model\t\t: 142\n\
             model name\t: {}\n\
             stepping\t: 10\n\
             cpu MHz\t\t: {:.3}\n\
             cache size\t: {} KB\n\
             physical id\t: 0\n\
             siblings\t: {}\n\
             core id\t\t: {}\n\
             cpu cores\t: {}\n\
             flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 sse sse2 ss ht syscall nx lm constant_tsc\n\
             bugs\t\t:\n\
             bogomips\t: {:.2}\n\n",
            cpu_id,
            get_cpu_vendor(),
            get_cpu_model_name(),
            3000.0,
            8192,
            cpu_count,
            cpu_id,
            cpu_count,
            6000.0
        );
    }

    info
}

pub(crate) fn generate_stat() -> String {
    let timer_ticks = crate::interrupts::get_timer_ticks();
    let ctx_switches = crate::task::context::CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed);
    let boot_time = crate::time::now().saturating_sub(crate::time::current_tick() / 1000);
    let cpu_count = crate::smp::cpu_count();
    let domain_count = list_domain_snapshots().len() as u64;

    use core::fmt::Write;
    let mut output = String::new();

    let _ = write!(
        output,
        "cpu  {} 0 {} 0 0 0 {} 0 0 0\n",
        timer_ticks / 10,
        timer_ticks / 5,
        timer_ticks / 20
    );

    for i in 0..cpu_count {
        let _ = write!(
            output,
            "cpu{} {} 0 {} 0 0 0 {} 0 0 0\n",
            i,
            timer_ticks / (10 * cpu_count as u64),
            timer_ticks / (5 * cpu_count as u64),
            timer_ticks / (20 * cpu_count as u64)
        );
    }

    let _ = write!(output, "intr {}\n", timer_ticks);
    let _ = write!(output, "ctxt {}\n", ctx_switches);
    let _ = write!(output, "btime {}\n", boot_time);
    let _ = write!(output, "processes {}\n", domain_count);
    let _ = write!(output, "procs_running 1\n");
    let _ = write!(output, "procs_blocked 0\n");
    let _ = write!(output, "softirq 0 0 0 0 0 0 0 0 0 0 0\n");

    output
}

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
