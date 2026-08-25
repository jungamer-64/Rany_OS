use qemu_runner::{RunConfig, run_fullboot};

fn main() {
    let mut args = std::env::args(); // nosemgrep: codacy.tools-configs.rust.lang.security.args.args
    let _bin = args.next();
    let profile = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("usage: qemu-runner <profile> [case-id]");
            std::process::exit(2);
        }
    };

    let mut config = RunConfig::for_profile(profile);
    config.case_filter = args.next();

    if let Ok(v) = std::env::var("QEMU_TEST_TIMEOUT_SECS")
        && let Ok(parsed) = v.parse::<u64>()
    {
        config.timeout_secs = parsed;
    }
    if let Ok(v) = std::env::var("QEMU_TEST_SMP")
        && let Ok(parsed) = v.parse::<u16>()
    {
        config.smp = parsed;
    }
    if let Ok(v) = std::env::var("QEMU_TEST_MAX_CPUS")
        && let Ok(parsed) = v.parse::<u16>()
    {
        config.max_cpus = parsed;
    }

    match run_fullboot(&config) {
        Ok(report) => {
            eprintln!(
                "full-boot profile '{}' passed in {:?} (log: {})",
                report.profile,
                report.duration,
                report.log_path.display()
            );
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
