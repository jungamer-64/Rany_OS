use qemu_runner::{RunConfig, run_suite};

fn main() {
    let mut args = std::env::args(); // nosemgrep: codacy.tools-configs.rust.lang.security.args.args
    let _bin = args.next();
    let suite = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("usage: qemu-runner <suite>");
            std::process::exit(2);
        }
    };

    let mut config = RunConfig::for_suite(suite);
    if let Ok(v) = std::env::var("QEMU_TEST_TIMEOUT_SECS") {
        if let Ok(parsed) = v.parse::<u64>() {
            config.timeout_secs = parsed;
        }
    }

    match run_suite(config) {
        Ok(report) => {
            eprintln!(
                "suite '{}' passed in {:?} (log: {})",
                report.suite,
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
