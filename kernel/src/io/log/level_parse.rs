use log::LevelFilter;

use super::set_log_level;

const DEFAULT_LEVEL: LevelFilter = if cfg!(feature = "verbose_logging") {
    LevelFilter::Trace
} else {
    LevelFilter::Info
};

fn parse(level: &str) -> Result<LevelFilter, &'static str> {
    if level.eq_ignore_ascii_case("warning") {
        return Ok(LevelFilter::Warn);
    }
    level
        .parse()
        .map_err(|_| "Invalid log level. Use: off, error, warn, info, debug, trace")
}

pub(crate) fn boot_log_level(cmdline: Option<&str>) -> (LevelFilter, Option<&str>) {
    match cmdline.and_then(|line| crate::util::get_cmdline_option(line, "loglevel")) {
        Some(value) => match parse(value) {
            Ok(level) => (level, None),
            Err(_) => (DEFAULT_LEVEL, Some(value)),
        },
        None => (DEFAULT_LEVEL, None),
    }
}

/// # Errors
/// Returns an error when the requested level name is unknown.
pub fn set_log_level_from_str(level_str: &str) -> Result<LevelFilter, &'static str> {
    let level = parse(level_str)?;
    set_log_level(level);
    Ok(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn boot_option_takes_precedence_over_the_build_default() {
        assert_eq!(boot_log_level(None), (DEFAULT_LEVEL, None));
        assert_eq!(
            boot_log_level(Some("shell=serial loglevel=debug")),
            (LevelFilter::Debug, None)
        );
        assert_eq!(
            boot_log_level(Some("loglevel=OFF")),
            (LevelFilter::Off, None)
        );
        assert_eq!(
            boot_log_level(Some("loglevel=unknown")),
            (DEFAULT_LEVEL, Some("unknown"))
        );
    }
}
