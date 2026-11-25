use super::*;

/// # Errors
/// Returns an error when the requested level name is unknown.
pub fn set_log_level_from_str(level_str: &str) -> Result<LevelFilter, &'static str> {
    // eq_ignore_ascii_case を使用してヒープアロケーションを回避
    if level_str.eq_ignore_ascii_case("off") {
        set_log_level(LevelFilter::Off);
        return Ok(LevelFilter::Off);
    }
    if level_str.eq_ignore_ascii_case("error") {
        set_log_level(LevelFilter::Error);
        return Ok(LevelFilter::Error);
    }
    if level_str.eq_ignore_ascii_case("warn") || level_str.eq_ignore_ascii_case("warning") {
        set_log_level(LevelFilter::Warn);
        return Ok(LevelFilter::Warn);
    }
    if level_str.eq_ignore_ascii_case("info") {
        set_log_level(LevelFilter::Info);
        return Ok(LevelFilter::Info);
    }
    if level_str.eq_ignore_ascii_case("debug") {
        set_log_level(LevelFilter::Debug);
        return Ok(LevelFilter::Debug);
    }
    if level_str.eq_ignore_ascii_case("trace") {
        set_log_level(LevelFilter::Trace);
        return Ok(LevelFilter::Trace);
    }

    Err("Invalid log level. Use: off, error, warn, info, debug, trace")
}
