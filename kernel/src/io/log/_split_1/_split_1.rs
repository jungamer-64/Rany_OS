use super::*;


/// 文字列からログレベルを設定
///
/// シェルコマンド等から呼び出される。
/// alloc依存を排除し、ゼロアロケーションで比較を行います。
///
/// # Arguments
/// * `level_str` - "error", "warn", "info", "debug", "trace" のいずれか（大文字小文字不問）
///
/// # Returns
/// 設定成功時は`Ok(新レベル)`、無効な文字列は`Err`
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



/// Prints formatted arguments to the serial port.
/// Used by println!/eprintln! macros in lib.rs
pub fn print(args: core::fmt::Arguments) {
    struct SerialWriter;
    impl core::fmt::Write for SerialWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            KernelLogger::write_raw(s);
            Ok(())
        }
    }
    let _ = core::fmt::Write::write_fmt(&mut SerialWriter, args);
}
