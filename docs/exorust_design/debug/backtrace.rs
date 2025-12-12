//! パニック時バックトレース
//!
//! 設計書セクション 10.5.1 参照

/// バックトレースフレーム
pub struct BacktraceFrame {
    pub function: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

/// パニック時のバックトレース出力
/// 
/// `gimli` クレートを使用したDWARFアンワインドにより、
/// パニック時に詳細なバックトレースを出力する
pub fn print_backtrace() {
    let mut frames = Vec::new();
    
    // gimliを使用してスタックをアンワインド
    let mut ctx = UnwindContext::new();
    let mut cursor = UnwindCursor::new(&ctx);
    
    while let Ok(true) = cursor.step() {
        if let Some(name) = cursor.function_name() {
            frames.push(BacktraceFrame {
                function: demangle(name),
                file: cursor.source_file(),
                line: cursor.source_line(),
            });
        }
    }
    
    // フォーマット出力
    for (i, frame) in frames.iter().enumerate() {
        log::error!("  {:>2}: {} at {}:{}", 
            i, 
            frame.function, 
            frame.file.as_deref().unwrap_or("<unknown>"), 
            frame.line.unwrap_or(0));
    }
}

/// 出力例:
/// ```text
/// PANIC: index out of bounds: the len is 10 but the index is 15
///   0: core::panicking::panic_bounds_check at core/src/panicking.rs:163
///   1: network_driver::handle_packet at drivers/network/src/lib.rs:245
///   2: executor::poll_task at kernel/executor/src/lib.rs:89
/// ```

// 以下はプレースホルダー
struct UnwindContext;
impl UnwindContext {
    fn new() -> Self { Self }
}

struct UnwindCursor<'a>(&'a UnwindContext);
impl<'a> UnwindCursor<'a> {
    fn new(_ctx: &'a UnwindContext) -> Self { Self(_ctx) }
    fn step(&mut self) -> Result<bool, ()> { Ok(false) }
    fn function_name(&self) -> Option<&str> { None }
    fn source_file(&self) -> Option<String> { None }
    fn source_line(&self) -> Option<u32> { None }
}

fn demangle(name: &str) -> String { name.to_string() }

mod log {
    pub fn error(_fmt: std::fmt::Arguments) {}
    macro_rules! error {
        ($($arg:tt)*) => { $crate::log::error(format_args!($($arg)*)) };
    }
    pub(crate) use error;
}
use log::error;
