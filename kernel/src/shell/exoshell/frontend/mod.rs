// ============================================================================
// kernel/src/shell/exoshell/frontend/mod.rs
// ============================================================================

pub mod serial;

use alloc::string::String;

use super::error::ExoResult;
use super::shell::ExoShell;
use super::types::ExoValue;

/// Shell Frontend Trait
///
/// Abstracts the input/output mechanism of the shell.
/// Implementations handle:
/// - Reading input lines (including line editing if applicable)
/// - Displaying prompts
/// - Displaying command outputs
pub trait ShellFrontend {
    /// Read a line of input
    ///
    /// This method is responsible for blocking/awaiting until a full line is ready.
    fn read_line(
        &mut self,
        shell: &mut ExoShell,
    ) -> impl core::future::Future<Output = Option<String>> + Send;

    /// Display the command prompt
    fn print_prompt(&mut self, cwd: &str);

    /// Display the result of a command execution
    fn print_result(&mut self, result: &ExoResult<ExoValue<'static>>);

    /// Display a generic message (e.g. welcome message)
    fn print_message(&mut self, msg: &str);
}
