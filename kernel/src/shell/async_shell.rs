// ============================================================================
// src/shell/async_shell.rs - ExoShell Async REPL
// ============================================================================
//!
//! # Async ExoShell Task
//!
//! Interrupt-driven ExoShell REPL using async/await.
//! Replaces polling-based input with IRQ4-triggered futures.
//!
//! Features:
//! - History navigation (/ arrow keys)
//! - Tab completion (namespace, method, file path)
//! - ANSI color prompts

use alloc::format;

use super::exoshell::ExoShell;
use super::exoshell::ExoValue;
use super::exoshell::frontend::ShellFrontend;
use super::exoshell::frontend::serial::SerialFrontend;

/// ANSI escape codes for colors
mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
}

/// Async shell task
/// This function runs as an async task and handles serial input via interrupts
pub async fn run_async_shell() {
    crate::console::write("\n");
    crate::console::write(&format!("{}{}", ansi::CYAN, ansi::RESET));
    crate::console::write("\n");
    crate::console::write(&format!(
        "{}{}  RanyOS ExoShell v0.3                            {}{}",
        ansi::CYAN,
        ansi::WHITE,
        ansi::CYAN,
        ansi::RESET
    ));
    crate::console::write("\n");
    crate::console::write(&format!(
        "{}{}  Type 'help' for available commands              {}{}",
        ansi::CYAN,
        ansi::WHITE,
        ansi::CYAN,
        ansi::RESET
    ));
    crate::console::write("\n");
    crate::console::write(&format!(
        "{}{}  Use / for history, Tab for completion         {}{}",
        ansi::CYAN,
        ansi::WHITE,
        ansi::CYAN,
        ansi::RESET
    ));
    crate::console::write("\n");
    crate::console::write(&format!("{}{}\n", ansi::CYAN, ansi::RESET));
    crate::console::write("\n");

    let mut exoshell = ExoShell::new();
    // Yield after heavy ExoShell allocation
    crate::task::yield_now().await;

    let mut frontend = SerialFrontend::new();

    // Print initial prompt
    frontend.print_prompt(exoshell.cwd.as_str());

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        match frontend.read_line(&mut exoshell).await {
            Some(line) => {
                let result = exoshell.eval(&line).await;

                if let ExoValue::Exit = result {
                    frontend.print_message("\nGoodbye!");
                    break;
                }

                // execute() uses print_result for normal output too
                frontend.print_result(&Ok(result));
            }
            None => {
                // Should not happen for serial unless we implement Ctrl-D
                break;
            }
        }

        frontend.print_prompt(exoshell.cwd.as_str());
    }

    crate::console::write("\n");
    crate::console::write(&format!("[SHELL] ExoShell terminated"));
    crate::console::write("\n");
}

/// Start the async shell task
pub fn spawn_async_shell() {
    match crate::task::spawn(run_async_shell(), crate::task::TaskPlacement::Any) {
        Ok(_) => crate::console::write("[SHELL] ExoShell task spawned\n"),
        Err(error) => log::error!("failed to schedule ExoShell: {:?}", error),
    }
}
