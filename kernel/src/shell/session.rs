// ============================================================================
// src/shell/session.rs - Unified Shell Session
// ============================================================================
//!
//! # Shell Session
//!
//! Manages the Read-Eval-Print Loop (REPL) for the ExoShell.
//! Abstracts the input/output details via the `ShellFrontend` trait.
//!

use alloc::format;
use boot_proto::{BootPolicy, BootShellMode};

use crate::shell::exoshell::frontend::ShellFrontend;
use crate::shell::exoshell::{ExoShell, ExoValue};
use crate::util;

/// Shell launch mode selected from kernel command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellLaunchMode {
    Console,
    Serial,
    Both,
    Off,
}

impl Default for ShellLaunchMode {
    fn default() -> Self {
        Self::Console
    }
}

pub fn shell_launch_mode_from_boot_policy(policy: &BootPolicy) -> ShellLaunchMode {
    match policy.shell_mode {
        BootShellMode::Console => ShellLaunchMode::Console,
        BootShellMode::Serial => ShellLaunchMode::Serial,
        BootShellMode::Both => ShellLaunchMode::Both,
        BootShellMode::Off => ShellLaunchMode::Off,
    }
}

/// Parse shell launch mode from kernel cmdline.
///
/// Priority:
/// 1. `shell=...` (canonical)
/// 2. `console=serial|both` (compat fallback)
pub fn parse_shell_launch_mode(cmdline: Option<&str>) -> ShellLaunchMode {
    let Some(cmdline) = cmdline else {
        return ShellLaunchMode::default();
    };

    if let Some(shell) = util::get_cmdline_option(cmdline, "shell") {
        return match shell {
            "console" => ShellLaunchMode::Console,
            "serial" => ShellLaunchMode::Serial,
            "both" => ShellLaunchMode::Both,
            "off" => ShellLaunchMode::Off,
            _ => ShellLaunchMode::default(),
        };
    }

    if let Some(console) = util::get_cmdline_option(cmdline, "console") {
        return match console {
            "serial" => ShellLaunchMode::Serial,
            "both" => ShellLaunchMode::Both,
            _ => ShellLaunchMode::default(),
        };
    }

    ShellLaunchMode::default()
}

/// Downgrade shell launch mode when the framebuffer console is unavailable.
pub fn adjust_shell_launch_mode_for_console_availability(
    mode: ShellLaunchMode,
    console_available: bool,
) -> ShellLaunchMode {
    if console_available {
        return mode;
    }

    match mode {
        ShellLaunchMode::Console | ShellLaunchMode::Both => ShellLaunchMode::Serial,
        ShellLaunchMode::Serial | ShellLaunchMode::Off => mode,
    }
}

/// A unified shell session that runs the REPL loop
pub struct ShellSession<F: ShellFrontend> {
    shell: ExoShell,
    frontend: F,
}

impl<F: ShellFrontend> ShellSession<F> {
    /// Create a new shell session
    pub fn new(frontend: F) -> Self {
        Self {
            shell: ExoShell::new(),
            frontend,
        }
    }

    /// Run the shell loop (async)
    pub async fn run(&mut self) {
        // Initial Greeting
        self.print_welcome();

        // Initial Prompt
        self.frontend.print_prompt(self.shell.cwd.as_str());

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            // 1. Read Line
            match self.frontend.read_line(&mut self.shell).await {
                Some(line) => {
                    // 2. Evaluate
                    let result = self.shell.eval(&line).await;

                    // 3. Check for Exit
                    if let ExoValue::Exit = result {
                        self.frontend.print_message("\nGoodbye!");
                        break;
                    }

                    // 4. Print Result
                    self.frontend.print_result(&Ok(result));
                }
                None => {
                    // End of stream
                    break;
                }
            }

            // 5. Next Prompt
            self.frontend.print_prompt(self.shell.cwd.as_str());
        }
    }

    fn print_welcome(&mut self) {
        self.frontend.print_message("\n");
        // Using ANSI colors if the frontend supports them (most do)
        // Hardcoding ANSI here might be slightly leaky but it's consistent with previous async_shell
        let cyan = "\x1b[36m";
        let white = "\x1b[37m";
        let reset = "\x1b[0m";

        self.frontend.print_message(&format!("{}{}", cyan, reset));
        self.frontend.print_message(&format!(
            "{}{}  RanyOS ExoShell v0.3                            {}{}",
            cyan, white, cyan, reset
        ));
        self.frontend.print_message(&format!(
            "{}{}  Type 'help' for available commands              {}{}",
            cyan, white, cyan, reset
        ));
        self.frontend.print_message(&format!(
            "{}{}  Use / for history, Tab for completion         {}{}",
            cyan, white, cyan, reset
        ));
        self.frontend.print_message(&format!("{}{}\n", cyan, reset));
    }
}

/// Spawn a console shell task
pub fn spawn_console_shell() {
    use crate::shell::frontend::ConsoleFrontend;
    use crate::task::Task;

    crate::task::spawn_task(Task::new(async {
        #[cfg(feature = "qemu-test-export")]
        crate::io::log::early_print("[SHELL] console shell task start\n");
        // Acquire the keyboard stream before yielding so background services
        // cannot steal the SPSC stream first.
        let mut session = ShellSession::new(ConsoleFrontend::new());
        crate::task::yield_now().await;
        crate::io::log::set_console_mirror_enabled(false);
        session.run().await;
        crate::io::log::set_console_mirror_enabled(true);
        #[cfg(feature = "qemu-test-export")]
        crate::io::log::early_print("[SHELL] console shell task exit\n");
    }));
}

/// Spawn a serial shell task
pub fn spawn_serial_shell() {
    use crate::shell::exoshell::frontend::serial::SerialFrontend;
    use crate::task::Task;

    crate::task::spawn_task(Task::new(async {
        #[cfg(feature = "qemu-test-export")]
        crate::io::log::early_print("[SHELL] serial shell task start\n");
        crate::task::yield_now().await;
        let mut session = ShellSession::new(SerialFrontend::new());
        session.run().await;
        #[cfg(feature = "qemu-test-export")]
        crate::io::log::early_print("[SHELL] serial shell task exit\n");
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn parse_shell_mode_defaults_to_console() {
        assert_eq!(parse_shell_launch_mode(None), ShellLaunchMode::Console);
        assert_eq!(parse_shell_launch_mode(Some("")), ShellLaunchMode::Console);
    }

    #[test_case]
    fn parse_shell_mode_from_shell_key() {
        assert_eq!(
            parse_shell_launch_mode(Some("shell=serial")),
            ShellLaunchMode::Serial
        );
        assert_eq!(
            parse_shell_launch_mode(Some("shell=both")),
            ShellLaunchMode::Both
        );
        assert_eq!(
            parse_shell_launch_mode(Some("shell=off")),
            ShellLaunchMode::Off
        );
    }

    #[test_case]
    fn parse_shell_mode_uses_console_key_as_compat_fallback() {
        assert_eq!(
            parse_shell_launch_mode(Some("console=serial")),
            ShellLaunchMode::Serial
        );
        assert_eq!(
            parse_shell_launch_mode(Some("console=both")),
            ShellLaunchMode::Both
        );
    }

    #[test_case]
    fn parse_shell_mode_prefers_shell_key_over_console_key() {
        assert_eq!(
            parse_shell_launch_mode(Some("shell=console console=serial")),
            ShellLaunchMode::Console
        );
    }
}
