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

use crate::shell::exoshell::frontend::ShellFrontend;
use crate::shell::exoshell::{ExoShell, ExoValue};

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
pub fn spawn_console_shell(executor: &mut crate::task::Executor) {
    use crate::task::Task;
    use crate::shell::frontend::ConsoleFrontend;

    executor.spawn(Task::new(async {
        crate::task::yield_now().await;
        // Wait a bit more for drivers?
        let mut session = ShellSession::new(ConsoleFrontend::new());
        session.run().await;
    }));
}

/// Spawn a serial shell task
pub fn spawn_serial_shell(executor: &mut crate::task::Executor) {
    use crate::task::Task;
    use crate::shell::exoshell::frontend::serial::SerialFrontend;

    executor.spawn(Task::new(async {
        crate::task::yield_now().await;
        let mut session = ShellSession::new(SerialFrontend::new());
        session.run().await;
    }));
}
