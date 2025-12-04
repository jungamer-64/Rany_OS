// ============================================================================
// src/shell/async_shell.rs - Async Interactive Shell
// ============================================================================
//!
//! # Async Shell Task
//!
//! Interrupt-driven serial shell using async/await.
//! Replaces polling-based input with IRQ4-triggered futures.
//!
//! Supports two modes:
//! - Classic mode: Unix-like commands (ls, cd, cat, etc.)
//! - ExoShell mode: Rust-style REPL with typed objects

use alloc::string::String;
use alloc::format;
use super::{Shell, CommandResult};
use super::exoshell::{ExoShell, ExoValue};
use crate::io::serial;

/// Shell mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellMode {
    /// Classic Unix-like shell
    Classic,
    /// ExoShell Rust-style REPL
    ExoShell,
}

/// Async shell task
/// This function runs as an async task and handles serial input via interrupts
pub async fn run_async_shell() {
    crate::serial_println!("\n");
    crate::serial_println!("===========================================");
    crate::serial_println!("  RanyOS Async Shell v0.2");
    crate::serial_println!("  Type 'help' for available commands");
    crate::serial_println!("  Type 'exo' to switch to ExoShell mode");
    crate::serial_println!("  IRQ4 interrupt-driven input enabled");
    crate::serial_println!("===========================================\n");
    
    let mut shell = Shell::new();
    let mut exoshell = ExoShell::new();
    let mut mode = ShellMode::Classic;
    
    // Print initial prompt
    serial::serial1().send_str(shell.prompt());
    
    loop {
        // Wait for a line of input (interrupt-driven)
        let line = serial::read_line().await;
        
        // Handle empty line
        if line.is_empty() {
            print_prompt(mode, &shell, &exoshell);
            continue;
        }

        // Check for mode switch commands
        if line.trim() == "exo" || line.trim() == "exoshell" {
            mode = ShellMode::ExoShell;
            serial::serial1().send_str("\n");
            serial::serial1().send_str("╔═══════════════════════════════════════════╗\n");
            serial::serial1().send_str("║  ExoShell - Rust式REPL環境                ║\n");
            serial::serial1().send_str("║  Type 'help' for ExoShell commands        ║\n");
            serial::serial1().send_str("║  Type 'classic' to return to classic mode ║\n");
            serial::serial1().send_str("╚═══════════════════════════════════════════╝\n");
            print_prompt(mode, &shell, &exoshell);
            continue;
        }
        
        if line.trim() == "classic" || line.trim() == "shell" {
            mode = ShellMode::Classic;
            serial::serial1().send_str("\nSwitched to classic shell mode.\n");
            print_prompt(mode, &shell, &exoshell);
            continue;
        }

        match mode {
            ShellMode::Classic => {
                // Execute the command in classic mode
                let result = shell.execute(&line);
                
                // Handle result
                match result {
                    CommandResult::Success => {}
                    CommandResult::Output(ref s) => {
                        serial::serial1().send_str(s);
                    }
                    CommandResult::Error(ref e) => {
                        serial::serial1().send_str("Error: ");
                        serial::serial1().send_str(e);
                        serial::serial1().send_str("\n");
                    }
                    CommandResult::Exit(code) => {
                        serial::serial1().send_str(&format!("Shell exiting with code {}\n", code));
                        break;
                    }
                    CommandResult::ChangeDir(_) => {}
                }
                
                if !shell.is_running() {
                    break;
                }
            }
            ShellMode::ExoShell => {
                // Execute in ExoShell mode
                let result = exoshell.eval(&line);
                
                // Display result
                match &result {
                    ExoValue::Nil => {}
                    ExoValue::Error(e) => {
                        serial::serial1().send_str("Error: ");
                        serial::serial1().send_str(e);
                        serial::serial1().send_str("\n");
                    }
                    ExoValue::Bytes(bytes) => {
                        // Display bytes as UTF-8 if possible
                        if let Ok(text) = core::str::from_utf8(bytes) {
                            serial::serial1().send_str(text);
                            if !text.ends_with('\n') {
                                serial::serial1().send_str("\n");
                            }
                        } else {
                            serial::serial1().send_str(&format!("<{} bytes>\n", bytes.len()));
                        }
                    }
                    ExoValue::Array(items) => {
                        for item in items {
                            serial::serial1().send_str(&format!("{}\n", item));
                        }
                    }
                    other => {
                        serial::serial1().send_str(&format!("{}\n", other));
                    }
                }
            }
        }
        
        // Print next prompt
        print_prompt(mode, &shell, &exoshell);
    }
    
    crate::serial_println!("\n[SHELL] Async shell terminated");
}

fn print_prompt(mode: ShellMode, shell: &Shell, exoshell: &ExoShell) {
    match mode {
        ShellMode::Classic => {
            serial::serial1().send_str(shell.prompt());
        }
        ShellMode::ExoShell => {
            serial::serial1().send_str(&exoshell.prompt());
        }
    }
}

/// Start the async shell task
pub fn spawn_async_shell() {
    crate::task::spawn(run_async_shell());
    crate::serial_println!("[SHELL] Async shell task spawned");
}
