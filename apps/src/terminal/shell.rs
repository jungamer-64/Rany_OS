// ============================================================================
// apps/src/terminal/shell.rs - Shell Command Execution
// ============================================================================
//!
//! Shell command parsing and execution logic.
//! This module handles commands that are not built-in to the terminal.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::string::String;
use alloc::vec::Vec;

use app_sdk::AppContext;

/// Shell command result
#[derive(Debug, Clone)]
pub enum ShellResult {
    /// Successful output
    Output(String),
    /// Array of results
    Array(Vec<String>),
    /// Binary data
    Bytes(Vec<u8>),
    /// No output
    None,
    /// Error message
    Error(String),
}

/// Parse and execute a shell command
///
/// This is a stub that can be connected to the kernel's ExoShell
/// via KernelServices or IPC.
pub async fn execute_command(cmd: &str, cwd: &str) -> ShellResult {
    execute_command_with_context(cmd, cwd, None).await
}

/// Parse and execute a shell command with optional AppContext
pub async fn execute_command_with_context(
    cmd: &str,
    cwd: &str,
    ctx: Option<&AppContext>,
) -> ShellResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    if parts.is_empty() {
        return ShellResult::None;
    }

    match parts[0] {
        "echo" => {
            let output = parts[1..].join(" ");
            ShellResult::Output(output)
        }
        "ls" => {
            if ctx.and_then(|c| c.fs()).is_none() {
                return ShellResult::Error(String::from("filesystem capability not granted"));
            }
            ShellResult::Output(format!("(ls not implemented yet for {})", cwd))
        }
        "cat" => {
            if parts.len() < 2 {
                ShellResult::Error(String::from("usage: cat <file>"))
            } else {
                if ctx.and_then(|c| c.fs()).is_none() {
                    return ShellResult::Error(String::from("filesystem capability not granted"));
                }
                ShellResult::Output(format!("(cat not implemented yet for {})", parts[1]))
            }
        }
        "ps" => {
            if ctx.and_then(|c| c.task()).is_none() {
                return ShellResult::Error(String::from("task capability not granted"));
            }
            ShellResult::Output(String::from("(ps not implemented yet)"))
        }
        "net" => {
            if ctx.and_then(|c| c.net()).is_none() {
                return ShellResult::Error(String::from("network capability not granted"));
            }
            ShellResult::Output(String::from("(net not implemented yet)"))
        }
        _ => ShellResult::Error(format!("command not found: {}", parts[0])),
    }
}

/// Get tab completions for the current input
pub fn get_completions(input: &str, cwd: &str) -> Vec<String> {
    let mut completions = Vec::new();

    // Built-in command completions
    let builtins = [
        "help", "exit", "quit", "clear", "pwd", "cd", "echo", "ls", "cat", "ps", "net",
    ];

    for cmd in &builtins {
        if cmd.starts_with(input) {
            completions.push(String::from(*cmd));
        }
    }

    completions
}
