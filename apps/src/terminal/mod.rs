// ============================================================================
// apps/src/terminal/mod.rs - Terminal Application
// ============================================================================
//!
//! # Terminal Application
//!
//! A full-featured terminal emulator with:
//! - Command history (↑/↓ navigation)
//! - Tab completion
//! - ANSI color support
//! - Line editing (←/→, Home/End, Backspace)
//!
//! This application uses the `Application` trait and delegates to
//! kernel shell facilities via KernelServices.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use app_sdk::{Application, AppContext, print};

pub mod shell;

/// ANSI escape codes for colors
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
}

// ============================================================================
// History Manager
// ============================================================================

/// Shell history manager
pub struct History {
    entries: Vec<String>,
    index: Option<usize>,
    stash: String,
    max_size: usize,
}

impl History {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            index: None,
            stash: String::new(),
            max_size,
        }
    }

    /// Add entry to history (avoids duplicates at the end)
    pub fn push(&mut self, entry: String) {
        if entry.trim().is_empty() {
            return;
        }
        if self.entries.last() != Some(&entry) {
            self.entries.push(entry);
            if self.entries.len() > self.max_size {
                self.entries.remove(0);
            }
        }
        self.index = None;
    }

    /// Go back in history (↑ key)
    pub fn prev(&mut self, current: &str) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }

        match self.index {
            None => {
                self.stash = current.to_string();
                self.index = Some(self.entries.len() - 1);
            }
            Some(0) => {
                return Some(&self.entries[0]);
            }
            Some(idx) => {
                self.index = Some(idx - 1);
            }
        }

        self.index.map(|i| self.entries[i].as_str())
    }

    /// Go forward in history (↓ key)
    pub fn next(&mut self) -> Option<&str> {
        match self.index {
            None => None,
            Some(idx) => {
                if idx + 1 >= self.entries.len() {
                    self.index = None;
                    Some(self.stash.as_str())
                } else {
                    self.index = Some(idx + 1);
                    Some(&self.entries[idx + 1])
                }
            }
        }
    }

    /// Reset navigation state
    pub fn reset_navigation(&mut self) {
        self.index = None;
        self.stash.clear();
    }
}

// ============================================================================
// Terminal Application
// ============================================================================

/// Terminal application state
pub struct Terminal {
    history: History,
    current_line: String,
    cwd: String,
}

impl Terminal {
    pub fn new() -> Self {
        Self {
            history: History::new(100),
            current_line: String::new(),
            cwd: String::from("/"),
        }
    }

    /// Run the terminal REPL
    async fn run(&mut self, _ctx: AppContext) {
        print(format_args!("\n"));
        print(format_args!("{}{}  RanyOS Terminal v0.3                            {}{}\n", 
            ansi::CYAN, ansi::WHITE, ansi::CYAN, ansi::RESET));
        print(format_args!("{}{}  Type 'help' for available commands              {}{}\n", 
            ansi::CYAN, ansi::WHITE, ansi::CYAN, ansi::RESET));
        print(format_args!("{}{}  Use ↑/↓ for history, Tab for completion         {}{}\n", 
            ansi::CYAN, ansi::WHITE, ansi::CYAN, ansi::RESET));
        print(format_args!("\n"));
        
        self.print_prompt();
        
        // Main REPL loop - in a real implementation this would:
        // 1. Read keyboard input via AppContext
        // 2. Handle special keys (history, completion, etc.)
        // 3. Execute commands via the shell module
        // For now, this is a skeleton that the kernel's async_shell can call into
    }

    /// Print the colored prompt
    fn print_prompt(&self) {
        print(format_args!("{}exo{}:{}{}{}> ", 
            ansi::MAGENTA, ansi::RESET,
            ansi::CYAN, self.cwd, ansi::RESET));
    }

    /// Execute a command line
    pub async fn execute(&mut self, line: &str) {
        let trimmed = line.trim();
        
        if trimmed.is_empty() {
            return;
        }

        // Add to history
        self.history.push(line.to_string());
        self.history.reset_navigation();

        // Handle built-in commands
        match trimmed {
            "help" => {
                print(format_args!("Available commands:\n"));
                print(format_args!("  help     - Show this help\n"));
                print(format_args!("  exit     - Exit terminal\n"));
                print(format_args!("  clear    - Clear screen\n"));
                print(format_args!("  pwd      - Print working directory\n"));
                print(format_args!("  cd DIR   - Change directory\n"));
            }
            "exit" | "quit" => {
                print(format_args!("{}Goodbye!{}\n", ansi::YELLOW, ansi::RESET));
            }
            "clear" => {
                print(format_args!("\x1b[2J\x1b[H")); // Clear screen and home cursor
            }
            "pwd" => {
                print(format_args!("{}\n", self.cwd));
            }
            cmd if cmd.starts_with("cd ") => {
                let path = cmd.strip_prefix("cd ").unwrap_or("/");
                self.cwd = path.to_string();
                print(format_args!("Changed to: {}\n", self.cwd));
            }
            _ => {
                print(format_args!("{}Unknown command: {}{}\n", 
                    ansi::RED, trimmed, ansi::RESET));
            }
        }
    }
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for Terminal {
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut terminal = Terminal::new();
        Box::pin(async move {
            terminal.run(ctx).await;
        })
    }

    fn on_stop(&mut self) {
        print(format_args!("Terminal shutting down...\n"));
    }

    fn name(&self) -> &str {
        "terminal"
    }
}
