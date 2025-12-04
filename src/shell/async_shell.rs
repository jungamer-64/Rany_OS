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
//! - Cursor movement (/, Home/End)

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
use super::exoshell::{ExoShell, ExoValue};
use crate::io::serial::{self, InputEvent, LineEditor};

/// ANSI escape codes for colors
mod ansi {
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

/// Shell history manager
struct History {
    entries: Vec<String>,
    index: Option<usize>,
    stash: String,
    max_size: usize,
}

impl History {
    fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            index: None,
            stash: String::new(),
            max_size,
        }
    }

    /// Add entry to history (avoids duplicates at the end)
    fn push(&mut self, entry: String) {
        if entry.trim().is_empty() {
            return;
        }
        // Don't add duplicates
        if self.entries.last() != Some(&entry) {
            self.entries.push(entry);
            if self.entries.len() > self.max_size {
                self.entries.remove(0);
            }
        }
        self.index = None;
    }

    /// Go back in history ( key)
    fn prev(&mut self, current: &str) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }

        match self.index {
            None => {
                // First time going back, stash current input
                self.stash = current.to_string();
                self.index = Some(self.entries.len() - 1);
            }
            Some(0) => {
                // Already at oldest, do nothing
                return Some(&self.entries[0]);
            }
            Some(idx) => {
                self.index = Some(idx - 1);
            }
        }

        self.index.map(|i| self.entries[i].as_str())
    }

    /// Go forward in history ( key)
    fn next(&mut self) -> Option<&str> {
        match self.index {
            None => None,
            Some(idx) => {
                if idx + 1 >= self.entries.len() {
                    // Back to current input
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
    fn reset_navigation(&mut self) {
        self.index = None;
        self.stash.clear();
    }
}

/// Async shell task
/// This function runs as an async task and handles serial input via interrupts
pub async fn run_async_shell() {
    crate::serial_println!("\n");
    crate::serial_println!("{}{}", ansi::CYAN, ansi::RESET);
    crate::serial_println!("{}{}  RanyOS ExoShell v0.3                            {}{}", ansi::CYAN, ansi::WHITE, ansi::CYAN, ansi::RESET);
    crate::serial_println!("{}{}  Type 'help' for available commands              {}{}", ansi::CYAN, ansi::WHITE, ansi::CYAN, ansi::RESET);
    crate::serial_println!("{}{}  Use / for history, Tab for completion         {}{}", ansi::CYAN, ansi::WHITE, ansi::CYAN, ansi::RESET);
    crate::serial_println!("{}{}\n", ansi::CYAN, ansi::RESET);
    
    let mut exoshell = ExoShell::new();
    let mut history = History::new(100);
    let mut editor = LineEditor::new();
    
    // Print initial prompt
    print_prompt(&exoshell);
    
    loop {
        // Wait for input event (handles special keys)
        let event = serial::read_line_advanced(&mut editor).await;
        
        match event {
            InputEvent::Line(line) => {
                if line.is_empty() {
                    print_prompt(&exoshell);
                    continue;
                }

                // Add to history
                history.push(line.clone());
                history.reset_navigation();

                // Check for exit command
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    serial::serial1().send_str(&format!("\n{}Goodbye!{}\n", ansi::YELLOW, ansi::RESET));
                    break;
                }

                // Execute command (async)
                execute_exoshell(&mut exoshell, &line).await;
                print_prompt(&exoshell);
            }

            InputEvent::ArrowUp => {
                if let Some(prev_line) = history.prev(&editor.content()) {
                    // Clear current line and show history entry
                    clear_line(&editor);
                    editor.set_content(prev_line);
                    print_prompt(&exoshell);
                    serial::serial1().send_str(&editor.content());
                }
            }

            InputEvent::ArrowDown => {
                if let Some(next_line) = history.next() {
                    clear_line(&editor);
                    editor.set_content(next_line);
                    print_prompt(&exoshell);
                    serial::serial1().send_str(&editor.content());
                }
            }

            InputEvent::Tab => {
                // Tab completion
                let completions = exoshell.complete(&editor.content());
                
                if completions.len() == 1 {
                    // Single completion - apply it
                    clear_line(&editor);
                    editor.set_content(&completions[0]);
                    print_prompt(&exoshell);
                    serial::serial1().send_str(&editor.content());
                } else if completions.len() > 1 {
                    // Multiple completions - show them
                    serial::serial1().send_str("\r\n");
                    for c in &completions {
                        serial::serial1().send_str(&format!("  {}\n", c));
                    }
                    print_prompt(&exoshell);
                    serial::serial1().send_str(&editor.content());
                }
            }

            InputEvent::Interrupt => {
                // Ctrl+C - clear line and show new prompt
                serial::serial1().send_str("^C\n");
                editor.clear();
                print_prompt(&exoshell);
            }

            InputEvent::Eof => {
                // Ctrl+D - exit if line is empty
                serial::serial1().send_str(&format!("\n{}exit{}\n", ansi::YELLOW, ansi::RESET));
                break;
            }

            _ => {
                // Other events handled by read_line_advanced
            }
        }
    }
    
    crate::serial_println!("\n[SHELL] ExoShell terminated");
}

/// Execute command in ExoShell (async version)
async fn execute_exoshell(exoshell: &mut ExoShell, line: &str) {
    let result = exoshell.eval(line).await;
    
    match &result {
        ExoValue::Nil => {}
        ExoValue::Error(e) => {
            serial::serial1().send_str(&format!("{}Error: {}{}\n", ansi::RED, e, ansi::RESET));
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

/// Print colored prompt
fn print_prompt(exoshell: &ExoShell) {
    serial::serial1().send_str(&format!("{}exo{}:{}{}{} {}>{} ", 
        ansi::MAGENTA, ansi::RESET,
        ansi::CYAN, exoshell.cwd(), ansi::RESET,
        ansi::MAGENTA, ansi::RESET));
}

/// Clear current line (for history navigation)
fn clear_line(_editor: &LineEditor) {
    let port = serial::serial1();
    // Move to start of line
    port.send_str("\r");
    // Clear entire line
    port.send_str("\x1b[K");
}

/// Start the async shell task
pub fn spawn_async_shell() {
    crate::task::spawn(run_async_shell());
    crate::serial_println!("[SHELL] ExoShell task spawned");
}
