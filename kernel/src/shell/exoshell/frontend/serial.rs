// ============================================================================
// kernel/src/shell/exoshell/frontend/serial.rs
// ============================================================================


use alloc::format;
use alloc::string::{String, ToString};

use crate::io::serial;
use crate::shell::exoshell::display;
use crate::shell::exoshell::error::ExoResult;
use crate::shell::exoshell::history::HistoryNavigator;
use crate::shell::exoshell::{ExoShell, ExoValue};
use crate::shell::line_buffer::LineBuffer;

use super::ShellFrontend;

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

/// Serial Port Frontend
/// 
/// Handles input from the serial port with line editing capabilities.
pub struct SerialFrontend {
    line_buffer: LineBuffer,
    navigator: HistoryNavigator,
}

impl SerialFrontend {
    pub fn new() -> Self {
        Self {
            line_buffer: LineBuffer::new(),
            navigator: HistoryNavigator::new(),
        }
    }

    fn clear_line_visual(&self) {
        // Move to beginning of line (after prompt)
        // We assume we are at the cursor position
        let back = self.line_buffer.cursor;
        for _ in 0..back {
            crate::console::write("\x08");
        }
        // Overwrite with spaces
        for _ in 0..self.line_buffer.len() {
            crate::console::write(" ");
        }
        // Go back again
        for _ in 0..self.line_buffer.len() {
            crate::console::write("\x08");
        }
    }
}

impl ShellFrontend for SerialFrontend {
    fn print_message(&mut self, msg: &str) {
         crate::console::write(msg);
         if !msg.ends_with('\n') {
             crate::console::write("\n");
         }
    }

    fn print_prompt(&mut self, cwd: &str) {
        crate::console::write(&format!(
            "{}exo{}:{}{}{} {}>{} ",
            ansi::MAGENTA,
            ansi::RESET,
            ansi::CYAN,
            cwd,
            ansi::RESET,
            ansi::MAGENTA,
            ansi::RESET
        ));
    }

    fn print_result(&mut self, result: &ExoResult<ExoValue<'static>>) {
        match result {
            Ok(val) => {
                 if let ExoValue::Exit = val {
                     return;
                 }
                 if let ExoValue::Error(e) = val {
                     crate::console::write(&format!("{}Error: {}{}\n", ansi::RED, e, ansi::RESET));
                     return;
                 }
                 if let Some(text) = display::format_shell_output(val) {
                    crate::console::write(&text);
                    if !text.ends_with('\n') {
                        crate::console::write("\n");
                    }
                }
            }
            Err(e) => {
                 crate::console::write(&format!("{}Error: {}{}\n", ansi::RED, e, ansi::RESET));
            }
        }
    }

    async fn read_line(&mut self, shell: &mut ExoShell) -> Option<String> {
        self.line_buffer.clear();
        self.navigator.reset_navigation();
        
        loop {
            let byte = serial::read_byte().await;

            match byte {
                // Enter (CR or LF)
                b'\r' | b'\n' => {
                    crate::console::write("\r\n");
                    let line = self.line_buffer.as_str().to_string();
                    if !line.trim().is_empty() {
                         shell.add_history(line.clone());
                    }
                    return Some(line);
                }
                // Backspace
                0x08 | 0x7F => {
                    if !self.line_buffer.is_empty() && self.line_buffer.cursor > 0 {
                        self.line_buffer.backspace();
                        crate::console::write("\x08 \x08");
                    }
                }
                // Tab
                b'\t' => {
                    let completions = shell.complete(self.line_buffer.as_str());
                    if completions.len() == 1 {
                        self.clear_line_visual();
                        self.line_buffer.set(&completions[0]);
                        crate::console::write(self.line_buffer.as_str());
                    } else if completions.len() > 1 {
                        crate::console::write("\r\n");
                        for c in &completions {
                            crate::console::write(&format!("  {}\n", c));
                        }
                        self.print_prompt(&shell.cwd);
                        crate::console::write(self.line_buffer.as_str());
                    }
                }
                // Ctrl+C
                0x03 => {
                    crate::console::write("^C\n");
                    self.line_buffer.clear();
                    self.navigator.reset_navigation();
                    // We need to reprint prompt here, but read_line doesn't own prompt logic fully?
                    // It does know how to print it via self.print_prompt()
                    self.print_prompt(&shell.cwd);
                }
                // Escape sequence
                0x1B => {
                    let b2 = serial::read_byte().await;
                    if b2 == b'[' {
                        let b3 = serial::read_byte().await;
                        match b3 {
                            b'A' => { // Up
                                if let Some(prev) = self.navigator.prev(shell.history(), self.line_buffer.as_str()) {
                                    self.clear_line_visual();
                                    self.line_buffer.set(&prev);
                                    crate::console::write(self.line_buffer.as_str());
                                }
                            }
                            b'B' => { // Down
                                if let Some(next) = self.navigator.next(shell.history()) {
                                    self.clear_line_visual();
                                    self.line_buffer.set(&next);
                                    crate::console::write(self.line_buffer.as_str());
                                }
                            }
                            b'C' => { // Right
                                if self.line_buffer.cursor < self.line_buffer.len() {
                                    self.line_buffer.move_right();
                                    crate::console::write("\x1b[C");
                                }
                            }
                            b'D' => { // Left
                                if self.line_buffer.cursor > 0 {
                                    self.line_buffer.move_left();
                                    crate::console::write("\x1b[D");
                                }
                            }
                            b'H' => { // Home
                                let moves = self.line_buffer.cursor;
                                self.line_buffer.move_home();
                                for _ in 0..moves {
                                    crate::console::write("\x1b[D");
                                }
                            }
                            b'F' => { // End
                                let moves = self.line_buffer.content.len() - self.line_buffer.cursor;
                                self.line_buffer.move_end();
                                for _ in 0..moves {
                                    crate::console::write("\x1b[C");
                                }
                            }
                            b'3' => { // Delete
                                let tilde = serial::read_byte().await;
                                if tilde == b'~' {
                                    if self.line_buffer.cursor < self.line_buffer.len() {
                                        self.line_buffer.delete();
                                        self.clear_line_visual();
                                        crate::console::write("\r");
                                        self.print_prompt(&shell.cwd);
                                        crate::console::write(self.line_buffer.as_str());
                                        let diff = self.line_buffer.len() - self.line_buffer.cursor;
                                        for _ in 0..diff {
                                            crate::console::write("\x08");
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                // Printable
                0x20..=0x7E => {
                    let c = byte as char;
                    if self.line_buffer.cursor == self.line_buffer.len() {
                        self.line_buffer.insert(c);
                        let mut b = [0u8; 4];
                        crate::console::write(c.encode_utf8(&mut b));
                    } else {
                        self.line_buffer.insert(c);
                        crate::console::write("\r");
                        self.print_prompt(&shell.cwd);
                        crate::console::write(self.line_buffer.as_str());
                        let diff = self.line_buffer.len() - self.line_buffer.cursor;
                        for _ in 0..diff {
                            crate::console::write("\x08");
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
