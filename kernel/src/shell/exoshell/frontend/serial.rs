// ============================================================================
// kernel/src/shell/exoshell/frontend/serial.rs
// ============================================================================

use alloc::format;
use alloc::string::{String, ToString};

use crate::drivers::serial;
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
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
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

    fn write_str(&self, s: &str) {
        serial::write_str(s);
    }

    fn redraw_line(&mut self, shell: &ExoShell) {
        self.write_str("\r\x1b[2K");
        self.print_prompt(&shell.cwd);
        self.write_str(self.line_buffer.as_str());

        let diff = self
            .line_buffer
            .len()
            .saturating_sub(self.line_buffer.cursor);
        if diff > 0 {
            self.write_str(&format!("\x1b[{}D", diff));
        }
    }
}

impl ShellFrontend for SerialFrontend {
    fn print_message(&mut self, msg: &str) {
        self.write_str(msg);
        if !msg.ends_with('\n') {
            self.write_str("\n");
        }
    }

    fn print_prompt(&mut self, cwd: &str) {
        self.write_str(&format!(
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
                    self.write_str(&format!("{}Error: {}{}\n", ansi::RED, e, ansi::RESET));
                    return;
                }
                if let Some(text) = display::format_shell_output(val) {
                    self.write_str(&text);
                    if !text.ends_with('\n') {
                        self.write_str("\n");
                    }
                }
            }
            Err(e) => {
                self.write_str(&format!("{}Error: {}{}\n", ansi::RED, e, ansi::RESET));
            }
        }
    }

    async fn read_line(&mut self, shell: &mut ExoShell) -> Option<String> {
        self.line_buffer.clear();
        self.navigator.reset_navigation();

        loop {
            let byte = serial::read_byte_for_shell().await;

            match byte {
                b'\r' | b'\n' => {
                    self.write_str("\r\n");
                    let line = self.line_buffer.as_str().to_string();
                    if !line.trim().is_empty() {
                        shell.add_history(line.clone());
                    }
                    return Some(line);
                }
                0x08 | 0x7F => {
                    if !self.line_buffer.is_empty() && self.line_buffer.cursor > 0 {
                        self.line_buffer.backspace();
                        self.redraw_line(shell);
                    }
                }
                b'\t' => self.handle_tab(shell),
                0x03 => {
                    self.write_str("^C\n");
                    self.line_buffer.clear();
                    self.navigator.reset_navigation();
                    self.print_prompt(&shell.cwd);
                }
                0x1B => {
                    let b2 = serial::read_byte_for_shell().await;
                    if b2 == b'[' {
                        let b3 = serial::read_byte_for_shell().await;
                        if b3 == b'3' {
                            let tilde = serial::read_byte_for_shell().await;
                            if tilde == b'~' {
                                self.handle_delete_key(shell);
                            }
                        } else {
                            self.handle_escape_csi(b3, shell);
                        }
                    }
                }
                0x20..=0x7E => self.handle_printable(byte, shell),
                _ => {}
            }
        }
    }
}

impl SerialFrontend {
    fn handle_tab(&mut self, shell: &ExoShell) {
        let completions = shell.complete(self.line_buffer.as_str());
        if completions.len() == 1 {
            self.line_buffer.set(&completions[0]);
            self.redraw_line(shell);
        } else if completions.len() > 1 {
            self.write_str("\r\n");
            for c in &completions {
                self.write_str(&format!("  {}\n", c));
            }
            self.redraw_line(shell);
        }
    }

    fn handle_escape_csi(&mut self, b3: u8, shell: &mut ExoShell) {
        match b3 {
            b'A' => {
                // Up
                if let Some(prev) = self
                    .navigator
                    .prev(shell.history(), self.line_buffer.as_str())
                {
                    self.line_buffer.set(&prev);
                    self.redraw_line(shell);
                }
            }
            b'B' => {
                // Down
                if let Some(next) = self.navigator.next(shell.history()) {
                    self.line_buffer.set(&next);
                    self.redraw_line(shell);
                }
            }
            b'C' => {
                // Right
                if self.line_buffer.cursor < self.line_buffer.len() {
                    self.line_buffer.move_right();
                    self.redraw_line(shell);
                }
            }
            b'D' => {
                // Left
                if self.line_buffer.cursor > 0 {
                    self.line_buffer.move_left();
                    self.redraw_line(shell);
                }
            }
            b'H' => {
                // Home
                if self.line_buffer.cursor > 0 {
                    self.line_buffer.move_home();
                    self.redraw_line(shell);
                }
            }
            b'F' => {
                // End
                if self.line_buffer.cursor < self.line_buffer.len() {
                    self.line_buffer.move_end();
                    self.redraw_line(shell);
                }
            }
            _ => {}
        }
    }

    fn handle_delete_key(&mut self, shell: &ExoShell) {
        if self.line_buffer.cursor < self.line_buffer.len() {
            self.line_buffer.delete();
            self.redraw_line(shell);
        }
    }

    fn handle_printable(&mut self, byte: u8, shell: &ExoShell) {
        let c = byte as char;
        self.line_buffer.insert(c);
        self.redraw_line(shell);
    }
}
