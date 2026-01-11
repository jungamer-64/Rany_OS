// ============================================================================
// src/shell/frontend.rs - Shell Frontends
// ============================================================================
//!
//! # Shell Frontends
//!
//! Adapters for different input/output devices (Console, Serial, etc.)
//!

use alloc::format;
use alloc::string::{String, ToString};

use crate::io::hid::keyboard::{self, KeyCode, KeyState, KeyboardStream, KeyEventExt};
use crate::shell::exoshell::display;
use crate::shell::exoshell::error::ExoResult;
use crate::shell::exoshell::frontend::ShellFrontend;
use crate::shell::exoshell::history::HistoryNavigator;
use crate::shell::exoshell::{ExoShell, ExoValue};
use crate::shell::line_buffer::LineBuffer;

/// Console Frontend (Keyboard Input + VGA/Serial Console Output)
pub struct ConsoleFrontend {
    line_buffer: LineBuffer,
    navigator: HistoryNavigator,
    input_stream: Option<KeyboardStream>,
}

impl ConsoleFrontend {
    pub fn new() -> Self {
        // Try to take the keyboard stream. If failed, it will be None and read_line will fail/exit.
        let input_stream = keyboard::take_stream().ok();
        
        if input_stream.is_none() {
            crate::console::write("[SHELL] Warning: Could not acquire keyboard stream.\n");
        }

        Self {
            line_buffer: LineBuffer::new(),
            navigator: HistoryNavigator::new(),
            input_stream,
        }
    }

    fn clear_line_visual(&self) {
        // Move to beginning of input (assuming we are at cursor)
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

    fn redraw_line(&mut self, shell: &ExoShell) {
        crate::console::write("\r");
        self.print_prompt(&shell.cwd);
        crate::console::write(self.line_buffer.as_str());
        
        // Adjust cursor position if it's not at the end
        let diff = self.line_buffer.len() - self.line_buffer.cursor;
        for _ in 0..diff {
            crate::console::write("\x08");
        }
    }
}

impl ShellFrontend for ConsoleFrontend {
    fn print_message(&mut self, msg: &str) {
        crate::console::write(msg);
        if !msg.ends_with('\n') {
            crate::console::write("\n");
        }
    }

    fn print_prompt(&mut self, cwd: &str) {
        // ANSI colors for prompt
        let magenta = "\x1b[35m";
        let cyan = "\x1b[36m";
        let reset = "\x1b[0m";

        crate::console::write(&format!(
            "{}exo{}:{}{}{} {}>{} ",
            magenta, reset,
            cyan, cwd, reset,
            magenta, reset
        ));
    }

    fn print_result(&mut self, result: &ExoResult<ExoValue<'static>>) {
        let red = "\x1b[31m";
        let reset = "\x1b[0m";

        match result {
            Ok(val) => {
                if let ExoValue::Exit = val {
                    return;
                }
                if let ExoValue::Error(e) = val {
                    crate::console::write(&format!("{}Error: {}{}\n", red, e, reset));
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
                crate::console::write(&format!("{}Error: {}{}\n", red, e, reset));
            }
        }
    }

    async fn read_line(&mut self, shell: &mut ExoShell) -> Option<String> {
        let mut stream = self.input_stream.take()?;
        
        self.line_buffer.clear();
        self.navigator.reset_navigation();

        loop {
            let event = stream.read_key().await;
            
            // Ignore key releases, only process presses
            if event.state == KeyState::Released {
                continue;
            }

            match event.key {
                KeyCode::Enter => {
                    crate::console::write("\r\n");
                    let line = self.line_buffer.as_str().to_string();
                    if !line.trim().is_empty() {
                        shell.add_history(line.clone());
                    }
                    // Restore stream
                    self.input_stream = Some(stream);
                    return Some(line);
                }
                KeyCode::Backspace => {
                    if !self.line_buffer.is_empty() && self.line_buffer.cursor > 0 {
                        self.line_buffer.backspace();
                        crate::console::write("\x08 \x08");
                    }
                }
                KeyCode::Delete => {
                    if self.line_buffer.cursor < self.line_buffer.len() {
                        self.line_buffer.delete();
                        // Redraw from cursor to end is tricky with just backspace/space
                        // Easiest is to clear line visual (from cursor) and reprint
                         // Or use ANSI to save cursor?
                        self.clear_line_visual(); // Clears whole line basically
                        self.redraw_line(shell);
                    }
                }
                KeyCode::Tab => {
                     let completions = shell.complete(self.line_buffer.as_str());
                    if completions.len() == 1 {
                        self.clear_line_visual();
                        self.line_buffer.set(&completions[0]);
                         self.redraw_line(shell);
                    } else if completions.len() > 1 {
                        crate::console::write("\r\n");
                        for c in &completions {
                            crate::console::write(&format!("  {}\n", c));
                        }
                        self.redraw_line(shell);
                    }
                }
                KeyCode::Up => {
                    if let Some(prev) = self.navigator.prev(shell.history(), self.line_buffer.as_str()) {
                        self.clear_line_visual();
                        self.line_buffer.set(&prev);
                        self.redraw_line(shell);
                    }
                }
                KeyCode::Down => {
                    if let Some(next) = self.navigator.next(shell.history()) {
                         self.clear_line_visual();
                        self.line_buffer.set(&next);
                         self.redraw_line(shell);
                    }
                }
                KeyCode::Left => {
                    if self.line_buffer.cursor > 0 {
                        self.line_buffer.move_left();
                        crate::console::write("\x1b[D");
                    }
                }
                KeyCode::Right => {
                    if self.line_buffer.cursor < self.line_buffer.len() {
                        self.line_buffer.move_right();
                        crate::console::write("\x1b[C");
                    }
                }
                 KeyCode::Home => {
                    let moves = self.line_buffer.cursor;
                    self.line_buffer.move_home();
                    // Move cursor left 'moves' times
                     if moves > 0 {
                        crate::console::write(&format!("\x1b[{}D", moves));
                     }
                }
                KeyCode::End => {
                    let moves = self.line_buffer.content.len() - self.line_buffer.cursor;
                    self.line_buffer.move_end();
                    if moves > 0 {
                        crate::console::write(&format!("\x1b[{}C", moves));
                    }
                }
                KeyCode::PageUp => {
                    crate::console::scroll(10);
                }
                KeyCode::PageDown => {
                    crate::console::scroll(-10);
                }
                // Handle Ctrl+C, etc. if modifiers present?
                // For now just basic char input
                _ => {
                    if let Some(c) = event.to_char() {
                         // Check for Ctrl+C
                         if c == '\x03' {
                             crate::console::write("^C\n");
                             self.line_buffer.clear();
                             self.navigator.reset_navigation();
                             self.print_prompt(&shell.cwd);
                             continue;
                         } else if c == '\x0c' {
                            // Ctrl+L (Form Feed) -> Clear Screen
                            // Clear terminal and redraw prompt
                            crate::console::write("\x1b[2J\x1b[H"); 
                            self.print_prompt(&shell.cwd);
                            crate::console::write(self.line_buffer.as_str());
                            continue;
                         }
                        
                        if self.line_buffer.cursor == self.line_buffer.len() {
                            self.line_buffer.insert(c);
                            let mut b = [0u8; 4];
                            crate::console::write(c.encode_utf8(&mut b));
                        } else {
                            self.line_buffer.insert(c);
                            // Insert in middle requires redraw of the rest of the line
                             // Simplest: update buffer, clear visual, redraw
                            // Optimize: save cursor, print rest, restore cursor?
                            // For now:
                             self.clear_line_visual();
                            self.redraw_line(shell);
                        }
                    }
                }
            }
        }
    }
}
