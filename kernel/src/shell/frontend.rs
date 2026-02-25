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
use core::fmt::Write;

use crate::io::hid::keyboard::{self, KeyCode, KeyEventExt, KeyState, KeyboardStream};
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
    target_vt: u32,
}

impl ConsoleFrontend {
    fn format_prompt(cwd: &str) -> String {
        // ANSI colors for prompt
        let magenta = "\x1b[35m";
        let cyan = "\x1b[36m";
        let reset = "\x1b[0m";

        format!(
            "{}exo{}:{}{}{} {}>{} ",
            magenta, reset, cyan, cwd, reset, magenta, reset
        )
    }

    pub fn new() -> Self {
        let target_vt = crate::console::active_console();
        // Try to take the keyboard stream. If failed, it will be None and read_line will fail/exit.
        let input_stream = keyboard::take_stream().ok();

        if input_stream.is_none() {
            crate::console::write_to(
                target_vt,
                "[SHELL] Warning: Could not acquire keyboard stream.\n",
            );
        }

        Self {
            line_buffer: LineBuffer::new(),
            navigator: HistoryNavigator::new(),
            input_stream,
            target_vt,
        }
    }

    #[inline]
    fn console_write(&self, s: &str) {
        crate::console::write_to(self.target_vt, s);
    }

    #[inline]
    fn is_active_vt(&self) -> bool {
        crate::console::active_console() == self.target_vt
    }

    fn redraw_line(&mut self, shell: &ExoShell) {
        // Single-line redraw: clear, reprint prompt+buffer, then restore cursor.
        let mut out = String::from("\r\x1b[2K");
        out.push_str(&Self::format_prompt(&shell.cwd));
        out.push_str(self.line_buffer.as_str());

        let diff = self
            .line_buffer
            .len()
            .saturating_sub(self.line_buffer.cursor);
        if diff > 0 {
            let _ = write!(&mut out, "\x1b[{}D", diff);
        }

        self.console_write(&out);
    }
}

impl ShellFrontend for ConsoleFrontend {
    fn print_message(&mut self, msg: &str) {
        self.console_write(msg);
        if !msg.ends_with('\n') {
            self.console_write("\n");
        }
    }

    fn print_prompt(&mut self, cwd: &str) {
        self.console_write(&Self::format_prompt(cwd));
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
                    self.console_write(&format!("{}Error: {}{}\n", red, e, reset));
                    return;
                }
                if let Some(text) = display::format_shell_output(val) {
                    self.console_write(&text);
                    if !text.ends_with('\n') {
                        self.console_write("\n");
                    }
                }
            }
            Err(e) => {
                self.console_write(&format!("{}Error: {}{}\n", red, e, reset));
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

            if !self.is_active_vt() {
                continue;
            }

            match event.key {
                KeyCode::Enter => {
                    self.console_write("\r\n");
                    let line = self.line_buffer.as_str().to_string();
                    if !line.trim().is_empty() {
                        shell.add_history(line.clone());
                    }
                    // Restore stream
                    self.input_stream = Some(stream);
                    return Some(line);
                }
                KeyCode::Backspace | KeyCode::Delete => {
                    self.handle_delete_key(&event.key, shell);
                }
                KeyCode::Tab => {
                    self.handle_tab_completion(shell);
                }
                KeyCode::Up | KeyCode::Down => {
                    self.handle_history_navigation(&event.key, shell);
                }
                KeyCode::Left | KeyCode::Right | KeyCode::Home | KeyCode::End => {
                    self.handle_cursor_movement(&event.key, shell);
                }
                KeyCode::PageUp => {
                    crate::console::scroll(10);
                }
                KeyCode::PageDown => {
                    crate::console::scroll(-10);
                }
                _ => {
                    if let Some(c) = event.to_char() {
                        self.handle_char_input(c, shell);
                    }
                }
            }
        }
    }
}

impl ConsoleFrontend {
    fn handle_delete_key(&mut self, key: &KeyCode, shell: &ExoShell) {
        match key {
            KeyCode::Backspace => {
                if !self.line_buffer.is_empty() && self.line_buffer.cursor > 0 {
                    self.line_buffer.backspace();
                    self.redraw_line(shell);
                }
            }
            KeyCode::Delete => {
                if self.line_buffer.cursor < self.line_buffer.len() {
                    self.line_buffer.delete();
                    self.redraw_line(shell);
                }
            }
            _ => {}
        }
    }

    fn handle_tab_completion(&mut self, shell: &mut ExoShell) {
        let completions = shell.complete(self.line_buffer.as_str());
        if completions.len() == 1 {
            self.line_buffer.set(&completions[0]);
            self.redraw_line(shell);
        } else if completions.len() > 1 {
            let mut out = String::from("\r\n");
            for c in &completions {
                let _ = writeln!(&mut out, "  {}", c);
            }
            self.console_write(&out);
            self.redraw_line(shell);
        }
    }

    fn handle_history_navigation(&mut self, key: &KeyCode, shell: &mut ExoShell) {
        let entry = match key {
            KeyCode::Up => self
                .navigator
                .prev(shell.history(), self.line_buffer.as_str()),
            KeyCode::Down => self.navigator.next(shell.history()),
            _ => None,
        };
        if let Some(text) = entry {
            self.line_buffer.set(&text);
            self.redraw_line(shell);
        }
    }

    fn handle_cursor_movement(&mut self, key: &KeyCode, shell: &ExoShell) {
        match key {
            KeyCode::Left => {
                if self.line_buffer.cursor > 0 {
                    self.line_buffer.move_left();
                    self.redraw_line(shell);
                }
            }
            KeyCode::Right => {
                if self.line_buffer.cursor < self.line_buffer.len() {
                    self.line_buffer.move_right();
                    self.redraw_line(shell);
                }
            }
            KeyCode::Home => {
                if self.line_buffer.cursor > 0 {
                    self.line_buffer.move_home();
                    self.redraw_line(shell);
                }
            }
            KeyCode::End => {
                if self.line_buffer.cursor < self.line_buffer.len() {
                    self.line_buffer.move_end();
                    self.redraw_line(shell);
                }
            }
            _ => {}
        }
    }

    fn handle_char_input(&mut self, c: char, shell: &ExoShell) {
        // Check for Ctrl+C
        if c == '\x03' {
            self.console_write("^C\n");
            self.line_buffer.clear();
            self.navigator.reset_navigation();
            self.print_prompt(&shell.cwd);
            return;
        } else if c == '\x0c' {
            // Ctrl+L (Form Feed) -> Clear Screen
            self.console_write("\x1b[2J\x1b[H");
            self.redraw_line(shell);
            return;
        }

        self.line_buffer.insert(c);
        if self.line_buffer.cursor <= self.line_buffer.len() {
            self.redraw_line(shell);
        }
    }
}
