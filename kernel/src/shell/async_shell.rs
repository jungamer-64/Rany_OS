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
use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;

use super::exoshell::{ExoShell, ExoValue};
use crate::io::serial;

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

use crate::shell::exoshell::history::HistoryNavigator;
use crate::shell::line_buffer::LineBuffer;

/// Async shell task
/// This function runs as an async task and handles serial input via interrupts
pub async fn run_async_shell() {
    crate::console::write("\n");
    crate::console::write(&format!("{}{}", ansi::CYAN, ansi::RESET));
    crate::console::write("\n");
    crate::console::write(&format!(
        "{}{}  RanyOS ExoShell v0.3                            {}{}",
        ansi::CYAN,
        ansi::WHITE,
        ansi::CYAN,
        ansi::RESET
    ));
    crate::console::write("\n");
    crate::console::write(&format!(
        "{}{}  Type 'help' for available commands              {}{}",
        ansi::CYAN,
        ansi::WHITE,
        ansi::CYAN,
        ansi::RESET
    ));
    crate::console::write("\n");
    crate::console::write(&format!(
        "{}{}  Use / for history, Tab for completion         {}{}",
        ansi::CYAN,
        ansi::WHITE,
        ansi::CYAN,
        ansi::RESET
    ));
    crate::console::write("\n");
    crate::console::write(&format!("{}{}\n", ansi::CYAN, ansi::RESET));
    crate::console::write("\n");

    let mut exoshell = ExoShell::new();
    // Yield after heavy ExoShell allocation
    crate::task::yield_now().await;

    let mut navigator = HistoryNavigator::new();
    let mut line_buffer = LineBuffer::new();

    // Yield again after all initialization is complete
    crate::task::yield_now().await;

    // Print initial prompt
    print_prompt(&exoshell);

    loop {
        let byte = serial::read_byte().await;

        match byte {
            // Enter (CR or LF)
            b'\r' | b'\n' => {
                crate::console::write("\r\n");
                let line = line_buffer.as_str().to_string();
                
                if !line.trim().is_empty() {
                    // Reset navigation state
                    navigator.reset_navigation();
                    
                    // Add to history
                    exoshell.add_history(line.clone());

                    // Check for exit
                    if line.trim() == "exit" || line.trim() == "quit" {
                        crate::console::write(&format!(
                            "\n{}Goodbye!{}\n",
                            ansi::YELLOW,
                            ansi::RESET
                        ));
                        break;
                    }

                    // Execute
                    execute_exoshell(&mut exoshell, &line).await;
                }
                
                line_buffer.clear();
                print_prompt(&exoshell);
            }
            // Backspace
            0x08 | 0x7F => {
                if !line_buffer.is_empty() && line_buffer.cursor > 0 {
                    line_buffer.backspace();
                    // Echo backspace (visual erase)
                    crate::console::write("\x08 \x08");
                }
            }
            // Tab
            b'\t' => {
                let completions = exoshell.complete(line_buffer.as_str());
                if completions.len() == 1 {
                    // Clear current line on screen
                    clear_line_visual(&line_buffer);
                    line_buffer.set(&completions[0]);
                    crate::console::write(line_buffer.as_str());
                } else if completions.len() > 1 {
                    crate::console::write("\r\n");
                    for c in &completions {
                        crate::console::write(&format!("  {}\n", c));
                    }
                    print_prompt(&exoshell);
                    crate::console::write(line_buffer.as_str());
                }
            }
            // Ctrl+C
            0x03 => {
                crate::console::write("^C\n");
                line_buffer.clear();
                navigator.reset_navigation();
                print_prompt(&exoshell);
            }
            // Escape sequence
            0x1B => {
                let b2 = serial::read_byte().await;
                if b2 == b'[' {
                    let b3 = serial::read_byte().await;
                    match b3 {
                        b'A' => { // Up
                            if let Some(prev) = navigator.prev(exoshell.history(), line_buffer.as_str()) {
                                clear_line_visual(&line_buffer);
                                line_buffer.set(&prev);
                                crate::console::write(line_buffer.as_str());
                            }
                        }
                        b'B' => { // Down
                            if let Some(next) = navigator.next(exoshell.history()) {
                                clear_line_visual(&line_buffer);
                                line_buffer.set(&next);
                                crate::console::write(line_buffer.as_str());
                            }
                        }
                        b'C' => { // Right
                            if line_buffer.cursor < line_buffer.len() {
                                line_buffer.move_right();
                                crate::console::write("\x1b[C");
                            }
                        }
                        b'D' => { // Left
                            if line_buffer.cursor > 0 {
                                line_buffer.move_left();
                                crate::console::write("\x1b[D");
                            }
                        }
                        b'H' => { // Home
                            let moves = line_buffer.cursor;
                            line_buffer.move_home();
                            for _ in 0..moves {
                                crate::console::write("\x1b[D");
                            }
                        }
                        b'F' => { // End
                            let moves = line_buffer.content.len() - line_buffer.cursor;
                            line_buffer.move_end();
                            for _ in 0..moves {
                                crate::console::write("\x1b[C");
                            }
                        }
                        b'3' => { // Delete (Esc [ 3 ~)
                            let tilde = serial::read_byte().await;
                            if tilde == b'~' {
                                if line_buffer.cursor < line_buffer.len() {
                                    line_buffer.delete();
                                    // Visual update is hard without scrolling everything.
                                    // Use Save/Restore cursor if supported (Esc 7 / Esc 8 or Esc [ s / Esc [ u)
                                    // Or just reprint line.
                                    clear_line_visual(&line_buffer);
                                    crate::console::write("\r");
                                    print_prompt(&exoshell);
                                    crate::console::write(line_buffer.as_str());
                                    
                                    // Restore cursor logic (similar to insert)
                                    let diff = line_buffer.len() - line_buffer.cursor;
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
            // Printable characters
            0x20..=0x7E => {
                let c = byte as char;
                if line_buffer.cursor == line_buffer.len() {
                    // Append at end
                    line_buffer.insert(c);
                    let mut b = [0u8; 4];
                    crate::console::write(c.encode_utf8(&mut b));
                } else {
                    // Insert in middle (complex redraw needed)
                    line_buffer.insert(c);
                    // Redraw from cursor
                     // Save cursor pos, print rest of line, restore cursor
                     // For simplicity in serial shell, we just reprint the line from cursor
                     // But VT100 insert mode is hard.
                     // Simple approach: Clear line, reprint.
                     clear_line_visual(&line_buffer); // Reprints prompt too? No.
                     // We need a clear_from_cursor function.
                     // Let's implement full clear and reprint for simplicity
                     // This is slightly flickering but robust.
                     crate::console::write("\r");
                     print_prompt(&exoshell);
                     crate::console::write(line_buffer.as_str());
                     
                     // Restore visual cursor
                     let diff = line_buffer.len() - line_buffer.cursor;
                     for _ in 0..diff {
                         crate::console::write("\x08"); // Go back
                     }
                }
            }
            _ => {}
        }
    }

    crate::console::write("\n");
    crate::console::write(&format!("[SHELL] ExoShell terminated"));
    crate::console::write("\n");
}

fn clear_line_visual(buffer: &LineBuffer) {
    // Move to beginning of line (after prompt)
    // We assume we are at the cursor position
    // Iterate back to 0
    let back = buffer.cursor;
    for _ in 0..back {
        crate::console::write("\x08");
    }
    // Overwrite with spaces
    for _ in 0..buffer.len() {
        crate::console::write(" ");
    }
    // Go back again
    for _ in 0..buffer.len() {
        crate::console::write("\x08");
    }
}

/// Execute command in ExoShell (async version)
async fn execute_exoshell(exoshell: &mut ExoShell, line: &str) {
    let result = exoshell.eval(line).await;

    // Error handling with color
    if let ExoValue::Error(ref e) = result {
        crate::console::write(&format!("{}Error: {}{}\n", ansi::RED, e, ansi::RESET));
        return;
    }

    // Normal output
    if let Some(text) = crate::shell::exoshell::display::format_shell_output(&result) {
        crate::console::write(&text);
        if !text.ends_with('\n') {
            crate::console::write("\n");
        }
    }
}

/// Print colored prompt
fn print_prompt(exoshell: &ExoShell) {
    crate::console::write(&format!(
        "{}exo{}:{}{}{} {}>{} ",
        ansi::MAGENTA,
        ansi::RESET,
        ansi::CYAN,
        exoshell.cwd(),
        ansi::RESET,
        ansi::MAGENTA,
        ansi::RESET
    ));
} 



/// Start the async shell task
pub fn spawn_async_shell() {
    crate::task::spawn(run_async_shell());
    crate::console::write(&format!("[SHELL] ExoShell task spawned"));
    crate::console::write("\n");
}
