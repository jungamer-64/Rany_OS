//! Simple text-based boot menu UI
//!
//! Displays a boot menu using UEFI Simple Text Output Protocol.
//! Supports arrow key navigation and timer-based default selection.

use crate::config::{BootConfig, BootEntry};
use core::time::Duration;
use log::info;
use uefi::prelude::*;
use uefi::proto::console::text::{Key, ScanCode};
use uefi::boot;

/// Boot menu result
pub enum MenuResult {
    /// User selected an entry
    Selected(usize),
    /// Timeout reached, use default
    Timeout,
    /// Menu cancelled (ESC pressed)
    Cancelled,
}

/// Display boot menu and wait for user selection
///
/// # Arguments
/// * `config` - Boot configuration with entries
///
/// # Returns
/// MenuResult indicating user selection or timeout
pub fn show_boot_menu(config: &BootConfig) -> MenuResult {
    // If no entries or only one entry with 0 timeout, skip menu
    if config.entries.is_empty() {
        return MenuResult::Cancelled;
    }

    if config.entries.len() == 1 && config.timeout == 0 {
        return MenuResult::Selected(0);
    }

    let mut selected = config.default_entry;
    let mut remaining_seconds = config.timeout;

    // Initial draw
    draw_menu(config, selected, remaining_seconds);

    // Main loop
    loop {
        // Check for key press (non-blocking)
        if let Some(key) = read_key_nonblocking() {
            match key {
                Key::Special(ScanCode::UP) => {
                    if selected > 0 {
                        selected -= 1;
                    } else {
                        selected = config.entries.len() - 1;
                    }
                    remaining_seconds = 0; // Cancel timer on key press
                    draw_menu(config, selected, remaining_seconds);
                }
                Key::Special(ScanCode::DOWN) => {
                    if selected < config.entries.len() - 1 {
                        selected += 1;
                    } else {
                        selected = 0;
                    }
                    remaining_seconds = 0;
                    draw_menu(config, selected, remaining_seconds);
                }
                Key::Printable(c) => {
                    let ch = char::from(c);
                    if ch == '\r' || ch == '\n' {
                        // Enter pressed
                        return MenuResult::Selected(selected);
                    }
                }
                Key::Special(ScanCode::ESCAPE) => {
                    return MenuResult::Cancelled;
                }
                _ => {}
            }
        }

        // Handle timeout
        if remaining_seconds > 0 {
            // Wait 1 second
            boot::stall(Duration::from_micros(1_000_000)); // 1 second in microseconds
            remaining_seconds -= 1;

            if remaining_seconds == 0 && config.timeout > 0 {
                // Timeout reached
                info!("Boot menu timeout, selecting default entry {}", config.default_entry);
                return MenuResult::Timeout;
            }

            // Redraw to update timer
            draw_menu(config, selected, remaining_seconds);
        } else {
            // No timer, just poll occasionally
            boot::stall(Duration::from_micros(50_000)); // 50ms
        }
    }
}

/// Draw the boot menu
fn draw_menu(
    config: &BootConfig,
    selected: usize,
    remaining_seconds: u32,
) {
    uefi::system::with_stdout(|stdout| {
        // Clear screen
        let _ = stdout.clear();

        // Header
        let _ = stdout.output_string(cstr16!("\r\n"));
        let _ = stdout.output_string(cstr16!("  ╔══════════════════════════════════════╗\r\n"));
        let _ = stdout.output_string(cstr16!("  ║      ExoLoader Boot Menu             ║\r\n"));
        let _ = stdout.output_string(cstr16!("  ╚══════════════════════════════════════╝\r\n"));
        let _ = stdout.output_string(cstr16!("\r\n"));

        // Menu entries
        for (i, entry) in config.entries.iter().enumerate() {
            if i == selected {
                let _ = stdout.output_string(cstr16!("  → "));
            } else {
                let _ = stdout.output_string(cstr16!("    "));
            }

            // Print entry name (simplified - just first 30 chars)
            print_string(stdout, &entry.name);
            let _ = stdout.output_string(cstr16!("\r\n"));
        }

        let _ = stdout.output_string(cstr16!("\r\n"));

        // Footer with instructions
        let _ = stdout.output_string(cstr16!("  ─────────────────────────────────────────\r\n"));
        let _ = stdout.output_string(cstr16!("  Use ↑↓ to select, Enter to boot, ESC to cancel\r\n"));

        // Timer display
        if remaining_seconds > 0 {
            let _ = stdout.output_string(cstr16!("  Auto-boot in "));
            print_number(stdout, remaining_seconds);
            let _ = stdout.output_string(cstr16!(" second(s)...\r\n"));
        }
    });
}

/// Print a string to UEFI console (ASCII only)
fn print_string(stdout: &mut uefi::proto::console::text::Output, s: &str) {
    // Convert to UCS-2 manually (ASCII subset)
    let mut buf = [0u16; 64];
    let mut len = 0;

    for ch in s.chars().take(62) {
        if ch.is_ascii() {
            buf[len] = ch as u16;
            len += 1;
        }
    }
    buf[len] = 0; // Null terminate

    // Create CStr16 from buffer
    if let Ok(cstr) = uefi::CStr16::from_u16_with_nul(&buf[..=len]) {
        let _ = stdout.output_string(cstr);
    }
}

/// Print a number to UEFI console
fn print_number(stdout: &mut uefi::proto::console::text::Output, n: u32) {
    let mut buf = [0u16; 12];
    let mut num = n;
    let mut pos = 10;

    buf[11] = 0; // Null terminate

    if num == 0 {
        buf[pos] = b'0' as u16;
    } else {
        while num > 0 && pos > 0 {
            buf[pos] = b'0' as u16 + (num % 10) as u16;
            num /= 10;
            pos -= 1;
        }
        pos += 1;
    }

    if let Ok(cstr) = uefi::CStr16::from_u16_with_nul(&buf[pos..]) {
        let _ = stdout.output_string(cstr);
    }
}

/// Non-blocking key read
fn read_key_nonblocking() -> Option<Key> {
    uefi::system::with_stdin(|stdin| {
        stdin.read_key().ok().flatten()
    })
}

/// Get the selected boot entry
pub fn get_selected_entry<'a>(config: &'a BootConfig, result: &MenuResult) -> Option<&'a BootEntry> {
    match result {
        MenuResult::Selected(idx) => config.entries.get(*idx),
        MenuResult::Timeout => config.entries.get(config.default_entry),
        MenuResult::Cancelled => None,
    }
}
