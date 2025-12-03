// ============================================================================
// src/shell/async_shell.rs - Async Interactive Shell
// ============================================================================
//!
//! # Async Shell Task
//!
//! Interrupt-driven serial shell using async/await.
//! Replaces polling-based input with IRQ4-triggered futures.

use alloc::string::String;
use alloc::format;
use super::{Shell, CommandResult};
use crate::io::serial;

/// Async shell task
/// This function runs as an async task and handles serial input via interrupts
pub async fn run_async_shell() {
    crate::serial_println!("\n");
    crate::serial_println!("===========================================");
    crate::serial_println!("  RanyOS Async Shell v0.1");
    crate::serial_println!("  Type 'help' for available commands");
    crate::serial_println!("  IRQ4 interrupt-driven input enabled");
    crate::serial_println!("===========================================\n");
    
    let mut shell = Shell::new();
    
    // Print initial prompt
    serial::serial1().send_str(shell.prompt());
    
    loop {
        // Wait for a line of input (interrupt-driven)
        let line = serial::read_line().await;
        
        // Handle empty line (EOF or just enter)
        if line.is_empty() {
            serial::serial1().send_str(shell.prompt());
            continue;
        }
        
        // Execute the command
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
        
        // Check if shell should continue
        if !shell.is_running() {
            break;
        }
        
        // Print next prompt
        serial::serial1().send_str(shell.prompt());
    }
    
    crate::serial_println!("\n[SHELL] Async shell terminated");
}

/// Start the async shell task
pub fn spawn_async_shell() {
    crate::task::spawn(run_async_shell());
    crate::serial_println!("[SHELL] Async shell task spawned");
}
