// apps/src/terminal/mod.rs - Terminal Application
//!
//! Terminal emulator implementing the Application trait.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use app_sdk::{Application, AppContext, print};

/// Terminal application
pub struct Terminal {
    command_history: Vec<String>,
    current_line: String,
}

impl Terminal {
    pub fn new() -> Self {
        Self {
            command_history: Vec::new(),
            current_line: String::new(),
        }
    }

    async fn run_terminal(&mut self, _ctx: AppContext) {
        print(format_args!("ExoRust Terminal v0.1.0\n"));
        print(format_args!("Type 'help' for available commands.\n"));
        print(format_args!("> "));
        
        // Main terminal loop would go here
        // This is a stub - actual implementation would read keyboard input
        // and process commands via the AppContext
    }
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for Terminal {
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        // Create owned copy for the async block
        let mut terminal = Terminal::new();
        Box::pin(async move {
            terminal.run_terminal(ctx).await;
        })
    }

    fn on_stop(&mut self) {
        print(format_args!("Terminal shutting down...\n"));
    }

    fn name(&self) -> &str {
        "terminal"
    }
}
