// apps/src/editor/mod.rs - Text Editor Application
//!
//! Simple text editor implementing the Application trait.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use app_sdk::{Application, AppContext, print};

/// Editor application
pub struct Editor {
    content: Vec<String>,
    cursor_line: usize,
    cursor_col: usize,
    filename: Option<String>,
}

impl Editor {
    pub fn new() -> Self {
        Self {
            content: Vec::new(),
            cursor_line: 0,
            cursor_col: 0,
            filename: None,
        }
    }

    async fn run_editor(&mut self, ctx: AppContext) {
        print(format_args!("ExoRust Editor v0.1.0\n"));
        
        // Check if we have filesystem capability
        if ctx.fs().is_some() {
            print(format_args!("Filesystem capability available\n"));
        } else {
            print(format_args!("Warning: No filesystem capability\n"));
        }
        
        print(format_args!("Commands: Ctrl+S save, Ctrl+Q quit\n"));
        
        // Editor main loop would go here
    }
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for Editor {
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut editor = Editor::new();
        Box::pin(async move {
            editor.run_editor(ctx).await;
        })
    }

    fn on_stop(&mut self) {
        print(format_args!("Editor closing...\n"));
    }

    fn name(&self) -> &str {
        "editor"
    }
}
