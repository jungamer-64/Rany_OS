// apps/src/browser/mod.rs - Browser Application
//!
//! Web browser application implementing the Application trait.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;

use app_sdk::{Application, AppContext, print};

/// Browser application
pub struct Browser {
    current_url: String,
}

impl Browser {
    pub fn new() -> Self {
        Self {
            current_url: String::from("about:blank"),
        }
    }

    async fn run_browser(&mut self, ctx: AppContext) {
        print(format_args!("ExoRust Browser v0.1.0\n"));
        
        // Check if we have network capability
        if ctx.net().is_some() {
            print(format_args!("Network capability available\n"));
        } else {
            print(format_args!("Warning: No network capability\n"));
        }
        
        print(format_args!("Current URL: {}\n", self.current_url));
        
        // Browser main loop would go here
    }
}

impl Default for Browser {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for Browser {
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut browser = Browser::new();
        Box::pin(async move {
            browser.run_browser(ctx).await;
        })
    }

    fn on_stop(&mut self) {
        print(format_args!("Browser closing...\n"));
    }

    fn name(&self) -> &str {
        "browser"
    }
}
