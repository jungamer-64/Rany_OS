// apps/src/system_monitor.rs - System Monitor Application
//!
//! System resource monitoring implementing the Application trait.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use app_sdk::{Application, AppContext, print, sleep};

/// System monitor application
pub struct SystemMonitor;

impl SystemMonitor {
    pub fn new() -> Self {
        Self
    }

    async fn run_monitor(&mut self, _ctx: AppContext) {
        print(format_args!("ExoRust System Monitor v0.1.0\n"));
        print(format_args!("Press 'q' to quit\n\n"));
        
        // Main monitoring loop
        loop {
            print(format_args!("CPU Usage: ---%\n"));
            print(format_args!("Memory: ---MB / ---MB\n"));
            print(format_args!("Uptime: ---s\n"));
            print(format_args!("---\n"));
            
            // Update every second
            sleep(1000).await;
            
            // Would check for quit signal here
            break; // For now, just exit
        }
    }
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for SystemMonitor {
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut monitor = SystemMonitor::new();
        Box::pin(async move {
            monitor.run_monitor(ctx).await;
        })
    }

    fn on_stop(&mut self) {
        print(format_args!("System Monitor closing...\n"));
    }

    fn name(&self) -> &str {
        "system_monitor"
    }
}
