// ============================================================================
// apps/src/system_monitor/mod.rs - System Monitor Application
// ============================================================================
//!
//! # System Monitor Application
//!
//! Displays system resource information such as CPU, memory, and task status.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use app_sdk::{AppContext, Application, print};

/// System Monitor application
pub struct SystemMonitor {
    refresh_interval_ms: u64,
}

impl SystemMonitor {
    /// Create new system monitor
    pub fn new() -> Self {
        Self {
            refresh_interval_ms: 1000,
        }
    }

    /// Run the monitor loop
    async fn run(&mut self, ctx: AppContext) {
        print(format_args!("=== System Monitor ===\n"));
        print(format_args!("App ID: {}\n", ctx.app_id));
        print(format_args!("Domain ID: {:?}\n", ctx.domain_id));
        print(format_args!("\n"));

        print(format_args!("System Resources:\n"));
        print(format_args!("  CPU: (monitoring not implemented)\n"));
        print(format_args!("  Memory: (monitoring not implemented)\n"));
        print(format_args!("  Tasks: (monitoring not implemented)\n"));
        print(format_args!("\n"));

        print(format_args!("Capabilities:\n"));
        print(format_args!("  Network: {:?}\n", ctx.net()));
        print(format_args!("  Filesystem: {:?}\n", ctx.fs()));
        print(format_args!("  I/O: {:?}\n", ctx.io()));
        print(format_args!("\n"));

        print(format_args!("SystemMonitor running...\n"));
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
            monitor.run(ctx).await;
        })
    }

    fn on_stop(&mut self) {
        print(format_args!("SystemMonitor shutting down...\n"));
    }

    fn name(&self) -> &str {
        "system_monitor"
    }
}
