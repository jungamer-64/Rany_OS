// ============================================================================
// libs/app_sdk/src/application.rs - Application Trait
// ============================================================================
//!
//! The core trait that all ExoRust applications must implement.

use super::context::AppContext;
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

/// ExoRust Application Entry Point
///
/// All applications must implement this trait.
///
/// # Example
///
/// ```rust,ignore
/// struct MyApp;
///
/// impl Application for MyApp {
///     async fn on_start(&mut self, ctx: AppContext) {
///         println!("Hello from MyApp!");
///         
///         if let Some(net_cap) = ctx.net() {
///             // Network operations...
///         }
///         
///         app_sdk::sleep(1000).await;
///     }
/// }
/// ```
pub trait Application: Send + Sync {
    /// Main entry point
    ///
    /// Called when the application starts.
    /// The AppContext provides access to capabilities.
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    /// Cleanup on stop (optional)
    fn on_stop(&mut self) {
        // Default: nothing
    }

    /// Application name
    fn name(&self) -> &str {
        "unnamed"
    }
}
