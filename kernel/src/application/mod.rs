// ============================================================================
// kernel/src/application/mod.rs - Domain Manager (Kernel-Side)
// ============================================================================
//!
//! # Application Domain Manager
//!
//! This module provides kernel-side application lifecycle management.
//! Application types (trait, context) are in `kernel_api`.
//! User-facing applications are in the `apps` crate.

#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

// Re-export from kernel_api
pub use kernel_api::security::DomainCapabilities;
pub use kernel_api::{AppContext, Application};

// Re-export from apps crate (when available)
// pub use exorust_apps::{browser, editor, games, terminal, system_monitor};

// ============================================================================
// Domain State
// ============================================================================

/// Domain state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// Created, not started
    Created,
    /// Initializing
    Initializing,
    /// Running
    Running,
    /// Stopping
    Stopping,
    /// Stopped
    Stopped,
    /// Crashed
    Crashed,
}

/// Domain information
pub struct DomainInfo {
    pub id: u64,
    pub name: String,
    pub state: DomainState,
    pub app_id: u64,
}

// ============================================================================
// DomainManager
// ============================================================================

/// Domain manager
///
/// Manages application (domain) lifecycle.
pub struct DomainManager {
    domains: Vec<DomainInfo>,
    next_domain_id: u64,
    next_app_id: u64,
}

impl DomainManager {
    /// Create new manager
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            next_domain_id: 1,
            next_app_id: 1,
        }
    }

    /// Load and start an application
    pub fn load_and_start<A>(&mut self, mut app: A, name: String, caps: DomainCapabilities)
    where
        A: Application + 'static,
    {
        let domain_id = self.next_domain_id;
        self.next_domain_id += 1;

        let app_id = self.next_app_id;
        self.next_app_id += 1;

        self.domains.push(DomainInfo {
            id: domain_id,
            name: name.clone(),
            state: DomainState::Created,
            app_id,
        });

        log::info!("[Domain:{}] Loading application '{}'\n", domain_id, name);

        // Create application context
        let ctx = AppContext::new(app_id, name.clone(), domain_id, caps);

        // Spawn the application start future via kernel services
        let start_future = app.on_start(ctx);
        if let Err(e) = kernel_api::kernel().spawn_task(start_future) {
            log::info!("[Domain:{}] Failed to spawn app task: {:?}\n", domain_id, e);
        }
    }

    /// Get domain count
    pub fn count(&self) -> usize {
        self.domains.len()
    }

    /// Iterate all domains
    pub fn iter(&self) -> impl Iterator<Item = &DomainInfo> {
        self.domains.iter()
    }

    /// Set domain state
    pub fn set_state(&mut self, domain_id: u64, state: DomainState) {
        if let Some(domain) = self.domains.iter_mut().find(|d| d.id == domain_id) {
            domain.state = state;
        }
    }
}

impl Default for DomainManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static DOMAIN_MANAGER: Mutex<Option<DomainManager>> = Mutex::new(None);

/// Initialize domain manager
pub fn init() {
    *DOMAIN_MANAGER.lock() = Some(DomainManager::new());
    log::info!("[Application] Runtime initialized (SPL Domain Model)\n");
}

/// Access domain manager
pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut DomainManager) -> R,
{
    DOMAIN_MANAGER.lock().as_mut().map(f)
}

/// Start an application
pub fn start_application<A>(app: A, name: &str, caps: DomainCapabilities)
where
    A: Application + 'static,
{
    with_manager(|mgr| {
        mgr.load_and_start(app, String::from(name), caps);
    });
}

/// Get domain count
pub fn domain_count() -> usize {
    DOMAIN_MANAGER
        .lock()
        .as_ref()
        .map(|m| m.count())
        .unwrap_or(0)
}

// ============================================================================
// Backward Compatibility
// ============================================================================

/// Backward compatibility: AppHandle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppHandle(pub u64);

impl AppHandle {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn id(&self) -> u64 {
        self.0
    }
}

/// Backward compatibility: app count
pub fn app_count() -> usize {
    domain_count()
}
