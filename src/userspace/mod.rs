//! User Space API for ExoRust Kernel
//!
//! Provides a safe API for user applications running in Ring 0.
//! Since ExoRust uses Single Privilege Level (SPL), "user space"
//! applications run in Ring 0 but are constrained by:
//! - Safe Rust type system
//! - Compiler signature verification
//! - Capability-based access control

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// User application handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppHandle(u64);

impl AppHandle {
    /// Create new app handle
    pub fn new(id: u64) -> Self {
        AppHandle(id)
    }
    
    /// Get raw ID
    pub fn id(&self) -> u64 {
        self.0
    }
}

/// Application state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Application is created but not started
    Created,
    /// Application is running
    Running,
    /// Application is suspended
    Suspended,
    /// Application has completed
    Completed,
    /// Application crashed
    Crashed,
}

/// Application capabilities
#[derive(Debug, Clone)]
pub struct AppCapabilities {
    /// Can access network
    pub network: bool,
    /// Can access storage
    pub storage: bool,
    /// Can spawn tasks
    pub spawn_tasks: bool,
    /// Can create IPC channels
    pub ipc: bool,
    /// Memory limit in bytes
    pub memory_limit: usize,
    /// Maximum number of tasks
    pub max_tasks: usize,
}

impl Default for AppCapabilities {
    fn default() -> Self {
        AppCapabilities {
            network: false,
            storage: false,
            spawn_tasks: true,
            ipc: true,
            memory_limit: 64 * 1024 * 1024, // 64MB
            max_tasks: 16,
        }
    }
}

/// User application context
pub struct AppContext {
    /// Handle
    handle: AppHandle,
    /// Name
    name: String,
    /// State
    state: AppState,
    /// Capabilities
    capabilities: AppCapabilities,
    /// Domain ID
    domain_id: u64,
}

impl AppContext {
    /// Create new application context
    pub fn new(name: String, capabilities: AppCapabilities) -> Self {
        static NEXT_ID: core::sync::atomic::AtomicU64 = 
            core::sync::atomic::AtomicU64::new(1);
        
        let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let domain_id = crate::domain_system::create_domain(name.clone()).as_u64();
        
        AppContext {
            handle: AppHandle::new(id),
            name,
            state: AppState::Created,
            capabilities,
            domain_id,
        }
    }
    
    /// Get handle
    pub fn handle(&self) -> AppHandle {
        self.handle
    }
    
    /// Get name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get state
    pub fn state(&self) -> AppState {
        self.state
    }
    
    /// Get domain ID
    pub fn domain_id(&self) -> u64 {
        self.domain_id
    }
    
    /// Set state
    pub fn set_state(&mut self, state: AppState) {
        self.state = state;
    }
}

// ============================================================================
// User API Functions
// ============================================================================

/// Print to console
pub fn print(s: &str) {
    crate::log!("{}", s);
}

/// Print line to console
pub fn println(s: &str) {
    crate::log!("{}\n", s);
}

/// Get current time in milliseconds since boot
pub fn current_time_ms() -> u64 {
    crate::task::current_tick()
}

/// Sleep for specified milliseconds
pub fn sleep_ms(ms: u64) -> impl Future<Output = ()> {
    crate::task::sleep_ms(ms)
}

/// Yield execution to other tasks
pub fn yield_now() {
    crate::task::yield_point();
}

/// Allocate memory
pub fn alloc_buffer(size: usize) -> Option<Vec<u8>> {
    if size == 0 || size > 1024 * 1024 * 1024 { // 1GB limit
        return None;
    }
    Some(alloc::vec![0u8; size])
}

// ============================================================================
// Async I/O API
// ============================================================================

/// Async read result
pub enum ReadResult {
    /// Data read successfully
    Data(Vec<u8>),
    /// End of file
    Eof,
    /// Error
    Error(String),
}

/// Async write result
pub enum WriteResult {
    /// Bytes written
    Written(usize),
    /// Error
    Error(String),
}

/// File handle
#[derive(Debug, Clone, Copy)]
pub struct FileHandle(u64);

/// Open a file (placeholder)
pub async fn file_open(_path: &str) -> Result<FileHandle, String> {
    // In real implementation, would go through VFS
    Ok(FileHandle(1))
}

/// Read from file (placeholder)
pub async fn file_read(_handle: FileHandle, _buf: &mut [u8]) -> ReadResult {
    // In real implementation, would use async file system
    ReadResult::Eof
}

/// Write to file (placeholder)
pub async fn file_write(_handle: FileHandle, _data: &[u8]) -> WriteResult {
    // In real implementation, would use async file system
    WriteResult::Written(0)
}

/// Close file
pub fn file_close(_handle: FileHandle) {
    // Cleanup
}

// ============================================================================
// IPC API
// ============================================================================

/// IPC channel
pub struct Channel<T> {
    id: u64,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Send + 'static> Channel<T> {
    /// Create new channel pair
    pub fn new() -> (Sender<T>, Receiver<T>) {
        static NEXT_ID: core::sync::atomic::AtomicU64 = 
            core::sync::atomic::AtomicU64::new(1);
        
        let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        
        (
            Sender { id, _marker: core::marker::PhantomData },
            Receiver { id, _marker: core::marker::PhantomData },
        )
    }
}

/// Channel sender
pub struct Sender<T> {
    id: u64,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Send + 'static> Sender<T> {
    /// Send value (placeholder)
    pub async fn send(&self, _value: T) -> Result<(), String> {
        // In real implementation, would use IPC subsystem
        Ok(())
    }
}

/// Channel receiver
pub struct Receiver<T> {
    id: u64,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Send + 'static> Receiver<T> {
    /// Receive value (placeholder)
    pub async fn recv(&self) -> Option<T> {
        // In real implementation, would use IPC subsystem
        None
    }
}

// ============================================================================
// Task Spawning API
// ============================================================================

/// Spawn a new async task
pub fn spawn<F>(name: &str, future: F) -> TaskHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    static NEXT_ID: core::sync::atomic::AtomicU64 = 
        core::sync::atomic::AtomicU64::new(1);
    
    let id = NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    
    // In real implementation, would add to executor
    crate::log!("[USER] Spawned task '{}' (id: {})\n", name, id);
    
    TaskHandle { id }
}

/// Task handle
#[derive(Debug, Clone, Copy)]
pub struct TaskHandle {
    id: u64,
}

impl TaskHandle {
    /// Get task ID
    pub fn id(&self) -> u64 {
        self.id
    }
    
    /// Check if task is complete (placeholder)
    pub fn is_complete(&self) -> bool {
        false
    }
}

// ============================================================================
// Example User Application
// ============================================================================

/// Example user application entry point
pub async fn example_app() {
    println("[APP] Hello from user application!");
    
    // Print current time
    let time = current_time_ms();
    crate::log!("[APP] Current time: {} ms\n", time);
    
    // Allocate some memory
    if let Some(buf) = alloc_buffer(1024) {
        crate::log!("[APP] Allocated {} bytes\n", buf.len());
    }
    
    // Sleep a bit
    sleep_ms(100).await;
    
    // Yield to other tasks
    yield_now();
    
    println("[APP] User application complete!");
}

// ============================================================================
// Application Manager
// ============================================================================

use spin::Mutex;

/// Application manager
pub struct AppManager {
    apps: Vec<AppContext>,
}

impl AppManager {
    /// Create new app manager
    pub fn new() -> Self {
        AppManager { apps: Vec::new() }
    }
    
    /// Register application
    pub fn register(&mut self, app: AppContext) -> AppHandle {
        let handle = app.handle();
        self.apps.push(app);
        handle
    }
    
    /// Get application by handle
    pub fn get(&self, handle: AppHandle) -> Option<&AppContext> {
        self.apps.iter().find(|a| a.handle() == handle)
    }
    
    /// Get mutable application by handle
    pub fn get_mut(&mut self, handle: AppHandle) -> Option<&mut AppContext> {
        self.apps.iter_mut().find(|a| a.handle() == handle)
    }
    
    /// List all applications
    pub fn list(&self) -> impl Iterator<Item = &AppContext> {
        self.apps.iter()
    }
    
    /// Count applications
    pub fn count(&self) -> usize {
        self.apps.len()
    }
}

impl Default for AppManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global application manager
static APP_MANAGER: Mutex<Option<AppManager>> = Mutex::new(None);

/// Initialize application manager
pub fn init() {
    *APP_MANAGER.lock() = Some(AppManager::new());
}

/// Register an application
pub fn register_app(name: String, capabilities: AppCapabilities) -> AppHandle {
    let app = AppContext::new(name, capabilities);
    let handle = app.handle();
    
    if let Some(mgr) = APP_MANAGER.lock().as_mut() {
        mgr.register(app);
    }
    
    handle
}

/// Get application count
pub fn app_count() -> usize {
    APP_MANAGER.lock()
        .as_ref()
        .map(|m| m.count())
        .unwrap_or(0)
}
