pub mod stack;
pub mod manager;
pub mod bridge;
pub mod timeouts;
/// Host HTTP service — moved to `crate::net::services::http::server`.
/// Re-exported for backward compatibility.
pub(crate) mod host_http_service {
    pub fn start_once(executor: &mut crate::task::Executor) {
        crate::net::services::http::server::start_once(executor);
    }
}
