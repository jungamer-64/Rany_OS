use super::host::KERNEL_SERVICE_HOST;

/// Publish the built-in device providers before installing the service entry point.
pub(crate) fn install_builtin_providers() {
    super::providers::install_builtin_providers(&KERNEL_SERVICE_HOST);
}

/// Publish the kernel implementation for shared service callers.
///
/// # Safety
/// Boot must call this exactly once, after installing built-in providers and
/// before allowing callers to acquire the shared kernel service instance.
pub(crate) unsafe fn install() {
    // SAFETY: The caller owns boot ordering; the implementation has image lifetime.
    unsafe {
        kernel_api::service::kernel::install(&KERNEL_SERVICE_HOST);
    }
}
