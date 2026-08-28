use super::ExoKernel;

pub(crate) static EXOKERNEL: ExoKernel = ExoKernel::new();

pub(crate) fn register_builtin_service_providers() {
    crate::kapi::providers::register_builtin_service_providers(&EXOKERNEL);
}

/// Register the kernel services (call from kmain early in boot)
///
/// # Safety
/// Must be called exactly once, before any KAPI functions are used.
pub unsafe fn register_kernel_services() {
    unsafe {
        kernel_api::service::kernel::install(&EXOKERNEL);
    }
}
