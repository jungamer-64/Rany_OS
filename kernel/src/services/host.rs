//! Image-lifetime backing for the shared service trait implementations.

/// Connects shared service contracts to kernel-owned subsystems.
///
/// This instance carries neither caller identity nor resource ownership.
/// Authorization belongs to the service operations; subsystem state stays with
/// its owner.
pub(super) struct KernelServiceHost;

pub(super) static KERNEL_SERVICE_HOST: KernelServiceHost = KernelServiceHost;
