use super::*;

/// Helper: Map resource string to capability bit
pub fn resource_to_capability(resource: &str) -> Capability {
    match resource {
        "/net/bind" => CAP_NET_BIND,
        "/net/raw" => CAP_NET_RAW,
        "/sys/admin" => CAP_SYS_ADMIN,
        "/sys/boot" => CAP_SYS_BOOT,
        "/sys/time" => CAP_SYS_TIME,
        "/sys/module" => CAP_SYS_MODULE,
        "/sys/physmem" => CAP_SYS_PHYSMEM,
        "/sys/dma" => CAP_DMA,
        "/sys/iommu" => CAP_IOMMU,
        "/sys/interrupt" => CAP_INTERRUPT,
        _ => 0,
    }
}

/// Global capability manager
pub(crate) static CAPABILITY_MANAGER: CapabilityManager = CapabilityManager::new();

/// Get the global capability manager
pub fn manager() -> &'static CapabilityManager {
    &CAPABILITY_MANAGER
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    CAPABILITY_MANAGER.reset_for_tests();
}

/// Initialize capabilities for kernel domain
pub fn init() {
    // Kernel domain gets all capabilities
    CAPABILITY_MANAGER.set_capabilities(0, CapabilitySet::full());
}

/// The service host owns this image-lifetime grant maintenance operation.
/// Timer failure returns to that owner without losing outstanding grant leases.
pub(crate) async fn maintain_grants() -> Result<(), kernel_api::service::time::TimerError> {
    let grants = manager();
    // LOOP_PROOF: mode=event; reason=Grant maintenance waits on an admitted timer after each pass and returns timer failure to the service host.;
    loop {
        grants.expire_grants_at(crate::task::current_tick());
        grants.reclaim_revoked_now();
        kernel_api::service::time::sleep_ms(CAPABILITY_EXPIRY_INTERVAL_MS).await?;
    }
}

/// Get capability name
pub fn capability_name(cap: Capability) -> &'static str {
    match cap {
        CAP_NET_BIND => "CAP_NET_BIND",
        CAP_NET_RAW => "CAP_NET_RAW",
        CAP_SYS_ADMIN => "CAP_SYS_ADMIN",
        CAP_SYS_BOOT => "CAP_SYS_BOOT",
        CAP_SYS_TIME => "CAP_SYS_TIME",
        CAP_SYS_PTRACE => "CAP_SYS_PTRACE",
        CAP_DAC_OVERRIDE => "CAP_DAC_OVERRIDE",
        CAP_KILL => "CAP_KILL",
        CAP_SETUID => "CAP_SETUID",
        CAP_SETGID => "CAP_SETGID",
        CAP_CHOWN => "CAP_CHOWN",
        CAP_FOWNER => "CAP_FOWNER",
        CAP_SYS_RAWIO => "CAP_SYS_RAWIO",
        CAP_IPC_LOCK => "CAP_IPC_LOCK",
        CAP_SYS_NICE => "CAP_SYS_NICE",
        CAP_NET_ADMIN => "CAP_NET_ADMIN",
        CAP_SYS_MODULE => "CAP_SYS_MODULE",
        CAP_SYS_PHYSMEM => "CAP_SYS_PHYSMEM",
        CAP_DMA => "CAP_DMA",
        CAP_IOMMU => "CAP_IOMMU",
        CAP_INTERRUPT => "CAP_INTERRUPT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
