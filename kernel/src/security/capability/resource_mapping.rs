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
static CAPABILITY_DAEMONS_INIT: Once<()> = Once::new();

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

    // Keep init idempotent across repeated boot/test setup paths.
    CAPABILITY_DAEMONS_INIT.call_once(|| {
        spawn_expiry_daemon_task();
        spawn_reclamation_daemon_task();
    });
}

/// Expiry daemon (runs periodically to remove expired grants)
pub(crate) static CAP_EXPIRY_TASK: Once<()> = Once::new();

/// Async expiry daemon task
pub async fn expiry_daemon_task() {
    loop {
        manager().expire_grants();
        crate::task::sleep_ms(CAPABILITY_EXPIRY_INTERVAL_MS).await;
    }
}

/// Start the expiry daemon (idempotent)
pub fn spawn_expiry_daemon_task() {
    CAP_EXPIRY_TASK.call_once(|| {
        let _ = crate::task::spawn_detached(expiry_daemon_task());
    });
}

/// Test / utility: expire now (public wrapper)
pub fn expire_grants_now() {
    manager().expire_grants();
}

/// Reclamation daemon (runs periodically to reclaim revoked tokens once drained)
pub(crate) static CAP_RECLAIM_TASK: Once<()> = Once::new();

/// Async reclamation daemon task
pub async fn reclamation_daemon_task() {
    loop {
        manager().reclaim_revoked_now();
        crate::task::sleep_ms(CAPABILITY_EXPIRY_INTERVAL_MS).await;
    }
}

/// Start the reclamation daemon (idempotent)
pub fn spawn_reclamation_daemon_task() {
    CAP_RECLAIM_TASK.call_once(|| {
        let _ = crate::task::spawn_detached(reclamation_daemon_task());
    });
}

/// Test / utility: reclaim now (public wrapper)
pub fn reclaim_revoked_now() {
    manager().reclaim_revoked_now();
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
