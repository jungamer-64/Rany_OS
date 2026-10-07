//! Image-lifetime backing for the shared service trait implementations.

/// Connects shared service contracts to kernel-owned subsystems.
///
/// Authorization belongs to each service operation. The host owns admission and
/// unexpected termination of its image-lifetime maintenance tasks; device and
/// caller resources remain with their subsystem owners.
pub(super) struct KernelServiceHost {
    pub(super) network_consumers: crate::sync::Mutex<alloc::vec::Vec<super::network::Consumer>>,
    pub(super) block_io: crate::sync::Mutex<super::maintenance::State>,
    pub(super) maintenance: crate::sync::Mutex<super::maintenance::State>,
    pub(super) security_monitor: crate::sync::Mutex<super::maintenance::State>,
    pub(super) intel_commands: crate::sync::Mutex<super::maintenance::State>,
    pub(super) intel_faults: crate::sync::Mutex<super::maintenance::State>,
    pub(super) amd_commands: crate::sync::Mutex<super::maintenance::State>,
    pub(super) amd_faults: crate::sync::Mutex<super::maintenance::State>,
}

pub(super) static KERNEL_SERVICE_HOST: KernelServiceHost = KernelServiceHost {
    network_consumers: crate::sync::Mutex::new(alloc::vec::Vec::new()),
    block_io: crate::sync::Mutex::new(super::maintenance::State::Idle),
    maintenance: crate::sync::Mutex::new(super::maintenance::State::Idle),
    security_monitor: crate::sync::Mutex::new(super::maintenance::State::Idle),
    intel_commands: crate::sync::Mutex::new(super::maintenance::State::Idle),
    intel_faults: crate::sync::Mutex::new(super::maintenance::State::Idle),
    amd_commands: crate::sync::Mutex::new(super::maintenance::State::Idle),
    amd_faults: crate::sync::Mutex::new(super::maintenance::State::Idle),
};
