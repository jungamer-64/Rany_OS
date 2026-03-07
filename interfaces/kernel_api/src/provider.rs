// ============================================================================
// kernel_api/src/provider.rs - Provider metadata shared across kernel boundary
// ============================================================================

#![allow(clippy::module_name_repetitions)]

/// Version for provider descriptor tables.
pub const PROVIDER_DESCRIPTOR_ABI_VERSION: u32 = 1;

/// Runtime capability families exposed by drivers or kernel-owned adapters.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    PlatformAcpi = 1,
    PlatformPci = 2,
    PlatformApic = 3,
    Time = 4,
    Storage = 5,
    Netdev = 6,
    Input = 7,
    Serial = 8,
    Graphics = 9,
    Audio = 10,
}

/// Stable handle used by the kernel provider registry.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ProviderHandle(pub u64);

impl ProviderHandle {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// ABI-stable provider descriptor emitted by runtime-capable drivers.
///
/// `vtable` points at a family-specific table whose prefix is versioned by
/// `abi_version` / `abi_size`. The kernel keeps this generic descriptor and
/// interprets the concrete table based on `kind`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProviderDescriptorV1 {
    pub kind: ProviderKind,
    pub abi_version: u32,
    pub abi_size: u32,
    pub flags: u32,
    pub vtable: *const (),
    pub reserved: [u64; 4],
}

impl ProviderDescriptorV1 {
    pub const fn new(kind: ProviderKind, vtable: *const ()) -> Self {
        Self {
            kind,
            abi_version: PROVIDER_DESCRIPTOR_ABI_VERSION,
            abi_size: core::mem::size_of::<Self>() as u32,
            flags: 0,
            vtable,
            reserved: [0; 4],
        }
    }

    pub const fn validate(&self) -> bool {
        self.abi_version == PROVIDER_DESCRIPTOR_ABI_VERSION
            && self.abi_size >= core::mem::size_of::<Self>() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_descriptor_smoke() {
        let desc = ProviderDescriptorV1::new(ProviderKind::Time, core::ptr::null());
        assert!(desc.validate());
        assert_eq!(desc.kind, ProviderKind::Time);
        assert_eq!(desc.abi_version, PROVIDER_DESCRIPTOR_ABI_VERSION);
    }

    #[test]
    fn provider_handle_roundtrip() {
        let handle = ProviderHandle::new(42);
        assert_eq!(handle.raw(), 42);
    }
}
