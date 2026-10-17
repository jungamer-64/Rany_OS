// ============================================================================
// kernel_api/src/lib.rs - Shared interfaces for Rany OS components
// ============================================================================

#![no_std]
#![feature(allocator_ext)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::use_self)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::must_use_candidate)]

extern crate alloc;

pub mod balloon;
pub mod block_io;
pub mod dma;

#[path = "application.rs"]
pub mod app;

#[path = "security.rs"]
pub mod capability;

#[path = "driver.rs"]
pub mod driver;

#[path = "error.rs"]
pub mod error;

pub mod ipc;
pub mod mmio;
pub mod msix;
pub mod pci_config;
pub mod provider;

pub mod resource;

#[path = "driver_abi.rs"]
mod driver_abi_impl;

#[cfg(feature = "cell_runtime")]
#[path = "cell_runtime.rs"]
mod runtime_impl;

#[cfg(feature = "cell_runtime")]
pub mod cell_runtime {
    pub use crate::runtime_impl::*;
}

#[path = "services.rs"]
mod service_kernel_impl;

#[path = "gui.rs"]
mod service_gui_impl;
pub mod gui {
    pub use crate::service_gui_impl::*;
}

#[path = "graphics.rs"]
mod service_graphics_impl;
pub mod graphics {
    pub use crate::service_graphics_impl::*;
}

#[path = "input.rs"]
mod service_input_impl;

#[path = "netdev.rs"]
mod service_netdev_impl;

pub mod netdev {
    pub use crate::service_netdev_impl::*;
}

#[path = "platform.rs"]
mod service_platform_impl;

#[path = "serial.rs"]
mod service_serial_impl;

#[path = "shell.rs"]
mod service_shell_impl;
pub mod shell {
    pub use crate::service_shell_impl::*;
}

#[path = "storage.rs"]
mod service_storage_impl;

#[path = "time.rs"]
mod service_time_impl;

pub mod abi {
    pub mod driver {
        pub use crate::driver_abi_impl::*;
    }

    pub mod provider {
        pub use crate::provider::*;
    }

    #[cfg(feature = "cell_runtime")]
    pub mod runtime {
        pub use crate::runtime_impl::*;
    }
}

pub mod service {
    pub mod kernel {
        pub use crate::service_kernel_impl::*;
    }

    pub mod input {
        pub use crate::service_input_impl::*;
    }

    pub mod netdev {
        pub use crate::service_netdev_impl::*;
    }

    pub mod platform {
        pub use crate::service_platform_impl::*;
    }

    pub mod serial {
        pub use crate::service_serial_impl::*;
    }

    pub mod storage {
        pub use crate::service_storage_impl::*;
    }

    pub mod time {
        pub use crate::service_time_impl::*;
    }
}

#[path = "types.rs"]
mod types_impl;

pub use error::{KapiError, KapiResult};

pub mod type_metadata;

#[doc(hidden)]
#[macro_export]
macro_rules! __count_exprs {
    () => {
        0usize
    };
    ($head:expr $(, $tail:expr)*) => {
        1usize + $crate::__count_exprs!($($tail),*)
    };
}

/// Emit a minimal `.rany_loop_proof` section consumed by kernel-side loop proof
/// checks.
///
/// Format:
/// - 4 bytes magic "RLOP"
/// - 4 bytes format version (u32 LE)
/// - 4 bytes policy flags (u32 LE, currently reserved)
#[macro_export]
macro_rules! declare_rany_loop_proof_section {
    () => {
        const _: () = {
            #[used]
            #[unsafe(link_section = ".rany_loop_proof")]
            static RANY_LOOP_PROOF_SECTION: [u8; 12] =
                [b'R', b'L', b'O', b'P', 1, 0, 0, 0, 0, 0, 0, 0];
        };
    };
}

/// Emit a minimal `.rany_type_id` section consumed by kernel-side ABI checks.
///
/// Format:
/// - 4 bytes magic "RTID"
/// - 4 bytes format version (u32 LE)
/// - 4 bytes dependency count (u32 LE)
#[macro_export]
macro_rules! declare_rany_type_id_section {
    ($($dep:expr),* $(,)?) => {
        $crate::declare_rany_loop_proof_section!();
        const _: () = {
            #[used]
            #[unsafe(link_section = ".rany_type_id")]
            static RANY_TYPE_ID_SECTION: $crate::type_metadata::TypeIdSection<
                { $crate::__count_exprs!($($dep),*) },
            > = $crate::type_metadata::build_section([$($dep),*]);
        };
    };
}

#[cfg(test)]
mod tests {
    use crate::abi::driver::{
        AbiError, DriverContext, PackedPciLocation, pack_version, unpack_version,
    };
    use crate::type_metadata;

    #[test]
    fn version_pack_unpack_smoke() {
        let packed = pack_version(3, 5, 8);
        assert_eq!(unpack_version(packed), (3, 5, 8));
    }

    #[test]
    fn abi_error_decode_smoke() {
        assert_eq!(AbiError::from_raw(-7), AbiError::Timeout);
        assert_eq!(AbiError::from_raw(-8), AbiError::IoError);
        assert!(AbiError::from_raw(0).is_success());
    }

    #[test]
    fn native_failures_preserve_busy_exhaustion_and_mapping_status_namespaces() {
        use crate::KapiError;
        use crate::mmio::MmioAcquireError;
        use crate::service::time::TimerError;
        // Status values are independent ABI vectors, including the MMIO
        // namespace where -2 denotes resource contention rather than absence.
        for (native, expected) in [
            (KapiError::Busy, -3),
            (KapiError::ResourceExhausted, -12),
            (KapiError::OutOfMemory, -5),
            (KapiError::Mmio(MmioAcquireError::ResourceBusy), -3),
            (KapiError::Mmio(MmioAcquireError::MappingFailed), -16),
            (KapiError::Mmio(MmioAcquireError::PermissionDenied), -9),
            (KapiError::Timer(TimerError::OrderExhausted), -12),
        ] {
            assert_eq!(AbiError::from(native) as i32, expected);
        }
        assert_eq!(AbiError::from_raw(-3).into_result(), Err(KapiError::Busy));
        assert_eq!(
            AbiError::from_raw(-12).into_result(),
            Err(KapiError::ResourceExhausted)
        );
    }

    #[test]
    fn driver_context_default_smoke() {
        let ctx = DriverContext::new();
        assert_eq!(ctx.device_address, 0);
        assert_eq!(ctx.device_address_secondary, 0);
        assert_eq!(ctx.pci_locator, 0);
        assert_eq!(ctx.irq, 0);
        assert_eq!(ctx.flags, 0);
        assert_eq!(ctx.driver_data, 0);
        assert_eq!(ctx.reserved, [0; 2]);
    }

    #[test]
    fn packed_pci_location_round_trip() {
        let locator = PackedPciLocation::new(0x1234, 0x56, 0x1A, 0x07);
        assert_eq!(locator.segment(), 0x1234);
        assert_eq!(locator.bus(), 0x56);
        assert_eq!(locator.device(), 0x1A);
        assert_eq!(locator.function(), 0x07);
        assert_eq!(PackedPciLocation::from_raw(locator.raw()), locator);
    }

    #[test]
    fn packed_pci_location_null_accessors_are_zero() {
        let locator = PackedPciLocation::NULL;
        assert!(locator.is_null());
        assert_eq!(locator.segment(), 0);
        assert_eq!(locator.bus(), 0);
        assert_eq!(locator.device(), 0);
        assert_eq!(locator.function(), 0);
    }

    #[test]
    fn driver_context_for_pci_preserves_locator() {
        let locator = PackedPciLocation::new(0x002a, 0x11, 0x03, 0x01);
        let ctx = DriverContext::for_pci(0xfeed_0000, 17, 0x8086, 0x1234, 0x0001_0802, locator);
        assert_eq!(ctx.device_address, 0xfeed_0000);
        assert_eq!(ctx.irq, 17);
        assert_eq!(ctx.vendor_id, 0x8086);
        assert_eq!(ctx.device_id, 0x1234);
        assert_eq!(ctx.class_code, 0x0001_0802);
        assert_eq!(ctx.pci_location(), locator);
    }

    #[test]
    fn type_id_section_builder_encodes_dependency_count_and_name() {
        let section = type_metadata::build_section([type_metadata::IPC_INTERFACE]);
        assert_eq!(&section.header[0..4], b"RTID");
        assert_eq!(
            u32::from_le_bytes(section.header[8..12].try_into().unwrap()),
            1
        );
        assert_eq!(&section.entries[0][..12], b"IpcInterface");
    }

    #[test]
    fn metadata_emission_preserves_full_width_names() {
        let name = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let section = type_metadata::build_section([type_metadata::dependency(name, 0, 1, 0, 0)]);
        assert_eq!(&section.entries[0][..64], name.as_bytes());
        assert_eq!(&section.header[4..8], &1u32.to_le_bytes());
    }

    #[test]
    #[should_panic]
    fn metadata_emission_rejects_truncated_identity() {
        type_metadata::build_section([type_metadata::dependency(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefX",
            0,
            1,
            0,
            0,
        )]);
    }
}
