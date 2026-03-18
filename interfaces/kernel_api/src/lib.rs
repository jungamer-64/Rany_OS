// ============================================================================
// kernel_api/src/lib.rs - Shared interfaces for Rany OS components
// ============================================================================

#![no_std]
#![allow(dead_code)]
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::use_self)]
#![allow(clippy::inline_always)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::unnecessary_literal_bound)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(unused_variables)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::must_use_candidate)]

extern crate alloc;

pub mod block_io;

#[path = "application.rs"]
pub mod app;

#[path = "security.rs"]
pub mod capability;

pub mod dma;

#[path = "driver.rs"]
pub mod driver;

#[path = "error.rs"]
pub mod error;

pub mod ipc;
pub mod msix;
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

#[path = "graphics.rs"]
mod service_graphics_impl;

#[path = "input.rs"]
mod service_input_impl;

#[path = "netdev.rs"]
mod service_netdev_impl;

pub mod netdev {
    pub use crate::service_netdev_impl::*;
}

#[path = "platform.rs"]
mod service_platform_impl;

#[path = "audio.rs"]
mod service_audio_impl;

#[path = "serial.rs"]
mod service_serial_impl;

#[path = "shell.rs"]
mod service_shell_impl;

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

    pub mod gui {
        pub use crate::service_gui_impl::*;
    }

    pub mod graphics {
        pub use crate::service_graphics_impl::*;
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

    pub mod audio {
        pub use crate::service_audio_impl::*;
    }

    pub mod serial {
        pub use crate::service_serial_impl::*;
    }

    pub mod shell {
        pub use crate::service_shell_impl::*;
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

#[doc(hidden)]
pub mod __type_id {
    use crate::ipc::fnv1a_hash;

    pub const ENTRY_NAME_LEN: usize = 64;
    pub const ENTRY_SIZE: usize = 78;

    #[derive(Clone, Copy)]
    pub struct DependencySpec {
        pub name: &'static str,
        pub hash: u64,
        pub major: u16,
        pub minor: u16,
        pub patch: u16,
    }

    #[repr(C)]
    pub struct TypeIdSection<const N: usize> {
        pub header: [u8; 12],
        pub entries: [[u8; ENTRY_SIZE]; N],
    }

    pub const fn dependency(
        name: &'static str,
        hash: u64,
        major: u16,
        minor: u16,
        patch: u16,
    ) -> DependencySpec {
        DependencySpec {
            name,
            hash,
            major,
            minor,
            patch,
        }
    }

    const fn encode_entry(dep: DependencySpec) -> [u8; ENTRY_SIZE] {
        let mut entry = [0u8; ENTRY_SIZE];
        let bytes = dep.name.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() && i < ENTRY_NAME_LEN {
            entry[i] = bytes[i];
            i += 1;
        }

        let hash = dep.hash.to_le_bytes();
        let mut j = 0usize;
        while j < hash.len() {
            entry[64 + j] = hash[j];
            j += 1;
        }

        let major = dep.major.to_le_bytes();
        let minor = dep.minor.to_le_bytes();
        let patch = dep.patch.to_le_bytes();
        entry[72] = major[0];
        entry[73] = major[1];
        entry[74] = minor[0];
        entry[75] = minor[1];
        entry[76] = patch[0];
        entry[77] = patch[1];
        entry
    }

    pub const fn build_section<const N: usize>(deps: [DependencySpec; N]) -> TypeIdSection<N> {
        let mut entries = [[0u8; ENTRY_SIZE]; N];
        let mut i = 0usize;
        while i < N {
            entries[i] = encode_entry(deps[i]);
            i += 1;
        }

        TypeIdSection {
            header: [
                b'R',
                b'T',
                b'I',
                b'D',
                1,
                0,
                0,
                0,
                (N as u32).to_le_bytes()[0],
                (N as u32).to_le_bytes()[1],
                (N as u32).to_le_bytes()[2],
                (N as u32).to_le_bytes()[3],
            ],
            entries,
        }
    }

    pub const MEMORY_ALLOCATOR_INTERFACE: DependencySpec = dependency(
        "MemoryAllocatorInterface",
        fnv1a_hash(b"MemoryAllocatorInterface:v1:alloc(Layout)->*mut u8,dealloc(*mut u8,Layout)"),
        1,
        0,
        0,
    );
    pub const TASK_SCHEDULER_INTERFACE: DependencySpec = dependency(
        "TaskSchedulerInterface",
        fnv1a_hash(b"TaskSchedulerInterface:v1:spawn(Future)->TaskId,yield_now(),sleep(Duration)"),
        1,
        0,
        0,
    );
    pub const IPC_INTERFACE: DependencySpec = dependency(
        "IpcInterface",
        fnv1a_hash(b"IpcInterface:v1:send(RRef<T>),recv()->RRef<T>,create_channel()->ChannelPair"),
        1,
        0,
        0,
    );
    pub const KERNEL_API_INTERFACE: DependencySpec = dependency(
        "KernelApiInterface",
        fnv1a_hash(b"KernelApiInterface:v7:KernelApiV4+exchange_heap+ipc_raw+domain_id+net_packet"),
        1,
        0,
        0,
    );
    pub const DRIVER_EXPORTS_INTERFACE: DependencySpec = dependency(
        "DriverExportsInterface",
        fnv1a_hash(b"DriverExportsInterface:v2:DriverExportsV1+state_hooks"),
        1,
        0,
        0,
    );
}

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
            static RANY_TYPE_ID_SECTION: $crate::__type_id::TypeIdSection<
                { $crate::__count_exprs!($($dep),*) },
            > = $crate::__type_id::build_section([$($dep),*]);
        };
    };
}

#[cfg(test)]
mod tests {
    use crate::__type_id;
    use crate::abi::driver::{
        AbiError, DriverContext, PackedPciLocation, pack_version, unpack_version,
    };

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
        let ctx = DriverContext::for_pci(0xfeed_0000, 17, 0x8086, 0x1234, 0x0108_02, locator);
        assert_eq!(ctx.device_address, 0xfeed_0000);
        assert_eq!(ctx.irq, 17);
        assert_eq!(ctx.vendor_id, 0x8086);
        assert_eq!(ctx.device_id, 0x1234);
        assert_eq!(ctx.class_code, 0x0108_02);
        assert_eq!(ctx.pci_location(), locator);
    }

    #[test]
    fn type_id_section_builder_encodes_dependency_count_and_name() {
        let section = __type_id::build_section([__type_id::IPC_INTERFACE]);
        assert_eq!(&section.header[0..4], b"RTID");
        assert_eq!(
            u32::from_le_bytes(section.header[8..12].try_into().unwrap()),
            1
        );
        assert_eq!(&section.entries[0][..12], b"IpcInterface");
    }
}
