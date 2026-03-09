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
    () => {
        $crate::declare_rany_loop_proof_section!();
        const _: () = {
            #[used]
            #[unsafe(link_section = ".rany_type_id")]
            static RANY_TYPE_ID_SECTION: [u8; 12] =
                [b'R', b'T', b'I', b'D', 1, 0, 0, 0, 0, 0, 0, 0];
        };
    };
}

#[cfg(test)]
mod tests {
    use crate::abi::driver::{AbiError, DriverContext, pack_version, unpack_version};

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
        assert_eq!(ctx.irq, 0);
        assert_eq!(ctx.flags, 0);
        assert_eq!(ctx.driver_data, 0);
        assert_eq!(ctx.reserved, [0; 3]);
    }
}
