// Include only the IOMMU implementation for test builds to avoid
// pulling in the whole I/O subsystem and its wide dependency graph.
#[path = "../io/iommu/mod.rs"]
pub mod iommu;

/// Minimal logger shim for test builds. Kernel code calls `io::log::early_print`,
/// `io::log::init()` and `io::log::notify_heap_available()` during early boot. We
/// provide lightweight no-op implementations here so unit tests can run without
/// pulling the full I/O logging subsystem into the test build.
pub mod log {
    /// Early boot serial-like print used before the full logger is initialized.
    pub fn early_print(s: &str) {
        std::print!("{}", s);
    }

    pub fn early_print_dec(n: u64) {
        std::print!("{}", n);
    }

    pub fn early_print_hex(n: u64) {
        std::print!("0x{:016x}", n);
    }

    /// Early boot single-character print used by low-level routines.
    pub fn early_print_char(c: u8) {
        std::print!("{}", c as char);
    }

    /// Initialize the logger. Returns Ok(()) for the test shim.
    pub fn init() -> Result<(), ()> {
        Ok(())
    }

    /// Notify the logging subsystem that the heap is now available.
    pub fn notify_heap_available() {}

    /// Print formatted arguments (test stub delegates to early_print).
    pub fn print(args: core::fmt::Arguments) {
        #[cfg(feature = "std")]
        {
            std::print!("{}", args);
        }
        #[cfg(not(feature = "std"))]
        {
            use core::fmt::Write;
            struct SerialWriter;
            impl core::fmt::Write for SerialWriter {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    early_print(s);
                    Ok(())
                }
            }
            let _ = SerialWriter.write_fmt(args);
        }
    }
}

pub mod interrupt_manager {
    pub fn send_ipi(_apic_id: u32, _vector: u8) {}
    pub fn broadcast_ipi(_vector: u8) {}
}

// Minimal PCI stub for test builds so IOMMU functions that reference
// `crate::drivers::pci::PciDeviceInfo` compile.
pub mod pci {
    #[derive(Debug, Clone, Copy)]
    pub struct Bus(pub u8);
    #[derive(Debug, Clone, Copy)]
    pub struct Device(pub u8);
    #[derive(Debug, Clone, Copy)]
    pub struct Function(pub u8);

    #[derive(Debug, Clone, Copy)]
    pub struct Bdf {
        pub bus: Bus,
        pub device: Device,
        pub function: Function,
    }

    #[derive(Debug)]
    pub struct PciDeviceInfo {
        pub bdf: Bdf,
        pub iommu_domain_id: Option<u16>,
    }

    impl PciDeviceInfo {
        pub fn is_pci_bridge(&self) -> bool {
            false
        }
    }
}

pub mod nvme {
    // Re-export the task-scoped NVMe driver for compatibility in test builds.
    // Tests expect `crate::drivers::nvme::NvmePollingDriver` and driver-global helpers.
    pub use crate::task::io::nvme::NvmePollingDriver;

    pub mod global {
        use crate::task::io::nvme::NvmePollingDriver;

        pub fn with_driver<F, R>(_f: F) -> Option<R>
        where
            F: FnOnce(&NvmePollingDriver) -> R,
        {
            None
        }

        pub fn with_driver_mut<F, R>(_f: F) -> Option<R>
        where
            F: FnOnce(&mut NvmePollingDriver) -> R,
        {
            None
        }
    }
}

// Minimal MMIO stubs used by the IOMMU unit tests. These provide
// deterministic behavior suitable for unit testing.
pub mod mmio {
    pub fn mmio_read_u8(_addr: usize) -> u8 {
        0
    }
    pub fn mmio_read_u16(_addr: usize) -> u16 {
        0
    }
    pub fn mmio_read_u32(_addr: usize) -> u32 {
        0
    }
    pub fn mmio_read_u64(_addr: usize) -> u64 {
        0
    }
    pub fn mmio_write_u8(_addr: usize, _v: u8) {}
    pub fn mmio_write_u16(_addr: usize, _v: u16) {}
    pub fn mmio_write_u32(_addr: usize, _v: u32) {}
    pub fn mmio_write_u64(_addr: usize, _v: u64) {}

    /// Generic volatile read for test builds.
    pub fn volatile_read<T: Copy>(addr: usize) -> T {
        unsafe { core::ptr::read_volatile(addr as *const T) }
    }

    /// Generic volatile write for test builds.
    pub fn volatile_write<T>(addr: usize, val: T) {
        unsafe {
            core::ptr::write_volatile(addr as *mut T, val);
        }
    }
}
