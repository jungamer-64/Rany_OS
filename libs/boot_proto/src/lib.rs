// libs/boot_proto/src/lib.rs
#![no_std]

use graphic_types::FramebufferInfo;

/// Boot information passed from ExoLoader (UEFI) to the Kernel.
///
/// This struct must be `#[repr(C)]` to ensure ABI compatibility between
/// the bootloader (uefi-rs app) and the kernel (ELF).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExoBootInfo {
    /// Protocol version. Mismatch should cause a panic.
    pub version: u64,

    /// Physical memory offset (HHDM - Higher Half Direct Map).
    /// Used to convert physical addresses to virtual addresses (e.g. `phys + offset`).
    pub phys_mem_offset: u64,

    /// Physical address of the RSDP (Root System Description Pointer) for ACPI.
    pub rsdp_addr: u64,

    /// Physical address of the command line string (if any).
    pub cmdline_ptr: u64,
    /// Length of the command line string.
    pub cmdline_len: u64,

    /// Physical address of the PML4 page table (CR3 value) created by the bootloader.
    /// This allows the kernel to immediately take over memory management without finding it again.
    pub page_table_base: u64,

    /// TLS (Thread Local Storage) template information.
    /// Required for initializing TLS for the BSP and APs.
    pub tls_template: TlsInfo,

    /// Memory map provided by UEFI.
    pub memory_map: MemoryMap,

    /// Framebuffer information (resolution, base address, format).
    pub framebuffer: FramebufferInfo,

    /// Initramfs module (optional, for driver Cells).
    /// If ptr is null, no initramfs was loaded.
    pub initramfs: InitramfsModule,
}

/// Initramfs module information.
/// Contains pointer and size to the initramfs TAR archive loaded by bootloader.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InitramfsModule {
    /// Virtual address of initramfs data (null if not present).
    pub ptr: u64,
    /// Size of initramfs data in bytes.
    pub size: u64,
}

/// TLS Template Information derived from the ELF `PT_TLS` segment.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsInfo {
    /// Start address of the TLS template in memory (virtual address).
    pub start_addr: u64,
    /// Size of the TLS image (file size).
    pub file_size: u64,
    /// Total size of the TLS segment including BSS (memory size).
    pub mem_size: u64,
    /// Alignment requirement.
    pub align: u64,
}

/// A simplified memory map entry compatible with UEFI MemoryDescriptors.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMap {
    pub entries: *const MemoryDescriptor,
    pub count: u64,
}

/// Raw memory descriptor from UEFI (simplified or compatible).
/// For now, we assume this matches `uefi::table::boot::MemoryDescriptor` layout if `uefi-rs` is used,
/// or we convert it.
///
/// NOTE: To avoid direct dependency on `uefi` crate in the kernel, we define a compatible POD struct here.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub r#type: u32,
    pub pad: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}
