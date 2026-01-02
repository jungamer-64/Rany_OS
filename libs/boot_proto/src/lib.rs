// libs/boot_proto/src/lib.rs
#![no_std]
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::doc_markdown)]

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

    /// NUMA topology information (optional).
    /// Detected from ACPI SRAT table.
    pub numa_info: NumaInfo,

    /// AP (Application Processor) boot information.
    /// Contains trampoline code address and stack allocation info.
    pub ap_boot: ApBootInfo,

    /// UEFI Runtime Services information.
    /// Allows kernel to access UEFI variables, RTC, etc. after ExitBootServices.
    pub uefi_runtime: UefiRuntimeInfo,
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

/// Maximum number of NUMA nodes supported
pub const MAX_NUMA_NODES: usize = 8;

/// NUMA topology information detected from ACPI SRAT.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NumaInfo {
    /// Number of NUMA nodes detected (0 if NUMA not available)
    pub node_count: u8,
    /// Reserved for alignment
    pub _reserved: [u8; 7],
    /// Per-node information
    pub nodes: [NumaNodeInfo; MAX_NUMA_NODES],
}

impl Default for NumaInfo {
    fn default() -> Self {
        Self {
            node_count: 0,
            _reserved: [0; 7],
            nodes: [NumaNodeInfo::default(); MAX_NUMA_NODES],
        }
    }
}

/// Information about a single NUMA node.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NumaNodeInfo {
    /// Proximity domain ID (from SRAT)
    pub proximity_domain: u32,
    /// Number of memory ranges in this node
    pub memory_range_count: u8,
    /// Number of CPUs in this node
    pub cpu_count: u8,
    /// Reserved for alignment
    pub _reserved: [u8; 2],
    /// Memory ranges belonging to this node (up to 4)
    pub memory_ranges: [NumaMemoryRange; 4],
    /// CPU APIC IDs belonging to this node (up to 64)
    /// Stored as a bitmask for efficiency
    pub cpu_apic_mask_low: u64,
    pub cpu_apic_mask_high: u64,
}

impl Default for NumaNodeInfo {
    fn default() -> Self {
        Self {
            proximity_domain: 0,
            memory_range_count: 0,
            cpu_count: 0,
            _reserved: [0; 2],
            memory_ranges: [NumaMemoryRange::default(); 4],
            cpu_apic_mask_low: 0,
            cpu_apic_mask_high: 0,
        }
    }
}

/// A memory range within a NUMA node.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NumaMemoryRange {
    /// Base physical address
    pub base: u64,
    /// Length in bytes
    pub length: u64,
}

/// AP (Application Processor) boot information.
/// Used by the kernel to initialize secondary CPUs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ApBootInfo {
    /// Number of APs detected (excluding BSP)
    pub ap_count: u16,
    /// Reserved for alignment
    pub _reserved: [u8; 6],
    /// Physical address of AP trampoline code (must be < 1MB for real mode)
    pub trampoline_addr: u64,
    /// Size of trampoline code in bytes
    pub trampoline_size: u64,
    /// Physical address of pre-allocated AP stack region
    pub stack_base: u64,
    /// Size of each AP stack in bytes
    pub stack_size: u64,
    /// Total number of stacks pre-allocated
    pub stack_count: u16,
    /// Reserved
    pub _reserved2: [u8; 6],
}

impl Default for ApBootInfo {
    fn default() -> Self {
        Self {
            ap_count: 0,
            _reserved: [0; 6],
            trampoline_addr: 0,
            trampoline_size: 0,
            stack_base: 0,
            stack_size: 0,
            stack_count: 0,
            _reserved2: [0; 6],
        }
    }
}

/// Maximum number of runtime memory map entries
pub const MAX_RUNTIME_MMAP_ENTRIES: usize = 64;

/// UEFI Runtime Services information.
/// Allows the kernel to call UEFI runtime services after ExitBootServices.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UefiRuntimeInfo {
    /// Physical address of the UEFI Runtime Services Table.
    /// This table contains function pointers to GetTime, SetTime, GetVariable, etc.
    pub runtime_services_addr: u64,

    /// Virtual address to map the Runtime Services Table to.
    /// Must be set via SetVirtualAddressMap before using runtime services.
    pub runtime_services_virt: u64,

    /// Number of runtime memory regions that need virtual address mapping.
    pub runtime_mmap_count: u32,

    /// Flags indicating available runtime services.
    pub capabilities: u32,

    /// Runtime memory regions (physical addresses and sizes).
    /// These must be identity-mapped or virtually mapped for runtime services to work.
    pub runtime_mmap: [RuntimeMemoryRegion; MAX_RUNTIME_MMAP_ENTRIES],
}

impl Default for UefiRuntimeInfo {
    fn default() -> Self {
        Self {
            runtime_services_addr: 0,
            runtime_services_virt: 0,
            runtime_mmap_count: 0,
            capabilities: 0,
            runtime_mmap: [RuntimeMemoryRegion::default(); MAX_RUNTIME_MMAP_ENTRIES],
        }
    }
}

/// A runtime memory region that must remain accessible after ExitBootServices.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeMemoryRegion {
    /// Physical address of the region.
    pub phys_addr: u64,
    /// Virtual address (to be set by kernel).
    pub virt_addr: u64,
    /// Size in pages (4KB each).
    pub page_count: u64,
    /// Memory type (from UEFI).
    pub memory_type: u32,
    /// Memory attributes.
    pub attributes: u32,
}

/// UEFI Runtime Services capability flags
pub mod runtime_caps {
    /// GetTime / SetTime available
    pub const TIME_SERVICES: u32 = 1 << 0;
    /// GetVariable / SetVariable / GetNextVariableName available
    pub const VARIABLE_SERVICES: u32 = 1 << 1;
    /// ResetSystem available
    pub const RESET_SYSTEM: u32 = 1 << 2;
    /// UpdateCapsule available
    pub const CAPSULE_SERVICES: u32 = 1 << 3;
    /// QueryCapsuleCapabilities available
    pub const QUERY_CAPSULE: u32 = 1 << 4;
}
