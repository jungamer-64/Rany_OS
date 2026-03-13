// libs/boot_proto/src/lib.rs
#![no_std]
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::doc_markdown)]

use graphic_types::FramebufferInfo;

pub use ap_trampoline::ApBootFlags;
pub use boot_config::{BootPolicy, BootPolicyError, BootShellMode};

pub const EXO_BOOT_INFO_VERSION: u64 = 6;

/// Boot information passed from ExoLoader (UEFI) to the Kernel.
///
/// This struct must be `#[repr(C)]` to ensure ABI compatibility between
/// the bootloader (uefi-rs app) and the kernel (ELF).
///
/// # ブートローダー → カーネル ハンドオフプロトコル
///
/// 1. ブートローダーが `ExoBootInfo` を物理メモリに割り当て、全フィールドを設定する
/// 2. ポインタ型フィールド (`cmdline_ptr`, `boot_artifacts.entries_ptr`,
///    `memory_map.entries`, `usable_memory.entries_ptr`)
///    は HHDM 仮想アドレス (`phys_mem_offset + phys_addr`) で格納する
/// 3. ブートサービス終了後、CR3 を切り替え、`&ExoBootInfo` を RDI に渡してカーネルへジャンプ
/// 4. カーネルは `version` フィールドを検証し、不一致時はパニックする
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

    /// Boot-critical policy normalized by the bootloader.
    pub boot_policy: BootPolicy,

    /// Physical address of the root page table (CR3 value) created by the bootloader.
    /// This allows the kernel to immediately take over memory management without finding it again.
    pub page_table_base: u64,
    /// TLS (Thread Local Storage) template information.
    /// Required for initializing TLS for the BSP and APs.
    pub tls_template: TlsInfo,

    /// Memory map provided by UEFI.
    pub memory_map: MemoryMap,
    /// Bootloader-normalized usable physical memory regions.
    pub usable_memory: UsableMemoryTable,

    /// Framebuffer information (resolution, base address, format).
    pub framebuffer: FramebufferInfo,

    /// Boot artifacts discovered on the boot partition (optional).
    /// Driver artifacts under `/drivers` are autostart/staging inputs, and
    /// fixture cells under `/cells` remain data-only runtime artifacts.
    pub boot_artifacts: BootArtifactTable,

    /// NUMA topology information (optional).
    /// Detected from ACPI SRAT table.
    pub numa_info: NumaInfo,
    /// Immutable ACPI snapshot for early boot consumers.
    pub acpi_snapshot: AcpiBootSnapshot,

    /// AP (Application Processor) boot information.
    /// Contains trampoline code address and stack allocation info.
    pub ap_boot: ApBootInfo,

    /// UEFI Runtime Services information.
    /// Allows kernel to access UEFI variables, RTC, etc. after ExitBootServices.
    pub uefi_runtime: UefiRuntimeInfo,

    /// Memory encryption information (AMD SME/SEV, Intel TDX).
    /// Used for proper page table setup with encryption bits.
    pub mem_encryption: MemoryEncryptionInfo,

    /// UEFI Secure Boot state information.
    /// Indicates whether Secure Boot is enabled and its configuration.
    pub secure_boot: SecureBootInfo,

    /// Shim bootloader and MOK (Machine Owner Key) information.
    /// Indicates if we were launched via Shim and MOK state.
    pub shim_mok: ShimMokInfo,

    /// SMBIOS (System Management BIOS) information.
    /// Contains table addresses and basic system/BIOS info.
    pub smbios: SmbiosInfo,

    /// Boot recovery information.
    /// Contains failure count, recovery mode status, etc.
    pub boot_recovery: BootRecoveryInfo,

    /// Self-test results.
    /// Contains results from boot-time hardware validation.
    pub self_test: SelfTestInfo,

    /// Paging levels used by the bootloader (4 or 5).
    pub paging_levels: u64,
    /// LA57 enabled state (1 if CR4.LA57 is set, 0 otherwise).
    pub la57_enabled: u64,
}

impl ExoBootInfo {
    /// プロトコルバージョンを検証する。不一致なら `false` を返す。
    #[inline]
    pub fn is_version_compatible(&self) -> bool {
        self.version == EXO_BOOT_INFO_VERSION
    }

    /// カーネルコマンドラインを `&str` として取得する。
    ///
    /// ブートローダーは `cmdline_ptr` を HHDM 仮想アドレスで格納するため、
    /// 直接ポインタとして解釈して安全にアクセスできる。
    ///
    /// # Safety
    /// ブートローダーから渡された `cmdline_ptr` が有効な仮想アドレスであり、
    /// `cmdline_len` バイト分のメモリが読み取り可能であることが前提。
    pub unsafe fn cmdline(&self) -> Option<&str> {
        if self.cmdline_len == 0 || self.cmdline_ptr == 0 {
            return None;
        }
        let len = self.cmdline_len as usize;
        let ptr = self.cmdline_ptr as *const u8;
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        core::str::from_utf8(slice).ok()
    }
}

/// Kind discriminator for a boot artifact handed off by the bootloader.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootArtifactKind {
    /// Driver artifact under `/drivers`.
    DriverArtifact = 1,
    /// Fixture cell under `/cells`.
    FixtureCell = 2,
}

impl BootArtifactKind {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::DriverArtifact),
            2 => Some(Self::FixtureCell),
            _ => None,
        }
    }
}

/// Single boot artifact metadata + borrowed payload span.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BootArtifactEntry {
    /// Raw kind discriminator (`BootArtifactKind`).
    pub kind: u32,
    /// Reserved for future flags. Must be zero for now.
    pub flags: u32,
    /// HHDM virtual address of the UTF-8 artifact path bytes.
    pub path_ptr: u64,
    /// Length of the UTF-8 path bytes.
    pub path_len: u64,
    /// HHDM virtual address of the artifact payload bytes.
    pub data_ptr: u64,
    /// Length of the payload bytes.
    pub data_len: u64,
}

impl BootArtifactEntry {
    #[must_use]
    pub const fn kind(&self) -> Option<BootArtifactKind> {
        BootArtifactKind::from_raw(self.kind)
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        if self.path_ptr == 0 || self.path_len == 0 {
            return None;
        }
        let len = usize::try_from(self.path_len).ok()?;
        let bytes = unsafe { core::slice::from_raw_parts(self.path_ptr as *const u8, len) };
        core::str::from_utf8(bytes).ok()
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        if self.data_ptr == 0 || self.data_len == 0 {
            return &[];
        }
        let Some(len) = usize::try_from(self.data_len).ok() else {
            return &[];
        };
        unsafe { core::slice::from_raw_parts(self.data_ptr as *const u8, len) }
    }
}

/// Table of boot artifacts discovered by the bootloader.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BootArtifactTable {
    /// HHDM virtual address of a `BootArtifactEntry[count]` array.
    pub entries_ptr: u64,
    /// Number of entries in the array.
    pub count: u64,
}

impl BootArtifactTable {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries_ptr == 0 || self.count == 0
    }

    #[must_use]
    pub fn entries(&self) -> &[BootArtifactEntry] {
        if self.is_empty() {
            return &[];
        }
        let Some(count) = usize::try_from(self.count).ok() else {
            return &[];
        };
        unsafe { core::slice::from_raw_parts(self.entries_ptr as *const BootArtifactEntry, count) }
    }
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

/// Single usable physical memory region after bootloader reservations.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsableMemoryRegion {
    pub base: u64,
    pub length: u64,
}

/// Table of bootloader-normalized usable memory regions.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsableMemoryTable {
    pub entries_ptr: u64,
    pub count: u64,
}

impl UsableMemoryTable {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries_ptr == 0 || self.count == 0
    }

    #[must_use]
    pub fn regions(&self) -> &[UsableMemoryRegion] {
        if self.is_empty() {
            return &[];
        }
        let Some(count) = usize::try_from(self.count).ok() else {
            return &[];
        };
        unsafe { core::slice::from_raw_parts(self.entries_ptr as *const UsableMemoryRegion, count) }
    }
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

pub const MAX_ACPI_LOCAL_APICS: usize = 256;
pub const MAX_ACPI_IO_APICS: usize = 32;
pub const MAX_ACPI_INTERRUPT_OVERRIDES: usize = 64;
pub const MAX_ACPI_PCIE_ECAM: usize = 32;

/// ACPI snapshot validity flags.
pub mod acpi_snapshot_flags {
    pub const VALID: u32 = 1 << 0;
    pub const HAS_LEGACY_PICS: u32 = 1 << 1;
}

/// Local APIC flags stored in `BootLocalApicRecord.flags`.
pub mod acpi_local_apic_flags {
    pub const ENABLED: u8 = 1 << 0;
    pub const ONLINE_CAPABLE: u8 = 1 << 1;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootLocalApicRecord {
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u8,
    pub _reserved: u8,
}

impl BootLocalApicRecord {
    #[must_use]
    pub const fn enabled(&self) -> bool {
        (self.flags & acpi_local_apic_flags::ENABLED) != 0
    }

    #[must_use]
    pub const fn online_capable(&self) -> bool {
        (self.flags & acpi_local_apic_flags::ONLINE_CAPABLE) != 0
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootIoApicRecord {
    pub address: u64,
    pub gsi_base: u32,
    pub id: u8,
    pub _reserved: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootInterruptOverrideRecord {
    pub gsi: u32,
    pub bus: u8,
    pub source: u8,
    pub polarity: u8,
    pub trigger_mode: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootPcieEcamRecord {
    pub base_address: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

/// Immutable ACPI snapshot for early boot consumers.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AcpiBootSnapshot {
    pub flags: u32,
    pub revision: u8,
    pub _reserved: [u8; 3],
    pub local_apic_address: u64,
    pub dmar_addr: u64,
    pub ivrs_addr: u64,
    pub local_apic_count: u16,
    pub io_apic_count: u16,
    pub interrupt_override_count: u16,
    pub pcie_ecam_count: u16,
    pub local_apics: [BootLocalApicRecord; MAX_ACPI_LOCAL_APICS],
    pub io_apics: [BootIoApicRecord; MAX_ACPI_IO_APICS],
    pub interrupt_overrides: [BootInterruptOverrideRecord; MAX_ACPI_INTERRUPT_OVERRIDES],
    pub pcie_ecam: [BootPcieEcamRecord; MAX_ACPI_PCIE_ECAM],
}

impl Default for AcpiBootSnapshot {
    fn default() -> Self {
        Self {
            flags: 0,
            revision: 0,
            _reserved: [0; 3],
            local_apic_address: 0,
            dmar_addr: 0,
            ivrs_addr: 0,
            local_apic_count: 0,
            io_apic_count: 0,
            interrupt_override_count: 0,
            pcie_ecam_count: 0,
            local_apics: [BootLocalApicRecord::default(); MAX_ACPI_LOCAL_APICS],
            io_apics: [BootIoApicRecord::default(); MAX_ACPI_IO_APICS],
            interrupt_overrides: [BootInterruptOverrideRecord::default();
                MAX_ACPI_INTERRUPT_OVERRIDES],
            pcie_ecam: [BootPcieEcamRecord::default(); MAX_ACPI_PCIE_ECAM],
        }
    }
}

impl AcpiBootSnapshot {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        (self.flags & acpi_snapshot_flags::VALID) != 0
    }

    #[must_use]
    pub const fn has_legacy_pics(&self) -> bool {
        (self.flags & acpi_snapshot_flags::HAS_LEGACY_PICS) != 0
    }

    #[must_use]
    pub fn local_apics(&self) -> &[BootLocalApicRecord] {
        let count = usize::from(self.local_apic_count).min(self.local_apics.len());
        &self.local_apics[..count]
    }

    #[must_use]
    pub fn io_apics(&self) -> &[BootIoApicRecord] {
        let count = usize::from(self.io_apic_count).min(self.io_apics.len());
        &self.io_apics[..count]
    }

    #[must_use]
    pub fn interrupt_overrides(&self) -> &[BootInterruptOverrideRecord] {
        let count = usize::from(self.interrupt_override_count).min(self.interrupt_overrides.len());
        &self.interrupt_overrides[..count]
    }

    #[must_use]
    pub fn pcie_ecam(&self) -> &[BootPcieEcamRecord] {
        let count = usize::from(self.pcie_ecam_count).min(self.pcie_ecam.len());
        &self.pcie_ecam[..count]
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApBootInfo {
    /// Number of APs detected (excluding BSP)
    pub ap_count: u16,
    /// Total number of stacks pre-allocated
    pub stack_count: u16,
    /// Reserved for alignment
    pub _reserved: [u8; 4],
    /// AP boot handoff flags.
    pub flags: u32,
    /// Shared trampoline layout version.
    pub trampoline_layout_version: u32,
    /// Shared trampoline mailbox offset in bytes.
    pub trampoline_mailbox_offset: u32,
    /// Reserved for future expansion.
    pub _reserved2: [u8; 4],
    /// Physical address of AP trampoline code (must be < 1MB for real mode)
    pub trampoline_addr: u64,
    /// Size of trampoline code in bytes
    pub trampoline_size: u64,
    /// Physical address of pre-allocated AP stack region
    pub stack_base: u64,
    /// Size of each AP stack in bytes
    pub stack_size: u64,
}

impl Default for ApBootInfo {
    fn default() -> Self {
        Self {
            ap_count: 0,
            stack_count: 0,
            _reserved: [0; 4],
            flags: 0,
            trampoline_layout_version: 0,
            trampoline_mailbox_offset: 0,
            _reserved2: [0; 4],
            trampoline_addr: 0,
            trampoline_size: 0,
            stack_base: 0,
            stack_size: 0,
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

/// Memory encryption information (AMD SME/SEV, Intel TDX).
/// Used by the kernel to handle encrypted memory correctly.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryEncryptionInfo {
    /// AMD SME (Secure Memory Encryption) is available
    pub sme_available: bool,
    /// AMD SEV (Secure Encrypted Virtualization) is available
    pub sev_available: bool,
    /// AMD SEV-ES (Encrypted State) is available
    pub sev_es_available: bool,
    /// AMD SEV-SNP (Secure Nested Paging) is available
    pub sev_snp_available: bool,
    /// SME is currently enabled
    pub sme_enabled: bool,
    /// SEV is currently enabled (running in SEV guest)
    pub sev_enabled: bool,
    /// Reserved for alignment
    pub _reserved: [u8; 2],
    /// C-bit position in page table entries (AMD specific)
    pub c_bit_position: u8,
    /// Physical address reduction due to encryption
    pub phys_addr_reduction: u8,
    /// Reserved for alignment
    pub _reserved2: [u8; 6],
    /// Encryption mask to apply to page table entries
    pub encryption_mask: u64,
    /// Intel TDX is available
    pub tdx_available: bool,
    /// Reserved for future use
    pub _reserved3: [u8; 7],
}

impl Default for MemoryEncryptionInfo {
    fn default() -> Self {
        Self {
            sme_available: false,
            sev_available: false,
            sev_es_available: false,
            sev_snp_available: false,
            sme_enabled: false,
            sev_enabled: false,
            _reserved: [0; 2],
            c_bit_position: 0,
            phys_addr_reduction: 0,
            _reserved2: [0; 6],
            encryption_mask: 0,
            tdx_available: false,
            _reserved3: [0; 7],
        }
    }
}

/// UEFI Secure Boot state information.
/// Provides information about the Secure Boot configuration.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecureBootInfo {
    /// Secure Boot is enabled
    pub secure_boot_enabled: bool,
    /// System is in Setup Mode (Secure Boot not enforced)
    pub setup_mode: bool,
    /// Platform Key (PK) is enrolled
    pub pk_present: bool,
    /// Key Exchange Key (KEK) is enrolled
    pub kek_present: bool,
    /// Signature database (db) is present
    pub db_present: bool,
    /// Forbidden signature database (dbx) is present
    pub dbx_present: bool,
    /// Audit mode is enabled
    pub audit_mode: bool,
    /// Deployed mode is enabled
    pub deployed_mode: bool,
    /// Vendor keys are present
    pub vendor_keys: bool,
    /// dbx revocation check passed (kernel not in forbidden list)
    pub dbx_check_passed: bool,
    /// Reserved for alignment
    pub _reserved: [u8; 6],
    /// SHA-256 hash of the loaded kernel ELF image (set by bootloader)
    pub kernel_sha256: [u8; 32],
}

impl Default for SecureBootInfo {
    fn default() -> Self {
        Self {
            secure_boot_enabled: false,
            setup_mode: false,
            pk_present: false,
            kek_present: false,
            db_present: false,
            dbx_present: false,
            audit_mode: false,
            deployed_mode: false,
            vendor_keys: false,
            dbx_check_passed: false,
            _reserved: [0; 6],
            kernel_sha256: [0u8; 32],
        }
    }
}

/// Secure Boot mode flags
pub mod secure_boot_flags {
    /// Secure Boot is enabled and enforcing
    pub const SECURE_BOOT_ENABLED: u32 = 1 << 0;
    /// System is in Setup Mode
    pub const SETUP_MODE: u32 = 1 << 1;
    /// Platform Key is enrolled
    pub const PK_PRESENT: u32 = 1 << 2;
    /// Key Exchange Key is enrolled
    pub const KEK_PRESENT: u32 = 1 << 3;
    /// Signature database (db) is present
    pub const DB_PRESENT: u32 = 1 << 4;
    /// Forbidden signature database (dbx) is present
    pub const DBX_PRESENT: u32 = 1 << 5;
    /// Audit mode is enabled
    pub const AUDIT_MODE: u32 = 1 << 6;
    /// Deployed mode is enabled
    pub const DEPLOYED_MODE: u32 = 1 << 7;
}

/// Shim bootloader and MOK (Machine Owner Key) information.
/// Provides information about Shim-based Secure Boot chain.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ShimMokInfo {
    /// Shim Lock Protocol detected (we were launched by Shim)
    pub shim_detected: bool,
    /// MOK Secure Boot validation state in Shim
    /// 0 = disabled, 1 = enabled
    pub mok_sb_state: u8,
    /// MokList variable present (MOK certificates enrolled)
    pub mok_list_present: bool,
    /// MokListRT variable present (runtime MOK access)
    pub mok_list_rt_present: bool,
    /// MokListX variable present (MOK revocation list)
    pub mok_list_x_present: bool,
    /// SbatLevel variable present (SBAT revocation)
    pub sbat_level_present: bool,
    /// Shim validated this binary
    pub shim_validated: bool,
    /// Reserved for alignment
    pub _reserved: u8,
    /// Number of MOK certificates enrolled
    pub mok_count: u16,
    /// Shim version (major.minor)
    pub shim_version_major: u8,
    pub shim_version_minor: u8,
    /// Reserved for future use
    pub _reserved2: [u8; 4],
}

impl Default for ShimMokInfo {
    fn default() -> Self {
        Self {
            shim_detected: false,
            mok_sb_state: 0,
            mok_list_present: false,
            mok_list_rt_present: false,
            mok_list_x_present: false,
            sbat_level_present: false,
            shim_validated: false,
            _reserved: 0,
            mok_count: 0,
            shim_version_major: 0,
            shim_version_minor: 0,
            _reserved2: [0; 4],
        }
    }
}

/// Shim/MOK state flags
pub mod shim_mok_flags {
    /// Shim bootloader detected
    pub const SHIM_DETECTED: u32 = 1 << 0;
    /// MOK Secure Boot validation enabled in Shim
    pub const MOK_SB_ENABLED: u32 = 1 << 1;
    /// MokList (certificates) present
    pub const MOK_LIST_PRESENT: u32 = 1 << 2;
    /// MokListRT (runtime access) present
    pub const MOK_LIST_RT_PRESENT: u32 = 1 << 3;
    /// MokListX (revocation) present
    pub const MOK_LIST_X_PRESENT: u32 = 1 << 4;
    /// SBAT revocation data present
    pub const SBAT_LEVEL_PRESENT: u32 = 1 << 5;
    /// Binary validated by Shim
    pub const SHIM_VALIDATED: u32 = 1 << 6;
}

/// SMBIOS (System Management BIOS) information.
/// Contains table addresses and parsed basic information.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SmbiosInfo {
    /// SMBIOS 3.x table address (0 = not found)
    pub smbios3_addr: u64,
    /// SMBIOS 2.x table address (0 = not found)
    pub smbios_addr: u64,
    /// SMBIOS major version
    pub major_version: u8,
    /// SMBIOS minor version
    pub minor_version: u8,
    /// Maximum table structure size
    pub table_max_size: u32,
    /// Status flags (see smbios_flags module)
    pub flags: u16,
    /// Reserved for alignment
    pub _reserved: [u8; 4],
    /// BIOS vendor string offset (table internal)
    pub bios_vendor_offset: u32,
    /// BIOS version string offset
    pub bios_version_offset: u32,
    /// System manufacturer string offset
    pub system_manufacturer_offset: u32,
    /// System product name string offset
    pub system_product_offset: u32,
    /// System serial number string offset
    pub system_serial_offset: u32,
    /// System UUID (16 bytes)
    pub system_uuid: [u8; 16],
}

impl Default for SmbiosInfo {
    fn default() -> Self {
        Self {
            smbios3_addr: 0,
            smbios_addr: 0,
            major_version: 0,
            minor_version: 0,
            table_max_size: 0,
            flags: 0,
            _reserved: [0; 4],
            bios_vendor_offset: 0,
            bios_version_offset: 0,
            system_manufacturer_offset: 0,
            system_product_offset: 0,
            system_serial_offset: 0,
            system_uuid: [0; 16],
        }
    }
}

/// SMBIOS status flags
pub mod smbios_flags {
    /// SMBIOS 3.x available
    pub const SMBIOS3_AVAILABLE: u16 = 1 << 0;
    /// SMBIOS 2.x available
    pub const SMBIOS2_AVAILABLE: u16 = 1 << 1;
    /// BIOS information parsed
    pub const BIOS_INFO_VALID: u16 = 1 << 2;
    /// System information parsed
    pub const SYSTEM_INFO_VALID: u16 = 1 << 3;
    /// Processor information parsed
    pub const PROCESSOR_INFO_VALID: u16 = 1 << 4;
    /// Memory information parsed
    pub const MEMORY_INFO_VALID: u16 = 1 << 5;
}

/// Boot recovery information.
/// Contains failure tracking and recovery mode status.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootRecoveryInfo {
    /// Current boot attempt ID (incremental counter)
    pub boot_attempt_id: u32,
    /// Consecutive boot failure count
    pub failure_count: u8,
    /// Currently in recovery mode
    pub is_recovery_mode: bool,
    /// Using fallback kernel
    pub is_fallback: bool,
    /// Reserved for alignment
    pub _reserved: u8,
    /// Expected success ID (kernel should confirm this)
    pub expected_success_id: u32,
}

impl Default for BootRecoveryInfo {
    fn default() -> Self {
        Self {
            boot_attempt_id: 0,
            failure_count: 0,
            is_recovery_mode: false,
            is_fallback: false,
            _reserved: 0,
            expected_success_id: 0,
        }
    }
}

/// Boot recovery flags
pub mod boot_recovery_flags {
    /// Recovery mode active
    pub const RECOVERY_MODE: u32 = 1 << 0;
    /// Using fallback kernel
    pub const FALLBACK_KERNEL: u32 = 1 << 1;
    /// First boot attempt
    pub const FIRST_BOOT: u32 = 1 << 2;
    /// Previous boot failed
    pub const PREVIOUS_FAILED: u32 = 1 << 3;
}

/// Self-test results from boot-time hardware validation.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SelfTestInfo {
    /// Overall test result (0=Pass, 1=Warning, 2=Fail, 3=Skip)
    pub overall_result: u8,
    /// Number of critical failures
    pub critical_failures: u8,
    /// Number of warnings
    pub warnings: u8,
    /// Number of tests run
    pub tests_run: u8,
    /// Reserved for alignment
    pub _reserved: [u8; 4],
}

impl Default for SelfTestInfo {
    fn default() -> Self {
        Self {
            overall_result: 0,
            critical_failures: 0,
            warnings: 0,
            tests_run: 0,
            _reserved: [0; 4],
        }
    }
}

/// Self-test result values
pub mod self_test_results {
    /// All tests passed
    pub const PASS: u8 = 0;
    /// Some tests had warnings
    pub const WARNING: u8 = 1;
    /// Critical test failures
    pub const FAIL: u8 = 2;
    /// Tests were skipped
    pub const SKIP: u8 = 3;
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::{
        AcpiBootSnapshot, BootArtifactEntry, BootArtifactKind, BootArtifactTable, BootPolicy,
        UsableMemoryTable,
    };

    #[test]
    fn boot_artifact_entry_accessors_round_trip() {
        let path = b"drivers/demo.cell";
        let data = b"\x01\x02demo";
        let entry = BootArtifactEntry {
            kind: BootArtifactKind::DriverArtifact as u32,
            flags: 0,
            path_ptr: path.as_ptr() as u64,
            path_len: path.len() as u64,
            data_ptr: data.as_ptr() as u64,
            data_len: data.len() as u64,
        };

        assert_eq!(entry.kind(), Some(BootArtifactKind::DriverArtifact));
        assert_eq!(entry.path(), Some("drivers/demo.cell"));
        assert_eq!(entry.data(), data);
    }

    #[test]
    fn boot_artifact_entry_rejects_invalid_utf8_path() {
        let path = [0xffu8, 0xfeu8];
        let entry = BootArtifactEntry {
            kind: BootArtifactKind::FixtureCell as u32,
            flags: 0,
            path_ptr: path.as_ptr() as u64,
            path_len: path.len() as u64,
            data_ptr: 0,
            data_len: 0,
        };

        assert_eq!(entry.kind(), Some(BootArtifactKind::FixtureCell));
        assert_eq!(entry.path(), None);
        assert!(entry.data().is_empty());
    }

    #[test]
    fn boot_artifact_table_entries_round_trip() {
        let path = b"cells/fixture.cell";
        let data = b"fixture";
        let entries = [BootArtifactEntry {
            kind: BootArtifactKind::FixtureCell as u32,
            flags: 0,
            path_ptr: path.as_ptr() as u64,
            path_len: path.len() as u64,
            data_ptr: data.as_ptr() as u64,
            data_len: data.len() as u64,
        }];
        let table = BootArtifactTable {
            entries_ptr: entries.as_ptr() as u64,
            count: entries.len() as u64,
        };

        assert!(!table.is_empty());
        assert_eq!(table.entries().len(), 1);
        assert_eq!(table.entries()[0].path(), Some("cells/fixture.cell"));
        assert_eq!(table.entries()[0].data(), data);
    }

    #[test]
    fn usable_memory_table_empty_when_pointer_or_count_missing() {
        assert!(UsableMemoryTable::default().is_empty());

        let table = UsableMemoryTable {
            entries_ptr: 0x1000,
            count: 0,
        };
        assert!(table.is_empty());
        assert!(table.regions().is_empty());
    }

    #[test]
    fn acpi_snapshot_default_is_invalid_and_empty() {
        let snapshot = AcpiBootSnapshot::default();
        assert!(!snapshot.is_valid());
        assert!(!snapshot.has_legacy_pics());
        assert!(snapshot.local_apics().is_empty());
        assert!(snapshot.io_apics().is_empty());
        assert!(snapshot.interrupt_overrides().is_empty());
        assert!(snapshot.pcie_ecam().is_empty());
    }

    #[test]
    fn boot_policy_and_acpi_snapshot_wire_layout_is_stable() {
        assert_eq!(size_of::<BootPolicy>(), 8);
        assert_eq!(align_of::<BootPolicy>(), 1);
        assert_eq!(align_of::<AcpiBootSnapshot>(), 8);
        assert_eq!(size_of::<UsableMemoryTable>(), 16);
    }
}
