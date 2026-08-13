// libs/boot_proto/src/lib.rs
#![no_std]
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::doc_markdown)]

use core::mem::{align_of, size_of};
use core::slice;

use graphic_types::FramebufferInfo;

pub use boot_config::{BootPolicy, BootPolicyError, BootShellMode};

pub const EXO_BOOT_INFO_VERSION: u64 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootHhdmSpan {
    start: u64,
    len: u64,
}

impl BootHhdmSpan {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(start: u64, len: u64) -> Result<Self, &'static str> {
        if start == 0 {
            return Err("boot handoff span start is zero");
        }
        if len == 0 {
            return Err("boot handoff span length is zero");
        }
        let _ = start
            .checked_add(len)
            .ok_or("boot handoff span overflowed")?;
        Ok(Self { start, len })
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn len(&self) -> u64 {
        self.len
    }

    pub fn end(&self) -> Option<u64> {
        self.start.checked_add(self.len)
    }

    pub fn phys_range(&self, hhdm_start: u64) -> Option<(u64, u64)> {
        let phys_start = self.start.checked_sub(hhdm_start)?;
        let _ = phys_start.checked_add(self.len)?;
        Some((phys_start, self.len))
    }
}

fn hhdm_span_from_raw(start: u64, len: u64) -> Option<BootHhdmSpan> {
    if start == 0 || len == 0 {
        return None;
    }
    BootHhdmSpan::new(start, len).ok()
}

fn count_to_len(count: u64) -> usize {
    usize::try_from(count).ok().unwrap_or(0)
}

fn count_byte_len<T>(count: usize) -> Option<u64> {
    count.checked_mul(size_of::<T>())?.try_into().ok()
}

fn count_to_valid_len<T>(count: u64) -> usize {
    let count = count_to_len(count);
    if count == 0 || count_byte_len::<T>(count).is_none() {
        return 0;
    }
    count
}

fn table_span<T>(entries_ptr: u64, count: u64) -> Option<BootHhdmSpan> {
    let count = count_to_len(count);
    if entries_ptr == 0 || count == 0 {
        return None;
    }
    BootHhdmSpan::new(entries_ptr, count_byte_len::<T>(count)?).ok()
}

fn optional_span_from_raw(start: u64, len: u64) -> Result<Option<BootHhdmSpan>, &'static str> {
    match (start, len) {
        (0, 0) => Ok(None),
        (0, _) | (_, 0) => Err("boot handoff span is partially missing"),
        _ => BootHhdmSpan::new(start, len).map(Some),
    }
}

fn byte_slice_from_span<'a>(span: BootHhdmSpan) -> Result<&'a [u8], &'static str> {
    let len = usize::try_from(span.len()).map_err(|_| "boot handoff byte length overflowed")?;
    Ok(unsafe { slice::from_raw_parts(span.start() as *const u8, len) })
}

fn table_slice_from_span<'a, T>(span: BootHhdmSpan, count: u64) -> Result<&'a [T], &'static str> {
    let count = usize::try_from(count).map_err(|_| "boot handoff table count overflowed")?;
    if count == 0 {
        return Ok(&[]);
    }
    if count_byte_len::<T>(count) != Some(span.len()) {
        return Err("boot handoff table span length mismatch");
    }
    if span.start() % (align_of::<T>() as u64) != 0 {
        return Err("boot handoff table pointer is misaligned");
    }
    Ok(unsafe { slice::from_raw_parts(span.start() as *const T, count) })
}

fn optional_bytes_from_raw<'a>(start: u64, len: u64) -> Result<Option<&'a [u8]>, &'static str> {
    optional_span_from_raw(start, len)?
        .map(byte_slice_from_span)
        .transpose()
}

fn memory_map_slice<'a>(memory_map: &MemoryMap) -> Result<&'a [MemoryDescriptor], &'static str> {
    let Some(span) = memory_map.span() else {
        return if memory_map.count == 0 {
            Ok(&[])
        } else {
            Err("boot memory map span is invalid")
        };
    };
    table_slice_from_span(span, memory_map.count)
}

fn usable_memory_slice<'a>(
    usable_memory: &UsableMemoryTable,
) -> Result<&'a [UsableMemoryRegion], &'static str> {
    let Some(span) = usable_memory.regions_span() else {
        return if usable_memory.count == 0 {
            Ok(&[])
        } else {
            Err("boot usable memory span is invalid")
        };
    };
    table_slice_from_span(span, usable_memory.count)
}

fn boot_artifact_entries_slice<'a>(
    boot_artifacts: &BootArtifactTable,
) -> Result<&'a [BootArtifactEntry], &'static str> {
    let Some(span) = boot_artifacts.entries_span() else {
        return if boot_artifacts.count == 0 {
            Ok(&[])
        } else {
            Err("boot artifact table span is invalid")
        };
    };
    table_slice_from_span(span, boot_artifacts.count)
}

fn artifact_path_bytes<'a>(entry: &BootArtifactEntry) -> Result<&'a [u8], &'static str> {
    let span = optional_span_from_raw(entry.path_ptr, entry.path_len)?
        .ok_or("boot artifact path span is missing")?;
    byte_slice_from_span(span)
}

fn artifact_data_bytes<'a>(entry: &BootArtifactEntry) -> Result<&'a [u8], &'static str> {
    optional_bytes_from_raw(entry.data_ptr, entry.data_len).map(Option::unwrap_or_default)
}

#[derive(Debug, Clone, Copy)]
pub struct ExoBootInfoView<'a> {
    boot_info: &'a ExoBootInfo,
    cmdline: Option<&'a [u8]>,
    memory_map: &'a [MemoryDescriptor],
    usable_memory: &'a [UsableMemoryRegion],
    boot_artifacts: BootArtifactTableView<'a>,
}

impl<'a> ExoBootInfoView<'a> {
    pub const fn boot_info(&self) -> &'a ExoBootInfo {
        self.boot_info
    }

    pub const fn cmdline_bytes(&self) -> Option<&'a [u8]> {
        self.cmdline
    }

    pub fn cmdline(&self) -> Option<&'a str> {
        let bytes = self.cmdline?;
        core::str::from_utf8(bytes).ok()
    }

    pub const fn memory_map(&self) -> &'a [MemoryDescriptor] {
        self.memory_map
    }

    pub const fn usable_memory(&self) -> &'a [UsableMemoryRegion] {
        self.usable_memory
    }

    pub const fn boot_artifacts(&self) -> BootArtifactTableView<'a> {
        self.boot_artifacts
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BootArtifactTableView<'a> {
    entries: &'a [BootArtifactEntry],
}

impl<'a> BootArtifactTableView<'a> {
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> BootArtifactIter<'a> {
        BootArtifactIter {
            entries: self.entries.iter(),
        }
    }
}

pub struct BootArtifactIter<'a> {
    entries: slice::Iter<'a, BootArtifactEntry>,
}

impl<'a> Iterator for BootArtifactIter<'a> {
    type Item = BootArtifactView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(BootArtifactView::new_validated)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BootArtifactView<'a> {
    raw: &'a BootArtifactEntry,
    path_bytes: &'a [u8],
    data: &'a [u8],
}

impl<'a> BootArtifactView<'a> {
    fn new_validated(raw: &'a BootArtifactEntry) -> Self {
        Self {
            raw,
            path_bytes: artifact_path_bytes(raw)
                .expect("validated boot artifact path must remain readable"),
            data: artifact_data_bytes(raw)
                .expect("validated boot artifact data must remain readable"),
        }
    }

    pub const fn kind(&self) -> Option<BootArtifactKind> {
        self.raw.kind()
    }

    pub fn path(&self) -> Option<&'a str> {
        core::str::from_utf8(self.path_bytes).ok()
    }

    pub const fn path_bytes(&self) -> Option<&'a [u8]> {
        Some(self.path_bytes)
    }

    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// # Panics
    ///
    /// Panics only if the path span validated when this artifact view was
    /// constructed is no longer present in the backing entry.
    pub fn path_span(&self) -> BootHhdmSpan {
        self.raw
            .path_span()
            .expect("validated boot artifact path span must remain present")
    }

    pub fn data_span(&self) -> Option<BootHhdmSpan> {
        self.raw.data_span()
    }
}

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

    /// HHDM virtual address of the command line string (if any).
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

    /// Memory map provided by UEFI as an HHDM-backed pointer/count pair.
    pub memory_map: MemoryMap,
    /// Bootloader-normalized usable physical memory regions.
    pub usable_memory: UsableMemoryTable,

    /// Framebuffer information (resolution, base address, format).
    pub framebuffer: FramebufferInfo,

    /// Boot artifacts discovered on the boot partition (optional).
    /// Driver artifacts under `/drivers` are autostart/staging inputs, and
    /// fixture cells under `/cells` remain data-only runtime artifacts.
    pub boot_artifacts: BootArtifactTable,

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

    pub fn cmdline_span(&self) -> Option<BootHhdmSpan> {
        hhdm_span_from_raw(self.cmdline_ptr, self.cmdline_len)
    }

    pub fn set_cmdline_span(&mut self, span: Option<BootHhdmSpan>) {
        if let Some(span) = span {
            self.cmdline_ptr = span.start();
            self.cmdline_len = span.len();
        } else {
            self.cmdline_ptr = 0;
            self.cmdline_len = 0;
        }
    }

    /// # Safety
    ///
    /// The caller must guarantee that the bootloader handoff remains valid,
    /// immutable, and readable for the lifetime of the returned view.
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn view(&self) -> Result<ExoBootInfoView<'_>, &'static str> {
        if !self.is_version_compatible() {
            return Err("boot info version mismatch");
        }

        let cmdline = optional_bytes_from_raw(self.cmdline_ptr, self.cmdline_len)?;
        let memory_map = memory_map_slice(&self.memory_map)?;
        let usable_memory = usable_memory_slice(&self.usable_memory)?;
        let boot_artifacts = unsafe { self.boot_artifacts.view()? };

        Ok(ExoBootInfoView {
            boot_info: self,
            cmdline,
            memory_map,
            usable_memory,
            boot_artifacts,
        })
    }
}

// `ExoBootInfo` is a read-only handoff struct provided by the bootloader.
// It contains only plain data and pointers to immutable regions, so it is
// safe to access it from multiple threads concurrently.
unsafe impl Sync for ExoBootInfo {}

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
    pub fn new_hhdm(
        kind: BootArtifactKind,
        path: BootHhdmSpan,
        data: Option<BootHhdmSpan>,
    ) -> Self {
        Self {
            kind: kind as u32,
            flags: 0,
            path_ptr: path.start(),
            path_len: path.len(),
            data_ptr: data.map_or(0, |span| span.start()),
            data_len: data.map_or(0, |span| span.len()),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> Option<BootArtifactKind> {
        BootArtifactKind::from_raw(self.kind)
    }

    #[must_use]
    pub fn path_span(&self) -> Option<BootHhdmSpan> {
        hhdm_span_from_raw(self.path_ptr, self.path_len)
    }

    #[must_use]
    pub fn data_span(&self) -> Option<BootHhdmSpan> {
        hhdm_span_from_raw(self.data_ptr, self.data_len)
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
    pub fn len(&self) -> usize {
        if self.is_empty() {
            return 0;
        }
        count_to_valid_len::<BootArtifactEntry>(self.count)
    }

    #[must_use]
    pub fn entries_span(&self) -> Option<BootHhdmSpan> {
        table_span::<BootArtifactEntry>(self.entries_ptr, self.count)
    }

    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub fn from_hhdm_addr(entries_addr: u64, count: usize) -> Result<Self, &'static str> {
        if count == 0 {
            return Ok(Self::default());
        }
        let byte_len = count_byte_len::<BootArtifactEntry>(count)
            .ok_or("boot artifact table byte length overflowed")?;
        let _ = BootHhdmSpan::new(entries_addr, byte_len)?;
        Ok(Self {
            entries_ptr: entries_addr,
            count: count as u64,
        })
    }

    /// # Safety
    ///
    /// The caller must guarantee that the handoff backing this table remains
    /// valid, immutable, and readable for the lifetime of the returned view.
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn view(&self) -> Result<BootArtifactTableView<'_>, &'static str> {
        let entries = boot_artifact_entries_slice(self)?;
        for entry in entries {
            let _ = artifact_path_bytes(entry)?;
            let _ = artifact_data_bytes(entry)?;
        }
        Ok(BootArtifactTableView { entries })
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
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryMap {
    pub entries: *const MemoryDescriptor,
    pub count: u64,
}

impl MemoryMap {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_null() || self.count == 0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        if self.is_empty() {
            return 0;
        }
        count_to_valid_len::<MemoryDescriptor>(self.count)
    }

    #[must_use]
    pub fn span(&self) -> Option<BootHhdmSpan> {
        table_span::<MemoryDescriptor>(self.entries as u64, self.count)
    }

    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub fn from_hhdm_addr(entries_addr: u64, count: usize) -> Result<Self, &'static str> {
        if count == 0 {
            return Ok(Self::default());
        }
        let byte_len = count_byte_len::<MemoryDescriptor>(count)
            .ok_or("boot memory map byte length overflowed")?;
        let _ = BootHhdmSpan::new(entries_addr, byte_len)?;
        Ok(Self {
            entries: entries_addr as *const MemoryDescriptor,
            count: count as u64,
        })
    }
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
    pub fn len(&self) -> usize {
        if self.is_empty() {
            return 0;
        }
        count_to_valid_len::<UsableMemoryRegion>(self.count)
    }

    #[must_use]
    pub fn regions_span(&self) -> Option<BootHhdmSpan> {
        table_span::<UsableMemoryRegion>(self.entries_ptr, self.count)
    }

    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub fn from_hhdm_addr(entries_addr: u64, count: usize) -> Result<Self, &'static str> {
        if count == 0 {
            return Ok(Self::default());
        }
        let byte_len = count_byte_len::<UsableMemoryRegion>(count)
            .ok_or("usable memory table byte length overflowed")?;
        let _ = BootHhdmSpan::new(entries_addr, byte_len)?;
        Ok(Self {
            entries_ptr: entries_addr,
            count: count as u64,
        })
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

    use super::*;
    use ap_trampoline::{LAYOUT_VERSION, MAILBOX_OFFSET, TRAMPOLINE_SIZE, TrampolinePhysAddr};

    static DRIVER_PATH: &[u8] = b"drivers/demo.cell";
    static DRIVER_DATA: &[u8] = b"\x01\x02demo";
    static FIXTURE_PATH: &[u8] = b"cells/fixture.cell";
    static FIXTURE_DATA: &[u8] = b"fixture";

    fn minimal_exo_boot_info() -> ExoBootInfo {
        ExoBootInfo {
            version: EXO_BOOT_INFO_VERSION,
            phys_mem_offset: 0xffff_8000_0000_0000,
            rsdp_addr: 0,
            cmdline_ptr: 0,
            cmdline_len: 0,
            boot_policy: BootPolicy::default(),
            page_table_base: 0,
            tls_template: TlsInfo::default(),
            memory_map: MemoryMap::default(),
            usable_memory: UsableMemoryTable::default(),
            framebuffer: graphic_types::FramebufferInfo {
                address: 0,
                width: 0,
                height: 0,
                stride: 0,
                format: graphic_types::PixelFormat::Bgra8888,
                bpp: 32,
            },
            boot_artifacts: BootArtifactTable::default(),
            numa_info: NumaInfo::default(),
            acpi_snapshot: AcpiBootSnapshot::default(),
            ap_boot: ApBootInfo::default(),
            uefi_runtime: UefiRuntimeInfo::default(),
            mem_encryption: MemoryEncryptionInfo::default(),
            secure_boot: SecureBootInfo::default(),
            shim_mok: ShimMokInfo::default(),
            smbios: SmbiosInfo::default(),
            boot_recovery: BootRecoveryInfo::default(),
            self_test: SelfTestInfo::default(),
            paging_levels: 4,
            la57_enabled: 0,
        }
    }

    #[test]
    fn boot_hhdm_span_validates_and_converts_phys_ranges() {
        let span = BootHhdmSpan::new(0xffff_8000_0010_0000, 0x2000).unwrap();

        assert_eq!(span.start(), 0xffff_8000_0010_0000);
        assert_eq!(span.len(), 0x2000);
        assert_eq!(span.end(), Some(0xffff_8000_0010_2000));
        assert_eq!(
            span.phys_range(0xffff_8000_0000_0000),
            Some((0x0010_0000, 0x2000))
        );
        assert_eq!(span.phys_range(0xffff_9000_0000_0000), None);
        assert_eq!(
            BootHhdmSpan::new(u64::MAX - 3, 8),
            Err("boot handoff span overflowed")
        );
        assert_eq!(
            BootHhdmSpan::new(0, 0x10),
            Err("boot handoff span start is zero")
        );
        assert_eq!(
            BootHhdmSpan::new(0x1000, 0),
            Err("boot handoff span length is zero")
        );
    }

    #[test]
    fn boot_artifact_entry_accessors_round_trip() {
        let entry = BootArtifactEntry::new_hhdm(
            BootArtifactKind::DriverArtifact,
            BootHhdmSpan::new(DRIVER_PATH.as_ptr() as u64, DRIVER_PATH.len() as u64).unwrap(),
            Some(BootHhdmSpan::new(DRIVER_DATA.as_ptr() as u64, DRIVER_DATA.len() as u64).unwrap()),
        );
        let table =
            BootArtifactTable::from_hhdm_addr((&entry as *const BootArtifactEntry) as u64, 1)
                .unwrap();
        let view = unsafe { table.view() }.unwrap();
        let entry_view = view.iter().next().unwrap();

        assert_eq!(entry.kind(), Some(BootArtifactKind::DriverArtifact));
        assert_eq!(entry.path_span().unwrap().len(), DRIVER_PATH.len() as u64);
        assert_eq!(entry.data_span().unwrap().len(), DRIVER_DATA.len() as u64);
        assert_eq!(entry_view.path(), Some("drivers/demo.cell"));
        assert_eq!(entry_view.path_bytes(), Some(DRIVER_PATH));
        assert_eq!(entry_view.data(), DRIVER_DATA);
    }

    #[test]
    fn boot_artifact_entry_rejects_invalid_utf8_path() {
        let path = [0xffu8, 0xfeu8];
        let entry = BootArtifactEntry::new_hhdm(
            BootArtifactKind::FixtureCell,
            BootHhdmSpan::new(path.as_ptr() as u64, path.len() as u64).unwrap(),
            Some(
                BootHhdmSpan::new(FIXTURE_DATA.as_ptr() as u64, FIXTURE_DATA.len() as u64).unwrap(),
            ),
        );
        let table =
            BootArtifactTable::from_hhdm_addr((&entry as *const BootArtifactEntry) as u64, 1)
                .unwrap();
        let view = unsafe { table.view() }.unwrap();
        let entry_view = view.iter().next().unwrap();

        assert_eq!(entry.kind(), Some(BootArtifactKind::FixtureCell));
        assert_eq!(entry_view.path(), None);
        assert_eq!(entry_view.data(), FIXTURE_DATA);
    }

    #[test]
    fn boot_artifact_table_entries_round_trip() {
        let entries = [BootArtifactEntry::new_hhdm(
            BootArtifactKind::FixtureCell,
            BootHhdmSpan::new(FIXTURE_PATH.as_ptr() as u64, FIXTURE_PATH.len() as u64).unwrap(),
            Some(
                BootHhdmSpan::new(FIXTURE_DATA.as_ptr() as u64, FIXTURE_DATA.len() as u64).unwrap(),
            ),
        )];
        let table =
            BootArtifactTable::from_hhdm_addr(entries.as_ptr() as u64, entries.len()).unwrap();
        let view = unsafe { table.view() }.unwrap();
        let entry = view.iter().next().unwrap();

        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
        assert_eq!(view.len(), 1);
        assert_eq!(
            table.entries_span(),
            Some(
                BootHhdmSpan::new(
                    entries.as_ptr() as u64,
                    size_of::<BootArtifactEntry>() as u64,
                )
                .unwrap()
            )
        );
        assert_eq!(entry.path(), Some("cells/fixture.cell"));
        assert_eq!(entry.data(), FIXTURE_DATA);
    }

    #[test]
    fn boot_artifact_view_allows_empty_data() {
        let entry = BootArtifactEntry::new_hhdm(
            BootArtifactKind::FixtureCell,
            BootHhdmSpan::new(FIXTURE_PATH.as_ptr() as u64, FIXTURE_PATH.len() as u64).unwrap(),
            None,
        );
        let table =
            BootArtifactTable::from_hhdm_addr((&entry as *const BootArtifactEntry) as u64, 1)
                .unwrap();
        let view = unsafe { table.view() }.unwrap();
        let entry_view = view.iter().next().unwrap();

        assert_eq!(entry.data_span(), None);
        assert_eq!(entry_view.data(), &[]);
    }

    #[test]
    fn usable_memory_table_empty_when_pointer_or_count_missing() {
        assert!(UsableMemoryTable::default().is_empty());

        let table = UsableMemoryTable {
            entries_ptr: 0x1000,
            count: 0,
        };
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(table.regions_span().is_none());
    }

    #[test]
    fn boot_proto_safe_views_round_trip_and_reject_overflow() {
        static CMDLINE: &[u8] = b"console=serial";
        let mut boot_info = minimal_exo_boot_info();
        let cmdline_span =
            BootHhdmSpan::new(CMDLINE.as_ptr() as u64, CMDLINE.len() as u64).unwrap();
        boot_info.set_cmdline_span(Some(cmdline_span));
        let view = unsafe { boot_info.view() }.unwrap();

        assert_eq!(boot_info.cmdline_span(), Some(cmdline_span));
        assert_eq!(view.cmdline_bytes(), Some(CMDLINE));
        assert_eq!(view.cmdline(), Some("console=serial"));

        boot_info.set_cmdline_span(None);
        assert_eq!(boot_info.cmdline_span(), None);
        assert_eq!(unsafe { boot_info.view() }.unwrap().cmdline(), None);

        static INVALID_CMDLINE: &[u8] = &[0xff, 0xfe];
        boot_info.set_cmdline_span(Some(
            BootHhdmSpan::new(
                INVALID_CMDLINE.as_ptr() as u64,
                INVALID_CMDLINE.len() as u64,
            )
            .unwrap(),
        ));
        assert_eq!(unsafe { boot_info.view() }.unwrap().cmdline(), None);

        let descriptors = [
            MemoryDescriptor {
                r#type: 7,
                pad: 0,
                phys_start: 0x1000,
                virt_start: 0,
                page_count: 2,
                attribute: 0,
            },
            MemoryDescriptor {
                r#type: 4,
                pad: 0,
                phys_start: 0x3000,
                virt_start: 0,
                page_count: 1,
                attribute: 0,
            },
        ];
        boot_info.memory_map =
            MemoryMap::from_hhdm_addr(descriptors.as_ptr() as u64, descriptors.len()).unwrap();
        let view = unsafe { boot_info.view() }.unwrap();
        assert_eq!(boot_info.memory_map.len(), 2);
        assert_eq!(view.memory_map().len(), descriptors.len());
        for (actual, expected) in view.memory_map().iter().zip(descriptors.iter()) {
            assert_eq!(actual.r#type, expected.r#type);
            assert_eq!(actual.phys_start, expected.phys_start);
            assert_eq!(actual.page_count, expected.page_count);
        }
        assert_eq!(
            boot_info.memory_map.span(),
            Some(
                BootHhdmSpan::new(
                    descriptors.as_ptr() as u64,
                    (descriptors.len() * size_of::<MemoryDescriptor>()) as u64,
                )
                .unwrap()
            )
        );

        let regions = [
            UsableMemoryRegion {
                base: 0x1000,
                length: 0x2000,
            },
            UsableMemoryRegion {
                base: 0x4000,
                length: 0x1000,
            },
        ];
        boot_info.usable_memory =
            UsableMemoryTable::from_hhdm_addr(regions.as_ptr() as u64, regions.len()).unwrap();
        let view = unsafe { boot_info.view() }.unwrap();
        assert_eq!(boot_info.usable_memory.len(), 2);
        assert_eq!(view.usable_memory(), &regions);
        assert_eq!(
            boot_info.usable_memory.regions_span(),
            Some(
                BootHhdmSpan::new(
                    regions.as_ptr() as u64,
                    (regions.len() * size_of::<UsableMemoryRegion>()) as u64,
                )
                .unwrap()
            )
        );

        assert!(matches!(
            BootArtifactTable::from_hhdm_addr(0x1000, usize::MAX),
            Err("boot artifact table byte length overflowed")
        ));
        assert!(matches!(
            MemoryMap::from_hhdm_addr(0x1000, usize::MAX),
            Err("boot memory map byte length overflowed")
        ));
        assert!(matches!(
            UsableMemoryTable::from_hhdm_addr(0x1000, usize::MAX),
            Err("usable memory table byte length overflowed")
        ));

        let mut invalid_version = minimal_exo_boot_info();
        invalid_version.version = EXO_BOOT_INFO_VERSION + 1;
        assert!(matches!(
            unsafe { invalid_version.view() },
            Err("boot info version mismatch")
        ));

        let overflowing_table = BootArtifactTable {
            entries_ptr: 0x1000,
            count: u64::MAX,
        };
        let overflowing_map = MemoryMap {
            entries: 0x1000 as *const MemoryDescriptor,
            count: u64::MAX,
        };
        let overflowing_regions = UsableMemoryTable {
            entries_ptr: 0x1000,
            count: u64::MAX,
        };
        assert_eq!(overflowing_table.len(), 0);
        assert!(overflowing_table.entries_span().is_none());
        assert!(unsafe { overflowing_table.view() }.is_err());
        assert_eq!(overflowing_map.len(), 0);
        assert!(overflowing_map.span().is_none());
        assert_eq!(overflowing_regions.len(), 0);
        assert!(overflowing_regions.regions_span().is_none());

        let mut malformed = minimal_exo_boot_info();
        malformed.memory_map = overflowing_map;
        assert!(unsafe { malformed.view() }.is_err());

        let mut malformed = minimal_exo_boot_info();
        malformed.usable_memory = overflowing_regions;
        assert!(unsafe { malformed.view() }.is_err());

        let mut malformed = minimal_exo_boot_info();
        malformed.boot_artifacts = overflowing_table;
        assert!(unsafe { malformed.view() }.is_err());

        let partial_data = BootArtifactEntry {
            kind: BootArtifactKind::FixtureCell as u32,
            flags: 0,
            path_ptr: FIXTURE_PATH.as_ptr() as u64,
            path_len: FIXTURE_PATH.len() as u64,
            data_ptr: 0,
            data_len: 4,
        };
        let malformed_table = BootArtifactTable::from_hhdm_addr(
            (&partial_data as *const BootArtifactEntry) as u64,
            1,
        )
        .unwrap();
        assert!(unsafe { malformed_table.view() }.is_err());
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

    fn valid_ap_boot_layout() -> ApBootLayout {
        ApBootLayout::new(
            2,
            2,
            TrampolinePhysAddr::new(0x8000).unwrap(),
            TRAMPOLINE_SIZE as u64,
            0x20_0000,
            0x10_000,
        )
        .unwrap()
    }

    #[test]
    fn ap_boot_layout_round_trips_through_wire_format() {
        let layout = valid_ap_boot_layout();
        let boot_info = layout.into_boot_info();

        assert_eq!(boot_info.layout().unwrap(), layout);
        assert_eq!(
            boot_info.flags,
            ap_trampoline::ApBootFlags::TRAMPOLINE_READY
        );
        assert_eq!(boot_info.trampoline_layout_version, LAYOUT_VERSION);
        assert_eq!(boot_info.trampoline_mailbox_offset, MAILBOX_OFFSET as u32);
    }

    #[test]
    fn ap_boot_layout_rejects_invalid_values() {
        let trampoline_base = TrampolinePhysAddr::new(0x8000).unwrap();
        let overflowing_stack_size = ((u64::MAX / u64::from(u16::MAX)) + 4096) & !((4096_u64) - 1);

        assert_eq!(
            ApBootLayout::new(
                1,
                1,
                trampoline_base,
                (TRAMPOLINE_SIZE - 1) as u64,
                0x20_0000,
                0x10_000
            ),
            Err("shared AP trampoline allocation is smaller than expected")
        );
        assert_eq!(
            ApBootLayout::new(
                2,
                1,
                trampoline_base,
                TRAMPOLINE_SIZE as u64,
                0x20_0000,
                0x10_000
            ),
            Err("shared AP stack allocation count is smaller than AP count")
        );
        assert_eq!(
            ApBootLayout::new(1, 1, trampoline_base, TRAMPOLINE_SIZE as u64, 0, 0x10_000),
            Err("missing AP stack allocation")
        );
        assert_eq!(
            ApBootLayout::new(
                1,
                1,
                trampoline_base,
                TRAMPOLINE_SIZE as u64,
                0x20_0001,
                0x10_000
            ),
            Err("AP stack base must be page aligned")
        );
        assert_eq!(
            ApBootLayout::new(
                1,
                1,
                trampoline_base,
                TRAMPOLINE_SIZE as u64,
                0x20_0000,
                0x10_001
            ),
            Err("AP stack size must be page aligned")
        );
        assert_eq!(
            ApBootLayout::new(
                1,
                1,
                trampoline_base,
                TRAMPOLINE_SIZE as u64,
                0x20_0000,
                0x1000
            ),
            Err("AP stack size must include one mapped page above the guard")
        );
        assert_eq!(
            ApBootLayout::new(
                1,
                u16::MAX,
                trampoline_base,
                TRAMPOLINE_SIZE as u64,
                0x20_0000,
                overflowing_stack_size,
            ),
            Err("AP stack allocation size overflowed")
        );
    }

    #[test]
    fn ap_boot_info_layout_preserves_existing_error_strings() {
        let mut ap_boot = valid_ap_boot_layout().into_boot_info();

        ap_boot.flags = 0;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP trampoline is not marked ready")
        );

        let mut ap_boot = valid_ap_boot_layout().into_boot_info();
        ap_boot.trampoline_layout_version = LAYOUT_VERSION + 1;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP trampoline layout version mismatch")
        );

        let mut ap_boot = valid_ap_boot_layout().into_boot_info();
        ap_boot.trampoline_mailbox_offset = (MAILBOX_OFFSET + 8) as u32;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP trampoline mailbox offset mismatch")
        );
    }

    #[test]
    fn ap_boot_helpers_compute_ranges_and_stack_slots() {
        let layout = valid_ap_boot_layout();
        let boot_info = layout.into_boot_info();

        assert_eq!(layout.boot_capacity(), 2);
        assert_eq!(boot_info.boot_capacity(), 2);
        assert_eq!(
            layout.trampoline_range(),
            Some((0x8000, TRAMPOLINE_SIZE as u64))
        );
        assert_eq!(
            boot_info.trampoline_range(),
            Some((0x8000, TRAMPOLINE_SIZE as u64))
        );
        assert_eq!(layout.stack_region_bytes(), Some(0x20_000));
        assert_eq!(boot_info.stack_region_bytes(), Some(0x20_000));
        assert_eq!(layout.stack_region_range(), Some((0x20_0000, 0x20_000)));
        assert_eq!(boot_info.stack_region_range(), Some((0x20_0000, 0x20_000)));
        assert_eq!(layout.stack_base_for(0), Some(0x20_0000));
        assert_eq!(layout.stack_top_for(0), Some(0x21_0000));
        assert_eq!(layout.stack_base_for(1), Some(0x21_0000));
        assert_eq!(layout.stack_top_for(1), Some(0x22_0000));
        assert_eq!(layout.stack_base_for(2), None);
        assert_eq!(boot_info.stack_top_for(1), Some(0x22_0000));
    }
}
