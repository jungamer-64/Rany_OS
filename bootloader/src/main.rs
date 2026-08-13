#![no_std]
#![no_main]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::time::Duration;
use log::{error, info};
use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Identify, boot};

// Ed25519 signature verification for secure boot
use ed25519_compact::{PublicKey, Signature};

mod ap_trampoline_handoff;
mod boot_log;
mod config;
#[path = "main/elf_relocations.rs"]
mod elf_relocations;
use elf_relocations::*;
#[cfg(feature = "ui")]
mod menu;
mod page_table;
mod recovery;
mod secure_boot;
#[cfg(feature = "self_test")]
mod self_test;
#[cfg(feature = "serial_log")]
#[macro_use]
mod serial;
mod shim_mok;
mod smbios;
mod sme_sev;
mod tpm;

/// シリアルログ無効時のフォールバックマクロ（何もしない）
#[cfg(not(feature = "serial_log"))]
#[macro_export]
macro_rules! serial_println {
    () => {};
    ($($arg:tt)*) => {};
}
mod uefi_runtime;

/// Kernel base address for higher-half mapping
/// PIE ELF has VAddr starting at 0x0, so we add this offset
const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Ed25519 public key for kernel signature verification
/// Embedded at compile time - cannot be tampered with at runtime
static PUBLIC_KEY_BYTES: &[u8] = include_bytes!("../../keys/kernel_pub.key");

/// Ed25519 signature size in bytes
const SIG_SIZE: usize = 64;

#[entry]
fn main() -> Status {
    // Initialize UEFI helper services (allocator, logger, panic handler)
    uefi::helpers::init().expect("Failed to initialize UEFI helpers");

    // Initialize serial console early for headless debugging
    #[cfg(feature = "serial_log")]
    {
        serial::init();
        serial_println!("ExoLoader: Serial console initialized");
    }

    info!("ExoLoader v0.1.0 Starting...");
    #[cfg(feature = "serial_log")]
    serial_println!("ExoLoader v0.1.0 Starting...");
    info!("Initializing Boot Protocol...");

    // Get image handle for protocol operations
    let image_handle = boot::image_handle();

    // 0.5. Load boot configuration and show menu (if multiple entries)
    let boot_config = match load_boot_config(image_handle) {
        Ok(cfg) => cfg,
        Err(status) => return status,
    };

    #[cfg(feature = "ui")]
    let selected_entry = match select_boot_entry_ui(&boot_config) {
        Ok(entry) => entry,
        Err(status) => return status,
    };

    #[cfg(not(feature = "ui"))]
    let selected_entry = boot_config
        .entries
        .get(boot_config.default_entry)
        .or_else(|| boot_config.entries.first());

    let (kernel_name, entry_cmdline) = determine_boot_paths(selected_entry);

    // 1. Load signed kernel, boot artifacts, and command line
    let signed_kernel_data = match load_signed_kernel_file(image_handle, kernel_name) {
        Ok(data) => data,
        Err(e) => return e,
    };
    let boot_artifacts = match load_boot_artifacts(image_handle) {
        Ok(artifacts) => artifacts,
        Err(status) => return status,
    };
    let cmdline_data = load_and_merge_cmdline(image_handle, entry_cmdline);

    // ============================================================
    // SECURE BOOT: UEFI State Detection
    // ============================================================
    let sb_info = secure_boot::detect_secure_boot_state();
    let shim_info = shim_mok::detect_shim_mok();
    info!(
        "Boot environment: {} / {}",
        secure_boot::get_secure_boot_status_string(&sb_info),
        shim_mok::get_shim_mok_status_string(&shim_info)
    );

    // ============================================================
    // SECURE BOOT: Ed25519 Signature Verification
    // ============================================================
    let kernel_elf_data = match verify_and_split_signed_kernel(&signed_kernel_data) {
        Ok(data) => data,
        Err(status) => return status,
    };

    // ============================================================
    // SECURE BOOT: Boot Chain Integrity (dbx + policy enforcement)
    // ============================================================
    let kernel_sha256 = secure_boot::sha256(kernel_elf_data);
    match secure_boot::verify_boot_chain_integrity(&sb_info, kernel_elf_data) {
        Ok(()) => info!("Boot chain integrity: PASSED"),
        Err(status) => {
            error!("Boot chain integrity check FAILED - system halted");
            boot::stall(Duration::from_micros(10_000_000));
            return status;
        }
    }
    // dbx_check_passed: true if we reached this point without a revocation halt
    let dbx_check_passed = sb_info.dbx_present;

    // 1.3 TPM 2.0 Measured Boot
    let measured_artifacts = boot_artifacts
        .iter()
        .map(|artifact| tpm::MeasuredBootArtifact {
            path: artifact.path.as_str(),
            data: artifact.data.as_slice(),
        })
        .collect::<Vec<_>>();
    let tpm_result = tpm::perform_measured_boot(
        kernel_elf_data,
        &measured_artifacts,
        cmdline_data.as_deref(),
    );
    if tpm_result.tpm_available {
        info!(
            "TPM Measured Boot: kernel={}, boot_artifacts={}, cmdline={}",
            tpm_result.kernel_measured,
            tpm_result.boot_artifacts_measured,
            tpm_result.cmdline_measured
        );
    }

    // 2. Parse ELF (using verified kernel data, without signature)
    let elf = xmas_elf::ElfFile::new(kernel_elf_data).expect("Invalid ELF file");
    info!("ELF Entry Point: 0x{:x}", elf.header.pt2.entry_point());
    log_elf_load_segments(&elf);

    // 3. Map Memory
    use page_table::{CpuPageFeatures, PageTable, UefiMapper};

    let cpu_features = CpuPageFeatures::detect();
    info!(
        "CPU Page Features: PSE(2MB)={}, Page1GB={}",
        cpu_features.pse, cpu_features.page_1gb
    );

    info!("Allocating PML4...");
    // AP trampoline startup loads CR3 from a nonzero 32-bit mailbox field, so
    // the live BSP page-table root must stay below 4 GiB and off frame 0.
    let pml4_addr = UefiMapper::alloc_zeroed_page_table_pages(1).expect("Failed to allocate PML4");
    let pml4 = unsafe { &mut *(pml4_addr as *mut PageTable) };
    let mut mapper = UefiMapper::new(pml4);

    // Map ELF LOAD segments
    let segment_info = map_elf_load_segments(&elf, &mut mapper, kernel_elf_data);

    // 3.4 Detect PT_TLS segment
    let tls_info = detect_tls_segment(&elf);

    // 3.5 Process RELA relocations for PIE ELF
    if let Err(status) = process_elf_relocations(&elf, &segment_info) {
        return status;
    }

    // Debug: Resolve entry point physical address
    let entry_vaddr = elf.header.pt2.entry_point();
    let entry_phys_addr = resolve_entry_physical_address(entry_vaddr, &segment_info);
    info!("Entry point VAddr: 0x{:x}", entry_vaddr);

    // 4. Calculate Max Physical Address
    let max_phys = compute_max_physical_address();

    // 5. Map HHDM - Map up to 4GB (or more) to cover RAM and MMIO regions
    let hhdm_start = 0xffff_8000_0000_0000u64;
    let map_limit = if max_phys < 4 * 1024 * 1024 * 1024 {
        4 * 1024 * 1024 * 1024
    } else {
        max_phys
    };
    info!(
        "Mapping HHDM: max_phys=0x{:x}, limit=0x{:x} (Full Memory)",
        max_phys, map_limit
    );

    let (pages_1gb, pages_2mb, pages_4kb) =
        map_hhdm_and_identity(&mut mapper, map_limit, hhdm_start, &cpu_features);
    info!(
        "HHDM mapped: {} x 1GB, {} x 2MB, {} x 4KB pages",
        pages_1gb, pages_2mb, pages_4kb
    );

    // 6. Populate Boot Info
    use boot_proto::{
        EXO_BOOT_INFO_VERSION, ExoBootInfo, MemoryDescriptor as BootMemoryDescriptor,
    };

    info!("Allocating BootInfo...");
    let boot_info_pages = core::mem::size_of::<ExoBootInfo>().div_ceil(4096);
    let boot_info_phys = page_table::UefiMapper::alloc_zeroed_pages(
        boot_info_pages,
        MemoryType::RUNTIME_SERVICES_DATA,
    )
    .expect("Failed to allocate BootInfo");
    let boot_info = unsafe { &mut *(boot_info_phys as *mut ExoBootInfo) };

    boot_info.version = EXO_BOOT_INFO_VERSION;
    boot_info.phys_mem_offset = hhdm_start;
    boot_info.page_table_base = pml4_addr;
    boot_info.paging_levels = 4;
    boot_info.la57_enabled = 0;
    boot_info.tls_template = tls_info;

    // Populate all hardware detection fields
    populate_boot_info_detections(boot_info, hhdm_start);

    // Record kernel SHA-256 and dbx check result in boot_info for kernel attestation
    boot_info.secure_boot.kernel_sha256 = kernel_sha256;
    boot_info.secure_boot.dbx_check_passed = dbx_check_passed;

    // 6.8. Boot recovery state management
    let mut boot_logger = handle_boot_recovery(boot_info);

    // 6.9. Run self-tests
    run_boot_self_tests(boot_info, &mut boot_logger);

    // GOP framebuffer setup
    setup_gop_framebuffer(boot_info);

    if let Err(err) = populate_boot_policy(boot_info, &cmdline_data) {
        error!("Boot policy rejected: {:?}", err);
        boot::stall(Duration::from_micros(5_000_000));
        return Status::SECURITY_VIOLATION;
    }

    // 6.5. Initialize boot artifacts and cmdline in boot_info
    copy_boot_artifacts_to_boot_info(boot_info, &boot_artifacts, hhdm_start);
    copy_cmdline_to_boot_info(boot_info, &cmdline_data, hhdm_start);

    // 6.7. Pre-allocate memory map buffer BEFORE exiting boot services
    let mmap_estimate_count = 512;
    let mmap_buffer_size = mmap_estimate_count * core::mem::size_of::<BootMemoryDescriptor>();
    let mmap_buffer_pages = (mmap_buffer_size + 4095) / 4096;
    let mmap_buffer_phys = page_table::UefiMapper::alloc_zeroed_pages(
        mmap_buffer_pages,
        MemoryType::RUNTIME_SERVICES_DATA,
    )
    .expect("Failed to allocate memory map buffer");
    let usable_buffer_size =
        MAX_USABLE_MEMORY_REGIONS * core::mem::size_of::<boot_proto::UsableMemoryRegion>();
    let usable_buffer_pages = usable_buffer_size.div_ceil(4096);
    let usable_buffer_phys = page_table::UefiMapper::alloc_zeroed_pages(
        usable_buffer_pages,
        MemoryType::RUNTIME_SERVICES_DATA,
    )
    .expect("Failed to allocate usable memory buffer");

    // Log kernel entry points before exiting boot services
    let entry_addr = elf.header.pt2.entry_point();
    let hhdm_entry = hhdm_start + entry_phys_addr;
    info!("Kernel entry (KERNEL_BASE): 0x{:x}", entry_addr);
    info!("Kernel entry (HHDM): 0x{:x}", hhdm_entry);

    // Mark this attempt as successful once we are ready to hand off to kernel.
    // This prevents false-positive recovery escalation when kernel success
    // acknowledgement is unavailable.
    recovery::mark_boot_handoff_success();

    // Save boot log before exiting boot services
    boot_logger.info("About to exit boot services and jump to kernel");
    boot_logger.finalize(true);
    boot_logger.save();

    // 7. Exit Boot Services
    info!("Exiting Boot Services...");
    let mmap = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // Build memory map from UEFI into pre-allocated buffer
    build_memory_map_from_uefi(
        &mmap,
        boot_info,
        mmap_buffer_phys,
        mmap_estimate_count,
        hhdm_start,
    );
    build_usable_memory_from_uefi(
        &mmap,
        boot_info,
        &segment_info,
        boot_info_phys,
        mmap_buffer_phys,
        mmap_buffer_size as u64,
        usable_buffer_phys,
        hhdm_start,
    );

    // 8. Switch CR3 & Jump to kernel
    unsafe {
        switch_cr3_and_jump(pml4_addr, hhdm_start + boot_info_phys, entry_addr);
    }
}

// ============================================================
// Helper functions extracted from main() for cyclomatic complexity reduction
// ============================================================

/// Load and parse boot configuration from exoloader.cfg
fn load_boot_config(image_handle: Handle) -> Result<config::BootConfig, Status> {
    match load_kernel(image_handle, "exoloader.cfg") {
        Ok(data) => {
            if let Ok(cfg_str) = core::str::from_utf8(&data) {
                match config::parse_config(cfg_str) {
                    Ok(cfg) => Ok(cfg),
                    Err(config::BootConfigError::DeprecatedKey(key)) => {
                        error!("Boot config contains removed key '{}'", key);
                        boot::stall(Duration::from_micros(5_000_000));
                        Err(Status::LOAD_ERROR)
                    }
                }
            } else {
                info!("Boot config not valid UTF-8, using defaults");
                Ok(config::default_config())
            }
        }
        Err(_) => {
            info!("No exoloader.cfg found, using defaults");
            Ok(config::default_config())
        }
    }
}

/// Show boot menu (UI feature) and return selected entry index or error
#[cfg(feature = "ui")]
fn select_boot_entry_ui<'a>(
    boot_config: &'a config::BootConfig,
) -> Result<Option<&'a config::BootEntry>, Status> {
    if boot_config.entries.len() > 1 || boot_config.timeout > 0 {
        info!("Showing boot menu...");
        match menu::show_boot_menu(boot_config) {
            menu::MenuResult::Selected(idx) => {
                info!("User selected entry {}", idx);
                Ok(boot_config.entries.get(idx))
            }
            menu::MenuResult::Timeout => {
                info!("Timeout, using default entry {}", boot_config.default_entry);
                Ok(boot_config.entries.get(boot_config.default_entry))
            }
            menu::MenuResult::Cancelled => {
                info!("Boot cancelled by user");
                boot::stall(Duration::from_micros(2_000_000));
                Err(Status::ABORTED)
            }
        }
    } else {
        Ok(boot_config.entries.first())
    }
}

/// Determine kernel path and cmdline from selected boot entry
fn determine_boot_paths<'a>(
    selected_entry: Option<&'a config::BootEntry>,
) -> (&'a str, Option<&'a str>) {
    match selected_entry {
        Some(entry) => {
            info!("Booting: {}", entry.name);
            (entry.kernel.as_str(), entry.cmdline.as_deref())
        }
        None => {
            info!("No boot entry found, using defaults");
            ("rany_os", None)
        }
    }
}

/// Load signed kernel file from boot partition
fn load_signed_kernel_file(image_handle: Handle, kernel_name: &str) -> Result<Vec<u8>, Status> {
    info!("Loading signed kernel file '{}'...", kernel_name);
    match load_kernel(image_handle, kernel_name) {
        Ok(data) => {
            info!("Kernel loaded successfully. Size: {} bytes", data.len());
            Ok(data)
        }
        Err(e) => {
            error!("Failed to load kernel: {:?}", e);
            info!("Stalling before exit...");
            boot::stall(Duration::from_micros(5_000_000));
            Err(e)
        }
    }
}

/// Load command line from exoloader.cmdline file, trimming whitespace
fn load_cmdline_from_file(image_handle: Handle) -> Option<Vec<u8>> {
    match load_kernel(image_handle, "exoloader.cmdline") {
        Ok(data) => {
            let mut len = data.len();
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while len > 0
                && (data[len - 1] == b'\n' || data[len - 1] == b'\r' || data[len - 1] == 0)
            {
                len -= 1;
            }
            if len > 0 {
                Some(data[..len].to_vec())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Merge two cmdline sources (file takes precedence)
fn merge_cmdline_sources(
    file_cmdline: Option<Vec<u8>>,
    entry_cmdline: Option<&str>,
) -> Option<Vec<u8>> {
    match (file_cmdline, entry_cmdline) {
        (Some(file), Some(entry)) => {
            let mut merged = file;
            merged.push(b' ');
            merged.extend_from_slice(entry.as_bytes());
            info!("Cmdline (merged): {} bytes", merged.len());
            Some(merged)
        }
        (Some(file), None) => {
            info!("Cmdline (from file): {} bytes", file.len());
            Some(file)
        }
        (None, Some(entry)) => {
            let entry_bytes = entry.as_bytes().to_vec();
            info!("Cmdline (from config): {} bytes", entry_bytes.len());
            Some(entry_bytes)
        }
        (None, None) => {
            info!("No kernel cmdline specified");
            None
        }
    }
}

/// Log effective command line (first 64 bytes)
fn log_effective_cmdline(cmdline: Option<&[u8]>) {
    if let Some(data) = cmdline {
        if let Ok(s) = core::str::from_utf8(&data[..data.len().min(64)]) {
            info!("Effective cmdline: \"{}\"...", s);
        }
    }
}

/// Load and merge kernel command line from file and config
fn load_and_merge_cmdline(image_handle: Handle, entry_cmdline: Option<&str>) -> Option<Vec<u8>> {
    let file_cmdline = load_cmdline_from_file(image_handle);
    let result = merge_cmdline_sources(file_cmdline, entry_cmdline);
    log_effective_cmdline(result.as_deref());
    result
}

/// Verify kernel signature and return ELF data (after signature prefix)
fn verify_and_split_signed_kernel(signed_kernel_data: &[u8]) -> Result<&[u8], Status> {
    if signed_kernel_data.len() < SIG_SIZE {
        error!("SECURITY ERROR: Kernel file too small (< 64 bytes)!");
        boot::stall(Duration::from_micros(10_000_000));
        return Err(Status::SECURITY_VIOLATION);
    }

    let (signature_bytes, kernel_elf_data) = signed_kernel_data.split_at(SIG_SIZE);

    let verification_enabled = !cfg!(feature = "insecure_boot");
    if verification_enabled {
        info!("Verifying Kernel Signature...");
        if let Err(e) = verify_kernel(signature_bytes, kernel_elf_data) {
            error!("==================================================");
            error!("SECURITY VIOLATION: Invalid Kernel Signature!");
            error!("Error details: {:?}", e);
            error!("System halted for security.");
            error!("==================================================");
            boot::stall(Duration::from_micros(10_000_000));
            return Err(Status::SECURITY_VIOLATION);
        }
        info!("Signature Verification PASSED! Booting trusted kernel...");
    } else {
        info!("Signature verification skipped (insecure_boot feature)");
    }

    Ok(kernel_elf_data)
}

/// Log ELF LOAD segment headers
fn log_elf_load_segments(elf: &xmas_elf::ElfFile) {
    for header in elf.program_iter() {
        if let xmas_elf::program::ProgramHeader::Ph64(ph) = header {
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                info!(
                    "LOAD Segment: VAddr 0x{:x}, MemSize 0x{:x}, FileSize 0x{:x}",
                    ph.virtual_addr, ph.mem_size, ph.file_size
                );
            }
        }
    }
}

/// Map a single ELF LOAD segment, returning the physical start address
fn map_single_load_segment(
    ph: &xmas_elf::program::ProgramHeader64,
    mapper: &mut page_table::UefiMapper,
    kernel_elf_data: &[u8],
) -> u64 {
    use page_table::{PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_SIZE, PAGE_WRITABLE};

    let virt_addr = ph.virtual_addr;
    let page_offset = virt_addr & (PAGE_SIZE - 1);
    let virt_start_aligned = virt_addr & !(PAGE_SIZE - 1);
    let total_size = ph.mem_size + page_offset;
    let num_pages = ((total_size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;

    let mut page_flags = 0u64;
    if ph.flags.is_write() {
        page_flags |= PAGE_WRITABLE;
    }
    if !ph.flags.is_execute() {
        page_flags |= PAGE_NO_EXECUTE;
    }

    info!(
        "Mapping segment: Virt 0x{:x} (aligned: 0x{:x}, offset: 0x{:x}), MemSize 0x{:x}, Pages: {}, Flags: {}",
        virt_addr, virt_start_aligned, page_offset, ph.mem_size, num_pages, ph.flags
    );

    let phys_start = page_table::UefiMapper::alloc_zeroed_pages(num_pages, MemoryType::LOADER_DATA)
        .expect("Failed to allocate kernel segment");

    let data_slice = &kernel_elf_data[ph.offset as usize..(ph.offset + ph.file_size) as usize];
    unsafe {
        core::ptr::copy_nonoverlapping(
            data_slice.as_ptr(),
            (phys_start + page_offset) as *mut u8,
            data_slice.len(),
        );
    }

    for i in 0..num_pages {
        let vaddr = virt_start_aligned + (i as u64 * PAGE_SIZE);
        let paddr = phys_start + (i as u64 * PAGE_SIZE);
        mapper
            .map_page(vaddr, paddr, page_flags | PAGE_PRESENT)
            .expect("Failed to map page");
    }

    phys_start
}

/// Map all ELF LOAD segments and return segment info (virt, phys, size)
fn map_elf_load_segments(
    elf: &xmas_elf::ElfFile,
    mapper: &mut page_table::UefiMapper,
    kernel_elf_data: &[u8],
) -> Vec<(u64, u64, u64)> {
    use page_table::PAGE_SIZE;

    let mut segment_info: Vec<(u64, u64, u64)> = Vec::new();
    for header in elf.program_iter() {
        if let xmas_elf::program::ProgramHeader::Ph64(ph) = header {
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                let phys_start = map_single_load_segment(ph, mapper, kernel_elf_data);
                let page_offset = ph.virtual_addr & (PAGE_SIZE - 1);
                segment_info.push((ph.virtual_addr, phys_start + page_offset, ph.mem_size));
            }
        }
    }
    segment_info
}

/// Detect PT_TLS segment for Thread Local Storage initialization
fn detect_tls_segment(elf: &xmas_elf::ElfFile) -> boot_proto::TlsInfo {
    let mut tls_info = boot_proto::TlsInfo::default();
    for header in elf.program_iter() {
        if let xmas_elf::program::ProgramHeader::Ph64(ph) = header {
            if ph.get_type().unwrap() == xmas_elf::program::Type::Tls {
                tls_info.start_addr = ph.virtual_addr;
                tls_info.file_size = ph.file_size;
                tls_info.mem_size = ph.mem_size;
                tls_info.align = ph.align;
                info!(
                    "Found PT_TLS: start=0x{:x}, file_size=0x{:x}, mem_size=0x{:x}, align={}",
                    tls_info.start_addr, tls_info.file_size, tls_info.mem_size, tls_info.align
                );
                break;
            }
        }
    }
    tls_info
}

/// Find the physical address corresponding to a relocation offset
fn find_reloc_physical_addr(reloc_offset: u64, segment_info: &[(u64, u64, u64)]) -> Option<u64> {
    for &(seg_virt, seg_phys, seg_size) in segment_info {
        if reloc_offset >= seg_virt && reloc_offset < seg_virt + seg_size {
            return Some(seg_phys + (reloc_offset - seg_virt));
        }
    }
    None
}

/// Process RELA entries from a single section
fn process_rela_entries(
    rela_entries: &[xmas_elf::sections::Rela<u64>],
    segment_info: &[(u64, u64, u64)],
    reloc_count: &mut usize,
    applied_count: &mut usize,
    reloc_errors: &mut usize,
) {
    for rela in rela_entries {
        *reloc_count += 1;
        let r_type = rela.get_type();
        match r_type {
            8u32 => {
                // R_X86_64_RELATIVE: *reloc_addr = base + addend
                let reloc_offset = rela.get_offset();
                let addend = rela.get_addend();
                match find_reloc_physical_addr(reloc_offset, segment_info) {
                    Some(reloc_phys) => {
                        let value = (KERNEL_BASE as i64).wrapping_add(addend as i64) as u64;
                        if *applied_count < 5 {
                            info!(
                                "RELA[{}]: off=0x{:x} add=0x{:x} val=0x{:x} phys=0x{:x}",
                                *applied_count, reloc_offset, addend, value, reloc_phys
                            );
                        }
                        unsafe {
                            *(reloc_phys as *mut u64) = value;
                        }
                        *applied_count += 1;
                    }
                    None => {
                        *reloc_errors += 1;
                        error!(
                            "RELA[{}]: off=0x{:x} not found in load segments",
                            *reloc_count, reloc_offset
                        );
                    }
                }
            }
            other => {
                *reloc_errors += 1;
                if *reloc_errors <= 5 {
                    error!(
                        "Unsupported relocation type {} at offset 0x{:x}",
                        other,
                        rela.get_offset()
                    );
                }
            }
        }
    }
}
