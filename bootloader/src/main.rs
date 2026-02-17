#![no_std]
#![no_main]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::time::Duration;
use log::{error, info};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{boot, CStr16, Identify};
use uefi::mem::memory_map::{MemoryType, MemoryMap};

// Ed25519 signature verification for secure boot
use ed25519_compact::{PublicKey, Signature};

mod ap_boot;
mod boot_log;
mod config;
#[cfg(feature = "ui")]
mod menu;
mod numa;
mod page_table;
mod recovery;
mod secure_boot;
#[cfg(feature = "self_test")]
mod self_test;
#[cfg(feature = "serial_log")]
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
    let boot_config = load_boot_config(image_handle);

    #[cfg(feature = "ui")]
    let selected_entry = match select_boot_entry_ui(&boot_config) {
        Ok(entry) => entry,
        Err(status) => return status,
    };

    #[cfg(not(feature = "ui"))]
    let selected_entry = boot_config.entries.get(boot_config.default_entry).or_else(|| boot_config.entries.first());

    let (kernel_name, initramfs_name, entry_cmdline) = determine_boot_paths(selected_entry);

    // 1. Load signed kernel, initramfs, and command line
    let signed_kernel_data = match load_signed_kernel_file(image_handle, kernel_name) {
        Ok(data) => data,
        Err(e) => return e,
    };
    let initramfs_data = load_optional_initramfs_file(image_handle, initramfs_name);
    let cmdline_data = load_and_merge_cmdline(image_handle, entry_cmdline);

    // ============================================================
    // SECURE BOOT: Ed25519 Signature Verification
    // ============================================================
    let kernel_elf_data = match verify_and_split_signed_kernel(&signed_kernel_data) {
        Ok(data) => data,
        Err(status) => return status,
    };

    // 1.3 TPM 2.0 Measured Boot
    let tpm_result = tpm::perform_measured_boot(
        kernel_elf_data,
        initramfs_data.as_deref(),
        cmdline_data.as_deref(),
    );
    if tpm_result.tpm_available {
        info!(
            "TPM Measured Boot: kernel={}, initramfs={}, cmdline={}",
            tpm_result.kernel_measured,
            tpm_result.initramfs_measured,
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
    let pml4_addr =
        UefiMapper::alloc_zeroed_pages(1, MemoryType::RUNTIME_SERVICES_DATA)
            .expect("Failed to allocate PML4");
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
    use boot_proto::{ExoBootInfo, MemoryDescriptor as BootMemoryDescriptor, EXO_BOOT_INFO_VERSION};

    info!("Allocating BootInfo...");
    let boot_info_phys =
        page_table::UefiMapper::alloc_zeroed_pages(1, MemoryType::RUNTIME_SERVICES_DATA)
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

    // 6.8. Boot recovery state management
    let mut boot_logger = handle_boot_recovery(boot_info);

    // 6.9. Run self-tests
    run_boot_self_tests(boot_info, &mut boot_logger);

    // GOP framebuffer setup
    setup_gop_framebuffer(boot_info);

    // 6.5. Initialize initramfs and cmdline in boot_info
    copy_initramfs_to_boot_info(boot_info, &initramfs_data, hhdm_start);
    copy_cmdline_to_boot_info(boot_info, &cmdline_data, hhdm_start);

    // 6.7. Pre-allocate memory map buffer BEFORE exiting boot services
    let mmap_estimate_count = 512;
    let mmap_buffer_size = mmap_estimate_count * core::mem::size_of::<BootMemoryDescriptor>();
    let mmap_buffer_pages = (mmap_buffer_size + 4095) / 4096;
    let mmap_buffer_phys =
        page_table::UefiMapper::alloc_zeroed_pages(mmap_buffer_pages, MemoryType::RUNTIME_SERVICES_DATA)
            .expect("Failed to allocate memory map buffer");

    // Log kernel entry points before exiting boot services
    let entry_addr = elf.header.pt2.entry_point();
    let hhdm_entry = hhdm_start + entry_phys_addr;
    info!("Kernel entry (KERNEL_BASE): 0x{:x}", entry_addr);
    info!("Kernel entry (HHDM): 0x{:x}", hhdm_entry);

    // Save boot log before exiting boot services
    boot_logger.info("About to exit boot services and jump to kernel");
    boot_logger.finalize(true);
    boot_logger.save();

    // 7. Exit Boot Services
    info!("Exiting Boot Services...");
    let mmap = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // Build memory map from UEFI into pre-allocated buffer
    build_memory_map_from_uefi(&mmap, boot_info, mmap_buffer_phys, mmap_estimate_count, hhdm_start);

    // 8. Switch CR3 & Jump to kernel
    unsafe {
        switch_cr3_and_jump(pml4_addr, hhdm_start + boot_info_phys, entry_addr);
    }
}

// ============================================================
// Helper functions extracted from main() for cyclomatic complexity reduction
// ============================================================

/// Load and parse boot configuration from exoloader.cfg
fn load_boot_config(image_handle: Handle) -> config::BootConfig {
    match load_kernel(image_handle, "exoloader.cfg") {
        Ok(data) => {
            if let Ok(cfg_str) = core::str::from_utf8(&data) {
                config::parse_config(cfg_str)
            } else {
                info!("Boot config not valid UTF-8, using defaults");
                config::default_config()
            }
        }
        Err(_) => {
            info!("No exoloader.cfg found, using defaults");
            config::default_config()
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

/// Determine kernel path, initramfs path, and cmdline from selected boot entry
fn determine_boot_paths<'a>(
    selected_entry: Option<&'a config::BootEntry>,
) -> (&'a str, Option<&'a str>, Option<&'a str>) {
    match selected_entry {
        Some(entry) => {
            info!("Booting: {}", entry.name);
            (
                entry.kernel.as_str(),
                entry.initramfs.as_deref(),
                entry.cmdline.as_deref(),
            )
        }
        None => {
            info!("No boot entry found, using defaults");
            ("rany_os", Some("initramfs.tar"), None)
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

/// Load optional initramfs file
fn load_optional_initramfs_file(
    image_handle: Handle,
    initramfs_name: Option<&str>,
) -> Option<Vec<u8>> {
    if let Some(path) = initramfs_name {
        match load_kernel(image_handle, path) {
            Ok(data) => {
                info!("Initramfs loaded: {} bytes", data.len());
                Some(data)
            }
            Err(_) => {
                info!("No {} found (optional)", path);
                None
            }
        }
    } else {
        info!("No initramfs specified");
        None
    }
}

/// Load command line from exoloader.cmdline file, trimming whitespace
fn load_cmdline_from_file(image_handle: Handle) -> Option<Vec<u8>> {
    match load_kernel(image_handle, "exoloader.cmdline") {
        Ok(data) => {
            let mut len = data.len();
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
fn load_and_merge_cmdline(
    image_handle: Handle,
    entry_cmdline: Option<&str>,
) -> Option<Vec<u8>> {
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

    let verification_enabled = !(cfg!(debug_assertions) || cfg!(feature = "insecure_boot"));
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
        info!("Signature verification skipped (debug/insecure build)");
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

    let phys_start =
        page_table::UefiMapper::alloc_zeroed_pages(num_pages, MemoryType::LOADER_DATA)
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
fn find_reloc_physical_addr(
    reloc_offset: u64,
    segment_info: &[(u64, u64, u64)],
) -> Option<u64> {
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
                        let value =
                            (KERNEL_BASE as i64).wrapping_add(addend as i64) as u64;
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

/// Process all ELF RELA relocations
fn process_elf_relocations(
    elf: &xmas_elf::ElfFile,
    segment_info: &[(u64, u64, u64)],
) -> Result<(usize, usize), Status> {
    let mut reloc_count = 0usize;
    let mut applied_count = 0usize;
    let mut reloc_errors = 0usize;

    for section in elf.section_iter() {
        if let Ok(name) = section.get_name(elf) {
            if name == ".rela.dyn" || name.starts_with(".rela") {
                if let Ok(xmas_elf::sections::SectionData::Rela64(rela_entries)) =
                    section.get_data(elf)
                {
                    info!(
                        "Processing {} RELA relocations from {}",
                        rela_entries.len(),
                        name
                    );
                    process_rela_entries(
                        rela_entries,
                        segment_info,
                        &mut reloc_count,
                        &mut applied_count,
                        &mut reloc_errors,
                    );
                }
            }
        }
    }

    if reloc_errors > 0 {
        error!(
            "Relocation processing failed: {} error(s) out of {} entries",
            reloc_errors, reloc_count
        );
        boot::stall(Duration::from_micros(10_000_000));
        return Err(Status::LOAD_ERROR);
    }
    info!("Applied {}/{} relocations", applied_count, reloc_count);
    Ok((applied_count, reloc_count))
}

/// Resolve the physical address of the kernel entry point
fn resolve_entry_physical_address(
    entry_vaddr: u64,
    segment_info: &[(u64, u64, u64)],
) -> u64 {
    for &(seg_vaddr, seg_phys, seg_size) in segment_info {
        if entry_vaddr >= seg_vaddr && entry_vaddr < seg_vaddr + seg_size {
            let offset_in_seg = entry_vaddr - seg_vaddr;
            let entry_phys = seg_phys + offset_in_seg;
            info!(
                "Entry in segment VAddr 0x{:x}, PhysStart 0x{:x}, Offset 0x{:x}",
                seg_vaddr, seg_phys, offset_in_seg
            );
            info!("Entry physical address: 0x{:x}", entry_phys);
            let bytes = unsafe { core::slice::from_raw_parts(entry_phys as *const u8, 8) };
            info!(
                "Entry bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
            );
            return entry_phys;
        }
    }
    0
}

/// Compute maximum physical address from UEFI memory map
fn compute_max_physical_address() -> u64 {
    let map =
        boot::memory_map(MemoryType::LOADER_DATA).expect("Failed to get mmap");
    let mut max_phys = 0u64;
    for desc in map.entries() {
        let end = desc.phys_start + (desc.page_count * 4096);
        if end > max_phys {
            max_phys = end;
        }
    }
    max_phys
}

/// Page size selection for HHDM mapping
enum HhdmPageSize {
    Size1GB,
    Size2MB,
    Size4KB,
}

/// Select the best page size for the given address and remaining space
fn select_hhdm_page_size(
    current: u64,
    remaining: u64,
    cpu_features: &page_table::CpuPageFeatures,
) -> (u64, HhdmPageSize) {
    use page_table::{PAGE_SIZE, PAGE_SIZE_1GB, PAGE_SIZE_2MB};
    if cpu_features.page_1gb && current % PAGE_SIZE_1GB == 0 && remaining >= PAGE_SIZE_1GB {
        (PAGE_SIZE_1GB, HhdmPageSize::Size1GB)
    } else if current % PAGE_SIZE_2MB == 0 && remaining >= PAGE_SIZE_2MB {
        (PAGE_SIZE_2MB, HhdmPageSize::Size2MB)
    } else {
        (PAGE_SIZE, HhdmPageSize::Size4KB)
    }
}

/// Map first region with 4KB pages for both identity and HHDM
fn map_first_region_4kb(
    mapper: &mut page_table::UefiMapper,
    first_region: u64,
    hhdm_start: u64,
) {
    use page_table::{PAGE_PRESENT, PAGE_WRITABLE};
    for page in 0..(first_region / 4096) {
        let addr = page * 4096;
        mapper
            .map_page(addr, addr, PAGE_WRITABLE | PAGE_PRESENT)
            .expect("Failed to map first 8MB 4KB");
        mapper
            .map_page(hhdm_start + addr, addr, PAGE_WRITABLE | PAGE_PRESENT)
            .expect("Failed to map HHDM first 8MB 4KB");
    }
}

/// Map HHDM and identity regions using largest available page sizes
fn map_hhdm_and_identity(
    mapper: &mut page_table::UefiMapper,
    map_limit: u64,
    hhdm_start: u64,
    cpu_features: &page_table::CpuPageFeatures,
) -> (u32, u32, u32) {
    use page_table::{PAGE_PRESENT, PAGE_WRITABLE};

    let first_region = (8 * 1024 * 1024u64).min(map_limit);
    map_first_region_4kb(mapper, first_region, hhdm_start);

    let mut current = first_region;
    let mut pages_1gb = 0u32;
    let mut pages_2mb = 0u32;
    let mut pages_4kb = 0u32;

    while current < map_limit {
        let remaining = map_limit - current;
        let (advance, page_type) = select_hhdm_page_size(current, remaining, cpu_features);
        match page_type {
            HhdmPageSize::Size1GB => {
                mapper
                    .map_page_1gb(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                    .expect("Failed to map HHDM 1GB");
                mapper
                    .map_page_1gb(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                    .expect("Failed to map Identity 1GB");
                pages_1gb += 1;
            }
            HhdmPageSize::Size2MB => {
                mapper
                    .map_page_2mb(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                    .expect("Failed to map HHDM 2MB");
                mapper
                    .map_page_2mb(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                    .expect("Failed to map Identity 2MB");
                pages_2mb += 1;
            }
            HhdmPageSize::Size4KB => {
                mapper
                    .map_page(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                    .expect("Failed to map HHDM 4KB");
                mapper
                    .map_page(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                    .expect("Failed to map Identity 4KB");
                pages_4kb += 1;
            }
        }
        current += advance;
    }

    (pages_1gb, pages_2mb, pages_4kb)
}

/// Find RSDP (Root System Description Pointer) address from UEFI config table
fn find_rsdp_address() -> u64 {
    uefi::system::with_config_table(|entries| {
        if let Some(rsdp) = entries
            .iter()
            .find(|entry| entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID)
        {
            rsdp.address as u64
        } else if let Some(rsdp) = entries
            .iter()
            .find(|entry| entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI_GUID)
        {
            rsdp.address as u64
        } else {
            0
        }
    })
}

/// Populate memory encryption info in boot_info
fn populate_memory_encryption_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let mem_enc_info = sme_sev::detect_memory_encryption();
    boot_info.mem_encryption = boot_proto::MemoryEncryptionInfo {
        sme_available: mem_enc_info.sme_available,
        sev_available: mem_enc_info.sev_available,
        sev_es_available: mem_enc_info.sev_es_available,
        sev_snp_available: mem_enc_info.sev_snp_available,
        sme_enabled: mem_enc_info.sme_enabled,
        sev_enabled: mem_enc_info.sev_enabled,
        _reserved: [0; 2],
        c_bit_position: mem_enc_info.c_bit_position,
        phys_addr_reduction: mem_enc_info.phys_addr_reduction,
        _reserved2: [0; 6],
        encryption_mask: mem_enc_info.encryption_mask,
        tdx_available: mem_enc_info.tdx_available,
        _reserved3: [0; 7],
    };
    if mem_enc_info.sme_enabled || mem_enc_info.sev_enabled {
        info!(
            "Memory encryption enabled: C-bit={}, mask=0x{:x}",
            mem_enc_info.c_bit_position, mem_enc_info.encryption_mask
        );
    }
}

/// Populate secure boot state info in boot_info
fn populate_secure_boot_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let sb_info = secure_boot::detect_secure_boot_state();
    boot_info.secure_boot = boot_proto::SecureBootInfo {
        secure_boot_enabled: sb_info.secure_boot_enabled,
        setup_mode: sb_info.setup_mode,
        pk_present: sb_info.pk_present,
        kek_present: sb_info.kek_present,
        db_present: sb_info.db_present,
        dbx_present: sb_info.dbx_present,
        audit_mode: sb_info.audit_mode,
        deployed_mode: sb_info.deployed_mode,
        vendor_keys: sb_info.vendor_keys,
        _reserved: [0; 7],
    };
    info!("{}", secure_boot::get_secure_boot_status_string(&sb_info));
}

/// Populate Shim/MOK state info in boot_info
fn populate_shim_mok_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let shim_info = shim_mok::detect_shim_mok();
    boot_info.shim_mok = boot_proto::ShimMokInfo {
        shim_detected: shim_info.shim_detected,
        mok_sb_state: shim_info.mok_sb_state,
        mok_list_present: shim_info.mok_list_present,
        mok_list_rt_present: shim_info.mok_list_rt_present,
        mok_list_x_present: shim_info.mok_list_x_present,
        sbat_level_present: shim_info.sbat_level_present,
        shim_validated: shim_info.shim_validated,
        _reserved: 0,
        mok_count: shim_info.mok_count,
        shim_version_major: shim_info.shim_version_major,
        shim_version_minor: shim_info.shim_version_minor,
        _reserved2: [0; 4],
    };
    info!("{}", shim_mok::get_shim_mok_status_string(&shim_info));
}

/// Populate SMBIOS info in boot_info
fn populate_smbios_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let smbios_info = smbios::detect_smbios();
    boot_info.smbios = boot_proto::SmbiosInfo {
        smbios3_addr: smbios_info.smbios3_addr,
        smbios_addr: smbios_info.smbios_addr,
        major_version: smbios_info.major_version,
        minor_version: smbios_info.minor_version,
        table_max_size: smbios_info.table_max_size,
        flags: smbios_info.flags,
        _reserved: [0; 4],
        bios_vendor_offset: smbios_info.bios_vendor_offset,
        bios_version_offset: smbios_info.bios_version_offset,
        system_manufacturer_offset: smbios_info.system_manufacturer_offset,
        system_product_offset: smbios_info.system_product_offset,
        system_serial_offset: smbios_info.system_serial_offset,
        system_uuid: smbios_info.system_uuid,
    };
    smbios::log_smbios_info(&smbios_info);
}

/// Populate all hardware detection fields in boot_info
fn populate_boot_info_detections(
    boot_info: &mut boot_proto::ExoBootInfo,
    hhdm_start: u64,
) {
    // RSDP
    boot_info.rsdp_addr = find_rsdp_address();

    // NUMA topology
    if boot_info.rsdp_addr != 0 {
        boot_info.numa_info = numa::detect_numa_topology(boot_info.rsdp_addr);
        if boot_info.numa_info.node_count > 0 {
            info!("NUMA: {} node(s) detected", boot_info.numa_info.node_count);
        }
    }

    // AP (Application Processor) boot resources
    boot_info.ap_boot = ap_boot::prepare_ap_boot(0);
    if boot_info.ap_boot.ap_count > 0 {
        info!(
            "AP Boot: {} AP(s) prepared, trampoline at 0x{:x}",
            boot_info.ap_boot.ap_count, boot_info.ap_boot.trampoline_addr
        );
    }

    // UEFI Runtime Services
    boot_info.uefi_runtime = uefi_runtime::collect_runtime_info(hhdm_start);
    info!(
        "UEFI Runtime: {} region(s), capabilities 0x{:x}",
        boot_info.uefi_runtime.runtime_mmap_count, boot_info.uefi_runtime.capabilities
    );

    // Memory encryption, Secure Boot, Shim/MOK, SMBIOS
    populate_memory_encryption_info(boot_info);
    populate_secure_boot_info(boot_info);
    populate_shim_mok_info(boot_info);
    populate_smbios_info(boot_info);
}

/// Handle boot recovery state and return boot logger
fn handle_boot_recovery(
    boot_info: &mut boot_proto::ExoBootInfo,
) -> boot_log::BootLogger {
    let mut boot_state = recovery::load_boot_state();
    recovery::log_boot_state(&boot_state);

    let mut boot_logger = boot_log::BootLogger::new();
    boot_logger.init();
    boot_logger.info("ExoLoader boot sequence started");

    if recovery::should_enter_recovery(&boot_state) {
        boot_logger.warning("Entering recovery mode due to repeated failures");
        info!(
            "RECOVERY MODE: {} consecutive boot failures detected",
            boot_state.failure_count
        );
    }

    let recovery_info = recovery::prepare_boot_attempt(&mut boot_state, 0);
    boot_info.boot_recovery = boot_proto::BootRecoveryInfo {
        boot_attempt_id: recovery_info.boot_attempt_id,
        failure_count: recovery_info.failure_count,
        is_recovery_mode: recovery_info.is_recovery_mode,
        is_fallback: recovery_info.is_fallback,
        _reserved: 0,
        expected_success_id: recovery_info.expected_success_id,
    };
    boot_logger.info("Boot recovery state prepared");
    boot_logger
}

/// Run self-tests and populate boot_info (self_test feature enabled)
#[cfg(feature = "self_test")]
fn run_boot_self_tests(
    boot_info: &mut boot_proto::ExoBootInfo,
    boot_logger: &mut boot_log::BootLogger,
) {
    let self_test_config = self_test::SelfTestConfig::default();
    let self_test_results = self_test::run_self_tests(&self_test_config);
    boot_info.self_test = boot_proto::SelfTestInfo {
        overall_result: match self_test_results.overall {
            self_test::TestResult::Pass => 0,
            self_test::TestResult::Warning => 1,
            self_test::TestResult::Fail => 2,
            self_test::TestResult::Skip => 3,
        },
        critical_failures: self_test_results.critical_failures,
        warnings: self_test_results.warnings,
        tests_run: self_test_results.tests.len() as u8,
        _reserved: [0; 4],
    };

    if self_test_results.critical_failures > 0 {
        boot_logger.error("Self-test detected critical failures");
    } else if self_test_results.warnings > 0 {
        boot_logger.warning("Self-test completed with warnings");
    } else {
        boot_logger.info("All self-tests passed");
    }
}

/// Skip self-tests in minimal/production builds
#[cfg(not(feature = "self_test"))]
fn run_boot_self_tests(
    boot_info: &mut boot_proto::ExoBootInfo,
    boot_logger: &mut boot_log::BootLogger,
) {
    boot_info.self_test = boot_proto::SelfTestInfo {
        overall_result: 3, // Skip
        critical_failures: 0,
        warnings: 0,
        tests_run: 0,
        _reserved: [0; 4],
    };
    boot_logger.info("Self-tests skipped (minimal build)");
}

/// Configure pixel format for GOP framebuffer
fn configure_pixel_format(
    boot_info: &mut boot_proto::ExoBootInfo,
    pixel_format: uefi::proto::console::gop::PixelFormat,
    stride: usize,
) {
    match pixel_format {
        uefi::proto::console::gop::PixelFormat::Bgr => {
            boot_info.framebuffer.format = graphic_types::PixelFormat::Bgra8888;
            boot_info.framebuffer.bpp = 32;
            boot_info.framebuffer.stride = (stride * 4) as u32;
        }
        uefi::proto::console::gop::PixelFormat::Rgb => {
            boot_info.framebuffer.format = graphic_types::PixelFormat::Rgba8888;
            boot_info.framebuffer.bpp = 32;
            boot_info.framebuffer.stride = (stride * 4) as u32;
        }
        _ => {
            boot_info.framebuffer.format = graphic_types::PixelFormat::Bgra8888;
            boot_info.framebuffer.bpp = 32;
            boot_info.framebuffer.stride = (stride * 4) as u32;
        }
    }
}

/// Setup GOP (Graphics Output Protocol) framebuffer in boot_info
fn setup_gop_framebuffer(boot_info: &mut boot_proto::ExoBootInfo) {
    let handles = match boot::locate_handle_buffer(
        uefi::boot::SearchType::ByProtocol(&uefi::proto::console::gop::GraphicsOutput::GUID),
    ) {
        Ok(h) => h,
        Err(_) => return,
    };

    let handle = match handles.first() {
        Some(h) => *h,
        None => return,
    };

    let mut gop = match boot::open_protocol_exclusive::<
        uefi::proto::console::gop::GraphicsOutput,
    >(handle)
    {
        Ok(g) => g,
        Err(_) => return,
    };

    let mode = gop.current_mode_info();
    let mut fb = gop.frame_buffer();
    let stride = mode.stride();
    let (width, height) = mode.resolution();

    boot_info.framebuffer.address = fb.as_mut_ptr() as u64;
    boot_info.framebuffer.width = width as u32;
    boot_info.framebuffer.height = height as u32;
    boot_info.framebuffer.stride = stride as u32;

    configure_pixel_format(boot_info, mode.pixel_format(), stride);
}

/// Copy initramfs data to allocated pages and set up boot_info
fn copy_initramfs_to_boot_info(
    boot_info: &mut boot_proto::ExoBootInfo,
    initramfs_data: &Option<Vec<u8>>,
    hhdm_start: u64,
) {
    if let Some(initramfs) = initramfs_data {
        let num_pages = (initramfs.len() + 4095) / 4096;
        let initramfs_phys =
            page_table::UefiMapper::alloc_zeroed_pages(num_pages, MemoryType::LOADER_DATA)
                .expect("Failed to alloc initramfs");
        unsafe {
            core::ptr::copy_nonoverlapping(
                initramfs.as_ptr(),
                initramfs_phys as *mut u8,
                initramfs.len(),
            );
        }
        boot_info.initramfs.ptr = hhdm_start + initramfs_phys;
        boot_info.initramfs.size = initramfs.len() as u64;
        info!(
            "Initramfs mapped at HHDM 0x{:x}, size {}",
            boot_info.initramfs.ptr, boot_info.initramfs.size
        );
    } else {
        boot_info.initramfs.ptr = 0;
        boot_info.initramfs.size = 0;
    }
}

/// Copy cmdline data to allocated pages and set up boot_info
fn copy_cmdline_to_boot_info(
    boot_info: &mut boot_proto::ExoBootInfo,
    cmdline_data: &Option<Vec<u8>>,
    hhdm_start: u64,
) {
    if let Some(cmdline) = cmdline_data {
        let cmdline_size = cmdline.len() + 1;
        let num_pages = (cmdline_size + 4095) / 4096;
        let cmdline_phys =
            page_table::UefiMapper::alloc_zeroed_pages(num_pages, MemoryType::LOADER_DATA)
                .expect("Failed to alloc cmdline");
        unsafe {
            core::ptr::copy_nonoverlapping(
                cmdline.as_ptr(),
                cmdline_phys as *mut u8,
                cmdline.len(),
            );
            // Null terminate
            *((cmdline_phys + cmdline.len() as u64) as *mut u8) = 0;
        }
        boot_info.cmdline_ptr = hhdm_start + cmdline_phys;
        boot_info.cmdline_len = cmdline.len() as u64;
        info!(
            "Cmdline mapped at HHDM 0x{:x}, len {}",
            boot_info.cmdline_ptr, boot_info.cmdline_len
        );
    } else {
        boot_info.cmdline_ptr = 0;
        boot_info.cmdline_len = 0;
    }
}

/// Build memory map from UEFI memory map into pre-allocated buffer
fn build_memory_map_from_uefi(
    mmap: &uefi::mem::memory_map::MemoryMapOwned,
    boot_info: &mut boot_proto::ExoBootInfo,
    mmap_buffer_phys: u64,
    mmap_estimate_count: usize,
    hhdm_start: u64,
) {
    use boot_proto::MemoryDescriptor as BootMemoryDescriptor;

    let mmap_entries = mmap.entries();
    let count = mmap_entries.len();
    boot_info.memory_map.count = count as u64;

    let boot_mmap_slice = unsafe {
        core::slice::from_raw_parts_mut(
            mmap_buffer_phys as *mut BootMemoryDescriptor,
            mmap_estimate_count,
        )
    };
    for (i, desc) in mmap_entries.enumerate() {
        if i >= mmap_estimate_count {
            break;
        }
        boot_mmap_slice[i] = BootMemoryDescriptor {
            r#type: desc.ty.0,
            pad: 0,
            phys_start: desc.phys_start,
            virt_start: desc.virt_start,
            page_count: desc.page_count,
            attribute: desc.att.bits(),
        };
    }
    boot_info.memory_map.entries = (hhdm_start + mmap_buffer_phys) as *const _;
}

/// Switch CR3 to kernel page tables and jump to kernel entry point
unsafe fn switch_cr3_and_jump(pml4_addr: u64, boot_info_virt: u64, entry_addr: u64) -> ! {
    unsafe { core::arch::asm!(
        // Output 'J' before cli to show we're about to jump
        "mov dx, 0x3F8",
        "mov al, 0x4A",  // 'J' for Jump
        "out dx, al",
        // Disable interrupts
        "cli",
        // Output '1' to show cli executed
        "mov al, 0x31",  // '1'
        "out dx, al",
        // Memory fence
        "mfence",
        // Output '2' to show mfence executed
        "mov al, 0x32",  // '2'
        "out dx, al",
        // Switch to kernel page tables
        "mov cr3, r8",
        // Output '3' to show CR3 switch executed
        "mov al, 0x33",  // '3'
        "out dx, al",
        // Set up argument register
        "mov rdi, r9",
        // Output '4' to show mov rdi executed
        "mov al, 0x34",  // '4'
        "out dx, al",
        // Jump to kernel entry
        "jmp r10",
        in("r8") pml4_addr,
        in("r9") boot_info_virt,
        in("r10") entry_addr,
        options(noreturn)
    ); }
}

fn load_kernel(
    image_handle: Handle,
    filename: &str,
) -> Result<Vec<u8>, Status> {
    let mut file = open_uefi_file(image_handle, filename)?;
    read_uefi_file_contents(&mut file)
}

/// UEFI ファイルシステムからファイルを開く
fn open_uefi_file(
    image_handle: Handle,
    filename: &str,
) -> Result<RegularFile, Status> {
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(image_handle)
        .map_err(|_| Status::ABORTED)?;

    let device_handle = loaded_image.device().ok_or(Status::ABORTED)?;

    let mut fs = boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle)
        .map_err(|_| Status::ABORTED)?;

    let mut root = fs.open_volume().map_err(|_| Status::ABORTED)?;

    let name_utf16: Vec<u16> = filename.encode_utf16().collect();
    if name_utf16.len() >= 127 {
        return Err(Status::INVALID_PARAMETER);
    }

    let mut path_buf = [0u16; 128];
    path_buf[..name_utf16.len()].copy_from_slice(&name_utf16);
    path_buf[name_utf16.len()] = 0;
    let path = CStr16::from_u16_with_nul(&path_buf[..=name_utf16.len()])
        .map_err(|_| Status::INVALID_PARAMETER)?;

    let mut alt_path_buf = [0u16; 129];
    alt_path_buf[0] = b'\\' as u16;
    alt_path_buf[1..=name_utf16.len()].copy_from_slice(&name_utf16);
    alt_path_buf[name_utf16.len() + 1] = 0;
    let alt_path = CStr16::from_u16_with_nul(&alt_path_buf[..=name_utf16.len() + 1])
        .map_err(|_| Status::INVALID_PARAMETER)?;

    let file_handle = root
        .open(path, FileMode::Read, FileAttribute::empty())
        .or_else(|_| root.open(alt_path, FileMode::Read, FileAttribute::empty()))
        .map_err(|_| Status::NOT_FOUND)?;

    file_handle.into_regular_file().ok_or(Status::ABORTED)
}

/// UEFI ファイルの全内容をバッファに読み込む
fn read_uefi_file_contents(file: &mut RegularFile) -> Result<Vec<u8>, Status> {
    let mut info_buf = [0u8; 512];
    let info_result = file.get_info::<FileInfo>(&mut info_buf);

    let size = match info_result {
        Ok(info) => info.file_size(),
        Err(e) => {
            return Err(e.status());
        }
    };

    info!("Found file. Size: {}", size);

    if size > usize::MAX as u64 {
        return Err(Status::OUT_OF_RESOURCES);
    }
    let mut buffer = vec![0u8; size as usize];
    let mut total_read = 0usize;
    while total_read < buffer.len() {
        let read_size = file
            .read(&mut buffer[total_read..])
            .map_err(|_| Status::ABORTED)?;
        if read_size == 0 {
            return Err(Status::ABORTED);
        }
        total_read += read_size;
    }

    Ok(buffer)
}

/// Verifies the Ed25519 signature of the kernel
///
/// # Arguments
/// * `sig_bytes` - The 64-byte signature
/// * `message` - The kernel ELF data (message that was signed)
///
/// # Returns
/// * `Ok(())` if verification passes
/// * `Err(ed25519_compact::Error)` if verification fails
fn verify_kernel(sig_bytes: &[u8], message: &[u8]) -> Result<(), ed25519_compact::Error> {
    // Create public key from embedded bytes
    let pk = PublicKey::from_slice(PUBLIC_KEY_BYTES)?;

    // Create signature object from bytes
    let sig = Signature::from_slice(sig_bytes)?;

    // Verify: check that the signature was created by signing `message` with
    // the secret key corresponding to `pk`
    pk.verify(message, &sig)
}
