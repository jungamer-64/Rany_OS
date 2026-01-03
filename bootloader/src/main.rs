#![no_std]
#![no_main]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::time::Duration;
use log::{error, info};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{boot, CStr16, Identify};
use uefi::mem::memory_map::{MemoryType, MemoryMap};

// Ed25519 signature verification for secure boot
use ed25519_compact::{PublicKey, Signature};

mod ap_boot;
mod boot_log;
mod config;
mod menu;
mod numa;
mod page_table;
mod recovery;
mod secure_boot;
mod self_test;
mod serial;
mod shim_mok;
mod smbios;
mod sme_sev;
mod tpm;
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
    serial::init();
    serial_println!("ExoLoader: Serial console initialized");

    info!("ExoLoader v0.1.0 Starting...");
    serial_println!("ExoLoader v0.1.0 Starting...");
    info!("Initializing Boot Protocol...");

    // Get image handle for protocol operations
    let image_handle = boot::image_handle();

    // 0.5. Load boot configuration and show menu (if multiple entries)
    let boot_config = match load_kernel(image_handle, "exoloader.cfg") {
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
    };

    // Show boot menu if multiple entries or timeout > 0
    let selected_entry = if boot_config.entries.len() > 1 || boot_config.timeout > 0 {
        info!("Showing boot menu...");
        match menu::show_boot_menu(&boot_config) {
            menu::MenuResult::Selected(idx) => {
                info!("User selected entry {}", idx);
                boot_config.entries.get(idx)
            }
            menu::MenuResult::Timeout => {
                info!("Timeout, using default entry {}", boot_config.default_entry);
                boot_config.entries.get(boot_config.default_entry)
            }
            menu::MenuResult::Cancelled => {
                info!("Boot cancelled by user");
                boot::stall(Duration::from_micros(2_000_000));
                return Status::ABORTED;
            }
        }
    } else {
        boot_config.entries.first()
    };

    // Determine kernel/initramfs paths from selected entry
    let (kernel_name, initramfs_name, entry_cmdline) = match selected_entry {
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
    };

    // 1. Locate and load signed kernel
    // We assume the kernel file is named "rany_os" and located in the root of the boot partition
    // Format: [Ed25519 Signature (64 bytes)] + [ELF Binary]
    info!("Loading signed kernel file '{}'...", kernel_name);
    let signed_kernel_data = match load_kernel(image_handle, kernel_name) {
        Ok(data) => {
            info!("Kernel loaded successfully. Size: {} bytes", data.len());
            data
        }
        Err(e) => {
            error!("Failed to load kernel: {:?}", e);
            info!("Stalling before exit...");
            boot::stall(Duration::from_micros(5_000_000));
            return e;
        }
    };

    // 1.1. Optionally load initramfs (Cell drivers)
    // This is optional - kernel will boot without it
    let initramfs_data = if let Some(initramfs_path) = initramfs_name {
        match load_kernel(image_handle, initramfs_path) {
            Ok(data) => {
                info!("Initramfs loaded: {} bytes", data.len());
                Some(data)
            }
            Err(_) => {
                info!("No {} found (optional)", initramfs_path);
                None
            }
        }
    } else {
        info!("No initramfs specified");
        None
    };

    // 1.2. Kernel command line handling
    // Priority: exoloader.cmdline file > boot entry cmdline
    let cmdline_data = {
        // First try loading from file
        let file_cmdline = match load_kernel(image_handle, "exoloader.cmdline") {
            Ok(data) => {
                // Trim trailing newlines and null bytes
                let mut len = data.len();
                while len > 0 && (data[len - 1] == b'\n' || data[len - 1] == b'\r' || data[len - 1] == 0) {
                    len -= 1;
                }
                if len > 0 {
                    Some(data[..len].to_vec())
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        // Merge: file cmdline takes precedence, then entry cmdline
        match (file_cmdline, entry_cmdline) {
            (Some(file), Some(entry)) => {
                // Merge both: "file_args entry_args"
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
    };

    if let Some(ref cmdline) = cmdline_data {
        if let Ok(s) = core::str::from_utf8(&cmdline[..cmdline.len().min(64)]) {
            info!("Effective cmdline: \"{}\"...", s);
        }
    }

    // ============================================================
    // SECURE BOOT: Ed25519 Signature Verification
    // ============================================================
    let verification_enabled = !(cfg!(debug_assertions) || cfg!(feature = "insecure_boot"));
    if signed_kernel_data.len() < SIG_SIZE {
        error!("SECURITY ERROR: Kernel file too small (< 64 bytes)!");
        boot::stall(Duration::from_micros(10_000_000));
        return Status::SECURITY_VIOLATION;
    }

    // Split: [Signature (64 bytes)] + [ELF binary]
    let (signature_bytes, kernel_elf_data) = signed_kernel_data.split_at(SIG_SIZE);

    if verification_enabled {
        info!("Verifying Kernel Signature...");
        match verify_kernel(signature_bytes, kernel_elf_data) {
            Ok(()) => {
                info!("Signature Verification PASSED! Booting trusted kernel...");
            }
            Err(e) => {
                // Verification failed - NEVER boot an untrusted kernel
                error!("==================================================");
                error!("SECURITY VIOLATION: Invalid Kernel Signature!");
                error!("Error details: {:?}", e);
                error!("System halted for security.");
                error!("==================================================");
                boot::stall(Duration::from_micros(10_000_000)); // 10 seconds to read error
                return Status::SECURITY_VIOLATION;
            }
        }
    } else {
        info!("Signature verification skipped (debug/insecure build)");
    }

    // 1.3 TPM 2.0 Measured Boot
    // Extend PCRs with hashes of kernel, initramfs, and cmdline
    // This creates a cryptographic chain of trust verifiable via remote attestation
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
    #[cfg(feature = "uefi")]
    uefi_services::print!("ELF Entry Point: 0x{:x}\n", elf.header.pt2.entry_point());

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

    // 3. Map Memory
    use page_table::{
        CpuPageFeatures, PageTable, UefiMapper, PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_SIZE,
        PAGE_SIZE_1GB, PAGE_SIZE_2MB, PAGE_WRITABLE,
    };

    // Detect CPU page size support
    let cpu_features = CpuPageFeatures::detect();
    info!(
        "CPU Page Features: PSE(2MB)={}, Page1GB={}",
        cpu_features.pse, cpu_features.page_1gb
    );

    info!("Allocating PML4...");
    let pml4_addr =
        UefiMapper::alloc_zeroed_pages(1).expect("Failed to allocate PML4");
    let pml4 = unsafe { &mut *(pml4_addr as *mut PageTable) };

    let mut mapper = UefiMapper::new(pml4);

    // Note: 512MB identity mapping was removed - it conflicted with 4KB segment mapping
    // (2MB huge pages can't be overridden by 4KB pages in same address range)

    // Track segment physical addresses for relocation processing
    let mut segment_info: alloc::vec::Vec<(u64, u64, u64)> = alloc::vec::Vec::new(); // (virt, phys, size)

    for header in elf.program_iter() {
        if let xmas_elf::program::ProgramHeader::Ph64(ph) = header {
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                // Kernel is now statically linked at higher-half - use virtual address directly
                let virt_addr = ph.virtual_addr;
                let mem_size = ph.mem_size;
                let file_size = ph.file_size;
                let offset = ph.offset;

                // Page-align virtual address (round down)
                let page_offset = virt_addr & (PAGE_SIZE - 1);
                let virt_start_aligned = virt_addr & !(PAGE_SIZE - 1);

                // Calculate total size including page offset
                let total_size = mem_size + page_offset;
                let num_pages = ((total_size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;

                let ph_flags = ph.flags;
                let mut page_flags = 0;
                if ph_flags.is_write() {
                    page_flags |= PAGE_WRITABLE;
                }
                if !ph_flags.is_execute() {
                    page_flags |= PAGE_NO_EXECUTE;
                }

                info!(
                    "Mapping segment: Virt 0x{:x} (aligned: 0x{:x}, offset: 0x{:x}), MemSize 0x{:x}, Pages: {}, Flags: {}",
                    virt_addr, virt_start_aligned, page_offset, mem_size, num_pages, ph_flags
                );

                let phys_start = UefiMapper::alloc_zeroed_pages(num_pages)
                    .expect("Failed to allocate kernel segment");

                // Track this segment for relocation processing (use original VAddr)
                segment_info.push((ph.virtual_addr, phys_start + page_offset, mem_size));

                // Copy data at the correct offset within the first page
                let data_slice = &kernel_elf_data[offset as usize..(offset + file_size) as usize];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data_slice.as_ptr(),
                        (phys_start + page_offset) as *mut u8,
                        data_slice.len(),
                    );
                }

                // Map pages using page-aligned addresses
                for i in 0..num_pages {
                    let vaddr = virt_start_aligned + (i as u64 * PAGE_SIZE);
                    let paddr = phys_start + (i as u64 * PAGE_SIZE);
                    // Standard Kernel Flags: Present | Writable.
                    mapper
                        .map_page(vaddr, paddr, page_flags | PAGE_PRESENT)
                        .expect("Failed to map page");
                }
            }
        }
    }

    // 3.4 Detect PT_TLS segment for Thread Local Storage initialization
    // TLS is required for per-CPU variables in the kernel
    use boot_proto::TlsInfo;
    let mut tls_info = TlsInfo::default();
    for header in elf.program_iter() {
        if let xmas_elf::program::ProgramHeader::Ph64(ph) = header {
            // PT_TLS = 7
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

    // 3.5 Process RELA relocations for PIE ELF
    // Find RELA section and apply R_X86_64_RELATIVE relocations
    let mut reloc_count = 0usize;
    let mut applied_count = 0usize;
    let mut reloc_errors = 0usize;
    for section in elf.section_iter() {
        if let Ok(name) = section.get_name(&elf) {
            if name == ".rela.dyn" || name.starts_with(".rela") {
                if let Ok(xmas_elf::sections::SectionData::Rela64(rela_entries)) =
                    section.get_data(&elf)
                {
                    info!(
                        "Processing {} RELA relocations from {}",
                        rela_entries.len(),
                        name
                    );
                    for rela in rela_entries {
                        reloc_count += 1;
                        // R_X86_64_RELATIVE = 8
                        let r_type = rela.get_type();
                        match r_type {
                            8u32 => {
                                // R_X86_64_RELATIVE: *reloc_addr = base + addend
                                let reloc_offset = rela.get_offset();
                                let addend = rela.get_addend();

                                // Find which segment this relocation belongs to
                                let mut found = false;
                                for &(seg_virt, seg_phys, seg_size) in &segment_info {
                                    if reloc_offset >= seg_virt
                                        && reloc_offset < seg_virt + seg_size
                                    {
                                        // Calculate physical address of relocation target
                                        let reloc_phys = seg_phys + (reloc_offset - seg_virt);
                                        // Apply relocation: write base + addend
                                        // Base is KERNEL_BASE since we're relocating from 0 to KERNEL_BASE
                                        let value =
                                            (KERNEL_BASE as i64).wrapping_add(addend as i64) as u64;

                                        // Debug first 5 relocations
                                        if applied_count < 5 {
                                            info!("RELA[{}]: off=0x{:x} add=0x{:x} val=0x{:x} phys=0x{:x}", 
                                                applied_count, reloc_offset, addend, value, reloc_phys);
                                        }

                                        unsafe {
                                            *(reloc_phys as *mut u64) = value;
                                        }
                                        applied_count += 1;
                                        found = true;
                                        break;
                                    }
                                }
                                if !found {
                                    reloc_errors += 1;
                                    error!(
                                        "RELA[{}]: off=0x{:x} not found in load segments",
                                        reloc_count, reloc_offset
                                    );
                                }
                            }
                            other => {
                                reloc_errors += 1;
                                if reloc_errors <= 5 {
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
            }
        }
    }
    if reloc_errors > 0 {
        error!(
            "Relocation processing failed: {} error(s) out of {} entries",
            reloc_errors, reloc_count
        );
        boot::stall(Duration::from_micros(10_000_000));
        return Status::LOAD_ERROR;
    }
    info!("Applied {}/{} relocations", applied_count, reloc_count);

    // Debug: Find physical address of entry point and dump first 8 bytes
    let entry_vaddr = elf.header.pt2.entry_point();
    let mut entry_phys_addr = 0u64; // Store for later HHDM test
    info!("Entry point VAddr: 0x{:x}", entry_vaddr);
    for (seg_vaddr, seg_phys, seg_size) in &segment_info {
        if entry_vaddr >= *seg_vaddr && entry_vaddr < *seg_vaddr + *seg_size {
            let offset_in_seg = entry_vaddr - *seg_vaddr;
            let entry_phys = *seg_phys + offset_in_seg;
            entry_phys_addr = entry_phys;
            info!(
                "Entry in segment VAddr 0x{:x}, PhysStart 0x{:x}, Offset 0x{:x}",
                seg_vaddr, seg_phys, offset_in_seg
            );
            info!("Entry physical address: 0x{:x}", entry_phys);
            // Dump first 8 bytes at entry
            let bytes = unsafe { core::slice::from_raw_parts(entry_phys as *const u8, 8) };
            info!(
                "Entry bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
            );
            // Expected: 66 ba f8 03 b0 4b ee b0
            // Note: Page table walk verification removed due to borrow checker issues
            break;
        }
    }

    // 4. Calculate Max Physical Address
    // We allocate a large buffer to avoid reallocation issues
    let map = boot::memory_map(MemoryType::LOADER_DATA)
        .expect("Failed to get mmap");

    let mut max_phys = 0;
    for desc in map.entries() {
        let end = desc.phys_start + (desc.page_count * 4096);
        if end > max_phys {
            max_phys = end;
        }
    }

    // 5. Map HHDM - Map up to 4GB to cover RAM and MMIO regions
    // Device MMIO regions (e.g., IOMMU at 0xfed90000) must be accessible via HHDM.
    // We use max_phys (from all memory map entries) but cap at 4GB to avoid excessive pages.
    let hhdm_start = 0xffff_8000_0000_0000;

    // Use max_phys to cover all regions including MMIO, but cap at 4GB
    // This ensures IOMMU registers (0xfed90000), LAPIC, etc. are accessible.
    let map_limit = max_phys.min(4 * 1024 * 1024 * 1024); // 4GB max
    info!(
        "Mapping HHDM: max_phys=0x{:x}, limit=0x{:x}",
        max_phys, map_limit
    );

    // First, explicitly map first 8MB with 4KB pages to ensure bootloader code is mapped
    // This is a workaround for potential issues with 2MB page support in QEMU TCG
    let first_region = (8 * 1024 * 1024u64).min(map_limit);
    for page in 0..(first_region / 4096) {
        let addr = page * 4096;
        mapper
            .map_page(addr, addr, PAGE_WRITABLE | PAGE_PRESENT)
            .expect("Failed to map first 8MB 4KB");
        mapper
            .map_page(hhdm_start + addr, addr, PAGE_WRITABLE | PAGE_PRESENT)
            .expect("Failed to map HHDM first 8MB 4KB");
    }

    // Continue with largest possible page size: 1GB > 2MB > 4KB
    // This minimizes TLB pressure and improves memory access performance
    let mut current = first_region;
    let mut pages_1gb = 0u32;
    let mut pages_2mb = 0u32;
    let mut pages_4kb = 0u32;

    while current < map_limit {
        let remaining = map_limit - current;

        // Try 1GB page first (if CPU supports and alignment is correct)
        if cpu_features.page_1gb
            && current % PAGE_SIZE_1GB == 0
            && remaining >= PAGE_SIZE_1GB
        {
            mapper
                .map_page_1gb(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map HHDM 1GB");
            mapper
                .map_page_1gb(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map Identity 1GB");
            current += PAGE_SIZE_1GB;
            pages_1gb += 1;
        }
        // Try 2MB page
        else if current % PAGE_SIZE_2MB == 0 && remaining >= PAGE_SIZE_2MB {
            mapper
                .map_page_2mb(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map HHDM 2MB");
            mapper
                .map_page_2mb(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map Identity 2MB");
            current += PAGE_SIZE_2MB;
            pages_2mb += 1;
        }
        // Fall back to 4KB page
        else {
            mapper
                .map_page(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map HHDM 4KB");
            mapper
                .map_page(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map Identity 4KB");
            current += PAGE_SIZE;
            pages_4kb += 1;
        }
    }

    info!(
        "HHDM mapped: {} x 1GB, {} x 2MB, {} x 4KB pages",
        pages_1gb, pages_2mb, pages_4kb
    );

    // 6. Populate Boot Info
    use boot_proto::{ExoBootInfo, MemoryDescriptor as BootMemoryDescriptor};

    info!("Allocating BootInfo...");
    let boot_info_phys =
        UefiMapper::alloc_zeroed_pages(1).expect("Failed to allocate BootInfo");
    let boot_info = unsafe { &mut *(boot_info_phys as *mut ExoBootInfo) };

    boot_info.version = 1;
    boot_info.phys_mem_offset = hhdm_start;
    boot_info.page_table_base = pml4_addr;

    // TLS template information for kernel per-CPU variables
    boot_info.tls_template = tls_info;

    // RSDP
    boot_info.rsdp_addr = uefi::system::with_config_table(|entries| {
        if let Some(rsdp) = entries.iter().find(|entry| entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID) {
            rsdp.address as u64
        } else if let Some(rsdp) = entries.iter().find(|entry| entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI_GUID) {
            rsdp.address as u64
        } else {
            0
        }
    });

    // 6.1. Early NUMA topology detection from ACPI SRAT table
    // This provides the kernel with NUMA node information for NUMA-aware allocations
    if boot_info.rsdp_addr != 0 {
        boot_info.numa_info = numa::detect_numa_topology(boot_info.rsdp_addr);
        if boot_info.numa_info.node_count > 0 {
            info!(
                "NUMA: {} node(s) detected",
                boot_info.numa_info.node_count
            );
        }
    }

    // 6.2. Prepare AP (Application Processor) boot resources
    // Allocates trampoline code region below 1MB and pre-allocates per-AP stacks
    boot_info.ap_boot = ap_boot::prepare_ap_boot(0);
    if boot_info.ap_boot.ap_count > 0 {
        info!(
            "AP Boot: {} AP(s) prepared, trampoline at 0x{:x}",
            boot_info.ap_boot.ap_count, boot_info.ap_boot.trampoline_addr
        );
    }

    // 6.3. Collect UEFI Runtime Services information
    // This must be done BEFORE ExitBootServices so we can access the memory map
    boot_info.uefi_runtime =
        uefi_runtime::collect_runtime_info(hhdm_start);
    info!(
        "UEFI Runtime: {} region(s), capabilities 0x{:x}",
        boot_info.uefi_runtime.runtime_mmap_count, boot_info.uefi_runtime.capabilities
    );

    // 6.4. Detect AMD SME/SEV and Intel TDX memory encryption
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

    // 6.5. Detect UEFI Secure Boot state
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

    // 6.6. Detect Shim bootloader and MOK (Machine Owner Key) state
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

    // 6.7. Detect SMBIOS (System Management BIOS) tables
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

    // 6.8. Boot recovery state management
    let mut boot_state = recovery::load_boot_state();
    recovery::log_boot_state(&boot_state);

    // Create boot logger for this session and initialize (rotates old logs)
    let mut boot_logger = boot_log::BootLogger::new();
    boot_logger.init();
    boot_logger.info("ExoLoader boot sequence started");

    // Check if we should enter recovery mode
    if recovery::should_enter_recovery(&boot_state) {
        boot_logger.warning("Entering recovery mode due to repeated failures");
        info!("RECOVERY MODE: {} consecutive boot failures detected", boot_state.failure_count);
    }

    // Prepare boot attempt (sets failure flag, will be cleared by kernel on success)
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

    // 6.9. Run self-tests
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

    // Log self-test results
    if self_test_results.critical_failures > 0 {
        boot_logger.error("Self-test detected critical failures");
    } else if self_test_results.warnings > 0 {
        boot_logger.warning("Self-test completed with warnings");
    } else {
        boot_logger.info("All self-tests passed");
    }

    // GOP
    if let Ok(handles) = boot::locate_handle_buffer(
        uefi::boot::SearchType::ByProtocol(&uefi::proto::console::gop::GraphicsOutput::GUID),
    ) {
        if let Some(handle) = handles.first() {
            if let Ok(mut gop) = boot::open_protocol_exclusive::<uefi::proto::console::gop::GraphicsOutput>(*handle)
            {
                let mode = gop.current_mode_info();
                let mut fb = gop.frame_buffer();
                let stride = mode.stride();
                let (width, height) = mode.resolution();

                boot_info.framebuffer.address = fb.as_mut_ptr() as u64;
                boot_info.framebuffer.width = width as u32;
                boot_info.framebuffer.height = height as u32;
                boot_info.framebuffer.stride = stride as u32;

                // Set pixel format and bpp based on UEFI GOP pixel format
                // UEFI GOP typically uses Bgr888 (with 32-bit stride, i.e., 4 bytes/pixel)
                // or BlueGreenRedReserved8BitPerColor which is effectively BGRA8888
                let pixel_format = mode.pixel_format();
                match pixel_format {
                    uefi::proto::console::gop::PixelFormat::Bgr => {
                        boot_info.framebuffer.format = graphic_types::PixelFormat::Bgra8888;
                        boot_info.framebuffer.bpp = 32;
                        // GOP stride is in pixels, convert to bytes
                        boot_info.framebuffer.stride = (stride * 4) as u32;
                    }
                    uefi::proto::console::gop::PixelFormat::Rgb => {
                        boot_info.framebuffer.format = graphic_types::PixelFormat::Rgba8888;
                        boot_info.framebuffer.bpp = 32;
                        // GOP stride is in pixels, convert to bytes
                        boot_info.framebuffer.stride = (stride * 4) as u32;
                    }
                    _ => {
                        // Default to BGRA8888 (most common for modern UEFI)
                        boot_info.framebuffer.format = graphic_types::PixelFormat::Bgra8888;
                        boot_info.framebuffer.bpp = 32;
                        boot_info.framebuffer.stride = (stride * 4) as u32;
                    }
                }
            }
        }
    }

    // 6.5. Initialize initramfs in boot_info
    // Copy initramfs data to allocated pages and set up boot_info.initramfs
    if let Some(ref initramfs) = initramfs_data {
        let num_pages = (initramfs.len() + 4095) / 4096;
        let initramfs_phys = UefiMapper::alloc_zeroed_pages(num_pages)
            .expect("Failed to alloc initramfs");
        unsafe {
            core::ptr::copy_nonoverlapping(
                initramfs.as_ptr(),
                initramfs_phys as *mut u8,
                initramfs.len(),
            );
        }
        // Pass HHDM virtual address to kernel
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

    // 6.6. Initialize command line in boot_info
    // Copy cmdline data to allocated pages and set up boot_info.cmdline_ptr/len
    if let Some(ref cmdline) = cmdline_data {
        // Allocate pages for command line (+ 1 for null terminator)
        let cmdline_size = cmdline.len() + 1;
        let num_pages = (cmdline_size + 4095) / 4096;
        let cmdline_phys = UefiMapper::alloc_zeroed_pages(num_pages)
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
        // Pass HHDM virtual address to kernel
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

    // 6.7. Pre-allocate memory map buffer BEFORE exiting boot services
    // We cannot allocate after exit_boot_services() - UEFI heap will be invalid!
    // In uefi 0.36, we estimate size based on typical memory map
    let mmap_estimate_count = 512; // Generous estimate for typical systems
    let mmap_buffer_size = mmap_estimate_count * core::mem::size_of::<BootMemoryDescriptor>();
    let mmap_buffer_pages = (mmap_buffer_size + 4095) / 4096;
    let mmap_buffer_phys = UefiMapper::alloc_zeroed_pages(mmap_buffer_pages)
        .expect("Failed to allocate memory map buffer");

    // Log kernel entry points before exiting boot services (info!() won't work after)
    let entry_addr = elf.header.pt2.entry_point();
    let hhdm_entry = 0xffff_8000_0000_0000u64 + entry_phys_addr;
    info!("Kernel entry (KERNEL_BASE): 0x{:x}", entry_addr);
    info!("Kernel entry (HHDM): 0x{:x}", hhdm_entry);

    // Save boot log before exiting boot services
    boot_logger.info("About to exit boot services and jump to kernel");
    boot_logger.finalize(true);
    boot_logger.save();

    // 7. Exit Boot Services
    info!("Exiting Boot Services...");
    let mmap = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // NOTE: After exit_boot_services(), NO allocations allowed!
    // We must use pre-allocated buffer only.

    // Update Memory Map using pre-allocated buffer
    let mmap_entries = mmap.entries();
    let count = mmap_entries.len();
    boot_info.memory_map.count = count as u64;

    // Copy to pre-allocated buffer (no heap allocation!)
    let boot_mmap_slice = unsafe {
        core::slice::from_raw_parts_mut(
            mmap_buffer_phys as *mut BootMemoryDescriptor,
            mmap_estimate_count,
        )
    };
    for (i, desc) in mmap_entries.enumerate() {
        if i >= mmap_estimate_count {
            break; // Safety: don't overflow buffer
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

    // 8. Switch CR3 & Jump
    // Kernel is statically linked at higher-half - entry point is already at correct address

    // Use inline asm for absolute jump to kernel after CR3 switch
    // NOTE: Use explicit registers to avoid compiler reordering:
    //   - r8 for pml4 (not clobbered by subsequent instructions)
    //   - r9 for boot_info
    //   - r10 for entry address
    // These are callee-saved in System V ABI and safe to use
    // All in single asm block to avoid compiler-inserted code between steps
    unsafe {
        core::arch::asm!(
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
            in("r9") hhdm_start + boot_info_phys, // Pass HHDM virtual address so kernel can access it
            in("r10") entry_addr,
            options(noreturn)
        );
    }
}

fn load_kernel(
    image_handle: Handle,
    filename: &str,
) -> Result<Vec<u8>, Status> {
    // 1. Get LoadedImage protocol to find the device handle
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(image_handle)
        .map_err(|_| Status::ABORTED)?;

    let device_handle = loaded_image.device().ok_or(Status::ABORTED)?;

    // 2. Get SimpleFileSystem from the device handle
    let mut fs = boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle)
        .map_err(|_| Status::ABORTED)?;

    let mut root = fs.open_volume().map_err(|_| Status::ABORTED)?;

    // 3. Convert filename to UCS-2 (UTF-16)
    // Try both bare name and a leading backslash to handle firmware differences.
    let name_utf16: Vec<u16> = filename.encode_utf16().collect();
    if name_utf16.len() >= 127 {
        return Err(Status::INVALID_PARAMETER);
    }

    // Primary path: bare filename
    let mut path_buf = [0u16; 128];
    path_buf[..name_utf16.len()].copy_from_slice(&name_utf16);
    path_buf[name_utf16.len()] = 0; // Null terminator
    let path = CStr16::from_u16_with_nul(&path_buf[..=name_utf16.len()])
        .map_err(|_| Status::INVALID_PARAMETER)?;

    // Fallback path: leading backslash
    let mut alt_path_buf = [0u16; 129];
    alt_path_buf[0] = b'\\' as u16;
    alt_path_buf[1..=name_utf16.len()].copy_from_slice(&name_utf16);
    alt_path_buf[name_utf16.len() + 1] = 0;
    let alt_path = CStr16::from_u16_with_nul(&alt_path_buf[..=name_utf16.len() + 1])
        .map_err(|_| Status::INVALID_PARAMETER)?;

    // 4. Open file (try bare name, fall back to leading backslash)
    let file_handle = root
        .open(path, FileMode::Read, FileAttribute::empty())
        .or_else(|_| root.open(alt_path, FileMode::Read, FileAttribute::empty()))
        .map_err(|_| Status::NOT_FOUND)?;

    let mut file = file_handle.into_regular_file().ok_or(Status::ABORTED)?;

    // 5. Get file info to determine size
    let mut info_buf = [0u8; 512]; // Buffer for FileInfo
    let info_result = file.get_info::<FileInfo>(&mut info_buf);

    let size = match info_result {
        Ok(info) => info.file_size(),
        Err(e) => {
            // Sometimes buffer is too small, but 512 should be enough for basic info
            return Err(e.status());
        }
    };

    info!("Found file. Size: {}", size);

    // 6. Allocate buffer and read (avoid uninitialized memory)
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
            // EOF before expected size
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
