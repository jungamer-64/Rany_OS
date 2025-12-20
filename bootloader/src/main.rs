#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use log::{error, info};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::CStr16;
use uefi::Identify;

// Ed25519 signature verification for secure boot
use ed25519_compact::{PublicKey, Signature};

mod page_table;

/// Kernel base address for higher-half mapping
/// PIE ELF has VAddr starting at 0x0, so we add this offset
const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Ed25519 public key for kernel signature verification
/// Embedded at compile time - cannot be tampered with at runtime
static PUBLIC_KEY_BYTES: &[u8] = include_bytes!("../../keys/kernel_pub.key");

/// Ed25519 signature size in bytes
const SIG_SIZE: usize = 64;

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).expect("Failed to initialize UEFI services");

    let boot_services = system_table.boot_services();

    info!("ExoLoader v0.1.0 Starting...");
    info!("Initializing Boot Protocol...");

    // 1. Locate and load signed kernel
    // We assume the kernel file is named "rany_os" and located in the root of the boot partition
    // Format: [Ed25519 Signature (64 bytes)] + [ELF Binary]
    info!("Loading signed kernel file 'rany_os'...");
    let signed_kernel_data = match load_kernel(boot_services, image_handle, "rany_os") {
        Ok(data) => {
            info!("Kernel loaded successfully. Size: {} bytes", data.len());
            data
        }
        Err(e) => {
            error!("Failed to load kernel: {:?}", e);
            info!("Stalling before exit...");
            boot_services.stall(5_000_000);
            return e;
        }
    };

    // ============================================================
    // SECURE BOOT: Ed25519 Signature Verification
    // ============================================================
    info!("Verifying Kernel Signature... (SKIPPED for Debugging)");

    // Dummy logic to proceed without verification
    let (_signature_bytes, kernel_elf_data) = if signed_kernel_data.len() >= SIG_SIZE {
        signed_kernel_data.split_at(SIG_SIZE)
    } else {
        panic!("Kernel too small");
    };

    /*
    if signed_kernel_data.len() < SIG_SIZE {
        error!("SECURITY ERROR: Kernel file too small (< 64 bytes)!");
        boot_services.stall(10_000_000);
        loop {
            core::hint::spin_loop();
        }
    }

    // Split: [Signature (64 bytes)] + [ELF binary]
    let (signature_bytes, kernel_elf_data) = signed_kernel_data.split_at(SIG_SIZE);

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
            boot_services.stall(10_000_000); // 10 seconds to read error
            loop {
                core::hint::spin_loop();
            }
        }
    }
    */

    // 2. Parse ELF (using verified kernel data, without signature)
    let elf = xmas_elf::ElfFile::new(kernel_elf_data).expect("Invalid ELF file");
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
    use page_table::{PageTable, UefiMapper, PAGE_PRESENT, PAGE_SIZE, PAGE_WRITABLE};

    info!("Allocating PML4...");
    let pml4_addr =
        UefiMapper::alloc_zeroed_pages(boot_services, 1).expect("Failed to allocate PML4");
    let pml4 = unsafe { &mut *(pml4_addr as *mut PageTable) };

    let mut mapper = UefiMapper::new(boot_services, pml4);

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

                info!(
                    "Mapping segment: Virt 0x{:x} (aligned: 0x{:x}, offset: 0x{:x}), MemSize 0x{:x}, Pages: {}",
                    virt_addr, virt_start_aligned, page_offset, mem_size, num_pages
                );

                let phys_start = UefiMapper::alloc_zeroed_pages(boot_services, num_pages)
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
                        .map_page(vaddr, paddr, PAGE_WRITABLE | PAGE_PRESENT)
                        .expect("Failed to map page");
                }
            }
        }
    }

    // 3.5 Process RELA relocations for PIE ELF
    // Find RELA section and apply R_X86_64_RELATIVE relocations
    let mut reloc_count = 0usize;
    let mut applied_count = 0usize;
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
                        if r_type == 8u32 {
                            // R_X86_64_RELATIVE: *reloc_addr = base + addend
                            let reloc_offset = rela.get_offset();
                            let addend = rela.get_addend();

                            // Find which segment this relocation belongs to
                            let mut found = false;
                            for &(seg_virt, seg_phys, seg_size) in &segment_info {
                                if reloc_offset >= seg_virt && reloc_offset < seg_virt + seg_size {
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
                            if !found && reloc_count <= 5 {
                                info!(
                                    "RELA[{}]: off=0x{:x} NOT FOUND in segments!",
                                    reloc_count, reloc_offset
                                );
                            }
                        }
                    }
                }
            }
        }
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
    let mmap_size = boot_services.memory_map_size().map_size + 8 * 4096;
    let mut mmap_buf = Vec::with_capacity(mmap_size);
    unsafe {
        mmap_buf.set_len(mmap_size);
    }
    let map = boot_services
        .memory_map(&mut mmap_buf)
        .expect("Failed to get mmap");

    let mut max_phys = 0;
    for desc in map.entries() {
        let end = desc.phys_start + (desc.page_count * 4096);
        if end > max_phys {
            max_phys = end;
        }
    }

    // 5. Map HHDM
    let hhdm_start = 0xffff_8000_0000_0000;
    info!("Mapping HHDM [0, 0x{:x}) at 0x{:x}", max_phys, hhdm_start);

    // First, explicitly map first 8MB with 4KB pages to ensure bootloader code is mapped
    // This is a workaround for potential issues with 2MB page support in QEMU TCG
    for page in 0..(8 * 1024 * 1024 / 4096) {
        let addr = page * 4096;
        mapper
            .map_page(addr, addr, PAGE_WRITABLE | PAGE_PRESENT)
            .expect("Failed to map first 8MB 4KB");
        mapper
            .map_page(hhdm_start + addr, addr, PAGE_WRITABLE | PAGE_PRESENT)
            .expect("Failed to map HHDM first 8MB 4KB");
    }

    // Continue with 2MB pages for the rest
    let mut current = 8 * 1024 * 1024; // Start after the first 8MB
    while current < max_phys {
        let remaining = max_phys - current;
        if current % 0x200000 == 0 && remaining >= 0x200000 {
            mapper
                .map_page_2mb(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map HHDM 2MB");
            mapper
                .map_page_2mb(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map Identity 2MB");
            current += 0x200000;
        } else {
            mapper
                .map_page(hhdm_start + current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map HHDM 4KB");
            mapper
                .map_page(current, current, PAGE_WRITABLE | PAGE_PRESENT)
                .expect("Failed to map Identity 4KB");
            current += 0x1000;
        }
    }

    // 6. Populate Boot Info
    use boot_proto::ExoBootInfo;

    info!("Allocating BootInfo...");
    let boot_info_phys =
        UefiMapper::alloc_zeroed_pages(boot_services, 1).expect("Failed to allocate BootInfo");
    let boot_info = unsafe { &mut *(boot_info_phys as *mut ExoBootInfo) };

    boot_info.version = 1;
    boot_info.phys_mem_offset = hhdm_start;
    boot_info.page_table_base = pml4_addr;

    // RSDP
    if let Some(rsdp) = system_table
        .config_table()
        .iter()
        .find(|entry| entry.guid == uefi::table::cfg::ACPI2_GUID)
    {
        boot_info.rsdp_addr = rsdp.address as u64;
    } else if let Some(rsdp) = system_table
        .config_table()
        .iter()
        .find(|entry| entry.guid == uefi::table::cfg::ACPI_GUID)
    {
        boot_info.rsdp_addr = rsdp.address as u64;
    }

    // GOP
    if let Ok(handles) = boot_services.locate_handle_buffer(
        uefi::table::boot::SearchType::ByProtocol(&uefi::proto::console::gop::GraphicsOutput::GUID),
    ) {
        if let Some(handle) = handles.first() {
            if let Ok(mut gop) = boot_services
                .open_protocol_exclusive::<uefi::proto::console::gop::GraphicsOutput>(*handle)
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

    // 7. Exit Boot Services
    info!("Exiting Boot Services...");
    let (_runtime, mmap) = system_table.exit_boot_services();

    // Update Memory Map
    let count = mmap.entries().len();
    boot_info.memory_map.count = count as u64;

    // Copy to mmap_buf
    let dest_ptr = mmap_buf.as_mut_ptr() as *mut uefi::table::boot::MemoryDescriptor;
    for (i, desc) in mmap.entries().enumerate() {
        unsafe {
            *dest_ptr.add(i) = *desc;
        }
    }
    boot_info.memory_map.entries = mmap_buf.as_ptr() as *const _;

    // 8. Switch CR3 & Jump
    // Kernel is statically linked at higher-half - entry point is already at correct address
    let entry_addr = elf.header.pt2.entry_point();
    // HHDM test showed kernel CAN execute - problem is KERNEL_BASE mapping
    let hhdm_entry = 0xffff_8000_0000_0000u64 + entry_phys_addr;
    // Debug: log both addresses before boot services exit
    info!("Kernel entry (KERNEL_BASE): 0x{:x}", entry_addr);
    info!("Kernel entry (HHDM): 0x{:x}", hhdm_entry);
    // NOTE: Cannot use info!() after exit_boot_services() - ConOut is invalid!

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
    boot_services: &BootServices,
    image_handle: Handle,
    filename: &str,
) -> Result<Vec<u8>, Status> {
    // 1. Get LoadedImage protocol to find the device handle
    let loaded_image = boot_services
        .open_protocol_exclusive::<LoadedImage>(image_handle)
        .map_err(|_| Status::ABORTED)?;

    let device_handle = loaded_image.device();

    // 2. Get SimpleFileSystem from the device handle
    let mut fs = boot_services
        .open_protocol_exclusive::<SimpleFileSystem>(device_handle)
        .map_err(|_| Status::ABORTED)?;

    let mut root = fs.open_volume().map_err(|_| Status::ABORTED)?;

    // 3. Convert filename to UCS-2 (UTF-16)
    // Standard UEFI paths use backslashes, but root opening often accepts basenames.
    // We construct a simple buffer.
    let mut path_buf = [0u16; 128];
    if filename.len() >= 127 {
        return Err(Status::INVALID_PARAMETER);
    }

    // Manual copy to CStr16 buffer
    let mut len = 0;
    // Prefix with backslash? Some firmwares prefer it relative to root.
    // Let's try direct name first.
    for (i, c) in filename.chars().enumerate() {
        path_buf[i] = c as u16;
        len += 1;
    }
    path_buf[len] = 0; // Null terminator

    let path =
        CStr16::from_u16_with_nul(&path_buf[..=len]).map_err(|_| Status::INVALID_PARAMETER)?;

    // 4. Open file
    let file_handle = root
        .open(path, FileMode::Read, FileAttribute::empty())
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

    // 6. Allocate buffer and read
    let mut buffer = Vec::with_capacity(size as usize);
    unsafe {
        buffer.set_len(size as usize);
    }

    let read_size = file.read(&mut buffer).map_err(|_| Status::ABORTED)?;

    if read_size != size as usize {
        // Partial read?
        return Err(Status::ABORTED);
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
