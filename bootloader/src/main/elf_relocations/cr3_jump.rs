#![allow(clippy::wildcard_imports)]
use super::*;
use uefi::proto::media::file::Directory;

/// Switch CR3 to kernel page tables and jump to kernel entry point
pub(crate) unsafe fn switch_cr3_and_jump(
    pml4_addr: u64,
    boot_info_virt: u64,
    entry_addr: u64,
) -> ! {
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
            in("r9") boot_info_virt,
            in("r10") entry_addr,
            options(noreturn)
        );
    }
}

pub(crate) fn load_kernel(image_handle: Handle, filename: &str) -> Result<Vec<u8>, Status> {
    let mut file = open_uefi_file(image_handle, filename)?;
    read_uefi_file_contents(&mut file)
}

/// UEFI ファイルシステムからファイルを開く
pub(crate) fn open_boot_volume(image_handle: Handle) -> Result<Directory, Status> {
    let loaded_image =
        boot::open_protocol_exclusive::<LoadedImage>(image_handle).map_err(|_| Status::ABORTED)?;
    let device_handle = loaded_image.device().ok_or(Status::ABORTED)?;
    let mut fs = boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle)
        .map_err(|_| Status::ABORTED)?;
    fs.open_volume().map_err(|_| Status::ABORTED)
}

pub(crate) fn open_uefi_file(image_handle: Handle, filename: &str) -> Result<RegularFile, Status> {
    let mut root = open_boot_volume(image_handle)?;

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
pub(crate) fn read_uefi_file_contents(file: &mut RegularFile) -> Result<Vec<u8>, Status> {
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
pub(crate) fn verify_kernel(
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<(), ed25519_compact::Error> {
    // Create public key from embedded bytes
    let pk = PublicKey::from_slice(PUBLIC_KEY_BYTES)?;

    // Create signature object from bytes
    let sig = Signature::from_slice(sig_bytes)?;

    // Verify: check that the signature was created by signing `message` with
    // the secret key corresponding to `pk`
    pk.verify(message, &sig)
}
