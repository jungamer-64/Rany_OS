//! UEFI ファイルシステムI/O操作
//!
//! ブートパーティションからカーネル、initramfs、設定ファイル等を読み込む。

#![allow(clippy::wildcard_imports)]
use super::*;
use uefi::proto::media::file::Directory;

/// ブートボリュームのルートディレクトリを開く
pub(crate) fn open_boot_volume(image_handle: Handle) -> Result<Directory, Status> {
    let loaded_image =
        boot::open_protocol_exclusive::<LoadedImage>(image_handle).map_err(|_| Status::ABORTED)?;
    let device_handle = loaded_image.device().ok_or(Status::ABORTED)?;
    let mut fs = boot::open_protocol_exclusive::<SimpleFileSystem>(device_handle)
        .map_err(|_| Status::ABORTED)?;
    fs.open_volume().map_err(|_| Status::ABORTED)
}

/// UEFI ファイルシステムからファイルを開く
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

/// ブートパーティションからファイルをロードする
pub(crate) fn load_kernel(image_handle: Handle, filename: &str) -> Result<Vec<u8>, Status> {
    let mut file = open_uefi_file(image_handle, filename)?;
    read_uefi_file_contents(&mut file)
}

/// Ed25519署名によるカーネル検証
///
/// # Arguments
/// * `sig_bytes` - 64バイトの署名
/// * `message` - 署名対象のカーネルELFデータ
///
/// # Returns
/// * `Ok(())` - 検証成功
/// * `Err(ed25519_compact::Error)` - 検証失敗
pub(crate) fn verify_kernel(
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<(), ed25519_compact::Error> {
    let pk = PublicKey::from_slice(PUBLIC_KEY_BYTES)?;
    let sig = Signature::from_slice(sig_bytes)?;
    pk.verify(message, &sig)
}
