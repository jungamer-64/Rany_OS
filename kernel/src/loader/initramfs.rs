// ============================================================================
// kernel/src/loader/initramfs.rs - Initramfs Loader
//
// 以前は kernel/src/initramfs.rs にルートレベルで配置されていたが、
// セルローディングの一部であるため loader/ モジュール配下に移動。
// ============================================================================
//!
//! # Initramfs Loader
//!
//! Parses a USTAR TAR archive from boot info and loads driver Cells
//! using the Cell loader infrastructure.
//!
//! ## TAR Format (USTAR)
//!
//! Each entry consists of:
//! - 512-byte header
//! - File data (rounded up to 512-byte blocks)
//!
//! The archive ends with two consecutive zero-filled 512-byte blocks.

use crate::driver_domain;
use crate::driver_domain::RestartPolicy;
use crate::driver_domain::lifecycle::DriverDomainConfig;
use crate::loader::staged_pci::StageArtifactResult;
use alloc::string::String;
use alloc::vec::Vec;
use boot_proto::InitramfsModule;
use log::{debug, info, warn};

/// TAR header size in bytes
const TAR_BLOCK_SIZE: usize = 512;

/// USTAR magic value
const USTAR_MAGIC: &[u8; 6] = b"ustar\0";

/// TAR file type indicators
#[allow(dead_code)]
mod tar_type {
    pub const REGULAR: u8 = b'0';
    pub const HARDLINK: u8 = b'1';
    pub const SYMLINK: u8 = b'2';
    pub const CHARDEV: u8 = b'3';
    pub const BLOCKDEV: u8 = b'4';
    pub const DIRECTORY: u8 = b'5';
    pub const FIFO: u8 = b'6';
}

/// TAR header structure (USTAR format)
#[repr(C)]
struct TarHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    checksum: [u8; 8],
    typeflag: u8,
    linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    devmajor: [u8; 8],
    devminor: [u8; 8],
    prefix: [u8; 155],
    _padding: [u8; 12],
}

impl TarHeader {
    /// Check if this is a valid USTAR header
    fn is_valid(&self) -> bool {
        &self.magic == USTAR_MAGIC || &self.magic[..5] == b"ustar"
    }

    /// Check if this is an end-of-archive marker (all zeros)
    fn is_end_marker(&self) -> bool {
        self.name.iter().all(|&b| b == 0)
    }

    /// Get the file size from octal string
    fn file_size(&self) -> usize {
        parse_octal(&self.size)
    }

    /// Get the filename as a string (handles prefix for long names)
    fn filename(&self) -> String {
        let prefix = bytes_to_str(&self.prefix);
        let name = bytes_to_str(&self.name);

        if prefix.is_empty() {
            String::from(name)
        } else {
            let mut path = String::from(prefix);
            path.push('/');
            path.push_str(name);
            path
        }
    }

    /// Check if this is a regular file
    fn is_regular_file(&self) -> bool {
        self.typeflag == tar_type::REGULAR || self.typeflag == 0
    }
}

/// Parse octal string to usize
fn parse_octal(bytes: &[u8]) -> usize {
    let s = bytes_to_str(bytes);
    usize::from_str_radix(s.trim(), 8).unwrap_or(0)
}

/// Convert null-terminated bytes to str
fn bytes_to_str(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// A file entry extracted from the TAR archive
pub struct TarEntry<'a> {
    pub name: String,
    pub data: &'a [u8],
}

/// TAR archive iterator
pub struct TarArchive<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TarArchive<'a> {
    /// Create a new TAR archive parser
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Collect all regular files from the archive
    pub fn files(&mut self) -> Vec<TarEntry<'a>> {
        let mut entries = Vec::new();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(entry) = self.next_entry() {
            entries.push(entry);
        }

        entries
    }

    /// Get the next file entry
    fn next_entry(&mut self) -> Option<TarEntry<'a>> {
        loop {
            // Check bounds
            if self.offset + TAR_BLOCK_SIZE > self.data.len() {
                return None;
            }

            // Read header
            let header_bytes = &self.data[self.offset..self.offset + TAR_BLOCK_SIZE];
            let header: &TarHeader = unsafe { &*(header_bytes.as_ptr() as *const TarHeader) };

            // Check for end marker
            if header.is_end_marker() {
                return None;
            }

            // Get file info
            let file_size = header.file_size();
            let data_blocks = (file_size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
            let data_start = self.offset + TAR_BLOCK_SIZE;
            let data_end = data_start + file_size;

            // Move offset past this entry
            self.offset = data_start + data_blocks * TAR_BLOCK_SIZE;

            // Only return regular files
            if header.is_regular_file() && header.is_valid() {
                let name = header.filename();
                let data = &self.data[data_start..data_end];
                return Some(TarEntry { name, data });
            }
            // Skip directories and other types, continue to next entry
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Load driver Cells from initramfs
///
/// Parses the initramfs TAR archive and loads `drivers/*.cell` files as drivers.
///
/// # Returns
/// Number of successfully loaded drivers
pub fn load_cells_from_initramfs(initramfs: &InitramfsModule) -> usize {
    if initramfs.ptr == 0 || initramfs.size == 0 {
        debug!(target: "initramfs", "No initramfs provided");
        return 0;
    }

    info!(
        target: "initramfs",
        "Loading initramfs: addr=0x{:016x}, size={} bytes",
        initramfs.ptr,
        initramfs.size
    );

    // SAFETY: bootloader provides valid pointer and size
    let data =
        unsafe { core::slice::from_raw_parts(initramfs.ptr as *const u8, initramfs.size as usize) };

    let mut archive = TarArchive::new(data);
    let mut loaded = 0;
    let mut staged = 0;

    for entry in archive.files() {
        #[cfg(feature = "qemu-test-export")]
        if entry.name.starts_with("cells/") && entry.name.ends_with(".cell") {
            crate::io::log::early_print("[INITRAMFS] fixture cache begin ");
            crate::io::log::early_print(&entry.name);
            crate::io::log::early_print("\n");
            crate::driver_domain::qemu_tests::cache_runtime_fixture_cell(&entry.name, entry.data);
            crate::io::log::early_print("[INITRAMFS] fixture cache done ");
            crate::io::log::early_print(&entry.name);
            crate::io::log::early_print("\n");
        }
        // Only autoload driver payloads under /drivers. Other .cell files (e.g.
        // /cells fixtures used by runtime tests) are kept as data artifacts.
        if entry.name.starts_with("drivers/") && entry.name.ends_with(".cell") {
            info!(
                target: "initramfs",
                "Found Cell: {} ({} bytes)",
                entry.name,
                entry.data.len()
            );

            // Extract driver name without path and extension
            let driver_name = extract_driver_name(&entry.name);

            // SAFETY: initramfs bytes come from the bootloader-owned archive that
            // remains mapped for the kernel lifetime, so staged PCI packs can hold
            // borrowed slices without copying the entire artifact into heap memory.
            let staged_artifact =
                unsafe { core::slice::from_raw_parts(entry.data.as_ptr(), entry.data.len()) };
            match crate::loader::staged_pci::stage_initramfs_driver_artifact_static(
                &driver_name,
                staged_artifact,
                true,
            ) {
                StageArtifactResult::Staged => {
                    info!(
                        target: "initramfs",
                        "Staged PCI driver pack '{}' for later PCI binding",
                        driver_name
                    );
                    staged += 1;
                    continue;
                }
                StageArtifactResult::Rejected(reason) => {
                    warn!(target: "initramfs", "Rejected '{}': {}", driver_name, reason);
                    continue;
                }
                StageArtifactResult::NotStaged => {}
            }

            let config = DriverDomainConfig::new(driver_name.clone())
                .with_restart_policy(RestartPolicy::on_panic(3, 100))
                .with_capabilities(crate::security::CapabilitySet::empty())
                .with_unsafe_allowed();

            match driver_domain::lifecycle::create_and_start(&config, entry.data) {
                Ok((driver_domain_id, handles)) => {
                    let loader_cell_id = driver_domain::driver_domain_manager()
                        .with_cell(driver_domain_id, |c| c.cell_id)
                        .ok()
                        .flatten()
                        .map(|c| c.as_u64());
                    info!(
                        target: "initramfs",
                        "Loaded driver cell '{}' as dcell={} loader_cell={:?} handles={}",
                        driver_name,
                        driver_domain_id.as_u64(),
                        loader_cell_id,
                        handles.len()
                    );
                    loaded += 1;
                }
                Err(e) => {
                    warn!(
                        target: "initramfs",
                        "Failed to load driver '{}': {:?}",
                        driver_name,
                        e
                    );
                }
            }
        }
    }

    info!(
        target: "initramfs",
        "Loaded {} driver(s) and staged {} PCI driver pack(s) from initramfs",
        loaded,
        staged
    );
    loaded
}

/// Extract driver name from path (e.g., "drivers/nvme.cell" -> "nvme")
fn extract_driver_name(path: &str) -> String {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let name = filename.strip_suffix(".cell").unwrap_or(filename);
    String::from(name)
}
