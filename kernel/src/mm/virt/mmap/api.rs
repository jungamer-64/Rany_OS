use super::*;


/// mmap統計
#[derive(Debug)]
pub struct MmapStats {
    pub total_mapped: usize,
    pub total_unmapped: usize,
    pub active_mappings: usize,
}

/// グローバルmmapマネージャー
pub(crate) static MMAP_MANAGER: MmapManager = MmapManager::new();

/// mmapマネージャーを取得
pub fn mmap_manager() -> &'static MmapManager {
    &MMAP_MANAGER
}

// --- POSIX風 API ---

/// mmap() 相当
pub fn mmap(
    addr: Option<MappedAddress>,
    size: MappingSize,
    protection: Protection,
    flags: MappingFlags,
) -> Result<MappedAddress, MmapError> {
    MMAP_MANAGER.mmap_anonymous(addr, size, protection, flags)
}

/// mmap() ファイル版
pub fn mmap_file(
    addr: Option<MappedAddress>,
    size: MappingSize,
    protection: Protection,
    flags: MappingFlags,
    path: &str,
    offset: MappingOffset,
) -> Result<MappedAddress, MmapError> {
    MMAP_MANAGER.mmap_file(addr, size, protection, flags, path, offset)
}

/// munmap() 相当
pub fn munmap(addr: MappedAddress, size: MappingSize) -> Result<(), MmapError> {
    MMAP_MANAGER.munmap(addr, size)
}

/// mprotect() 相当
pub fn mprotect(
    addr: MappedAddress,
    size: MappingSize,
    protection: Protection,
) -> Result<(), MmapError> {
    MMAP_MANAGER.mprotect(addr, size, protection)
}

/// msync() 相当
pub fn msync(addr: MappedAddress, size: MappingSize) -> Result<(), MmapError> {
    MMAP_MANAGER.msync(addr, size)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

