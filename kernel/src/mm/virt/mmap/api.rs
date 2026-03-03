use super::*;


/// マッピング統計
#[derive(Debug)]
pub struct MappingStats {
    pub total_mapped: usize,
    pub total_unmapped: usize,
    pub active_mappings: usize,
}

/// グローバルマッピングマネージャー
pub(crate) static MAPPING_MANAGER: MappingManager = MappingManager::new();

/// マッピングマネージャーを取得
pub fn mapping_manager() -> &'static MappingManager {
    &MAPPING_MANAGER
}

// --- Mapping API ---

/// 匿名領域をマップ
pub fn map_anonymous_region(
    addr: Option<MappedAddress>,
    size: MappingSize,
    protection: Protection,
    flags: MappingFlags,
) -> Result<MappedAddress, MappingError> {
    MAPPING_MANAGER.map_anonymous(addr, size, protection, flags)
}

/// ファイル領域をマップ
pub fn map_file_region(
    addr: Option<MappedAddress>,
    size: MappingSize,
    protection: Protection,
    flags: MappingFlags,
    path: &str,
    offset: MappingOffset,
) -> Result<MappedAddress, MappingError> {
    MAPPING_MANAGER.map_file(addr, size, protection, flags, path, offset)
}

/// 領域のマッピングを解除
pub fn unmap_region(addr: MappedAddress, size: MappingSize) -> Result<(), MappingError> {
    MAPPING_MANAGER.unmap(addr, size)
}

/// 領域の保護属性を更新
pub fn protect_region(
    addr: MappedAddress,
    size: MappingSize,
    protection: Protection,
) -> Result<(), MappingError> {
    MAPPING_MANAGER.protect(addr, size, protection)
}

/// 領域の同期を実行
pub fn sync_region(addr: MappedAddress, size: MappingSize) -> Result<(), MappingError> {
    MAPPING_MANAGER.sync(addr, size)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
