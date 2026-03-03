//! HHDM (Higher Half Direct Map) およびアイデンティティマッピング
//!
//! カーネルが使用する HHDM 領域と、ブート遷移中のアイデンティティマッピングを構築する。

#![allow(clippy::wildcard_imports)]
use super::*;

/// UEFI メモリマップから最大物理アドレスを算出
pub(crate) fn compute_max_physical_address() -> u64 {
    let map = boot::memory_map(MemoryType::LOADER_DATA).expect("Failed to get mmap");
    let mut max_phys = 0u64;
    for desc in map.entries() {
        let end = desc.phys_start + (desc.page_count * 4096);
        if end > max_phys {
            max_phys = end;
        }
    }
    max_phys
}

/// HHDM マッピングのページサイズ選択
pub(crate) enum HhdmPageSize {
    Size1GB,
    Size2MB,
    Size4KB,
}

/// アドレスと残りサイズに基づいて最適なページサイズを選択
pub(crate) fn select_hhdm_page_size(
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

/// 先頭領域を 4KB ページでアイデンティティ + HHDM マッピング
pub(crate) fn map_first_region_4kb(
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

/// HHDM とアイデンティティ領域を最大ページサイズでマッピング
///
/// 返り値: (1GB ページ数, 2MB ページ数, 4KB ページ数)
pub(crate) fn map_hhdm_and_identity(
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
