//! ブートローダー中核モジュール
//!
//! ブートローダーの主要機能を以下のサブモジュールに分割して管理する：
//!
//! - `file_io` - UEFI ファイルシステム操作（カーネルロード、署名検証）
//! - `boot_info_setup` - ExoBootInfo の構築（ハードウェア検出、リカバリ、セルフテスト）
//! - `hhdm` - HHDM/アイデンティティマッピングの構築
//! - `cr3_jump` - CR3 切替とカーネルジャンプ

#![allow(clippy::wildcard_imports)]
use super::*;

// ============================================================
// サブモジュール
// ============================================================

#[path = "elf_relocations/file_io.rs"]
mod file_io;
pub use file_io::*;

#[path = "elf_relocations/boot_info_setup.rs"]
mod boot_info_setup;
pub use boot_info_setup::*;

#[path = "elf_relocations/hhdm.rs"]
mod hhdm;
pub use hhdm::*;

#[path = "elf_relocations/cr3_jump.rs"]
mod cr3_jump;
pub use cr3_jump::*;

// ============================================================
// ELF リロケーション処理
// ============================================================

pub(crate) fn process_elf_relocations(
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
pub(crate) fn resolve_entry_physical_address(
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

// 以下の関数はサブモジュールに移動済み:
// - file_io: load_kernel, open_boot_volume, open_uefi_file, read_uefi_file_contents, verify_kernel
// - boot_info_setup: populate_*, handle_boot_recovery, run_boot_self_tests, setup_gop_framebuffer,
//                    copy_initramfs_to_boot_info, copy_cmdline_to_boot_info, build_memory_map_from_uefi
// - hhdm: compute_max_physical_address, map_hhdm_and_identity, select_hhdm_page_size
// - cr3_jump: switch_cr3_and_jump
