//! 初期ページテーブル設定
//!
//! 設計書セクション 11 Phase 1 参照

/// 初期ページテーブルのセットアップ
/// 
/// Phase 1（ブートストラップ）では、可能な限り1GBページを使用して
/// 物理メモリ全体をリニアマッピングし、動的アロケータのブートストラップに必要な
/// 最小限のページテーブルを静的バッファで構築する
pub fn setup_early_pagetables(memory_map: &MemoryMap) {
    // UEFIから受け取ったメモリマップを解析
    let total_memory = memory_map.total_usable_memory();
    
    // 静的バッファを使用（動的アロケータはまだ使えない）
    static mut EARLY_PML4: PageTable = PageTable::empty();
    static mut EARLY_PDPT: [PageTable; 4] = [PageTable::empty(); 4];
    
    unsafe {
        // PML4エントリの設定
        EARLY_PML4.entries[0] = PageTableEntry::new()
            .with_address(&EARLY_PDPT[0] as *const _ as u64)
            .with_present(true)
            .with_writable(true);
        
        // 1GBページでリニアマッピング
        // 最大4TB（4 PDPT * 512 entries * 1GB）をマッピング可能
        for (pdpt_idx, pdpt) in EARLY_PDPT.iter_mut().enumerate() {
            for entry_idx in 0..512 {
                let phys_addr = ((pdpt_idx * 512) + entry_idx) as u64 * (1 << 30); // 1GB
                if phys_addr < total_memory {
                    pdpt.entries[entry_idx] = PageTableEntry::new()
                        .with_address(phys_addr)
                        .with_present(true)
                        .with_writable(true)
                        .with_huge_page(true); // 1GBページフラグ
                }
            }
        }
        
        // CR3レジスタに新しいページテーブルを設定
        let pml4_addr = &EARLY_PML4 as *const _ as u64;
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pml4_addr,
            options(nostack, preserves_flags)
        );
    }
}

// 以下はプレースホルダー
pub struct MemoryMap;
impl MemoryMap {
    fn total_usable_memory(&self) -> u64 { 0 }
}

#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; 512],
}

impl PageTable {
    const fn empty() -> Self {
        Self { entries: [PageTableEntry(0); 512] }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    const fn new() -> Self { Self(0) }
    fn with_address(self, addr: u64) -> Self { Self(self.0 | (addr & 0x000F_FFFF_FFFF_F000)) }
    fn with_present(self, v: bool) -> Self { Self(self.0 | (v as u64)) }
    fn with_writable(self, v: bool) -> Self { Self(self.0 | ((v as u64) << 1)) }
    fn with_huge_page(self, v: bool) -> Self { Self(self.0 | ((v as u64) << 7)) }
}
