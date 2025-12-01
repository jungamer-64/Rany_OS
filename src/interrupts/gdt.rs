// ============================================================================
// src/interrupts/gdt.rs - Global Descriptor Table with TSS
// Double Fault 用の専用スタック (IST) を設定
// ============================================================================
use x86_64::structures::gdt::{GlobalDescriptorTable, Descriptor, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;
use lazy_static::lazy_static;

/// Double Fault 用の IST インデックス
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Page Fault 用の IST インデックス（オプション）
pub const PAGE_FAULT_IST_INDEX: u16 = 1;

/// IST スタックサイズ（16KiB）
const IST_STACK_SIZE: usize = 16 * 1024;

lazy_static! {
    /// Task State Segment
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        
        // Double Fault 用の専用スタック
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            // 静的に確保したスタック
            static mut DOUBLE_FAULT_STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];
            
            let stack_start = VirtAddr::from_ptr(unsafe { &raw const DOUBLE_FAULT_STACK as *const u8 });
            let stack_end = stack_start + IST_STACK_SIZE as u64;
            stack_end
        };
        
        // Page Fault 用の専用スタック（オプション）
        tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = {
            static mut PAGE_FAULT_STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];
            
            let stack_start = VirtAddr::from_ptr(unsafe { &raw const PAGE_FAULT_STACK as *const u8 });
            let stack_end = stack_start + IST_STACK_SIZE as u64;
            stack_end
        };
        
        tss
    };
    
    /// Global Descriptor Table with TSS
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        
        // Kernel Code Segment
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        // Kernel Data Segment  
        let data_selector = gdt.add_entry(Descriptor::kernel_data_segment());
        // TSS Segment
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(&TSS));
        
        (gdt, Selectors { code_selector, data_selector, tss_selector })
    };
}

/// セグメントセレクタ
#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    pub code_selector: SegmentSelector,
    pub data_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

/// GDT と TSS を初期化・ロード
pub fn init_gdt() {
    use x86_64::instructions::segmentation::{CS, DS, SS, Segment};
    use x86_64::instructions::tables::load_tss;
    
    // GDT をロード
    GDT.0.load();
    
    unsafe {
        // コードセグメントを設定
        CS::set_reg(GDT.1.code_selector);
        // データセグメントを設定
        DS::set_reg(GDT.1.data_selector);
        SS::set_reg(GDT.1.data_selector);
        // TSS をロード
        load_tss(GDT.1.tss_selector);
    }
}

/// TSS のセレクタを取得
pub fn tss_selector() -> SegmentSelector {
    GDT.1.tss_selector
}
