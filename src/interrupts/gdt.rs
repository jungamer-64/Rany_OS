// ============================================================================
// src/interrupts/gdt.rs - Global Descriptor Table with TSS
// Double Fault 用の専用スタック (IST) を設定
// ============================================================================
#![allow(dead_code)]
#![allow(static_mut_refs)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::VirtAddr;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

/// Double Fault 用の IST インデックス
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Page Fault 用の IST インデックス（オプション）
pub const PAGE_FAULT_IST_INDEX: u16 = 1;

/// IST スタックサイズ（16KiB）
const IST_STACK_SIZE: usize = 16 * 1024;

/// 静的に確保した Double Fault 用スタック
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

/// スタックのラッパー（Sync実装のため）
struct SyncStack(UnsafeCell<IstStack>);
unsafe impl Sync for SyncStack {}

static DOUBLE_FAULT_STACK: SyncStack = SyncStack(UnsafeCell::new(IstStack([0; IST_STACK_SIZE])));
static PAGE_FAULT_STACK: SyncStack = SyncStack(UnsafeCell::new(IstStack([0; IST_STACK_SIZE])));

/// GDT/TSS/Selectorsのコンテナ
struct GdtContainer {
    tss: UnsafeCell<MaybeUninit<TaskStateSegment>>,
    gdt: UnsafeCell<MaybeUninit<GlobalDescriptorTable>>,
    selectors: UnsafeCell<MaybeUninit<Selectors>>,
}

unsafe impl Sync for GdtContainer {}

static GDT_CONTAINER: GdtContainer = GdtContainer {
    tss: UnsafeCell::new(MaybeUninit::uninit()),
    gdt: UnsafeCell::new(MaybeUninit::uninit()),
    selectors: UnsafeCell::new(MaybeUninit::uninit()),
};

/// 初期化完了フラグ
static GDT_INITIALIZED: AtomicBool = AtomicBool::new(false);

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
    
    // 早期シリアル出力関数を使用
    fn serial_str(s: &str) {
        crate::vga::early_serial_str(s);
    }
    
    serial_str("[GDT] init\n");

    // すでに初期化済みの場合はスキップ
    if GDT_INITIALIZED.load(Ordering::SeqCst) {
        serial_str("[GDT] skip\n");
        return;
    }

    unsafe {
        serial_str("[GDT] TSS\n");
        
        // TSSポインタを取得してゼロ初期化
        let tss_ptr = (*GDT_CONTAINER.tss.get()).as_mut_ptr();
        serial_str("[GDT] zero\n");
        
        // TSSサイズは約104バイト
        // バイト単位で明示的にゼロ初期化
        let tss_bytes = tss_ptr as *mut u8;
        let tss_size = core::mem::size_of::<TaskStateSegment>();
        for i in 0..tss_size {
            core::ptr::write_volatile(tss_bytes.add(i), 0);
        }
        
        serial_str("[GDT] done\n");
        
        // Double Fault 用の専用スタック
        let df_stack_end = DOUBLE_FAULT_STACK.0.get() as u64 + IST_STACK_SIZE as u64;
        (*tss_ptr).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = VirtAddr::new(df_stack_end);
        
        // Page Fault 用の専用スタック
        let pf_stack_end = PAGE_FAULT_STACK.0.get() as u64 + IST_STACK_SIZE as u64;
        (*tss_ptr).interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = VirtAddr::new(pf_stack_end);
        
        serial_str("[GDT] GDT\n");
        
        // GDTを初期化
        let gdt_ptr = (*GDT_CONTAINER.gdt.get()).as_mut_ptr();
        serial_str("[GDT] new\n");
        
        // GDTメモリをゼロクリア
        let gdt_bytes = gdt_ptr as *mut u8;
        let gdt_size = core::mem::size_of::<GlobalDescriptorTable>();
        for i in 0..gdt_size {
            core::ptr::write_volatile(gdt_bytes.add(i), 0);
        }
        serial_str("[GDT] z\n");
        
        // 新しいGDTを作成
        core::ptr::write(gdt_ptr, GlobalDescriptorTable::new());
        
        serial_str("[GDT] entry\n");
        
        let code_selector = (*gdt_ptr).add_entry(Descriptor::kernel_code_segment());
        let data_selector = (*gdt_ptr).add_entry(Descriptor::kernel_data_segment());
        let tss_selector = (*gdt_ptr).add_entry(Descriptor::tss_segment(&*tss_ptr));
        
        // セレクタを保存
        let selectors_ptr = (*GDT_CONTAINER.selectors.get()).as_mut_ptr();
        core::ptr::write(selectors_ptr, Selectors {
            code_selector,
            data_selector,
            tss_selector,
        });
        
        serial_str("[GDT] load\n");
        
        // GDTをロード
        (*gdt_ptr).load();
        
        serial_str("[GDT] seg\n");
        
        // セグメントレジスタを設定
        CS::set_reg(code_selector);
        DS::set_reg(data_selector);
        SS::set_reg(data_selector);
        
        serial_str("[GDT] tss\n");
        
        // TSSをロード
        load_tss(tss_selector);
        
        // 初期化完了
        GDT_INITIALIZED.store(true, Ordering::SeqCst);
    }
    
    serial_str("[GDT] OK\n");
}

/// TSS のセレクタを取得
pub fn tss_selector() -> SegmentSelector {
    if !GDT_INITIALIZED.load(Ordering::SeqCst) {
        panic!("GDT not initialized");
    }
    unsafe { (*(*GDT_CONTAINER.selectors.get()).as_ptr()).tss_selector }
}
