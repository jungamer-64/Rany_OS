// ============================================================================
// src/interrupts/gdt.rs - Per-CPU Global Descriptor Table with TSS
// Double Fault / Page Fault 用の IST を各CPUごとに分離して設定
// ============================================================================
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

/// SMP IPI（wake/TLB shootdown）用の IST インデックス
pub const SMP_IPI_IST_INDEX: u16 = 2;

/// IST スタックサイズ（16KiB）
const IST_STACK_SIZE: usize = 16 * 1024;
const MAX_GDT_CPUS: usize = crate::per_cpu::MAX_CPUS;

/// 静的アラインメントを持つ IST スタック
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

/// CPUごとの GDT/TSS/IST 一式
struct PerCpuGdtState {
    double_fault_stack: IstStack,
    page_fault_stack: IstStack,
    smp_ipi_stack: IstStack,
    tss: MaybeUninit<TaskStateSegment>,
    gdt: MaybeUninit<GlobalDescriptorTable>,
    selectors: MaybeUninit<Selectors>,
}

unsafe impl Sync for PerCpuGdtState {}

impl PerCpuGdtState {
    const fn uninit() -> Self {
        Self {
            double_fault_stack: IstStack([0; IST_STACK_SIZE]),
            page_fault_stack: IstStack([0; IST_STACK_SIZE]),
            smp_ipi_stack: IstStack([0; IST_STACK_SIZE]),
            tss: MaybeUninit::uninit(),
            gdt: MaybeUninit::uninit(),
            selectors: MaybeUninit::uninit(),
        }
    }

    unsafe fn initialize(&mut self) {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            VirtAddr::new(self.double_fault_stack_end());
        tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] =
            VirtAddr::new(self.page_fault_stack_end());
        tss.interrupt_stack_table[SMP_IPI_IST_INDEX as usize] =
            VirtAddr::new(self.smp_ipi_stack_end());
        self.tss.write(tss);

        let mut gdt = GlobalDescriptorTable::new();
        let tss_ref = &*self.tss.as_ptr();
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        let data_selector = gdt.append(Descriptor::kernel_data_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(tss_ref));
        self.gdt.write(gdt);
        self.selectors.write(Selectors {
            code_selector,
            data_selector,
            tss_selector,
        });
    }

    #[inline]
    fn double_fault_stack_end(&self) -> u64 {
        &self.double_fault_stack as *const IstStack as u64 + IST_STACK_SIZE as u64
    }

    #[inline]
    fn page_fault_stack_end(&self) -> u64 {
        &self.page_fault_stack as *const IstStack as u64 + IST_STACK_SIZE as u64
    }

    #[inline]
    fn smp_ipi_stack_end(&self) -> u64 {
        &self.smp_ipi_stack as *const IstStack as u64 + IST_STACK_SIZE as u64
    }

    #[inline]
    fn gdt(&'static self) -> &'static GlobalDescriptorTable {
        unsafe { &*self.gdt.as_ptr() }
    }

    #[inline]
    fn selectors(&self) -> Selectors {
        unsafe { *self.selectors.as_ptr() }
    }
}

struct GdtStateSlot {
    state: UnsafeCell<MaybeUninit<PerCpuGdtState>>,
    initialized: AtomicBool,
}

unsafe impl Sync for GdtStateSlot {}

impl GdtStateSlot {
    const fn new() -> Self {
        Self {
            state: UnsafeCell::new(MaybeUninit::uninit()),
            initialized: AtomicBool::new(false),
        }
    }

    unsafe fn get_or_init(&self) -> &'static PerCpuGdtState {
        if !self.initialized.load(Ordering::Acquire) {
            let state_ptr = (*self.state.get()).as_mut_ptr();
            // Avoid constructing a ~48KiB temporary on the current CPU's boot
            // stack. The slot lives in zeroed static storage already, so we can
            // initialize the TSS/GDT metadata in place and keep the IST stacks
            // resident in .bss.
            (*state_ptr).initialize();
            self.initialized.store(true, Ordering::Release);
        }

        &*(*self.state.get()).as_ptr()
    }
}

static GDT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PER_CPU_GDT_STATES: [GdtStateSlot; MAX_GDT_CPUS] = {
    const UNINIT: GdtStateSlot = GdtStateSlot::new();
    [UNINIT; MAX_GDT_CPUS]
};

#[inline]
fn smp_gdt_mark(marker: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") marker,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// セグメントセレクタ
#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    pub code_selector: SegmentSelector,
    pub data_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

fn ensure_cpu_state(cpu_id: usize) -> Result<&'static PerCpuGdtState, &'static str> {
    if cpu_id >= MAX_GDT_CPUS {
        return Err("CPU ID out of range for GDT/TSS");
    }

    unsafe { Ok(PER_CPU_GDT_STATES[cpu_id].get_or_init()) }
}

/// GDT/TSS を BSP に初期ロードする
pub fn init_gdt() {
    if GDT_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    load_for_cpu(0).expect("failed to initialize BSP GDT/TSS");
}

unsafe fn load_current_gdt(gdt: &'static GlobalDescriptorTable, selectors: Selectors) {
    use x86_64::instructions::segmentation::{CS, DS, SS, Segment};
    use x86_64::instructions::tables::load_tss;

    smp_gdt_mark(b'1');
    gdt.load();
    smp_gdt_mark(b'2');
    unsafe {
        CS::set_reg(selectors.code_selector);
        smp_gdt_mark(b'3');
        DS::set_reg(selectors.data_selector);
        SS::set_reg(selectors.data_selector);
        smp_gdt_mark(b'4');
        load_tss(selectors.tss_selector);
        smp_gdt_mark(b'5');
    }
}

pub fn load_for_cpu(cpu_id: usize) -> Result<(), &'static str> {
    smp_gdt_mark(b'a');
    if cpu_id != 0 && !GDT_INITIALIZED.load(Ordering::SeqCst) {
        return Err("GDT not initialized");
    }
    smp_gdt_mark(b'b');

    let state = ensure_cpu_state(cpu_id)?;
    smp_gdt_mark(b'c');
    unsafe {
        load_current_gdt(state.gdt(), state.selectors());
    }
    smp_gdt_mark(b'd');
    GDT_INITIALIZED.store(true, Ordering::SeqCst);
    smp_gdt_mark(b'e');

    Ok(())
}

pub fn load_for_current_cpu() -> Result<(), &'static str> {
    let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
    load_for_cpu(cpu_id)
}

/// 現在CPUの TSS セレクタを取得
pub fn tss_selector() -> SegmentSelector {
    if !GDT_INITIALIZED.load(Ordering::SeqCst) {
        panic!("GDT not initialized");
    }

    let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
    let state = ensure_cpu_state(cpu_id).expect("missing CPU-local GDT state");
    state.selectors().tss_selector
}
