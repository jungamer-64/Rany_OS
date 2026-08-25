use alloc::alloc::{Layout, alloc_zeroed};
use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::VirtAddr;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const PAGE_FAULT_IST_INDEX: u16 = 1;
pub const SMP_IPI_IST_INDEX: u16 = 2;

const IST_STACK_SIZE: usize = 16 * 1024;

#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

pub(crate) struct CpuDescriptorTables {
    double_fault_stack: IstStack,
    page_fault_stack: IstStack,
    smp_ipi_stack: IstStack,
    tss: UnsafeCell<MaybeUninit<TaskStateSegment>>,
    gdt: UnsafeCell<MaybeUninit<GlobalDescriptorTable>>,
    selectors: UnsafeCell<MaybeUninit<Selectors>>,
}

impl CpuDescriptorTables {
    pub(crate) fn allocate() -> Option<Pin<Box<Self>>> {
        let allocation = NonNull::new(unsafe { alloc_zeroed(Layout::new::<Self>()) })?;
        let tables = Pin::from(unsafe { Box::from_raw(allocation.cast::<Self>().as_ptr()) });
        unsafe { tables.as_ref().get_ref().initialize() };
        Some(tables)
    }

    unsafe fn initialize(&self) {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            VirtAddr::new(self.double_fault_stack_end());
        tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] =
            VirtAddr::new(self.page_fault_stack_end());
        tss.interrupt_stack_table[SMP_IPI_IST_INDEX as usize] =
            VirtAddr::new(self.smp_ipi_stack_end());
        let tss_storage = unsafe { &mut *self.tss.get() };
        tss_storage.write(tss);

        let mut gdt = GlobalDescriptorTable::new();
        let tss_storage = unsafe { &*self.tss.get() };
        let tss_ref = unsafe { tss_storage.assume_init_ref() };
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        let data_selector = gdt.append(Descriptor::kernel_data_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(tss_ref));
        let gdt_storage = unsafe { &mut *self.gdt.get() };
        gdt_storage.write(gdt);
        let selector_storage = unsafe { &mut *self.selectors.get() };
        selector_storage.write(Selectors {
            code_selector,
            data_selector,
            tss_selector,
        });
    }

    /// Reconstructs descriptors that hardware may have mutated while loaded.
    ///
    /// # Safety
    ///
    /// No CPU may have this GDT loaded or retain a reference into these
    /// descriptor tables. The enclosing `CpuLocal` allocation must remain
    /// pinned for the entire operation.
    pub(crate) unsafe fn rearm_physical_generation(&self) {
        unsafe { self.initialize() };
    }

    fn double_fault_stack_end(&self) -> u64 {
        &self.double_fault_stack as *const IstStack as u64 + IST_STACK_SIZE as u64
    }

    fn page_fault_stack_end(&self) -> u64 {
        &self.page_fault_stack as *const IstStack as u64 + IST_STACK_SIZE as u64
    }

    fn smp_ipi_stack_end(&self) -> u64 {
        &self.smp_ipi_stack as *const IstStack as u64 + IST_STACK_SIZE as u64
    }

    fn gdt(&'static self) -> &'static GlobalDescriptorTable {
        let storage = unsafe { &*self.gdt.get() };
        unsafe { storage.assume_init_ref() }
    }

    fn selectors(&self) -> Selectors {
        let storage = unsafe { &*self.selectors.get() };
        unsafe { *storage.assume_init_ref() }
    }

    pub(crate) unsafe fn load(&'static self) {
        use x86_64::instructions::segmentation::{CS, DS, SS, Segment};
        use x86_64::instructions::tables::load_tss;

        self.gdt().load();
        let selectors = self.selectors();
        unsafe {
            CS::set_reg(selectors.code_selector);
            DS::set_reg(selectors.data_selector);
            SS::set_reg(selectors.data_selector);
            load_tss(selectors.tss_selector);
        }
    }

    pub(crate) fn tss_selector(&self) -> SegmentSelector {
        self.selectors().tss_selector
    }
}

static BSP_GDT_LOADED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    pub code_selector: SegmentSelector,
    pub data_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

pub fn init_gdt() {
    if BSP_GDT_LOADED.load(Ordering::Acquire) {
        return;
    }
    load_for_current_cpu().expect("bootstrap CPU-local descriptor tables are unavailable");
    BSP_GDT_LOADED.store(true, Ordering::Release);
}

pub fn load_for_current_cpu() -> Result<(), &'static str> {
    let current = crate::cpu::CurrentCpu::acquire().ok_or("current CPU is not bound")?;
    if current.id() != crate::cpu::CpuId::BOOTSTRAP && !BSP_GDT_LOADED.load(Ordering::Acquire) {
        return Err("bootstrap GDT has not been loaded");
    }
    let tables = current.descriptor_tables();
    unsafe { tables.load() };
    if current.id() == crate::cpu::CpuId::BOOTSTRAP {
        BSP_GDT_LOADED.store(true, Ordering::Release);
    }
    Ok(())
}

pub fn tss_selector() -> SegmentSelector {
    let current = crate::cpu::CurrentCpu::acquire()
        .expect("current CPU is not bound while reading the TSS selector");
    current.descriptor_tables().tss_selector()
}
