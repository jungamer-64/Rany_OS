use alloc::collections::VecDeque;
use core::array;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::sync::IrqPoisonLock;

#[derive(Debug)]
pub struct RcuCallbackEntry;

#[derive(Debug)]
pub struct PerCpuFrameCache;

impl PerCpuFrameCache {
    pub const fn new(_cpu_id: usize) -> Self {
        Self
    }
}

#[derive(Clone, Copy, Default)]
pub struct DomainCacheEntry {
    pub device_id: u16,
    pub domain_id: u16,
    pub controller_idx: u8,
    pub valid: bool,
}

pub struct PerCpuDomainCache {
    pub entries: [DomainCacheEntry; Self::CACHE_SIZE],
}

impl PerCpuDomainCache {
    pub const CACHE_SIZE: usize = 64;

    pub fn new() -> Self {
        Self {
            entries: [DomainCacheEntry {
                device_id: 0,
                domain_id: 0,
                controller_idx: 0,
                valid: false,
            }; Self::CACHE_SIZE],
        }
    }

    pub fn lookup(&self, device_id: u16) -> Option<(u16, u8)> {
        let idx = (device_id as usize) % Self::CACHE_SIZE;
        let entry = self.entries[idx];
        if entry.valid && entry.device_id == device_id {
            Some((entry.domain_id, entry.controller_idx))
        } else {
            None
        }
    }

    pub fn insert(&mut self, device_id: u16, domain_id: u16, controller_idx: u8) {
        let idx = (device_id as usize) % Self::CACHE_SIZE;
        self.entries[idx] = DomainCacheEntry {
            device_id,
            domain_id,
            controller_idx,
            valid: true,
        };
    }

    pub fn invalidate(&mut self, device_id: u16) {
        let idx = (device_id as usize) % Self::CACHE_SIZE;
        if self.entries[idx].device_id == device_id {
            self.entries[idx].valid = false;
        }
    }
}

pub const IOVA_MAG_CAPACITY: usize = 256;
pub const MAX_IOMMU_CONTROLLERS: usize = 8;

use crate::mm::cache::magazine::Magazine;
pub type IovaMagazine = Magazine<u64, IOVA_MAG_CAPACITY>;

pub const PT_MAG_CAPACITY: usize = 8;

#[derive(Clone, Copy)]
pub struct PtMagEntry {
    pub phys: u64,
    pub virt: usize,
    pub node: u8,
}

impl PtMagEntry {
    pub const fn empty() -> Self {
        Self {
            phys: 0,
            virt: 0,
            node: 0,
        }
    }
    pub const fn is_valid(&self) -> bool {
        self.phys != 0
    }
}

pub struct PtMagazine {
    entries: [PtMagEntry; PT_MAG_CAPACITY],
    len: usize,
    preferred_node: u8,
}

impl PtMagazine {
    pub fn new() -> Self {
        Self {
            entries: [PtMagEntry::empty(); PT_MAG_CAPACITY],
            len: 0,
            preferred_node: 0,
        }
    }

    pub fn pop(&mut self) -> Option<PtMagEntry> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            let entry = self.entries[self.len];
            self.entries[self.len] = PtMagEntry::empty();
            Some(entry)
        }
    }

    pub fn push(&mut self, entry: PtMagEntry) -> bool {
        if self.len >= PT_MAG_CAPACITY {
            false
        } else {
            self.entries[self.len] = entry;
            self.len += 1;
            true
        }
    }

    pub fn available(&self) -> usize {
        PT_MAG_CAPACITY - self.len
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn set_preferred_node(&mut self, node: u8) {
        self.preferred_node = node;
    }

    pub fn preferred_node(&self) -> u8 {
        self.preferred_node
    }
}

#[repr(C, align(64))]
pub struct PerCpuHot {
    pub self_ptr: usize,
    pub cpu_id: usize,
    pub interrupt_depth: AtomicU32,
    pub preempt_disable_count: AtomicU32,
    pub in_page_fault: AtomicBool,
    pub current_task_ptr: AtomicU64,
    pub current_task_id: AtomicU64,
    cold: Option<NonNull<PerCpuCold>>,
}

impl PerCpuHot {
    pub fn new(cpu_id: usize) -> Self {
        Self {
            self_ptr: 0,
            cpu_id,
            interrupt_depth: AtomicU32::new(0),
            preempt_disable_count: AtomicU32::new(0),
            in_page_fault: AtomicBool::new(false),
            current_task_ptr: AtomicU64::new(0),
            current_task_id: AtomicU64::new(0),
            cold: None,
        }
    }

    pub fn set_cold(&mut self, cold_ptr: *mut PerCpuCold) {
        self.cold = NonNull::new(cold_ptr);
    }

    pub fn cold(&self) -> &PerCpuCold {
        self.cold_opt().expect("PerCpuHot.cold not initialized")
    }

    pub fn cold_opt(&self) -> Option<&PerCpuCold> {
        self.cold.map(|ptr| unsafe { ptr.as_ref() })
    }

    pub fn current_task_ptr(&self) -> u64 {
        self.current_task_ptr.load(Ordering::Acquire)
    }

    pub fn current_task_id(&self) -> u64 {
        self.current_task_id.load(Ordering::Acquire)
    }

    pub fn set_current_task(&self, task_ptr: u64, task_id: u64) {
        self.current_task_ptr.store(task_ptr, Ordering::Release);
        self.current_task_id.store(task_id, Ordering::Release);
    }

    pub fn clear_current_task(&self) {
        self.set_current_task(0, 0);
    }

    pub fn enter_page_fault(&self) -> bool {
        self.in_page_fault.swap(true, Ordering::SeqCst)
    }

    pub fn exit_page_fault(&self) {
        self.in_page_fault.store(false, Ordering::SeqCst);
    }

    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth.load(Ordering::Relaxed) > 0
    }

    pub fn preempt_disable(&self) {
        self.preempt_disable_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn preempt_enable(&self) {
        let _ = self.preempt_disable_count.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct PerCpuRcuState {
    pub qs_count: AtomicUsize,
    pub last_gp: AtomicUsize,
    pub read_depth: AtomicUsize,
    pub batch_queue: IrqPoisonLock<VecDeque<RcuCallbackEntry>>,
}

impl PerCpuRcuState {
    pub const fn new() -> Self {
        Self {
            qs_count: AtomicUsize::new(0),
            last_gp: AtomicUsize::new(0),
            read_depth: AtomicUsize::new(0),
            batch_queue: IrqPoisonLock::new(VecDeque::new()),
        }
    }
}

pub struct PerCpuCold {
    pub alloc_count: u64,
    pub dealloc_count: u64,
    pub iommu_domain_cache: PerCpuDomainCache,
    pub iova_magazines: [IovaMagazine; MAX_IOMMU_CONTROLLERS],
    pub pt_magazine: PtMagazine,
    pub numa_zonelist: [crate::mm::types::NumaNodeId; crate::mm::numa::topology::MAX_NUMA_NODES],
    pub numa_zonelist_len: u8,
    pub local_numa_node: crate::mm::types::NumaNodeId,
    pub rcu_state: PerCpuRcuState,
    pub frame_cache: IrqPoisonLock<PerCpuFrameCache>,
}

impl PerCpuCold {
    pub fn new(cpu_id: usize) -> Self {
        Self {
            alloc_count: 0,
            dealloc_count: 0,
            iommu_domain_cache: PerCpuDomainCache::new(),
            iova_magazines: array::from_fn(|_| IovaMagazine::new()),
            pt_magazine: PtMagazine::new(),
            numa_zonelist: [crate::mm::types::NumaNodeId::new(0);
                crate::mm::numa::topology::MAX_NUMA_NODES],
            numa_zonelist_len: 1,
            local_numa_node: crate::mm::types::NumaNodeId::new(0),
            rcu_state: PerCpuRcuState::new(),
            frame_cache: IrqPoisonLock::new(PerCpuFrameCache::new(cpu_id)),
        }
    }

    pub fn setup_numa_zonelist(
        &mut self,
        local_node: crate::mm::types::NumaNodeId,
        sorted_nodes: &[crate::mm::types::NumaNodeId; crate::mm::numa::topology::MAX_NUMA_NODES],
        node_count: usize,
    ) {
        self.local_numa_node = local_node;
        self.numa_zonelist_len =
            (node_count as u8).min(crate::mm::numa::topology::MAX_NUMA_NODES as u8);
        for i in 0..self.numa_zonelist_len as usize {
            self.numa_zonelist[i] = sorted_nodes[i];
        }
    }

    pub fn get_local_numa_node(&self) -> crate::mm::types::NumaNodeId {
        self.local_numa_node
    }

    pub fn zonelist_iter(&self) -> impl Iterator<Item = crate::mm::types::NumaNodeId> + '_ {
        self.numa_zonelist[..self.numa_zonelist_len as usize]
            .iter()
            .copied()
    }

    pub fn get_zonelist_node(&self, index: usize) -> Option<crate::mm::types::NumaNodeId> {
        if index < self.numa_zonelist_len as usize {
            Some(self.numa_zonelist[index])
        } else {
            None
        }
    }
}

pub fn try_current_cpu_id() -> Option<usize> {
    Some(0)
}

pub fn current_cpu_id() -> usize {
    0
}

pub fn in_interrupt_context() -> bool {
    false
}

pub const MAX_CPUS: usize = 8;

use alloc::boxed::Box;

static PER_CPU_INIT: AtomicBool = AtomicBool::new(false);
static mut PER_CPU_HOT_PTR: *mut PerCpuHot = core::ptr::null_mut();
static mut PER_CPU_COLD_PTR: *mut PerCpuCold = core::ptr::null_mut();

fn ensure_test_per_cpu() {
    unsafe {
        if !PER_CPU_INIT.load(Ordering::SeqCst) {
            let mut hot = Box::new(PerCpuHot::new(0));
            let cold = Box::new(PerCpuCold::new(0));
            let cold_ptr = Box::into_raw(cold);
            hot.set_cold(cold_ptr);
            hot.self_ptr = hot.as_ref() as *const _ as usize;
            PER_CPU_HOT_PTR = Box::into_raw(hot);
            PER_CPU_COLD_PTR = cold_ptr;
            PER_CPU_INIT.store(true, Ordering::SeqCst);
        }
    }
}

pub fn hot_for_cpu(cpu_id: usize) -> Option<&'static PerCpuHot> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    ensure_test_per_cpu();
    unsafe { PER_CPU_HOT_PTR.as_ref() }
}

pub fn cold_for_cpu(cpu_id: usize) -> Option<&'static PerCpuCold> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    ensure_test_per_cpu();
    unsafe { PER_CPU_COLD_PTR.as_ref() }
}

pub fn with_cpu_hot<R>(cpu_id: usize, f: impl FnOnce(&PerCpuHot) -> R) -> Option<R> {
    hot_for_cpu(cpu_id).map(f)
}

pub fn with_cpu_cold<R>(cpu_id: usize, f: impl FnOnce(&PerCpuCold) -> R) -> Option<R> {
    cold_for_cpu(cpu_id).map(f)
}

pub fn current_hot() -> Option<&'static PerCpuHot> {
    hot_for_cpu(0)
}

pub fn current_cold() -> Option<&'static PerCpuCold> {
    cold_for_cpu(0)
}

pub fn with_current_hot<R>(f: impl FnOnce(&PerCpuHot) -> R) -> Option<R> {
    with_cpu_hot(0, f)
}

pub fn with_current_cold<R>(f: impl FnOnce(&PerCpuCold) -> R) -> Option<R> {
    with_cpu_cold(0, f)
}

pub fn with_current_hot_mut<R>(f: impl FnOnce(&mut PerCpuHot) -> R) -> Option<R> {
    ensure_test_per_cpu();
    unsafe { PER_CPU_HOT_PTR.as_mut().map(f) }
}

pub fn with_current_cold_mut<R>(f: impl FnOnce(&mut PerCpuCold) -> R) -> Option<R> {
    ensure_test_per_cpu();
    unsafe { PER_CPU_COLD_PTR.as_mut().map(f) }
}

pub fn is_cpu_online(cpu_id: usize) -> bool {
    cpu_id == 0
}

pub unsafe fn current_per_cpu_hot() -> Option<&'static PerCpuHot> {
    current_hot()
}
