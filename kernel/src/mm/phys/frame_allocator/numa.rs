use super::*;
use alloc::collections::{BTreeMap, BTreeSet};

/// NUMA統計情報
mod contiguous;
pub use contiguous::*;
#[derive(Debug, Clone)]
pub struct NumaAllocatorStats {
    /// 各ノードの(空きフレーム数, 総フレーム数)
    pub per_node: [(u64, usize); MAX_NUMA_NODES],
    /// 全ノード合計の空きフレーム数
    pub total_free: u64,
    /// 全ノード合計の総フレーム数
    pub total_frames: usize,
}

/// NUMA対応PMMアロケータ（fast bitmap版）
pub(crate) struct NumaPmmAllocator {
    node_allocators: Vec<Option<PmmAllocatorFast>>,
    topology: NumaTopology,
}

impl NumaPmmAllocator {
    pub(super) fn new() -> Self {
        let mut node_allocators = Vec::with_capacity(MAX_NUMA_NODES);
        for _ in 0..MAX_NUMA_NODES {
            node_allocators.push(None);
        }
        Self {
            node_allocators,
            topology: NumaTopology::new(1),
        }
    }

    pub(super) fn cpu_set_for_node(&self, node_idx: usize) -> crate::cpu::CpuSet {
        let mut cpus = self
            .topology
            .nodes
            .get(node_idx)
            .map(|node| node.cpus.clone())
            .unwrap_or_else(|| {
                crate::cpu::CpuSet::new(1).expect("bootstrap CPU set capacity is valid")
            });
        if cpus.is_empty() {
            cpus.insert(crate::cpu::CpuId::BOOTSTRAP)
                .expect("bootstrap CPU fits the initial NUMA topology");
        }
        cpus
    }

    pub(super) fn init_numa_node(
        &mut self,
        node_idx: usize,
        usable_regions: &[(PhysAddr, u64, NumaNodeId)],
    ) -> bool {
        let node_id = NumaNodeId::new(node_idx as u8);
        let node_regions: Vec<(PhysAddr, u64)> = usable_regions
            .iter()
            .filter(|&&(_, size, region_node)| region_node == node_id && size > 0)
            .map(|&(addr, size, _)| (addr, size))
            .collect();

        if node_regions.is_empty() {
            return false;
        }

        if let Some(pmm) = build_pmm_from_regions(&node_regions) {
            let cpu_ids = self.cpu_set_for_node(node_idx);
            if let Err(error) = pmm.provision_cpu_set(&cpu_ids) {
                log::warn!(
                    "[PMM] NUMA node {} could not provision CPU-local cache slots: {:?}",
                    node_idx,
                    error
                );
            }
            self.node_allocators[node_idx] = Some(pmm);
        }

        for (addr, size) in node_regions {
            self.topology.nodes[node_idx].add_memory_range(addr.as_u64(), size);
        }

        true
    }

    pub(super) fn init_numa(&mut self, usable_regions: &[(PhysAddr, u64, NumaNodeId)]) {
        let mut max_node = 0usize;

        for node_idx in 0..MAX_NUMA_NODES {
            if self.init_numa_node(node_idx, usable_regions) {
                max_node = max_node.max(node_idx + 1);
            }
        }

        if max_node > 0 {
            self.topology.node_count = max_node;
        }
    }

    pub(super) fn allocate_4k_on_node(&self, node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()?.alloc_4k()
    }

    pub(super) fn allocate_4k_local(
        &self,
        current_cpu: crate::cpu::CpuId,
    ) -> Option<PhysFrame<Size4KiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_4k_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    pub(super) fn allocate_2m_on_node(&self, node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()?.alloc_2m()
    }

    pub(super) fn allocate_2m_local(
        &self,
        current_cpu: crate::cpu::CpuId,
    ) -> Option<PhysFrame<Size2MiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_2m_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    pub(super) fn allocate_1g_on_node(&self, node: NumaNodeId) -> Option<PhysFrame<Size1GiB>> {
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()?.alloc_1g()
    }

    pub(super) fn allocate_1g_local(
        &self,
        current_cpu: crate::cpu::CpuId,
    ) -> Option<PhysFrame<Size1GiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_1g_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    pub(super) fn alloc_contiguous_on_node_aligned(
        &self,
        node: NumaNodeId,
        frames: usize,
        align_bytes: u64,
    ) -> Option<PhysAddr> {
        let idx = node.as_usize();
        self.node_allocators
            .get(idx)?
            .as_ref()?
            .alloc_contiguous_aligned(frames, align_bytes)
    }

    pub(super) fn alloc_contiguous_local_aligned(
        &self,
        current_cpu: crate::cpu::CpuId,
        frames: usize,
        align_bytes: u64,
    ) -> Option<PhysAddr> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(addr) = self.alloc_contiguous_on_node_aligned(node, frames, align_bytes) {
                return Some(addr);
            }
        }

        None
    }

    pub(super) fn deallocate_4k_frame(&self, frame: PhysFrame<Size4KiB>) {
        let addr = frame.start_address().as_u64();
        let node = self.topology.addr_to_node(addr);
        let idx = node.as_usize();
        if let Some(Some(pmm)) = self.node_allocators.get(idx) {
            pmm.free_4k(frame);
        }
    }

    pub(super) fn deallocate_2m_frame(&self, frame: PhysFrame<Size2MiB>) {
        let addr = frame.start_address().as_u64();
        let node = self.topology.addr_to_node(addr);
        let idx = node.as_usize();
        if let Some(Some(pmm)) = self.node_allocators.get(idx) {
            pmm.free_2m(frame);
        }
    }

    pub(super) fn deallocate_1g_frame(&self, frame: PhysFrame<Size1GiB>) {
        let addr = frame.start_address().as_u64();
        let node = self.topology.addr_to_node(addr);
        let idx = node.as_usize();
        if let Some(Some(pmm)) = self.node_allocators.get(idx) {
            pmm.free_1g(frame);
        }
    }

    pub(super) fn stats(&self) -> NumaAllocatorStats {
        let mut stats = NumaAllocatorStats {
            per_node: [(0, 0); MAX_NUMA_NODES],
            total_free: 0,
            total_frames: 0,
        };

        for (i, allocator) in self.node_allocators.iter().enumerate() {
            if let Some(pmm) = allocator.as_ref() {
                let (free, total) = pmm.stats();
                stats.per_node[i] = (free, total);
                stats.total_free += free;
                stats.total_frames += total;
            }
        }

        stats
    }

    pub(super) fn topology(&self) -> &NumaTopology {
        &self.topology
    }

    pub(super) fn quiesce_current_cpu(&self) -> crate::mm::phys::fast_allocator::CpuMagazineDrain {
        let mut drained = crate::mm::phys::fast_allocator::CpuMagazineDrain::default();
        for allocator in self.node_allocators.iter().flatten() {
            drained.merge(allocator.quiesce_current_cpu());
        }
        drained
    }
}

// ============================================================================
// グローバルアロケータ（後方互換性維持）
// ============================================================================

/// グローバルなフレームアロケータ（NUMA非対応版、後方互換用）
/// 割り込み禁止PoisonLockで保護
pub(crate) static FRAME_ALLOCATOR: IrqPoisonLock<BitmapFrameAllocator> =
    IrqPoisonLock::new(BitmapFrameAllocator::new());

/// NUMA対応グローバルフレームアロケータ
/// 設計書 5.3: NUMAアーキテクチャへの対応
static NUMA_FRAME_ALLOCATOR: spin::Once<IrqPoisonLock<NumaFrameAllocator>> = spin::Once::new();

pub(crate) fn legacy_numa_frame_allocator() -> &'static IrqPoisonLock<NumaFrameAllocator> {
    NUMA_FRAME_ALLOCATOR.call_once(|| IrqPoisonLock::new(NumaFrameAllocator::new()))
}

/// PMM fast allocator (global)
pub(crate) static PMM_GLOBAL_PTR: AtomicPtr<PmmAllocatorFast> = AtomicPtr::new(ptr::null_mut());

/// PMM fast allocator (NUMA-aware)
pub(crate) static PMM_NUMA_PTR: AtomicPtr<NumaPmmAllocator> = AtomicPtr::new(ptr::null_mut());
/// PMM reconfiguration lock (prevents race during arena/topology updates)
pub(crate) static PMM_RECONFIG_LOCK: IrqPoisonLock<()> = IrqPoisonLock::new(());

pub(crate) fn pmm_global() -> Option<&'static PmmAllocatorFast> {
    let ptr = PMM_GLOBAL_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_ref() }
}

pub(crate) fn pmm_numa() -> Option<&'static NumaPmmAllocator> {
    let ptr = PMM_NUMA_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_ref() }
}

pub(crate) unsafe fn pmm_numa_mut() -> Option<&'static mut NumaPmmAllocator> {
    let ptr = PMM_NUMA_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_mut() }
}

/// フレームアロケータを初期化（後方互換）
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_frame_allocator(usable_regions: &[(PhysAddr, u64)]) {
    let _reconfig_guard = PMM_RECONFIG_LOCK.lock().expect("lock poisoned");
    if pmm_global().is_some() || pmm_numa().is_some() {
        return;
    }

    if let Some(pmm) = build_pmm_from_regions(usable_regions) {
        let boxed = Box::new(pmm);
        PMM_GLOBAL_PTR.store(Box::into_raw(boxed), Ordering::Release);
        return;
    }

    // Fallback to legacy bitmap allocator
    unsafe {
        FRAME_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .init(usable_regions);
    }
}

/// NUMA対応フレームアロケータを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
/// ACPI SRATから取得したNUMA情報を渡す
pub unsafe fn init_numa_frame_allocator(regions: &[(PhysAddr, u64, NumaNodeId)]) {
    let _reconfig_guard = PMM_RECONFIG_LOCK.lock().expect("lock poisoned");
    if pmm_numa().is_some() || pmm_global().is_some() {
        return;
    }

    let mut numa = NumaPmmAllocator::new();
    numa.init_numa(regions);
    let boxed = Box::new(numa);
    PMM_NUMA_PTR.store(Box::into_raw(boxed), Ordering::Release);
}

/// NUMA情報（ブートローダー由来）からフレームアロケータを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
#[derive(Debug)]
pub enum FirmwareNumaError {
    Acpi(acpi_driver::AcpiError),
    TooManyNodes { discovered: usize, supported: usize },
    AddressOverflow,
}

impl From<acpi_driver::AcpiError> for FirmwareNumaError {
    fn from(error: acpi_driver::AcpiError) -> Self {
        Self::Acpi(error)
    }
}

/// Initializes the NUMA PMM directly from the kernel-owned SRAT catalog.
///
/// CPU affinity is attached after MADT discovery; at this early phase the BSP
/// is the only allocator arena owner. Memory ranges are intersected with the
/// bootloader's authoritative usable-memory set before publication.
///
/// # Errors
///
/// Returns an error for malformed SRAT data, overflowing address ranges, or a
/// firmware node count that exceeds the allocator's supported topology.
pub fn init_numa_frame_allocator_from_firmware(
    catalog: &acpi_driver::TableCatalog,
    usable_regions: &[(PhysAddr, u64)],
) -> Result<bool, FirmwareNumaError> {
    let _reconfig_guard = PMM_RECONFIG_LOCK.lock().expect("lock poisoned");
    if pmm_numa().is_some() {
        return Ok(true);
    }
    if pmm_global().is_some() {
        return Ok(false);
    }

    let affinities = catalog.numa_memory_affinity()?;
    let enabled = affinities
        .iter()
        .filter(|affinity| affinity.enabled && affinity.length != 0)
        .collect::<Vec<_>>();
    if enabled.is_empty() {
        return Ok(false);
    }

    let domains = enabled
        .iter()
        .map(|affinity| affinity.proximity_domain)
        .collect::<BTreeSet<_>>();
    if domains.len() > MAX_NUMA_NODES {
        return Err(FirmwareNumaError::TooManyNodes {
            discovered: domains.len(),
            supported: MAX_NUMA_NODES,
        });
    }
    let domain_to_node = domains
        .into_iter()
        .enumerate()
        .map(|(index, domain)| (domain, NumaNodeId::new(index as u8)))
        .collect::<BTreeMap<_, _>>();

    let mut regions = Vec::new();
    for affinity in enabled {
        let affinity_end = affinity
            .base
            .checked_add(affinity.length)
            .ok_or(FirmwareNumaError::AddressOverflow)?;
        let node = domain_to_node[&affinity.proximity_domain];
        for &(usable_start, usable_length) in usable_regions {
            let usable_base = usable_start.as_u64();
            let usable_end = usable_base
                .checked_add(usable_length)
                .ok_or(FirmwareNumaError::AddressOverflow)?;
            let start = affinity.base.max(usable_base);
            let end = affinity_end.min(usable_end);
            if start < end {
                regions.push((PhysAddr::new(start), end - start, node));
            }
        }
    }

    if regions.is_empty() {
        return Ok(false);
    }

    let mut numa = NumaPmmAllocator::new();
    numa.init_numa(&regions);
    if domain_to_node.len() > numa.topology.node_count {
        numa.topology.node_count = domain_to_node.len();
    }

    let boxed = Box::new(numa);
    PMM_NUMA_PTR.store(Box::into_raw(boxed), Ordering::Release);
    Ok(true)
}

/// NUMAノード単位で CPU-local cache slot を準備する。
pub(crate) fn provision_numa_node_cpu_caches(
    numa: &NumaPmmAllocator,
    node_idx: usize,
    possible: &crate::cpu::CpuSet,
) -> Result<(), crate::mm::phys::fast_allocator::CpuCacheProvisionError> {
    let node_cpu_ids = numa.cpu_set_for_node(node_idx);
    let mut filtered = crate::cpu::CpuSet::new(possible.capacity())
        .expect("possible CPU set capacity is already validated");
    for cpu_id in node_cpu_ids.iter().filter(|id| possible.contains(*id)) {
        filtered
            .insert(cpu_id)
            .expect("filtered CPU belongs to the possible-set capacity");
    }
    if let Some(pmm) = numa
        .node_allocators
        .get(node_idx)
        .and_then(|opt| opt.as_ref())
    {
        if filtered.is_empty() {
            pmm.provision_cpu_set(possible)?;
        } else {
            pmm.provision_cpu_set(&filtered)?;
        }
    }
    Ok(())
}

fn pmm_provision_for_possible_set(
    possible: &crate::cpu::CpuSet,
) -> Result<(), crate::mm::phys::fast_allocator::CpuCacheProvisionError> {
    let _reconfig_guard = PMM_RECONFIG_LOCK.lock().expect("lock poisoned");

    if let Some(numa) = pmm_numa() {
        let node_count = numa.node_allocators.len();
        for node_idx in 0..node_count {
            provision_numa_node_cpu_caches(numa, node_idx, possible)?;
        }
        return Ok(());
    }

    if let Some(pmm) = pmm_global() {
        pmm.provision_cpu_set(possible)?;
    }
    Ok(())
}

/// Provision stable PMM cache slots for every possible logical CPU.
pub fn pmm_provision_possible_cpus()
-> Result<(), crate::mm::phys::fast_allocator::CpuCacheProvisionError> {
    let snapshot = crate::cpu::snapshot();
    pmm_provision_for_possible_set(snapshot.possible())
}

pub(crate) fn quiesce_current_cpu_for_offline() -> crate::mm::phys::fast_allocator::CpuMagazineDrain
{
    let current = crate::cpu::CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("PMM CPU-cache quiescence requires CPU-local state"));
    assert_ne!(
        current.id(),
        crate::cpu::CpuId::BOOTSTRAP,
        "bootstrap CPU cache cannot be retired"
    );
    if let Some(numa) = pmm_numa() {
        return numa.quiesce_current_cpu();
    }
    pmm_global()
        .map(PmmAllocatorFast::quiesce_current_cpu)
        .unwrap_or_default()
}

pub(crate) fn configure_numa_cpu_affinity(
    cpu_capacity: usize,
    assignments: &[(crate::cpu::CpuId, NumaNodeId)],
) -> Result<(), crate::cpu::CpuSetError> {
    let _reconfig_guard = PMM_RECONFIG_LOCK.lock().expect("lock poisoned");
    let Some(numa) = (unsafe { pmm_numa_mut() }) else {
        return Ok(());
    };

    for node in &mut numa.topology.nodes {
        node.cpus = crate::cpu::CpuSet::new(cpu_capacity)?;
    }
    for &(cpu_id, node_id) in assignments {
        let node = numa.topology.nodes.get_mut(node_id.as_usize()).ok_or(
            crate::cpu::CpuSetError::CapacityOutOfRange {
                capacity: node_id.as_usize() + 1,
            },
        )?;
        node.cpus.insert(cpu_id)?;
    }
    Ok(())
}

// 簡易的な計測: ローカル優先割当の試行回数と成功回数
pub(crate) static FRAME_LOCAL_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static FRAME_LOCAL_SUCCESSES: AtomicU64 = AtomicU64::new(0);

/// 4KiB フレームを割り当て（後方互換）
/// 現在のCPUのローカルNUMAノードからの割当を優先して試みる
pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::cpu::CurrentCpu::acquire().map(|cpu| cpu.id()) {
            FRAME_LOCAL_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            if let Some(frame) = numa.allocate_4k_local(cpu_id) {
                FRAME_LOCAL_SUCCESSES.fetch_add(1, Ordering::Relaxed);
                return Some(frame);
            }
        }

        for node_idx in 0..numa.topology().node_count() {
            if let Some(frame) = numa.allocate_4k_on_node(NumaNodeId::new(node_idx as u8)) {
                return Some(frame);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_4k();
    }

    // Try legacy bitmap allocator and log diagnostics on failure (helpful for qemu-suite debugging)
    let res = FRAME_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_4k_frame();
    if res.is_none() {
        // Gather diagnostics (best-effort, may race with other allocs)
        let pmm_init = pmm_initialized();
        let (attempts, successes) = get_frame_local_alloc_metrics();
        let buddy_stats = crate::mm::phys::buddy_allocator::buddy_allocator_stats();
        let bitmap_free = crate::mm::phys::frame_allocator::FRAME_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .free_frame_count();
        eprintln!(
            "[alloc_frame] FAILED: pmm_initialized={} pmm_numa_exists={} pmm_global_exists={} attempts/successes={}/{}, buddy_free_frames={} total_frames={} bitmap_free_frames={}",
            pmm_init,
            crate::mm::phys::frame_allocator::pmm_numa().is_some(),
            crate::mm::phys::frame_allocator::pmm_global().is_some(),
            attempts,
            successes,
            buddy_stats.free_frames,
            buddy_stats.total_frames,
            bitmap_free
        );
    }

    res
}

/// 指定NUMAノードから4KiBフレームを割り当て
/// 設計書 5.3.2: 明示的なノード指定API
pub fn alloc_frame_on_numa_node(node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_4k_on_node(node) {
            return Some(frame);
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_4k();
    }

    FRAME_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_4k_frame()
}

/// 現在のCPUのローカルNUMAノードから4KiBフレームを割り当て
/// 設計書 5.3.2: First-Touch Policy
pub fn alloc_frame_local(current_cpu: crate::cpu::CpuId) -> Option<PhysFrame<Size4KiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_4k_local(current_cpu) {
            return Some(frame);
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_4k();
    }

    FRAME_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_4k_frame()
}

/// 計測値取得（テスト用）
pub fn get_frame_local_alloc_metrics() -> (u64, u64) {
    (
        FRAME_LOCAL_ATTEMPTS.load(Ordering::Relaxed),
        FRAME_LOCAL_SUCCESSES.load(Ordering::Relaxed),
    )
}

/// 計測値リセット（テスト用）
pub fn reset_frame_local_alloc_metrics() {
    FRAME_LOCAL_ATTEMPTS.store(0, Ordering::Relaxed);
    FRAME_LOCAL_SUCCESSES.store(0, Ordering::Relaxed);
}

pub(crate) static FRAME2M_LOCAL_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static FRAME2M_LOCAL_SUCCESSES: AtomicU64 = AtomicU64::new(0);

/// 2MiB フレームを割り当て（後方互換）
/// NUMAローカル優先で割当を試みる
pub fn alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::cpu::CurrentCpu::acquire().map(|cpu| cpu.id()) {
            FRAME2M_LOCAL_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            if let Some(frame) = numa.allocate_2m_local(cpu_id) {
                FRAME2M_LOCAL_SUCCESSES.fetch_add(1, Ordering::Relaxed);
                return Some(frame);
            }
        }

        for node_idx in 0..numa.topology().node_count() {
            if let Some(frame) = numa.allocate_2m_on_node(NumaNodeId::new(node_idx as u8)) {
                return Some(frame);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_2m();
    }

    FRAME_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_2m_frame()
}

/// 指定NUMAノードから2MiBフレームを割り当て
pub fn alloc_frame_2m_on_numa_node(node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_2m_on_node(node) {
            return Some(frame);
        }
    }
    if let Some(pmm) = pmm_global() {
        return pmm.alloc_2m();
    }
    FRAME_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_2m_frame()
}

/// 現在のCPUのローカルNUMAノードから2MiBフレームを割り当て
pub fn alloc_frame_2m_local(current_cpu: crate::cpu::CpuId) -> Option<PhysFrame<Size2MiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_2m_local(current_cpu) {
            return Some(frame);
        }
    }
    if let Some(pmm) = pmm_global() {
        return pmm.alloc_2m();
    }
    FRAME_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_2m_frame()
}

/// PMM fast が初期化済みかどうか
pub fn pmm_initialized() -> bool {
    pmm_numa().is_some() || pmm_global().is_some()
}

/// 物理アドレスが属するNUMAノードを取得（PMM fastが初期化済みの場合のみ）
pub fn numa_node_for_addr(addr: PhysAddr) -> Option<NumaNodeId> {
    pmm_numa().map(|numa| numa.topology().addr_to_node(addr.as_u64()))
}

/// 連続した (4KiB) フレームをアライン指定で割り当てるラッパー
///
/// - `frames_needed`: 割り当てたいフレーム数
/// - `align_bytes`: アラインメント（バイト）
/// - 戻り値: 割り当て開始物理アドレス (4KiB 単位)
pub fn alloc_contiguous_frames_aligned(
    frames_needed: usize,
    align_bytes: usize,
) -> Option<PhysAddr> {
    if frames_needed == 0 {
        return None;
    }

    let align = align_size_to_page(align_bytes);

    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::cpu::CurrentCpu::acquire().map(|cpu| cpu.id()) {
            if let Some(addr) =
                numa.alloc_contiguous_local_aligned(cpu_id, frames_needed, align as u64)
            {
                return Some(addr);
            }
        }
        for node_idx in 0..numa.topology().node_count() {
            if let Some(addr) = numa.alloc_contiguous_on_node_aligned(
                NumaNodeId::new(node_idx as u8),
                frames_needed,
                align as u64,
            ) {
                return Some(addr);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_contiguous_aligned(frames_needed, align as u64);
    }

    FRAME_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_contiguous(frames_needed, align)
}
