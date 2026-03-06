use super::*;

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
            topology: NumaTopology::new(),
        }
    }

    pub(super) fn cpu_ids_for_node(&self, node_idx: usize) -> Vec<usize> {
        let mut ids = Vec::new();
        if node_idx < MAX_NUMA_NODES {
            let mask = self.topology.nodes[node_idx].cpu_mask;
            for cpu_id in 0..crate::per_cpu::MAX_CPUS {
                if (mask & (1u64 << cpu_id)) != 0 {
                    ids.push(cpu_id);
                }
            }
        }
        if ids.is_empty() {
            for cpu_id in 0..crate::per_cpu::MAX_CPUS {
                ids.push(cpu_id);
            }
        }
        ids
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

        if let Some(mut pmm) = build_pmm_from_regions(&node_regions) {
            let cpu_ids = self.cpu_ids_for_node(node_idx);
            pmm.configure_arenas_for_cpu_ids(&cpu_ids);
            pmm.enable_single_writer();
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

    pub(super) fn allocate_4k_local(&self, current_cpu: u8) -> Option<PhysFrame<Size4KiB>> {
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

    pub(super) fn allocate_2m_local(&self, current_cpu: u8) -> Option<PhysFrame<Size2MiB>> {
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

    pub(super) fn allocate_1g_local(&self, current_cpu: u8) -> Option<PhysFrame<Size1GiB>> {
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

    pub(super) fn alloc_contiguous_on_node(
        &self,
        node: NumaNodeId,
        frames: usize,
    ) -> Option<PhysAddr> {
        let idx = node.as_usize();
        self.node_allocators
            .get(idx)?
            .as_ref()?
            .alloc_contiguous(frames)
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

    pub(super) fn alloc_contiguous_local(
        &self,
        current_cpu: u8,
        frames: usize,
    ) -> Option<PhysAddr> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(addr) = self.alloc_contiguous_on_node(node, frames) {
                return Some(addr);
            }
        }

        None
    }

    pub(super) fn alloc_contiguous_local_aligned(
        &self,
        current_cpu: u8,
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

    pub(super) fn allocator_for_cpu(&self, cpu_id: u8) -> Option<&PmmAllocatorFast> {
        let node = self.topology.cpu_to_node(cpu_id);
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()
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
pub(crate) static NUMA_FRAME_ALLOCATOR: IrqPoisonLock<NumaFrameAllocator> =
    IrqPoisonLock::new(NumaFrameAllocator::new());

/// PMM fast allocator (global)
pub(crate) static PMM_GLOBAL_PTR: AtomicPtr<PmmAllocatorFast> = AtomicPtr::new(ptr::null_mut());

/// PMM fast allocator (NUMA-aware)
pub(crate) static PMM_NUMA_PTR: AtomicPtr<NumaPmmAllocator> = AtomicPtr::new(ptr::null_mut());
pub(crate) static PMM_LAST_SYNC_TICK: AtomicU64 = AtomicU64::new(0);

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

pub(crate) unsafe fn pmm_global_mut() -> Option<&'static mut PmmAllocatorFast> {
    let ptr = PMM_GLOBAL_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_mut() }
}

pub(crate) unsafe fn pmm_numa_mut() -> Option<&'static mut NumaPmmAllocator> {
    let ptr = PMM_NUMA_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_mut() }
}

pub(crate) fn should_sync_single_writer(tick: u64) -> bool {
    let last = PMM_LAST_SYNC_TICK.load(Ordering::Relaxed);
    if tick.saturating_sub(last) < PMM_SYNC_INTERVAL_TICKS {
        return false;
    }
    PMM_LAST_SYNC_TICK
        .compare_exchange(last, tick, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
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
        pmm.enable_single_writer();
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
pub unsafe fn init_numa_frame_allocator_from_info(numa_info: &NumaInfo) -> bool {
    let _reconfig_guard = PMM_RECONFIG_LOCK.lock().expect("lock poisoned");
    if pmm_numa().is_some() {
        return true;
    }
    if pmm_global().is_some() {
        return false;
    }

    let node_count = (numa_info.node_count as usize).min(MAX_NUMA_NODES);
    if node_count == 0 {
        return false;
    }

    let regions = collect_numa_memory_regions(numa_info, node_count);

    if regions.is_empty() {
        return false;
    }

    let mut numa = NumaPmmAllocator::new();
    for node_idx in 0..node_count {
        let node = &numa_info.nodes[node_idx];
        if node.cpu_apic_mask_high != 0 {
            log::warn!(
                "[PMM] NUMA node {} has APIC IDs >= 64; truncating CPU mask",
                node_idx
            );
        }
        numa.topology.nodes[node_idx].cpu_mask = node.cpu_apic_mask_low;
    }

    numa.init_numa(&regions);
    if node_count > numa.topology.node_count {
        numa.topology.node_count = node_count;
    }

    let boxed = Box::new(numa);
    PMM_NUMA_PTR.store(Box::into_raw(boxed), Ordering::Release);
    true
}

/// NUMAノード単位でアリーナを再構成
pub(crate) fn reconfigure_numa_node(
    numa: &mut NumaPmmAllocator,
    node_idx: usize,
    allowed: &[bool; crate::per_cpu::MAX_CPUS],
    cpu_ids: &[usize],
) {
    let node_cpu_ids = numa.cpu_ids_for_node(node_idx);
    let mut filtered = Vec::new();
    for cpu_id in node_cpu_ids {
        if cpu_id < allowed.len() && allowed[cpu_id] {
            filtered.push(cpu_id);
        }
    }
    if let Some(pmm) = numa
        .node_allocators
        .get_mut(node_idx)
        .and_then(|opt| opt.as_mut())
    {
        pmm.sync_single_writer_arenas();
        if filtered.is_empty() {
            pmm.configure_arenas_for_cpu_ids(cpu_ids);
        } else {
            pmm.configure_arenas_for_cpu_ids(&filtered);
        }
        pmm.enable_single_writer();
    }
}

/// Reconfigure PMM arena ownership for a CPU ID list.
///
/// # Safety
/// Call during early boot while no concurrent allocations are running.
pub unsafe fn pmm_reconfigure_for_cpu_ids(cpu_ids: &[usize]) {
    let _reconfig_guard = PMM_RECONFIG_LOCK.lock().expect("lock poisoned");
    let mut allowed = [false; crate::per_cpu::MAX_CPUS];
    for &cpu_id in cpu_ids {
        if cpu_id < allowed.len() {
            allowed[cpu_id] = true;
        }
    }

    if let Some(numa) = unsafe { pmm_numa_mut() } {
        let node_count = numa.node_allocators.len();
        for node_idx in 0..node_count {
            reconfigure_numa_node(numa, node_idx, &allowed, cpu_ids);
        }
        return;
    }

    if let Some(pmm) = unsafe { pmm_global_mut() } {
        pmm.sync_single_writer_arenas();
        pmm.configure_arenas_for_cpu_ids(cpu_ids);
        pmm.enable_single_writer();
    }
}

/// Reconfigure PMM arena ownership for currently online CPUs.
///
/// # Safety
/// Call during early boot while no concurrent allocations are running.
pub unsafe fn pmm_reconfigure_for_online_cpus() {
    let cpu_ids = crate::per_cpu::online_cpu_ids();
    unsafe {
        pmm_reconfigure_for_cpu_ids(&cpu_ids);
    }
}

// 簡易的な計測: ローカル優先割当の試行回数と成功回数
pub(crate) static FRAME_LOCAL_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static FRAME_LOCAL_SUCCESSES: AtomicU64 = AtomicU64::new(0);

/// 4KiB フレームを割り当て（後方互換）
/// 現在のCPUのローカルNUMAノードからの割当を優先して試みる
pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
            FRAME_LOCAL_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            if let Some(frame) = numa.allocate_4k_local(cpu_id as u8) {
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
pub fn alloc_frame_local(current_cpu: u8) -> Option<PhysFrame<Size4KiB>> {
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
        if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
            FRAME2M_LOCAL_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            if let Some(frame) = numa.allocate_2m_local(cpu_id as u8) {
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
pub fn alloc_frame_2m_local(current_cpu: u8) -> Option<PhysFrame<Size2MiB>> {
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
        if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
            if let Some(addr) =
                numa.alloc_contiguous_local_aligned(cpu_id as u8, frames_needed, align as u64)
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
