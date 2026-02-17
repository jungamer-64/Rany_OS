use super::*;


/// 連続した (4KiB) フレームを指定NUMAノードからアライン指定で割り当てる
pub fn alloc_contiguous_frames_aligned_on_node(
    node: NumaNodeId,
    frames_needed: usize,
    align_bytes: usize,
) -> Option<PhysAddr> {
    if frames_needed == 0 {
        return None;
    }

    let align = align_size_to_page(align_bytes);

    if let Some(numa) = pmm_numa() {
        return numa.alloc_contiguous_on_node_aligned(node, frames_needed, align as u64);
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_contiguous_aligned(frames_needed, align as u64);
    }

    FRAME_ALLOCATOR
        .lock()
        .allocate_contiguous(frames_needed, align)
}

/// 連続した (4KiB) フレームを割り当てるラッパー
///
/// - `frames_needed`: 割り当てたいフレーム数
/// - 戻り値: 割り当て開始物理アドレス (4KiB 単位)
pub fn alloc_contiguous_frames(frames_needed: usize) -> Option<PhysAddr> {
    alloc_contiguous_frames_aligned(frames_needed, PAGE_SIZE_4K)
}

/// 連続領域を解放するラッパー
///
/// - `start`: 開始物理アドレス
/// - `frames`: フレーム数
pub fn dealloc_contiguous_frames(start: PhysAddr, frames: usize) {
    // Deallocate frame-by-frame (4KiB)
    for i in 0..frames {
        let addr = start.as_u64() + (i as u64) * (PAGE_SIZE_4K as u64);
        if let Ok(frame) = PhysFrame::<Size4KiB>::from_start_address(x86_64::PhysAddr::new(addr)) {
            if let Some(numa) = pmm_numa() {
                numa.deallocate_4k_frame(frame);
                continue;
            }
            if let Some(pmm) = pmm_global() {
                pmm.free_4k(frame);
                continue;
            }
            FRAME_ALLOCATOR.lock().deallocate_4k_frame(frame);
        }
    }
}

/// 2MiB 計測値取得（テスト用）
pub fn get_frame2m_local_alloc_metrics() -> (u64, u64) {
    (
        FRAME2M_LOCAL_ATTEMPTS.load(Ordering::Relaxed),
        FRAME2M_LOCAL_SUCCESSES.load(Ordering::Relaxed),
    )
}

/// 2MiB 計測値リセット（テスト用）
pub fn reset_frame2m_local_alloc_metrics() {
    FRAME2M_LOCAL_ATTEMPTS.store(0, Ordering::Relaxed);
    FRAME2M_LOCAL_SUCCESSES.store(0, Ordering::Relaxed);
}

/// 1GiB フレームを割り当て（設計書5.1: TLBエントリの消費を最小限に）
pub fn alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
            if let Some(frame) = numa.allocate_1g_local(cpu_id as u8) {
                return Some(frame);
            }
        }
        for node_idx in 0..numa.topology().node_count() {
            if let Some(frame) = numa.allocate_1g_on_node(NumaNodeId::new(node_idx as u8)) {
                return Some(frame);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_1g();
    }

    FRAME_ALLOCATOR.lock().allocate_1g_frame()
}

/// 2MiB フレームを解放
pub fn dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_2m_frame(frame);
        return;
    }
    if let Some(pmm) = pmm_global() {
        pmm.free_2m(frame);
        return;
    }
    FRAME_ALLOCATOR.lock().deallocate_2m_frame(frame);
}

/// 1GiB フレームを解放
pub fn dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_1g_frame(frame);
        return;
    }
    if let Some(pmm) = pmm_global() {
        pmm.free_1g(frame);
        return;
    }
    FRAME_ALLOCATOR.lock().deallocate_1g_frame(frame);
}

/// 4KiB フレームを解放（後方互換）
pub fn dealloc_frame(frame: PhysFrame<Size4KiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_4k_frame(frame);
        return;
    }
    if let Some(pmm) = pmm_global() {
        pmm.free_4k(frame);
        return;
    }
    FRAME_ALLOCATOR.lock().deallocate_4k_frame(frame);
}

/// NUMAアロケータでフレームを解放
pub fn dealloc_frame_numa(frame: PhysFrame<Size4KiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_4k_frame(frame);
        return;
    }
    dealloc_frame(frame);
}

/// フレームアロケータの統計を取得（後方互換）
pub fn frame_allocator_stats() -> (u64, usize) {
    if let Some(numa) = pmm_numa() {
        let stats = numa.stats();
        return (stats.total_free, stats.total_frames);
    }
    if let Some(pmm) = pmm_global() {
        return pmm.stats();
    }
    let allocator = FRAME_ALLOCATOR.lock();
    (allocator.free_frame_count(), allocator.total_frame_count())
}

/// NUMA対応統計を取得
pub fn numa_frame_allocator_stats() -> NumaAllocatorStats {
    if let Some(numa) = pmm_numa() {
        return numa.stats();
    }
    NUMA_FRAME_ALLOCATOR.lock().stats()
}

/// 現在のCPUが属するNUMAノードを取得
pub fn get_cpu_numa_node(cpu_id: u8) -> NumaNodeId {
    if let Some(numa) = pmm_numa() {
        return numa.topology().cpu_to_node(cpu_id);
    }
    NUMA_FRAME_ALLOCATOR.lock().topology().cpu_to_node(cpu_id)
}

/// Check if a range is contained within any NUMA node's memory ranges.
pub(crate) fn is_range_in_numa_topology(topo: &super::numa::NumaTopology, start: u64, end: u64) -> bool {
    for node_idx in 0..topo.node_count() {
        let node = &topo.nodes[node_idx];
        for i in 0..node.range_count {
            let (range_start, range_size) = node.memory_ranges[i];
            let range_end = range_start.saturating_add(range_size);
            if start >= range_start && end <= range_end {
                return true;
            }
        }
    }
    false
}

/// 指定範囲がPMMで管理されているか（ベストエフォート）
pub fn is_range_managed_by_pmm(start: PhysAddr, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = start.as_u64().checked_add(size) else {
        return false;
    };

    if let Some(numa) = pmm_numa() {
        return is_range_in_numa_topology(numa.topology(), start.as_u64(), end);
    }

    if let Some(pmm) = pmm_global() {
        let range_start = pmm.base;
        let range_end = pmm.base.saturating_add(pmm.size);
        return start.as_u64() >= range_start && end <= range_end;
    }

    crate::mm::buddy_allocator::is_range_managed_by_buddy(start, size)
}

/// PMMが管理する最大物理アドレス（排他的上限）を取得
pub fn pmm_managed_end() -> Option<u64> {
    if let Some(numa) = pmm_numa() {
        let topo = numa.topology();
        let mut max_end = 0u64;
        for node_idx in 0..topo.node_count() {
            let node = &topo.nodes[node_idx];
            for i in 0..node.range_count {
                let (start, size) = node.memory_ranges[i];
                max_end = max_end.max(start.saturating_add(size));
            }
        }
        return if max_end == 0 { None } else { Some(max_end) };
    }

    if let Some(pmm) = pmm_global() {
        let end = pmm.base.saturating_add(pmm.size);
        return if end == 0 { None } else { Some(end) };
    }

    None
}

/// PMM定期メンテナンス（リモートフリーの排出など）
///
/// 非ISRコンテキストから呼び出すこと。
pub fn pmm_maintenance_tick(tick: u64) {
    let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() else {
        return;
    };

    if let Some(numa) = pmm_numa() {
        if let Some(pmm) = numa.allocator_for_cpu(cpu_id as u8) {
            let _ = pmm.drain_remote_frees();
            if should_sync_single_writer(tick) {
                pmm.sync_single_writer_arenas();
            }
        }
        return;
    }

    if let Some(pmm) = pmm_global() {
        let _ = pmm.drain_remote_frees();
        if should_sync_single_writer(tick) {
            pmm.sync_single_writer_arenas();
        }
    }
}

/// NUMAノードから物理範囲を解放
pub(crate) fn release_range_from_numa(numa: &NumaPmmAllocator, start: u64, end: u64) -> u64 {
    let node_count = numa.topology.node_count;
    let mut freed = 0u64;
    for node_idx in 0..node_count {
        let node = &numa.topology.nodes[node_idx];
        let Some(pmm) = numa
            .node_allocators
            .get(node_idx)
            .and_then(|opt| opt.as_ref())
        else {
            continue;
        };
        for i in 0..node.range_count {
            let (range_start, range_size) = node.memory_ranges[i];
            let range_end = range_start.saturating_add(range_size);
            let rel_start = start.max(range_start);
            let rel_end = end.min(range_end);
            if rel_end > rel_start {
                freed += pmm.release_range_direct(rel_start, rel_end - rel_start);
            }
        }
    }
    freed
}

/// NUMA情報からメモリ領域を収集
pub(crate) fn collect_numa_memory_regions(numa_info: &NumaInfo, node_count: usize) -> Vec<(PhysAddr, u64, NumaNodeId)> {
    let mut regions: Vec<(PhysAddr, u64, NumaNodeId)> = Vec::new();
    for node_idx in 0..node_count {
        let node = &numa_info.nodes[node_idx];
        let range_count = (node.memory_range_count as usize).min(node.memory_ranges.len());
        for i in 0..range_count {
            let range = node.memory_ranges[i];
            if range.length == 0 {
                continue;
            }
            regions.push((
                PhysAddr::new(range.base),
                range.length,
                NumaNodeId::new(node_idx as u8),
            ));
        }
    }
    regions
}

/// 予約済みだった物理範囲をPMMに戻す（ACPI reclaimなど向け）
pub fn pmm_release_range(start: PhysAddr, size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    let start = start.as_u64();
    let end = start.saturating_add(size);
    let cpu_ids = crate::mm::per_cpu::online_cpu_ids();

    if let Some(numa) = unsafe { pmm_numa_mut() } {
        for allocator in numa.node_allocators.iter_mut() {
            if let Some(pmm) = allocator.as_mut() {
                pmm.configure_arenas_for_cpu_ids(&cpu_ids);
            }
        }

        let freed = release_range_from_numa(numa, start, end);

        for allocator in numa.node_allocators.iter_mut() {
            if let Some(pmm) = allocator.as_mut() {
                pmm.enable_single_writer();
            }
        }

        return freed;
    }

    if let Some(pmm) = unsafe { pmm_global_mut() } {
        pmm.configure_arenas_for_cpu_ids(&cpu_ids);
        let freed = pmm.release_range_direct(start, size);
        pmm.enable_single_writer();
        return freed;
    }

    0
}

#[cfg(test)]
mod tests;

