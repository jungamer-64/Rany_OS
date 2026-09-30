// ============================================================================
// src/mm/frame_allocator.rs - Bitmap-based Physical Frame Allocator
// 設計書 5.2 Tier1: 4KiB/2MiB/1GiB単位の物理フレーム管理
// 設計書 5.3 NUMAアーキテクチャへの対応
//
// 注意: 構造体全体がMutexで保護されているため、内部フィールドは
// 通常のu64を使用。Mutex + Atomicの二重ロックはオーバーヘッド。
// ============================================================================
extern crate alloc;

use crate::mm::phys::fast_allocator::{FastBitmapAllocator, LocalCachePolicy, PageGranularity};
use crate::sync::IrqPoisonLock;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

// 共通型定義をインポート（IOVA_MM_MIGRATION_PLAN Phase 0.1）
use crate::loader::type_id::{SemVer, TypeHash, TypeIdHash, const_hash};
use crate::mm::numa::topology::{MAX_NUMA_NODES, NumaTopology};
use crate::mm::types::{FrameIndex, NumaNodeId, PAGE_SIZE_1G, PAGE_SIZE_2M, PAGE_SIZE_4K};

// ============================================================================
// 型安全性: フレーム番号のNewtype
// FrameIndex, PAGE_SIZE_* は crate::mm::types からインポート済み
// (IOVA_MM_MIGRATION_PLAN Phase 0.1 による統一)
// ============================================================================

/// PMMが管理する最大ページ数 (IOVA bitmapと同等: 256GiB / 4KiB)
mod numa;
pub use numa::*;
const PMM_MAX_PAGES: usize = 64 * 1024 * 1024;

pub(crate) const MANAGED_PHYS_START: u64 = PAGE_SIZE_4K as u64;
// PMM Fast Allocator (IOVA-based Bitmap + Magazine)
// ============================================================================

/// PMM fast allocator wrapper (phys addr aware)
pub(crate) struct PmmAllocatorFast {
    inner: FastBitmapAllocator,
    base: u64,
    size: u64,
}

impl PmmAllocatorFast {
    fn new(base: u64, size: u64) -> Self {
        Self {
            inner: FastBitmapAllocator::new(base, size, LocalCachePolicy::PerCpu),
            base,
            size,
        }
    }

    fn provision_cpu_set(
        &self,
        cpu_ids: &crate::cpu::CpuSet,
    ) -> Result<(), crate::mm::phys::fast_allocator::CpuCacheProvisionError> {
        self.inner.provision_cpu_set(cpu_ids)
    }

    fn quiesce_current_cpu(&self) -> crate::mm::phys::fast_allocator::CpuMagazineDrain {
        self.inner.quiesce_current_cpu()
    }

    fn stats(&self) -> (u64, usize) {
        self.inner.pmm_stats()
    }

    fn alloc_4k(&self) -> Option<PhysFrame<Size4KiB>> {
        let addr = self.inner.allocate_4k()?;
        PhysFrame::from_start_address(PhysAddr::new(addr)).ok()
    }

    fn alloc_2m(&self) -> Option<PhysFrame<Size2MiB>> {
        let addr = self.inner.allocate_2m()?;
        PhysFrame::from_start_address(PhysAddr::new(addr)).ok()
    }

    fn alloc_1g(&self) -> Option<PhysFrame<Size1GiB>> {
        let addr = self.inner.allocate_1g()?;
        PhysFrame::from_start_address(PhysAddr::new(addr)).ok()
    }

    fn alloc_contiguous_aligned(&self, frames: usize, align_bytes: u64) -> Option<PhysAddr> {
        if frames == 0 {
            return None;
        }
        let size = (frames as u64).checked_mul(PAGE_SIZE_4K as u64)?;
        let align = align_bytes.max(PAGE_SIZE_4K as u64);
        let addr = self.inner.allocate_contiguous(size, align)?;
        Some(PhysAddr::new(addr))
    }

    fn free_4k(&self, frame: PhysFrame<Size4KiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self.inner.free_immediate(addr, PageGranularity::Page4K);
    }

    fn free_2m(&self, frame: PhysFrame<Size2MiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self.inner.free_immediate(addr, PageGranularity::Page2M);
    }

    fn free_1g(&self, frame: PhysFrame<Size1GiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self.inner.free_immediate(addr, PageGranularity::Page1G);
    }

    fn reserve_range(&self, start: u64, size: u64) {
        if size == 0 {
            return;
        }
        if let Err(err) = self.inner.reserve(start, size) {
            log::warn!(
                "[PMM] reserve failed: start={:#x} size={:#x} err={:?}",
                start,
                size,
                err
            );
        }
    }

    fn reserve_gaps(&self, usable: &[(u64, u64)]) {
        let end = self.base.saturating_add(self.size);
        let mut cursor = self.base;

        for &(start, end_region) in usable {
            let start = start.max(self.base);
            let end_region = end_region.min(end);
            if end_region <= cursor {
                continue;
            }
            if start > cursor {
                self.reserve_range(cursor, start - cursor);
            }
            cursor = end_region;
        }

        if cursor < end {
            self.reserve_range(cursor, end - cursor);
        }
    }

    fn release_range_direct(&self, start: u64, size: u64) -> u64 {
        if size == 0 {
            return 0;
        }
        let mut range_start = start.max(self.base);
        let mut range_end = start.saturating_add(size);
        let pmm_end = self.base.saturating_add(self.size);
        if range_end > pmm_end {
            range_end = pmm_end;
        }
        if range_end <= range_start {
            return 0;
        }

        range_start = align_up(range_start, PAGE_SIZE_4K as u64);
        range_end = align_down(range_end, PAGE_SIZE_4K as u64);
        if range_end <= range_start {
            return 0;
        }

        let len = range_end - range_start;
        if self.inner.free_range_immediate(range_start, len).is_ok() {
            len / (PAGE_SIZE_4K as u64)
        } else {
            0
        }
    }
}

use crate::util::{align_down_u64 as align_down, align_up_u64 as align_up};

fn align_size_to_page(size: usize) -> usize {
    if size <= PAGE_SIZE_4K {
        return PAGE_SIZE_4K;
    }
    size.saturating_add(PAGE_SIZE_4K - 1) / PAGE_SIZE_4K * PAGE_SIZE_4K
}

pub(crate) fn sanitize_managed_region(start: u64, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }

    let end_raw = start.checked_add(size)?;
    let start = align_up(start.max(MANAGED_PHYS_START), PAGE_SIZE_4K as u64);
    let end = align_down(end_raw, PAGE_SIZE_4K as u64);
    if end <= start {
        return None;
    }

    Some((start, end))
}

fn normalize_regions(usable_regions: &[(PhysAddr, u64)]) -> Vec<(u64, u64)> {
    let mut regions: Vec<(u64, u64)> = usable_regions
        .iter()
        .filter_map(|&(addr, size)| sanitize_managed_region(addr.as_u64(), size))
        .collect();

    regions.sort_by_key(|&(start, _)| start);

    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(regions.len());
    for (start, end) in regions {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn build_pmm_from_regions(usable_regions: &[(PhysAddr, u64)]) -> Option<PmmAllocatorFast> {
    let merged = normalize_regions(usable_regions);
    if merged.is_empty() {
        return None;
    }

    let min_start = merged.iter().map(|&(start, _)| start).min()?;
    let base = align_down(min_start, PAGE_SIZE_4K as u64);
    let max_end = merged.iter().map(|&(_, end)| end).max()?;
    let max_size = (PMM_MAX_PAGES as u64) * (PAGE_SIZE_4K as u64);
    let size = align_down(max_end.saturating_sub(base), PAGE_SIZE_4K as u64).min(max_size);
    if size == 0 {
        return None;
    }

    let pmm = PmmAllocatorFast::new(base, size);
    pmm.reserve_gaps(&merged);
    Some(pmm)
}

// ============================================================================
