// ============================================================================
// src/fs/async_ops.rs - Async File Operations
// 設計書 6.3: ストレージと非同期ファイルシステム
// ============================================================================
//!
//! # 非同期ファイル操作
//!
//! NVMe SSDの性能を引き出すための完全非同期API。
//! 従来のブロックレイヤーやページキャッシュの概念を刷新。
//!
//! ## 設計原則
//! - NVMeポーリング: 各CPUコアごとにSubmission/Completion Queueペア
//! - ロックフリーでコマンド発行
//! - ファイルシステムをバイパスした直接ブロックアクセスAPI
//! - ページキャッシュはカーネルヒープ上のArc<Vec<u8>>として実装
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;
use x86_64::PhysAddr;

use kernel_api::dma::{CpuOwned as KapiCpuOwned, DmaSlice};

use super::cache::{PAGE_SIZE as CACHE_PAGE_SIZE, page_cache};
use super::fs_model::{
    FileAttr, FsError, FsResult, SeekFrom, read_inode_by_number, write_inode_by_number,
};

// NVme per-core API
use crate::io::dma::{
    DeviceDmaContext, DeviceDmaMapping, DmaDirection, DmaMemoryAttributes, DmaRegion,
};
use crate::io::io_scheduler::{
    CompletionHook, DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoPriority, IoResult,
};
use crate::io::nvme::dma::{NvmeDmaError, NvmeDmaRegion};
mod cleanup_helpers;

// re-export only the public types/functions kernel relies on instead of a wildcard
pub use cleanup_helpers::{
    AsyncFile,
    AsyncIoRequest,
    AsyncIoScheduler,
    AsyncIoType,
    DirectBlockHandle,
    IoSchedulerStats,
    async_io_scheduler,
    // helper APIs that are internal but still referenced by other parts of the crate
};

type DmaBuffer = DmaSlice<KapiCpuOwned>;

const NVME_PAGE_SIZE: usize = 4096;
const NVME_BLOCK_SIZE: u64 = 512;

/// Local DSM Range definition to avoid io::nvme import
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LocalDsmRange {
    context_attributes: u32,
    length: u32,
    starting_lba: u64,
}

impl LocalDsmRange {
    fn new(starting_lba: u64, length: u32) -> Self {
        Self {
            context_attributes: 0,
            length,
            starting_lba,
        }
    }
}

pub(crate) type NvmeIommuMapping = DeviceDmaMapping;

struct NvmePrpListPage {
    region: DmaRegion,
    map: Option<NvmeIommuMapping>,
    iova: u64,
}

impl NvmePrpListPage {
    fn device_iova(&self) -> u64 {
        debug_assert!(self.region.size() >= NVME_PAGE_SIZE);
        if let Some(map) = &self.map {
            debug_assert_eq!(map.device_addr(), self.iova);
        }
        self.iova
    }
}

struct NvmePrpListChain {
    pages: Vec<NvmePrpListPage>,
}

impl NvmePrpListChain {
    fn first_iova(&self) -> u64 {
        self.pages
            .first()
            .map(NvmePrpListPage::device_iova)
            .unwrap_or(0)
    }

    fn complete(self) {
        drop(self);
    }
}

struct NvmeDmaContext {
    region: Option<NvmeDmaRegion>,
    completed: bool,
    inflight: bool,
}

impl NvmeDmaContext {
    fn mark_inflight(&mut self) {
        self.inflight = true;
    }

    fn complete(mut self) -> DmaRegion {
        self.completed = true;
        self.inflight = false;
        self.region
            .take()
            .expect("NvmeDmaContext missing region")
            .complete()
    }
}

struct NvmeExternalDmaContext {
    prp_list: Option<NvmePrpListChain>,
    data_map: Option<NvmeIommuMapping>,
    completed: bool,
    inflight: bool,
}

impl NvmeExternalDmaContext {
    fn mark_inflight(&mut self) {
        self.inflight = true;
    }

    fn complete(mut self) {
        self.completed = true;
        self.inflight = false;
        if let Some(prp) = self.prp_list.take() {
            prp.complete();
        }
        if let Some(map) = self.data_map.take() {
            let _ = map.unmap();
        }
    }
}

impl Drop for NvmeDmaContext {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.inflight {
            log::warn!("[NVME] NvmeDmaContext dropped while in-flight; leaking DMA resources");
            return;
        }
        if let Some(region) = self.region.take() {
            drop(region.complete());
        }
    }
}

impl Drop for NvmeExternalDmaContext {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.inflight {
            log::warn!("[NVME] NvmeExternalDmaContext dropped while in-flight; leaking mappings");
            return;
        }
        if let Some(prp) = self.prp_list.take() {
            prp.complete();
        }
        if let Some(map) = self.data_map.take() {
            let _ = map.unmap();
        }
    }
}

struct NvmeCancelGuard {
    canceled: Arc<AtomicBool>,
    active: bool,
}

impl NvmeCancelGuard {
    fn new(canceled: Arc<AtomicBool>) -> Self {
        Self {
            canceled,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for NvmeCancelGuard {
    fn drop(&mut self) {
        if self.active {
            self.canceled.store(true, Ordering::Release);
        }
    }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn map_nvme_dma_error(err: NvmeDmaError) -> FsError {
    match err {
        NvmeDmaError::InvalidLen => FsError::InvalidArgument,
        NvmeDmaError::OutOfMemory => FsError::NoSpace,
        NvmeDmaError::IommuMappingFailed => FsError::IoError,
    }
}

fn map_nvme_iommu(phys_addr: u64, size: usize) -> FsResult<(u64, Option<NvmeIommuMapping>)> {
    let device_id = crate::io::nvme::iommu_device();
    let ctx = DeviceDmaContext::for_attached_device(device_id);
    let mapping = ctx
        .map_physical_range(PhysAddr::new(phys_addr), size, DmaDirection::Bidirectional)
        .map_err(|_| FsError::IoError)?;
    let iova = mapping.device_addr();
    Ok((iova, Some(mapping)))
}

/// PRPリストページのDMAバッファを割り当てる
fn allocate_prp_list_pages(total_entries: usize) -> FsResult<Vec<DmaRegion>> {
    let mut remaining = total_entries;
    let mut list_buffers = Vec::new();
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while remaining > 0 {
        let list = DmaRegion::new(NVME_PAGE_SIZE, DmaMemoryAttributes::TO_DEVICE)
            .ok_or(FsError::NoSpace)?;
        list_buffers.push(list);
        if remaining > 512 {
            remaining = remaining.saturating_sub(511);
        } else {
            remaining = 0;
        }
    }
    Ok(list_buffers)
}

/// PRPリストページをIOMMUにマッピングする
fn map_prp_list_pages(
    list_buffers: &[DmaRegion],
) -> FsResult<(Vec<u64>, Vec<Option<NvmeIommuMapping>>)> {
    let mut list_iovas = Vec::with_capacity(list_buffers.len());
    let mut list_maps = Vec::with_capacity(list_buffers.len());
    for list in list_buffers {
        let (list_addr, list_map) = map_nvme_iommu(list.host_addr(), NVME_PAGE_SIZE)?;
        list_iovas.push(list_addr);
        list_maps.push(list_map);
    }
    Ok((list_iovas, list_maps))
}

/// PRPリストエントリにデータページのアドレスを書き込む
fn fill_prp_list_entries(
    list_buffers: &mut [DmaRegion],
    list_iovas: &[u64],
    base_addr: u64,
    total_entries: usize,
) -> FsResult<()> {
    let mut filled = 0usize;
    for idx in 0..list_buffers.len() {
        let remaining_entries = total_entries - filled;
        let needs_chain = remaining_entries > 512;
        let data_capacity = if needs_chain { 511 } else { remaining_entries };

        let entries = unsafe {
            core::slice::from_raw_parts_mut(
                list_buffers[idx].as_mut_slice().as_mut_ptr() as *mut u64,
                NVME_PAGE_SIZE / core::mem::size_of::<u64>(),
            )
        };

        for j in 0..data_capacity {
            entries[j] = base_addr + ((filled + j + 1) * NVME_PAGE_SIZE) as u64;
        }

        if needs_chain {
            let next_iova = *list_iovas.get(idx + 1).ok_or(FsError::InvalidArgument)?;
            entries[511] = next_iova;
        }

        filled += data_capacity;
    }
    Ok(())
}

fn build_prp_list(base_addr: u64, len: usize) -> FsResult<(u64, Option<NvmePrpListChain>)> {
    if len == 0 {
        return Err(FsError::InvalidArgument);
    }

    let pages = (len + NVME_PAGE_SIZE - 1) / NVME_PAGE_SIZE;
    if pages <= 1 {
        return Ok((0, None));
    }
    if pages == 2 {
        return Ok((base_addr + NVME_PAGE_SIZE as u64, None));
    }

    let total_entries = pages - 1;
    let mut list_buffers = allocate_prp_list_pages(total_entries)?;
    let (list_iovas, list_maps) = map_prp_list_pages(&list_buffers)?;
    fill_prp_list_entries(&mut list_buffers, &list_iovas, base_addr, total_entries)?;

    let mut pages_vec = Vec::with_capacity(list_buffers.len());
    for ((list, map), iova) in list_buffers.into_iter().zip(list_maps).zip(list_iovas) {
        list.prepare_for_device();
        pages_vec.push(NvmePrpListPage {
            region: list,
            map,
            iova,
        });
    }

    let chain = NvmePrpListChain { pages: pages_vec };
    let prp2 = chain.first_iova();
    Ok((prp2, Some(chain)))
}

fn prepare_dma_read(len: usize) -> FsResult<(NvmeDmaContext, u64, u64)> {
    let region = NvmeDmaRegion::for_read(len, crate::io::nvme::iommu_device())
        .map_err(map_nvme_dma_error)?;
    let prp1 = region.prp1();
    let prp2 = region.prp2();
    Ok((
        NvmeDmaContext {
            region: Some(region),
            completed: false,
            inflight: false,
        },
        prp1,
        prp2,
    ))
}

fn prepare_dma_write(buf: &[u8], dma_len: usize) -> FsResult<(NvmeDmaContext, u64, u64)> {
    let region = NvmeDmaRegion::for_write(dma_len, buf, crate::io::nvme::iommu_device())
        .map_err(map_nvme_dma_error)?;
    let prp1 = region.prp1();
    let prp2 = region.prp2();
    Ok((
        NvmeDmaContext {
            region: Some(region),
            completed: false,
            inflight: false,
        },
        prp1,
        prp2,
    ))
}

fn prepare_dma_from_cpu_buffer(data: DmaRegion) -> FsResult<(NvmeDmaContext, u64, u64)> {
    let logical_len = data.size();
    let region = NvmeDmaRegion::from_region(data, logical_len, crate::io::nvme::iommu_device())
        .map_err(map_nvme_dma_error)?;
    let prp1 = region.prp1();
    let prp2 = region.prp2();
    Ok((
        NvmeDmaContext {
            region: Some(region),
            completed: false,
            inflight: false,
        },
        prp1,
        prp2,
    ))
}

fn prepare_dma_from_kapi_buffer(
    buffer: &DmaBuffer,
) -> FsResult<(NvmeExternalDmaContext, u64, u64)> {
    let alloc_len = buffer.size();
    // KAPI DMA buffers are already device-scoped and expose the hardware-visible
    // address directly, so this path does not remap them through raw IOMMU APIs.
    let data_addr = buffer.device_address();
    let (prp2, prp_list) = build_prp_list(data_addr, alloc_len)?;
    Ok((
        NvmeExternalDmaContext {
            prp_list,
            data_map: None,
            completed: false,
            inflight: false,
        },
        data_addr,
        prp2,
    ))
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
#[cfg(any(test, feature = "qemu-test-export"))]
pub use tests::*;
