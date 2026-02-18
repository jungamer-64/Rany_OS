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

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use kernel_api::DmaBuffer;

use super::cache::{page_cache, PAGE_SIZE as CACHE_PAGE_SIZE};
use super::fs_abstraction::{
    read_inode_by_number, write_inode_by_number, FileAttr, FsError, FsResult, SeekFrom,
};

// NVme per-core API
use crate::io::io_scheduler::{
    CompletionHook,
    DeviceId as IoDeviceId,
    IoCommand,
    DmaBufHandle, IoResult,
    IoPriority, NvmeSglDescriptor,
};
use crate::io::dma::{CpuOwned, DeviceOwned, SgDmaGuard, SliceDmaGuard, TypedDmaSlice, TypedSgList};
mod cleanup_helpers;
pub use cleanup_helpers::*;

const NVME_PAGE_SIZE: usize = 4096;
const NVME_BLOCK_SIZE: u64 = 512;
const NVME_MAX_SGL_ENTRIES: usize = 32;
/// Size of NVMe SGL descriptor (16 bytes)
const NVME_SGL_DESCRIPTOR_SIZE: usize = 16;

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

/// Local SGL Descriptor definition to avoid io::nvme import
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LocalSglDescriptor {
    addr: u64,
    length: u32,
    _reserved: [u8; 3],
    type_specific: u8,
}

impl LocalSglDescriptor {
    fn data_block(addr: u64, length: u32) -> Self {
        Self {
            addr,
            length,
            _reserved: [0; 3],
            type_specific: 0x00 << 4, // Data Block
        }
    }
}

pub(crate) struct NvmeIommuMapping {
    /// Kernel-assigned mapping ID for unmap via kernel_api
    mapping_id: u64,
    iova: u64,
}

impl NvmeIommuMapping {
    fn unmap(self) {
        // Use kernel_api abstraction for IOMMU unmap
        let _ = kernel_api::kernel().nvme_iommu_unmap(self.mapping_id);
    }
}

struct NvmePrpListPage {
    dev: TypedDmaSlice<DeviceOwned>,
    guard: SliceDmaGuard,
    map: Option<NvmeIommuMapping>,
    iova: u64,
}

struct NvmePrpListChain {
    pages: Vec<NvmePrpListPage>,
}

impl NvmePrpListChain {
    fn first_iova(&self) -> u64 {
        self.pages.first().map(|page| page.iova).unwrap_or(0)
    }

    fn complete(self) {
        for page in self.pages {
            let _ = page.guard.complete(page.dev);
            if let Some(map) = page.map {
                map.unmap();
            }
        }
    }
}

struct NvmeDmaContext {
    data_dev: Option<TypedDmaSlice<DeviceOwned>>,
    data_guard: Option<SliceDmaGuard>,
    prp_list: Option<NvmePrpListChain>,
    data_map: Option<NvmeIommuMapping>,
    completed: bool,
    inflight: bool,
}

impl NvmeDmaContext {
    fn mark_inflight(&mut self) {
        self.inflight = true;
    }

    fn complete(mut self) -> TypedDmaSlice<CpuOwned> {
        self.completed = true;
        self.inflight = false;
        if let Some(prp) = self.prp_list.take() {
            prp.complete();
        }
        let data_dev = self.data_dev.take().expect("NvmeDmaContext missing data_dev");
        let data_guard = self
            .data_guard
            .take()
            .expect("NvmeDmaContext missing data_guard");
        let data = data_guard.complete(data_dev);
        if let Some(map) = self.data_map.take() {
            map.unmap();
        }
        data
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
            map.unmap();
        }
    }
}

pub(crate) struct NvmeSglContext {
    data_list: Option<TypedSgList<DeviceOwned>>,
    data_guard: Option<SgDmaGuard>,
    data_maps: Vec<NvmeIommuMapping>,
    list_dev: Option<TypedDmaSlice<DeviceOwned>>,
    list_guard: Option<SliceDmaGuard>,
    list_map: Option<NvmeIommuMapping>,
    completed: bool,
    inflight: bool,
}

impl NvmeSglContext {
    fn mark_inflight(&mut self) {
        self.inflight = true;
    }

    fn complete(mut self) -> TypedSgList<CpuOwned> {
        self.completed = true;
        self.inflight = false;

        if let Some(map) = self.list_map.take() {
            map.unmap();
        }
        for map in self.data_maps.drain(..) {
            map.unmap();
        }

        if let (Some(list_dev), Some(list_guard)) = (self.list_dev.take(), self.list_guard.take())
        {
            let _ = list_guard.complete(list_dev);
        }

        let data_list = self.data_list.take().expect("NvmeSglContext missing data_list");
        let data_guard = self.data_guard.take().expect("NvmeSglContext missing data_guard");
        data_guard.complete_all(data_list)
    }
}

impl Drop for NvmeSglContext {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.inflight {
            log::warn!("[NVME] NvmeSglContext dropped while in-flight; leaking DMA resources");
            return;
        }

        if let Some(map) = self.list_map.take() {
            map.unmap();
        }

        for map in self.data_maps.drain(..) {
            map.unmap();
        }

        if let (Some(list_dev), Some(list_guard)) = (self.list_dev.take(), self.list_guard.take())
        {
            let _ = list_guard.complete(list_dev);
        }

        if let (Some(data_list), Some(data_guard)) = (self.data_list.take(), self.data_guard.take())
        {
            let _ = data_guard.complete_all(data_list);
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
        if let Some(prp) = self.prp_list.take() {
            prp.complete();
        }
        if let (Some(data_dev), Some(data_guard)) =
            (self.data_dev.take(), self.data_guard.take())
        {
            let _ = data_guard.complete(data_dev);
        }
        if let Some(map) = self.data_map.take() {
            map.unmap();
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
            map.unmap();
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

fn map_nvme_iommu(
    phys_addr: u64,
    size: usize,
) -> FsResult<(u64, Option<NvmeIommuMapping>)> {
    // Use kernel_api abstraction for IOMMU mapping
    match kernel_api::kernel().nvme_iommu_map(0, phys_addr, size) {
        Ok((iova, mapping_id)) => {
            if mapping_id == 0 {
                // Identity mapping (no IOMMU or passthrough)
                Ok((iova, None))
            } else {
                Ok((iova, Some(NvmeIommuMapping { mapping_id, iova })))
            }
        }
        Err(_) => Err(FsError::IoError),
    }
}

/// PRPリストページのDMAバッファを割り当てる
fn allocate_prp_list_pages(total_entries: usize) -> FsResult<Vec<TypedDmaSlice<CpuOwned>>> {
    let mut remaining = total_entries;
    let mut list_buffers = Vec::new();
    while remaining > 0 {
        let list =
            TypedDmaSlice::<CpuOwned>::new(NVME_PAGE_SIZE).ok_or(FsError::NoSpace)?;
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
    list_buffers: &[TypedDmaSlice<CpuOwned>],
) -> FsResult<(Vec<u64>, Vec<Option<NvmeIommuMapping>>)> {
    let mut list_iovas = Vec::with_capacity(list_buffers.len());
    let mut list_maps = Vec::with_capacity(list_buffers.len());
    for list in list_buffers {
        let list_phys = list.phys_addr().as_u64();
        let (list_addr, list_map) = map_nvme_iommu(list_phys, NVME_PAGE_SIZE)?;
        list_iovas.push(list_addr);
        list_maps.push(list_map);
    }
    Ok((list_iovas, list_maps))
}

/// PRPリストエントリにデータページのアドレスを書き込む
fn fill_prp_list_entries(
    list_buffers: &mut [TypedDmaSlice<CpuOwned>],
    list_iovas: &[u64],
    base_addr: u64,
    total_entries: usize,
) -> FsResult<()> {
    let mut filled = 0usize;
    for idx in 0..list_buffers.len() {
        let remaining_entries = total_entries - filled;
        let needs_chain = remaining_entries > 512;
        let data_capacity = if needs_chain {
            511
        } else {
            remaining_entries
        };

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
            let next_iova = *list_iovas
                .get(idx + 1)
                .ok_or(FsError::InvalidArgument)?;
            entries[511] = next_iova;
        }

        filled += data_capacity;
    }
    Ok(())
}

fn build_prp_list(
    base_addr: u64,
    len: usize,
) -> FsResult<(u64, Option<NvmePrpListChain>)> {
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
    for ((list, map), iova) in list_buffers
        .into_iter()
        .zip(list_maps)
        .zip(list_iovas)
    {
        let (dev, guard) = list.start_dma();
        pages_vec.push(NvmePrpListPage {
            dev,
            guard,
            map,
            iova,
        });
    }

    let chain = NvmePrpListChain { pages: pages_vec };
    let prp2 = chain.first_iova();
    Ok((prp2, Some(chain)))
}

fn prepare_dma_read(len: usize) -> FsResult<(NvmeDmaContext, u64, u64)> {
    let alloc_len = align_up(len, NVME_PAGE_SIZE);
    let data = TypedDmaSlice::<CpuOwned>::new(alloc_len).ok_or(FsError::NoSpace)?;
    let data_phys = data.phys_addr().as_u64();
    // Use kernel_api abstractions - device param is now ignored
    let (data_addr, data_map) = map_nvme_iommu(data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(data_addr, alloc_len)?;
    let (data_dev, data_guard) = data.start_dma();
    Ok((
        NvmeDmaContext {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            prp_list,
            data_map,
            completed: false,
            inflight: false,
        },
        data_addr,
        prp2,
    ))
}

fn prepare_dma_write(buf: &[u8], dma_len: usize) -> FsResult<(NvmeDmaContext, u64, u64)> {
    let alloc_len = align_up(dma_len, NVME_PAGE_SIZE);
    let mut data = TypedDmaSlice::<CpuOwned>::new(alloc_len).ok_or(FsError::NoSpace)?;
    data.as_mut_slice()[..buf.len()].copy_from_slice(buf);
    if alloc_len > buf.len() {
        data.as_mut_slice()[buf.len()..].fill(0);
    }
    let data_phys = data.phys_addr().as_u64();
    // Use kernel_api abstractions - device param is now ignored
    let (data_addr, data_map) = map_nvme_iommu(data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(data_addr, alloc_len)?;
    let (data_dev, data_guard) = data.start_dma();
    Ok((
        NvmeDmaContext {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            prp_list,
            data_map,
            completed: false,
            inflight: false,
        },
        data_addr,
        prp2,
    ))
}

fn prepare_dma_from_cpu_buffer(
    data: TypedDmaSlice<CpuOwned>,
) -> FsResult<(NvmeDmaContext, u64, u64)> {
    let alloc_len = data.len();
    let data_phys = data.phys_addr().as_u64();
    // Use kernel_api abstractions - device param is now ignored
    let (data_addr, data_map) = map_nvme_iommu(data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(data_addr, alloc_len)?;
    let (data_dev, data_guard) = data.start_dma();
    Ok((
        NvmeDmaContext {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            prp_list,
            data_map,
            completed: false,
            inflight: false,
        },
        data_addr,
        prp2,
    ))
}

fn prepare_dma_from_kapi_buffer(
    buffer: &DmaBuffer,
) -> FsResult<(NvmeExternalDmaContext, u64, u64)> {
    let alloc_len = buffer.size();
    let data_phys = buffer.physical_address();
    // Use kernel_api abstractions - device param is now ignored
    let (data_addr, data_map) = map_nvme_iommu(data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(data_addr, alloc_len)?;
    Ok((
        NvmeExternalDmaContext {
            prp_list,
            data_map,
            completed: false,
            inflight: false,
        },
        data_addr,
        prp2,
    ))
}

/// SGLエントリの検証と合計バイト数の計算
fn validate_sgl_total_bytes(
    list: &TypedSgList<CpuOwned>,
    max_entries: usize,
) -> FsResult<usize> {
    if list.is_empty() || list.len() > max_entries {
        return Err(FsError::InvalidArgument);
    }
    let mut total: usize = 0;
    for entry in list.entries() {
        if entry.size == 0 {
            return Err(FsError::InvalidArgument);
        }
        total = total
            .checked_add(entry.size as usize)
            .ok_or(FsError::InvalidArgument)?;
    }
    Ok(total)
}
