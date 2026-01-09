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
use x86_64::PhysAddr;

use kernel_api::DmaBuffer;

use super::cache::{page_cache, PAGE_SIZE as CACHE_PAGE_SIZE};
use super::vfs::{
    read_inode_by_number, write_inode_by_number, FileAttr, FsError, FsResult, SeekFrom,
};

// NVMe per-core API
use crate::io::nvme::global as nvme_global;
use crate::io::io_scheduler::{
    CompletionHook,
    DeviceId as IoDeviceId,
    IoOperationType,
    IoPayload,
    IoPriority,
    IoResult,
    NvmeDsmPayload,
    NvmeRwPayload,
    NvmeSglDescriptor,
    NvmeSglPayload,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::dma::{CpuOwned, DeviceOwned, SgDmaGuard, SliceDmaGuard, TypedDmaSlice, TypedSgList};

const NVME_PAGE_SIZE: usize = 4096;
const NVME_BLOCK_SIZE: u64 = 512;
const NVME_MAX_SGL_ENTRIES: usize = 32;

struct NvmeIommuMapping {
    device: IommuDeviceId,
    iova: u64,
    size: u64,
}

impl NvmeIommuMapping {
    fn unmap(self) {
        let _ = crate::io::iommu::api::unmap_for_device(&self.device, self.iova, self.size);
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

struct NvmeSglContext {
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
    device: Option<IommuDeviceId>,
    phys_addr: u64,
    size: usize,
) -> FsResult<(u64, Option<NvmeIommuMapping>)> {
    if !crate::io::iommu::api::is_iommu_enabled() {
        if crate::io::iommu::api::is_iommu_required() {
            return Err(FsError::IoError);
        }
        if !crate::io::iommu::api::is_unsafe_identity_mapping_allowed() {
            return Err(FsError::IoError);
        }
        return Ok((phys_addr, None));
    }

    let device = device.ok_or(FsError::IoError)?;
    let map_len = align_up(size, NVME_PAGE_SIZE);
    #[allow(deprecated)]
    let iova = unsafe {
        crate::io::iommu::api::raw::map_for_device(&device, PhysAddr::new(phys_addr), map_len as u64)
    }
    .map_err(|_| FsError::IoError)?;

    Ok((
        iova,
        Some(NvmeIommuMapping {
            device,
            iova,
            size: map_len as u64,
        }),
    ))
}

fn build_prp_list(
    device: Option<IommuDeviceId>,
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

    let mut list_iovas = Vec::with_capacity(list_buffers.len());
    let mut list_maps = Vec::with_capacity(list_buffers.len());
    for list in &list_buffers {
        let list_phys = list.phys_addr().as_u64();
        let (list_addr, list_map) = map_nvme_iommu(device, list_phys, NVME_PAGE_SIZE)?;
        list_iovas.push(list_addr);
        list_maps.push(list_map);
    }

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

    let mut pages = Vec::with_capacity(list_buffers.len());
    for ((list, map), iova) in list_buffers
        .into_iter()
        .zip(list_maps)
        .zip(list_iovas)
    {
        let (dev, guard) = list.start_dma();
        pages.push(NvmePrpListPage {
            dev,
            guard,
            map,
            iova,
        });
    }

    let chain = NvmePrpListChain { pages };
    let prp2 = chain.first_iova();
    Ok((prp2, Some(chain)))
}

fn prepare_dma_read(len: usize) -> FsResult<(NvmeDmaContext, u64, u64)> {
    let alloc_len = align_up(len, NVME_PAGE_SIZE);
    let data = TypedDmaSlice::<CpuOwned>::new(alloc_len).ok_or(FsError::NoSpace)?;
    let data_phys = data.phys_addr().as_u64();
    let device = crate::io::nvme::iommu_device();
    let (data_addr, data_map) = map_nvme_iommu(device, data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(device, data_addr, alloc_len)?;
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
    let device = crate::io::nvme::iommu_device();
    let (data_addr, data_map) = map_nvme_iommu(device, data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(device, data_addr, alloc_len)?;
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
    let device = crate::io::nvme::iommu_device();
    let (data_addr, data_map) = map_nvme_iommu(device, data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(device, data_addr, alloc_len)?;
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
    let device = crate::io::nvme::iommu_device();
    let (data_addr, data_map) = map_nvme_iommu(device, data_phys, alloc_len)?;
    let (prp2, prp_list) = build_prp_list(device, data_addr, alloc_len)?;
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

fn prepare_nvme_sgl(
    list: TypedSgList<CpuOwned>,
    max_entries: usize,
) -> FsResult<(NvmeSglContext, NvmeSglDescriptor, usize)> {
    if list.is_empty() {
        return Err(FsError::InvalidArgument);
    }
    if list.len() > max_entries {
        return Err(FsError::InvalidArgument);
    }

    let mut total_bytes: usize = 0;
    for entry in list.entries() {
        if entry.size == 0 {
            return Err(FsError::InvalidArgument);
        }
        total_bytes = total_bytes
            .checked_add(entry.size as usize)
            .ok_or(FsError::InvalidArgument)?;
    }

    let entry_count = list.entries().len();
    let device = crate::io::nvme::iommu_device();
    let mut data_maps: Vec<NvmeIommuMapping> = Vec::new();
    let mut mapped_entries = Vec::with_capacity(entry_count);

    for entry in list.entries() {
        let (addr, map) = match map_nvme_iommu(device, entry.phys_addr, entry.size as usize) {
            Ok(v) => v,
            Err(e) => {
                for map in data_maps.drain(..) {
                    map.unmap();
                }
                return Err(e);
            }
        };
        if let Some(map) = map {
            data_maps.push(map);
        }
        mapped_entries.push((addr, entry.size));
    }

    if entry_count == 1 {
        let (data_list, data_guard) = list.start_dma();
        let (addr, size) = mapped_entries[0];
        let sgl = NvmeSglDescriptor::data_block(addr, size);
        let ctx = NvmeSglContext {
            data_list: Some(data_list),
            data_guard: Some(data_guard),
            data_maps,
            list_dev: None,
            list_guard: None,
            list_map: None,
            completed: false,
            inflight: false,
        };
        return Ok((ctx, sgl, total_bytes));
    }

    let list_bytes = entry_count * core::mem::size_of::<crate::io::nvme::SglDescriptor>();
    let list_len = match u32::try_from(list_bytes) {
        Ok(v) => v,
        Err(_) => {
            for map in data_maps.drain(..) {
                map.unmap();
            }
            return Err(FsError::InvalidArgument);
        }
    };
    let mut list_buf = match TypedDmaSlice::<CpuOwned>::new(list_bytes) {
        Some(v) => v,
        None => {
            for map in data_maps.drain(..) {
                map.unmap();
            }
            return Err(FsError::NoSpace);
        }
    };
    let list_slice = unsafe {
        core::slice::from_raw_parts_mut(
            list_buf.as_mut_slice().as_mut_ptr() as *mut crate::io::nvme::SglDescriptor,
            entry_count,
        )
    };

    for (dst, (addr, size)) in list_slice.iter_mut().zip(mapped_entries.iter()) {
        *dst = crate::io::nvme::SglDescriptor::data_block(*addr, *size);
    }

    let list_phys = list_buf.phys_addr().as_u64();
    let (list_addr, list_map) = match map_nvme_iommu(device, list_phys, list_bytes) {
        Ok(v) => v,
        Err(e) => {
            for map in data_maps.drain(..) {
                map.unmap();
            }
            return Err(e);
        }
    };

    let (data_list, data_guard) = list.start_dma();
    let (list_dev, list_guard) = list_buf.start_dma();
    let sgl = NvmeSglDescriptor::last_segment(list_addr, list_len);
    let ctx = NvmeSglContext {
        data_list: Some(data_list),
        data_guard: Some(data_guard),
        data_maps,
        list_dev: Some(list_dev),
        list_guard: Some(list_guard),
        list_map,
        completed: false,
        inflight: false,
    };

    Ok((ctx, sgl, total_bytes))
}

fn nvme_sgl_max_entries() -> Option<usize> {
    nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
        driver.sgl_max_entries()
    })
    .flatten()
}

fn sg_total_bytes(list: &TypedSgList<CpuOwned>) -> FsResult<usize> {
    list.entries()
        .iter()
        .try_fold(0usize, |acc, entry| {
            acc.checked_add(entry.size as usize)
                .ok_or(FsError::InvalidArgument)
        })
}

fn sg_copy_to_vec(list: &TypedSgList<CpuOwned>) -> FsResult<Vec<u8>> {
    let total = sg_total_bytes(list)?;
    let mut buf = vec![0u8; total];
    let mut offset = 0usize;

    for idx in 0..list.len() {
        let slice = list
            .buffer(idx)
            .ok_or(FsError::InvalidArgument)?;
        let len = slice.len();
        let end = offset
            .checked_add(len)
            .ok_or(FsError::InvalidArgument)?;
        buf[offset..end].copy_from_slice(slice.as_slice());
        offset = end;
    }

    Ok(buf)
}

fn sg_copy_from_vec(list: &mut TypedSgList<CpuOwned>, buf: &[u8]) -> FsResult<()> {
    let mut offset = 0usize;
    let total = sg_total_bytes(list)?;

    for idx in 0..list.len() {
        let slice = list
            .buffer_mut(idx)
            .ok_or(FsError::InvalidArgument)?;
        let len = slice.len();
        let end = offset
            .checked_add(len)
            .ok_or(FsError::InvalidArgument)?;
        let dst = slice.as_mut_slice();
        if offset >= buf.len() {
            dst.fill(0);
        } else if end <= buf.len() {
            dst.copy_from_slice(&buf[offset..end]);
        } else {
            let copy_len = buf.len().saturating_sub(offset);
            dst[..copy_len].copy_from_slice(&buf[offset..]);
            dst[copy_len..].fill(0);
        }
        offset = end;
    }

    if total < buf.len() {
        return Err(FsError::InvalidArgument);
    }

    Ok(())
}

fn nsid_from_device(device_id: u64) -> u32 {
    let nsid = device_id as u32;
    if nsid == 0 {
        1
    } else {
        nsid
    }
}

fn nvme_block_size(device_id: u64) -> u64 {
    let nsid = nsid_from_device(device_id);
    nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
        driver.namespace_block_size(nsid) as u64
    })
    .unwrap_or(NVME_BLOCK_SIZE)
}

fn read_via_page_cache(
    ino: u64,
    offset: u64,
    buf: &mut [u8],
    file_size: u64,
) -> FsResult<usize> {
    let cache = page_cache();
    let mut total = 0;

    while total < buf.len() {
        let cur_offset = offset + total as u64;
        let page_num = cur_offset / CACHE_PAGE_SIZE as u64;
        let page_offset = (cur_offset % CACHE_PAGE_SIZE as u64) as usize;
        let chunk = (CACHE_PAGE_SIZE - page_offset).min(buf.len() - total);

        if let Some(read) = cache.read(ino, cur_offset, &mut buf[total..total + chunk], file_size) {
            total += read;
            continue;
        }

        let page_start = page_num * CACHE_PAGE_SIZE as u64;
        let mut page_data = alloc::vec![0u8; CACHE_PAGE_SIZE];
        if page_start < file_size {
            let read_len =
                read_inode_by_number(ino, page_start, &mut page_data).map_err(|_| FsError::IoError)?;
            if read_len < CACHE_PAGE_SIZE {
                page_data[read_len..].fill(0);
            }
        }

        let copy_end = page_offset + chunk;
        buf[total..total + chunk].copy_from_slice(&page_data[page_offset..copy_end]);
        cache.insert(ino, page_num, page_data, file_size);
        total += chunk;
    }

    Ok(total)
}

fn write_via_page_cache(
    ino: u64,
    offset: u64,
    buf: &[u8],
    file_size: u64,
) -> FsResult<usize> {
    let cache = page_cache();
    let mut total = 0;

    while total < buf.len() {
        let cur_offset = offset + total as u64;
        let page_num = cur_offset / CACHE_PAGE_SIZE as u64;
        let page_offset = (cur_offset % CACHE_PAGE_SIZE as u64) as usize;
        let chunk = (CACHE_PAGE_SIZE - page_offset).min(buf.len() - total);

        if let Some(written) = cache.write(ino, cur_offset, &buf[total..total + chunk], file_size)
        {
            total += written;
            continue;
        }

        let page_start = page_num * CACHE_PAGE_SIZE as u64;
        let mut page_data = alloc::vec![0u8; CACHE_PAGE_SIZE];
        let needs_preserve = page_offset != 0 || chunk != CACHE_PAGE_SIZE;
        if needs_preserve && page_start < file_size {
            let read_len =
                read_inode_by_number(ino, page_start, &mut page_data).map_err(|_| FsError::IoError)?;
            if read_len < CACHE_PAGE_SIZE {
                page_data[read_len..].fill(0);
            }
        }

        let copy_end = page_offset + chunk;
        page_data[page_offset..copy_end].copy_from_slice(&buf[total..total + chunk]);
        cache.insert(ino, page_num, page_data, file_size);
        cache.mark_dirty(ino, page_num);
        total += chunk;
    }

    Ok(total)
}

fn flush_page_cache(ino: u64) -> FsResult<()> {
    let cache = page_cache();
    cache
        .sync_file(ino, |offset, data| {
            write_inode_by_number(ino, offset, data).map_err(|_| ())
        })
        .map_err(|_| FsError::IoError)?;
    Ok(())
}

// ============================================================================
// 非同期I/Oリクエスト
// ============================================================================

/// 非同期I/Oの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncIoType {
    /// 読み取り
    Read,
    /// 書き込み
    Write,
    /// フラッシュ
    Flush,
    /// 同期
    Sync,
    /// Discard（TRIM）
    Discard,
}

/// 非同期I/Oリクエスト
pub struct AsyncIoRequest {
    /// リクエストID
    pub id: u64,
    /// I/Oタイプ
    pub io_type: AsyncIoType,
    /// オフセット（バイト）
    pub offset: u64,
    /// データバッファ
    pub buffer: Option<Arc<Mutex<Vec<u8>>>>,
    /// バッファ内オフセット
    pub buf_offset: usize,
    /// 長さ
    pub length: usize,
    /// 完了フラグ
    completed: AtomicBool,
    /// 結果（完了時に設定）
    result: Mutex<Option<Result<usize, FsError>>>,
    /// 完了待ちWaker
    waker: Mutex<Option<Waker>>,
}

impl AsyncIoRequest {
    /// 新しいリクエストを作成
    pub fn new(
        id: u64,
        io_type: AsyncIoType,
        offset: u64,
        buffer: Option<Arc<Mutex<Vec<u8>>>>,
        length: usize,
    ) -> Self {
        Self {
            id,
            io_type,
            offset,
            buffer,
            buf_offset: 0,
            length,
            completed: AtomicBool::new(false),
            result: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }

    /// 読み取りリクエストを作成
    pub fn read(id: u64, offset: u64, buffer: Arc<Mutex<Vec<u8>>>, length: usize) -> Self {
        Self::new(id, AsyncIoType::Read, offset, Some(buffer), length)
    }

    /// 書き込みリクエストを作成
    pub fn write(id: u64, offset: u64, buffer: Arc<Mutex<Vec<u8>>>, length: usize) -> Self {
        Self::new(id, AsyncIoType::Write, offset, Some(buffer), length)
    }

    /// フラッシュリクエストを作成
    pub fn flush(id: u64) -> Self {
        Self::new(id, AsyncIoType::Flush, 0, None, 0)
    }

    /// 完了をマーク
    pub fn complete(&self, result: Result<usize, FsError>) {
        *self.result.lock() = Some(result);
        self.completed.store(true, Ordering::Release);
        async_io_scheduler().mark_completed(self.id);

        // Wakerを起こす
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    /// 完了したか
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    /// 結果を取得
    pub fn get_result(&self) -> Option<Result<usize, FsError>> {
        self.result.lock().clone()
    }
}

// ============================================================================
// 非同期ファイルハンドル
// ============================================================================

/// 非同期ファイルハンドル
/// 設計書 6.3: 非同期ファイルシステム
pub struct AsyncFile {
    /// ファイル識別子
    pub id: u64,
    /// ファイル属性
    attr: Mutex<FileAttr>,
    /// 現在位置
    position: AtomicU64,
    /// 読み取り可能
    readable: bool,
    /// 書き込み可能
    writable: bool,
    /// ダイレクトI/O（バイパスキャッシュ）
    direct_io: bool,
    /// バックエンドデバイスID（NVMe namespace ID）
    device_id: u64,
    /// 開始ブロック（ダイレクトI/O用）
    start_block: u64,
    /// ブロックサイズ（バイト、ダイレクトI/O用）
    block_size: u64,
}

impl AsyncFile {
    /// 新しい非同期ファイルを作成
    pub fn new(id: u64, attr: FileAttr, readable: bool, writable: bool) -> Self {
        Self {
            id,
            attr: Mutex::new(attr),
            position: AtomicU64::new(0),
            readable,
            writable,
            direct_io: false,
            device_id: 0,
            start_block: 0,
            block_size: NVME_BLOCK_SIZE,
        }
    }

    /// ダイレクトI/Oモードで作成
    pub fn new_direct(id: u64, device_id: u64, start_block: u64, size: u64) -> Self {
        let attr = FileAttr {
            ino: id,
            size,
            ..Default::default()
        };
        let block_size = nvme_block_size(device_id);

        Self {
            id,
            attr: Mutex::new(attr),
            position: AtomicU64::new(0),
            readable: true,
            writable: true,
            direct_io: true,
            device_id,
            start_block,
            block_size,
        }
    }

    fn io_device(&self) -> IoDeviceId {
        IoDeviceId::Nvme {
            controller: 0,
            namespace: nsid_from_device(self.device_id),
        }
    }

    /// 非同期読み取り
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> AsyncReadFuture<'a> {
        AsyncReadFuture::new(self, buf)
    }

    /// 非同期書き込み
    pub fn write<'a>(&'a self, buf: &'a [u8]) -> AsyncWriteFuture<'a> {
        AsyncWriteFuture::new(self, buf)
    }

    /// シーク
    pub fn seek(&self, pos: SeekFrom) -> FsResult<u64> {
        let current = self.position.load(Ordering::Relaxed);
        let size = self.attr.lock().size;

        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset < 0 {
                    size.checked_sub((-offset) as u64)
                        .ok_or(FsError::InvalidArgument)?
                } else {
                    size + offset as u64
                }
            }
            SeekFrom::Current(offset) => {
                if offset < 0 {
                    current
                        .checked_sub((-offset) as u64)
                        .ok_or(FsError::InvalidArgument)?
                } else {
                    current + offset as u64
                }
            }
        };

        self.position.store(new_pos, Ordering::Relaxed);
        Ok(new_pos)
    }

    /// 現在位置を取得
    pub fn position(&self) -> u64 {
        self.position.load(Ordering::Relaxed)
    }

    /// ファイルサイズを取得
    pub fn size(&self) -> u64 {
        self.attr.lock().size
    }

    /// フラッシュ
    pub async fn flush(&self) -> FsResult<()> {
        AsyncFlushFuture::new(self).await
    }

    /// 同期（fsync）
    pub async fn sync(&self) -> FsResult<()> {
        AsyncSyncFuture::new(self).await
    }
}

// ============================================================================
// Future 実装
// ============================================================================

/// 非同期読み取りFuture
pub struct AsyncReadFuture<'a> {
    file: &'a AsyncFile,
    buf: &'a mut [u8],
    started: bool,
    io_future: Option<crate::io::io_scheduler::IoFuture>,
    dma_user_len: usize,
    cancel_guard: Option<NvmeCancelGuard>,
    dma_result: Option<Arc<Mutex<Option<(TypedDmaSlice<CpuOwned>, usize)>>>>,
    dma_offset_in_block: Option<usize>,
    dma_dma_len: Option<usize>,
}

impl<'a> AsyncReadFuture<'a> {
    fn new(file: &'a AsyncFile, buf: &'a mut [u8]) -> Self {
        Self {
            file,
            buf,
            started: false,
            io_future: None,
            dma_user_len: 0,
            cancel_guard: None,
            dma_result: None,
            dma_offset_in_block: None,
            dma_dma_len: None,
        }
    }
}

impl<'a> Future for AsyncReadFuture<'a> {
    type Output = FsResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.file.readable {
            return Poll::Ready(Err(FsError::PermissionDenied));
        }

        // 最初のポーリングでリクエストを発行
        if !self.started {
            self.started = true;

            let position = self.file.position.load(Ordering::Relaxed);
            let len = self.buf.len();

            // ファイル終端チェック
            let size = self.file.attr.lock().size;
            if position >= size {
                return Poll::Ready(Ok(0)); // EOF
            }

            // 読み取り可能なバイト数を計算
            let available = (size - position) as usize;
            let to_read = len.min(available);

            if to_read == 0 {
                return Poll::Ready(Ok(0));
            }

            // ダイレクトI/Oの場合は直接デバイスアクセス
            if self.file.direct_io {
                // NVMeリードコマンド発行（コア固有のNVMeキューを使用）
                let block_size = self.file.block_size;
                let offset_in_block = (position % block_size) as usize;
                let total_len = offset_in_block + to_read;
                let blocks_u64 = (total_len as u64 + block_size - 1) / block_size;
                if blocks_u64 > u16::MAX as u64 {
                    return Poll::Ready(Err(FsError::InvalidArgument));
                }
                let blocks = blocks_u64 as u16;
                let dma_len = (blocks as usize) * (block_size as usize);
                let lba = self.file.start_block + (position / block_size);

                let (mut ctx, prp1, prp2) = match prepare_dma_read(dma_len) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };

                let canceled = Arc::new(AtomicBool::new(false));
                self.cancel_guard = Some(NvmeCancelGuard::new(canceled.clone()));
                let slot = Arc::new(Mutex::new(None::<(TypedDmaSlice<CpuOwned>, usize)>));
                let slot_clone = slot.clone();
                self.dma_result = Some(slot);
                self.dma_offset_in_block = Some(offset_in_block);
                self.dma_dma_len = Some(dma_len);

                let payload = IoPayload::NvmeRw(NvmeRwPayload {
                    lba,
                    blocks,
                    prp1,
                    prp2,
                    bytes: dma_len,
                });
                let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
                    self.file.io_device(),
                    IoOperationType::Read,
                    IoPriority::Normal,
                    payload,
                );
                let request_id = future.request_id();

                ctx.mark_inflight();
                let hook: CompletionHook = Box::new(move |result| {
                    let data = ctx.complete();
                    if canceled.load(Ordering::Acquire) {
                        return;
                    }
                    if let IoResult::Success(bytes) = result {
                        *slot_clone.lock() = Some((data, bytes));
                    }
                });
                crate::io::io_scheduler::io_scheduler()
                    .register_completion_hook(request_id, hook);

                self.io_future = Some(future);
                self.dma_user_len = to_read;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let file_id = self.file.id;
            match read_via_page_cache(file_id, position, &mut self.buf[..to_read], size) {
                Ok(read_len) => {
                    self.file
                        .position
                        .fetch_add(read_len as u64, Ordering::Relaxed);
                    return Poll::Ready(Ok(read_len));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        if let Some(future) = self.io_future.as_mut() {
            match Pin::new(future).poll(cx) {
                Poll::Ready(Ok(_)) => {
                    if let Some(mut guard) = self.cancel_guard.take() {
                        guard.disarm();
                    }

                    if let Some(slot) = self.dma_result.take() {
                        let (data, bytes_received) = slot.lock().take().ok_or(FsError::IoError)?;
                        let dma_len = self.dma_dma_len.take().ok_or(FsError::IoError)?;
                        let offset_in_block = self.dma_offset_in_block.take().ok_or(FsError::IoError)?;
                        let available = bytes_received.min(dma_len).min(data.len());
                        let start = offset_in_block.min(available);
                        let remaining = available.saturating_sub(start);
                        let copy_len = remaining.min(self.dma_user_len);
                        if copy_len > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    data.as_slice().as_ptr().add(start),
                                    self.buf.as_mut_ptr(),
                                    copy_len,
                                );
                            }
                        }
                        self.file
                            .position
                            .fetch_add(copy_len as u64, Ordering::Relaxed);
                        return Poll::Ready(Ok(copy_len));
                    }

                    return Poll::Ready(Err(FsError::IoError));
                }
                Poll::Ready(Err(_)) => {
                    if let Some(mut guard) = self.cancel_guard.take() {
                        guard.disarm();
                    }
                    return Poll::Ready(Err(FsError::IoError));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(0))
    }
}

/// 非同期書き込みFuture
pub struct AsyncWriteFuture<'a> {
    file: &'a AsyncFile,
    buf: &'a [u8],
    started: bool,
    io_future: Option<crate::io::io_scheduler::IoFuture>,
    dma_user_len: usize,
    unaligned: Option<UnalignedWriteState>,
}

struct UnalignedReadSlot {
    data: Mutex<Option<TypedDmaSlice<CpuOwned>>>,
}

impl UnalignedReadSlot {
    fn new() -> Self {
        Self {
            data: Mutex::new(None),
        }
    }
}

enum UnalignedWriteState {
    Reading {
        io_future: crate::io::io_scheduler::IoFuture,
        data_slot: Arc<UnalignedReadSlot>,
        lba: u64,
        blocks: u16,
        offset: usize,
        len: usize,
        start_pos: u64,
    },
    Writing {
        io_future: crate::io::io_scheduler::IoFuture,
        len: usize,
        start_pos: u64,
    },
}

impl<'a> AsyncWriteFuture<'a> {
    fn new(file: &'a AsyncFile, buf: &'a [u8]) -> Self {
        Self {
            file,
            buf,
            started: false,
            io_future: None,
            dma_user_len: 0,
            unaligned: None,
        }
    }
}

impl<'a> Future for AsyncWriteFuture<'a> {
    type Output = FsResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.file.writable {
            return Poll::Ready(Err(FsError::PermissionDenied));
        }

        if !self.started {
            self.started = true;

            let position = self.file.position.load(Ordering::Relaxed);
            let len = self.buf.len();

            if len == 0 {
                return Poll::Ready(Ok(0));
            }

            // ダイレクトI/Oの場合
            if self.file.direct_io {
                // NVMeライトコマンド発行（コア固有のNVMeキューを使用）
                let block_size = self.file.block_size;
                let offset_in_block = (position % block_size) as usize;
                if offset_in_block != 0 || (len as u64) % block_size != 0 {
                    let end_pos = position + len as u64;
                    let aligned_start = position / block_size;
                    let aligned_end =
                        (end_pos + block_size - 1) / block_size;
                    let blocks_u64 = aligned_end.saturating_sub(aligned_start);

                    if blocks_u64 > u16::MAX as u64 {
                        return Poll::Ready(Err(FsError::InvalidArgument));
                    }

                    let blocks = blocks_u64 as u16;
                    let dma_len = (blocks as usize) * (block_size as usize);
                    let lba = self.file.start_block + aligned_start;

                    let (mut ctx, prp1, prp2) = match prepare_dma_read(dma_len) {
                        Ok(v) => v,
                        Err(e) => return Poll::Ready(Err(e)),
                    };

                    let data_slot = Arc::new(UnalignedReadSlot::new());
                    let slot = data_slot.clone();
                    let payload = IoPayload::NvmeRw(NvmeRwPayload {
                        lba,
                        blocks,
                        prp1,
                        prp2,
                        bytes: dma_len,
                    });
                    let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
                        self.file.io_device(),
                        IoOperationType::Read,
                        IoPriority::Normal,
                        payload,
                    );
                    let request_id = future.request_id();
                    ctx.mark_inflight();
                    let hook: CompletionHook = Box::new(move |result| {
                        let data = ctx.complete();
                        if let IoResult::Success(_) = result {
                            *slot.data.lock() = Some(data);
                        }
                    });
                    crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

                    self.unaligned = Some(UnalignedWriteState::Reading {
                        io_future: future,
                        data_slot,
                        lba,
                        blocks,
                        offset: offset_in_block,
                        len,
                        start_pos: position,
                    });
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let blocks_u64 = len as u64 / block_size;
                if blocks_u64 > u16::MAX as u64 {
                    return Poll::Ready(Err(FsError::InvalidArgument));
                }
                let blocks = blocks_u64 as u16;
                let dma_len = (blocks as usize) * (block_size as usize);
                let lba = self.file.start_block + (position / block_size);

                let (mut ctx, prp1, prp2) = match prepare_dma_write(self.buf, dma_len) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };

                let payload = IoPayload::NvmeRw(NvmeRwPayload {
                    lba,
                    blocks,
                    prp1,
                    prp2,
                    bytes: dma_len,
                });
                let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
                    self.file.io_device(),
                    IoOperationType::Write,
                    IoPriority::Normal,
                    payload,
                );
                let request_id = future.request_id();
                ctx.mark_inflight();
                let hook: CompletionHook = Box::new(move |_result| {
                    let _ = ctx.complete();
                });
                crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

                self.io_future = Some(future);
                self.dma_user_len = len;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let file_size = self.file.attr.lock().size;
            match write_via_page_cache(self.file.id, position, self.buf, file_size) {
                Ok(written) => {
                    self.file
                        .position
                        .fetch_add(written as u64, Ordering::Relaxed);
                    {
                        let mut attr = self.file.attr.lock();
                        let new_end = position + written as u64;
                        if new_end > attr.size {
                            attr.size = new_end;
                        }
                    }
                    return Poll::Ready(Ok(written));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        if let Some(future) = self.io_future.as_mut() {
            match Pin::new(future).poll(cx) {
                Poll::Ready(Ok(_)) => {
                    let len = self.dma_user_len;
                    let position = self.file.position.load(Ordering::Relaxed);
                    self.file.position.fetch_add(len as u64, Ordering::Relaxed);
                    {
                        let mut attr = self.file.attr.lock();
                        let new_end = position + len as u64;
                        if new_end > attr.size {
                            attr.size = new_end;
                        }
                    }
                    return Poll::Ready(Ok(len));
                }
                Poll::Ready(Err(_)) => return Poll::Ready(Err(FsError::IoError)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if let Some(state) = self.unaligned.take() {
            match state {
                UnalignedWriteState::Reading {
                    mut io_future,
                    data_slot,
                    lba,
                    blocks,
                    offset,
                    len,
                    start_pos,
                } => match Pin::new(&mut io_future).poll(cx) {
                    Poll::Ready(Ok(_)) => {
                        let mut data = match data_slot.data.lock().take() {
                            Some(data) => data,
                            None => return Poll::Ready(Err(FsError::IoError)),
                        };
                        let end = offset + len;
                        if end > data.len() {
                            return Poll::Ready(Err(FsError::InvalidArgument));
                        }
                        data.as_mut_slice()[offset..end].copy_from_slice(self.buf);

                        let dma_len = data.len();
                        let (mut write_ctx, prp1, prp2) = match prepare_dma_from_cpu_buffer(data) {
                            Ok(v) => v,
                            Err(e) => return Poll::Ready(Err(e)),
                        };
                        let payload = IoPayload::NvmeRw(NvmeRwPayload {
                            lba,
                            blocks,
                            prp1,
                            prp2,
                            bytes: dma_len,
                        });
                        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
                            self.file.io_device(),
                            IoOperationType::Write,
                            IoPriority::Normal,
                            payload,
                        );
                        let request_id = future.request_id();
                        write_ctx.mark_inflight();
                        let hook: CompletionHook = Box::new(move |_result| {
                            let _ = write_ctx.complete();
                        });
                        crate::io::io_scheduler::io_scheduler()
                            .register_completion_hook(request_id, hook);

                        self.unaligned = Some(UnalignedWriteState::Writing {
                            io_future: future,
                            len,
                            start_pos,
                        });
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(FsError::IoError)),
                    Poll::Pending => {
                        self.unaligned = Some(UnalignedWriteState::Reading {
                            io_future,
                            data_slot,
                            lba,
                            blocks,
                            offset,
                            len,
                            start_pos,
                        });
                        return Poll::Pending;
                    }
                },
                UnalignedWriteState::Writing {
                    mut io_future,
                    len,
                    start_pos,
                } => match Pin::new(&mut io_future).poll(cx) {
                    Poll::Ready(Ok(_)) => {
                        self.file.position.fetch_add(len as u64, Ordering::Relaxed);
                        {
                            let mut attr = self.file.attr.lock();
                            let new_end = start_pos + len as u64;
                            if new_end > attr.size {
                                attr.size = new_end;
                            }
                        }
                        return Poll::Ready(Ok(len));
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(FsError::IoError)),
                    Poll::Pending => {
                        self.unaligned = Some(UnalignedWriteState::Writing {
                            io_future,
                            len,
                            start_pos,
                        });
                        return Poll::Pending;
                    }
                },
            }
        }

        Poll::Ready(Ok(0))
    }
}

/// 非同期フラッシュFuture
pub struct AsyncFlushFuture<'a> {
    file: &'a AsyncFile,
    started: bool,
    io_future: Option<crate::io::io_scheduler::IoFuture>,
}

impl<'a> AsyncFlushFuture<'a> {
    fn new(file: &'a AsyncFile) -> Self {
        Self {
            file,
            started: false,
            io_future: None,
        }
    }
}

impl<'a> Future for AsyncFlushFuture<'a> {
    type Output = FsResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;

            if self.file.direct_io {
                let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
                    self.file.io_device(),
                    IoOperationType::Flush,
                    IoPriority::High,
                    IoPayload::None,
                );
                self.io_future = Some(future);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            return match flush_page_cache(self.file.id) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            };
        }

        if let Some(future) = self.io_future.as_mut() {
            return match Pin::new(future).poll(cx) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(_)) => Poll::Ready(Err(FsError::IoError)),
                Poll::Pending => Poll::Pending,
            };
        }

        Poll::Ready(Ok(()))
    }
}

/// 非同期同期Future
pub struct AsyncSyncFuture<'a> {
    file: &'a AsyncFile,
    started: bool,
    flush: Option<AsyncFlushFuture<'a>>,
}

impl<'a> AsyncSyncFuture<'a> {
    fn new(file: &'a AsyncFile) -> Self {
        Self {
            file,
            started: false,
            flush: None,
        }
    }
}

impl<'a> Future for AsyncSyncFuture<'a> {
    type Output = FsResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;

            // データとメタデータの同期
            // ダイレクトI/Oの場合は既に同期済み
            if self.file.direct_io {
                self.flush = Some(AsyncFlushFuture::new(self.file));
            } else {
                self.flush = Some(AsyncFlushFuture::new(self.file));
            }
        }

        if let Some(flush) = self.flush.as_mut() {
            return Pin::new(flush).poll(cx);
        }

        Poll::Ready(Ok(()))
    }
}

// ============================================================================
// ダイレクトブロックアクセス API
// 設計書 6.3: ファイルシステムをバイパスした直接アクセス
// ============================================================================

/// ダイレクトブロックデバイスハンドル
/// データベースなどのアプリケーション向けに、
/// ファイルシステムを通さずNVMeを直接操作
#[derive(Clone, Copy)]
pub struct DirectBlockHandle {
    /// デバイスID（NVMe namespace ID）
    device_id: u64,
    /// 開始ブロック
    start_block: u64,
    /// ブロック数
    block_count: u64,
    /// ブロックサイズ
    block_size: u32,
}

impl DirectBlockHandle {
    /// 新しいダイレクトブロックハンドルを作成
    pub fn new(device_id: u64, start_block: u64, block_count: u64, block_size: u32) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
        }
    }

    fn io_device(&self) -> IoDeviceId {
        IoDeviceId::Nvme {
            controller: 0,
            namespace: nsid_from_device(self.device_id),
        }
    }

    /// ブロック読み取り
    pub async fn read_blocks(&self, block_offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        if buf.len() % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks_to_read = buf.len() / self.block_size as usize;
        let blocks_available = (self.block_count - block_offset) as usize;
        let blocks = blocks_to_read.min(blocks_available);

        if blocks == 0 {
            return Ok(0);
        }

        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }

        let dma_len = blocks * self.block_size as usize;
        let (mut ctx, prp1, prp2) = prepare_dma_read(dma_len)?;
        let lba = self.start_block + block_offset;
        let canceled = Arc::new(AtomicBool::new(false));
        let mut cancel_guard = NvmeCancelGuard::new(canceled.clone());
        let slot = Arc::new(Mutex::new(None::<(TypedDmaSlice<CpuOwned>, usize)>));
        let slot_clone = slot.clone();
        let payload = IoPayload::NvmeRw(NvmeRwPayload {
            lba,
            blocks: blocks as u16,
            prp1,
            prp2,
            bytes: dma_len,
        });
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
            self.io_device(),
            IoOperationType::Read,
            IoPriority::Normal,
            payload,
        );
        let request_id = future.request_id();

        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |result| {
            let data = ctx.complete();
            if canceled.load(Ordering::Acquire) {
                return;
            }
            if let IoResult::Success(bytes) = result {
                *slot_clone.lock() = Some((data, bytes));
            }
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        cancel_guard.disarm();
        match result {
            Ok(_reported) => {
                let mut guard = slot.lock();
                let (data, bytes_received) = guard.take().ok_or(FsError::IoError)?;
                let copy_len = bytes_received.min(dma_len).min(buf.len());
                if copy_len > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_slice().as_ptr(), buf.as_mut_ptr(), copy_len);
                    }
                }
                Ok(copy_len)
            }
            Err(_) => Err(FsError::IoError),
        }
    }

    /// DMAバッファへのブロック読み取り
    pub async fn read_blocks_dma(
        &self,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> FsResult<DmaBuffer> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        if buffer.size() == 0 {
            return Ok(buffer);
        }

        if buffer.size() % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks = buffer.size() / self.block_size as usize;
        if blocks == 0 {
            return Ok(buffer);
        }
        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }
        if blocks as u64 > self.block_count - block_offset {
            return Err(FsError::InvalidArgument);
        }

        let (mut ctx, prp1, prp2) = prepare_dma_from_kapi_buffer(&buffer)?;
        let lba = self.start_block + block_offset;
        let payload = IoPayload::NvmeRw(NvmeRwPayload {
            lba,
            blocks: blocks as u16,
            prp1,
            prp2,
            bytes: blocks * self.block_size as usize,
        });
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
            self.io_device(),
            IoOperationType::Read,
            IoPriority::Normal,
            payload,
        );
        let request_id = future.request_id();
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |_result| {
            ctx.complete();
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(_) => Ok(buffer),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// Scatter-Gather DMAバッファへのブロック読み取り
    pub async fn read_blocks_sg_dma(
        &self,
        block_offset: u64,
        mut list: TypedSgList<CpuOwned>,
    ) -> FsResult<TypedSgList<CpuOwned>> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }
        if list.is_empty() {
            return Ok(list);
        }

        let total_bytes = sg_total_bytes(&list)?;
        if total_bytes == 0 {
            return Ok(list);
        }
        if total_bytes % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks_u64 = total_bytes as u64 / self.block_size as u64;
        if blocks_u64 > u16::MAX as u64 {
            return Err(FsError::InvalidArgument);
        }
        if blocks_u64 > self.block_count - block_offset {
            return Err(FsError::InvalidArgument);
        }

        if let Some(max_entries) = nvme_sgl_max_entries() {
            let max_entries = max_entries.min(NVME_MAX_SGL_ENTRIES).max(1);
            if list.len() <= max_entries {
                let blocks = blocks_u64 as u16;
                let lba = self.start_block + block_offset;
                let (mut ctx, sgl, bytes) = prepare_nvme_sgl(list, max_entries)?;
                let payload = IoPayload::NvmeSgl(NvmeSglPayload {
                    lba,
                    blocks,
                    sgl,
                    bytes,
                });
                let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
                    self.io_device(),
                    IoOperationType::Read,
                    IoPriority::Normal,
                    payload,
                );
                let request_id = future.request_id();
                let slot = Arc::new(Mutex::new(None));
                let slot_clone = slot.clone();
                ctx.mark_inflight();
                let hook: CompletionHook = Box::new(move |result| {
                    let data = ctx.complete();
                    if let IoResult::Success(_) = result {
                        *slot_clone.lock() = Some(data);
                    }
                });
                crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

                let result = future.await;
                return match result {
                    Ok(_) => slot
                        .lock()
                        .take()
                        .ok_or(FsError::IoError),
                    Err(_) => Err(FsError::IoError),
                };
            }
        }

        let mut bounce = vec![0u8; total_bytes];
        let read_len = self.read_blocks(block_offset, &mut bounce).await?;
        sg_copy_from_vec(&mut list, &bounce[..read_len])?;
        Ok(list)
    }

    /// ブロック書き込み
    pub async fn write_blocks(&self, block_offset: u64, buf: &[u8]) -> FsResult<usize> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        if buf.len() % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks_to_write = buf.len() / self.block_size as usize;
        let blocks_available = (self.block_count - block_offset) as usize;
        let blocks = blocks_to_write.min(blocks_available);

        if blocks == 0 {
            return Ok(0);
        }

        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }

        let dma_len = blocks * self.block_size as usize;
        let (mut ctx, prp1, prp2) = prepare_dma_write(buf, dma_len)?;
        let lba = self.start_block + block_offset;
        let payload = IoPayload::NvmeRw(NvmeRwPayload {
            lba,
            blocks: blocks as u16,
            prp1,
            prp2,
            bytes: dma_len,
        });
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
            self.io_device(),
            IoOperationType::Write,
            IoPriority::Normal,
            payload,
        );
        let request_id = future.request_id();
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |_result| {
            let _ = ctx.complete();
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// Scatter-Gather DMAバッファからのブロック書き込み
    pub async fn write_blocks_sg_dma(
        &self,
        block_offset: u64,
        list: TypedSgList<CpuOwned>,
    ) -> FsResult<TypedSgList<CpuOwned>> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }
        if list.is_empty() {
            return Ok(list);
        }

        let total_bytes = sg_total_bytes(&list)?;
        if total_bytes == 0 {
            return Ok(list);
        }
        if total_bytes % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks_u64 = total_bytes as u64 / self.block_size as u64;
        if blocks_u64 > u16::MAX as u64 {
            return Err(FsError::InvalidArgument);
        }
        if blocks_u64 > self.block_count - block_offset {
            return Err(FsError::InvalidArgument);
        }

        if let Some(max_entries) = nvme_sgl_max_entries() {
            let max_entries = max_entries.min(NVME_MAX_SGL_ENTRIES).max(1);
            if list.len() <= max_entries {
                let blocks = blocks_u64 as u16;
                let lba = self.start_block + block_offset;
                let (mut ctx, sgl, bytes) = prepare_nvme_sgl(list, max_entries)?;
                let payload = IoPayload::NvmeSgl(NvmeSglPayload {
                    lba,
                    blocks,
                    sgl,
                    bytes,
                });
                let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
                    self.io_device(),
                    IoOperationType::Write,
                    IoPriority::Normal,
                    payload,
                );
                let request_id = future.request_id();
                let slot = Arc::new(Mutex::new(None));
                let slot_clone = slot.clone();
                ctx.mark_inflight();
                let hook: CompletionHook = Box::new(move |result| {
                    let data = ctx.complete();
                    if let IoResult::Success(_) = result {
                        *slot_clone.lock() = Some(data);
                    }
                });
                crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

                let result = future.await;
                return match result {
                    Ok(_) => slot
                        .lock()
                        .take()
                        .ok_or(FsError::IoError),
                    Err(_) => Err(FsError::IoError),
                };
            }
        }

        let bounce = sg_copy_to_vec(&list)?;
        let _ = self.write_blocks(block_offset, &bounce).await?;
        Ok(list)
    }

    /// Scatter-Gatherリクエストを非同期スケジューラに送信
    pub fn submit_sg_request(&self, request: Arc<SgIoRequest>) -> SgIoFuture {
        async_io_scheduler().submit_sg_request(*self, request)
    }

    async fn execute_sg_request(&self, request: &SgIoRequest) -> FsResult<usize> {
        if request.entries.is_empty() {
            return Ok(0);
        }

        if request.offset % (self.block_size as u64) != 0 {
            return Err(FsError::InvalidArgument);
        }

        let total_bytes = request.total_bytes();
        if total_bytes == 0 {
            return Ok(0);
        }
        if total_bytes % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let block_offset = request.offset / (self.block_size as u64);
        let list = sg_request_to_dma_list(request)?;

        if request.is_read {
            let list = self.read_blocks_sg_dma(block_offset, list).await?;
            sg_request_copy_back(request, &list, total_bytes)?;
        } else {
            let _ = self.write_blocks_sg_dma(block_offset, list).await?;
        }

        Ok(total_bytes)
    }

    /// DMAバッファからのブロック書き込み
    pub async fn write_blocks_dma(
        &self,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> FsResult<DmaBuffer> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        if buffer.size() == 0 {
            return Ok(buffer);
        }

        if buffer.size() % self.block_size as usize != 0 {
            return Err(FsError::InvalidArgument);
        }

        let blocks = buffer.size() / self.block_size as usize;
        if blocks == 0 {
            return Ok(buffer);
        }
        if blocks > u16::MAX as usize {
            return Err(FsError::InvalidArgument);
        }
        if blocks as u64 > self.block_count - block_offset {
            return Err(FsError::InvalidArgument);
        }

        let (mut ctx, prp1, prp2) = prepare_dma_from_kapi_buffer(&buffer)?;
        let lba = self.start_block + block_offset;
        let payload = IoPayload::NvmeRw(NvmeRwPayload {
            lba,
            blocks: blocks as u16,
            prp1,
            prp2,
            bytes: blocks * self.block_size as usize,
        });
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
            self.io_device(),
            IoOperationType::Write,
            IoPriority::Normal,
            payload,
        );
        let request_id = future.request_id();
        ctx.mark_inflight();
        let hook: CompletionHook = Box::new(move |_result| {
            ctx.complete();
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(_) => Ok(buffer),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// フラッシュ
    pub async fn flush(&self) -> FsResult<()> {
        let result = crate::io::io_scheduler::hybrid_coordinator()
            .submit_io_with_payload(
                self.io_device(),
                IoOperationType::Flush,
                IoPriority::High,
                IoPayload::None,
            )
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(FsError::IoError),
        }
    }

    /// TRIM（Discard）
    pub async fn discard(&self, block_offset: u64, block_count: u64) -> FsResult<()> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        let count = block_count.min(self.block_count - block_offset);
        if count == 0 {
            return Ok(());
        }
        if count > u32::MAX as u64 {
            return Err(FsError::InvalidArgument);
        }

        let mut dsm = TypedDmaSlice::<CpuOwned>::new(NVME_PAGE_SIZE)
            .ok_or(FsError::NoSpace)?;
        let range = crate::io::nvme::commands::DsmRange::new(
            self.start_block + block_offset,
            count as u32,
        );
        let dsm_bytes = dsm.as_mut_slice();
        let dst = unsafe {
            core::slice::from_raw_parts_mut(
                dsm_bytes.as_mut_ptr() as *mut crate::io::nvme::commands::DsmRange,
                1,
            )
        };
        dst[0] = range;

        let device = crate::io::nvme::iommu_device();
        let (prp1, prp_map) = map_nvme_iommu(device, dsm.phys_addr().as_u64(), dsm.len())?;
        let prp_map = prp_map;
        let (dev, guard) = dsm.start_dma();
        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_with_payload(
            self.io_device(),
            IoOperationType::Custom(0),
            IoPriority::High,
            IoPayload::NvmeDsm(NvmeDsmPayload { prp1, nr: 0 }),
        );
        let request_id = future.request_id();
        let hook: CompletionHook = Box::new(move |_result| {
            let _ = guard.complete(dev);
            if let Some(map) = prp_map {
                map.unmap();
            }
        });
        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, hook);

        let result = future.await;
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(FsError::IoError),
        }
    }
}

// ============================================================================
// Scatter-Gather I/O
// ============================================================================

/// Scatter-Gatherエントリ
#[derive(Debug, Clone)]
pub struct SgEntry {
    /// バッファアドレス
    pub addr: usize,
    /// 長さ
    pub len: usize,
}

/// Scatter-Gather I/O リクエスト
pub struct SgIoRequest {
    /// リクエストID
    pub id: u64,
    /// 読み取り/書き込み
    pub is_read: bool,
    /// オフセット
    pub offset: u64,
    /// SGエントリリスト
    pub entries: Vec<SgEntry>,
    /// 完了フラグ
    completed: AtomicBool,
    /// 結果
    result: Mutex<Option<FsResult<usize>>>,
    /// Waker
    waker: Mutex<Option<Waker>>,
}

impl SgIoRequest {
    /// 新しいSG I/Oリクエストを作成
    pub fn new(id: u64, is_read: bool, offset: u64, entries: Vec<SgEntry>) -> Self {
        Self {
            id,
            is_read,
            offset,
            entries,
            completed: AtomicBool::new(false),
            result: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }

    /// 総バイト数を計算
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.len).sum()
    }

    /// 完了をマーク
    pub fn complete(&self, result: FsResult<usize>) {
        *self.result.lock() = Some(result);
        self.completed.store(true, Ordering::Release);

        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    /// 完了したか
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    /// Futureを取得
    pub fn into_future(self: Arc<Self>) -> SgIoFuture {
        SgIoFuture::new(self)
    }
}

/// Scatter-Gather I/O Future
pub struct SgIoFuture {
    request: Arc<SgIoRequest>,
}

impl SgIoFuture {
    fn new(request: Arc<SgIoRequest>) -> Self {
        Self { request }
    }

    pub fn request_id(&self) -> u64 {
        self.request.id
    }
}

impl Future for SgIoFuture {
    type Output = FsResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.request.completed.load(Ordering::Acquire) {
            let result = self
                .request
                .result
                .lock()
                .take()
                .unwrap_or(Err(FsError::IoError));
            return Poll::Ready(result);
        }

        {
            let mut slot = self.request.waker.lock();
            let replace = match slot.as_ref() {
                Some(existing) => !existing.will_wake(cx.waker()),
                None => true,
            };
            if replace {
                *slot = Some(cx.waker().clone());
            }
        }

        if self.request.completed.load(Ordering::Acquire) {
            let result = self
                .request
                .result
                .lock()
                .take()
                .unwrap_or(Err(FsError::IoError));
            return Poll::Ready(result);
        }

        Poll::Pending
    }
}

fn sg_request_to_dma_list(request: &SgIoRequest) -> FsResult<TypedSgList<CpuOwned>> {
    let mut list = TypedSgList::new();

    for entry in &request.entries {
        if entry.len == 0 {
            return Err(FsError::InvalidArgument);
        }
        let idx = list.add_buffer(entry.len).ok_or(FsError::NoSpace)?;
        if !request.is_read {
            // Safety: caller provides valid source buffers in SgEntry.
            let src = unsafe { core::slice::from_raw_parts(entry.addr as *const u8, entry.len) };
            let dst = list
                .buffer_mut(idx)
                .ok_or(FsError::InvalidArgument)?;
            dst.as_mut_slice().copy_from_slice(src);
        }
    }

    Ok(list)
}

fn sg_request_copy_back(
    request: &SgIoRequest,
    list: &TypedSgList<CpuOwned>,
    bytes: usize,
) -> FsResult<()> {
    let mut remaining = bytes;

    for (idx, entry) in request.entries.iter().enumerate() {
        let src = list.buffer(idx).ok_or(FsError::InvalidArgument)?;
        let copy_len = entry.len.min(remaining);
        unsafe {
            // Safety: caller provides valid destination buffers in SgEntry.
            core::ptr::copy_nonoverlapping(
                src.as_slice().as_ptr(),
                entry.addr as *mut u8,
                copy_len,
            );
        }
        if copy_len < entry.len {
            unsafe {
                // Safety: caller provides valid destination buffers in SgEntry.
                core::ptr::write_bytes(
                    (entry.addr as *mut u8).add(copy_len),
                    0,
                    entry.len - copy_len,
                );
            }
        }
        remaining = remaining.saturating_sub(copy_len);
    }

    Ok(())
}

// ============================================================================
// I/Oスケジューラ統合
// ============================================================================

/// 非同期I/Oスケジューラ
pub struct AsyncIoScheduler {
    /// 保留中のリクエスト
    pending: Mutex<BTreeMap<u64, Arc<AsyncIoRequest>>>,
    /// 保留中のSGリクエスト
    pending_sg: Mutex<BTreeMap<u64, Arc<SgIoRequest>>>,
    /// 完了したリクエスト
    completed: Mutex<Vec<Arc<AsyncIoRequest>>>,
    /// 完了済みリクエストIDキュー
    completed_ids: Mutex<Vec<u64>>,
    /// 次のリクエストID
    next_id: AtomicU64,
    /// 統計: 発行リクエスト数
    requests_issued: AtomicU64,
    /// 統計: 完了リクエスト数
    requests_completed: AtomicU64,
}

impl AsyncIoScheduler {
    /// 新しいスケジューラを作成
    pub const fn new() -> Self {
        Self {
            pending: Mutex::new(BTreeMap::new()),
            pending_sg: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(Vec::new()),
            completed_ids: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            requests_issued: AtomicU64::new(0),
            requests_completed: AtomicU64::new(0),
        }
    }

    /// リクエストを発行
    pub fn submit(&self, request: Arc<AsyncIoRequest>) {
        self.pending.lock().insert(request.id, request);
        self.requests_issued.fetch_add(1, Ordering::Relaxed);
    }

    /// Scatter-Gatherリクエストを発行
    pub fn submit_sg_request(
        &self,
        handle: DirectBlockHandle,
        request: Arc<SgIoRequest>,
    ) -> SgIoFuture {
        let request_id = request.id;
        self.pending_sg.lock().insert(request_id, request.clone());
        self.requests_issued.fetch_add(1, Ordering::Relaxed);
        let future = SgIoFuture::new(request.clone());
        let task_request = request.clone();

        crate::task::spawn(async move {
            let result = handle.execute_sg_request(&task_request).await;
            task_request.complete(result);
            async_io_scheduler().complete_sg_request(request_id);
        });
        future
    }

    fn complete_sg_request(&self, request_id: u64) {
        self.pending_sg.lock().remove(&request_id);
        self.requests_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// 完了したリクエストを処理
    pub fn process_completions(&self) {
        let mut pending = self.pending.lock();
        let mut completed = self.completed.lock();
        let mut completed_ids = self.completed_ids.lock();

        for request_id in completed_ids.drain(..) {
            if let Some(req) = pending.remove(&request_id) {
                completed.push(req);
                self.requests_completed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 完了したリクエストIDを登録
    pub fn mark_completed(&self, request_id: u64) {
        self.completed_ids.lock().push(request_id);
    }

    /// 統計を取得
    pub fn stats(&self) -> IoSchedulerStats {
        IoSchedulerStats {
            requests_issued: self.requests_issued.load(Ordering::Relaxed),
            requests_completed: self.requests_completed.load(Ordering::Relaxed),
            pending_count: self.pending.lock().len() + self.pending_sg.lock().len(),
        }
    }
}

/// I/Oスケジューラ統計
#[derive(Debug, Clone)]
pub struct IoSchedulerStats {
    pub requests_issued: u64,
    pub requests_completed: u64,
    pub pending_count: usize,
}

// ============================================================================
// ヘルパー関数
// ============================================================================

/// リクエストIDを生成
fn generate_request_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

// ============================================================================
// グローバルインスタンス
// ============================================================================

/// グローバル非同期I/Oスケジューラ
static ASYNC_IO_SCHEDULER: AsyncIoScheduler = AsyncIoScheduler::new();

/// 非同期I/Oスケジューラを取得
pub fn async_io_scheduler() -> &'static AsyncIoScheduler {
    &ASYNC_IO_SCHEDULER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_async_file_seek() {
        let attr = FileAttr {
            size: 1000,
            ..Default::default()
        };
        let file = AsyncFile::new(1, attr, true, true);

        // Start
        assert_eq!(file.seek(SeekFrom::Start(100)).unwrap(), 100);
        assert_eq!(file.position(), 100);

        // Current
        assert_eq!(file.seek(SeekFrom::Current(50)).unwrap(), 150);
        assert_eq!(file.seek(SeekFrom::Current(-30)).unwrap(), 120);

        // End
        assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), 1000);
        assert_eq!(file.seek(SeekFrom::End(-100)).unwrap(), 900);
    }

    #[test]
    fn test_direct_block_handle() {
        let handle = DirectBlockHandle::new(0, 0, 1000, 512);
        assert_eq!(handle.block_size, 512);
        assert_eq!(handle.block_count, 1000);
    }
}
