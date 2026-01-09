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

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;
use x86_64::PhysAddr;

use super::cache::{page_cache, PAGE_SIZE as CACHE_PAGE_SIZE};
use super::vfs::{
    read_inode_by_number, write_inode_by_number, FileAttr, FsError, FsResult, SeekFrom,
};

// NVMe per-core API
use crate::io::nvme::global as nvme_global;
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::dma::{CpuOwned, DeviceOwned, SliceDmaGuard, TypedDmaSlice};
use crate::smp::current_cpu;

const NVME_PAGE_SIZE: usize = 4096;
const NVME_BLOCK_SIZE: u64 = 512;

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
    data_dev: TypedDmaSlice<DeviceOwned>,
    data_guard: SliceDmaGuard,
    prp_list: Option<NvmePrpListChain>,
    data_map: Option<NvmeIommuMapping>,
}

impl NvmeDmaContext {
    fn complete(self) -> TypedDmaSlice<CpuOwned> {
        if let Some(prp) = self.prp_list {
            prp.complete();
        }
        let data = self.data_guard.complete(self.data_dev);
        if let Some(map) = self.data_map {
            map.unmap();
        }
        data
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
            data_dev,
            data_guard,
            prp_list,
            data_map,
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
            data_dev,
            data_guard,
            prp_list,
            data_map,
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
            data_dev,
            data_guard,
            prp_list,
            data_map,
        },
        data_addr,
        prp2,
    ))
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
    request_id: Option<u64>,
    dma_ctx: Option<NvmeDmaContext>,
    dma_user_len: usize,
    dma_offset: usize,
}

impl<'a> AsyncReadFuture<'a> {
    fn new(file: &'a AsyncFile, buf: &'a mut [u8]) -> Self {
        Self {
            file,
            buf,
            started: false,
            request_id: None,
            dma_ctx: None,
            dma_user_len: 0,
            dma_offset: 0,
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
                let core_id = current_cpu();
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
                let nsid = nsid_from_device(self.file.device_id);

                let (ctx, prp1, prp2) = match prepare_dma_read(dma_len) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };

                // NVMeドライバ経由でリードコマンドを発行
                let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.submit_read(core_id, nsid, lba, blocks, prp1, prp2) }
                });

                match result {
                    Some(Ok(cid)) => {
                        self.request_id = Some(cid as u64);
                        self.dma_ctx = Some(ctx);
                        self.dma_user_len = to_read;
                        self.dma_offset = offset_in_block;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Some(Err(_)) | None => {
                        let _ = ctx.complete();
                        return Poll::Ready(Err(FsError::IoError));
                    }
                }
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

        // リクエストの完了を確認 (Polling/Interrupt対応)
        if let Some(request_id) = self.request_id {
            let core_id = current_cpu();

            let completed = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                if !driver.interrupt_mode() {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.poll_loop(core_id) };
                }
                driver.take_completion(core_id, request_id as u16)
            });

            if let Some(Some(cqe)) = completed {
                if cqe.is_success() {
                    if let Some(ctx) = self.dma_ctx.take() {
                        let data = ctx.complete();
                        let start = self.dma_offset;
                        let end = start + self.dma_user_len;
                        self.buf[..self.dma_user_len]
                            .copy_from_slice(&data.as_slice()[start..end]);
                    }
                    self.file
                        .position
                        .fetch_add(self.dma_user_len as u64, Ordering::Relaxed);
                    return Poll::Ready(Ok(self.dma_user_len));
                }

                if let Some(ctx) = self.dma_ctx.take() {
                    let _ = ctx.complete();
                }
                return Poll::Ready(Err(FsError::IoError));
            }

            let interrupt_mode =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.interrupt_mode()
                })
                .unwrap_or(false);

            if interrupt_mode {
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.register_waker(core_id, request_id as u16, cx.waker().clone());
                });

                let completed_retry =
                    nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                        driver.take_completion(core_id, request_id as u16)
                    });

                if let Some(Some(cqe)) = completed_retry {
                    if cqe.is_success() {
                        if let Some(ctx) = self.dma_ctx.take() {
                            let data = ctx.complete();
                            let start = self.dma_offset;
                            let end = start + self.dma_user_len;
                            self.buf[..self.dma_user_len]
                                .copy_from_slice(&data.as_slice()[start..end]);
                        }
                        self.file
                            .position
                            .fetch_add(self.dma_user_len as u64, Ordering::Relaxed);
                        return Poll::Ready(Ok(self.dma_user_len));
                    }

                    if let Some(ctx) = self.dma_ctx.take() {
                        let _ = ctx.complete();
                    }
                    return Poll::Ready(Err(FsError::IoError));
                }
            } else {
                cx.waker().wake_by_ref();
            }

            Poll::Pending
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

/// 非同期書き込みFuture
pub struct AsyncWriteFuture<'a> {
    file: &'a AsyncFile,
    buf: &'a [u8],
    started: bool,
    request_id: Option<u64>,
    dma_ctx: Option<NvmeDmaContext>,
    dma_user_len: usize,
    unaligned: Option<UnalignedWriteState>,
}

enum UnalignedWriteState {
    Reading {
        ctx: NvmeDmaContext,
        lba: u64,
        blocks: u16,
        offset: usize,
        len: usize,
        start_pos: u64,
    },
    Writing {
        ctx: NvmeDmaContext,
        lba: u64,
        blocks: u16,
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
            request_id: None,
            dma_ctx: None,
            dma_user_len: 0,
            unaligned: None,
        }
    }

    fn handle_unaligned_completion(
        &mut self,
        state: UnalignedWriteState,
        cqe: crate::io::nvme::NvmeCompletion,
        cx: &mut Context<'_>,
    ) -> Poll<FsResult<usize>> {
        if !cqe.is_success() {
            match state {
                UnalignedWriteState::Reading { ctx, .. }
                | UnalignedWriteState::Writing { ctx, .. } => {
                    let _ = ctx.complete();
                }
            }
            return Poll::Ready(Err(FsError::IoError));
        }

        match state {
            UnalignedWriteState::Reading {
                ctx,
                lba,
                blocks,
                offset,
                len,
                start_pos,
            } => {
                let mut data = ctx.complete();
                let end = offset + len;
                if end > data.len() {
                    return Poll::Ready(Err(FsError::InvalidArgument));
                }
                data.as_mut_slice()[offset..end].copy_from_slice(self.buf);

                let (write_ctx, prp1, prp2) = match prepare_dma_from_cpu_buffer(data) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };

                let core_id = current_cpu();
                let nsid = nsid_from_device(self.file.device_id);
                let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.submit_write(core_id, nsid, lba, blocks, prp1, prp2) }
                });

                match result {
                    Some(Ok(cid)) => {
                        self.request_id = Some(cid as u64);
                        self.unaligned = Some(UnalignedWriteState::Writing {
                            ctx: write_ctx,
                            lba,
                            blocks,
                            len,
                            start_pos,
                        });
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Some(Err(_)) | None => {
                        let _ = write_ctx.complete();
                        Poll::Ready(Err(FsError::IoError))
                    }
                }
            }
            UnalignedWriteState::Writing { ctx, len, start_pos, .. } => {
                let _ = ctx.complete();
                self.file.position.fetch_add(len as u64, Ordering::Relaxed);
                {
                    let mut attr = self.file.attr.lock();
                    let new_end = start_pos + len as u64;
                    if new_end > attr.size {
                        attr.size = new_end;
                    }
                }
                Poll::Ready(Ok(len))
            }
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
                let core_id = current_cpu();
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
                    let nsid = nsid_from_device(self.file.device_id);

                    let (ctx, prp1, prp2) = match prepare_dma_read(dma_len) {
                        Ok(v) => v,
                        Err(e) => return Poll::Ready(Err(e)),
                    };

                    let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                        // Safety: 現在のコアIDで自身のキューにアクセス
                        unsafe { driver.submit_read(core_id, nsid, lba, blocks, prp1, prp2) }
                    });

                    match result {
                        Some(Ok(cid)) => {
                            self.request_id = Some(cid as u64);
                            self.unaligned = Some(UnalignedWriteState::Reading {
                                ctx,
                                lba,
                                blocks,
                                offset: offset_in_block,
                                len,
                                start_pos: position,
                            });
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Some(Err(_)) | None => {
                            let _ = ctx.complete();
                            return Poll::Ready(Err(FsError::IoError));
                        }
                    }
                }

                let blocks_u64 = len as u64 / block_size;
                if blocks_u64 > u16::MAX as u64 {
                    return Poll::Ready(Err(FsError::InvalidArgument));
                }
                let blocks = blocks_u64 as u16;
                let dma_len = (blocks as usize) * (block_size as usize);
                let lba = self.file.start_block + (position / block_size);
                let nsid = nsid_from_device(self.file.device_id);

                let (ctx, prp1, prp2) = match prepare_dma_write(self.buf, dma_len) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };

                // NVMeドライバ経由でライトコマンドを発行
                let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.submit_write(core_id, nsid, lba, blocks, prp1, prp2) }
                });

                match result {
                    Some(Ok(cid)) => {
                        self.request_id = Some(cid as u64);
                        self.dma_ctx = Some(ctx);
                        self.dma_user_len = len;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Some(Err(_)) | None => {
                        let _ = ctx.complete();
                        return Poll::Ready(Err(FsError::IoError));
                    }
                }
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

        if let Some(state) = self.unaligned.take() {
            let core_id = current_cpu();
            let request_id = match self.request_id {
                Some(id) => id as u16,
                None => return Poll::Ready(Err(FsError::IoError)),
            };

            let completed = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                if !driver.interrupt_mode() {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.poll_loop(core_id) };
                }
                driver.take_completion(core_id, request_id)
            });

            if completed.is_none() {
                return Poll::Ready(Err(FsError::IoError));
            }

            if let Some(Some(cqe)) = completed {
                return self.handle_unaligned_completion(state, cqe, cx);
            }

            let interrupt_mode =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.interrupt_mode()
                })
                .unwrap_or(false);

            if interrupt_mode {
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.register_waker(core_id, request_id, cx.waker().clone());
                });

                let completed_retry =
                    nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                        driver.take_completion(core_id, request_id)
                    });

                if let Some(Some(cqe)) = completed_retry {
                    return self.handle_unaligned_completion(state, cqe, cx);
                }
            } else {
                cx.waker().wake_by_ref();
            }

            self.unaligned = Some(state);
            return Poll::Pending;
        }

        // 完了確認 (Polling/Interrupt対応)
        if let Some(request_id) = self.request_id {
            let core_id = current_cpu();

            let completed = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                if !driver.interrupt_mode() {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.poll_loop(core_id) };
                }
                driver.take_completion(core_id, request_id as u16)
            });

            if let Some(Some(cqe)) = completed {
                if cqe.is_success() {
                    if let Some(ctx) = self.dma_ctx.take() {
                        let _ = ctx.complete();
                    }
                    let position = self.file.position.load(Ordering::Relaxed);
                    let len = self.dma_user_len;
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

                if let Some(ctx) = self.dma_ctx.take() {
                    let _ = ctx.complete();
                }
                return Poll::Ready(Err(FsError::IoError));
            }

            let interrupt_mode =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.interrupt_mode()
                })
                .unwrap_or(false);

            if interrupt_mode {
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.register_waker(core_id, request_id as u16, cx.waker().clone());
                });

                let completed_retry =
                    nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                        driver.take_completion(core_id, request_id as u16)
                    });

                if let Some(Some(cqe)) = completed_retry {
                    if cqe.is_success() {
                        if let Some(ctx) = self.dma_ctx.take() {
                            let _ = ctx.complete();
                        }
                        let position = self.file.position.load(Ordering::Relaxed);
                        let len = self.dma_user_len;
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

                    if let Some(ctx) = self.dma_ctx.take() {
                        let _ = ctx.complete();
                    }
                    return Poll::Ready(Err(FsError::IoError));
                }
            } else {
                cx.waker().wake_by_ref();
            }

            Poll::Pending
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

/// 非同期フラッシュFuture
pub struct AsyncFlushFuture<'a> {
    file: &'a AsyncFile,
    started: bool,
    request_id: Option<u64>,
}

impl<'a> AsyncFlushFuture<'a> {
    fn new(file: &'a AsyncFile) -> Self {
        Self {
            file,
            started: false,
            request_id: None,
        }
    }
}

impl<'a> Future for AsyncFlushFuture<'a> {
    type Output = FsResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;

            if self.file.direct_io {
                let core_id = current_cpu();
                let nsid = nsid_from_device(self.file.device_id);
                let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.submit_flush(core_id, nsid) }
                });

                match result {
                    Some(Ok(cid)) => {
                        self.request_id = Some(cid as u64);
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Some(Err(_)) | None => {
                        return Poll::Ready(Err(FsError::IoError));
                    }
                }
            }

            return match flush_page_cache(self.file.id) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            };
        }

        if let Some(request_id) = self.request_id {
            let core_id = current_cpu();

            let completed = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                if !driver.interrupt_mode() {
                    // Safety: 現在のコアIDで自身のキューにアクセス
                    unsafe { driver.poll_loop(core_id) };
                }
                driver.take_completion(core_id, request_id as u16)
            });

            if let Some(Some(cqe)) = completed {
                if cqe.is_success() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(FsError::IoError));
            }

            let interrupt_mode =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.interrupt_mode()
                })
                .unwrap_or(false);

            if interrupt_mode {
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    driver.register_waker(core_id, request_id as u16, cx.waker().clone());
                });

                let completed_retry =
                    nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                        driver.take_completion(core_id, request_id as u16)
                    });

                if let Some(Some(cqe)) = completed_retry {
                    if cqe.is_success() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(FsError::IoError));
                }
            } else {
                cx.waker().wake_by_ref();
            }

            return Poll::Pending;
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
        let (ctx, prp1, prp2) = prepare_dma_read(dma_len)?;
        let core_id = current_cpu();
        let lba = self.start_block + block_offset;
        let nsid = nsid_from_device(self.device_id);

        let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
            // Safety: 現在のコアIDで自身のキューにアクセス
            unsafe { driver.submit_read(core_id, nsid, lba, blocks as u16, prp1, prp2) }
        });

        let cid = match result {
            Some(Ok(cid)) => cid,
            _ => {
                let _ = ctx.complete();
                return Err(FsError::IoError);
            }
        };

        loop {
            let completed =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    if !driver.interrupt_mode() {
                        // Safety: 現在のコアIDで自身のキューにアクセス
                        unsafe { driver.poll_loop(core_id) };
                    }
                    driver.take_completion(core_id, cid)
                });

            if completed.is_none() {
                let _ = ctx.complete();
                return Err(FsError::IoError);
            }

            if let Some(Some(cqe)) = completed {
                if cqe.is_success() {
                    let data = ctx.complete();
                    buf[..dma_len].copy_from_slice(&data.as_slice()[..dma_len]);
                    return Ok(dma_len);
                }

                let _ = ctx.complete();
                return Err(FsError::IoError);
            }

            crate::task::yield_now().await;
        }
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
        let (ctx, prp1, prp2) = prepare_dma_write(buf, dma_len)?;
        let core_id = current_cpu();
        let lba = self.start_block + block_offset;
        let nsid = nsid_from_device(self.device_id);

        let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
            // Safety: 現在のコアIDで自身のキューにアクセス
            unsafe { driver.submit_write(core_id, nsid, lba, blocks as u16, prp1, prp2) }
        });

        let cid = match result {
            Some(Ok(cid)) => cid,
            _ => {
                let _ = ctx.complete();
                return Err(FsError::IoError);
            }
        };

        loop {
            let completed =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    if !driver.interrupt_mode() {
                        // Safety: 現在のコアIDで自身のキューにアクセス
                        unsafe { driver.poll_loop(core_id) };
                    }
                    driver.take_completion(core_id, cid)
                });

            if completed.is_none() {
                let _ = ctx.complete();
                return Err(FsError::IoError);
            }

            if let Some(Some(cqe)) = completed {
                let _ = ctx.complete();
                return if cqe.is_success() {
                    Ok(dma_len)
                } else {
                    Err(FsError::IoError)
                };
            }

            crate::task::yield_now().await;
        }
    }

    /// フラッシュ
    pub async fn flush(&self) -> FsResult<()> {
        let core_id = current_cpu();
        let nsid = nsid_from_device(self.device_id);
        let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
            // Safety: 現在のコアIDで自身のキューにアクセス
            unsafe { driver.submit_flush(core_id, nsid) }
        });

        let cid = match result {
            Some(Ok(cid)) => cid,
            _ => return Err(FsError::IoError),
        };

        loop {
            let completed =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    if !driver.interrupt_mode() {
                        // Safety: 現在のコアIDで自身のキューにアクセス
                        unsafe { driver.poll_loop(core_id) };
                    }
                    driver.take_completion(core_id, cid)
                });

            if let Some(Some(cqe)) = completed {
                return if cqe.is_success() {
                    Ok(())
                } else {
                    Err(FsError::IoError)
                };
            }

            crate::task::yield_now().await;
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
        let mut prp_map = prp_map;
        let (dev, guard) = dsm.start_dma();
        let core_id = current_cpu();
        let nsid = nsid_from_device(self.device_id);

        let result = nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
            // Safety: 現在のコアIDで自身のキューにアクセス
            unsafe { driver.submit_dataset_management(core_id, nsid, 0, prp1) }
        });

        let cid = match result {
            Some(Ok(cid)) => cid,
            _ => {
                let _ = guard.complete(dev);
                if let Some(map) = prp_map.take() {
                    map.unmap();
                }
                return Err(FsError::IoError);
            }
        };

        loop {
            let completed =
                nvme_global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
                    if !driver.interrupt_mode() {
                        // Safety: 現在のコアIDで自身のキューにアクセス
                        unsafe { driver.poll_loop(core_id) };
                    }
                    driver.take_completion(core_id, cid)
                });

            if let Some(Some(cqe)) = completed {
                let _ = guard.complete(dev);
                if let Some(map) = prp_map.take() {
                    map.unmap();
                }
                return if cqe.is_success() {
                    Ok(())
                } else {
                    Err(FsError::IoError)
                };
            }

            crate::task::yield_now().await;
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
}

// ============================================================================
// I/Oスケジューラ統合
// ============================================================================

/// 非同期I/Oスケジューラ
pub struct AsyncIoScheduler {
    /// 保留中のリクエスト
    pending: Mutex<Vec<Arc<AsyncIoRequest>>>,
    /// 完了したリクエスト
    completed: Mutex<Vec<Arc<AsyncIoRequest>>>,
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
            pending: Mutex::new(Vec::new()),
            completed: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            requests_issued: AtomicU64::new(0),
            requests_completed: AtomicU64::new(0),
        }
    }

    /// リクエストを発行
    pub fn submit(&self, request: Arc<AsyncIoRequest>) {
        self.pending.lock().push(request);
        self.requests_issued.fetch_add(1, Ordering::Relaxed);
    }

    /// 完了したリクエストを処理
    pub fn process_completions(&self) {
        let mut pending = self.pending.lock();
        let mut completed = self.completed.lock();

        pending.retain(|req| {
            if req.is_completed() {
                completed.push(req.clone());
                self.requests_completed.fetch_add(1, Ordering::Relaxed);
                false
            } else {
                true
            }
        });
    }

    /// 統計を取得
    pub fn stats(&self) -> IoSchedulerStats {
        IoSchedulerStats {
            requests_issued: self.requests_issued.load(Ordering::Relaxed),
            requests_completed: self.requests_completed.load(Ordering::Relaxed),
            pending_count: self.pending.lock().len(),
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
