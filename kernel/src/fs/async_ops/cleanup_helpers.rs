use super::*;
use crate::sync::PoisonLock;

/// IOMMUマッピングを一括解放する
mod read_future_impl;
pub use self::read_future_impl::*;

pub(crate) fn nsid_from_device(device_id: u64) -> u32 {
    let nsid = device_id as u32;
    if nsid == 0 { 1 } else { nsid }
}

pub(crate) fn nvme_block_size(device_id: u64) -> u64 {
    // Use kernel_api abstraction instead of direct driver access
    kernel_api::service::kernel::instance()
        .nvme_block_size(device_id)
        .unwrap_or(NVME_BLOCK_SIZE)
}

pub(crate) fn read_via_page_cache(
    ino: u64,
    offset: u64,
    buf: &mut [u8],
    file_size: u64,
) -> FsResult<usize> {
    let cache = page_cache();
    let mut total = 0;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
            let read_len = read_inode_by_number(ino, page_start, &mut page_data)
                .map_err(|_| FsError::IoError)?;
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

pub(crate) fn write_via_page_cache(
    ino: u64,
    offset: u64,
    buf: &[u8],
    file_size: u64,
) -> FsResult<usize> {
    let cache = page_cache();
    let mut total = 0;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while total < buf.len() {
        let cur_offset = offset + total as u64;
        let page_num = cur_offset / CACHE_PAGE_SIZE as u64;
        let page_offset = (cur_offset % CACHE_PAGE_SIZE as u64) as usize;
        let chunk = (CACHE_PAGE_SIZE - page_offset).min(buf.len() - total);

        if let Some(written) = cache.write(ino, cur_offset, &buf[total..total + chunk], file_size) {
            total += written;
            continue;
        }

        let page_start = page_num * CACHE_PAGE_SIZE as u64;
        let mut page_data = alloc::vec![0u8; CACHE_PAGE_SIZE];
        let needs_preserve = page_offset != 0 || chunk != CACHE_PAGE_SIZE;
        if needs_preserve && page_start < file_size {
            let read_len = read_inode_by_number(ino, page_start, &mut page_data)
                .map_err(|_| FsError::IoError)?;
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

pub(crate) fn flush_page_cache(ino: u64) -> FsResult<()> {
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
    pub buffer: Option<Arc<PoisonLock<Vec<u8>>>>,
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
        buffer: Option<Arc<PoisonLock<Vec<u8>>>>,
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
    pub fn read(id: u64, offset: u64, buffer: Arc<PoisonLock<Vec<u8>>>, length: usize) -> Self {
        Self::new(id, AsyncIoType::Read, offset, Some(buffer), length)
    }

    /// 書き込みリクエストを作成
    pub fn write(id: u64, offset: u64, buffer: Arc<PoisonLock<Vec<u8>>>, length: usize) -> Self {
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

    pub(super) fn io_device(&self) -> IoDeviceId {
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
    dma_result: Option<Arc<PoisonLock<Option<(DmaRegion, usize)>>>>,
    dma_offset_in_block: Option<usize>,
    dma_dma_len: Option<usize>,
}
