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

use super::vfs::{FileAttr, FsError, FsResult, SeekFrom};

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
    /// バックエンドデバイスID
    device_id: u64,
    /// 開始ブロック（ダイレクトI/O用）
    start_block: u64,
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
        }
    }

    /// ダイレクトI/Oモードで作成
    pub fn new_direct(id: u64, device_id: u64, start_block: u64, size: u64) -> Self {
        let attr = FileAttr {
            ino: id,
            size,
            ..Default::default()
        };

        Self {
            id,
            attr: Mutex::new(attr),
            position: AtomicU64::new(0),
            readable: true,
            writable: true,
            direct_io: true,
            device_id,
            start_block,
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
}

impl<'a> AsyncReadFuture<'a> {
    fn new(file: &'a AsyncFile, buf: &'a mut [u8]) -> Self {
        Self {
            file,
            buf,
            started: false,
            request_id: None,
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
                // TODO: 実際のNVMeコマンド発行
                let request_id = generate_request_id();
                self.request_id = Some(request_id);

                // リクエストを発行（シミュレーション）
                // 実際にはNVMeサブミッションキューにコマンドを追加

                return Poll::Pending;
            }

            // ページキャッシュ経由（シミュレーション）
            // 実際にはキャッシュヒット/ミスを処理
            self.buf[..to_read].fill(0); // プレースホルダー

            // 位置を更新
            self.file
                .position
                .fetch_add(to_read as u64, Ordering::Relaxed);

            return Poll::Ready(Ok(to_read));
        }

        // リクエストの完了を確認
        if let Some(_request_id) = self.request_id {
            // TODO: 完了キューをチェック
            // 完了していない場合はWakerを登録
            cx.waker().wake_by_ref();
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
}

impl<'a> AsyncWriteFuture<'a> {
    fn new(file: &'a AsyncFile, buf: &'a [u8]) -> Self {
        Self {
            file,
            buf,
            started: false,
            request_id: None,
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
                let request_id = generate_request_id();
                self.request_id = Some(request_id);

                // TODO: NVMeコマンド発行

                return Poll::Pending;
            }

            // ページキャッシュ経由（シミュレーション）
            // 位置を更新
            self.file.position.fetch_add(len as u64, Ordering::Relaxed);

            // ファイルサイズを更新
            {
                let mut attr = self.file.attr.lock();
                let new_end = position + len as u64;
                if new_end > attr.size {
                    attr.size = new_end;
                }
            }

            return Poll::Ready(Ok(len));
        }

        // 完了確認
        if let Some(_request_id) = self.request_id {
            cx.waker().wake_by_ref();
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
}

impl<'a> AsyncFlushFuture<'a> {
    fn new(file: &'a AsyncFile) -> Self {
        Self {
            file,
            started: false,
        }
    }
}

impl<'a> Future for AsyncFlushFuture<'a> {
    type Output = FsResult<()>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;

            if self.file.direct_io {
                // ダイレクトI/Oの場合、実際にはデバイスフラッシュコマンドを発行
                // TODO: NVMe Flushコマンド
            }

            // シミュレーション: 即座に完了
            return Poll::Ready(Ok(()));
        }

        Poll::Ready(Ok(()))
    }
}

/// 非同期同期Future
pub struct AsyncSyncFuture<'a> {
    file: &'a AsyncFile,
    started: bool,
}

impl<'a> AsyncSyncFuture<'a> {
    fn new(file: &'a AsyncFile) -> Self {
        Self {
            file,
            started: false,
        }
    }
}

impl<'a> Future for AsyncSyncFuture<'a> {
    type Output = FsResult<()>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.started {
            self.started = true;

            // データとメタデータの同期
            // ダイレクトI/Oの場合は既に同期済み
            if !self.file.direct_io {
                // TODO: ページキャッシュのフラッシュ
            }

            return Poll::Ready(Ok(()));
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
    /// デバイスID
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

        let blocks_to_read = buf.len() / self.block_size as usize;
        let blocks_available = (self.block_count - block_offset) as usize;
        let blocks = blocks_to_read.min(blocks_available);

        if blocks == 0 {
            return Ok(0);
        }

        // TODO: 実際のNVMeリードコマンド発行
        // コア固有のSubmission Queueを使用

        // シミュレーション
        let bytes = blocks * self.block_size as usize;
        buf[..bytes].fill(0);

        Ok(bytes)
    }

    /// ブロック書き込み
    pub async fn write_blocks(&self, block_offset: u64, buf: &[u8]) -> FsResult<usize> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        let blocks_to_write = buf.len() / self.block_size as usize;
        let blocks_available = (self.block_count - block_offset) as usize;
        let blocks = blocks_to_write.min(blocks_available);

        if blocks == 0 {
            return Ok(0);
        }

        // TODO: 実際のNVMeライトコマンド発行

        Ok(blocks * self.block_size as usize)
    }

    /// フラッシュ
    pub async fn flush(&self) -> FsResult<()> {
        // TODO: NVMe Flushコマンド
        Ok(())
    }

    /// TRIM（Discard）
    pub async fn discard(&self, block_offset: u64, block_count: u64) -> FsResult<()> {
        if block_offset >= self.block_count {
            return Err(FsError::InvalidArgument);
        }

        let _count = block_count.min(self.block_count - block_offset);

        // TODO: NVMe Dataset Management (TRIM) コマンド

        Ok(())
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
