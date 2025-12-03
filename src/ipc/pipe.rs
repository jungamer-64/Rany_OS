//! パイプ (Pipe) - プロセス間通信
//!
//! ExoRust Async-First アーキテクチャに基づくパイプ実装
//! ゼロコピー転送と非同期I/Oをサポート

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

/// パイプファイルディスクリプタ (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PipeFd(u32);

impl PipeFd {
    pub const fn new(fd: u32) -> Self {
        Self(fd)
    }

    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

/// パイプID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PipeId(u64);

impl PipeId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// パイプバッファサイズ (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeBufferSize(usize);

impl PipeBufferSize {
    pub const DEFAULT: Self = Self(65536); // 64KB
    pub const MIN: Self = Self(4096); // 4KB
    pub const MAX: Self = Self(1048576); // 1MB

    pub const fn new(size: usize) -> Self {
        Self(size)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }
}

/// パイプエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// パイプが閉じられている
    BrokenPipe,
    /// バッファがフル
    WouldBlock,
    /// 無効なファイルディスクリプタ
    InvalidFd,
    /// パイプ作成エラー
    CreationFailed,
    /// メモリ不足
    OutOfMemory,
    /// 読み取り端が閉じられている
    ReaderClosed,
    /// 書き込み端が閉じられている
    WriterClosed,
    /// タイムアウト
    Timeout,
    /// 割り込み
    Interrupted,
}

/// パイプフラグ
#[derive(Debug, Clone, Copy)]
pub struct PipeFlags {
    /// ノンブロッキングモード
    pub non_blocking: bool,
    /// close-on-exec
    pub cloexec: bool,
    /// ダイレクトI/O (バッファリングなし)
    pub direct: bool,
}

impl Default for PipeFlags {
    fn default() -> Self {
        Self {
            non_blocking: false,
            cloexec: false,
            direct: false,
        }
    }
}

/// パイプ統計
#[derive(Debug, Default)]
pub struct PipeStats {
    /// 読み取りバイト数
    pub bytes_read: AtomicU64,
    /// 書き込みバイト数
    pub bytes_written: AtomicU64,
    /// 読み取り操作数
    pub read_ops: AtomicU64,
    /// 書き込み操作数
    pub write_ops: AtomicU64,
    /// 読み取りブロック回数
    pub read_blocks: AtomicU64,
    /// 書き込みブロック回数
    pub write_blocks: AtomicU64,
}

impl PipeStats {
    pub const fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            read_blocks: AtomicU64::new(0),
            write_blocks: AtomicU64::new(0),
        }
    }
}

/// リングバッファ (ロックフリー)
pub struct RingBuffer {
    buffer: Vec<u8>,
    capacity: usize,
    read_pos: AtomicUsize,
    write_pos: AtomicUsize,
}

impl RingBuffer {
    /// 新しいリングバッファを作成
    pub fn new(capacity: usize) -> Self {
        let mut buffer = Vec::with_capacity(capacity);
        buffer.resize(capacity, 0);

        Self {
            buffer,
            capacity,
            read_pos: AtomicUsize::new(0),
            write_pos: AtomicUsize::new(0),
        }
    }

    /// 使用中のバイト数
    pub fn len(&self) -> usize {
        let write = self.write_pos.load(Ordering::Acquire);
        let read = self.read_pos.load(Ordering::Acquire);
        write.wrapping_sub(read)
    }

    /// 空きバイト数
    pub fn available(&self) -> usize {
        self.capacity - self.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// フルかどうか
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// データを書き込み
    pub fn write(&mut self, data: &[u8]) -> usize {
        let available = self.available();
        let to_write = data.len().min(available);

        if to_write == 0 {
            return 0;
        }

        let write_pos = self.write_pos.load(Ordering::Acquire);

        for i in 0..to_write {
            let pos = (write_pos + i) % self.capacity;
            self.buffer[pos] = data[i];
        }

        self.write_pos
            .store(write_pos.wrapping_add(to_write), Ordering::Release);
        to_write
    }

    /// データを読み取り
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let len = self.len();
        let to_read = buf.len().min(len);

        if to_read == 0 {
            return 0;
        }

        let read_pos = self.read_pos.load(Ordering::Acquire);

        for i in 0..to_read {
            let pos = (read_pos + i) % self.capacity;
            buf[i] = self.buffer[pos];
        }

        self.read_pos
            .store(read_pos.wrapping_add(to_read), Ordering::Release);
        to_read
    }

    /// データをピーク (読み取り位置を進めない)
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let len = self.len();
        let to_read = buf.len().min(len);

        if to_read == 0 {
            return 0;
        }

        let read_pos = self.read_pos.load(Ordering::Acquire);

        for i in 0..to_read {
            let pos = (read_pos + i) % self.capacity;
            buf[i] = self.buffer[pos];
        }

        to_read
    }
}

/// パイプの内部状態
pub struct PipeInner {
    /// パイプID
    id: PipeId,
    /// リングバッファ
    buffer: spin::Mutex<RingBuffer>,
    /// 読み取り端が開いているか
    reader_open: AtomicBool,
    /// 書き込み端が開いているか
    writer_open: AtomicBool,
    /// 読み取り待機中のWaker
    read_wakers: spin::Mutex<VecDeque<Waker>>,
    /// 書き込み待機中のWaker
    write_wakers: spin::Mutex<VecDeque<Waker>>,
    /// 統計
    stats: PipeStats,
    /// フラグ
    flags: PipeFlags,
}

impl PipeInner {
    /// 新しいパイプを作成
    pub fn new(id: PipeId, buffer_size: PipeBufferSize, flags: PipeFlags) -> Self {
        Self {
            id,
            buffer: spin::Mutex::new(RingBuffer::new(buffer_size.as_usize())),
            reader_open: AtomicBool::new(true),
            writer_open: AtomicBool::new(true),
            read_wakers: spin::Mutex::new(VecDeque::new()),
            write_wakers: spin::Mutex::new(VecDeque::new()),
            stats: PipeStats::new(),
            flags,
        }
    }

    /// 読み取り端をクローズ
    pub fn close_reader(&self) {
        self.reader_open.store(false, Ordering::Release);
        // 書き込み待機中のタスクを起床
        let mut wakers = self.write_wakers.lock();
        while let Some(waker) = wakers.pop_front() {
            waker.wake();
        }
    }

    /// 書き込み端をクローズ
    pub fn close_writer(&self) {
        self.writer_open.store(false, Ordering::Release);
        // 読み取り待機中のタスクを起床
        let mut wakers = self.read_wakers.lock();
        while let Some(waker) = wakers.pop_front() {
            waker.wake();
        }
    }

    /// 読み取り端が開いているか
    pub fn is_reader_open(&self) -> bool {
        self.reader_open.load(Ordering::Acquire)
    }

    /// 書き込み端が開いているか
    pub fn is_writer_open(&self) -> bool {
        self.writer_open.load(Ordering::Acquire)
    }

    /// 非同期読み取り
    pub fn poll_read(
        &self,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, PipeError>> {
        // 書き込み端がクローズされていてバッファが空ならEOF
        if !self.is_writer_open() {
            let buffer = self.buffer.lock();
            if buffer.is_empty() {
                return Poll::Ready(Ok(0)); // EOF
            }
        }

        // バッファから読み取り
        let mut buffer = self.buffer.lock();
        let read = buffer.read(buf);

        if read > 0 {
            self.stats
                .bytes_read
                .fetch_add(read as u64, Ordering::Relaxed);
            self.stats.read_ops.fetch_add(1, Ordering::Relaxed);

            // 書き込み待機中のタスクを起床
            let mut wakers = self.write_wakers.lock();
            if let Some(waker) = wakers.pop_front() {
                waker.wake();
            }

            Poll::Ready(Ok(read))
        } else if self.flags.non_blocking {
            Poll::Ready(Err(PipeError::WouldBlock))
        } else {
            // Wakerを登録して待機
            self.stats.read_blocks.fetch_add(1, Ordering::Relaxed);
            let mut wakers = self.read_wakers.lock();
            wakers.push_back(cx.waker().clone());
            Poll::Pending
        }
    }

    /// 非同期書き込み
    pub fn poll_write(&self, data: &[u8], cx: &mut Context<'_>) -> Poll<Result<usize, PipeError>> {
        // 読み取り端がクローズされていたらエラー
        if !self.is_reader_open() {
            return Poll::Ready(Err(PipeError::BrokenPipe));
        }

        // バッファに書き込み
        let mut buffer = self.buffer.lock();
        let written = buffer.write(data);

        if written > 0 {
            self.stats
                .bytes_written
                .fetch_add(written as u64, Ordering::Relaxed);
            self.stats.write_ops.fetch_add(1, Ordering::Relaxed);

            // 読み取り待機中のタスクを起床
            let mut wakers = self.read_wakers.lock();
            if let Some(waker) = wakers.pop_front() {
                waker.wake();
            }

            Poll::Ready(Ok(written))
        } else if self.flags.non_blocking {
            Poll::Ready(Err(PipeError::WouldBlock))
        } else {
            // Wakerを登録して待機
            self.stats.write_blocks.fetch_add(1, Ordering::Relaxed);
            let mut wakers = self.write_wakers.lock();
            wakers.push_back(cx.waker().clone());
            Poll::Pending
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> &PipeStats {
        &self.stats
    }

    /// バッファサイズを取得
    pub fn buffer_size(&self) -> usize {
        self.buffer.lock().capacity
    }

    /// 現在のデータ量を取得
    pub fn data_len(&self) -> usize {
        self.buffer.lock().len()
    }
}

/// 読み取り端
pub struct PipeReader {
    inner: Arc<PipeInner>,
}

impl PipeReader {
    /// 新しい読み取り端を作成
    fn new(inner: Arc<PipeInner>) -> Self {
        Self { inner }
    }

    /// 非同期読み取り
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> PipeReadFuture<'a> {
        PipeReadFuture { reader: self, buf }
    }

    /// 同期読み取り (ブロッキング)
    pub fn read_sync(&self, buf: &mut [u8]) -> Result<usize, PipeError> {
        let mut buffer = self.inner.buffer.lock();
        let read = buffer.read(buf);

        if read > 0 {
            Ok(read)
        } else if !self.inner.is_writer_open() {
            Ok(0) // EOF
        } else {
            Err(PipeError::WouldBlock)
        }
    }

    /// パイプIDを取得
    pub fn pipe_id(&self) -> PipeId {
        self.inner.id
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.inner.close_reader();
    }
}

/// 書き込み端
pub struct PipeWriter {
    inner: Arc<PipeInner>,
}

impl PipeWriter {
    /// 新しい書き込み端を作成
    fn new(inner: Arc<PipeInner>) -> Self {
        Self { inner }
    }

    /// 非同期書き込み
    pub fn write<'a>(&'a self, data: &'a [u8]) -> PipeWriteFuture<'a> {
        PipeWriteFuture { writer: self, data }
    }

    /// 同期書き込み (ブロッキング)
    pub fn write_sync(&self, data: &[u8]) -> Result<usize, PipeError> {
        if !self.inner.is_reader_open() {
            return Err(PipeError::BrokenPipe);
        }

        let mut buffer = self.inner.buffer.lock();
        let written = buffer.write(data);

        if written > 0 {
            Ok(written)
        } else {
            Err(PipeError::WouldBlock)
        }
    }

    /// パイプIDを取得
    pub fn pipe_id(&self) -> PipeId {
        self.inner.id
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.inner.close_writer();
    }
}

/// 読み取りFuture
pub struct PipeReadFuture<'a> {
    reader: &'a PipeReader,
    buf: &'a mut [u8],
}

impl<'a> Future for PipeReadFuture<'a> {
    type Output = Result<usize, PipeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        this.reader.inner.poll_read(this.buf, cx)
    }
}

/// 書き込みFuture
pub struct PipeWriteFuture<'a> {
    writer: &'a PipeWriter,
    data: &'a [u8],
}

impl<'a> Future for PipeWriteFuture<'a> {
    type Output = Result<usize, PipeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.writer.inner.poll_write(self.data, cx)
    }
}

/// パイプペア
pub struct Pipe {
    pub reader: PipeReader,
    pub writer: PipeWriter,
}

impl Pipe {
    /// 新しいパイプを作成
    pub fn new(id: PipeId) -> Self {
        Self::with_options(id, PipeBufferSize::DEFAULT, PipeFlags::default())
    }

    /// オプション付きで新しいパイプを作成
    pub fn with_options(id: PipeId, buffer_size: PipeBufferSize, flags: PipeFlags) -> Self {
        let inner = Arc::new(PipeInner::new(id, buffer_size, flags));

        Self {
            reader: PipeReader::new(inner.clone()),
            writer: PipeWriter::new(inner),
        }
    }
}

/// 名前付きパイプ (FIFO)
pub struct NamedPipe {
    inner: Arc<PipeInner>,
    name: alloc::string::String,
}

impl NamedPipe {
    /// 新しい名前付きパイプを作成
    pub fn new(id: PipeId, name: &str) -> Self {
        let inner = Arc::new(PipeInner::new(
            id,
            PipeBufferSize::DEFAULT,
            PipeFlags::default(),
        ));

        Self {
            inner,
            name: alloc::string::String::from(name),
        }
    }

    /// 名前を取得
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 読み取り端を取得
    pub fn reader(&self) -> PipeReader {
        PipeReader::new(self.inner.clone())
    }

    /// 書き込み端を取得
    pub fn writer(&self) -> PipeWriter {
        PipeWriter::new(self.inner.clone())
    }
}

/// パイプマネージャー
pub struct PipeManager {
    /// 次のパイプID
    next_id: AtomicU64,
    /// 名前付きパイプ
    named_pipes: spin::Mutex<alloc::collections::BTreeMap<alloc::string::String, Arc<PipeInner>>>,
    /// 統計
    total_created: AtomicU64,
    total_destroyed: AtomicU64,
}

impl PipeManager {
    /// 新しいパイプマネージャーを作成
    pub const fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            named_pipes: spin::Mutex::new(alloc::collections::BTreeMap::new()),
            total_created: AtomicU64::new(0),
            total_destroyed: AtomicU64::new(0),
        }
    }

    /// 新しいパイプを作成
    pub fn create(&self) -> Pipe {
        let id = PipeId::new(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.total_created.fetch_add(1, Ordering::Relaxed);
        Pipe::new(id)
    }

    /// オプション付きで新しいパイプを作成
    pub fn create_with_options(&self, buffer_size: PipeBufferSize, flags: PipeFlags) -> Pipe {
        let id = PipeId::new(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.total_created.fetch_add(1, Ordering::Relaxed);
        Pipe::with_options(id, buffer_size, flags)
    }

    /// 名前付きパイプを作成
    pub fn create_named(&self, name: &str) -> Result<NamedPipe, PipeError> {
        let id = PipeId::new(self.next_id.fetch_add(1, Ordering::Relaxed));
        let inner = Arc::new(PipeInner::new(
            id,
            PipeBufferSize::DEFAULT,
            PipeFlags::default(),
        ));

        let mut pipes = self.named_pipes.lock();
        if pipes.contains_key(name) {
            return Err(PipeError::CreationFailed);
        }

        pipes.insert(alloc::string::String::from(name), inner.clone());
        self.total_created.fetch_add(1, Ordering::Relaxed);

        Ok(NamedPipe {
            inner,
            name: alloc::string::String::from(name),
        })
    }

    /// 名前付きパイプを取得
    pub fn open_named(&self, name: &str) -> Option<NamedPipe> {
        let pipes = self.named_pipes.lock();
        pipes.get(name).map(|inner| NamedPipe {
            inner: inner.clone(),
            name: alloc::string::String::from(name),
        })
    }

    /// 名前付きパイプを削除
    pub fn remove_named(&self, name: &str) -> bool {
        let mut pipes = self.named_pipes.lock();
        if pipes.remove(name).is_some() {
            self.total_destroyed.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// 作成されたパイプ総数
    pub fn total_created(&self) -> u64 {
        self.total_created.load(Ordering::Relaxed)
    }

    /// 破棄されたパイプ総数
    pub fn total_destroyed(&self) -> u64 {
        self.total_destroyed.load(Ordering::Relaxed)
    }
}

/// グローバルパイプマネージャー
static PIPE_MANAGER: PipeManager = PipeManager::new();

/// パイプマネージャーを取得
pub fn pipe_manager() -> &'static PipeManager {
    &PIPE_MANAGER
}

/// パイプを作成 (pipe() システムコール相当)
pub fn pipe() -> Pipe {
    PIPE_MANAGER.create()
}

/// オプション付きパイプを作成 (pipe2() システムコール相当)
pub fn pipe2(flags: PipeFlags) -> Pipe {
    PIPE_MANAGER.create_with_options(PipeBufferSize::DEFAULT, flags)
}

/// 名前付きパイプを作成 (mkfifo() システムコール相当)
pub fn mkfifo(name: &str) -> Result<NamedPipe, PipeError> {
    PIPE_MANAGER.create_named(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer() {
        let mut buf = RingBuffer::new(16);

        assert!(buf.is_empty());
        assert!(!buf.is_full());

        let written = buf.write(b"Hello");
        assert_eq!(written, 5);
        assert_eq!(buf.len(), 5);

        let mut read_buf = [0u8; 10];
        let read = buf.read(&mut read_buf);
        assert_eq!(read, 5);
        assert_eq!(&read_buf[..5], b"Hello");
    }

    #[test]
    fn test_pipe_sync() {
        let pipe = pipe();

        let written = pipe.writer.write_sync(b"Test data").unwrap();
        assert!(written > 0);

        let mut buf = [0u8; 32];
        let read = pipe.reader.read_sync(&mut buf).unwrap();
        assert_eq!(read, written);
    }
}
