// ============================================================================
// src/sync/lockfree.rs - Lock-Free Ring Buffer for Inter-Core Communication
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// コア間でのデータ共有を避け、ロックフリーなリングバッファでメッセージパッシング
// ============================================================================
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// ロックフリーSPSC (Single-Producer Single-Consumer) リングバッファ
/// 
/// 設計書 4.3: コア間通信が必要な場合は、ロックフリーなリングバッファを
/// 用いたメッセージパッシングを行う
/// 
/// # 特徴
/// - 単一プロデューサー・単一コンシューマー
/// - ロックフリー（CASベース）
/// - キャッシュライン最適化
/// - ゼロコピー（可能な場合）
#[repr(C)]
pub struct SpscRingBuffer<T, const N: usize> {
    /// バッファ（キャッシュライン境界にアラインメント）
    buffer: UnsafeCell<[MaybeUninit<T>; N]>,
    /// 書き込みインデックス（プロデューサー所有）
    head: CacheLinePadded<AtomicUsize>,
    /// 読み取りインデックス（コンシューマー所有）
    tail: CacheLinePadded<AtomicUsize>,
}

/// キャッシュラインパディング（False Sharing防止）
/// x86_64のキャッシュラインは通常64バイト
#[repr(align(64))]
struct CacheLinePadded<T> {
    value: T,
}

impl<T> CacheLinePadded<T> {
    const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> core::ops::Deref for CacheLinePadded<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

// SAFETY: SpscRingBufferはSend/Sync安全
// - headはプロデューサーのみが書き込み
// - tailはコンシューマーのみが書き込み
// - バッファはatomicインデックスで保護
unsafe impl<T: Send, const N: usize> Send for SpscRingBuffer<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for SpscRingBuffer<T, N> {}

impl<T, const N: usize> SpscRingBuffer<T, N> {
    /// 新しいリングバッファを作成
    /// 
    /// # Panics
    /// Nが2以上でない場合パニック
    pub const fn new() -> Self {
        assert!(N >= 2, "Ring buffer must have at least 2 slots");
        
        Self {
            buffer: UnsafeCell::new(unsafe { MaybeUninit::uninit().assume_init() }),
            head: CacheLinePadded::new(AtomicUsize::new(0)),
            tail: CacheLinePadded::new(AtomicUsize::new(0)),
        }
    }
    
    /// キャパシティを取得（実際に使用可能なスロット数はN-1）
    #[inline]
    pub const fn capacity(&self) -> usize {
        N - 1
    }
    
    /// 現在の要素数を取得
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) % N
    }
    
    /// バッファが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail
    }
    
    /// バッファが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        (head.wrapping_add(1)) % N == tail
    }
    
    /// 要素をプッシュ（プロデューサー側）
    /// 
    /// # Returns
    /// - `Ok(())` - 成功
    /// - `Err(value)` - バッファが満杯で失敗（値を返却）
    #[inline]
    pub fn push(&self, value: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let next_head = (head + 1) % N;
        
        // 満杯チェック
        if next_head == self.tail.load(Ordering::Acquire) {
            return Err(value);
        }
        
        // バッファに書き込み
        unsafe {
            let slot = &mut (*self.buffer.get())[head];
            slot.write(value);
        }
        
        // headを更新（Releaseでコンシューマーに可視化）
        self.head.store(next_head, Ordering::Release);
        
        Ok(())
    }
    
    /// 要素をポップ（コンシューマー側）
    /// 
    /// # Returns
    /// - `Some(value)` - 成功
    /// - `None` - バッファが空
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        
        // 空チェック（Acquireでプロデューサーの書き込みを可視化）
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        
        // バッファから読み取り
        let value = unsafe {
            let slot = &(*self.buffer.get())[tail];
            slot.assume_init_read()
        };
        
        // tailを更新
        let next_tail = (tail + 1) % N;
        self.tail.store(next_tail, Ordering::Release);
        
        Some(value)
    }
    
    /// 要素を覗き見（コンシューマー側、削除しない）
    #[inline]
    pub fn peek(&self) -> Option<&T> {
        let tail = self.tail.load(Ordering::Relaxed);
        
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        
        unsafe {
            let slot = &(*self.buffer.get())[tail];
            Some(slot.assume_init_ref())
        }
    }
}

impl<T, const N: usize> Default for SpscRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for SpscRingBuffer<T, N> {
    fn drop(&mut self) {
        // 残っている要素をドロップ
        while self.pop().is_some() {}
    }
}

// ============================================================================
// MPSC (Multi-Producer Single-Consumer) リングバッファ
// 複数コアから単一コアへのメッセージ送信用
// ============================================================================

/// ロックフリーMPSC リングバッファ
/// 
/// 複数のプロデューサーが同時にプッシュ可能
/// CAS操作を使用して競合を解決
#[repr(C)]
pub struct MpscRingBuffer<T, const N: usize> {
    buffer: UnsafeCell<[MaybeUninit<T>; N]>,
    /// 予約済みの書き込み位置
    head: CacheLinePadded<AtomicUsize>,
    /// コミット済みの書き込み位置
    committed: CacheLinePadded<AtomicUsize>,
    /// 読み取り位置
    tail: CacheLinePadded<AtomicUsize>,
}

unsafe impl<T: Send, const N: usize> Send for MpscRingBuffer<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for MpscRingBuffer<T, N> {}

impl<T, const N: usize> MpscRingBuffer<T, N> {
    pub const fn new() -> Self {
        assert!(N >= 2, "Ring buffer must have at least 2 slots");
        
        Self {
            buffer: UnsafeCell::new(unsafe { MaybeUninit::uninit().assume_init() }),
            head: CacheLinePadded::new(AtomicUsize::new(0)),
            committed: CacheLinePadded::new(AtomicUsize::new(0)),
            tail: CacheLinePadded::new(AtomicUsize::new(0)),
        }
    }
    
    #[inline]
    pub const fn capacity(&self) -> usize {
        N - 1
    }
    
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }
    
    /// 要素をプッシュ（複数プロデューサー対応）
    /// 
    /// CASループでスロットを予約してから書き込む
    #[inline]
    pub fn push(&self, value: T) -> Result<(), T> {
        loop {
            let head = self.head.load(Ordering::Relaxed);
            let next_head = (head + 1) % N;
            
            // 満杯チェック
            if next_head == self.tail.load(Ordering::Acquire) {
                return Err(value);
            }
            
            // CASでスロットを予約
            match self.head.compare_exchange_weak(
                head,
                next_head,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // 予約成功、書き込み
                    unsafe {
                        let slot = &mut (*self.buffer.get())[head];
                        slot.write(value);
                    }
                    
                    // コミットを待機（順序保証）
                    // 前のスロットがコミットされるまで待つ
                    while self.committed.load(Ordering::Acquire) != head {
                        core::hint::spin_loop();
                    }
                    
                    // コミット
                    self.committed.store(next_head, Ordering::Release);
                    
                    return Ok(());
                }
                Err(_) => {
                    // 競合、リトライ
                    core::hint::spin_loop();
                }
            }
        }
    }
    
    /// 要素をポップ（単一コンシューマー）
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        
        // コミット済みまでのデータのみ読める
        if tail == self.committed.load(Ordering::Acquire) {
            return None;
        }
        
        let value = unsafe {
            let slot = &(*self.buffer.get())[tail];
            slot.assume_init_read()
        };
        
        let next_tail = (tail + 1) % N;
        self.tail.store(next_tail, Ordering::Release);
        
        Some(value)
    }
}

impl<T, const N: usize> Default for MpscRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for MpscRingBuffer<T, N> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

// ============================================================================
// コア間メッセージチャネル
// ============================================================================

/// コア間メッセージの種類
#[derive(Debug, Clone)]
pub enum InterCoreMessage {
    /// タスクの移動要求
    MigrateTask {
        task_id: u64,
        from_core: u32,
        to_core: u32,
    },
    /// Work Stealing 要求
    StealRequest {
        from_core: u32,
    },
    /// Work Stealing 応答
    StealResponse {
        task_id: Option<u64>,
    },
    /// 割り込みのリレー
    RelayInterrupt {
        vector: u8,
    },
    /// シャットダウン通知
    Shutdown,
    /// カスタムメッセージ
    Custom(u64),
}

/// デフォルトのメッセージキューサイズ
pub const DEFAULT_QUEUE_SIZE: usize = 256;

/// コア間通信チャネル
pub type InterCoreChannel = SpscRingBuffer<InterCoreMessage, DEFAULT_QUEUE_SIZE>;

/// コア間チャネルを作成
pub const fn create_inter_core_channel() -> InterCoreChannel {
    SpscRingBuffer::new()
}

// ============================================================================
// Bounded Channel (mpsc)
// ============================================================================

use alloc::sync::Arc;

/// Bounded MPSC チャネル
pub struct BoundedChannel<T, const N: usize> {
    inner: Arc<MpscRingBuffer<T, N>>,
}

impl<T, const N: usize> BoundedChannel<T, N> {
    pub fn new() -> (BoundedSender<T, N>, BoundedReceiver<T, N>) {
        let inner = Arc::new(MpscRingBuffer::new());
        
        (
            BoundedSender { inner: inner.clone() },
            BoundedReceiver { inner },
        )
    }
}

/// MPSC チャネルの送信側
pub struct BoundedSender<T, const N: usize> {
    inner: Arc<MpscRingBuffer<T, N>>,
}

impl<T, const N: usize> BoundedSender<T, N> {
    pub fn send(&self, value: T) -> Result<(), T> {
        self.inner.push(value)
    }
    
    pub fn is_full(&self) -> bool {
        // capacity check
        let head = self.inner.head.load(Ordering::Relaxed);
        let tail = self.inner.tail.load(Ordering::Relaxed);
        (head + 1) % N == tail
    }
}

impl<T, const N: usize> Clone for BoundedSender<T, N> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

/// MPSC チャネルの受信側
pub struct BoundedReceiver<T, const N: usize> {
    inner: Arc<MpscRingBuffer<T, N>>,
}

impl<T, const N: usize> BoundedReceiver<T, N> {
    pub fn recv(&self) -> Option<T> {
        self.inner.pop()
    }
    
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// ============================================================================
// Seqlock (Reader-Writer Lock Optimization)
// 読み取りが多い場合に最適化されたロック
// ============================================================================

/// Seqlock - 読み取り優先のロック
/// 
/// 書き込みはロックを取得、読み取りはシーケンス番号で整合性を検証
/// 読み取りが非常に多く、書き込みが少ない場合に最適
pub struct Seqlock<T> {
    sequence: AtomicUsize,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Seqlock<T> {}
unsafe impl<T: Send + Sync> Sync for Seqlock<T> {}

impl<T: Copy> Seqlock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            data: UnsafeCell::new(value),
        }
    }
    
    /// 読み取り（ロックフリー、整合性検証付き）
    pub fn read(&self) -> T {
        loop {
            let seq1 = self.sequence.load(Ordering::Acquire);
            
            // 奇数の場合は書き込み中なのでリトライ
            if seq1 & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            
            // データを読み取り
            let value = unsafe { *self.data.get() };
            
            // シーケンス番号が変わっていないか確認
            core::sync::atomic::fence(Ordering::Acquire);
            let seq2 = self.sequence.load(Ordering::Relaxed);
            
            if seq1 == seq2 {
                return value;
            }
            
            // 書き込みが発生したのでリトライ
            core::hint::spin_loop();
        }
    }
    
    /// 書き込み（排他ロック）
    pub fn write(&self, value: T) {
        // シーケンス番号をインクリメント（奇数に）
        let _seq = self.sequence.fetch_add(1, Ordering::Acquire);
        
        // データを書き込み
        unsafe {
            *self.data.get() = value;
        }
        
        // シーケンス番号をインクリメント（偶数に）
        self.sequence.fetch_add(1, Ordering::Release);
    }
    
    /// 書き込みガードを取得
    pub fn write_guard(&self) -> SeqlockWriteGuard<'_, T> {
        // シーケンス番号をインクリメント（奇数に）
        self.sequence.fetch_add(1, Ordering::Acquire);
        
        SeqlockWriteGuard { lock: self }
    }
}

/// Seqlock 書き込みガード
pub struct SeqlockWriteGuard<'a, T> {
    lock: &'a Seqlock<T>,
}

impl<'a, T> core::ops::Deref for SeqlockWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SeqlockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SeqlockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // シーケンス番号をインクリメント（偶数に）
        self.lock.sequence.fetch_add(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_spsc_basic() {
        let rb: SpscRingBuffer<u32, 8> = SpscRingBuffer::new();
        
        assert!(rb.is_empty());
        assert!(!rb.is_full());
        
        // Push some values
        for i in 0..7 {
            assert!(rb.push(i).is_ok());
        }
        
        // Buffer should be full now
        assert!(rb.is_full());
        assert!(rb.push(100).is_err());
        
        // Pop values
        for i in 0..7 {
            assert_eq!(rb.pop(), Some(i));
        }
        
        assert!(rb.is_empty());
        assert_eq!(rb.pop(), None);
    }
    
    #[test]
    fn test_mpsc_basic() {
        let rb: MpscRingBuffer<u32, 8> = MpscRingBuffer::new();
        
        assert!(rb.is_empty());
        
        assert!(rb.push(1).is_ok());
        assert!(rb.push(2).is_ok());
        assert!(rb.push(3).is_ok());
        
        assert_eq!(rb.pop(), Some(1));
        assert_eq!(rb.pop(), Some(2));
        assert_eq!(rb.pop(), Some(3));
        assert_eq!(rb.pop(), None);
    }
    
    #[test]
    fn test_seqlock() {
        let lock: Seqlock<u64> = Seqlock::new(0);
        
        assert_eq!(lock.read(), 0);
        
        lock.write(42);
        assert_eq!(lock.read(), 42);
        
        {
            let mut guard = lock.write_guard();
            *guard = 100;
        }
        
        assert_eq!(lock.read(), 100);
    }
}
