// ============================================================================
// src/io/virtio/core.rs - VirtQueue Core Implementation
// ============================================================================
//!
//! VirtQueue（仮想キュー）の共通実装
//!
//! VirtIO仕様に基づくリングバッファ管理を提供。
//! 各デバイスドライバはこのVirtQueueを使用してデバイスと通信する。

#![allow(dead_code)]

use alloc::collections::VecDeque;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use super::defs::*;

// ============================================================================
// VirtQueue - Generic Implementation
// ============================================================================

/// VirtQueue管理構造体（汎用）
///
/// デバイス非依存のVirtQueue操作を提供する。
/// 各デバイスドライバはこの構造体をラップして使用する。
pub struct VirtQueue {
    /// キューインデックス（0, 1, 2...）
    queue_index: u16,
    /// キューサイズ（2のべき乗）
    queue_size: u16,
    /// ディスクリプタテーブルへのポインタ
    desc_table: NonNull<VringDesc>,
    /// Availableリングへのポインタ
    avail_ring: NonNull<VringAvailHeader>,
    /// Usedリングへのポインタ
    used_ring: NonNull<VringUsedHeader>,
    /// 空きディスクリプタビットマップ（最大64エントリ対応）
    free_bitmap: AtomicU64,
    /// 拡張空きビットマップ（64-128エントリ対応）
    free_bitmap_ext: AtomicU64,
    /// 拡張空きビットマップ2（128-192エントリ対応）
    free_bitmap_ext2: AtomicU64,
    /// 拡張空きビットマップ3（192-256エントリ対応）
    free_bitmap_ext3: AtomicU64,
    /// 最後に処理したUsedインデックス
    last_used_idx: AtomicU16,
    /// 通知アドレス（MMIO/PIO）
    notify_addr: *mut u16,
    /// 通知オフセット乗数（PCI用）
    notify_off_multiplier: u32,
}

// SAFETY: VirtQueueはMutexで保護されるか、適切な同期メカニズムを使用する。
// NonNullポインタはDMA領域への有効なポインタを指す。
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// 新しいVirtQueueを初期化
    ///
    /// # Safety
    /// - `desc_table`, `avail_ring`, `used_ring` は有効なDMA可能メモリを指す必要がある
    /// - メモリ領域はキューの寿命中有効である必要がある
    /// - `queue_size` は2のべき乗で、VIRTQUEUE_MAX_SIZE以下である必要がある
    pub unsafe fn new(
        queue_index: u16,
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvailHeader,
        used_ring: *mut VringUsedHeader,
        notify_addr: *mut u16,
        notify_off_multiplier: u32,
    ) -> Result<Self, &'static str> { unsafe {
        if queue_size == 0 || !queue_size.is_power_of_two() {
            return Err("Queue size must be a power of 2");
        }
        if queue_size > VIRTQUEUE_MAX_SIZE {
            return Err("Queue size exceeds maximum");
        }

        // ディスクリプタテーブルを初期化（チェーン形式で連結）
        for i in 0..queue_size {
            let desc = desc_table.add(i as usize);
            (*desc) = VringDesc {
                addr: 0,
                len: 0,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: if i + 1 < queue_size { i + 1 } else { 0 },
            };
        }

        // Availableリングを初期化
        (*avail_ring).flags = 0;
        (*avail_ring).idx = 0;

        // Usedリングを初期化
        (*used_ring).flags = 0;
        (*used_ring).idx = 0;

        // 空きビットマップを初期化（全て空き）
        let (bitmap0, bitmap1, bitmap2, bitmap3) = Self::init_free_bitmap(queue_size);

        Ok(Self {
            queue_index,
            queue_size,
            desc_table: NonNull::new_unchecked(desc_table),
            avail_ring: NonNull::new_unchecked(avail_ring),
            used_ring: NonNull::new_unchecked(used_ring),
            free_bitmap: AtomicU64::new(bitmap0),
            free_bitmap_ext: AtomicU64::new(bitmap1),
            free_bitmap_ext2: AtomicU64::new(bitmap2),
            free_bitmap_ext3: AtomicU64::new(bitmap3),
            last_used_idx: AtomicU16::new(0),
            notify_addr,
            notify_off_multiplier,
        })
    }}

    /// 空きビットマップを初期化
    fn init_free_bitmap(queue_size: u16) -> (u64, u64, u64, u64) {
        let size = queue_size as u64;
        let bitmap0 = if size >= 64 { u64::MAX } else { (1u64 << size) - 1 };
        let bitmap1 = if size > 64 {
            if size >= 128 { u64::MAX } else { (1u64 << (size - 64)) - 1 }
        } else { 0 };
        let bitmap2 = if size > 128 {
            if size >= 192 { u64::MAX } else { (1u64 << (size - 128)) - 1 }
        } else { 0 };
        let bitmap3 = if size > 192 {
            if size >= 256 { u64::MAX } else { (1u64 << (size - 192)) - 1 }
        } else { 0 };
        (bitmap0, bitmap1, bitmap2, bitmap3)
    }

    /// キューインデックスを取得
    pub fn queue_index(&self) -> u16 {
        self.queue_index
    }

    /// キューサイズを取得
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// 空きディスクリプタを割り当て
    pub fn alloc_desc(&self) -> Option<u16> {
        // bitmap0 (0-63)
        if let Some(idx) = self.try_alloc_from_bitmap(&self.free_bitmap, 0) {
            return Some(idx);
        }
        // bitmap1 (64-127)
        if self.queue_size > 64 {
            if let Some(idx) = self.try_alloc_from_bitmap(&self.free_bitmap_ext, 64) {
                return Some(idx);
            }
        }
        // bitmap2 (128-191)
        if self.queue_size > 128 {
            if let Some(idx) = self.try_alloc_from_bitmap(&self.free_bitmap_ext2, 128) {
                return Some(idx);
            }
        }
        // bitmap3 (192-255)
        if self.queue_size > 192 {
            if let Some(idx) = self.try_alloc_from_bitmap(&self.free_bitmap_ext3, 192) {
                return Some(idx);
            }
        }
        None
    }

    /// ビットマップから空きを探して割り当て
    fn try_alloc_from_bitmap(&self, bitmap: &AtomicU64, base: u16) -> Option<u16> {
        loop {
            let bits = bitmap.load(Ordering::Acquire);
            if bits == 0 {
                return None;
            }

            let bit_idx = bits.trailing_zeros() as u16;
            let new_bits = bits & !(1u64 << bit_idx);

            if bitmap
                .compare_exchange(bits, new_bits, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(base + bit_idx);
            }
            // CAS失敗時はリトライ
        }
    }

    /// ディスクリプタを解放
    pub fn free_desc(&self, idx: u16) {
        let (bitmap, bit_idx) = if idx < 64 {
            (&self.free_bitmap, idx)
        } else if idx < 128 {
            (&self.free_bitmap_ext, idx - 64)
        } else if idx < 192 {
            (&self.free_bitmap_ext2, idx - 128)
        } else {
            (&self.free_bitmap_ext3, idx - 192)
        };

        loop {
            let bits = bitmap.load(Ordering::Acquire);
            let new_bits = bits | (1u64 << bit_idx);

            if bitmap
                .compare_exchange(bits, new_bits, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// ディスクリプタチェーンを解放
    pub fn free_desc_chain(&self, head: u16) {
        let mut idx = head;
        loop {
            let desc = unsafe { &*self.desc_table.as_ptr().add(idx as usize) };
            let next = desc.next;
            let has_next = desc.has_next();
            
            self.free_desc(idx);
            
            if !has_next {
                break;
            }
            idx = next;
        }
    }

    /// ディスクリプタを取得（読み取り専用）
    pub fn get_desc(&self, idx: u16) -> &VringDesc {
        unsafe { &*self.desc_table.as_ptr().add(idx as usize) }
    }

    /// ディスクリプタを取得（書き込み可能）
    ///
    /// # Safety
    /// 呼び出し側が排他制御を保証する必要がある
    pub unsafe fn get_desc_mut(&self, idx: u16) -> &mut VringDesc { unsafe {
        &mut *self.desc_table.as_ptr().add(idx as usize)
    }}

    /// バッファをキューに追加（単一ディスクリプタ）
    ///
    /// # Safety
    /// - `addr` は有効なDMA物理アドレスである必要がある
    /// - バッファは処理完了まで有効である必要がある
    pub unsafe fn add_buffer_single(
        &self,
        addr: u64,
        len: u32,
        writable: bool,
    ) -> Result<u16, &'static str> { unsafe {
        let desc_idx = self.alloc_desc().ok_or("No free descriptors")?;

        // ディスクリプタを設定
        let desc = self.get_desc_mut(desc_idx);
        desc.addr = addr;
        desc.len = len;
        desc.flags = if writable { vring_flags::VRING_DESC_F_WRITE } else { 0 };
        desc.next = 0;

        // Availリングに追加
        self.submit_avail(desc_idx);

        Ok(desc_idx)
    }}

    /// バッファチェーンをキューに追加
    ///
    /// `buffers` は (物理アドレス, 長さ, writable) のタプルのスライス
    ///
    /// # Safety
    /// - 全てのアドレスは有効なDMA物理アドレスである必要がある
    pub unsafe fn add_buffer_chain(
        &self,
        buffers: &[(u64, u32, bool)],
    ) -> Result<u16, &'static str> { unsafe {
        if buffers.is_empty() {
            return Err("Empty buffer chain");
        }

        // 必要な数のディスクリプタを割り当て
        let mut indices = alloc::vec::Vec::with_capacity(buffers.len());
        for _ in 0..buffers.len() {
            let idx = self.alloc_desc().ok_or("No free descriptors")?;
            indices.push(idx);
        }

        // ディスクリプタチェーンを構築
        for (i, (addr, len, writable)) in buffers.iter().enumerate() {
            let desc = self.get_desc_mut(indices[i]);
            desc.addr = *addr;
            desc.len = *len;
            desc.flags = if *writable { vring_flags::VRING_DESC_F_WRITE } else { 0 };
            
            if i + 1 < buffers.len() {
                desc.flags |= vring_flags::VRING_DESC_F_NEXT;
                desc.next = indices[i + 1];
            } else {
                desc.next = 0;
            }
        }

        // Availリングに追加
        let head = indices[0];
        self.submit_avail(head);

        Ok(head)
    }}

    /// Availリングにディスクリプタを追加
    unsafe fn submit_avail(&self, head: u16) { unsafe {
        // メモリバリア: ディスクリプタの書き込みを完了させる
        core::sync::atomic::fence(Ordering::Release);

        let avail = self.avail_ring.as_ptr();
        let avail_idx = (*avail).idx;
        
        // リング配列はヘッダの直後に配置されている
        let ring_ptr = (avail as *mut u16).add(2); // flags + idx をスキップ
        *ring_ptr.add((avail_idx % self.queue_size) as usize) = head;

        // メモリバリア: リングエントリの書き込み後にidxを更新
        core::sync::atomic::fence(Ordering::Release);

        (*avail).idx = avail_idx.wrapping_add(1);
    }}

    /// デバイスに通知
    pub fn notify(&self) {
        // メモリバリア: 全ての書き込みが完了してから通知
        core::sync::atomic::fence(Ordering::SeqCst);

        unsafe {
            core::ptr::write_volatile(self.notify_addr, self.queue_index);
        }
    }

    /// 完了したリクエストをポーリング
    ///
    /// 戻り値: `Some((descriptor_head_id, written_length))` または `None`
    pub fn poll_used(&self) -> Option<(u16, u32)> {
        // メモリバリア: デバイスの書き込みを読み取る前に
        core::sync::atomic::fence(Ordering::Acquire);

        let used = unsafe { self.used_ring.as_ref() };
        let used_idx = used.idx;
        let last_used = self.last_used_idx.load(Ordering::Acquire);

        if last_used == used_idx {
            return None;
        }

        // Usedリング配列を読み取り
        let ring_ptr = unsafe {
            (self.used_ring.as_ptr() as *const u8).add(4) as *const VringUsedElem
        };
        let elem = unsafe { *ring_ptr.add((last_used % self.queue_size) as usize) };

        // last_used_idxを更新
        self.last_used_idx
            .store(last_used.wrapping_add(1), Ordering::Release);

        Some((elem.id as u16, elem.len))
    }

    /// 処理待ちのリクエスト数を取得
    pub fn pending_count(&self) -> u16 {
        let avail = unsafe { (*self.avail_ring.as_ptr()).idx };
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        avail.wrapping_sub(last_used)
    }

    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        self.pending_count() == 0
    }

    /// ディスクリプタテーブルの物理アドレス
    pub fn desc_table_phys(&self) -> u64 {
        self.desc_table.as_ptr() as u64
    }

    /// Availリングの物理アドレス
    pub fn avail_ring_phys(&self) -> u64 {
        self.avail_ring.as_ptr() as u64
    }

    /// Usedリングの物理アドレス
    pub fn used_ring_phys(&self) -> u64 {
        self.used_ring.as_ptr() as u64
    }
}

// ============================================================================
// VirtQueue with Buffer Tracking
// ============================================================================

/// バッファ追跡付きVirtQueue
///
/// 保留中のバッファ参照を保持し、完了時に返却する。
/// ゼロコピーI/Oに使用する。
pub struct TrackedVirtQueue<T> {
    /// 基本VirtQueue
    inner: VirtQueue,
    /// 保留中のバッファ（ディスクリプタインデックスでインデックス）
    pending: spin::Mutex<VecDeque<Option<T>>>,
}

impl<T> TrackedVirtQueue<T> {
    /// 新しいTrackedVirtQueueを作成
    ///
    /// # Safety
    /// `VirtQueue::new`と同じ安全性要件
    pub unsafe fn new(
        queue_index: u16,
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvailHeader,
        used_ring: *mut VringUsedHeader,
        notify_addr: *mut u16,
        notify_off_multiplier: u32,
    ) -> Result<Self, &'static str> { unsafe {
        let inner = VirtQueue::new(
            queue_index,
            queue_size,
            desc_table,
            avail_ring,
            used_ring,
            notify_addr,
            notify_off_multiplier,
        )?;

        let mut pending = VecDeque::with_capacity(queue_size as usize);
        for _ in 0..queue_size {
            pending.push_back(None);
        }

        Ok(Self {
            inner,
            pending: spin::Mutex::new(pending),
        })
    }}

    /// 基本VirtQueueへの参照
    pub fn inner(&self) -> &VirtQueue {
        &self.inner
    }

    /// バッファをキューに追加し、追跡情報を保存
    ///
    /// # Safety
    /// - `addr` は有効なDMA物理アドレスである必要がある
    pub unsafe fn add_buffer_tracked(
        &self,
        addr: u64,
        len: u32,
        writable: bool,
        buffer: T,
    ) -> Result<u16, &'static str> { unsafe {
        let desc_idx = self.inner.alloc_desc().ok_or("No free descriptors")?;

        // ディスクリプタを設定
        {
            let desc = self.inner.get_desc_mut(desc_idx);
            desc.addr = addr;
            desc.len = len;
            desc.flags = if writable { vring_flags::VRING_DESC_F_WRITE } else { 0 };
            desc.next = 0;
        }

        // バッファ参照を保存
        {
            let mut pending = self.pending.lock();
            if (desc_idx as usize) < pending.len() {
                pending[desc_idx as usize] = Some(buffer);
            }
        }

        // Availリングに追加
        self.inner.submit_avail(desc_idx);

        Ok(desc_idx)
    }}

    /// 完了したリクエストをポーリングし、バッファを返却
    ///
    /// 戻り値: `Some((descriptor_id, buffer, written_length))`
    pub fn poll_used_tracked(&self) -> Option<(u16, T, u32)> {
        let (desc_idx, len) = self.inner.poll_used()?;

        // バッファを取り出し
        let buffer = {
            let mut pending = self.pending.lock();
            pending.get_mut(desc_idx as usize)?.take()?
        };

        // ディスクリプタを解放
        self.inner.free_desc(desc_idx);

        Some((desc_idx, buffer, len))
    }

    /// デバイスに通知
    pub fn notify(&self) {
        self.inner.notify();
    }

    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// VirtQueueのメモリレイアウトサイズを計算
pub fn virtqueue_memory_size(queue_size: u16) -> (usize, usize, usize) {
    let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
    let avail_size = 4 + 2 * queue_size as usize + 2; // flags + idx + ring + used_event
    let used_size = 4 + core::mem::size_of::<VringUsedElem>() * queue_size as usize + 2;
    (desc_size, avail_size, used_size)
}

/// VirtQueueのアライメント要件を取得
pub fn virtqueue_alignment() -> usize {
    4096 // VirtIO仕様ではページアライメントが推奨
}
