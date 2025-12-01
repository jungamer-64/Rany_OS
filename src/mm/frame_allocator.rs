// ============================================================================
// src/mm/frame_allocator.rs - Bitmap-based Physical Frame Allocator
// 設計書 5.2 Tier1: 4KiB/2MiB/1GiB単位の物理フレーム管理
// 
// 注意: 構造体全体がMutexで保護されているため、内部フィールドは
// 通常のu64を使用。Mutex + Atomicの二重ロックはオーバーヘッド。
// ============================================================================
#![allow(dead_code)]

use crate::sync::IrqMutex;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB, Size2MiB, Size1GiB};
use x86_64::PhysAddr;

// ============================================================================
// 型安全性: フレーム番号のNewtype
// 物理アドレスとフレームインデックスの取り違えをコンパイル時に防ぐ
// ============================================================================

/// フレーム番号（物理アドレス / PAGE_SIZE_4K）
/// 
/// 型安全性のためのNewTypeパターン。
/// `usize` や `PhysAddr` との取り違えをコンパイル時に検出。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameIndex(usize);

impl FrameIndex {
    /// フレーム番号から作成
    #[inline]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }
    
    /// 物理アドレスからフレーム番号を計算
    #[inline]
    pub const fn from_phys_addr(addr: u64) -> Self {
        Self((addr as usize) / PAGE_SIZE_4K)
    }
    
    /// フレーム番号を物理アドレスに変換
    #[inline]
    pub const fn to_phys_addr(self) -> u64 {
        (self.0 * PAGE_SIZE_4K) as u64
    }
    
    /// 生の値を取得
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }
    
    /// ビットマップのワードインデックスを取得
    #[inline]
    pub const fn word_index(self) -> usize {
        self.0 / 64
    }
    
    /// ビットマップ内のビット位置を取得
    #[inline]
    pub const fn bit_index(self) -> usize {
        self.0 % 64
    }
}

/// 4KiB ページサイズ
pub const PAGE_SIZE_4K: usize = 4096;
/// 2MiB ページサイズ
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
/// 1GiB ページサイズ
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

/// 物理メモリの最大サイズ（16GiB想定）
const MAX_PHYSICAL_MEMORY: usize = 16 * 1024 * 1024 * 1024;
/// 4KiBページ数の最大値
const MAX_4K_FRAMES: usize = MAX_PHYSICAL_MEMORY / PAGE_SIZE_4K;
/// ビットマップのワード数（64ビット単位）
const BITMAP_WORDS: usize = MAX_4K_FRAMES / 64;

/// ビットマップ方式の物理フレームアロケータ
/// 設計書: ビットマップ管理。頻繁には呼ばれない。
/// 
/// 注意: 構造体全体がFRAME_ALLOCATOR: Mutex<BitmapFrameAllocator>で保護されるため、
/// 内部フィールドにAtomicは不要。通常のu64を使用する。
pub struct BitmapFrameAllocator {
    /// ビットマップ（1 = 使用中, 0 = 空き）
    bitmap: [u64; BITMAP_WORDS],
    /// 総フレーム数
    total_frames: usize,
    /// 空きフレーム数（統計用）
    free_frames: u64,
    /// 最初の空き領域のヒント（高速化用）
    next_free_hint: u64,
}

impl BitmapFrameAllocator {
    /// 新しいフレームアロケータを作成（未初期化）
    pub const fn new() -> Self {
        Self {
            bitmap: [0u64; BITMAP_WORDS],
            total_frames: 0,
            free_frames: 0,
            next_free_hint: 0,
        }
    }
    
    /// メモリマップに基づいてアロケータを初期化
    /// 
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    pub unsafe fn init(&mut self, usable_regions: &[(PhysAddr, u64)]) {
        // 最初は全てを使用中としてマーク
        for word in self.bitmap.iter_mut() {
            *word = u64::MAX;
        }
        
        let mut total = 0usize;
        let mut free = 0u64;
        
        // 使用可能な領域を空きとしてマーク
        for &(start, size) in usable_regions {
            let start_frame = FrameIndex::from_phys_addr(start.as_u64());
            let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);
            
            for frame_idx in start_frame.as_usize()..end_frame.as_usize() {
                if frame_idx < MAX_4K_FRAMES {
                    self.mark_frame_free(FrameIndex::new(frame_idx));
                    free += 1;
                }
            }
            
            total = total.max(end_frame.as_usize());
        }
        
        self.total_frames = total;
        self.free_frames = free;
    }
    
    /// フレームを空きとしてマーク
    fn mark_frame_free(&mut self, frame: FrameIndex) {
        let word_idx = frame.word_index();
        let bit_idx = frame.bit_index();
        
        if word_idx < BITMAP_WORDS {
            let mask = !(1u64 << bit_idx);
            self.bitmap[word_idx] &= mask;
        }
    }
    
    /// フレームを使用中としてマーク
    fn mark_frame_used(&mut self, frame: FrameIndex) {
        let word_idx = frame.word_index();
        let bit_idx = frame.bit_index();
        
        if word_idx < BITMAP_WORDS {
            let mask = 1u64 << bit_idx;
            self.bitmap[word_idx] |= mask;
        }
    }
    
    /// フレームが空きかどうか確認
    fn is_frame_free(&self, frame: FrameIndex) -> bool {
        let word_idx = frame.word_index();
        let bit_idx = frame.bit_index();
        
        if word_idx >= BITMAP_WORDS {
            return false;
        }
        
        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }
    
    /// 4KiB フレームを1つ割り当て
    pub fn allocate_4k_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let hint = FrameIndex::new(self.next_free_hint as usize);
        let hint_word = hint.word_index();
        
        // ヒントの位置から検索開始
        for word_offset in 0..BITMAP_WORDS {
            let word_idx = (hint_word + word_offset) % BITMAP_WORDS;
            let word = self.bitmap[word_idx];
            
            // このワードに空きビットがあるか
            if word != u64::MAX {
                // 空きビットを見つける
                let bit_idx = (!word).trailing_zeros() as usize;
                let frame = FrameIndex::new(word_idx * 64 + bit_idx);
                
                if frame.as_usize() >= self.total_frames {
                    continue;
                }
                
                // Mutexで保護されているので通常のビット操作でOK
                self.bitmap[word_idx] |= 1u64 << bit_idx;
                self.free_frames -= 1;
                self.next_free_hint = frame.as_usize() as u64 + 1;
                
                let addr = PhysAddr::new(frame.to_phys_addr());
                return Some(PhysFrame::containing_address(addr));
            }
        }
        
        None
    }
    
    /// 連続する物理フレームを割り当て（2MiB, 1GiB用）
    pub fn allocate_contiguous(&mut self, frame_count: usize, alignment: usize) -> Option<PhysAddr> {
        let aligned_frames = alignment / PAGE_SIZE_4K;
        
        for start_word in 0..BITMAP_WORDS {
            let start_frame = start_word * 64;
            
            // アライメントに合わせる
            let aligned_start = (start_frame + aligned_frames - 1) / aligned_frames * aligned_frames;
            
            if aligned_start + frame_count > self.total_frames {
                break;
            }
            
            // 連続した空きフレームがあるかチェック
            let mut all_free = true;
            for i in 0..frame_count {
                if !self.is_frame_free(FrameIndex::new(aligned_start + i)) {
                    all_free = false;
                    break;
                }
            }
            
            if all_free {
                // 全て確保
                for i in 0..frame_count {
                    self.mark_frame_used(FrameIndex::new(aligned_start + i));
                }
                self.free_frames -= frame_count as u64;
                
                let start_frame = FrameIndex::new(aligned_start);
                return Some(PhysAddr::new(start_frame.to_phys_addr()));
            }
        }
        
        None
    }
    
    /// 2MiB フレームを割り当て
    pub fn allocate_2m_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let frames_needed = PAGE_SIZE_2M / PAGE_SIZE_4K; // 512
        self.allocate_contiguous(frames_needed, PAGE_SIZE_2M)
            .map(|addr| PhysFrame::containing_address(addr))
    }
    
    /// 1GiB フレームを割り当て（設計書5.1: 1GBページの活用）
    pub fn allocate_1g_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let frames_needed = PAGE_SIZE_1G / PAGE_SIZE_4K; // 262144
        self.allocate_contiguous(frames_needed, PAGE_SIZE_1G)
            .map(|addr| PhysFrame::containing_address(addr))
    }
    
    /// 4KiB フレームを解放
    pub fn deallocate_4k_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        self.mark_frame_free(frame_idx);
        self.free_frames += 1;
    }
    
    /// 2MiB フレームを解放
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_2M / PAGE_SIZE_4K;
        
        for i in 0..frames_count {
            self.mark_frame_free(FrameIndex::new(start_frame.as_usize() + i));
        }
        self.free_frames += frames_count as u64;
    }
    
    /// 空きフレーム数を取得
    pub fn free_frame_count(&self) -> u64 {
        self.free_frames
    }
    
    /// 総フレーム数を取得
    pub fn total_frame_count(&self) -> usize {
        self.total_frames
    }
}

// x86_64 crateのFrameAllocatorトレイトを実装
unsafe impl FrameAllocator<Size4KiB> for BitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_4k_frame()
    }
}

/// グローバルなフレームアロケータ
/// 割り込み禁止Mutexで保護（デッドロック防止）
static FRAME_ALLOCATOR: IrqMutex<BitmapFrameAllocator> = IrqMutex::new(BitmapFrameAllocator::new());

/// フレームアロケータを初期化
/// 
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_frame_allocator(usable_regions: &[(PhysAddr, u64)]) {
    // SAFETY: 呼び出し元がusable_regionsの正当性を保証
    unsafe { FRAME_ALLOCATOR.lock().init(usable_regions); }
}

/// 4KiB フレームを割り当て
pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    FRAME_ALLOCATOR.lock().allocate_4k_frame()
}

/// 2MiB フレームを割り当て
pub fn alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    FRAME_ALLOCATOR.lock().allocate_2m_frame()
}

/// 1GiB フレームを割り当て（設計書5.1: TLBエントリの消費を最小限に）
pub fn alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    FRAME_ALLOCATOR.lock().allocate_1g_frame()
}

/// 4KiB フレームを解放
pub fn dealloc_frame(frame: PhysFrame<Size4KiB>) {
    FRAME_ALLOCATOR.lock().deallocate_4k_frame(frame);
}

/// フレームアロケータの統計を取得
pub fn frame_allocator_stats() -> (u64, usize) {
    let allocator = FRAME_ALLOCATOR.lock();
    (allocator.free_frame_count(), allocator.total_frame_count())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bitmap_allocator() {
        let mut allocator = BitmapFrameAllocator::new();
        
        // テスト用のメモリ領域（1MiB）
        let regions = [(PhysAddr::new(0x100000), 0x100000u64)];
        unsafe {
            allocator.init(&regions);
        }
        
        // フレーム割り当て
        let frame1 = allocator.allocate_4k_frame();
        assert!(frame1.is_some());
        
        let frame2 = allocator.allocate_4k_frame();
        assert!(frame2.is_some());
        
        // 異なるフレームが割り当てられていることを確認
        assert_ne!(frame1.unwrap().start_address(), frame2.unwrap().start_address());
    }
}
