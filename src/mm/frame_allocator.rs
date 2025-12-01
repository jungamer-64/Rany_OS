// ============================================================================
// src/mm/frame_allocator.rs - Bitmap-based Physical Frame Allocator
// 設計書 5.2 Tier1: 4KiB/2MiB/1GiB単位の物理フレーム管理
// ============================================================================
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB, Size2MiB, Size1GiB};
use x86_64::PhysAddr;

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
pub struct BitmapFrameAllocator {
    /// ビットマップ（1 = 使用中, 0 = 空き）
    bitmap: [AtomicU64; BITMAP_WORDS],
    /// 総フレーム数
    total_frames: usize,
    /// 空きフレーム数（統計用）
    free_frames: AtomicU64,
    /// 最初の空き領域のヒント（高速化用）
    next_free_hint: AtomicU64,
}

impl BitmapFrameAllocator {
    /// 新しいフレームアロケータを作成（未初期化）
    pub const fn new() -> Self {
        const ATOMIC_ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            bitmap: [ATOMIC_ZERO; BITMAP_WORDS],
            total_frames: 0,
            free_frames: AtomicU64::new(0),
            next_free_hint: AtomicU64::new(0),
        }
    }
    
    /// メモリマップに基づいてアロケータを初期化
    /// 
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    pub unsafe fn init(&mut self, usable_regions: &[(PhysAddr, u64)]) {
        // 最初は全てを使用中としてマーク
        for word in self.bitmap.iter() {
            word.store(u64::MAX, Ordering::Relaxed);
        }
        
        let mut total = 0usize;
        let mut free = 0u64;
        
        // 使用可能な領域を空きとしてマーク
        for &(start, size) in usable_regions {
            let start_frame = start.as_u64() as usize / PAGE_SIZE_4K;
            let end_frame = (start.as_u64() as usize + size as usize) / PAGE_SIZE_4K;
            
            for frame in start_frame..end_frame {
                if frame < MAX_4K_FRAMES {
                    self.mark_frame_free(frame);
                    free += 1;
                }
            }
            
            total = total.max(end_frame);
        }
        
        self.total_frames = total;
        self.free_frames.store(free, Ordering::Relaxed);
    }
    
    /// フレームを空きとしてマーク
    fn mark_frame_free(&self, frame: usize) {
        let word_idx = frame / 64;
        let bit_idx = frame % 64;
        
        if word_idx < BITMAP_WORDS {
            let mask = !(1u64 << bit_idx);
            self.bitmap[word_idx].fetch_and(mask, Ordering::Relaxed);
        }
    }
    
    /// フレームを使用中としてマーク
    fn mark_frame_used(&self, frame: usize) {
        let word_idx = frame / 64;
        let bit_idx = frame % 64;
        
        if word_idx < BITMAP_WORDS {
            let mask = 1u64 << bit_idx;
            self.bitmap[word_idx].fetch_or(mask, Ordering::Relaxed);
        }
    }
    
    /// フレームが空きかどうか確認
    fn is_frame_free(&self, frame: usize) -> bool {
        let word_idx = frame / 64;
        let bit_idx = frame % 64;
        
        if word_idx >= BITMAP_WORDS {
            return false;
        }
        
        let word = self.bitmap[word_idx].load(Ordering::Relaxed);
        (word & (1u64 << bit_idx)) == 0
    }
    
    /// 4KiB フレームを1つ割り当て
    pub fn allocate_4k_frame(&self) -> Option<PhysFrame<Size4KiB>> {
        let hint = self.next_free_hint.load(Ordering::Relaxed) as usize;
        let hint_word = hint / 64;
        
        // ヒントの位置から検索開始
        for word_offset in 0..BITMAP_WORDS {
            let word_idx = (hint_word + word_offset) % BITMAP_WORDS;
            let word = self.bitmap[word_idx].load(Ordering::Relaxed);
            
            // このワードに空きビットがあるか
            if word != u64::MAX {
                // 空きビットを見つける
                let bit_idx = (!word).trailing_zeros() as usize;
                let frame = word_idx * 64 + bit_idx;
                
                if frame >= self.total_frames {
                    continue;
                }
                
                // CAS で確保を試みる
                let mask = 1u64 << bit_idx;
                let prev = self.bitmap[word_idx].fetch_or(mask, Ordering::AcqRel);
                
                if (prev & mask) == 0 {
                    // 成功
                    self.free_frames.fetch_sub(1, Ordering::Relaxed);
                    self.next_free_hint.store(frame as u64 + 1, Ordering::Relaxed);
                    
                    let addr = PhysAddr::new((frame * PAGE_SIZE_4K) as u64);
                    return Some(PhysFrame::containing_address(addr));
                }
                // 他のスレッドに取られた、リトライ
            }
        }
        
        None
    }
    
    /// 連続する物理フレームを割り当て（2MiB, 1GiB用）
    pub fn allocate_contiguous(&self, frame_count: usize, alignment: usize) -> Option<PhysAddr> {
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
                if !self.is_frame_free(aligned_start + i) {
                    all_free = false;
                    break;
                }
            }
            
            if all_free {
                // 全て確保
                for i in 0..frame_count {
                    self.mark_frame_used(aligned_start + i);
                }
                self.free_frames.fetch_sub(frame_count as u64, Ordering::Relaxed);
                
                return Some(PhysAddr::new((aligned_start * PAGE_SIZE_4K) as u64));
            }
        }
        
        None
    }
    
    /// 2MiB フレームを割り当て
    pub fn allocate_2m_frame(&self) -> Option<PhysFrame<Size2MiB>> {
        let frames_needed = PAGE_SIZE_2M / PAGE_SIZE_4K; // 512
        self.allocate_contiguous(frames_needed, PAGE_SIZE_2M)
            .map(|addr| PhysFrame::containing_address(addr))
    }
    
    /// 1GiB フレームを割り当て（設計書5.1: 1GBページの活用）
    pub fn allocate_1g_frame(&self) -> Option<PhysFrame<Size1GiB>> {
        let frames_needed = PAGE_SIZE_1G / PAGE_SIZE_4K; // 262144
        self.allocate_contiguous(frames_needed, PAGE_SIZE_1G)
            .map(|addr| PhysFrame::containing_address(addr))
    }
    
    /// 4KiB フレームを解放
    pub fn deallocate_4k_frame(&self, frame: PhysFrame<Size4KiB>) {
        let frame_num = frame.start_address().as_u64() as usize / PAGE_SIZE_4K;
        self.mark_frame_free(frame_num);
        self.free_frames.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 2MiB フレームを解放
    pub fn deallocate_2m_frame(&self, frame: PhysFrame<Size2MiB>) {
        let start_frame = frame.start_address().as_u64() as usize / PAGE_SIZE_4K;
        let frames_count = PAGE_SIZE_2M / PAGE_SIZE_4K;
        
        for i in 0..frames_count {
            self.mark_frame_free(start_frame + i);
        }
        self.free_frames.fetch_add(frames_count as u64, Ordering::Relaxed);
    }
    
    /// 空きフレーム数を取得
    pub fn free_frame_count(&self) -> u64 {
        self.free_frames.load(Ordering::Relaxed)
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
static FRAME_ALLOCATOR: Mutex<BitmapFrameAllocator> = Mutex::new(BitmapFrameAllocator::new());

/// フレームアロケータを初期化
/// 
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_frame_allocator(usable_regions: &[(PhysAddr, u64)]) {
    FRAME_ALLOCATOR.lock().init(usable_regions);
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
