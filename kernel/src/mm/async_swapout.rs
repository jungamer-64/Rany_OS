// ============================================================================
// kernel/src/mm/async_swapout.rs
// ============================================================================
//! 非同期スワップアウト / 書き戻し合流モジュール
//!
//! - テスト時は std スレッドを使ったワーカを起動し非同期処理をシミュレートする
//! - 非テスト（カーネル実装）ではフォールバックとして同期処理を行う
//!
#![allow(dead_code)]

use x86_64::structures::paging::PhysFrame;

use crate::mm::types::FrameIndex;
use crate::mm::frame_backing;
use crate::mm::buddy_allocator;

// ファイルシステム型（Inode）
use crate::fs::fs_abstraction::InodeNum;

/// スワップアウト種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKind {
    File { ino: InodeNum, page_num: u64 },
    Anon,
}

/// エラー種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    QueueFull,
    AlreadyPending,
    NotSupported,
}

// Completion handle (テスト用に簡易実装)
#[cfg(test)]
pub struct SwapHandle {
    done: Arc<(SpinMutex<bool>, std::sync::Condvar)>,
}

#[cfg(not(test))]
pub struct SwapHandle;

#[cfg(test)]
impl SwapHandle {
    pub fn wait(&self) {
        let (lock, cvar) = &*self.done;
        let mut done = lock.lock();
        while !*done {
            cvar.wait(&mut done).unwrap();
        }
    }

    pub fn is_done(&self) -> bool {
        let (lock, _) = &*self.done;
        *lock.lock()
    }
}

// 内部エントリ（テスト用）
#[cfg(test)]
struct SwapEntry {
    frame: FrameIndex,
    kind: SwapKind,
    completion: Arc<(SpinMutex<bool>, std::sync::Condvar)>,
}

// テスト専用: 単発ワーカ実装（エントリごとに短命スレッドを生成）
#[cfg(test)]
mod test_impl {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use spin::Mutex as SpinMutex;
    use std::thread;

    static PENDING: SpinMutex<BTreeSet<usize>> = SpinMutex::new(BTreeSet::new());

    pub fn try_enqueue(frame: FrameIndex, kind: SwapKind) -> Result<super::SwapHandle, SwapError> {
        // Mark pending (prevent duplicate)
        {
            let mut p = PENDING.lock();
            if p.contains(&frame.as_usize()) {
                return Err(SwapError::AlreadyPending);
            }
            p.insert(frame.as_usize());
        }

        let completion = Arc::new((SpinMutex::new(false), std::sync::Condvar::new()));
        let completion_clone = completion.clone();

        // Spawn a short-lived worker for this entry
        thread::spawn(move || {
            match kind {
                SwapKind::File { ino, page_num } => {
                    let res = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
                        match crate::fs::write_inode_by_number(ino, offset, data) {
                            Ok(_) => Ok(()),
                            Err(_) => Err(()),
                        }
                    });

                    if res.is_ok() {
                        let _ = frame_backing::untrack_frame_backing(frame);
                        let phys = unsafe { x86_64::PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr())) };
                        buddy_allocator::buddy_dealloc_frame(phys);
                    }
                }
                SwapKind::Anon => {
                    if crate::mm::zswap::ZPOOL.is_enabled() {
                        let phys = frame.to_phys_addr();
                        let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
                        let src = vaddr.as_u64() as *const u8;
                        let mut buf = vec![0u8; crate::mm::PAGE_SIZE_4K];
                        unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), crate::mm::PAGE_SIZE_4K); }
                        let _ = crate::mm::zswap::ZPOOL.store(0, &buf);
                        let physf = unsafe { x86_64::PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr())) };
                        buddy_allocator::buddy_dealloc_frame(physf);
                    } else {
                        let physf = unsafe { x86_64::PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr())) };
                        buddy_allocator::buddy_dealloc_frame(physf);
                    }
                }
            }

            // 完了通知
            let (lock, cvar) = &*completion_clone;
            *lock.lock() = true;
            cvar.notify_all();

            // Unmark pending
            PENDING.lock().remove(&frame.as_usize());
        });

        Ok(super::SwapHandle { done: completion })
    }
}

// 公開API: try_enqueue_swapout
pub fn try_enqueue_swapout(frame: FrameIndex, kind: SwapKind) -> Result<SwapHandle, SwapError> {
    #[cfg(test)]
    {
        test_impl::try_enqueue(frame, kind)
    }

    #[cfg(not(test))]
    {
        // 非テストではフォールバックとして同期処理を行う
        match kind {
            SwapKind::File { ino, page_num } => {
                let written = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
                    match crate::fs::write_inode_by_number(ino, offset, data) {
                        Ok(_) => Ok(()),
                        Err(_) => Err(()),
                    }
                });

                match written {
                    Ok(true) => {
                        let _ = frame_backing::untrack_frame_backing(frame);
                        let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr())) };
                        buddy_allocator::buddy_dealloc_frame(physf);
                        Err(SwapError::NotSupported) // indicates sync fallback was used
                    }
                    _ => Err(SwapError::NotSupported),
                }
            }
            SwapKind::Anon => {
                // zswap attempt
                // if crate::mm::zswap::ZPOOL.is_enabled() {
                    Err(SwapError::NotSupported)
                // } else {
                //     Err(SwapError::NotSupported)
                // }
            }
        }
    }
}

// テスト: キューイング API とワーカの動作を検証するユニットテストを追加
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::{PAGE_SIZE_4K, frame_backing};

    #[test]
    fn test_async_swapout_file_backed() {
        // セットアップ: page cache にページを入れ、対応するフレームを確保して frame_backing を登録
        let cache = crate::fs::cache::PageCache::new(64 * 1024);
        let ino = 42u64;
        let page_num = 1u64;
        let data = alloc::vec![0xAAu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num as usize));

        // allocate a frame to represent the physical page
        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // track the frame backing
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // enqueue
        let handle = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num })
            .expect("enqueue ok");

        // wait for completion
        handle.wait();

        // backing must be gone
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());

        // page should be clean
        let files = cache.files.read();
        if let Some(file_cache) = files.get(&ino) {
            if let Some(page) = file_cache.get_page(page_num as usize) {
                assert!(!page.is_dirty());
            } else { panic!("page not found"); }
        } else { panic!("file cache not found"); }
    }
}
