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
use alloc::sync::Arc;

#[cfg(test)]
pub struct SwapHandle {
    done: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(not(test))]
pub struct SwapHandle;

#[cfg(test)]
impl SwapHandle {
    pub fn wait(&self) {
        let (lock, cvar) = &*self.done;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = cvar.wait(done).unwrap();
        }
    }

    pub fn is_done(&self) -> bool {
        let (lock, _) = &*self.done;
        *lock.lock().unwrap()
    }
} 

// 内部エントリ（テスト用）
#[cfg(test)]
struct SwapEntry {
    frame: FrameIndex,
    kind: SwapKind,
    completion: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
} 

// テスト専用: 永続ワーカ実装（条件変数 + バウンドキュー）
#[cfg(test)]
mod test_impl {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;
    use std::collections::VecDeque;
    use std::sync::{Mutex as StdMutex, Condvar};
    use spin::Once;
    use std::thread;

    /// キュー容量／バッチサイズはテスト向けに控えめに設定可能
    const QUEUE_CAPACITY: usize = 1024;
    const BATCH_SIZE: usize = 32;

    struct WorkerInner {
        queue: StdMutex<VecDeque<SwapEntry>>,
        pending: StdMutex<BTreeSet<usize>>,
        condvar: Condvar,
    }

    static WORKER: Once<Option<Arc<WorkerInner>>> = Once::new();

    fn init_worker() -> Arc<WorkerInner> {
        WORKER.call_once(|| {
            let inner = Arc::new(WorkerInner {
                queue: StdMutex::new(VecDeque::new()),
                pending: StdMutex::new(BTreeSet::new()),
                condvar: Condvar::new(),
            });

            // 永続ワーカスレッドを生成
            let thread_inner = inner.clone();
            thread::spawn(move || {
                loop {
                    // キューからバッチを取り出す
                    let mut q_guard = thread_inner.queue.lock().unwrap();
                    while q_guard.is_empty() {
                        q_guard = thread_inner.condvar.wait(q_guard).unwrap();
                    }

                    let mut batch = Vec::new();
                    for _ in 0..BATCH_SIZE {
                        if let Some(entry) = q_guard.pop_front() {
                            batch.push(entry);
                        } else {
                            break;
                        }
                    }
                    drop(q_guard);

                    // バッチ処理
                    for entry in batch {
                        match entry.kind {
                            SwapKind::File { ino, page_num } => {
                                let res = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
                                    match crate::fs::write_inode_by_number(ino, offset, data) {
                                        Ok(_) => Ok(()),
                                        Err(_) => Err(()),
                                    }
                                });

                                if res.is_ok() {
                                    let _ = frame_backing::untrack_frame_backing(entry.frame);
                                    let phys = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                    buddy_allocator::buddy_dealloc_frame(phys);
                                }
                            }
                            SwapKind::Anon => {
                                if crate::mm::zswap::ZPOOL.is_enabled() {
                                    let phys = entry.frame.to_phys_addr();
                                    let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
                                    let src = vaddr.as_u64() as *const u8;
                                    let mut buf = vec![0u8; crate::mm::PAGE_SIZE_4K];
                                    unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), crate::mm::PAGE_SIZE_4K); }
                                    let _ = crate::mm::zswap::ZPOOL.store(0, &buf);
                                    let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                    buddy_allocator::buddy_dealloc_frame(physf);
                                } else {
                                    let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                    buddy_allocator::buddy_dealloc_frame(physf);
                                }
                            }
                        }

                        // 完了通知
                        let (lock, cvar) = &*entry.completion;
                        let mut done = lock.lock().unwrap();
                        *done = true;
                        cvar.notify_all();

                        // pending を解除
                        thread_inner.pending.lock().unwrap().remove(&entry.frame.as_usize());
                    }
                }
            });

            Some(inner)
        });

        WORKER.get().as_ref().unwrap().clone()
    }

    pub fn try_enqueue(frame: FrameIndex, kind: SwapKind) -> Result<super::SwapHandle, SwapError> {
        let worker = init_worker();

        // pending と容量チェック
        {
            let mut pending = worker.pending.lock().unwrap();
            if pending.contains(&frame.as_usize()) {
                return Err(SwapError::AlreadyPending);
            }

            let q = worker.queue.lock().unwrap();
            if q.len() >= QUEUE_CAPACITY {
                return Err(SwapError::QueueFull);
            }

            pending.insert(frame.as_usize());
        }

        let completion = Arc::new((StdMutex::new(false), Condvar::new()));
        let entry = SwapEntry { frame, kind, completion: completion.clone() };

        {
            let mut q = worker.queue.lock().unwrap();
            q.push_back(entry);
            worker.condvar.notify_one();
        }

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

    #[test]
    fn test_async_swapout_dedup() {
        // setup similar to file-backed test
        let cache = crate::fs::cache::PageCache::new(64 * 1024);
        let ino = 43u64;
        let page_num = 2u64;
        let data = alloc::vec![0xBBu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num as usize));

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // first enqueue should succeed
        let handle1 = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");

        // second enqueue for same frame should return AlreadyPending
        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect_err("should be pending");
        assert_eq!(err, SwapError::AlreadyPending);

        // wait for first completion, then enqueue again
        handle1.wait();
        let handle2 = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");
        handle2.wait();

        // after completion backing must be removed
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());
    }
}
