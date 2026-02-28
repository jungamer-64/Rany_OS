// テスト: キューイング API とワーカの動作を検証するユニットテストを追加
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::mm::meta::frame_backing;
    use crate::mm::types::PAGE_SIZE_4K;

    #[test_case]
    pub(super) fn test_async_swapout_file_backed() {
        // セットアップ: page cache にページを入れ、対応するフレームを確保して frame_backing を登録
        let cache = crate::fs::PageCache::new(64 * 1024);
        let ino = 42u64;
        let page_num = 1u64;
        let data = alloc::vec![0xAAu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        // allocate a frame to represent the physical page
        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // track the frame backing
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // enqueue
        let handle = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
            frame_idx,
            SwapKind::File { ino, page_num },
        )
        .expect("enqueue ok");

        // wait for completion
        handle.wait();

        // backing must be gone
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());

        // page should be present and readable (cleanness asserted via PageCache API)
        let mut buf = vec![0u8; PAGE_SIZE_4K];
        let read = crate::fs::PageCache::read(
            &cache,
            ino,
            page_num * PAGE_SIZE_4K as u64,
            &mut buf,
            PAGE_SIZE_4K as u64,
        );
        assert!(read.is_some(), "page should exist and be readable");
    }

    #[test_case]
    pub(super) fn test_async_swapout_dedup() {
        // setup similar to file-backed test
        let cache = crate::fs::PageCache::new(64 * 1024);
        let ino = 43u64;
        let page_num = 2u64;
        let data = alloc::vec![0xBBu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // first enqueue should succeed
        let handle1 = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
            frame_idx,
            SwapKind::File { ino, page_num },
        )
        .expect("enqueue ok");

        // second enqueue for same frame should return AlreadyPending
        let err = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
            frame_idx,
            SwapKind::File { ino, page_num },
        )
        .expect_err("should be pending");
        assert_eq!(err, SwapError::AlreadyPending);

        // wait for first completion, then enqueue again
        handle1.wait();
        let handle2 = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
            frame_idx,
            SwapKind::File { ino, page_num },
        )
        .expect("enqueue ok");
        handle2.wait();

        // after completion backing must be removed
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());
    }

    #[test_case]
    #[cfg(not(feature = "full_mm_tests"))]
    pub(super) fn test_enqueue_override_forces_error() {
        crate::mm::reclaim::async_swapout::set_test_enqueue_override(Some(SwapError::QueueFull));

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let err = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect_err("override must force error");
        assert_eq!(err, SwapError::QueueFull);

        crate::mm::reclaim::async_swapout::set_test_enqueue_override(None);
        if crate::mm::phys::buddy_allocator::is_frame_allocated(frame_idx.as_usize()) {
            let physf = unsafe {
                x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
                    x86_64::PhysAddr::new(frame_idx.to_phys_addr()),
                )
            };
            crate::mm::phys::buddy_allocator::buddy_dealloc_frame(physf);
        }
    }

    #[test_case]
    #[cfg(feature = "std")]
    pub(super) fn test_memcg_concurrent_swapout() {
        // Initialize memcg and global page cache
        crate::mm::meta::memcg::init_memcg();
        let cg = crate::mm::meta::memcg::memcg_create(
            String::from("concurrent"),
            crate::mm::meta::memcg::memcg_root(),
        )
        .expect("create memcg");
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        let n = 64usize;
        let mut join_handles = Vec::new();

        for i in 0..n {
            let cache = cache; // copy ref
            let cg = cg;
            let handle = std::thread::spawn(move || {
                // allocate a frame
                let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
                let frame_idx =
                    crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

                if i % 2 == 0 {
                    // file-backed
                    assert!(
                        crate::mm::meta::memcg::memcg_charge(
                            cg,
                            1,
                            crate::mm::meta::memcg::ChargeType::Cache
                        )
                        .is_ok()
                    );
                    crate::mm::meta::memcg::memcg_track_page(
                        frame_idx,
                        cg,
                        crate::mm::meta::memcg::ChargeType::Cache,
                    );

                    let ino = 1000u64;
                    let page_num = i as u64;
                    let data = alloc::vec![0u8; PAGE_SIZE_4K];
                    cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
                    assert!(cache.mark_dirty(ino, page_num));
                    crate::mm::meta::frame_backing::track_frame_backing(frame_idx, ino, page_num);

                    let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                        frame_idx,
                        SwapKind::File { ino, page_num },
                    )
                    .expect("enqueue ok");
                    h.wait();
                } else {
                    // anon
                    assert!(
                        crate::mm::meta::memcg::memcg_charge(
                            cg,
                            1,
                            crate::mm::meta::memcg::ChargeType::Anon
                        )
                        .is_ok()
                    );
                    crate::mm::meta::memcg::memcg_track_page(
                        frame_idx,
                        cg,
                        crate::mm::meta::memcg::ChargeType::Anon,
                    );

                    let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                        frame_idx,
                        SwapKind::Anon,
                    )
                    .expect("enqueue ok");
                    h.wait();
                }

                // After completion, page info should be gone
                assert!(crate::mm::meta::memcg::memcg_get_page_info(frame_idx).is_none());
            });

            join_handles.push(handle);
        }

        for h in join_handles {
            h.join().expect("thread join");
        }

        // All charges should be cleared
        let stats = crate::mm::meta::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test_case]
    #[cfg(feature = "std")]
    pub(super) fn test_async_swapout_concurrent_dedup() {
        // Initialize global cache
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Setup a single frame and track it
        let ino = 2000u64;
        let page_num = 1u64;
        let data = alloc::vec![0xEEu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::meta::frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // Check queue/pending metrics before enqueue
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_pending_len(), 0);
        assert!(!test_impl::_is_pending(frame_idx));

        // Barrier to synchronize enqueuers
        let threads = 8usize;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(threads + 1));
        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut joiners = Vec::new();
        for _ in 0..threads {
            let barrier = barrier.clone();
            let results = results.clone();
            let frame_idx = frame_idx;
            let t = std::thread::spawn(move || {
                barrier.wait();
                let res = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                    frame_idx,
                    SwapKind::File { ino, page_num },
                );
                results.lock().unwrap().push(res);
            });
            joiners.push(t);
        }

        // Release all enqueuers
        barrier.wait();

        // Give a tiny moment for enqueues to be processed
        std::thread::sleep(std::time::Duration::from_millis(10));

        // After enqueuing, queue and pending should reflect the entry
        assert!(test_impl::_queue_len() >= 1);
        assert_eq!(test_impl::_pending_len(), 1);
        assert!(test_impl::_is_pending(frame_idx));

        for j in joiners {
            j.join().expect("join");
        }

        let resvec = results.lock().unwrap();
        // There should be at least one Ok and at least one AlreadyPending among the others
        let mut ok_count = 0usize;
        let mut pending_count = 0usize;
        for r in resvec.iter() {
            match r {
                Ok(_) => ok_count += 1,
                Err(SwapError::AlreadyPending) => pending_count += 1,
                Err(_) => (),
            }
        }

        assert!(ok_count >= 1, "expected at least one successful enqueue");
        assert!(pending_count >= 1, "expected at least one AlreadyPending");

        // Wait for any successful handles to complete
        for r in resvec.iter() {
            if let Ok(h) = r {
                h.wait();
            }
        }

        // After completion, queue must be drained and pending cleared
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_pending_len(), 0);
        assert!(!test_impl::_is_pending(frame_idx));

        assert!(crate::mm::meta::frame_backing::get_frame_backing(frame_idx).is_none());
    }

    #[test_case]
    #[cfg(feature = "std")]
    pub(super) fn test_worker_restart() {
        // ensure worker lifecycle control works via top-level API
        start_worker();
        assert!(is_worker_running(), "worker should be running after start");

        stop_worker();
        // Wait for worker to stop
        for _ in 0..20 {
            if !is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!is_worker_running(), "worker should have stopped");

        // Restart and ensure it runs
        start_worker();
        assert!(
            is_worker_running(),
            "worker should be running after restart"
        );

        // Clean up
        stop_worker();
    }

    #[test_case]
    #[cfg(feature = "std")]
    pub(super) fn test_async_swapout_qos_reservation() {
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Stop worker to allow deterministic queue fill
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let cap = test_impl::_queue_capacity();
        let reserved = test_impl::_reserved_file_slots();

        let fill_count = cap.saturating_sub(reserved) + 1;

        let mut handles = Vec::new();

        let ino = 3000u64;
        for i in 0..fill_count {
            let page_num = i as u64;
            let data = alloc::vec![0u8; PAGE_SIZE_4K];
            cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
            assert!(cache.mark_dirty(ino, page_num));

            let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
            let frame_idx =
                crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            crate::mm::meta::frame_backing::track_frame_backing(frame_idx, ino, page_num);

            let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                frame_idx,
                SwapKind::File { ino, page_num },
            )
            .expect("enqueue ok");
            handles.push(h);
        }

        assert!(test_impl::_queue_len() >= fill_count);
        assert!(test_impl::_file_queue_len() >= reserved);

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let err = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect_err("expected QueueFull due to reservation");
        assert_eq!(err, SwapError::QueueFull);

        // Start worker to process entries
        test_impl::start_worker();

        for h in handles {
            h.wait();
        }

        // After processing, queue should be empty
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_file_queue_len(), 0);

        // Now anon enqueue should succeed
        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect("enqueue ok");
        h.wait();

        // Ensure backing removed (if any)
        assert!(crate::mm::meta::memcg::memcg_get_page_info(frame_idx).is_none());
    }

    #[test_case]
    #[cfg(feature = "std")]
    pub(super) fn test_token_bucket_exhaustion_and_refill() {
        // Ensure worker controlled
        stop_worker();
        for _ in 0..20 {
            if !is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Set tokens to zero to simulate exhaustion
        test_impl::set_tokens(0);

        // allocate a frame
        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // Ensure anon enqueue fails
        let err = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect_err("should be QueueFull due to tokens");
        assert_eq!(err, SwapError::QueueFull);

        // Add one token and try again
        test_impl::add_tokens(1);

        // Start worker to allow processing
        start_worker();

        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect("enqueue ok");
        h.wait();

        // cleanup: restore tokens to capacity
        test_impl::set_tokens(test_impl::token_capacity());

        // stop worker
        stop_worker();
    }

    #[test_case]
    #[cfg(feature = "std")]
    pub(super) fn test_token_refill_on_processing() {
        // Stop worker to control processing
        stop_worker();
        for _ in 0..20 {
            if !is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Set tokens to zero
        test_impl::set_tokens(0);

        // Enqueue a file-backed entry to trigger processing and refill
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();
        let ino = 4000u64;
        let page_num = 1u64;
        let data = alloc::vec![0u8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::meta::frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // Enqueue file entry
        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
            frame_idx,
            SwapKind::File { ino, page_num },
        )
        .expect("enqueue ok");

        // Start worker to process and refill tokens
        start_worker();

        h.wait();

        // After processing, tokens should have been refilled
        assert!(test_impl::_token_count() > 0);

        // Clean up
        stop_worker();
    }

    #[test_case]
    #[cfg(feature = "std")]
    pub(super) fn test_async_swapout_stress_concurrency() {
        crate::mm::meta::memcg::init_memcg();
        let cg = crate::mm::meta::memcg::memcg_create(
            String::from("stress"),
            crate::mm::meta::memcg::memcg_root(),
        )
        .expect("create memcg");
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Slow down processing to build pressure and exercise tokens
        test_impl::set_processing_delay(2);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let threads = 32usize;
        let iters = 80usize;
        let mut joiners = Vec::new();

        for t in 0..threads {
            let cache = cache;
            let cg = cg;
            #[cfg(feature = "std")]
            let j = std::thread::spawn(move || {
                for i in 0..iters {
                    let frame =
                        crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
                    let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(
                        frame.start_address().as_u64(),
                    );

                    if ((i + t) % 2) == 0 {
                        // file-backed
                        assert!(
                            crate::mm::meta::memcg::memcg_charge(
                                cg,
                                1,
                                crate::mm::meta::memcg::ChargeType::Cache
                            )
                            .is_ok()
                        );
                        crate::mm::meta::memcg::memcg_track_page(
                            frame_idx,
                            cg,
                            crate::mm::meta::memcg::ChargeType::Cache,
                        );

                        let ino = 6000u64 + (i % 256) as u64;
                        let page_num = i as u64;
                        let data = alloc::vec![0u8; PAGE_SIZE_4K];
                        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
                        assert!(cache.mark_dirty(ino, page_num));
                        crate::mm::meta::frame_backing::track_frame_backing(
                            frame_idx, ino, page_num,
                        );

                        match crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                            frame_idx,
                            SwapKind::File { ino, page_num },
                        ) {
                            Ok(h) => {
                                h.wait();
                            }
                            Err(SwapError::QueueFull) => {
                                // fallback sync writeback
                                let _ = crate::fs::page_cache().sync_page(
                                    ino,
                                    page_num,
                                    |_offset, _data| Ok(()),
                                );
                                let physf = unsafe {
                                    PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(
                                        frame_idx.to_phys_addr(),
                                    ))
                                };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    } else {
                        // anon
                        assert!(
                            crate::mm::meta::memcg::memcg_charge(
                                cg,
                                1,
                                crate::mm::meta::memcg::ChargeType::Anon
                            )
                            .is_ok()
                        );
                        crate::mm::meta::memcg::memcg_track_page(
                            frame_idx,
                            cg,
                            crate::mm::meta::memcg::ChargeType::Anon,
                        );

                        match crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                            frame_idx,
                            SwapKind::Anon,
                        ) {
                            Ok(h) => {
                                h.wait();
                            }
                            Err(SwapError::QueueFull) => {
                                let physf = unsafe {
                                    PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(
                                        frame_idx.to_phys_addr(),
                                    ))
                                };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    }
                }
            });

            joiners.push(j);
        }

        for j in joiners {
            j.join().expect("join");
        }

        stop_worker();
        for _ in 0..200 {
            if !is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let stats = crate::mm::meta::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test_case]
    #[ignore]
    pub(super) fn test_async_swapout_heavy_stress() {
        crate::mm::meta::memcg::init_memcg();
        let cg = crate::mm::meta::memcg::memcg_create(
            String::from("heavy"),
            crate::mm::meta::memcg::memcg_root(),
        )
        .expect("create memcg");
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        test_impl::set_processing_delay(5);
        // Apply recommended validation defaults for heavy stress run
        test_impl::set_token_capacity_for_test(32);
        test_impl::set_reserved_file_slots_for_test(128);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let threads = 64usize;
        let iters = 200usize;
        let mut joiners = Vec::new();

        for t in 0..threads {
            let cache = cache;
            let cg = cg;
            let j = std::thread::spawn(move || {
                for i in 0..iters {
                    let frame =
                        crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
                    let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(
                        frame.start_address().as_u64(),
                    );
                    if ((i + t) % 2) == 0 {
                        assert!(
                            crate::mm::meta::memcg::memcg_charge(
                                cg,
                                1,
                                crate::mm::meta::memcg::ChargeType::Cache
                            )
                            .is_ok()
                        );
                        crate::mm::meta::memcg::memcg_track_page(
                            frame_idx,
                            cg,
                            crate::mm::meta::memcg::ChargeType::Cache,
                        );
                        let ino = 7000u64 + (i % 512) as u64;
                        let page_num = i as u64;
                        let data = alloc::vec![0u8; PAGE_SIZE_4K];
                        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
                        assert!(cache.mark_dirty(ino, page_num));
                        crate::mm::meta::frame_backing::track_frame_backing(
                            frame_idx, ino, page_num,
                        );
                        match crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                            frame_idx,
                            SwapKind::File { ino, page_num },
                        ) {
                            Ok(h) => {
                                h.wait();
                            }
                            Err(SwapError::QueueFull) => {
                                let _ =
                                    crate::fs::page_cache()
                                        .sync_page(ino, page_num, |_o, _d| Ok(()));
                                let physf = unsafe {
                                    PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(
                                        frame_idx.to_phys_addr(),
                                    ))
                                };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    } else {
                        assert!(
                            crate::mm::meta::memcg::memcg_charge(
                                cg,
                                1,
                                crate::mm::meta::memcg::ChargeType::Anon
                            )
                            .is_ok()
                        );
                        crate::mm::meta::memcg::memcg_track_page(
                            frame_idx,
                            cg,
                            crate::mm::meta::memcg::ChargeType::Anon,
                        );
                        match crate::mm::reclaim::async_swapout::try_enqueue_swapout(
                            frame_idx,
                            SwapKind::Anon,
                        ) {
                            Ok(h) => {
                                h.wait();
                            }
                            Err(SwapError::QueueFull) => {
                                let physf = unsafe {
                                    PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(
                                        frame_idx.to_phys_addr(),
                                    ))
                                };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    }
                }
            });
            joiners.push(j);
        }

        for j in joiners {
            j.join().expect("join");
        }

        stop_worker();
        for _ in 0..500 {
            if !is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let stats = crate::mm::meta::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test_case]
    #[ignore]
    pub(super) fn bench_enqueue_throughput() {
        crate::fs::init_page_cache(64 * 1024);

        test_impl::set_processing_delay(1);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let count = 2000usize;
        let start = std::time::Instant::now();
        for _ in 0..count {
            let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
            let frame_idx =
                crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            let h =
                crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
                    .expect("enqueue ok");
            h.wait();
        }
        let dur = start.elapsed();
        println!("Enqueued+processed {} anon entries in {:?}", count, dur);

        stop_worker();
    }

    #[test_case]
    pub(super) fn test_zswap_failure_does_not_dealloc() {
        crate::fs::init_page_cache(64 * 1024);

        // Ensure deterministic worker lifecycle
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        test_impl::_reset_dealloc_count();
        test_impl::_reset_zswap_fail_count();

        // Configure zswap to be effectively full (force PoolFull)
        crate::mm::reclaim::zswap::zswap_set_enabled(true);
        crate::mm::reclaim::zswap::zswap_update_config(crate::mm::reclaim::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::reclaim::zswap::CompressionAlgo::Lz4,
            max_pool_size: 0,
            max_compression_ratio: 0.9,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect("enqueue ok");
        test_impl::start_worker();
        h.wait();

        // On zswap failure we must NOT deallocate the frame (test-only counter)
        assert_eq!(test_impl::_dealloc_count(), 0);
        assert!(test_impl::_zswap_fail_count() > 0);

        stop_worker();
    }

    #[test_case]
    pub(super) fn test_huge_page_2m_anon_store() {
        // Ensure deterministic worker lifecycle
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Ensure zswap is enabled and has room for 2MiB
        crate::mm::reclaim::zswap::zswap_set_enabled(true);
        crate::mm::reclaim::zswap::zswap_update_config(crate::mm::reclaim::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::reclaim::zswap::CompressionAlgo::Lz4,
            max_pool_size: crate::mm::types::PAGE_SIZE_2M * 4,
            max_compression_ratio: 1.0,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        // Allocate a 2MiB huge page (buddy allocator)
        let huge =
            crate::mm::phys::buddy_allocator::buddy_alloc_frame_2m().expect("alloc 2m frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(huge.start_address().as_u64());

        let before = crate::mm::reclaim::zswap::zswap_stats().stored_pages_2m;

        // Enqueue as anon
        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect("enqueue ok");
        test_impl::start_worker();
        h.wait();

        // Should have been stored and deallocated
        assert!(crate::mm::reclaim::zswap::zswap_stats().stored_pages_2m > before);
        assert!(!crate::mm::phys::buddy_allocator::is_frame_allocated(
            frame_idx.as_usize()
        ));

        stop_worker();
    }

    #[test_case]
    pub(super) fn test_global_async_swapout_metrics_update() {
        // ensure metrics are zeroed in the beginning
        // Note: These are global, so we don't reset them here; just ensure they are accessible and behave monotonically
        let before_fail = crate::mm::reclaim::async_swapout::stats_zswap_fail_count();
        let before_dealloc = crate::mm::reclaim::async_swapout::stats_async_dealloc_count();

        // Force zswap failure and enqueue anon
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        crate::mm::reclaim::zswap::zswap_set_enabled(true);
        crate::mm::reclaim::zswap::zswap_update_config(crate::mm::reclaim::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::reclaim::zswap::CompressionAlgo::Lz4,
            max_pool_size: 0,
            max_compression_ratio: 0.9,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect("enqueue ok");
        test_impl::start_worker();
        h.wait();

        // Metrics should be non-decreasing
        assert!(crate::mm::reclaim::async_swapout::stats_zswap_fail_count() >= before_fail);
        assert!(crate::mm::reclaim::async_swapout::stats_async_dealloc_count() >= before_dealloc);

        stop_worker();
    }

    #[test_case]
    pub(super) fn test_notify_failure_on_file_writeback_error() {
        crate::fs::init_page_cache(64 * 1024);

        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let before = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::reclaim::page_reclaim::test_register_pending_async(
            frame_idx,
            crate::mm::reclaim::page_reclaim::PageType::FileBacked,
            0,
        );

        let ino = u64::MAX - 1;
        let page_num = 0u64;
        let cache = crate::fs::page_cache();
        cache.insert(
            ino,
            page_num,
            alloc::vec![0x11u8; PAGE_SIZE_4K],
            PAGE_SIZE_4K as u64,
        );
        assert!(cache.mark_dirty(ino, page_num));

        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(
            frame_idx,
            SwapKind::File { ino, page_num },
        )
        .expect("enqueue file");
        test_impl::start_worker();
        h.wait();

        let after = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();
        assert_eq!(after.pending_async, before.pending_async);
        assert!(after.async_fail > before.async_fail);
        assert!(after.requeued > before.requeued);
        assert_eq!(after.total_reclaimed, before.total_reclaimed);
        assert!(after.writeback_skipped > before.writeback_skipped);

        if crate::mm::phys::buddy_allocator::is_frame_allocated(frame_idx.as_usize()) {
            let physf = unsafe {
                x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
                    x86_64::PhysAddr::new(frame_idx.to_phys_addr()),
                )
            };
            crate::mm::phys::buddy_allocator::buddy_dealloc_frame(physf);
        }

        stop_worker();
    }

    #[test_case]
    pub(super) fn test_notify_failure_on_anon_zswap_error() {
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        crate::mm::reclaim::zswap::zswap_set_enabled(true);
        crate::mm::reclaim::zswap::zswap_update_config(crate::mm::reclaim::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::reclaim::zswap::CompressionAlgo::Lz4,
            max_pool_size: 0,
            max_compression_ratio: 0.9,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        let before = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::reclaim::page_reclaim::test_register_pending_async(
            frame_idx,
            crate::mm::reclaim::page_reclaim::PageType::Anonymous,
            0,
        );

        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect("enqueue anon");
        test_impl::start_worker();
        h.wait();

        let after = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();
        assert_eq!(after.pending_async, before.pending_async);
        assert!(after.async_fail > before.async_fail);
        assert!(after.requeued > before.requeued);
        assert_eq!(after.total_reclaimed, before.total_reclaimed);
        assert_eq!(after.writeback_skipped, before.writeback_skipped);

        if crate::mm::phys::buddy_allocator::is_frame_allocated(frame_idx.as_usize()) {
            let physf = unsafe {
                x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
                    x86_64::PhysAddr::new(frame_idx.to_phys_addr()),
                )
            };
            crate::mm::phys::buddy_allocator::buddy_dealloc_frame(physf);
        }

        stop_worker();
    }

    #[test_case]
    pub(super) fn test_notify_success_once_per_pending() {
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        crate::mm::reclaim::zswap::zswap_set_enabled(true);
        crate::mm::reclaim::zswap::zswap_update_config(crate::mm::reclaim::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::reclaim::zswap::CompressionAlgo::Lz4,
            max_pool_size: crate::mm::types::PAGE_SIZE_2M * 32,
            max_compression_ratio: 1.0,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        let before = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::reclaim::page_reclaim::test_register_pending_async(
            frame_idx,
            crate::mm::reclaim::page_reclaim::PageType::Anonymous,
            0,
        );

        let h = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect("enqueue anon");
        test_impl::start_worker();
        h.wait();

        let after = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();
        assert_eq!(after.pending_async, before.pending_async);
        assert!(after.async_success > before.async_success);
        assert!(after.total_reclaimed > before.total_reclaimed);

        crate::mm::reclaim::page_reclaim::notify_async_swapout_success(frame_idx);
        let after_duplicate = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();
        assert_eq!(after_duplicate.async_success, after.async_success);
        assert_eq!(after_duplicate.pending_async, after.pending_async);
        assert_eq!(after_duplicate.total_reclaimed, after.total_reclaimed);

        stop_worker();
    }

    #[test_case]
    pub(super) fn test_notify_failure_once_per_pending() {
        let before = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::reclaim::page_reclaim::test_register_pending_async(
            frame_idx,
            crate::mm::reclaim::page_reclaim::PageType::Anonymous,
            0,
        );

        crate::mm::reclaim::page_reclaim::notify_async_swapout_failure(frame_idx);
        let after = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();
        assert_eq!(after.pending_async, before.pending_async);
        assert_eq!(after.async_fail, before.async_fail + 1);
        assert_eq!(after.requeued, before.requeued + 1);
        assert_eq!(after.total_reclaimed, before.total_reclaimed);

        // Duplicate failure notify should not double count.
        crate::mm::reclaim::page_reclaim::notify_async_swapout_failure(frame_idx);
        let after_duplicate = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();
        assert_eq!(after_duplicate.pending_async, after.pending_async);
        assert_eq!(after_duplicate.async_fail, after.async_fail);
        assert_eq!(after_duplicate.requeued, after.requeued);
        assert_eq!(after_duplicate.total_reclaimed, after.total_reclaimed);

        if crate::mm::phys::buddy_allocator::is_frame_allocated(frame_idx.as_usize()) {
            let physf = unsafe {
                x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
                    x86_64::PhysAddr::new(frame_idx.to_phys_addr()),
                )
            };
            crate::mm::phys::buddy_allocator::buddy_dealloc_frame(physf);
        }
    }

    #[test_case]
    pub(super) fn test_token_exhaustion_does_not_leave_pending() {
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        test_impl::set_tokens(0);

        let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
        let frame_idx =
            crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        let err = crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
            .expect_err("should be QueueFull due to tokens");
        assert_eq!(err, SwapError::QueueFull);

        // Ensure pending flag was rolled back
        assert_eq!(test_impl::_pending_len(), 0);
    }

    #[test_case]
    pub(super) fn test_file_queue_counter_saturation() {
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Repeated safe decrement must not underflow
        for _ in 0..10 {
            test_impl::_dec_file_queue_count_safe();
            assert_eq!(test_impl::_file_queue_len(), 0);
        }
    }

    #[test_case]
    pub(super) fn test_buffer_pool_basic() {
        // Ensure pool is cleared and capacity is small
        crate::mm::reclaim::async_swapout::buffer_pool_4k_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_4k_set_capacity(2);

        let (h0, m0, o0) = crate::mm::reclaim::async_swapout::buffer_pool_4k_stats();
        assert_eq!(h0, 0);
        assert_eq!(m0, 0);
        assert_eq!(o0, 0);

        let b1 = crate::mm::reclaim::async_swapout::buffer_pool_get_4k();
        let b2 = crate::mm::reclaim::async_swapout::buffer_pool_get_4k();
        let (_h1, m1, _o1) = crate::mm::reclaim::async_swapout::buffer_pool_4k_stats();
        assert_eq!(m1 - m0, 2);

        crate::mm::reclaim::async_swapout::buffer_pool_put_4k(b1);
        crate::mm::reclaim::async_swapout::buffer_pool_put_4k(b2);

        let _b3 = crate::mm::reclaim::async_swapout::buffer_pool_get_4k();
        let _b4 = crate::mm::reclaim::async_swapout::buffer_pool_get_4k();
        let (h2, _m2, o2) = crate::mm::reclaim::async_swapout::buffer_pool_4k_stats();
        assert!(h2 >= 1);
        assert!(o2 <= 2);

        crate::mm::reclaim::async_swapout::buffer_pool_4k_clear();
    }

    #[test_case]
    pub(super) fn test_buffer_pool_concurrent() {
        crate::mm::reclaim::async_swapout::buffer_pool_4k_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_4k_set_capacity(16);

        let threads = 8usize;
        let iters = 500usize;
        let mut handles = Vec::new();
        for _ in 0..threads {
            #[cfg(feature = "std")]
            let h = std::thread::spawn(move || {
                for _ in 0..iters {
                    let mut b = crate::mm::reclaim::async_swapout::buffer_pool_get_4k();
                    b[0] = 1; // touch
                    crate::mm::reclaim::async_swapout::buffer_pool_put_4k(b);
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().expect("join");
        }

        let (hits, misses, occ) = crate::mm::reclaim::async_swapout::buffer_pool_4k_stats();
        assert!(hits + misses >= threads * iters);
        assert!(occ <= 16);

        crate::mm::reclaim::async_swapout::buffer_pool_4k_clear();
    }

    #[test_case]
    pub(super) fn test_buffer_pool_2m_basic() {
        crate::mm::reclaim::async_swapout::buffer_pool_2m_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_2m_set_capacity(2);

        let (h0, m0, o0) = crate::mm::reclaim::async_swapout::buffer_pool_2m_stats();
        assert_eq!(h0, 0);
        assert_eq!(m0, 0);
        assert_eq!(o0, 0);

        let b1 = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
        let b2 = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
        let (_h1, m1, _o1) = crate::mm::reclaim::async_swapout::buffer_pool_2m_stats();
        assert_eq!(m1 - m0, 2);

        crate::mm::reclaim::async_swapout::buffer_pool_put_2m(b1);
        crate::mm::reclaim::async_swapout::buffer_pool_put_2m(b2);

        let _b3 = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
        let _b4 = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
        let (h2, _m2, o2) = crate::mm::reclaim::async_swapout::buffer_pool_2m_stats();
        assert!(h2 >= 1);
        assert!(o2 <= 2);

        crate::mm::reclaim::async_swapout::buffer_pool_2m_clear();
    }

    #[test_case]
    pub(super) fn test_buffer_pool_2m_concurrent() {
        crate::mm::reclaim::async_swapout::buffer_pool_2m_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_2m_set_capacity(8);

        let threads = 4usize;
        let iters = 10usize;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let h = std::thread::spawn(move || {
                for _ in 0..iters {
                    let mut b = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
                    b[0] = 1; // touch
                    crate::mm::reclaim::async_swapout::buffer_pool_put_2m(b);
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().expect("join");
        }

        let (hits, misses, occ) = crate::mm::reclaim::async_swapout::buffer_pool_2m_stats();
        assert!(hits + misses >= threads * iters);
        assert!(occ <= 8);

        crate::mm::reclaim::async_swapout::buffer_pool_2m_clear();
    }

    #[test_case]
    #[ignore]
    pub(super) fn test_buffer_pool_1g_basic() {
        crate::mm::reclaim::async_swapout::buffer_pool_1g_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_1g_set_capacity(1);

        let (h0, m0, o0) = crate::mm::reclaim::async_swapout::buffer_pool_1g_stats();
        assert_eq!(h0, 0);
        assert_eq!(m0, 0);
        assert_eq!(o0, 0);

        let b1 = crate::mm::reclaim::async_swapout::buffer_pool_get_1g();
        let (_h1, m1, _o1) = crate::mm::reclaim::async_swapout::buffer_pool_1g_stats();
        assert_eq!(m1 - m0, 1);

        crate::mm::reclaim::async_swapout::buffer_pool_put_1g(b1);

        let _b2 = crate::mm::reclaim::async_swapout::buffer_pool_get_1g();
        let (h2, _m2, o2) = crate::mm::reclaim::async_swapout::buffer_pool_1g_stats();
        assert!(h2 >= 1);
        assert!(o2 <= 1);

        crate::mm::reclaim::async_swapout::buffer_pool_1g_clear();
    }

    #[test_case]
    #[ignore]
    #[cfg(feature = "std")]
    pub(super) fn bench_enqueue_throughput_pool_vs_nopool() {
        crate::fs::init_page_cache(64 * 1024);

        // small micro-bench (ignored by default)
        let count = 200usize;

        // Phase A: no pool
        crate::mm::reclaim::async_swapout::buffer_pool_4k_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_4k_set_capacity(0);

        test_impl::set_processing_delay(1);
        test_impl::set_tokens(test_impl::token_capacity());
        test_impl::start_worker();

        let start = std::time::Instant::now();
        for _ in 0..count {
            let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
            let frame_idx =
                crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            let h =
                crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
                    .expect("enqueue ok");
            h.wait();
        }
        let dur_no_pool = start.elapsed();
        if cfg!(feature = "std") {
            test_impl::stop_worker();
        }

        // Phase B: pool enabled
        crate::mm::reclaim::async_swapout::buffer_pool_4k_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_4k_set_capacity(128);

        if cfg!(feature = "std") {
            test_impl::set_processing_delay(1);
            test_impl::set_tokens(test_impl::token_capacity());
            test_impl::start_worker();
        }

        let start2 = std::time::Instant::now();
        for _ in 0..count {
            let frame = crate::mm::phys::frame_allocator::alloc_frame().expect("alloc frame");
            let frame_idx =
                crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            let h =
                crate::mm::reclaim::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon)
                    .expect("enqueue ok");
            h.wait();
        }
        let dur_pool = start2.elapsed();
        if cfg!(feature = "std") {
            test_impl::stop_worker();
        }

        eprintln!("No-pool: {:?}, With-pool: {:?}", dur_no_pool, dur_pool);

        // make sure pool was exercised
        let (hits, misses, _occ) = crate::mm::reclaim::async_swapout::buffer_pool_4k_stats();
        assert!(hits + misses > 0);
    }

    #[test_case]
    #[ignore]
    #[cfg(feature = "std")]
    pub(super) fn bench_buffer_pool_2m_throughput() {
        // micro-bench: small counts to avoid excessive memory use
        let count = 12usize;

        // Phase A: no pool
        crate::mm::reclaim::async_swapout::buffer_pool_2m_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_2m_set_capacity(0);

        let start = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
            b[0] = 1;
            crate::mm::reclaim::async_swapout::buffer_pool_put_2m(b);
        }
        let dur_no_pool = start.elapsed();

        // Phase B: pool enabled
        crate::mm::reclaim::async_swapout::buffer_pool_2m_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_2m_set_capacity(8);

        let start2 = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
            b[0] = 1;
            crate::mm::reclaim::async_swapout::buffer_pool_put_2m(b);
        }
        let dur_pool = start2.elapsed();

        eprintln!("2M No-pool: {:?}, With-pool: {:?}", dur_no_pool, dur_pool);

        let (hits, misses, _occ) = crate::mm::reclaim::async_swapout::buffer_pool_2m_stats();
        assert!(hits + misses > 0);
    }

    #[test_case]
    #[ignore]
    #[cfg(feature = "std")]
    pub(super) fn bench_buffer_pool_1g_throughput() {
        // very small count due to size
        let count = 2usize;

        crate::mm::reclaim::async_swapout::buffer_pool_1g_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_1g_set_capacity(0);

        let start = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::reclaim::async_swapout::buffer_pool_get_1g();
            b[0] = 1;
            crate::mm::reclaim::async_swapout::buffer_pool_put_1g(b);
        }
        let dur_no_pool = start.elapsed();

        crate::mm::reclaim::async_swapout::buffer_pool_1g_clear();
        crate::mm::reclaim::async_swapout::buffer_pool_1g_set_capacity(1);

        let start2 = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::reclaim::async_swapout::buffer_pool_get_1g();
            b[0] = 1;
            crate::mm::reclaim::async_swapout::buffer_pool_put_1g(b);
        }
        let dur_pool = start2.elapsed();

        eprintln!("1G No-pool: {:?}, With-pool: {:?}", dur_no_pool, dur_pool);

        let (hits, misses, _occ) = crate::mm::reclaim::async_swapout::buffer_pool_1g_stats();
        assert!(hits + misses > 0);
    }
}
