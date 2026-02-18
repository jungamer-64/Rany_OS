use super::*;


impl PageReclaimController {
    /// 新しいコントローラを作成
    pub const fn new() -> Self {
        Self {
            lru_lists: lru_list_array(),
            watermarks: Watermarks {
                high: 1024,
                low: 512,
                min: 256,
                critical: 64,
            },
            kswapd_wake: AtomicBool::new(false),
            pressure: AtomicU64::new(0),
            mglru_tuning: MglruTuningController::new(),
            direct_reclaim_count: AtomicU64::new(0),
            background_reclaim_count: AtomicU64::new(0),
            total_reclaimed: AtomicU64::new(0),
            writeback_skipped: AtomicU64::new(0),
            unsafe_eviction_enabled: AtomicBool::new(false),
            pending_async: IrqMutex::new(BTreeMap::new()),
            pending_async_count: AtomicU64::new(0),
            async_enqueued: AtomicU64::new(0),
            async_success: AtomicU64::new(0),
            async_fail: AtomicU64::new(0),
            requeued: AtomicU64::new(0),
            blocked_unsafe: AtomicU64::new(0),
            scan_ratio: AtomicU64::new(1), // 1:1
        }
    }
    
    /// ウォーターマークを設定
    pub fn set_watermarks(&mut self, watermarks: Watermarks) {
        self.watermarks = watermarks;
    }

    /// 書き戻しI/O失敗による再キュー回数をインクリメント
    pub fn account_writeback_skipped(&self) {
        self.writeback_skipped.fetch_add(1, Ordering::Relaxed);
    }

    /// Enable/disable potentially unsafe eviction paths.
    pub fn set_unsafe_eviction_enabled(&self, enabled: bool) {
        self.unsafe_eviction_enabled.store(enabled, Ordering::Release);
    }

    /// Return whether unsafe eviction paths are enabled.
    pub fn unsafe_eviction_enabled(&self) -> bool {
        self.unsafe_eviction_enabled.load(Ordering::Acquire)
    }

    pub(super) fn finalize_reclaim_success(&self, entry: &MglruEntry, node_idx: usize) {
        let node = node_idx.min(7) as u8;
        self.lru_lists[node as usize].account_reclaimed(1);
        super::workingset::workingset_evict(
            entry.frame,
            entry.generation,
            entry.page_type as u8,
            node,
        );
    }

    pub(super) fn enqueue_pending_async(&self, entry: &MglruEntry, node_idx: usize) {
        let mut map = self.pending_async.lock();
        let old = map.insert(
            entry.frame,
            PendingAsyncMeta {
                frame: entry.frame,
                page_type: entry.page_type,
                generation: entry.generation,
                flags: entry.flags,
                node: node_idx.min(7) as u8,
            },
        );
        if old.is_none() {
            self.pending_async_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn take_pending_async(&self, frame: FrameIndex) -> Option<PendingAsyncMeta> {
        let mut map = self.pending_async.lock();
        let removed = map.remove(&frame);
        if removed.is_some() {
            self.pending_async_count.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    pub(super) fn has_pending_async(&self, frame: FrameIndex) -> bool {
        let map = self.pending_async.lock();
        map.contains_key(&frame)
    }

    pub(super) fn requeue_candidate(&self, mut entry: MglruEntry, node_idx: usize) {
        entry.generation = MglruGen::Gen1;
        entry.referenced.store(true, Ordering::Relaxed);
        let idx = node_idx.min(7);
        self.lru_lists[idx].add_page_to_generation(entry, 1);
        self.requeued.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn pending_meta_to_entry(meta: PendingAsyncMeta) -> MglruEntry {
        let mut entry = MglruEntry::new(meta.frame, meta.page_type, crate::time::current_time_ns());
        entry.generation = MglruGen::Gen1;
        entry.flags = meta.flags;
        entry.referenced.store(true, Ordering::Relaxed);
        entry
    }

    /// Async swapout completion notification.
    pub fn on_async_swapout_complete(&self, frame: FrameIndex, success: bool) {
        let Some(meta) = self.take_pending_async(frame) else {
            return;
        };

        let node_idx = (meta.node as usize).min(7);
        if success {
            self.async_success.fetch_add(1, Ordering::Relaxed);
            self.total_reclaimed.fetch_add(1, Ordering::Relaxed);
            let entry = MglruEntry {
                frame: meta.frame,
                page_type: meta.page_type,
                generation: meta.generation,
                referenced: AtomicBool::new(false),
                add_time: 0,
                flags: meta.flags,
            };
            self.finalize_reclaim_success(&entry, node_idx);
        } else {
            self.async_fail.fetch_add(1, Ordering::Relaxed);
            let entry = Self::pending_meta_to_entry(meta);
            self.requeue_candidate(entry, node_idx);
        }
    }
    
    /// 空きページ数を更新し、必要なアクションを返す
    pub fn update_free_pages(&self, free_pages: usize) -> MemoryPressure {
        let pressure = self.watermarks.pressure_level(free_pages);
        self.pressure.store(pressure as u64, Ordering::Release);
        
        // Low watermark以下ならkswapdを起動
        if pressure >= MemoryPressure::Background {
            self.kswapd_wake.store(true, Ordering::Release);
        }
        
        pressure
    }
    
    /// kswapdが起動すべきか
    pub fn should_wake_kswapd(&self) -> bool {
        self.kswapd_wake.swap(false, Ordering::AcqRel)
    }

    // ========================================================================
    // MGLRU Tuning Interface (Phase 1.2)
    // ========================================================================

    /// MGLRU のチューニングを実行
    ///
    /// Refault 統計に基づいて aging interval を動的に調整する。
    pub fn tune_mglru(&self, workingset_refaults: u64, normal_refaults: u64) {
        let pressure_val = self.pressure.load(Ordering::Acquire);
        let pressure = match pressure_val {
            1 => MemoryPressure::Background,
            2 => MemoryPressure::Direct,
            3 => MemoryPressure::Critical,
            _ => MemoryPressure::None,
        };
        
        self.mglru_tuning.adjust_interval(workingset_refaults, normal_refaults, pressure);
    }

    /// Aging cycle を実行すべきか判定
    pub fn should_age_mglru(&self, current_time_ns: u64) -> bool {
        self.mglru_tuning.should_run_aging(current_time_ns)
    }

    /// Aging 完了をマーク
    pub fn mark_mglru_aging_done(&self, current_time_ns: u64) {
        self.mglru_tuning.mark_aging_run(current_time_ns);
    }

    /// MGLRU チューニング統計を取得
    pub fn mglru_tuning_stats(&self) -> MglruTuningStats {
        self.mglru_tuning.stats()
    }
    
    /// 現在のメモリ圧迫レベル
    pub fn current_pressure(&self) -> MemoryPressure {
        match self.pressure.load(Ordering::Acquire) {
            0 => MemoryPressure::None,
            1 => MemoryPressure::Background,
            2 => MemoryPressure::Direct,
            _ => MemoryPressure::Critical,
        }
    }
    
    /// ページをLRUに追加
    pub fn add_page(&self, frame: FrameIndex, page_type: PageType, node: usize, timestamp: u64) {
        let entry = MglruEntry::new(frame, page_type, timestamp);
        
        let node_idx = node.min(7);
        // Gen0 (Newest) に追加
        self.lru_lists[node_idx].add_page(entry);
    }
    
    /// ページアクセスを記録（参照ビットをセット）
    pub fn mark_accessed(&self, frame: FrameIndex, node: usize) {
        // 実際の実装ではフレームからエントリを検索する必要がある
        // ここでは簡略化
        let _ = (frame, node);
    }
    
    /// バックグラウンド回収（kswapd相当）
    /// 
    /// 返り値: 回収したページ数
    /// バックグラウンド回収（kswapd相当）
    /// 
    /// 返り値: 回収したページ数
    pub fn background_reclaim(&self, target_pages: usize) -> usize {
        let mut total_reclaimed = 0;
        let current_time = crate::task::timer::current_tick(); // actually ticks, but sufficient for aging

        // Check if we need to run aging cycle
        let run_aging = self.should_age_mglru(current_time);

        for (node_idx, lru) in self.lru_lists.iter().enumerate() {
            if total_reclaimed >= target_pages {
                break;
            }
            
            // Aging cycle の実行
            if run_aging {
                let stats = lru.run_aging_cycle();
                // 若返ったページ数を考慮すると良さそうだが、ここでは単純にagingを進める
                let _ = stats;
            }
            
            // Gen3 (Oldest) から回収
            let to_reclaim = (target_pages - total_reclaimed).min(64);
            let victims = lru.reclaim_from_oldest(to_reclaim);
            
            for entry in victims {
                // 実際にフレームを解放
                match self.reclaim_page(&entry, node_idx) {
                    ReclaimOutcome::FreedNow => {
                        self.finalize_reclaim_success(&entry, node_idx);
                        total_reclaimed += 1;
                    }
                    ReclaimOutcome::DeferredAsync => {}
                    ReclaimOutcome::Requeued | ReclaimOutcome::BlockedUnsafe => {
                        self.requeue_candidate(entry, node_idx);
                    }
                }
            }
        }
        
        if run_aging {
            self.mark_mglru_aging_done(current_time);
        }
        
        if total_reclaimed > 0 {
            self.background_reclaim_count.fetch_add(1, Ordering::Relaxed);
            self.total_reclaimed.fetch_add(total_reclaimed as u64, Ordering::Relaxed);
        }
        
        total_reclaimed
    }
    
    /// 直接回収（Direct Reclaim）
    /// 
    /// 割り当てパスから呼ばれる同期的な回収
    /// 直接回収（Direct Reclaim）
    /// 
    /// 割り当てパスから呼ばれる同期的な回収
    pub fn direct_reclaim(&self, needed_pages: usize) -> usize {
        self.direct_reclaim_count.fetch_add(1, Ordering::Relaxed);
        
        let mut total_reclaimed = 0;

        
        // Direct Reclaimでは強制的にAgingを行うことが一般的だが
        // ここでは単純化のためAgingはSkipし、既存のGen3から回収を試みる
        // 必要ならAgingを呼び出すロジックを追加可能

        for (node_idx, lru) in self.lru_lists.iter().enumerate() {
            if total_reclaimed >= needed_pages {
                break;
            }
            
            // Gen3から積極的に回収
            let to_reclaim = (needed_pages - total_reclaimed).min(64).max(16);
            let victims = lru.reclaim_from_oldest(to_reclaim);
            
            for entry in victims {
                match self.reclaim_page(&entry, node_idx) {
                    ReclaimOutcome::FreedNow => {
                        self.finalize_reclaim_success(&entry, node_idx);
                        total_reclaimed += 1;
                    }
                    ReclaimOutcome::DeferredAsync => {}
                    ReclaimOutcome::Requeued | ReclaimOutcome::BlockedUnsafe => {
                        self.requeue_candidate(entry, node_idx);
                    }
                }
            }
        }
        
        self.total_reclaimed.fetch_add(total_reclaimed as u64, Ordering::Relaxed);
        total_reclaimed
    }

    /// Attempt to write back a specific dirty page.
    /// Returns true when the page writeback succeeds.
    pub(super) fn attempt_writeback_page(
        &self,
        ino: crate::fs::fs_abstraction::InodeNum,
        page_num: u64,
    ) -> bool {
        #[cfg(any(test, feature = "qemu-test-export"))]
        if let Some(forced) = decode_test_writeback_override(
            TEST_SYNC_PAGE_WRITEBACK_OVERRIDE.load(Ordering::Acquire),
        ) {
            return forced;
        }

        match crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
            match crate::fs::write_inode_by_number(ino, offset, data) {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            }
        }) {
            Ok(true) => true,
            Ok(false) | Err(_) => false,
        }
    }

    /// Attempt to write back all dirty pages via the global page cache.
    /// Returns true if any pages were written back successfully.
    pub(super) fn attempt_writeback_all(&self) -> bool {
        #[cfg(any(test, feature = "qemu-test-export"))]
        if let Some(forced) = decode_test_writeback_override(
            TEST_SYNC_ALL_WRITEBACK_OVERRIDE.load(Ordering::Acquire),
        ) {
            return forced;
        }

        let res = crate::fs::page_cache().sync_all(|ino, offset, data| {
            match crate::fs::write_inode_by_number(ino, offset, data) {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            }
        });

        match res {
            Ok(n) => n > 0,
            Err(_) => false,
        }
    }
    
    /// ページを実際に回収
    pub(super) fn reclaim_page(&self, entry: &MglruEntry, node_idx: usize) -> ReclaimOutcome {
        let unsafe_eviction = self.unsafe_eviction_enabled();
        if !unsafe_eviction && matches!(entry.page_type, PageType::Anonymous) {
            self.blocked_unsafe.fetch_add(1, Ordering::Relaxed);
            return ReclaimOutcome::BlockedUnsafe;
        }

        match entry.page_type {
            PageType::Anonymous => self.reclaim_anonymous(entry, node_idx),
            PageType::FileBacked => self.reclaim_file_backed(entry, node_idx, unsafe_eviction),
            PageType::Slab | PageType::Kernel => ReclaimOutcome::Requeued,
        }
    }

    /// 匿名ページの回収
    pub(super) fn reclaim_anonymous(&self, entry: &MglruEntry, node_idx: usize) -> ReclaimOutcome {
        let order = crate::mm::page_flags::get_order(entry.frame);
        let count = 1u64 << order;

        if entry.flags.contains(LruFlags::DIRTY) {
            self.try_async_swapout(entry, node_idx, crate::mm::async_swapout::SwapKind::Anon)
        } else {
            super::memcg::memcg_untrack_and_uncharge(entry.frame, count);
            self.free_frame(entry.frame);
            ReclaimOutcome::FreedNow
        }
    }

    /// ファイルバックページの回収
    pub(super) fn reclaim_file_backed(&self, entry: &MglruEntry, node_idx: usize, unsafe_eviction: bool) -> ReclaimOutcome {
        let order = crate::mm::page_flags::get_order(entry.frame);
        let count = 1u64 << order;

        if !entry.flags.contains(LruFlags::DIRTY) {
            super::memcg::memcg_untrack_and_uncharge(entry.frame, count);
            self.free_frame(entry.frame);
            return ReclaimOutcome::FreedNow;
        }

        if let Some(backing) = super::frame_backing::get_frame_backing(entry.frame) {
            self.reclaim_dirty_file_with_backing(entry, node_idx, &backing, count)
        } else if unsafe_eviction {
            self.try_async_swapout(entry, node_idx, crate::mm::async_swapout::SwapKind::Anon)
        } else {
            ReclaimOutcome::Requeued
        }
    }

    /// ダーティなファイルバックページをバッキング情報ありで回収
    pub(super) fn reclaim_dirty_file_with_backing(
        &self,
        entry: &MglruEntry,
        node_idx: usize,
        backing: &super::frame_backing::FrameBackingInfo,
        count: u64,
    ) -> ReclaimOutcome {
        let kind = crate::mm::async_swapout::SwapKind::File { ino: backing.ino, page_num: backing.page_num };
        match crate::mm::async_swapout::try_enqueue_swapout(entry.frame, kind) {
            Ok(_handle) => {
                self.enqueue_pending_async(entry, node_idx);
                self.async_enqueued.fetch_add(1, Ordering::Relaxed);
                ReclaimOutcome::DeferredAsync
            }
            Err(crate::mm::async_swapout::SwapError::AlreadyPending) => {
                if self.has_pending_async(entry.frame) {
                    ReclaimOutcome::DeferredAsync
                } else {
                    ReclaimOutcome::Requeued
                }
            }
            Err(crate::mm::async_swapout::SwapError::QueueFull)
            | Err(crate::mm::async_swapout::SwapError::NotSupported) => {
                if self.attempt_writeback_page(backing.ino, backing.page_num)
                    || self.attempt_writeback_all()
                {
                    super::memcg::memcg_untrack_and_uncharge(entry.frame, count);
                    let _ = super::frame_backing::untrack_frame_backing(entry.frame);
                    self.free_frame(entry.frame);
                    ReclaimOutcome::FreedNow
                } else {
                    self.account_writeback_skipped();
                    ReclaimOutcome::Requeued
                }
            }
        }
    }

    /// 非同期スワップアウトを試みる共通ヘルパー
    pub(super) fn try_async_swapout(
        &self,
        entry: &MglruEntry,
        node_idx: usize,
        kind: crate::mm::async_swapout::SwapKind,
    ) -> ReclaimOutcome {
        match crate::mm::async_swapout::try_enqueue_swapout(entry.frame, kind) {
            Ok(_handle) => {
                self.enqueue_pending_async(entry, node_idx);
                self.async_enqueued.fetch_add(1, Ordering::Relaxed);
                ReclaimOutcome::DeferredAsync
            }
            Err(crate::mm::async_swapout::SwapError::AlreadyPending) => {
                if self.has_pending_async(entry.frame) {
                    ReclaimOutcome::DeferredAsync
                } else {
                    ReclaimOutcome::Requeued
                }
            }
            Err(crate::mm::async_swapout::SwapError::QueueFull)
            | Err(crate::mm::async_swapout::SwapError::NotSupported) => {
                if matches!(kind, crate::mm::async_swapout::SwapKind::Anon) && self.attempt_writeback_all() {
                    let order = crate::mm::page_flags::get_order(entry.frame);
                    let count = 1u64 << order;
                    super::memcg::memcg_untrack_and_uncharge(entry.frame, count);
                    self.free_frame(entry.frame);
                    ReclaimOutcome::FreedNow
                } else {
                    self.account_writeback_skipped();
                    ReclaimOutcome::Requeued
                }
            }
        }
    }
    
    /// フレームをBuddyに返却
    pub(super) fn free_frame(&self, frame: FrameIndex) {
        use super::buddy_allocator::buddy_dealloc_frame;
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        use x86_64::PhysAddr;
        
        // Remove any frame backing mapping if present
        let _ = super::frame_backing::untrack_frame_backing(frame);

        let phys_frame = unsafe {
            PhysFrame::<Size4KiB>::from_start_address_unchecked(
                PhysAddr::new(frame.to_phys_addr())
            )
        };
        buddy_dealloc_frame(phys_frame);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> ReclaimStats {
        let mut lru_stats = [MglruStats::default(); 8];
        
        for (i, lru) in self.lru_lists.iter().enumerate() {
            lru_stats[i] = lru.stats();
        }
        
        ReclaimStats {
            direct_reclaim_count: self.direct_reclaim_count.load(Ordering::Relaxed),
            background_reclaim_count: self.background_reclaim_count.load(Ordering::Relaxed),
            total_reclaimed: self.total_reclaimed.load(Ordering::Relaxed),
            pressure: self.current_pressure(),
            writeback_skipped: self.writeback_skipped.load(Ordering::Relaxed),
            unsafe_eviction_enabled: self.unsafe_eviction_enabled(),
            pending_async: self.pending_async_count.load(Ordering::Relaxed),
            async_enqueued: self.async_enqueued.load(Ordering::Relaxed),
            async_success: self.async_success.load(Ordering::Relaxed),
            async_fail: self.async_fail.load(Ordering::Relaxed),
            requeued: self.requeued.load(Ordering::Relaxed),
            blocked_unsafe: self.blocked_unsafe.load(Ordering::Relaxed),
            lru_stats,
        }
    }
}
