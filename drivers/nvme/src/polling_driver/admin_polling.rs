use super::*;

impl NvmePollingDriver {
    /// Admin完了をポーリング
    pub(super) fn poll_admin_completion(&self) -> Result<NvmeCompletion, &'static str> {
        self.poll_admin_completion_named("admin")
    }

    /// Admin完了をポーリング（コマンド名付き診断ログ出力）
    pub(super) fn poll_admin_completion_named(
        &self,
        cmd_name: &str,
    ) -> Result<NvmeCompletion, &'static str> {
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

        // NVMeスペック準拠: 十分な待機（10M回 ≈ 100-200ms）
        for _ in 0..10_000_000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                if cqe.is_success() {
                    return Ok(cqe);
                } else {
                    log::error!(
                        "[NVME] {} failed: status=0x{:04x} SCT={} SC=0x{:02x} DNR={} CID={}",
                        cmd_name,
                        cqe.status,
                        cqe.sct(),
                        cqe.sc(),
                        cqe.dnr(),
                        cqe.command_id()
                    );
                    return Err("Admin command failed");
                }
            }
            cpu_pause();
        }
        log::error!("[NVME] {} timed out after 10M iterations", cmd_name);
        Err("Admin command timeout")
    }

    /// I/Oキューを設定（レガシーAPI）
    ///
    /// # Safety
    /// 初期化中にのみ呼び出すこと。
    pub unsafe fn setup_io_queue(&self, core_id: u32, qp: QueuePair) {
        if let Some(queue) = self.io_queues.get(core_id as usize) {
            unsafe { queue.set_queue_pair(qp) };
        }
    }

    /// コアのキューを取得
    pub fn get_queue(&self, core_id: u32) -> Option<&PerCoreNvmeQueue> {
        let max_queues = self.io_queue_count as u32;
        if max_queues == 0 || core_id >= max_queues {
            return None;
        }
        let queue = self.io_queues.get(core_id as usize)?;
        if queue.is_initialized() {
            Some(queue)
        } else {
            None
        }
    }

    // ========================================================================
    // Polling
    // ========================================================================

    /// ポーリングループを実行（最適化版）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_loop(&self, core_id: u32) -> usize {
        let queue = match self.get_queue(core_id) {
            Some(q) => q,
            None => return 0,
        };

        let completed = unsafe { queue.process_completions() };

        if completed == 0 {
            cpu_pause();
        }

        completed
    }

    /// リードコマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1/prp2は有効な物理アドレスである必要がある。
    pub unsafe fn submit_read(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.read(nsid, lba, blocks, prp1, prp2) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// リードコマンドを発行（SGL）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// sglは有効なデータブロック/セグメントディスクリプタである必要がある。
    pub unsafe fn submit_read_sgl(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.read_sgl(nsid, lba, blocks, sgl) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// ライトコマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1/prp2は有効な物理アドレスである必要がある。
    pub unsafe fn submit_write(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.write(nsid, lba, blocks, prp1, prp2) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// ライトコマンドを発行（SGL）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// sglは有効なデータブロック/セグメントディスクリプタである必要がある。
    pub unsafe fn submit_write_sgl(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.write_sgl(nsid, lba, blocks, sgl) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// Dataset Management (DSM) コマンドを発行 (TRIM等)
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1は有効な物理アドレスである必要がある (DSM Range Buffer)。
    /// prp2は現在未使用 (バッファサイズが1ページ以下を想定)。
    pub unsafe fn submit_dsm(
        &self,
        core_id: u32,
        nsid: u32,
        prp1: u64,
        _prp2: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        // nr=0 (1 range). async_ops.rs currently only constructs single-range DSMs.
        let cid = unsafe { queue.dataset_management(nsid, 0, prp1) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// SGL最大エントリ数を取得
    pub fn sgl_max_entries(&self) -> Option<usize> {
        let ctrl = self.identify_controller?;
        if (ctrl.sgls & SGLS_SUPPORTED) == 0 {
            return None;
        }
        if (ctrl.sgls & SGLS_DATA_BLOCK) == 0 {
            return None;
        }
        let max = if ctrl.msdbd == 0 {
            MAX_SGL_ENTRIES
        } else {
            ctrl.msdbd as usize
        };
        let max = max.min(MAX_SGL_ENTRIES);
        if max == 0 { None } else { Some(max) }
    }

    /// フラッシュコマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn submit_flush(&self, core_id: u32, nsid: u32) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.flush(nsid) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// Dataset Management (TRIM) コマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1は有効な物理アドレスである必要がある。
    pub unsafe fn submit_dataset_management(
        &self,
        core_id: u32,
        nsid: u32,
        nr: u8,
        prp1: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.dataset_management(nsid, nr, prp1) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// 特定のCIDの完了をポーリング
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_completion_by_cid(&self, core_id: u32, cid: u16) -> Option<NvmeCompletion> {
        let queue = self.get_queue(core_id)?;

        // ポーリングして完了を取得
        if let Some(cqe) = unsafe { queue.poll() } {
            // CIDが一致するかチェック
            if cqe.command_id() == cid {
                return Some(cqe);
            }
            // Note: CIDが一致しない場合は別のリクエストの完了
            // 完全な実装では、ペンディングキューで管理する必要がある
        }
        None
    }

    /// バッチポーリング（高スループット用）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_batch(&self, core_id: u32, completions: &mut [NvmeCompletion]) -> usize {
        let queue = match self.get_queue(core_id) {
            Some(q) => q,
            None => return 0,
        };

        let mut count = 0;
        for slot in completions.iter_mut() {
            if let Some(cqe) = unsafe { queue.poll() } {
                *slot = cqe;
                count += 1;
            } else {
                break;
            }
        }

        count
    }

    /// アダプティブポーリング（負荷に応じて調整）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn adaptive_poll(&self, core_id: u32, idle_count: &mut u32) -> usize {
        let completed = unsafe { self.poll_loop(core_id) };

        if completed > 0 {
            *idle_count = 0;
        } else {
            *idle_count += 1;
            if *idle_count > 100 {
                for _ in 0..10 {
                    cpu_pause();
                }
            }
        }

        completed
    }

    // ========================================================================
    // Status & Statistics
    // ========================================================================

    /// アクティブかどうか
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// 初期化済みI/Oキュー数を取得
    pub fn io_queue_count(&self) -> u16 {
        self.io_queue_count
    }

    /// 最大転送サイズを取得
    pub fn max_transfer_size(&self) -> usize {
        self.max_transfer_size
    }

    /// 名前空間の総ブロック数を取得
    pub fn namespace_total_blocks(&self) -> u64 {
        self.namespace_total_blocks
    }

    /// 統計を収集
    pub fn collect_stats(&self) -> NvmeDriverStats {
        let mut stats = NvmeDriverStats::default();

        for queue in self.io_queues.iter().take(self.io_queue_count as usize) {
            let qs = queue.stats();
            stats.total_commands_submitted += qs.commands_submitted.load(Ordering::Relaxed);
            stats.total_commands_completed += qs.commands_completed.load(Ordering::Relaxed);
            stats.total_read_bytes += qs.read_bytes.load(Ordering::Relaxed);
            stats.total_write_bytes += qs.write_bytes.load(Ordering::Relaxed);
            stats.total_errors += qs.errors.load(Ordering::Relaxed);
            stats.total_poll_cycles += qs.poll_cycles.load(Ordering::Relaxed);
        }

        stats
    }
}
