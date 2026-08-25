use super::*;

// ============================================================================
// Helper Functions
// ============================================================================

impl Drop for NvmePollingDriver {
    fn drop(&mut self) {
        if let Some(buf) = self.admin_sq_buffer.take() {
            drop(buf);
        }
        if let Some(buf) = self.admin_cq_buffer.take() {
            drop(buf);
        }
        if let Some(buf) = self.identify_buffer.take() {
            drop(buf);
        }
        for buf in self.io_sq_buffers.iter_mut().filter_map(|b| b.take()) {
            drop(buf);
        }
        for buf in self.io_cq_buffers.iter_mut().filter_map(|b| b.take()) {
            drop(buf);
        }
    }
}

/// CPU PAUSE命令（スピン待機の電力効率化）
#[inline(always)]
pub(crate) fn cpu_pause() {
    core::hint::spin_loop();
}

impl NvmePollingDriver {
    /// Wakerを登録（Reactor Pattern）
    pub fn register_waker(&self, queue_index: u32, cid: u16, waker: core::task::Waker) {
        if let Some(queue) = self.get_queue(queue_index) {
            queue.register_waker(cid, waker);
        }
    }

    /// 完了を確認（ソフトウェア状態のみチェック）
    pub fn check_completion(&self, queue_index: u32, cid: u16) -> Option<NvmeCompletion> {
        if let Some(queue) = self.get_queue(queue_index) {
            queue.check_completion(cid)
        } else {
            None
        }
    }

    /// 完了を取得してペンディングから削除
    pub fn take_completion(&self, queue_index: u32, cid: u16) -> Option<NvmeCompletion> {
        if let Some(queue) = self.get_queue(queue_index) {
            queue.take_completion(cid)
        } else {
            None
        }
    }

    /// 割り込みモードかどうか
    pub fn interrupt_mode(&self) -> bool {
        self.interrupt_mode
    }

    /// 名前空間の論理ブロックサイズ（バイト）
    pub fn namespace_block_size(&self, nsid: u32) -> u32 {
        if nsid == self.nsid {
            self.namespace_block_size
        } else {
            self.namespace_block_size
        }
    }
}
