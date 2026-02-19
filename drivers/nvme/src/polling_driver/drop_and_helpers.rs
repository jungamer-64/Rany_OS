use super::*;

// ============================================================================
// Helper Functions
// ============================================================================

impl Drop for NvmePollingDriver {
    fn drop(&mut self) {
        // Free any allocated DMA buffers via KernelServices
        let kernel = kernel_api::services::kernel();

        if let Some(buf) = self.admin_sq_buffer.take() {
            kernel.free_dma(buf);
        }
        if let Some(buf) = self.admin_cq_buffer.take() {
            kernel.free_dma(buf);
        }
        if let Some(buf) = self.identify_buffer.take() {
            kernel.free_dma(buf);
        }
        for buf in self.io_sq_buffers.iter_mut().filter_map(|b| b.take()) {
            kernel.free_dma(buf);
        }
        for buf in self.io_cq_buffers.iter_mut().filter_map(|b| b.take()) {
            kernel.free_dma(buf);
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
    pub fn register_waker(&self, core_id: u32, cid: u16, waker: core::task::Waker) {
        if let Some(queue) = self.get_queue(core_id) {
            queue.register_waker(cid, waker);
        }
    }

    /// 完了を確認（ソフトウェア状態のみチェック）
    pub fn check_completion(&self, core_id: u32, cid: u16) -> Option<NvmeCompletion> {
        if let Some(queue) = self.get_queue(core_id) {
            queue.check_completion(cid)
        } else {
            None
        }
    }

    /// 完了を取得してペンディングから削除
    pub fn take_completion(&self, core_id: u32, cid: u16) -> Option<NvmeCompletion> {
        if let Some(queue) = self.get_queue(core_id) {
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
