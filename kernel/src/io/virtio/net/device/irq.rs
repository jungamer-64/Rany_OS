use super::*;

impl VirtioNetDevice {
    /// 割り込みハンドラ
    pub fn handle_interrupt(&self) {
        self.process_rx_completions();
        self.process_tx_completions();

        // Interrupt-Wakerブリッジに通知（設計書 4.2）
        // RX/TXで待機中のFutureを起床
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::VirtioNet(self.virtio_index),
        );
    }
}
