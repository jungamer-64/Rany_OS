use super::*;

impl VirtioNetDevice {
    /// 割り込みハンドラ
    pub fn handle_interrupt(&self) {
        self.process_rx_completions();
        self.process_tx_completions();
    }
}
