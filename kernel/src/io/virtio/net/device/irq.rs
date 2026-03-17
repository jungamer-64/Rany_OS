use super::*;

impl VirtioNetDevice {
    /// 割り込みハンドラ
    pub fn handle_interrupt(&self) {
        if let Some(runtime) = registry::virtio_net_runtime(self.virtio_index) {
            let _ = runtime.schedule_event(kernel_api::service::netdev::NetDriverEvent::Interrupt);
        }
    }

    pub fn process_interrupt_deferred(&self) {
        self.process_rx_completions();
        self.process_tx_completions();
    }
}
