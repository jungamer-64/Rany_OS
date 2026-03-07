use super::*;
pub use virtio_driver::net::VirtioNetStats;

// ============================================================================
// Statistics
// ============================================================================

impl VirtioNetDevice {
    /// 統計を取得
    pub fn stats(&self) -> VirtioNetStats {
        VirtioNetStats {
            tx_packets: self.tx_packets.load(core::sync::atomic::Ordering::Relaxed),
            rx_packets: self.rx_packets.load(core::sync::atomic::Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(core::sync::atomic::Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(core::sync::atomic::Ordering::Relaxed),
        }
    }
}
