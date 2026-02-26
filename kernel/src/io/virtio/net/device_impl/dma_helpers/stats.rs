use super::*;

// ============================================================================
// Statistics
// ============================================================================

/// VirtIO ネットワーク統計
#[derive(Debug, Clone)]
pub struct VirtioNetStats {
    pub tx_packets: u32,
    pub rx_packets: u32,
    pub tx_bytes: u32,
    pub rx_bytes: u32,
}

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
