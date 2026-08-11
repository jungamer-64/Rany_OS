// ============================================================================
// kernel/src/net/event_queue.rs - Network Event Queue (2-stage wake)
// ============================================================================
//! ネットワークイベント用 lock-free MPMC リングバッファ

use crate::sync::lockfree::MpmcRingBuffer;

/// ネットワークイベント
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// パケット受信
    PacketReceived,
    /// 送信完了
    TxComplete,
    /// リンク状態の変更
    LinkChange,
    /// その他のイベント
    Unknown,
}

impl From<u32> for NetworkEvent {
    fn from(status: u32) -> Self {
        // ISRステータスからの変換（ドライバによって異なる可能性があるため、適宜調整）
        match status {
            1 => NetworkEvent::PacketReceived,
            2 => NetworkEvent::TxComplete,
            3 => NetworkEvent::LinkChange,
            _ => NetworkEvent::Unknown,
        }
    }
}

/// ネットワークイベントキュー (固定1024エントリ)
pub static NET_EVENT_QUEUE: MpmcRingBuffer<NetworkEvent, 1024> = MpmcRingBuffer::new();
