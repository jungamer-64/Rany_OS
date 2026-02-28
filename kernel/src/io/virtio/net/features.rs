// ============================================================================
// VirtIO Net Device Feature Flags
// ============================================================================

/// デバイスはチェックサムオフロードをサポート
pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
/// ゲストはチェックサムオフロードを使用可能
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
/// MTU設定をサポート
pub const VIRTIO_NET_F_MTU: u64 = 1 << 3;
/// MACアドレスをサポート
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// TCPセグメンテーションオフロード
pub const VIRTIO_NET_F_GSO: u64 = 1 << 6;
/// ゲストTSO4
pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
/// ゲストTSO6
pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
/// マルチキューサポート
pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;
/// CTRL_VQサポート
pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
/// 割り込み抑制
pub const VIRTIO_NET_F_NOTIF_COAL: u64 = 1 << 52;
