// ============================================================================
// drivers/virtio/src/net/features.rs - VirtIO Net feature bits
// ============================================================================

/// Device supports checksum offload.
pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
/// Guest checksum offload support.
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
/// Device exposes MTU.
pub const VIRTIO_NET_F_MTU: u64 = 1 << 3;
/// Device exposes MAC address.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// Segmentation offload support.
pub const VIRTIO_NET_F_GSO: u64 = 1 << 6;
/// Guest TSOv4 support.
pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
/// Guest TSOv6 support.
pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
/// Control virtqueue support.
pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
/// Multiqueue support.
pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;
/// Notification coalescing support.
pub const VIRTIO_NET_F_NOTIF_COAL: u64 = 1 << 52;
