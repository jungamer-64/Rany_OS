// ============================================================================
// drivers/virtio/src/defs.rs - Shared VirtIO Common Definitions
// ============================================================================
pub mod status {
    pub const VIRTIO_STATUS_RESET: u8 = 0;
    pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
    pub const VIRTIO_STATUS_DRIVER: u8 = 2;
    pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
    pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
    pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
    pub const VIRTIO_STATUS_FAILED: u8 = 128;
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioDeviceStatus {
    Reset = status::VIRTIO_STATUS_RESET,
    Acknowledge = status::VIRTIO_STATUS_ACKNOWLEDGE,
    Driver = status::VIRTIO_STATUS_DRIVER,
    DriverOk = status::VIRTIO_STATUS_DRIVER_OK,
    FeaturesOk = status::VIRTIO_STATUS_FEATURES_OK,
    DeviceNeedsReset = status::VIRTIO_STATUS_DEVICE_NEEDS_RESET,
    Failed = status::VIRTIO_STATUS_FAILED,
}

/// VirtQueue management constants
pub const VIRTIO_F_INDIRECT_DESC: u64 = 1 << 28;
pub const VIRTIO_F_EVENT_IDX: u64 = 1 << 29;

/// Descriptor flags
pub mod vring_flags {
    pub const VRING_DESC_F_NEXT: u16 = 1;
    pub const VRING_DESC_F_WRITE: u16 = 2;
    pub const VRING_DESC_F_INDIRECT: u16 = 4;
}

/// Descriptor structure
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl VringDesc {
    pub const F_NEXT: u16 = 1;
    pub const F_WRITE: u16 = 2;
    pub const F_INDIRECT: u16 = 4;

    pub fn has_next(&self) -> bool {
        (self.flags & Self::F_NEXT) != 0
    }
}

/// Available ring header
#[repr(C)]
#[derive(Debug)]
pub struct VringAvailHeader {
    pub flags: u16,
    pub idx: u16,
}

/// Used element
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Used ring header
#[repr(C)]
#[derive(Debug)]
pub struct VringUsedHeader {
    pub flags: u16,
    pub idx: u16,
}

pub const VIRTQUEUE_DEFAULT_SIZE: u16 = 256;
pub const VIRTQUEUE_MAX_SIZE: u16 = 32768;
pub const VRING_DESC_ALIGN: usize = 16;
pub const VRING_AVAIL_ALIGN: usize = 2;
pub const VRING_USED_ALIGN: usize = 4;
pub const VIRTIO_MMIO_MAGIC: u32 = 0x74726976;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioDeviceType {
    Network = 1,
    Block = 2,
    Console = 3,
    Balloon = 5,
    Gpu = 16,
    Input = 18,
    Unknown = 0,
}

impl From<u32> for VirtioDeviceType {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Network,
            2 => Self::Block,
            3 => Self::Console,
            5 => Self::Balloon,
            16 => Self::Gpu,
            18 => Self::Input,
            _ => Self::Unknown,
        }
    }
}

pub mod mmio_regs {
    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00c;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    pub const QUEUE_AVAIL_LOW: usize = 0x090;
    pub const QUEUE_AVAIL_HIGH: usize = 0x094;
    pub const QUEUE_USED_LOW: usize = 0x0a0;
    pub const QUEUE_USED_HIGH: usize = 0x0a4;
    pub const CONFIG: usize = 0x100;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioPciCapType {
    CommonCfg = 1,
    NotifyCfg = 2,
    IsrCfg = 3,
    DeviceCfg = 4,
    PciCfg = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtioPciCap {
    pub cap_vndr: u8,
    pub cap_next: u8,
    pub cap_len: u8,
    pub cfg_type: u8,
    pub bar: u8,
    pub padding: [u8; 3],
    pub offset: u32,
    pub length: u32,
}

pub mod common_features {
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
    pub const VIRTIO_F_IN_ORDER: u64 = 1 << 35;
    pub const VIRTIO_F_ORDER_PLATFORM: u64 = 1 << 36;
    pub const VIRTIO_F_SR_IOV: u64 = 1 << 37;
    pub const VIRTIO_F_NOTIFICATION_DATA: u64 = 1 << 38;
}

pub mod avail_flags {
    pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
}

pub mod used_flags {
    pub const VRING_USED_F_NO_NOTIFY: u16 = 1;
}
