// ============================================================================
// src/io/virtio/defs.rs - VirtIO Common Definitions
// ============================================================================
//!
//! VirtIO共通定数・構造体定義
//!
//! VirtIO仕様 v1.1/v1.2に基づく共通定義を提供。
//! 各デバイスドライバはこれらの定義を使用してVirtQueueを操作する。

#![allow(dead_code)]

// ============================================================================
// Device Status Bits (VirtIO 1.0+ Common)
// ============================================================================

/// VirtIOデバイスステータスビット
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioDeviceStatus {
    /// 初期状態（リセット）
    Reset = 0,
    /// ドライバがデバイスを認識した
    Acknowledge = 1,
    /// ドライバがデバイスを駆動できる
    Driver = 2,
    /// ドライバの設定が完了し、駆動準備が整った
    DriverOk = 4,
    /// ドライバがフィーチャーネゴシエーションを完了した
    FeaturesOk = 8,
    /// デバイスが回復不能なエラーを経験した
    DeviceNeedsReset = 64,
    /// ドライバがデバイスを放棄した
    Failed = 128,
}

/// ステータスビット定数（直接値として使用する場合）
pub mod status {
    pub const VIRTIO_STATUS_RESET: u8 = 0;
    pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
    pub const VIRTIO_STATUS_DRIVER: u8 = 2;
    pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
    pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
    pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
    pub const VIRTIO_STATUS_FAILED: u8 = 128;
}

// ============================================================================
// VirtQueue Constants
// ============================================================================

/// デフォルトキューサイズ
pub const VIRTQUEUE_DEFAULT_SIZE: u16 = 256;

/// 最大キューサイズ（仕様上の制限）
pub const VIRTQUEUE_MAX_SIZE: u16 = 32768;

// ============================================================================
// Descriptor Ring Structures
// ============================================================================

/// Virtqueueディスクリプタフラグ
pub mod vring_flags {
    /// チェーン内に次のディスクリプタがある
    pub const VRING_DESC_F_NEXT: u16 = 1;
    /// このバッファはデバイスが書き込む（ホスト→ゲスト）
    pub const VRING_DESC_F_WRITE: u16 = 2;
    /// 間接ディスクリプタテーブルを指す
    pub const VRING_DESC_F_INDIRECT: u16 = 4;
}

/// Availableリングフラグ
pub mod avail_flags {
    /// 割り込みを抑制しない
    pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
}

/// Usedリングフラグ
pub mod used_flags {
    /// 通知を抑制
    pub const VRING_USED_F_NO_NOTIFY: u16 = 1;
}

/// Virtqueueディスクリプタ
///
/// 各ディスクリプタはバッファの物理アドレス、長さ、フラグ、
/// およびチェーン内の次のディスクリプタへのインデックスを保持する。
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringDesc {
    /// ゲスト物理アドレス
    pub addr: u64,
    /// バッファ長（バイト）
    pub len: u32,
    /// フラグ (NEXT, WRITE, INDIRECT)
    pub flags: u16,
    /// 次のディスクリプタインデックス（FLAG_NEXTが設定されている場合有効）
    pub next: u16,
}

impl VringDesc {
    /// 新しいディスクリプタを作成
    pub const fn new() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }
    
    /// 読み取り専用バッファ（デバイスが読む）として設定
    pub fn set_readable(&mut self, addr: u64, len: u32) {
        self.addr = addr;
        self.len = len;
        self.flags = 0;
    }
    
    /// 書き込み可能バッファ（デバイスが書く）として設定
    pub fn set_writable(&mut self, addr: u64, len: u32) {
        self.addr = addr;
        self.len = len;
        self.flags = vring_flags::VRING_DESC_F_WRITE;
    }
    
    /// 次のディスクリプタを設定
    pub fn set_next(&mut self, next: u16) {
        self.flags |= vring_flags::VRING_DESC_F_NEXT;
        self.next = next;
    }
    
    /// 次のディスクリプタがあるか
    pub fn has_next(&self) -> bool {
        self.flags & vring_flags::VRING_DESC_F_NEXT != 0
    }
    
    /// デバイスが書き込むバッファか
    pub fn is_writable(&self) -> bool {
        self.flags & vring_flags::VRING_DESC_F_WRITE != 0
    }
}

/// Availableリングヘッダ
///
/// ゲストがデバイスに利用可能なバッファを通知するためのリング。
/// 実際のリング配列はこの構造体の直後に配置される。
#[repr(C)]
#[derive(Debug)]
pub struct VringAvailHeader {
    /// フラグ（割り込み抑制など）
    pub flags: u16,
    /// 次に書き込むインデックス
    pub idx: u16,
}

/// Used要素
///
/// デバイスが処理を完了したバッファを示す。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringUsedElem {
    /// ディスクリプタチェーンの先頭インデックス
    pub id: u32,
    /// 書き込まれたバイト数
    pub len: u32,
}

/// Usedリングヘッダ
///
/// デバイスがゲストに処理完了を通知するためのリング。
/// 実際のリング配列はこの構造体の直後に配置される。
#[repr(C)]
#[derive(Debug)]
pub struct VringUsedHeader {
    /// フラグ（通知抑制など）
    pub flags: u16,
    /// 次に書き込むインデックス
    pub idx: u16,
}

// ============================================================================
// Fixed-Size Ring Structures (for static allocation)
// ============================================================================

/// 固定サイズ（256エントリ）のAvailableリング
#[repr(C)]
pub struct VringAvail256 {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 256],
    pub used_event: u16,
}

/// 固定サイズ（256エントリ）のUsedリング
#[repr(C)]
pub struct VringUsed256 {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VringUsedElem; 256],
    pub avail_event: u16,
}

// ============================================================================
// VirtIO Transport Abstraction
// ============================================================================

/// VirtIOトランスポートタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioTransport {
    /// PCI/PCIeトランスポート
    Pci,
    /// MMIOトランスポート
    Mmio,
    /// Channel I/O (S390専用)
    ChannelIO,
}

/// VirtIOデバイスタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioDeviceType {
    /// ネットワークカード
    Network = 1,
    /// ブロックデバイス
    Block = 2,
    /// コンソール
    Console = 3,
    /// エントロピーソース
    Entropy = 4,
    /// メモリバルーン
    Balloon = 5,
    /// SCSI Host
    Scsi = 8,
    /// 9P Transport
    NineP = 9,
    /// GPU
    Gpu = 16,
    /// Input Device
    Input = 18,
    /// Socket Device
    Vsock = 19,
    /// Crypto Device
    Crypto = 20,
    /// Unknown
    Unknown = 0,
}

impl From<u32> for VirtioDeviceType {
    fn from(value: u32) -> Self {
        match value {
            1 => VirtioDeviceType::Network,
            2 => VirtioDeviceType::Block,
            3 => VirtioDeviceType::Console,
            4 => VirtioDeviceType::Entropy,
            5 => VirtioDeviceType::Balloon,
            8 => VirtioDeviceType::Scsi,
            9 => VirtioDeviceType::NineP,
            16 => VirtioDeviceType::Gpu,
            18 => VirtioDeviceType::Input,
            19 => VirtioDeviceType::Vsock,
            20 => VirtioDeviceType::Crypto,
            _ => VirtioDeviceType::Unknown,
        }
    }
}

// ============================================================================
// MMIO Register Offsets (VirtIO MMIO Transport)
// ============================================================================

/// VirtIO MMIOレジスタオフセット
pub mod mmio_regs {
    /// Magic value "virt" (0x74726976)
    pub const MAGIC_VALUE: usize = 0x000;
    /// VirtIO version
    pub const VERSION: usize = 0x004;
    /// Device type
    pub const DEVICE_ID: usize = 0x008;
    /// Vendor ID
    pub const VENDOR_ID: usize = 0x00c;
    /// Device features
    pub const DEVICE_FEATURES: usize = 0x010;
    /// Device features selector
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    /// Driver features
    pub const DRIVER_FEATURES: usize = 0x020;
    /// Driver features selector
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    /// Queue selector
    pub const QUEUE_SEL: usize = 0x030;
    /// Maximum queue size
    pub const QUEUE_NUM_MAX: usize = 0x034;
    /// Queue size
    pub const QUEUE_NUM: usize = 0x038;
    /// Queue ready
    pub const QUEUE_READY: usize = 0x044;
    /// Queue notify
    pub const QUEUE_NOTIFY: usize = 0x050;
    /// Interrupt status
    pub const INTERRUPT_STATUS: usize = 0x060;
    /// Interrupt acknowledge
    pub const INTERRUPT_ACK: usize = 0x064;
    /// Device status
    pub const STATUS: usize = 0x070;
    /// Queue descriptor table address (low)
    pub const QUEUE_DESC_LOW: usize = 0x080;
    /// Queue descriptor table address (high)
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    /// Queue available ring address (low)
    pub const QUEUE_AVAIL_LOW: usize = 0x090;
    /// Queue available ring address (high)
    pub const QUEUE_AVAIL_HIGH: usize = 0x094;
    /// Queue used ring address (low)
    pub const QUEUE_USED_LOW: usize = 0x0a0;
    /// Queue used ring address (high)
    pub const QUEUE_USED_HIGH: usize = 0x0a4;
    /// Config space starts here
    pub const CONFIG: usize = 0x100;
}

/// VirtIO MMIO Magic Value
pub const VIRTIO_MMIO_MAGIC: u32 = 0x74726976; // "virt" in little-endian

// ============================================================================
// PCI Capability Structures (VirtIO PCI Transport)
// ============================================================================

/// VirtIO PCI Capability タイプ
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioPciCapType {
    /// Common configuration
    CommonCfg = 1,
    /// Notifications
    NotifyCfg = 2,
    /// ISR status
    IsrCfg = 3,
    /// Device specific configuration
    DeviceCfg = 4,
    /// PCI configuration access
    PciCfg = 5,
}

/// VirtIO PCI Capability構造体
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtioPciCap {
    /// Capability type
    pub cap_vndr: u8,
    /// Next capability offset
    pub cap_next: u8,
    /// Capability length
    pub cap_len: u8,
    /// VirtIO capability type
    pub cfg_type: u8,
    /// BAR index
    pub bar: u8,
    /// Padding
    pub padding: [u8; 3],
    /// Offset within BAR
    pub offset: u32,
    /// Length
    pub length: u32,
}

// ============================================================================
// Common Feature Bits
// ============================================================================

/// VirtIO共通フィーチャービット
pub mod common_features {
    /// Ring event index support
    pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
    /// Version 1 support
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    /// Access platform support
    pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;
    /// Ring packed layout
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
    /// In-order completion
    pub const VIRTIO_F_IN_ORDER: u64 = 1 << 35;
    /// Order platform operations
    pub const VIRTIO_F_ORDER_PLATFORM: u64 = 1 << 36;
    /// Single root I/O virtualization
    pub const VIRTIO_F_SR_IOV: u64 = 1 << 37;
    /// Notification data
    pub const VIRTIO_F_NOTIFICATION_DATA: u64 = 1 << 38;
}
