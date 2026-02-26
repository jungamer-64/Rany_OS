// ============================================================================
// src/io/virtio/transport.rs - VirtIO Transport Layer Abstraction
// ============================================================================
//!
//! # VirtIO トランスポート層抽象化
//!
//! VirtIO仕様に基づくトランスポート層（MMIO、PCI）を抽象化するトレイト定義。
//! デバイスドライバはトランスポートに依存せず、統一的なインターフェースで
//! VirtIOデバイスにアクセスできる。
//!
//! ## サポートするトランスポート
//! - MMIO (Memory Mapped I/O) - ARM/RISC-V向け
//! - PCI (Legacy/Modern) - x86_64向け
//!
//! ## 参考
//! - VirtIO Specification v1.2
//! - MMIO Transport: Section 4.2
//! - PCI Transport: Section 4.1
//!

#![allow(dead_code)]

use crate::defs::{VirtioDeviceType, status};

// ============================================================================
// Transport Error
// ============================================================================

/// トランスポート層エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// デバイスが見つからない
    DeviceNotFound,
    /// 無効なマジック値
    InvalidMagic,
    /// サポートされていないバージョン
    UnsupportedVersion,
    /// フィーチャネゴシエーション失敗
    FeatureNegotiationFailed,
    /// キュー設定エラー
    QueueSetupFailed,
    /// 設定空間アクセスエラー
    ConfigAccessFailed,
    /// デバイスエラー
    DeviceError,
    /// タイムアウト
    Timeout,
    /// 無効なキューインデックス
    InvalidQueueIndex,
    /// リソース不足
    OutOfResources,
}

/// トランスポート結果型
pub type TransportResult<T> = Result<T, TransportError>;

// ============================================================================
// VirtIO Transport Trait
// ============================================================================

/// VirtIOトランスポート層トレイト
///
/// MMIOとPCIの両方のトランスポートを抽象化する。
/// デバイスドライバはこのトレイトを通じてVirtIOデバイスにアクセスする。
pub trait VirtioTransport: Send + Sync {
    /// デバイスタイプを取得
    fn device_type(&self) -> VirtioDeviceType;

    /// デバイスステータスを取得
    fn get_status(&self) -> u8;

    /// デバイスステータスを設定
    fn set_status(&mut self, status: u8);

    /// デバイスをリセット
    fn reset(&mut self) {
        self.set_status(status::VIRTIO_STATUS_RESET);
    }

    /// デバイスフィーチャを取得（ビット0-31）
    fn get_device_features_low(&self) -> u32;

    /// デバイスフィーチャを取得（ビット32-63）
    fn get_device_features_high(&self) -> u32;

    /// デバイスフィーチャを取得（64ビット）
    fn get_device_features(&self) -> u64 {
        let low = self.get_device_features_low() as u64;
        let high = self.get_device_features_high() as u64;
        low | (high << 32)
    }

    /// ドライバフィーチャを設定（ビット0-31）
    fn set_driver_features_low(&mut self, features: u32);

    /// ドライバフィーチャを設定（ビット32-63）
    fn set_driver_features_high(&mut self, features: u32);

    /// ドライバフィーチャを設定（64ビット）
    fn set_driver_features(&mut self, features: u64) {
        self.set_driver_features_low(features as u32);
        self.set_driver_features_high((features >> 32) as u32);
    }

    /// キュー数を取得
    fn get_num_queues(&self) -> u16;

    /// キューを選択
    fn select_queue(&mut self, queue_index: u16);

    /// 選択されたキューの最大サイズを取得
    fn get_queue_max_size(&self) -> u16;

    /// キューサイズを設定
    fn set_queue_size(&mut self, size: u16);

    /// キューが有効かどうかを確認
    fn is_queue_ready(&self) -> bool;

    /// キューを有効化
    fn enable_queue(&mut self);

    /// キューを無効化
    fn disable_queue(&mut self);

    /// キューのディスクリプタテーブルアドレスを設定
    fn set_queue_desc_addr(&mut self, addr: u64);

    /// キューのAvailリングアドレスを設定
    fn set_queue_avail_addr(&mut self, addr: u64);

    /// キューのUsedリングアドレスを設定
    fn set_queue_used_addr(&mut self, addr: u64);

    /// キューに通知
    fn notify_queue(&self, queue_index: u16);

    /// キューの通知アドレスを取得
    ///
    /// ポーリングなどで、トランスポートを介さずに直接OS側へ通知したい場合に使用
    fn get_notify_addr(&mut self, queue_index: u16) -> Option<u64>;

    /// 割り込みステータスを取得
    fn get_interrupt_status(&self) -> u32;

    /// 割り込みACK (updated to &self)
    fn ack_interrupt(&self, status: u32);

    /// コンフィグ空間から8ビット値を読み取り
    fn read_config_u8(&self, offset: usize) -> u8;

    /// コンフィグ空間から16ビット値を読み取り
    fn read_config_u16(&self, offset: usize) -> u16;

    /// コンフィグ空間から32ビット値を読み取り
    fn read_config_u32(&self, offset: usize) -> u32;

    /// コンフィグ空間から64ビット値を読み取り
    fn read_config_u64(&self, offset: usize) -> u64 {
        let low = self.read_config_u32(offset) as u64;
        let high = self.read_config_u32(offset + 4) as u64;
        low | (high << 32)
    }

    /// コンフィグ空間に8ビット値を書き込み
    fn write_config_u8(&mut self, offset: usize, value: u8);

    /// コンフィグ空間に16ビット値を書き込み
    fn write_config_u16(&mut self, offset: usize, value: u16);

    /// コンフィグ空間に32ビット値を書き込み
    fn write_config_u32(&mut self, offset: usize, value: u32);

    /// トランスポート種別を取得
    fn transport_type(&self) -> TransportType;

    /// MSI-X対応かどうか（PCI transport用）
    fn supports_msix(&self) -> bool {
        false
    }

    /// MSI-Xを設定（PCI transport用）
    fn configure_msix(&mut self, _queue_index: u16, _vector: u16) -> TransportResult<()> {
        Err(TransportError::UnsupportedVersion)
    }
}

/// トランスポート種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// MMIO トランスポート
    Mmio,
    /// PCI Legacy トランスポート
    PciLegacy,
    /// PCI Modern トランスポート (VIRTIO_F_VERSION_1)
    PciModern,
}

// ============================================================================
// MMIO Transport Implementation
// ============================================================================

/// MMIOレジスタオフセット
mod mmio_regs {
    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00C;
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
    pub const QUEUE_USED_LOW: usize = 0x0A0;
    pub const QUEUE_USED_HIGH: usize = 0x0A4;
    pub const CONFIG: usize = 0x100;
}

/// VirtIO MMIO トランスポート
pub struct VirtioMmioTransport {
    /// MMIOベースアドレス
    base: usize,
    /// デバイスタイプ
    device_type: VirtioDeviceType,
}

impl VirtioMmioTransport {
    const MAGIC: u32 = 0x74726976; // "virt"

    /// 新しいMMIOトランスポートを作成
    ///
    /// # Safety
    /// - `base` は有効なMMIOアドレスを指す必要がある。
    pub unsafe fn new(base: usize) -> TransportResult<Self> {
        let magic = Self::read32_raw(base, mmio_regs::MAGIC_VALUE);
        if magic != Self::MAGIC {
            return Err(TransportError::InvalidMagic);
        }

        let version = Self::read32_raw(base, mmio_regs::VERSION);
        if version != 1 && version != 2 {
            return Err(TransportError::UnsupportedVersion);
        }

        let device_id = Self::read32_raw(base, mmio_regs::DEVICE_ID);
        let device_type = VirtioDeviceType::from(device_id);

        Ok(Self { base, device_type })
    }

    /// 生MMIO読み取り
    #[inline]
    fn read32_raw(base: usize, offset: usize) -> u32 {
        hal::mmio::mmio_read_u32(base + offset)
    }

    /// 生MMIO書き込み
    #[inline]
    fn write32_raw(base: usize, offset: usize, value: u32) {
        hal::mmio::mmio_write_u32(base + offset, value);
    }

    /// 32ビットレジスタを読み取り
    #[inline]
    fn read32(&self, offset: usize) -> u32 {
        Self::read32_raw(self.base, offset)
    }

    /// 32ビットレジスタに書き込み
    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        Self::write32_raw(self.base, offset, value)
    }
}

impl VirtioTransport for VirtioMmioTransport {
    fn device_type(&self) -> VirtioDeviceType {
        self.device_type
    }

    fn get_status(&self) -> u8 {
        self.read32(mmio_regs::STATUS) as u8
    }

    fn set_status(&mut self, status: u8) {
        self.write32(mmio_regs::STATUS, status as u32);
    }

    fn get_device_features_low(&self) -> u32 {
        self.write32(mmio_regs::DEVICE_FEATURES_SEL, 0);
        self.read32(mmio_regs::DEVICE_FEATURES)
    }

    fn get_device_features_high(&self) -> u32 {
        self.write32(mmio_regs::DEVICE_FEATURES_SEL, 1);
        self.read32(mmio_regs::DEVICE_FEATURES)
    }

    fn set_driver_features_low(&mut self, features: u32) {
        self.write32(mmio_regs::DRIVER_FEATURES_SEL, 0);
        self.write32(mmio_regs::DRIVER_FEATURES, features);
    }

    fn set_driver_features_high(&mut self, features: u32) {
        self.write32(mmio_regs::DRIVER_FEATURES_SEL, 1);
        self.write32(mmio_regs::DRIVER_FEATURES, features);
    }

    fn get_num_queues(&self) -> u16 {
        // MMIOでは明示的なキュー数フィールドがないため、
        // 各キューを選択してサイズを確認する
        for i in 0..16 {
            self.write32(mmio_regs::QUEUE_SEL, i as u32);
            if self.read32(mmio_regs::QUEUE_NUM_MAX) == 0 {
                return i;
            }
        }
        16
    }

    fn select_queue(&mut self, queue_index: u16) {
        self.write32(mmio_regs::QUEUE_SEL, queue_index as u32);
    }

    fn get_queue_max_size(&self) -> u16 {
        self.read32(mmio_regs::QUEUE_NUM_MAX) as u16
    }

    fn set_queue_size(&mut self, size: u16) {
        self.write32(mmio_regs::QUEUE_NUM, size as u32);
    }

    fn is_queue_ready(&self) -> bool {
        self.read32(mmio_regs::QUEUE_READY) != 0
    }

    fn enable_queue(&mut self) {
        self.write32(mmio_regs::QUEUE_READY, 1);
    }

    fn disable_queue(&mut self) {
        self.write32(mmio_regs::QUEUE_READY, 0);
    }

    fn set_queue_desc_addr(&mut self, addr: u64) {
        self.write32(mmio_regs::QUEUE_DESC_LOW, addr as u32);
        self.write32(mmio_regs::QUEUE_DESC_HIGH, (addr >> 32) as u32);
    }

    fn set_queue_avail_addr(&mut self, addr: u64) {
        self.write32(mmio_regs::QUEUE_AVAIL_LOW, addr as u32);
        self.write32(mmio_regs::QUEUE_AVAIL_HIGH, (addr >> 32) as u32);
    }

    fn set_queue_used_addr(&mut self, addr: u64) {
        self.write32(mmio_regs::QUEUE_USED_LOW, addr as u32);
        self.write32(mmio_regs::QUEUE_USED_HIGH, (addr >> 32) as u32);
    }

    fn notify_queue(&self, queue_index: u16) {
        let addr = (self.base + mmio_regs::QUEUE_NOTIFY) as usize;
        log::info!(
            "[EARLY][VIRTIO-MMIO] notify_queue queue={} addr=0x{:x}",
            queue_index,
            addr
        );
        self.write32(mmio_regs::QUEUE_NOTIFY, queue_index as u32);
        let read_back = self.read32(mmio_regs::QUEUE_NOTIFY);
        log::info!(
            "[EARLY][VIRTIO-MMIO] notify wrote {}, read_back=0x{:x}",
            queue_index,
            read_back
        );
    }

    fn get_notify_addr(&mut self, _queue_index: u16) -> Option<u64> {
        Some((self.base + mmio_regs::QUEUE_NOTIFY) as u64)
    }

    fn get_interrupt_status(&self) -> u32 {
        self.read32(mmio_regs::INTERRUPT_STATUS)
    }

    fn ack_interrupt(&self, status: u32) {
        self.write32(mmio_regs::INTERRUPT_ACK, status);
    }

    fn read_config_u8(&self, offset: usize) -> u8 {
        hal::mmio::mmio_read_u8((self.base + mmio_regs::CONFIG + offset) as usize)
    }

    fn read_config_u16(&self, offset: usize) -> u16 {
        hal::mmio::mmio_read_u16((self.base + mmio_regs::CONFIG + offset) as usize)
    }

    fn read_config_u32(&self, offset: usize) -> u32 {
        hal::mmio::mmio_read_u32((self.base + mmio_regs::CONFIG + offset) as usize)
    }

    fn write_config_u8(&mut self, offset: usize, value: u8) {
        hal::mmio::mmio_write_u8((self.base + mmio_regs::CONFIG + offset) as usize, value);
    }

    fn write_config_u16(&mut self, offset: usize, value: u16) {
        hal::mmio::mmio_write_u16((self.base + mmio_regs::CONFIG + offset) as usize, value);
    }

    fn write_config_u32(&mut self, offset: usize, value: u32) {
        hal::mmio::mmio_write_u32((self.base + mmio_regs::CONFIG + offset) as usize, value);
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Mmio
    }
}

// ============================================================================
// PCI Transport Implementation
// ============================================================================

/// VirtIO PCI Capability offsets (Common Configuration)
mod pci_common_cfg {
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub const DEVICE_FEATURE: usize = 0x04;
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub const DRIVER_FEATURE: usize = 0x0C;
    pub const MSIX_CONFIG: usize = 0x10;
    pub const NUM_QUEUES: usize = 0x12;
    pub const DEVICE_STATUS: usize = 0x14;
    pub const CONFIG_GENERATION: usize = 0x15;
    pub const QUEUE_SELECT: usize = 0x16;
    pub const QUEUE_SIZE: usize = 0x18;
    pub const QUEUE_MSIX_VECTOR: usize = 0x1A;
    pub const QUEUE_ENABLE: usize = 0x1C;
    pub const QUEUE_NOTIFY_OFF: usize = 0x1E;
    pub const QUEUE_DESC: usize = 0x20;
    pub const QUEUE_AVAIL: usize = 0x28;
    pub const QUEUE_USED: usize = 0x30;
}

/// VirtIO PCI トランスポート (Modern)
pub struct VirtioPciTransport {
    /// BDF (Bus/Device/Function) アドレス
    bdf: u32,
    /// Common Configuration BAR アドレス
    common_cfg_addr: usize,
    /// Notify BAR アドレス
    notify_addr: usize,
    /// Notify オフセット乗数
    notify_off_multiplier: u32,
    /// ISR BAR アドレス
    isr_addr: usize,
    /// Device Configuration BAR アドレス
    device_cfg_addr: usize,
    /// デバイスタイプ
    device_type: VirtioDeviceType,
    /// MSI-X対応
    msix_enabled: bool,
}

impl VirtioPciTransport {
    /// 新しいPCIトランスポートを作成
    ///
    /// # Safety
    /// - 各BARアドレスは有効なMMIOアドレスを指す必要がある。
    pub unsafe fn new(
        bdf: u32,
        common_cfg_addr: usize,
        notify_addr: usize,
        notify_off_multiplier: u32,
        isr_addr: usize,
        device_cfg_addr: usize,
        device_type: VirtioDeviceType,
    ) -> TransportResult<Self> {
        Ok(Self {
            bdf,
            common_cfg_addr,
            notify_addr,
            notify_off_multiplier,
            isr_addr,
            device_cfg_addr,
            device_type,
            msix_enabled: false,
        })
    }

    /// Common Configuration レジスタ読み取り（8ビット）
    #[inline]
    fn read_common_u8(&self, offset: usize) -> u8 {
        hal::mmio::mmio_read_u8((self.common_cfg_addr + offset) as usize)
    }

    /// Common Configuration レジスタ読み取り（16ビット）
    #[inline]
    fn read_common_u16(&self, offset: usize) -> u16 {
        hal::mmio::mmio_read_u16((self.common_cfg_addr + offset) as usize)
    }

    /// Common Configuration レジスタ読み取り（32ビット）
    #[inline]
    fn read_common_u32(&self, offset: usize) -> u32 {
        hal::mmio::mmio_read_u32((self.common_cfg_addr + offset) as usize)
    }

    /// Common Configuration レジスタ読み取り（64ビット）
    #[inline]
    fn read_common_u64(&self, offset: usize) -> u64 {
        hal::mmio::mmio_read_u64((self.common_cfg_addr + offset) as usize)
    }

    /// Common Configuration レジスタに書き込み（8ビット）
    #[inline]
    fn write_common_u8(&self, offset: usize, value: u8) {
        hal::mmio::mmio_write_u8((self.common_cfg_addr + offset) as usize, value);
    }

    /// Common Configuration レジスタに書き込み（16ビット）
    #[inline]
    fn write_common_u16(&self, offset: usize, value: u16) {
        hal::mmio::mmio_write_u16((self.common_cfg_addr + offset) as usize, value);
    }

    /// Common Configuration レジスタに書き込み（32ビット）
    #[inline]
    fn write_common_u32(&self, offset: usize, value: u32) {
        hal::mmio::mmio_write_u32((self.common_cfg_addr + offset) as usize, value);
    }

    /// Common Configuration レジスタに書き込み（64ビット）
    #[inline]
    fn write_common_u64(&self, offset: usize, value: u64) {
        hal::mmio::mmio_write_u64((self.common_cfg_addr + offset) as usize, value);
    }

    /// キューの通知オフセットを取得
    fn get_queue_notify_offset(&self) -> u16 {
        self.read_common_u16(pci_common_cfg::QUEUE_NOTIFY_OFF)
    }
}

impl VirtioTransport for VirtioPciTransport {
    fn device_type(&self) -> VirtioDeviceType {
        self.device_type
    }

    fn get_status(&self) -> u8 {
        self.read_common_u8(pci_common_cfg::DEVICE_STATUS)
    }

    fn set_status(&mut self, status: u8) {
        self.write_common_u8(pci_common_cfg::DEVICE_STATUS, status);
    }

    fn get_device_features_low(&self) -> u32 {
        self.write_common_u32(pci_common_cfg::DEVICE_FEATURE_SELECT, 0);
        self.read_common_u32(pci_common_cfg::DEVICE_FEATURE)
    }

    fn get_device_features_high(&self) -> u32 {
        self.write_common_u32(pci_common_cfg::DEVICE_FEATURE_SELECT, 1);
        self.read_common_u32(pci_common_cfg::DEVICE_FEATURE)
    }

    fn set_driver_features_low(&mut self, features: u32) {
        self.write_common_u32(pci_common_cfg::DRIVER_FEATURE_SELECT, 0);
        self.write_common_u32(pci_common_cfg::DRIVER_FEATURE, features);
    }

    fn set_driver_features_high(&mut self, features: u32) {
        self.write_common_u32(pci_common_cfg::DRIVER_FEATURE_SELECT, 1);
        self.write_common_u32(pci_common_cfg::DRIVER_FEATURE, features);
    }

    fn get_num_queues(&self) -> u16 {
        self.read_common_u16(pci_common_cfg::NUM_QUEUES)
    }

    fn select_queue(&mut self, queue_index: u16) {
        self.write_common_u16(pci_common_cfg::QUEUE_SELECT, queue_index);
    }

    fn get_queue_max_size(&self) -> u16 {
        self.read_common_u16(pci_common_cfg::QUEUE_SIZE)
    }

    fn set_queue_size(&mut self, size: u16) {
        self.write_common_u16(pci_common_cfg::QUEUE_SIZE, size);
    }

    fn is_queue_ready(&self) -> bool {
        self.read_common_u16(pci_common_cfg::QUEUE_ENABLE) != 0
    }

    fn enable_queue(&mut self) {
        self.write_common_u16(pci_common_cfg::QUEUE_ENABLE, 1);
    }

    fn disable_queue(&mut self) {
        self.write_common_u16(pci_common_cfg::QUEUE_ENABLE, 0);
    }

    fn set_queue_desc_addr(&mut self, addr: u64) {
        self.write_common_u64(pci_common_cfg::QUEUE_DESC, addr);
    }

    fn set_queue_avail_addr(&mut self, addr: u64) {
        self.write_common_u64(pci_common_cfg::QUEUE_AVAIL, addr);
    }

    fn set_queue_used_addr(&mut self, addr: u64) {
        self.write_common_u64(pci_common_cfg::QUEUE_USED, addr);
    }

    fn notify_queue(&self, queue_index: u16) {
        // Select the queue in the device common config
        self.write_common_u16(pci_common_cfg::QUEUE_SELECT, queue_index);
        let notify_off = self.get_queue_notify_offset() as usize;

        // Compute notify doorbell address using the multiplier
        let notify_addr = self.notify_addr + notify_off * self.notify_off_multiplier as usize;

        log::info!(
            "[EARLY][VIRTIO-PCI] notify_queue queue={} notify_off={} notify_mult={} notify_addr=0x{:x}",
            queue_index,
            notify_off,
            self.notify_off_multiplier,
            notify_addr
        );

        // Perform the doorbell write (16-bit)
        hal::mmio::mmio_write_u16(notify_addr as usize, queue_index);

        // Read back for diagnostics (may not reflect device state)
        let read_back = hal::mmio::mmio_read_u16(notify_addr as usize);
        log::info!(
            "[EARLY][VIRTIO-PCI] notify_queue wrote {} read_back=0x{:x}",
            queue_index,
            read_back
        );
    }

    fn get_notify_addr(&mut self, queue_index: u16) -> Option<u64> {
        self.write_common_u16(pci_common_cfg::QUEUE_SELECT, queue_index);
        let notify_off = self.get_queue_notify_offset() as usize;
        Some((self.notify_addr + notify_off * self.notify_off_multiplier as usize) as u64)
    }

    fn get_interrupt_status(&self) -> u32 {
        hal::mmio::mmio_read_u8(self.isr_addr as usize) as u32
    }

    fn ack_interrupt(&self, _status: u32) {
        // PCI transportではISRを読むだけでACKになる
        let _ = self.get_interrupt_status();
    }

    fn read_config_u8(&self, offset: usize) -> u8 {
        hal::mmio::mmio_read_u8((self.device_cfg_addr + offset) as usize)
    }

    fn read_config_u16(&self, offset: usize) -> u16 {
        hal::mmio::mmio_read_u16((self.device_cfg_addr + offset) as usize)
    }

    fn read_config_u32(&self, offset: usize) -> u32 {
        hal::mmio::mmio_read_u32((self.device_cfg_addr + offset) as usize)
    }

    fn write_config_u8(&mut self, offset: usize, value: u8) {
        hal::mmio::mmio_write_u8((self.device_cfg_addr + offset) as usize, value);
    }

    fn write_config_u16(&mut self, offset: usize, value: u16) {
        hal::mmio::mmio_write_u16((self.device_cfg_addr + offset) as usize, value);
    }

    fn write_config_u32(&mut self, offset: usize, value: u32) {
        hal::mmio::mmio_write_u32((self.device_cfg_addr + offset) as usize, value);
    }

    fn transport_type(&self) -> TransportType {
        TransportType::PciModern
    }

    fn supports_msix(&self) -> bool {
        true
    }

    fn configure_msix(&mut self, queue_index: u16, vector: u16) -> TransportResult<()> {
        self.write_common_u16(pci_common_cfg::QUEUE_SELECT, queue_index);
        self.write_common_u16(pci_common_cfg::QUEUE_MSIX_VECTOR, vector);

        // 設定が成功したか確認
        let configured = self.read_common_u16(pci_common_cfg::QUEUE_MSIX_VECTOR);
        if configured == vector {
            self.msix_enabled = true;
            Ok(())
        } else {
            Err(TransportError::ConfigAccessFailed)
        }
    }
}

// ============================================================================
// Device Initialization Helper
// ============================================================================

/// デバイス初期化ヘルパー
pub struct VirtioDeviceInit<'a, T: VirtioTransport> {
    transport: &'a mut T,
}

impl<'a, T: VirtioTransport> VirtioDeviceInit<'a, T> {
    /// 新しい初期化ヘルパーを作成
    pub fn new(transport: &'a mut T) -> Self {
        Self { transport }
    }

    /// 標準的な初期化シーケンスを実行
    pub fn initialize(&mut self, required_features: u64) -> TransportResult<u64> {
        // 1. デバイスをリセット
        self.transport.reset();

        // 2. ACKNOWLEDGE を設定
        self.transport.set_status(status::VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. DRIVER を設定
        let mut current_status = self.transport.get_status();
        current_status |= status::VIRTIO_STATUS_DRIVER;
        self.transport.set_status(current_status);

        // 4. フィーチャネゴシエーション
        let device_features = self.transport.get_device_features();
        let negotiated_features = device_features & required_features;
        self.transport.set_driver_features(negotiated_features);

        // 5. FEATURES_OK を設定
        current_status = self.transport.get_status();
        current_status |= status::VIRTIO_STATUS_FEATURES_OK;
        self.transport.set_status(current_status);

        // 6. FEATURES_OK が設定されたことを確認
        let status_check = self.transport.get_status();
        if (status_check & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.transport.set_status(status::VIRTIO_STATUS_FAILED);
            return Err(TransportError::FeatureNegotiationFailed);
        }

        Ok(negotiated_features)
    }

    /// DRIVER_OK を設定してデバイスを使用可能にする
    pub fn finish_init(&mut self) -> TransportResult<()> {
        let mut current_status = self.transport.get_status();
        current_status |= status::VIRTIO_STATUS_DRIVER_OK;
        self.transport.set_status(current_status);

        // デバイスがエラー状態でないことを確認
        let final_status = self.transport.get_status();
        if (final_status & status::VIRTIO_STATUS_FAILED) != 0 {
            return Err(TransportError::DeviceError);
        }

        Ok(())
    }
}
