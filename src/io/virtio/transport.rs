// ============================================================================
// src/io/virtio/transport.rs - VirtIO Transport Layer Abstraction
// ============================================================================
//!
//! # VirtIO 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝亥ｱ､謚ｽ雎｡蛹・
//!
//! VirtIO莉墓ｧ假ｿｽE繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝亥ｱ､・ｽE・ｽEMIO縲￣CI・ｽE・ｽ繧呈歓雎｡蛹悶☆繧九ヨ繝ｬ繧､繝亥ｮ夂ｾｩ縲・
//! 繝・・ｽ・ｽ繧､繧ｹ繝峨Λ繧､繝撰ｿｽE繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝医↓萓晏ｭ倥○縺壹∫ｵｱ荳逧・・ｽ・ｽ繧､繝ｳ繧ｿ繝ｼ繝輔ぉ繝ｼ繧ｹ縺ｧ
//! VirtIO繝・・ｽ・ｽ繧､繧ｹ縺ｫ繧｢繧ｯ繧ｻ繧ｹ縺ｧ縺阪ｋ縲・
//!
//! ## 繧ｵ繝晢ｿｽE繝医☆繧九ヨ繝ｩ繝ｳ繧ｹ繝晢ｿｽE繝・
//! - MMIO (Memory Mapped I/O) - ARM/RISC-V蜷代￠
//! - PCI (Legacy/Modern) - x86_64蜷代￠
//!
//! ## 蜿り・
//! - VirtIO Specification v1.2
//! - MMIO Transport: Section 4.2
//! - PCI Transport: Section 4.1

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::NonNull;

use super::defs::{VirtioDeviceType, status};

// ============================================================================
// Transport Error
// ============================================================================

/// 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝亥ｱ､繧ｨ繝ｩ繝ｼ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// 繝・・ｽ・ｽ繧､繧ｹ縺瑚ｦ九▽縺九ｉ縺ｪ縺・
    DeviceNotFound,
    /// 辟｡蜉ｹ縺ｪ繝槭ず繝・・ｽ・ｽ蛟､
    InvalidMagic,
    /// 繧ｵ繝晢ｿｽE繝医＆繧後※縺・・ｽ・ｽ縺・・ｽ・ｽ繝ｼ繧ｸ繝ｧ繝ｳ
    UnsupportedVersion,
    /// 繝輔ぅ繝ｼ繝√Ε繝阪ざ繧ｷ繧ｨ繝ｼ繧ｷ繝ｧ繝ｳ螟ｱ謨・
    FeatureNegotiationFailed,
    /// 繧ｭ繝･繝ｼ險ｭ螳壹お繝ｩ繝ｼ
    QueueSetupFailed,
    /// 險ｭ螳夂ｩｺ髢薙い繧ｯ繧ｻ繧ｹ繧ｨ繝ｩ繝ｼ
    ConfigAccessFailed,
    /// 繝・・ｽ・ｽ繧､繧ｹ繧ｨ繝ｩ繝ｼ
    DeviceError,
    /// 繧ｿ繧､繝繧｢繧ｦ繝・
    Timeout,
    /// 辟｡蜉ｹ縺ｪ繧ｭ繝･繝ｼ繧､繝ｳ繝・・ｽ・ｽ繧ｯ繧ｹ
    InvalidQueueIndex,
    /// 繝ｪ繧ｽ繝ｼ繧ｹ荳崎ｶｳ
    OutOfResources,
}

/// 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝育ｵ先棡蝙・
pub type TransportResult<T> = Result<T, TransportError>;

// ============================================================================
// VirtIO Transport Trait
// ============================================================================

/// VirtIO繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝亥ｱ､繝医Ξ繧､繝・
///
/// MMIO縺ｨPCI縺ｮ荳｡譁ｹ縺ｮ繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝医ｒ謚ｽ雎｡蛹悶☆繧九・
/// 繝・・ｽ・ｽ繧､繧ｹ繝峨Λ繧､繝撰ｿｽE縺難ｿｽE繝医Ξ繧､繝医ｒ騾壹§縺ｦVirtIO繝・・ｽ・ｽ繧､繧ｹ縺ｫ繧｢繧ｯ繧ｻ繧ｹ縺吶ｋ縲・
pub trait VirtioTransport: Send + Sync {
    /// 繝・・ｽ・ｽ繧､繧ｹ繧ｿ繧､繝励ｒ蜿門ｾ・
    fn device_type(&self) -> VirtioDeviceType;
    
    /// 繝・・ｽ・ｽ繧､繧ｹ繧ｹ繝・・ｽE繧ｿ繧ｹ繧貞叙蠕・
    fn get_status(&self) -> u8;
    
    /// 繝・・ｽ・ｽ繧､繧ｹ繧ｹ繝・・ｽE繧ｿ繧ｹ繧定ｨｭ螳・
    fn set_status(&mut self, status: u8);
    
    /// 繝・・ｽ・ｽ繧､繧ｹ繧偵Μ繧ｻ繝・・ｽ・ｽ
    fn reset(&mut self) {
        self.set_status(status::VIRTIO_STATUS_RESET);
    }
    
    /// 繝・・ｽ・ｽ繧､繧ｹ繝輔ぅ繝ｼ繝√Ε繧貞叙蠕暦ｼ医ン繝・・ｽ・ｽ0-31・ｽE・ｽE
    fn get_device_features_low(&self) -> u32;
    
    /// 繝・・ｽ・ｽ繧､繧ｹ繝輔ぅ繝ｼ繝√Ε繧貞叙蠕暦ｼ医ン繝・・ｽ・ｽ32-63・ｽE・ｽE
    fn get_device_features_high(&self) -> u32;
    
    /// 繝・・ｽ・ｽ繧､繧ｹ繝輔ぅ繝ｼ繝√Ε繧貞叙蠕暦ｼ・4繝薙ャ繝茨ｼ・
    fn get_device_features(&self) -> u64 {
        let low = self.get_device_features_low() as u64;
        let high = self.get_device_features_high() as u64;
        low | (high << 32)
    }
    
    /// 繝峨Λ繧､繝舌ヵ繧｣繝ｼ繝√Ε繧定ｨｭ螳夲ｼ医ン繝・・ｽ・ｽ0-31・ｽE・ｽE
    fn set_driver_features_low(&mut self, features: u32);
    
    /// 繝峨Λ繧､繝舌ヵ繧｣繝ｼ繝√Ε繧定ｨｭ螳夲ｼ医ン繝・・ｽ・ｽ32-63・ｽE・ｽE
    fn set_driver_features_high(&mut self, features: u32);
    
    /// 繝峨Λ繧､繝舌ヵ繧｣繝ｼ繝√Ε繧定ｨｭ螳夲ｼ・4繝薙ャ繝茨ｼ・
    fn set_driver_features(&mut self, features: u64) {
        self.set_driver_features_low(features as u32);
        self.set_driver_features_high((features >> 32) as u32);
    }
    
    /// 繧ｭ繝･繝ｼ謨ｰ繧貞叙蠕・
    fn get_num_queues(&self) -> u16;
    
    /// 繧ｭ繝･繝ｼ繧帝∈謚・
    fn select_queue(&mut self, queue_index: u16);
    
    /// 驕ｸ謚槭＆繧後◆繧ｭ繝･繝ｼ縺ｮ譛螟ｧ繧ｵ繧､繧ｺ繧貞叙蠕・
    fn get_queue_max_size(&self) -> u16;
    
    /// 繧ｭ繝･繝ｼ繧ｵ繧､繧ｺ繧定ｨｭ螳・
    fn set_queue_size(&mut self, size: u16);
    
    /// 繧ｭ繝･繝ｼ縺梧怏蜉ｹ縺九←縺・・ｽ・ｽ繧堤｢ｺ隱・
    fn is_queue_ready(&self) -> bool;
    
    /// 繧ｭ繝･繝ｼ繧呈怏蜉ｹ蛹・
    fn enable_queue(&mut self);
    
    /// 繧ｭ繝･繝ｼ繧堤┌蜉ｹ蛹・
    fn disable_queue(&mut self);
    
    /// 繧ｭ繝･繝ｼ縺ｮ繝・・ｽ・ｽ繧ｹ繧ｯ繝ｪ繝励ち繝・・ｽE繝悶Ν繧｢繝峨Ξ繧ｹ繧定ｨｭ螳・
    fn set_queue_desc_addr(&mut self, addr: u64);
    
    /// 繧ｭ繝･繝ｼ縺ｮAvail繝ｪ繝ｳ繧ｰ繧｢繝峨Ξ繧ｹ繧定ｨｭ螳・
    fn set_queue_avail_addr(&mut self, addr: u64);
    
    /// 繧ｭ繝･繝ｼ縺ｮUsed繝ｪ繝ｳ繧ｰ繧｢繝峨Ξ繧ｹ繧定ｨｭ螳・
    fn set_queue_used_addr(&mut self, addr: u64);
    
    /// 繧ｭ繝･繝ｼ縺ｫ騾夂衍
    fn notify_queue(&mut self, queue_index: u16);
    
    /// 蜑ｲ繧願ｾｼ縺ｿ繧ｹ繝・・ｽE繧ｿ繧ｹ繧貞叙蠕・
    fn get_interrupt_status(&self) -> u32;
    
    /// 蜑ｲ繧願ｾｼ縺ｿ繧但CK
    fn ack_interrupt(&mut self, status: u32);
    
    /// 繧ｳ繝ｳ繝輔ぅ繧ｰ遨ｺ髢薙°繧・繝薙ャ繝亥､繧定ｪｭ縺ｿ蜿悶ｊ
    fn read_config_u8(&self, offset: usize) -> u8;
    
    /// 繧ｳ繝ｳ繝輔ぅ繧ｰ遨ｺ髢薙°繧・6繝薙ャ繝亥､繧定ｪｭ縺ｿ蜿悶ｊ
    fn read_config_u16(&self, offset: usize) -> u16;
    
    /// 繧ｳ繝ｳ繝輔ぅ繧ｰ遨ｺ髢薙°繧・2繝薙ャ繝亥､繧定ｪｭ縺ｿ蜿悶ｊ
    fn read_config_u32(&self, offset: usize) -> u32;
    
    /// 繧ｳ繝ｳ繝輔ぅ繧ｰ遨ｺ髢薙°繧・4繝薙ャ繝亥､繧定ｪｭ縺ｿ蜿悶ｊ
    fn read_config_u64(&self, offset: usize) -> u64 {
        let low = self.read_config_u32(offset) as u64;
        let high = self.read_config_u32(offset + 4) as u64;
        low | (high << 32)
    }
    
    /// 繧ｳ繝ｳ繝輔ぅ繧ｰ遨ｺ髢薙↓8繝薙ャ繝亥､繧呈嶌縺崎ｾｼ縺ｿ
    fn write_config_u8(&mut self, offset: usize, value: u8);
    
    /// 繧ｳ繝ｳ繝輔ぅ繧ｰ遨ｺ髢薙↓16繝薙ャ繝亥､繧呈嶌縺崎ｾｼ縺ｿ
    fn write_config_u16(&mut self, offset: usize, value: u16);
    
    /// 繧ｳ繝ｳ繝輔ぅ繧ｰ遨ｺ髢薙↓32繝薙ャ繝亥､繧呈嶌縺崎ｾｼ縺ｿ
    fn write_config_u32(&mut self, offset: usize, value: u32);
    
    /// 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝育ｨｮ蛻･繧貞叙蠕・
    fn transport_type(&self) -> TransportType;
    
    /// MSI-X蟇ｾ蠢懊°縺ｩ縺・・ｽ・ｽ・ｽE・ｽECI transport逕ｨ・ｽE・ｽE
    fn supports_msix(&self) -> bool {
        false
    }
    
    /// MSI-X繧定ｨｭ螳夲ｼ・CI transport逕ｨ・ｽE・ｽE
    fn configure_msix(&mut self, _queue_index: u16, _vector: u16) -> TransportResult<()> {
        Err(TransportError::UnsupportedVersion)
    }
}

/// 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝育ｨｮ蛻･
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// MMIO 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝・
    Mmio,
    /// PCI Legacy 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝・
    PciLegacy,
    /// PCI Modern 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝・(VIRTIO_F_VERSION_1)
    PciModern,
}

// ============================================================================
// MMIO Transport Implementation
// ============================================================================

/// MMIO繝ｬ繧ｸ繧ｹ繧ｿ繧ｪ繝輔そ繝・・ｽ・ｽ
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

/// VirtIO MMIO 繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝・
pub struct VirtioMmioTransport {
    /// MMIO繝呻ｿｽE繧ｹ繧｢繝峨Ξ繧ｹ
    base: usize,
    /// 繝・・ｽ・ｽ繧､繧ｹ繧ｿ繧､繝・
    device_type: VirtioDeviceType,
}

impl VirtioMmioTransport {
    const MAGIC: u32 = 0x74726976; // "virt"
    
    /// 譁ｰ縺励＞MMIO繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝医ｒ菴懶ｿｽE
    ///
    /// # Safety
    /// - `base` 縺ｯ譛牙柑縺ｪMMIO繧｢繝峨Ξ繧ｹ繧呈欠縺吝ｿ・・ｽ・ｽ縺後≠繧・
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
    
    /// 逕滂ｿｽEMMIO隱ｭ縺ｿ蜿悶ｊ
    #[inline]
    unsafe fn read32_raw(base: usize, offset: usize) -> u32 {
        core::ptr::read_volatile((base + offset) as *const u32)
    }
    
    /// 逕滂ｿｽEMMIO譖ｸ縺崎ｾｼ縺ｿ
    #[inline]
    unsafe fn write32_raw(base: usize, offset: usize, value: u32) {
        core::ptr::write_volatile((base + offset) as *mut u32, value);
    }
    
    /// 32繝薙ャ繝医Ξ繧ｸ繧ｹ繧ｿ繧定ｪｭ縺ｿ蜿悶ｊ
    #[inline]
    fn read32(&self, offset: usize) -> u32 {
        unsafe { Self::read32_raw(self.base, offset) }
    }
    
    /// 32繝薙ャ繝医Ξ繧ｸ繧ｹ繧ｿ縺ｫ譖ｸ縺崎ｾｼ縺ｿ
    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        unsafe { Self::write32_raw(self.base, offset, value) }
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
        // MMIO縺ｧ縺ｯ譏守､ｺ逧・・ｽ・ｽ繧ｭ繝･繝ｼ謨ｰ繝輔ぅ繝ｼ繝ｫ繝峨′縺ｪ縺・・ｽ・ｽ繧√・
        // 蜷・・ｽ・ｽ繝･繝ｼ繧帝∈謚槭＠縺ｦ繧ｵ繧､繧ｺ繧堤｢ｺ隱阪☆繧・
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
    
    fn notify_queue(&mut self, queue_index: u16) {
        self.write32(mmio_regs::QUEUE_NOTIFY, queue_index as u32);
    }
    
    fn get_interrupt_status(&self) -> u32 {
        self.read32(mmio_regs::INTERRUPT_STATUS)
    }
    
    fn ack_interrupt(&mut self, status: u32) {
        self.write32(mmio_regs::INTERRUPT_ACK, status);
    }
    
    fn read_config_u8(&self, offset: usize) -> u8 {
        unsafe {
            core::ptr::read_volatile((self.base + mmio_regs::CONFIG + offset) as *const u8)
        }
    }
    
    fn read_config_u16(&self, offset: usize) -> u16 {
        unsafe {
            core::ptr::read_volatile((self.base + mmio_regs::CONFIG + offset) as *const u16)
        }
    }
    
    fn read_config_u32(&self, offset: usize) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.base + mmio_regs::CONFIG + offset) as *const u32)
        }
    }
    
    fn write_config_u8(&mut self, offset: usize, value: u8) {
        unsafe {
            core::ptr::write_volatile((self.base + mmio_regs::CONFIG + offset) as *mut u8, value);
        }
    }
    
    fn write_config_u16(&mut self, offset: usize, value: u16) {
        unsafe {
            core::ptr::write_volatile((self.base + mmio_regs::CONFIG + offset) as *mut u16, value);
        }
    }
    
    fn write_config_u32(&mut self, offset: usize, value: u32) {
        unsafe {
            core::ptr::write_volatile((self.base + mmio_regs::CONFIG + offset) as *mut u32, value);
        }
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

/// VirtIO PCI 繝医Λ繝ｳ繧ｹ繝昴・繝・(Modern)
pub struct VirtioPciTransport {
    /// BDF (Bus/Device/Function) 繧｢繝峨Ξ繧ｹ
    bdf: u32,
    /// Common Configuration BAR 繧｢繝峨Ξ繧ｹ
    common_cfg_addr: usize,
    /// Notify BAR 繧｢繝峨Ξ繧ｹ
    notify_addr: usize,
    /// Notify 繧ｪ繝輔そ繝・ヨ荵玲焚
    notify_off_multiplier: u32,
    /// ISR BAR 繧｢繝峨Ξ繧ｹ
    isr_addr: usize,
    /// Device Configuration BAR 繧｢繝峨Ξ繧ｹ
    device_cfg_addr: usize,
    /// 繝・ヰ繧､繧ｹ繧ｿ繧､繝・
    device_type: VirtioDeviceType,
    /// MSI-X蟇ｾ蠢・
    msix_enabled: bool,
}

impl VirtioPciTransport {
    /// 譁ｰ縺励＞PCI繝医Λ繝ｳ繧ｹ繝昴・繝医ｒ菴懈・
    ///
    /// # Safety
    /// - 蜷ВAR繧｢繝峨Ξ繧ｹ縺ｯ譛牙柑縺ｪMMIO繧｢繝峨Ξ繧ｹ繧呈欠縺吝ｿ・・ｽ・ｽ縺後≠繧・
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
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ繧定ｪｭ縺ｿ蜿悶ｊ・ｽE・ｽE繝薙ャ繝茨ｼ・
    #[inline]
    fn read_common_u8(&self, offset: usize) -> u8 {
        unsafe {
            core::ptr::read_volatile((self.common_cfg_addr + offset) as *const u8)
        }
    }
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ繧定ｪｭ縺ｿ蜿悶ｊ・ｽE・ｽE6繝薙ャ繝茨ｼ・
    #[inline]
    fn read_common_u16(&self, offset: usize) -> u16 {
        unsafe {
            core::ptr::read_volatile((self.common_cfg_addr + offset) as *const u16)
        }
    }
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ繧定ｪｭ縺ｿ蜿悶ｊ・ｽE・ｽE2繝薙ャ繝茨ｼ・
    #[inline]
    fn read_common_u32(&self, offset: usize) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.common_cfg_addr + offset) as *const u32)
        }
    }
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ繧定ｪｭ縺ｿ蜿悶ｊ・ｽE・ｽE4繝薙ャ繝茨ｼ・
    #[inline]
    fn read_common_u64(&self, offset: usize) -> u64 {
        unsafe {
            core::ptr::read_volatile((self.common_cfg_addr + offset) as *const u64)
        }
    }
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ縺ｫ譖ｸ縺崎ｾｼ縺ｿ・ｽE・ｽE繝薙ャ繝茨ｼ・
    #[inline]
    fn write_common_u8(&self, offset: usize, value: u8) {
        unsafe {
            core::ptr::write_volatile((self.common_cfg_addr + offset) as *mut u8, value);
        }
    }
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ縺ｫ譖ｸ縺崎ｾｼ縺ｿ・ｽE・ｽE6繝薙ャ繝茨ｼ・
    #[inline]
    fn write_common_u16(&self, offset: usize, value: u16) {
        unsafe {
            core::ptr::write_volatile((self.common_cfg_addr + offset) as *mut u16, value);
        }
    }
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ縺ｫ譖ｸ縺崎ｾｼ縺ｿ・ｽE・ｽE2繝薙ャ繝茨ｼ・
    #[inline]
    fn write_common_u32(&self, offset: usize, value: u32) {
        unsafe {
            core::ptr::write_volatile((self.common_cfg_addr + offset) as *mut u32, value);
        }
    }
    
    /// Common Configuration 繝ｬ繧ｸ繧ｹ繧ｿ縺ｫ譖ｸ縺崎ｾｼ縺ｿ・ｽE・ｽE4繝薙ャ繝茨ｼ・
    #[inline]
    fn write_common_u64(&self, offset: usize, value: u64) {
        unsafe {
            core::ptr::write_volatile((self.common_cfg_addr + offset) as *mut u64, value);
        }
    }
    
    /// 繧ｭ繝･繝ｼ縺ｮ騾夂衍繧ｪ繝輔そ繝・・ｽ・ｽ繧貞叙蠕・
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
    
    fn notify_queue(&mut self, queue_index: u16) {
        // 繧ｭ繝･繝ｼ繧帝∈謚槭＠縺ｦ騾夂衍繧ｪ繝輔そ繝・・ｽ・ｽ繧貞叙蠕・
        self.write_common_u16(pci_common_cfg::QUEUE_SELECT, queue_index);
        let notify_off = self.get_queue_notify_offset() as usize;
        
        // 騾夂衍繧｢繝峨Ξ繧ｹ繧定ｨ育ｮ・
        let notify_addr = self.notify_addr + notify_off * self.notify_off_multiplier as usize;
        
        // 騾夂衍繧帝∽ｿ｡
        unsafe {
            core::ptr::write_volatile(notify_addr as *mut u16, queue_index);
        }
    }
    
    fn get_interrupt_status(&self) -> u32 {
        unsafe {
            core::ptr::read_volatile(self.isr_addr as *const u8) as u32
        }
    }
    
    fn ack_interrupt(&mut self, _status: u32) {
        // PCI transport縺ｧ縺ｯISR繧定ｪｭ繧縺縺代〒ACK縺ｫ縺ｪ繧・
        let _ = self.get_interrupt_status();
    }
    
    fn read_config_u8(&self, offset: usize) -> u8 {
        unsafe {
            core::ptr::read_volatile((self.device_cfg_addr + offset) as *const u8)
        }
    }
    
    fn read_config_u16(&self, offset: usize) -> u16 {
        unsafe {
            core::ptr::read_volatile((self.device_cfg_addr + offset) as *const u16)
        }
    }
    
    fn read_config_u32(&self, offset: usize) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.device_cfg_addr + offset) as *const u32)
        }
    }
    
    fn write_config_u8(&mut self, offset: usize, value: u8) {
        unsafe {
            core::ptr::write_volatile((self.device_cfg_addr + offset) as *mut u8, value);
        }
    }
    
    fn write_config_u16(&mut self, offset: usize, value: u16) {
        unsafe {
            core::ptr::write_volatile((self.device_cfg_addr + offset) as *mut u16, value);
        }
    }
    
    fn write_config_u32(&mut self, offset: usize, value: u32) {
        unsafe {
            core::ptr::write_volatile((self.device_cfg_addr + offset) as *mut u32, value);
        }
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
        
        // 險ｭ螳壹′謌仙粥縺励◆縺狗｢ｺ隱・
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

/// 繝・・ｽ・ｽ繧､繧ｹ蛻晄悄蛹厄ｿｽE繝ｫ繝托ｿｽE
pub struct VirtioDeviceInit<'a, T: VirtioTransport> {
    transport: &'a mut T,
}

impl<'a, T: VirtioTransport> VirtioDeviceInit<'a, T> {
    /// 譁ｰ縺励＞蛻晄悄蛹厄ｿｽE繝ｫ繝托ｿｽE繧剃ｽ懶ｿｽE
    pub fn new(transport: &'a mut T) -> Self {
        Self { transport }
    }
    
    /// 讓呎ｺ也噪縺ｪ蛻晄悄蛹悶す繝ｼ繧ｱ繝ｳ繧ｹ繧貞ｮ溯｡・
    pub fn initialize(&mut self, required_features: u64) -> TransportResult<u64> {
        // 1. 繝・・ｽ・ｽ繧､繧ｹ繧偵Μ繧ｻ繝・・ｽ・ｽ
        self.transport.reset();
        
        // 2. ACKNOWLEDGE 繧定ｨｭ螳・
        self.transport.set_status(status::VIRTIO_STATUS_ACKNOWLEDGE);
        
        // 3. DRIVER 繧定ｨｭ螳・
        let mut current_status = self.transport.get_status();
        current_status |= status::VIRTIO_STATUS_DRIVER;
        self.transport.set_status(current_status);
        
        // 4. 繝輔ぅ繝ｼ繝√Ε繝阪ざ繧ｷ繧ｨ繝ｼ繧ｷ繝ｧ繝ｳ
        let device_features = self.transport.get_device_features();
        let negotiated_features = device_features & required_features;
        self.transport.set_driver_features(negotiated_features);
        
        // 5. FEATURES_OK 繧定ｨｭ螳・
        current_status = self.transport.get_status();
        current_status |= status::VIRTIO_STATUS_FEATURES_OK;
        self.transport.set_status(current_status);
        
        // 6. FEATURES_OK 縺瑚ｨｭ螳壹＆繧後◆縺薙→繧堤｢ｺ隱・
        let status_check = self.transport.get_status();
        if (status_check & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.transport.set_status(status::VIRTIO_STATUS_FAILED);
            return Err(TransportError::FeatureNegotiationFailed);
        }
        
        Ok(negotiated_features)
    }
    
    /// DRIVER_OK 繧定ｨｭ螳壹＠縺ｦ繝・・ｽ・ｽ繧､繧ｹ繧剃ｽｿ逕ｨ蜿ｯ閭ｽ縺ｫ縺吶ｋ
    pub fn finish_init(&mut self) -> TransportResult<()> {
        let mut current_status = self.transport.get_status();
        current_status |= status::VIRTIO_STATUS_DRIVER_OK;
        self.transport.set_status(current_status);
        
        // 繝・・ｽ・ｽ繧､繧ｹ縺後お繝ｩ繝ｼ迥ｶ諷九〒縺ｪ縺・・ｽ・ｽ縺ｨ繧堤｢ｺ隱・
        let final_status = self.transport.get_status();
        if (final_status & status::VIRTIO_STATUS_FAILED) != 0 {
            return Err(TransportError::DeviceError);
        }
        
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    // 繝｢繝・・ｽ・ｽ繝医Λ繝ｳ繧ｹ繝晢ｿｽE繝・for testing
    struct MockTransport {
        status: u8,
        device_features: u64,
        driver_features: u64,
        queue_sizes: [u16; 8],
        selected_queue: u16,
    }
    
    impl MockTransport {
        fn new() -> Self {
            Self {
                status: 0,
                device_features: 0xFFFFFFFF,
                driver_features: 0,
                queue_sizes: [256; 8],
                selected_queue: 0,
            }
        }
    }
    
    impl VirtioTransport for MockTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Network
        }
        
        fn get_status(&self) -> u8 {
            self.status
        }
        
        fn set_status(&mut self, status: u8) {
            self.status = status;
        }
        
        fn get_device_features_low(&self) -> u32 {
            self.device_features as u32
        }
        
        fn get_device_features_high(&self) -> u32 {
            (self.device_features >> 32) as u32
        }
        
        fn set_driver_features_low(&mut self, features: u32) {
            self.driver_features = (self.driver_features & 0xFFFFFFFF00000000) | features as u64;
        }
        
        fn set_driver_features_high(&mut self, features: u32) {
            self.driver_features = (self.driver_features & 0x00000000FFFFFFFF) | ((features as u64) << 32);
        }
        
        fn get_num_queues(&self) -> u16 {
            8
        }
        
        fn select_queue(&mut self, queue_index: u16) {
            self.selected_queue = queue_index;
        }
        
        fn get_queue_max_size(&self) -> u16 {
            self.queue_sizes[self.selected_queue as usize]
        }
        
        fn set_queue_size(&mut self, size: u16) {
            self.queue_sizes[self.selected_queue as usize] = size;
        }
        
        fn is_queue_ready(&self) -> bool {
            false
        }
        
        fn enable_queue(&mut self) {}
        fn disable_queue(&mut self) {}
        fn set_queue_desc_addr(&mut self, _addr: u64) {}
        fn set_queue_avail_addr(&mut self, _addr: u64) {}
        fn set_queue_used_addr(&mut self, _addr: u64) {}
        fn notify_queue(&mut self, _queue_index: u16) {}
        fn get_interrupt_status(&self) -> u32 { 0 }
        fn ack_interrupt(&mut self, _status: u32) {}
        fn read_config_u8(&self, _offset: usize) -> u8 { 0 }
        fn read_config_u16(&self, _offset: usize) -> u16 { 0 }
        fn read_config_u32(&self, _offset: usize) -> u32 { 0 }
        fn write_config_u8(&mut self, _offset: usize, _value: u8) {}
        fn write_config_u16(&mut self, _offset: usize, _value: u16) {}
        fn write_config_u32(&mut self, _offset: usize, _value: u32) {}
        fn transport_type(&self) -> TransportType { TransportType::Mmio }
    }
    
    #[test]
    fn test_init_sequence() {
        let mut transport = MockTransport::new();
        let mut init = VirtioDeviceInit::new(&mut transport);
        
        let result = init.initialize(0xFFFF);
        assert!(result.is_ok());
        
        let negotiated = result.unwrap();
        assert_eq!(negotiated, 0xFFFF);
    }
}
