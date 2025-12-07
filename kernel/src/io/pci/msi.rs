// ============================================================================
// src/io/pci/msi.rs - MSI and MSI-X Support
// ============================================================================
//!
//! # MSI/MSI-X サポート
//!
//! Message Signaled Interrupts (MSI) および MSI-X の実装。
//! 従来の INTx ピン割り込みより効率的な割り込み配送を提供。
//!
//! ## 機能
//! - MSI 設定・有効化
//! - MSI-X テーブル管理
//! - ベクトル割り当て

#![allow(dead_code)]

use alloc::vec::Vec;
use spin::Mutex;

use super::bus::{PciDeviceInfo, config_regs, command_bits};
use super::traits::ConfigSpaceAccessor;
use super::types::BdfAddress;

// ============================================================================
// Constants
// ============================================================================

/// MSI capability ID
pub const MSI_CAP_ID: u8 = 0x05;
/// MSI-X capability ID
pub const MSIX_CAP_ID: u8 = 0x11;

/// MSI message address base (for x2APIC)
const MSI_ADDRESS_BASE: u64 = 0xFEE00000;

/// MSI message control register bits
const MSI_CTRL_ENABLE: u16 = 0x0001;
const MSI_CTRL_64BIT: u16 = 0x0080;
const MSI_CTRL_PER_VECTOR_MASK: u16 = 0x0100;

/// MSI-X message control register bits
const MSIX_CTRL_ENABLE: u16 = 0x8000;
const MSIX_CTRL_FUNCTION_MASK: u16 = 0x4000;
const MSIX_TABLE_SIZE_MASK: u16 = 0x07FF;

// ============================================================================
// Delivery and Trigger Modes
// ============================================================================

/// Delivery mode for MSI messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Fixed delivery
    Fixed = 0,
    /// Lowest priority
    LowestPriority = 1,
    /// SMI
    Smi = 2,
    /// NMI
    Nmi = 4,
    /// INIT
    Init = 5,
    /// External interrupt
    ExtInt = 7,
}

/// Trigger mode for MSI messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TriggerMode {
    /// Edge triggered
    Edge = 0,
    /// Level triggered
    Level = 1,
}

// ============================================================================
// MSI Configuration
// ============================================================================

/// MSI configuration
#[derive(Debug, Clone, Copy)]
pub struct MsiConfig {
    /// Target CPU APIC ID
    pub apic_id: u8,
    /// Interrupt vector
    pub vector: u8,
    /// Delivery mode
    pub delivery_mode: DeliveryMode,
    /// Trigger mode
    pub trigger_mode: TriggerMode,
}

impl MsiConfig {
    /// Create a new MSI configuration
    pub fn new(apic_id: u8, vector: u8) -> Self {
        MsiConfig {
            apic_id,
            vector,
            delivery_mode: DeliveryMode::Fixed,
            trigger_mode: TriggerMode::Edge,
        }
    }

    /// Build the MSI message address
    pub fn message_address(&self) -> u64 {
        MSI_ADDRESS_BASE | ((self.apic_id as u64) << 12)
    }

    /// Build the MSI message data
    pub fn message_data(&self) -> u32 {
        let mut data = self.vector as u32;
        data |= (self.delivery_mode as u32) << 8;
        if self.trigger_mode == TriggerMode::Level {
            data |= 1 << 15; // Level trigger
            data |= 1 << 14; // Assert
        }
        data
    }
}

// ============================================================================
// MSI Capability
// ============================================================================

/// MSI capability structure
#[derive(Debug, Clone)]
pub struct MsiCapability {
    /// BDF address
    bdf: BdfAddress,
    /// Capability offset
    cap_offset: u8,
    /// Supports 64-bit addressing
    supports_64bit: bool,
    /// Supports per-vector masking
    supports_masking: bool,
    /// Number of vectors (1, 2, 4, 8, 16, or 32)
    max_vectors: u8,
}

impl MsiCapability {
    /// Probe for MSI capability using ConfigSpaceAccessor
    pub fn probe<A: ConfigSpaceAccessor>(accessor: &A, device: &PciDeviceInfo) -> Option<Self> {
        let cap_offset = device.msi_cap_offset?;

        let message_control = accessor.read16(device.bdf, cap_offset as u16 + 2);
        let supports_64bit = (message_control & MSI_CTRL_64BIT) != 0;
        let supports_masking = (message_control & MSI_CTRL_PER_VECTOR_MASK) != 0;
        let max_vectors = 1 << ((message_control >> 1) & 0x7);

        Some(MsiCapability {
            bdf: device.bdf,
            cap_offset,
            supports_64bit,
            supports_masking,
            max_vectors,
        })
    }

    /// Enable MSI with single vector
    pub fn enable<A: ConfigSpaceAccessor>(&self, accessor: &A, config: &MsiConfig) {
        let address = config.message_address();
        let data = config.message_data();

        // Write message address (low)
        accessor.write32(self.bdf, self.cap_offset as u16 + 4, address as u32);

        if self.supports_64bit {
            // Write message address (high)
            accessor.write32(self.bdf, self.cap_offset as u16 + 8, (address >> 32) as u32);
            // Write message data
            accessor.write32(self.bdf, self.cap_offset as u16 + 12, data);
        } else {
            // Write message data
            accessor.write32(self.bdf, self.cap_offset as u16 + 8, data);
        }

        // Enable MSI
        let mut message_control = accessor.read16(self.bdf, self.cap_offset as u16 + 2);
        message_control |= MSI_CTRL_ENABLE;
        // Request only 1 vector
        message_control &= !0x70;

        let dword = accessor.read32(self.bdf, self.cap_offset as u16);
        accessor.write32(
            self.bdf,
            self.cap_offset as u16,
            (dword & 0x0000FFFF) | ((message_control as u32) << 16),
        );
    }

    /// Disable MSI
    pub fn disable<A: ConfigSpaceAccessor>(&self, accessor: &A) {
        let mut message_control = accessor.read16(self.bdf, self.cap_offset as u16 + 2);
        message_control &= !MSI_CTRL_ENABLE;

        let dword = accessor.read32(self.bdf, self.cap_offset as u16);
        accessor.write32(
            self.bdf,
            self.cap_offset as u16,
            (dword & 0x0000FFFF) | ((message_control as u32) << 16),
        );
    }

    /// Check if MSI is enabled
    pub fn is_enabled<A: ConfigSpaceAccessor>(&self, accessor: &A) -> bool {
        let message_control = accessor.read16(self.bdf, self.cap_offset as u16 + 2);
        (message_control & MSI_CTRL_ENABLE) != 0
    }

    /// Mask a vector (if supported)
    pub fn mask_vector<A: ConfigSpaceAccessor>(&self, accessor: &A, vector: u8) {
        if !self.supports_masking {
            return;
        }

        let mask_offset = if self.supports_64bit {
            self.cap_offset as u16 + 16
        } else {
            self.cap_offset as u16 + 12
        };

        let mask = accessor.read32(self.bdf, mask_offset);
        accessor.write32(self.bdf, mask_offset, mask | (1u32 << vector));
    }

    /// Unmask a vector (if supported)
    pub fn unmask_vector<A: ConfigSpaceAccessor>(&self, accessor: &A, vector: u8) {
        if !self.supports_masking {
            return;
        }

        let mask_offset = if self.supports_64bit {
            self.cap_offset as u16 + 16
        } else {
            self.cap_offset as u16 + 12
        };

        let mask = accessor.read32(self.bdf, mask_offset);
        accessor.write32(self.bdf, mask_offset, mask & !(1u32 << vector));
    }

    /// Get maximum supported vectors
    pub fn max_vectors(&self) -> u8 {
        self.max_vectors
    }

    /// Check if 64-bit addressing is supported
    pub fn supports_64bit(&self) -> bool {
        self.supports_64bit
    }

    /// Check if per-vector masking is supported
    pub fn supports_masking(&self) -> bool {
        self.supports_masking
    }
}

// ============================================================================
// MSI-X Table Entry
// ============================================================================

/// MSI-X table entry
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MsixTableEntry {
    /// Message address (lower 32 bits)
    pub msg_addr_lo: u32,
    /// Message address (upper 32 bits)
    pub msg_addr_hi: u32,
    /// Message data
    pub msg_data: u32,
    /// Vector control (bit 0 = masked)
    pub vector_ctrl: u32,
}

impl MsixTableEntry {
    /// Configure this entry
    pub fn configure(&mut self, config: &MsiConfig) {
        let address = config.message_address();
        self.msg_addr_lo = address as u32;
        self.msg_addr_hi = (address >> 32) as u32;
        self.msg_data = config.message_data();
    }

    /// Mask this entry
    pub fn mask(&mut self) {
        self.vector_ctrl |= 1;
    }

    /// Unmask this entry
    pub fn unmask(&mut self) {
        self.vector_ctrl &= !1;
    }

    /// Check if masked
    pub fn is_masked(&self) -> bool {
        (self.vector_ctrl & 1) != 0
    }
}

// ============================================================================
// MSI-X Capability
// ============================================================================

/// MSI-X capability structure
#[derive(Debug, Clone)]
pub struct MsixCapability {
    /// BDF address
    bdf: BdfAddress,
    /// Capability offset
    cap_offset: u8,
    /// Number of table entries
    table_size: u16,
    /// Table BAR index
    table_bir: u8,
    /// Table offset within BAR
    table_offset: u32,
    /// PBA BAR index
    pba_bir: u8,
    /// PBA offset within BAR
    pba_offset: u32,
}

impl MsixCapability {
    /// Probe for MSI-X capability using ConfigSpaceAccessor
    pub fn probe<A: ConfigSpaceAccessor>(accessor: &A, device: &PciDeviceInfo) -> Option<Self> {
        let cap_offset = device.msix_cap_offset?;

        let message_control = accessor.read16(device.bdf, cap_offset as u16 + 2);
        let table_size = (message_control & MSIX_TABLE_SIZE_MASK) + 1;

        let table_info = accessor.read32(device.bdf, cap_offset as u16 + 4);
        let table_bir = (table_info & 0x7) as u8;
        let table_offset = table_info & !0x7;

        let pba_info = accessor.read32(device.bdf, cap_offset as u16 + 8);
        let pba_bir = (pba_info & 0x7) as u8;
        let pba_offset = pba_info & !0x7;

        Some(MsixCapability {
            bdf: device.bdf,
            cap_offset,
            table_size,
            table_bir,
            table_offset,
            pba_bir,
            pba_offset,
        })
    }

    /// Get number of vectors
    pub fn table_size(&self) -> u16 {
        self.table_size
    }

    /// Get table BAR index
    pub fn table_bar(&self) -> u8 {
        self.table_bir
    }

    /// Get table offset
    pub fn table_offset(&self) -> u32 {
        self.table_offset
    }

    /// Get PBA BAR index
    pub fn pba_bar(&self) -> u8 {
        self.pba_bir
    }

    /// Get PBA offset
    pub fn pba_offset(&self) -> u32 {
        self.pba_offset
    }

    /// Enable MSI-X (but mask all vectors initially)
    pub fn enable<A: ConfigSpaceAccessor>(&self, accessor: &A) {
        let mut message_control = accessor.read16(self.bdf, self.cap_offset as u16 + 2);
        // Enable MSI-X with function mask set
        message_control |= MSIX_CTRL_ENABLE | MSIX_CTRL_FUNCTION_MASK;

        let dword = accessor.read32(self.bdf, self.cap_offset as u16);
        accessor.write32(
            self.bdf,
            self.cap_offset as u16,
            (dword & 0x0000FFFF) | ((message_control as u32) << 16),
        );
    }

    /// Clear function mask (allow interrupts)
    pub fn clear_function_mask<A: ConfigSpaceAccessor>(&self, accessor: &A) {
        let mut message_control = accessor.read16(self.bdf, self.cap_offset as u16 + 2);
        message_control &= !MSIX_CTRL_FUNCTION_MASK;

        let dword = accessor.read32(self.bdf, self.cap_offset as u16);
        accessor.write32(
            self.bdf,
            self.cap_offset as u16,
            (dword & 0x0000FFFF) | ((message_control as u32) << 16),
        );
    }

    /// Disable MSI-X
    pub fn disable<A: ConfigSpaceAccessor>(&self, accessor: &A) {
        let mut message_control = accessor.read16(self.bdf, self.cap_offset as u16 + 2);
        message_control &= !MSIX_CTRL_ENABLE;

        let dword = accessor.read32(self.bdf, self.cap_offset as u16);
        accessor.write32(
            self.bdf,
            self.cap_offset as u16,
            (dword & 0x0000FFFF) | ((message_control as u32) << 16),
        );
    }

    /// Check if MSI-X is enabled
    pub fn is_enabled<A: ConfigSpaceAccessor>(&self, accessor: &A) -> bool {
        let message_control = accessor.read16(self.bdf, self.cap_offset as u16 + 2);
        (message_control & MSIX_CTRL_ENABLE) != 0
    }

    /// Configure a vector in the MSI-X table
    ///
    /// # Safety
    /// The table_base must be a valid mapped address for the MSI-X table
    pub unsafe fn configure_vector(
        &self,
        table_base: *mut MsixTableEntry,
        vector: u16,
        config: &MsiConfig,
    ) {
        if vector >= self.table_size {
            return;
        }

        unsafe {
            let entry = &mut *table_base.add(vector as usize);
            entry.configure(config);
        }
    }

    /// Mask a vector
    ///
    /// # Safety
    /// The table_base must be a valid mapped address
    pub unsafe fn mask_vector(&self, table_base: *mut MsixTableEntry, vector: u16) {
        if vector >= self.table_size {
            return;
        }

        unsafe {
            let entry = &mut *table_base.add(vector as usize);
            entry.mask();
        }
    }

    /// Unmask a vector
    ///
    /// # Safety
    /// The table_base must be a valid mapped address
    pub unsafe fn unmask_vector(&self, table_base: *mut MsixTableEntry, vector: u16) {
        if vector >= self.table_size {
            return;
        }

        unsafe {
            let entry = &mut *table_base.add(vector as usize);
            entry.unmask();
        }
    }
}

// ============================================================================
// Interrupt Vector Allocator
// ============================================================================

/// Interrupt allocation state
struct InterruptAllocator {
    /// Next available vector
    next_vector: u8,
    /// Allocated vectors: (BDF, vector)
    allocated: Vec<(BdfAddress, u8)>,
}

impl InterruptAllocator {
    const fn new() -> Self {
        InterruptAllocator {
            // Start allocating from vector 32 (after exceptions and PIC IRQs)
            next_vector: 32,
            allocated: Vec::new(),
        }
    }

    fn allocate(&mut self, bdf: BdfAddress) -> Option<u8> {
        if self.next_vector >= 224 {
            // Reserve 224-255 for system use
            return None;
        }

        let vector = self.next_vector;
        self.next_vector += 1;
        self.allocated.push((bdf, vector));
        Some(vector)
    }

    fn allocate_range(&mut self, bdf: BdfAddress, count: u8) -> Option<u8> {
        if self.next_vector.saturating_add(count) >= 224 {
            return None;
        }

        let base = self.next_vector;
        for i in 0..count {
            self.allocated.push((bdf, base + i));
        }
        self.next_vector += count;
        Some(base)
    }
}

static INTERRUPT_ALLOCATOR: Mutex<InterruptAllocator> = Mutex::new(InterruptAllocator::new());

/// Allocate an interrupt vector for a device
pub fn allocate_vector(bdf: BdfAddress) -> Option<u8> {
    INTERRUPT_ALLOCATOR.lock().allocate(bdf)
}

/// Allocate multiple contiguous interrupt vectors
pub fn allocate_vectors(bdf: BdfAddress, count: u8) -> Option<u8> {
    INTERRUPT_ALLOCATOR.lock().allocate_range(bdf, count)
}

// ============================================================================
// High-Level Setup Functions
// ============================================================================

/// Set up MSI for a device
pub fn setup_msi<A: ConfigSpaceAccessor>(
    accessor: &A,
    device: &PciDeviceInfo,
    apic_id: u8,
) -> Option<u8> {
    let msi = MsiCapability::probe(accessor, device)?;
    let vector = allocate_vector(device.bdf)?;

    let config = MsiConfig::new(apic_id, vector);
    msi.enable(accessor, &config);

    // Disable legacy interrupt
    disable_intx(accessor, device);

    Some(vector)
}

/// Set up MSI-X for a device
/// Returns (capability, base_vector) if successful
pub fn setup_msix<A: ConfigSpaceAccessor>(
    accessor: &A,
    device: &PciDeviceInfo,
    num_vectors: u16,
) -> Option<(MsixCapability, u8)> {
    let msix = MsixCapability::probe(accessor, device)?;
    let actual_count = num_vectors.min(msix.table_size);
    let base_vector = allocate_vectors(device.bdf, actual_count as u8)?;

    // Enable MSI-X (vectors will be configured separately)
    msix.enable(accessor);

    // Disable legacy interrupt
    disable_intx(accessor, device);

    Some((msix, base_vector))
}

/// Disable legacy INTx interrupts for a device
pub fn disable_intx<A: ConfigSpaceAccessor>(accessor: &A, device: &PciDeviceInfo) {
    let command = accessor.read16(device.bdf, config_regs::COMMAND);
    accessor.write16(device.bdf, config_regs::COMMAND, command | command_bits::INTERRUPT_DISABLE);
}

/// Enable legacy INTx interrupts for a device
pub fn enable_intx<A: ConfigSpaceAccessor>(accessor: &A, device: &PciDeviceInfo) {
    let command = accessor.read16(device.bdf, config_regs::COMMAND);
    accessor.write16(device.bdf, config_regs::COMMAND, command & !command_bits::INTERRUPT_DISABLE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msi_config() {
        let config = MsiConfig::new(0, 33);

        assert_eq!(config.message_address(), 0xFEE00000);
        assert_eq!(config.message_data(), 33);
    }

    #[test]
    fn test_delivery_mode() {
        assert_eq!(DeliveryMode::Fixed as u32, 0);
        assert_eq!(DeliveryMode::LowestPriority as u32, 1);
    }
}
