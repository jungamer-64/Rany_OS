// ============================================================================
// src/io/iommu.rs - IOMMU (Intel VT-d) Support
// ============================================================================
//!
//! IOMMU サポート (Intel VT-d / AMD-Vi)
//!
//! ## 設計原則 (仕様書 7.2準拠)
//! - デバイスメモリアクセス制限
//! - DMA領域の保護
//! - デバイス分離
//!
//! ## Intel VT-d 主要機能
//! - DMA Remapping: デバイスDMAのアドレス変換
//! - Interrupt Remapping: 割り込みの仮想化
//! - Posted Interrupts: 効率的な割り込み配送

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

// ============================================================================
// Constants and Register Definitions
// ============================================================================

/// DMAR (DMA Remapping) register offsets
pub mod regs {
    /// Version register
    pub const VER: u64 = 0x00;
    /// Capabilities register
    pub const CAP: u64 = 0x08;
    /// Extended capabilities register
    pub const ECAP: u64 = 0x10;
    /// Global command register
    pub const GCMD: u64 = 0x18;
    /// Global status register
    pub const GSTS: u64 = 0x1C;
    /// Root table address register
    pub const RTADDR: u64 = 0x20;
    /// Context command register
    pub const CCMD: u64 = 0x28;
    /// Fault status register
    pub const FSTS: u64 = 0x34;
    /// Fault event control register
    pub const FECTL: u64 = 0x38;
    /// Fault event data register
    pub const FEDATA: u64 = 0x3C;
    /// Fault event address register
    pub const FEADDR: u64 = 0x40;
    /// Invalidation queue head register
    pub const IQH: u64 = 0x80;
    /// Invalidation queue tail register
    pub const IQT: u64 = 0x88;
    /// Invalidation queue address register
    pub const IQA: u64 = 0x90;
}

/// Global command bits
pub mod gcmd_bits {
    /// Translation enable
    pub const GCMD_TE: u32 = 1 << 31;
    /// Set root table pointer
    pub const GCMD_SRTP: u32 = 1 << 30;
    /// Set fault log
    pub const GCMD_SFL: u32 = 1 << 29;
    /// Enable advanced fault logging
    pub const GCMD_EAFL: u32 = 1 << 28;
    /// Write buffer flush
    pub const GCMD_WBF: u32 = 1 << 27;
    /// Queued invalidation enable
    pub const GCMD_QIE: u32 = 1 << 26;
    /// Interrupt remapping enable
    pub const GCMD_IRE: u32 = 1 << 25;
    /// Set interrupt remap table pointer
    pub const GCMD_SIRTP: u32 = 1 << 24;
    /// Compatibility format interrupt
    pub const GCMD_CFI: u32 = 1 << 23;
}

/// Global status bits
pub mod gsts_bits {
    /// Translation enable status
    pub const GSTS_TES: u32 = 1 << 31;
    /// Root table pointer status
    pub const GSTS_RTPS: u32 = 1 << 30;
    /// Fault log status
    pub const GSTS_FLS: u32 = 1 << 29;
    /// Advanced fault logging status
    pub const GSTS_AFLS: u32 = 1 << 28;
    /// Write buffer flush status
    pub const GSTS_WBFS: u32 = 1 << 27;
    /// Queued invalidation enable status
    pub const GSTS_QIES: u32 = 1 << 26;
    /// Interrupt remapping enable status
    pub const GSTS_IRES: u32 = 1 << 25;
    /// Interrupt remap table pointer status
    pub const GSTS_IRTPS: u32 = 1 << 24;
    /// Compatibility format interrupt status
    pub const GSTS_CFIS: u32 = 1 << 23;
}

/// Capability register bits
pub mod cap_bits {
    /// Required write-buffer flushing
    pub const CAP_RWBF: u64 = 1 << 4;
    /// Page-level memory introspection
    pub const CAP_PLMR: u64 = 1 << 5;
    /// Pass through support
    pub const CAP_PT: u64 = 1 << 6;
    /// Super-page support
    pub const CAP_SLLPS: u64 = 3 << 34;
    /// Page walk coherency
    pub const CAP_PWC: u64 = 1 << 38;
    /// Snoop control
    pub const CAP_SC: u64 = 1 << 7;
}

// ============================================================================
// Page Table Structures
// ============================================================================

/// Page table levels
pub const PT_LEVELS: usize = 4;

/// Page table entries per level (512 for 4KB pages)
pub const PT_ENTRIES: usize = 512;

/// Root table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct RootEntry {
    /// Lower 64 bits (context table pointer)
    pub lo: u64,
    /// Upper 64 bits (reserved)
    pub hi: u64,
}

impl RootEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Set context table pointer
    pub fn set_context_table(&mut self, addr: u64) {
        self.lo = (addr & !0xFFF) | 1; // Present bit
    }

    /// Get context table address
    pub fn context_table_addr(&self) -> u64 {
        self.lo & !0xFFF
    }
}

/// Context table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ContextEntry {
    /// Lower 64 bits
    pub lo: u64,
    /// Upper 64 bits
    pub hi: u64,
}

impl ContextEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Check if entry is fault disabled
    pub fn is_fault_disabled(&self) -> bool {
        (self.lo & 2) != 0
    }

    /// Set second level page table pointer
    pub fn set_sl_pt(&mut self, addr: u64, domain_id: u16, agaw: u8) {
        self.lo = (addr & !0xFFF) | 1; // Present
        self.hi = ((domain_id as u64) << 8) | ((agaw as u64) << 0);
    }

    /// Get second level page table address
    pub fn sl_pt_addr(&self) -> u64 {
        self.lo & !0xFFF
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.hi >> 8) & 0xFFFF) as u16
    }
}

/// Second level page table entry
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlPte(pub u64);

impl SlPte {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// Read permission
    pub const READ: u64 = 1 << 0;
    /// Write permission
    pub const WRITE: u64 = 1 << 1;
    /// Snoop behavior
    pub const SNOOP: u64 = 1 << 11;
    /// Transient mapping hint
    pub const TRANSIENT: u64 = 1 << 62;

    /// Create a new entry
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create a present entry with address and permissions
    pub fn mapping(phys_addr: u64, read: bool, write: bool) -> Self {
        let mut flags = Self::PRESENT;
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }
        Self((phys_addr & !0xFFF) | flags)
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }

    /// Get physical address
    pub fn phys_addr(&self) -> u64 {
        self.0 & !0xFFF
    }

    /// Check read permission
    pub fn can_read(&self) -> bool {
        (self.0 & Self::READ) != 0
    }

    /// Check write permission
    pub fn can_write(&self) -> bool {
        (self.0 & Self::WRITE) != 0
    }
}

// ============================================================================
// IOMMU Domain
// ============================================================================

/// IOMMU Domain (address space for devices)
pub struct IommuDomain {
    /// Domain ID
    id: u16,
    /// Second-level page table root
    page_table: *mut SlPte,
    /// Mapped regions
    mappings: BTreeMap<u64, DmaMapping>,
    /// Total mapped size
    mapped_size: u64,
}

/// DMA mapping info
#[derive(Clone, Debug)]
pub struct DmaMapping {
    /// I/O virtual address
    pub iova: u64,
    /// Physical address
    pub phys: u64,
    /// Size in bytes
    pub size: u64,
    /// Read permission
    pub read: bool,
    /// Write permission
    pub write: bool,
}

unsafe impl Send for IommuDomain {}
unsafe impl Sync for IommuDomain {}

impl IommuDomain {
    /// Create a new domain
    pub fn new(id: u16) -> Self {
        // Allocate page table
        // SAFETY: 4096アライメントと4096の倍数サイズは常に有効なレイアウト
        let layout = unsafe {
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .unwrap_unchecked()
        };

        let page_table = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut SlPte };

        Self {
            id,
            page_table,
            mappings: BTreeMap::new(),
            mapped_size: 0,
        }
    }

    /// Get domain ID
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Get page table physical address
    pub fn page_table_addr(&self) -> u64 {
        self.page_table as u64
    }

    /// Map a DMA region
    pub fn map(
        &mut self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        // Validate alignment
        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        // Check for overlapping mappings
        for (existing_iova, mapping) in &self.mappings {
            let existing_end = existing_iova + mapping.size;
            let new_end = iova + size;

            if iova < existing_end && new_end > *existing_iova {
                return Err(IommuError::AlreadyMapped);
            }
        }

        // Create page table entries
        let num_pages = size / 4096;
        for i in 0..num_pages {
            let page_iova = iova + i * 4096;
            let page_phys = phys + i * 4096;

            self.map_page(page_iova, page_phys, read, write)?;
        }

        // Record mapping
        self.mappings.insert(
            iova,
            DmaMapping {
                iova,
                phys,
                size,
                read,
                write,
            },
        );

        self.mapped_size += size;

        Ok(())
    }

    /// Map a single page (internal)
    fn map_page(
        &mut self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        // Simple single-level implementation for demonstration
        // Real implementation would use multi-level page tables

        let index = (iova >> 12) & 0x1FF;

        if index >= PT_ENTRIES as u64 {
            return Err(IommuError::InvalidAddress);
        }

        unsafe {
            let entry = self.page_table.add(index as usize);
            if (*entry).is_present() {
                return Err(IommuError::AlreadyMapped);
            }
            *entry = SlPte::mapping(phys, read, write);
        }

        Ok(())
    }

    /// Unmap a DMA region
    pub fn unmap(&mut self, iova: u64) -> Result<DmaMapping, IommuError> {
        let mapping = self.mappings.remove(&iova).ok_or(IommuError::NotMapped)?;

        // Clear page table entries
        let num_pages = mapping.size / 4096;
        for i in 0..num_pages {
            let page_iova = iova + i * 4096;
            self.unmap_page(page_iova)?;
        }

        self.mapped_size -= mapping.size;

        Ok(mapping)
    }

    /// Unmap a single page (internal)
    fn unmap_page(&mut self, iova: u64) -> Result<(), IommuError> {
        let index = (iova >> 12) & 0x1FF;

        if index >= PT_ENTRIES as u64 {
            return Err(IommuError::InvalidAddress);
        }

        unsafe {
            let entry = self.page_table.add(index as usize);
            *entry = SlPte::new();
        }

        Ok(())
    }

    /// Get total mapped size
    pub fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    /// Get all mappings
    pub fn mappings(&self) -> &BTreeMap<u64, DmaMapping> {
        &self.mappings
    }
}

impl Drop for IommuDomain {
    fn drop(&mut self) {
        if !self.page_table.is_null() {
            let layout = alloc::alloc::Layout::from_size_align(
                PT_ENTRIES * core::mem::size_of::<SlPte>(),
                4096,
            )
            .unwrap();

            unsafe {
                alloc::alloc::dealloc(self.page_table as *mut u8, layout);
            }
        }
    }
}

// ============================================================================
// IOMMU Controller
// ============================================================================

/// IOMMU error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    /// IOMMU not present
    NotPresent,
    /// Not supported
    NotSupported,
    /// Already initialized
    AlreadyInitialized,
    /// Invalid address
    InvalidAddress,
    /// Invalid alignment
    InvalidAlignment,
    /// Region already mapped
    AlreadyMapped,
    /// Region not mapped
    NotMapped,
    /// Domain not found
    DomainNotFound,
    /// Device not found
    DeviceNotFound,
    /// Hardware error
    HardwareError,
    /// Timeout
    Timeout,
}

/// Device identifier (BDF: Bus/Device/Function)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DeviceId {
    /// Segment number
    pub segment: u16,
    /// Bus number
    pub bus: u8,
    /// Device number
    pub device: u8,
    /// Function number
    pub function: u8,
}

impl DeviceId {
    /// Create a new device ID
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    /// Get requester ID (used for root/context table indexing)
    pub fn requester_id(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }
}

/// IOMMU Controller
pub struct IommuController {
    /// MMIO base address
    mmio_base: u64,
    /// Capabilities
    cap: u64,
    /// Extended capabilities
    ecap: u64,
    /// Root table
    root_table: *mut RootEntry,
    /// Context tables (per bus)
    context_tables: Vec<*mut ContextEntry>,
    /// Domains
    domains: BTreeMap<u16, IommuDomain>,
    /// Device to domain mapping
    device_domains: BTreeMap<DeviceId, u16>,
    /// Next domain ID
    next_domain_id: AtomicU64,
    /// Translation enabled
    enabled: AtomicBool,
}

unsafe impl Send for IommuController {}
unsafe impl Sync for IommuController {}

impl IommuController {
    /// Create a new IOMMU controller
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            cap: 0,
            ecap: 0,
            root_table: core::ptr::null_mut(),
            context_tables: Vec::new(),
            domains: BTreeMap::new(),
            device_domains: BTreeMap::new(),
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
        }
    }

    /// Read 32-bit register
    unsafe fn read32(&self, offset: u64) -> u32 { unsafe {
        let ptr = (self.mmio_base + offset) as *const u32;
        core::ptr::read_volatile(ptr)
    }}

    /// Write 32-bit register
    unsafe fn write32(&self, offset: u64, value: u32) { unsafe {
        let ptr = (self.mmio_base + offset) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }}

    /// Read 64-bit register
    unsafe fn read64(&self, offset: u64) -> u64 { unsafe {
        let ptr = (self.mmio_base + offset) as *const u64;
        core::ptr::read_volatile(ptr)
    }}

    /// Write 64-bit register
    unsafe fn write64(&self, offset: u64, value: u64) { unsafe {
        let ptr = (self.mmio_base + offset) as *mut u64;
        core::ptr::write_volatile(ptr, value);
    }}

    /// Initialize the IOMMU
    ///
    /// # Safety
    /// Caller must ensure MMIO address is valid
    pub unsafe fn init(&mut self) -> Result<(), IommuError> { unsafe {
        // Read capabilities
        self.cap = self.read64(regs::CAP);
        self.ecap = self.read64(regs::ECAP);

        // Allocate root table (4KB, 256 entries)
        // SAFETY: 4096 アライメントと4096サイズは常に有効
        let rt_layout = alloc::alloc::Layout::from_size_align(4096, 4096).unwrap_unchecked();
        self.root_table = alloc::alloc::alloc_zeroed(rt_layout) as *mut RootEntry;

        if self.root_table.is_null() {
            return Err(IommuError::HardwareError);
        }

        // Allocate context tables for all buses
        for _ in 0..256 {
            // SAFETY: 4096 アライメントと4096サイズは常に有効
            let ct_layout = alloc::alloc::Layout::from_size_align(4096, 4096).unwrap_unchecked();
            let ct = alloc::alloc::alloc_zeroed(ct_layout) as *mut ContextEntry;

            if ct.is_null() {
                return Err(IommuError::HardwareError);
            }

            self.context_tables.push(ct);
        }

        // Set root table address
        self.write64(regs::RTADDR, self.root_table as u64);

        // Set root table pointer
        self.write32(regs::GCMD, gcmd_bits::GCMD_SRTP);

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_RTPS != 0 {
                break;
            }
        }

        Ok(())
    }}

    /// Enable DMA remapping
    pub unsafe fn enable(&self) -> Result<(), IommuError> { unsafe {
        // Write buffer flush if required
        if self.cap & cap_bits::CAP_RWBF != 0 {
            self.write32(regs::GCMD, gcmd_bits::GCMD_WBF);

            for _ in 0..1000 {
                if self.read32(regs::GSTS) & gsts_bits::GSTS_WBFS == 0 {
                    break;
                }
            }
        }

        // Enable translation
        self.write32(regs::GCMD, gcmd_bits::GCMD_TE);

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_TES != 0 {
                self.enabled.store(true, Ordering::Release);
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
    }}

    /// Disable DMA remapping
    pub unsafe fn disable(&self) -> Result<(), IommuError> { unsafe {
        // Clear translation enable
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_TE);

        // Wait for completion
        for _ in 0..1000 {
            if self.read32(regs::GSTS) & gsts_bits::GSTS_TES == 0 {
                self.enabled.store(false, Ordering::Release);
                return Ok(());
            }
        }

        Err(IommuError::Timeout)
    }}

    /// Check if translation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Create a new domain
    pub fn create_domain(&mut self) -> Result<u16, IommuError> {
        let id = self.next_domain_id.fetch_add(1, Ordering::Relaxed) as u16;

        let domain = IommuDomain::new(id);
        self.domains.insert(id, domain);

        Ok(id)
    }

    /// Get a domain by ID
    pub fn domain(&self, id: u16) -> Option<&IommuDomain> {
        self.domains.get(&id)
    }

    /// Get a mutable domain by ID
    pub fn domain_mut(&mut self, id: u16) -> Option<&mut IommuDomain> {
        self.domains.get_mut(&id)
    }

    /// Attach a device to a domain
    pub fn attach_device(&mut self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        let domain = self
            .domains
            .get(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;

        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        // Setup root entry
        let root_entry = unsafe { &mut *self.root_table.add(bus) };
        if !root_entry.is_present() {
            root_entry.set_context_table(self.context_tables[bus] as u64);
        }

        // Setup context entry
        let context_entry = unsafe { &mut *self.context_tables[bus].add(devfn) };

        // 48-bit address width (AGAW = 2)
        context_entry.set_sl_pt(domain.page_table_addr(), domain.id(), 2);

        self.device_domains.insert(device, domain_id);

        Ok(())
    }

    /// Detach a device from its domain
    pub fn detach_device(&mut self, device: DeviceId) -> Result<(), IommuError> {
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        // Clear context entry
        let context_entry = unsafe { &mut *self.context_tables[bus].add(devfn) };

        *context_entry = ContextEntry::default();

        self.device_domains.remove(&device);

        Ok(())
    }

    /// Map DMA region for a device
    pub fn map_dma(
        &mut self,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let domain_id = self
            .device_domains
            .get(device)
            .copied()
            .ok_or(IommuError::DeviceNotFound)?;

        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;

        domain.map(iova, phys, size, read, write)
    }

    /// Unmap DMA region for a device
    pub fn unmap_dma(&mut self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let domain_id = self
            .device_domains
            .get(device)
            .copied()
            .ok_or(IommuError::DeviceNotFound)?;

        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;

        domain.unmap(iova)
    }

    /// Invalidate IOTLB for a domain
    pub unsafe fn invalidate_iotlb(&self, domain_id: u16) { unsafe {
        // Context command register invalidation
        let cmd: u64 = (1u64 << 63) |          // ICC (Invalidate context-cache)
                       (1u64 << 61) |          // Global invalidation
                       ((domain_id as u64) << 16);

        self.write64(regs::CCMD, cmd);

        // Wait for completion
        for _ in 0..1000 {
            if self.read64(regs::CCMD) & (1u64 << 63) == 0 {
                break;
            }
        }
    }}
}

// ============================================================================
// Global Instance
// ============================================================================

static IOMMU: Mutex<Option<IommuController>> = Mutex::new(None);

/// Initialize the global IOMMU
///
/// # Safety
/// Caller must ensure MMIO address is valid
pub unsafe fn init_iommu(mmio_base: u64) -> Result<(), IommuError> { unsafe {
    let mut controller = IommuController::new(mmio_base);
    controller.init()?;

    crate::log!("IOMMU initialized at 0x{:X}\n", mmio_base);

    *IOMMU.lock() = Some(controller);
    Ok(())
}}

/// Enable IOMMU translation
pub fn enable_iommu() -> Result<(), IommuError> {
    let guard = IOMMU.lock();
    let controller = guard.as_ref().ok_or(IommuError::NotPresent)?;

    unsafe { controller.enable() }
}

/// Disable IOMMU translation
pub fn disable_iommu() -> Result<(), IommuError> {
    let guard = IOMMU.lock();
    let controller = guard.as_ref().ok_or(IommuError::NotPresent)?;

    unsafe { controller.disable() }
}

/// Check if IOMMU is enabled
pub fn is_iommu_enabled() -> bool {
    IOMMU.lock().is_some()
}

/// Map a physical address range for DMA access
///
/// Returns the IOVA (I/O Virtual Address) that devices should use
pub fn map_for_dma(phys_addr: x86_64::PhysAddr, size: u64) -> Result<u64, IommuError> {
    let mut guard = IOMMU.lock();
    let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;

    // For simplicity, use identity mapping (IOVA == physical address)
    // In a more sophisticated implementation, this would allocate from an IOVA space
    let iova = phys_addr.as_u64();

    // Create a mapping in the default domain (domain 0)
    // This is a simplified implementation
    let domain = controller
        .domains
        .get_mut(&0)
        .ok_or(IommuError::DomainNotFound)?;

    domain.map(iova, phys_addr.as_u64(), size, true, true)?;

    Ok(iova)
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let mut guard = IOMMU.lock();
    let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;

    // Unmap from the default domain
    let domain = controller
        .domains
        .get_mut(&0)
        .ok_or(IommuError::DomainNotFound)?;

    domain.unmap(iova)?;
    Ok(())
}

/// Execute with IOMMU controller
pub fn with_iommu<F, R>(f: F) -> Result<R, IommuError>
where
    F: FnOnce(&mut IommuController) -> R,
{
    let mut guard = IOMMU.lock();
    let controller = guard.as_mut().ok_or(IommuError::NotPresent)?;
    Ok(f(controller))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id() {
        let dev = DeviceId::new(0, 0, 1, 0);
        assert_eq!(dev.requester_id(), 0x08); // bus=0, dev=1, func=0
    }

    #[test]
    fn test_sl_pte() {
        let pte = SlPte::mapping(0x1000, true, true);
        assert!(pte.is_present());
        assert!(pte.can_read());
        assert!(pte.can_write());
        assert_eq!(pte.phys_addr(), 0x1000);
    }

    #[test]
    fn test_iommu_domain() {
        let mut domain = IommuDomain::new(1);
        assert_eq!(domain.id(), 1);

        // Map a region
        let result = domain.map(0x1000, 0x2000, 0x1000, true, false);
        assert!(result.is_ok());

        // Try to map overlapping region
        let result = domain.map(0x1000, 0x3000, 0x1000, true, false);
        assert_eq!(result, Err(IommuError::AlreadyMapped));
    }
}
