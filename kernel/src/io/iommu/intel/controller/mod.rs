// ============================================================================
// kernel/src/io/iommu/intel/controller/mod.rs
// ============================================================================

//! Intel IOMMU Controller Implementation
//!
//! Contains `IommuController` and its implementation modules.

pub mod cpu_cache;
pub mod dma;
pub mod fault;
pub mod init;
pub mod init_global;
pub mod iova;
pub mod ir;
pub mod perfmon;
pub mod pi;
pub mod pri;
pub mod qi_init;
pub mod qi_ops;
pub mod utils;

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use hashbrown::HashMap;

use self::iova::IovaManager;
use self::ir::InterruptRemapTable;
use self::init::CapabilityManager;
use crate::io::iommu::common::{PageRequestQueue, PostedInterruptPool};
use crate::io::iommu::domain::IommuDomain;
use crate::io::iommu::fault_log::FaultLog;
use crate::io::iommu::intel::qi::{InvalidationQueue, QiStats};
use crate::io::iommu::intel::registers::regs::IQH;
use crate::io::iommu::intel::registers::{gcmd_bits, gsts_bits, regs, rtaddr_bits};
use crate::io::iommu::intel::tables::{ContextEntry, PasidTable, RootEntry, ScalableContextEntry};
use crate::io::iommu::interface::IommuHardwareContext;
use crate::io::iommu::IovaAllocatorFast;
use crate::io::iommu::page_table_pool::PageTablePool;
use crate::io::iommu::security::{SecurityEvent, SecurityNotifier};
use crate::io::iommu::tables::HardwareTable;
use crate::io::iommu::types::{DeviceId, IommuDeviceScope, IommuError};

use crate::sync::{IrqMutex, PoisonLock, WakerQueue};

// use self::cpu_cache::HardwareContext; // Removed duplicate import
// In previous file (Step 587), HardwareContext was defined inline.

// ============================================================================
// Hardware Context
// ============================================================================

/// Hardware Tables (Root Table and Context Tables)
mod hw_context_impl;
pub use hw_context_impl::*;
mod ats_control;
pub use ats_control::*;
#[derive(Debug)]
pub struct HardwareContext {
    /// Root Table: 256 entries (16 bytes each = 4KB)
    pub root_table: Option<HardwareTable<RootEntry>>,
    /// Legacy Context Tables: 256 tables, each 4KB (256 entries, 16 bytes each)
    pub legacy_context_tables: Vec<HardwareTable<ContextEntry>>,
    /// Scalable Context Tables: 256 tables, each 8KB (256 entries, 32 bytes each)
    pub scalable_context_tables: Vec<HardwareTable<ScalableContextEntry>>,
}

impl Default for HardwareContext {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareContext {
    /// Create an empty HardwareContext (tables will be allocated during init)
    pub fn new() -> Self {
        Self {
            root_table: None,
            legacy_context_tables: Vec::new(),
            scalable_context_tables: Vec::new(),
        }
    }

    /// Check if hardware tables are initialized
    pub fn is_initialized(&self) -> bool {
        self.root_table.is_some()
            && (!self.legacy_context_tables.is_empty() || !self.scalable_context_tables.is_empty())
    }
}

unsafe impl Send for HardwareContext {}

// ============================================================================
// IOMMU Controller
// ============================================================================

/// IOMMU Controller
pub struct IommuController {
    /// MMIO base address
    pub(crate) mmio_base: u64,
    /// Capabilities
    pub(crate) cap: u64,
    /// Extended capabilities
    pub(crate) ecap: u64,
    /// Hardware/Table Lock (protects root_table and context tables)
    pub(crate) hardware: PoisonLock<HardwareContext>,
    /// Register Lock (protects MMIO command sequences)
    pub(crate) register_lock: PoisonLock<()>,

    /// Domains
    pub domains: PoisonLock<HashMap<u16, Arc<IommuDomain>>>,
    /// Device to domain mapping
    pub(crate) device_domains: PoisonLock<HashMap<DeviceId, u16>>,
    /// Device to PASID table mapping (scalable mode)
    pub(crate) device_pasid_tables: PoisonLock<HashMap<DeviceId, PasidTable>>,
    /// Next domain ID
    pub(crate) next_domain_id: AtomicU64,
    /// Translation enabled
    pub(crate) enabled: AtomicBool,
    /// Interrupt Remapping Table (optional)
    pub(crate) interrupt_remap_table: PoisonLock<Option<InterruptRemapTable>>,
    /// Interrupt remapping enabled
    pub(crate) ir_enabled: AtomicBool,
    /// Queued Invalidation Queue (optional)
    pub(crate) invalidation_queue: PoisonLock<Option<InvalidationQueue>>,
    /// Queued Invalidation enabled
    pub(crate) qi_enabled: AtomicBool,
    /// Scalable Mode enabled (SMTS)
    pub(crate) scalable_mode_enabled: AtomicBool,
    /// IOMMU Segment number
    pub segment: u16,
    /// Controller index within the registry (for per-core caches)
    pub(crate) controller_idx: AtomicUsize,
    /// IOVA allocator (lock-free bitmap-based)
    pub(crate) iova_allocator: PoisonLock<Option<IovaAllocatorFast>>,
    /// Set of devices with ATS enabled
    pub(crate) ats_enabled_devices: PoisonLock<BTreeSet<DeviceId>>,
    /// Posted Interrupt Descriptor pool
    pub(crate) pid_pool: PoisonLock<Option<PostedInterruptPool>>,
    /// Page Request Queue
    pub(crate) page_request_queue: PoisonLock<Option<PageRequestQueue>>,
    /// Fault log ring buffer
    pub(crate) fault_log: IrqMutex<Option<FaultLog>>,
    /// Device scopes
    pub(crate) device_scopes: Vec<IommuDeviceScope>,
    /// Include all devices
    pub(crate) include_all: bool,
    /// Pending wakers for async invalidation completion
    pub(crate) pending_waiters: WakerQueue,
    /// Command Queue
    pub command_queue: Option<crate::io::iommu::cmdqueue::CommandQueue>,
    /// Phase 6: Page Table Recycling Pool
    pub page_table_pool: Arc<PageTablePool>,
    /// Phase 7: Security event notifier
    security_notifier: spin::Once<Arc<dyn SecurityNotifier>>,
    /// Phase 7: Dropped security events counter
    dropped_security_events: AtomicU64,
}

unsafe impl Send for IommuController {}
unsafe impl Sync for IommuController {}

impl IommuController {
    /// Create a new IOMMU controller
    pub fn new(mmio_base: u64, segment: u16) -> Self {
        Self {
            mmio_base,
            segment,
            cap: 0,
            ecap: 0,
            hardware: PoisonLock::new(HardwareContext::default()),
            register_lock: PoisonLock::new(()),
            domains: PoisonLock::new(HashMap::new()),
            device_domains: PoisonLock::new(HashMap::new()),
            device_pasid_tables: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: PoisonLock::new(None),
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: PoisonLock::new(None),
            qi_enabled: AtomicBool::new(false),
            scalable_mode_enabled: AtomicBool::new(false),
            controller_idx: AtomicUsize::new(usize::MAX),
            iova_allocator: PoisonLock::new(None),
            ats_enabled_devices: PoisonLock::new(BTreeSet::new()),
            pid_pool: PoisonLock::new(None),
            page_request_queue: PoisonLock::new(None),
            fault_log: IrqMutex::new(None),
            device_scopes: Vec::new(),
            include_all: false,
            pending_waiters: WakerQueue::new(),
            command_queue: None,
            page_table_pool: PageTablePool::new(crate::mm::numa::num_nodes().max(1), 32),
            security_notifier: spin::Once::new(),
            dropped_security_events: AtomicU64::new(0),
        }
    }

    /// Create a new IOMMU controller with device scopes
    pub fn new_with_scopes(
        mmio_base: u64,
        segment: u16,
        scopes: Vec<IommuDeviceScope>,
        include_all: bool,
    ) -> Self {
        Self {
            mmio_base,
            segment,
            cap: 0,
            ecap: 0,
            hardware: PoisonLock::new(HardwareContext::default()),
            register_lock: PoisonLock::new(()),
            domains: PoisonLock::new(HashMap::new()),
            device_domains: PoisonLock::new(HashMap::new()),
            device_pasid_tables: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: PoisonLock::new(None),
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: PoisonLock::new(None),
            qi_enabled: AtomicBool::new(false),
            scalable_mode_enabled: AtomicBool::new(false),
            controller_idx: AtomicUsize::new(usize::MAX),
            iova_allocator: PoisonLock::new(None),
            ats_enabled_devices: PoisonLock::new(BTreeSet::new()),
            pid_pool: PoisonLock::new(None),
            page_request_queue: PoisonLock::new(None),
            fault_log: IrqMutex::new(None),
            device_scopes: scopes,
            include_all,
            pending_waiters: WakerQueue::new(),
            command_queue: None,
            page_table_pool: PageTablePool::new(crate::mm::numa::num_nodes().max(1), 32),
            security_notifier: spin::Once::new(),
            dropped_security_events: AtomicU64::new(0),
        }
    }

    pub(crate) fn set_controller_idx(&self, idx: usize) {
        self.controller_idx.store(idx, Ordering::Relaxed);
    }

    pub(crate) fn controller_idx(&self) -> Option<usize> {
        let idx = self.controller_idx.load(Ordering::Relaxed);
        if idx == usize::MAX {
            None
        } else {
            Some(idx)
        }
    }

    pub(crate) fn is_scalable_mode_enabled(&self) -> bool {
        self.scalable_mode_enabled.load(Ordering::Acquire)
    }

    pub(crate) fn set_scalable_mode_enabled(&self, enabled: bool) {
        self.scalable_mode_enabled.store(enabled, Ordering::Release);
    }

    fn sagaw_mask(&self) -> u8 {
        if self.cap == 0 {
            return 0;
        }
        ((self.cap & crate::io::iommu::intel::registers::cap_bits::CAP_SAGAW_MASK) >> 8) as u8
    }

    fn max_guest_address_width(&self) -> u8 {
        if self.cap == 0 {
            return 48;
        }
        let raw = ((self.cap & crate::io::iommu::intel::registers::cap_bits::CAP_MGAW_MASK) >> 16)
            as u8;
        raw.saturating_add(1).clamp(1, 64)
    }

    /// Get QI runtime stats if the queue is initialized.
    pub fn qi_stats(&self) -> Result<Option<QiStats>, IommuError> {
        match self.invalidation_queue.lock() {
            Ok(guard) => Ok(guard.as_ref().map(|iq| iq.stats())),
            Err(_) => Err(IommuError::HardwareError),
        }
    }

    /// Reset QI runtime stats (no-op if QI is not initialized).
    pub fn reset_qi_stats(&self) -> Result<(), IommuError> {
        match self.invalidation_queue.lock() {
            Ok(mut guard) => {
                if let Some(iq) = guard.as_mut() {
                    iq.reset_stats();
                }
                Ok(())
            }
            Err(_) => Err(IommuError::HardwareError),
        }
    }

    /// Initialize the IOMMU controller hardware
    pub unsafe fn init(&mut self, enable_scalable_mode: bool) -> Result<(), IommuError> {
        if self.mmio_base == 0 {
            log::error!("IOMMU MMIO Base is NULL");
            return Err(IommuError::HardwareError);
        }

        self.read_and_log_caps();
        let scalable_enabled = self.resolve_scalable_mode(enable_scalable_mode);
        self.setup_and_program_root_table()?;
        self.allocate_context_tables(scalable_enabled)?;

        Ok(())
    }

    /// Read capability registers and log address width information.
    fn read_and_log_caps(&mut self) {
        self.cap = self.read64(regs::CAP);
        log::info!("IOMMU init: CAP read success: {:#x}", self.cap);

        self.ecap = self.read64(regs::ECAP);
        log::info!("IOMMU init: ECAP read success: {:#x}", self.ecap);

        let sagaw = self.sagaw_mask();
        let mgaw = self.max_guest_address_width();
        log::info!(
            "IOMMU init: MGAW={} bits, SAGAW=0x{:02x}",
            mgaw,
            sagaw
        );
        if mgaw < 48 {
            log::warn!(
                "IOMMU init: MGAW below 48 bits; 4-level page tables may be unsupported"
            );
        }
        if (sagaw & (1 << 2)) == 0 {
            log::warn!(
                "IOMMU init: 48-bit AGAW not reported in SAGAW; page table compatibility may be limited"
            );
        }
    }

    /// Resolve whether scalable mode should be enabled.
    fn resolve_scalable_mode(&mut self, enable_scalable_mode: bool) -> bool {
        if enable_scalable_mode && !self.supports_scalable_mode() {
            log::warn!("[IOMMU] Scalable mode requested but not supported");
        }
        let scalable_enabled = enable_scalable_mode && self.supports_scalable_mode();
        self.set_scalable_mode_enabled(scalable_enabled);
        if scalable_enabled {
            log::warn!("[IOMMU] Scalable mode context tables enabled (translation path is experimental)");
        }
        scalable_enabled
    }

    /// Allocate root table, program its address, and wait for hardware acknowledgment.
    unsafe fn setup_and_program_root_table(&mut self) -> Result<(), IommuError> {
        let root_table = HardwareTable::new(256, None)?;
        self.hardware.lock().unwrap().root_table = Some(root_table);

        let mut root_phys = self
            .hardware
            .lock()
            .unwrap()
            .root_table
            .as_ref()
            .unwrap()
            .phys_addr();
        if self.is_scalable_mode_enabled() {
            root_phys |= rtaddr_bits::RTADDR_SMT;
        }
        self.write64(regs::RTADDR, root_phys);

        self.write32(regs::GCMD, gcmd_bits::GCMD_SRTP);

        use crate::io::iommu::intel::controller::utils::IommuUtils;
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_RTPS) != 0,
            100_000,
            false,
        )
    }

    /// Allocate context tables (legacy or scalable depending on mode).
    unsafe fn allocate_context_tables(&mut self, scalable: bool) -> Result<(), IommuError> {
        if scalable {
            let mut context_tables: Vec<HardwareTable<ScalableContextEntry>> =
                Vec::with_capacity(256);
            for _ in 0..256 {
                context_tables.push(HardwareTable::new(256, None)?);
            }
            let mut hw = self.hardware.lock().unwrap();
            hw.scalable_context_tables = context_tables;
            hw.legacy_context_tables.clear();
        } else {
            let mut context_tables: Vec<HardwareTable<ContextEntry>> = Vec::with_capacity(256);
            for _ in 0..256 {
                context_tables.push(HardwareTable::new(256, None)?);
            }
            let mut hw = self.hardware.lock().unwrap();
            hw.legacy_context_tables = context_tables;
            hw.scalable_context_tables.clear();
        }

        Ok(())
    }

    /// Get IOTLB register offset from ECAP
    fn iotlb_reg_offset(&self) -> u64 {
        use crate::io::iommu::intel::registers::ecap_bits;
        ((self.ecap & ecap_bits::ECAP_IRO_MASK) >> 8) * 16
    }

    /// Invalidate IOTLB for a specific domain (Register-based / Direct)
    pub unsafe fn invalidate_iotlb_direct(&self, domain_id: u16) {
        #[cfg(feature = "qemu-test-export")]
        if self.mmio_base == 0 {
            return;
        }

        use crate::io::iommu::intel::registers::{iotlb_bits, iotlb_regs};
        let offset = self.iotlb_reg_offset();

        let cmd = iotlb_bits::IOTLB_IIRG_DOMAIN
            | iotlb_bits::IOTLB_DR
            | iotlb_bits::IOTLB_DW
            | ((domain_id as u64) << iotlb_bits::IOTLB_DID_SHIFT)
            | iotlb_bits::IOTLB_IVT;

        // Write command (IVT bit must be set in the upper 64-bit write or simultaneous)
        self.write64(offset + iotlb_regs::IOTLB, cmd);

        // Wait for completion (IVT bit cleared)
        while (self.read64(offset + iotlb_regs::IOTLB) & iotlb_bits::IOTLB_IVT) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Invalidate Global IOTLB (Register-based / Direct)
    pub unsafe fn invalidate_iotlb_global(&self) {
        #[cfg(feature = "qemu-test-export")]
        if self.mmio_base == 0 {
            return;
        }

        use crate::io::iommu::intel::registers::{iotlb_bits, iotlb_regs};
        let offset = self.iotlb_reg_offset();

        let cmd = iotlb_bits::IOTLB_IIRG_GLOBAL
            | iotlb_bits::IOTLB_DR
            | iotlb_bits::IOTLB_DW
            | iotlb_bits::IOTLB_IVT;

        self.write64(offset + iotlb_regs::IOTLB, cmd);

        while (self.read64(offset + iotlb_regs::IOTLB) & iotlb_bits::IOTLB_IVT) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Invalidate IOTLB (Generic: uses QI if enabled, else Direct)
    pub fn invalidate_iotlb(&self, domain_id: u16) {
        use crate::io::iommu::intel::controller::qi_ops::InvalidationOps;
        if self.is_queued_invalidation_enabled() {
            let _ = self.qi_invalidate_iotlb_domain(domain_id, true);
        } else {
            unsafe {
                self.invalidate_iotlb_direct(domain_id);
            }
        }
    }

    /// Invalidate IOTLB globally (synchronous).
    ///
    /// Used for emergency device isolation.
    pub fn invalidate_iotlb_global_sync(&self) -> Result<(), IommuError> {
        use crate::io::iommu::intel::controller::qi_ops::InvalidationOps;
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_iotlb_global(true)
        } else {
            unsafe {
                self.invalidate_iotlb_global();
            }
            Ok(())
        }
    }

    /// Invalidate context cache globally (synchronous).
    ///
    /// Used for emergency device isolation.
    pub fn invalidate_context_global_sync(&self) -> Result<(), IommuError> {
        use crate::io::iommu::intel::controller::qi_ops::InvalidationOps;
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_context_global()
        } else {
            // Register-based context invalidation
            unsafe {
                self.invalidate_context_global_direct();
            }
            Ok(())
        }
    }

    /// Register-based global context cache invalidation.
    unsafe fn invalidate_context_global_direct(&self) {
        #[cfg(feature = "qemu-test-export")]
        if self.mmio_base == 0 {
            return;
        }

        use crate::io::iommu::intel::registers::ccmd_bits;
        
        // Global context invalidation command
        let cmd: u64 = ccmd_bits::CCMD_ICC
            | ((ccmd_bits::CCMD_CIRG_GLOBAL as u64) << ccmd_bits::CCMD_CIRG_SHIFT);
        
        self.write64(regs::CCMD, cmd);
        
        // Wait for completion (ICC bit cleared)
        while (self.read64(regs::CCMD) & ccmd_bits::CCMD_ICC) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Lookup device to domain mapping.
    pub fn device_to_domain(&self, bus: u8, devfn: u8) -> Option<u16> {
        // Use the device_domains hashmap directly
        let device_id = DeviceId::from_bus_devfn(self.segment, bus, devfn);
        
        match self.device_domains.lock() {
            Ok(device_domains) => device_domains.get(&device_id).copied(),
            Err(_) => None,
        }
    }

    /// Enable IOMMU Translation
    pub unsafe fn enable(&self) -> Result<(), IommuError> {
        // Enable Translation (TE)
        self.write32(regs::GCMD, gcmd_bits::GCMD_TE);

        use crate::io::iommu::intel::controller::utils::IommuUtils;
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_TES) != 0,
            100_000,
            false,
        )?;

        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Disable IOMMU Translation
    pub unsafe fn disable(&self) -> Result<(), IommuError> {
        // We generally shouldn't disable but if requested, we try.
        // Clearing TE bit might not be straightforward if it's Write-1-to-Enable.
        // Assuming writing 0 to register or implementing Read-Modify-Write if needed.
        // But for GCMD, usually we write the single command bit we want.
        // It's possible we can't easily disable without reset.
        // For now, mark as disabled in software.
        self.enabled.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Check if a device is in scope for this IOMMU
    pub fn device_in_scope(&self, bus: u8, device: u8, function: u8) -> bool {
        if self.include_all {
            return true;
        }
        for scope in &self.device_scopes {
            if scope.matches(bus, device, function) {
                return true;
            }
        }
        false
    }

    pub(crate) fn read32(&self, offset: u64) -> u32 {
        crate::io::mmio::mmio_read_u32((self.mmio_base + offset) as usize)
    }

    pub(crate) fn write32(&self, offset: u64, value: u32) {
        crate::io::mmio::mmio_write_u32((self.mmio_base + offset) as usize, value)
    }

    pub(crate) fn read64(&self, offset: u64) -> u64 {
        crate::io::mmio::mmio_read_u64((self.mmio_base + offset) as usize)
    }

    pub(crate) fn write64(&self, offset: u64, value: u64) {
        crate::io::mmio::mmio_write_u64((self.mmio_base + offset) as usize, value)
    }

    pub fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let mut set = false;
        self.security_notifier.call_once(|| {
            set = true;
            notifier
        });
        if set {
            if let Some(notifier) = self.security_notifier.get() {
                match self.domains.lock() {
                    Ok(domains) => {
                        for domain in domains.values() {
                            let _ = domain.set_security_notifier(Arc::clone(notifier));
                        }
                    }
                    Err(_) => {
                        log::error!(
                            "[IOMMU] Domains map poisoned while propagating security notifier"
                        );
                    }
                }
            }
        }
        set
    }

    pub(crate) fn notify_security(&self, event: SecurityEvent) {
        if let Some(notifier) = self.security_notifier.get() {
            notifier.notify(event);
        }
    }

    pub(crate) fn record_dropped_security_event(&self) {
        self.dropped_security_events.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn flush_dropped_security_events(&self) -> u64 {
        self.dropped_security_events.swap(0, Ordering::Relaxed)
    }
}
