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
//!
//! ## 【設計書 7.2】IOMMU必須化
//!
//! セキュリティ上の理由から、IOMMUの存在を起動時に必須とするオプションを提供。
//! `IOMMU_REQUIRED`が`true`の場合、IOMMU未検出でパニック。

#![allow(dead_code)]

// use crate::memory; // not used directly here; use `crate::mm::phys_to_virt` instead
use crate::sync::AtomicWaker;
use crate::sync::IrqMutex;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use hashbrown::HashMap;

// PCI helpers used when enabling ATS for devices
#[allow(unused_imports)]
use pci_driver::{
    AcsController, AtsController, DeviceId as PciDeviceId, PciDeviceInfo, PcieBdf, PcieConfig,
    PcieError, PcieExtManager, device_supports_acs, device_supports_ats, pcie_ext_config,
    pcie_ext_manager,
};

pub mod qi;
pub use self::qi::*;

pub mod tables;
pub use self::tables::*;

pub mod fault_log;
pub use self::fault_log::*;

pub mod iova_allocator;
pub use self::iova_allocator::*;

pub mod domain;
pub use self::domain::*;

// fault logic moved to controller/fault.rs
pub use self::controller::fault::*;

pub mod groups;
pub use self::groups::*;

pub mod types;
pub use self::types::*;

// pub mod ir; -> moved to controller
pub use self::controller::ir::*;

pub mod pasid;

pub mod dma_handle;
pub use self::dma_handle::*;

pub mod quarantine;
pub use self::quarantine::*;

pub mod page_table_pool;
pub use self::page_table_pool::{PageTablePool, PoolStats, PooledPt};

pub mod security;
pub use self::security::*;

pub mod registers;
pub use self::registers::*;

// pub mod iova; -> moved to controller
pub use self::controller::iova::*;

pub mod controller;
pub use self::controller::init_global::*;
use self::controller::qi_ops::InvalidationOps;
use self::controller::utils::IommuUtils;
pub use self::controller::*;
use self::cpu_cache::*;

pub mod ats;
pub use self::ats::*;

pub mod cache;
pub use self::cache::*;

pub mod config;
pub use self::config::*;

pub mod api;
pub use self::api::*;

pub mod registry;
// Explicit re-exports (avoid wildcard for API stability)
pub use self::registry::{IommuRegistry, get_iommu_registry, init_registry, is_iommu_enabled};

pub mod pci;
// Explicit re-exports for PCI integration (avoid wildcard for API stability)
#[cfg(not(test))]
pub use self::pci::{setup_iommu_for_all_pci_devices, setup_iommu_for_pci_device};

// DMAR parsing moved to `drivers::acpi::dmar` (see `drivers/acpi/src/dmar.rs`).
// This centralizes parsing logic and avoids duplication / circular dependencies.

// ============================================================================
// Configuration - IOMMU Requirement
// ============================================================================

/// 【設計書 7.2】IOMMUを起動時に必須とするかどうか
///
/// セキュリティ要件により、IOMMUがない環境では起動を拒否できる。
/// - `true`: IOMMU未検出時にパニック
/// - `false`: IOMMU未検出時も警告のみで続行
pub static IOMMU_REQUIRED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Fault Logging Rate Limiting
// ============================================================================
// Constant moved to controller/fault.rs

// API functions (set_iommu_required, is_iommu_required, enforce_iommu_requirement) are now in api.rs
// and re-exported via `pub use self::api::*;`

// ============================================================================

// Register definitions (regs, gcmd_bits, gsts_bits, cap_bits, ecap_bits) are now in registers.rs
// and re-exported via `pub use self::registers::*;`

// Interrupt Remapping types (InterruptRemapEntry, InterruptRemapTable, DeliveryMode)
// are now defined in ir.rs and re-exported via `pub use self::ir::*;`

// ============================================================================
// Queued Invalidation (QI) Structures
// ============================================================================

/// Invalidation Queue Entry (128 bits)
///
/// Intel VT-d Queued Invalidation provides:
/// - Asynchronous invalidation requests
/// - Batched invalidation for performance

// Context caching structures (ContextCache) are now defined in cache.rs
// and re-exported via `pub use self::cache::*;`

// ============================================================================
// IOMMU Controller
// ============================================================================

// ============================================================================
// Invalidation Waiter Future
// ============================================================================

/// Future for async invalidation completion
///
/// This future polls the hardware head register to check if all queued
/// invalidation descriptors have been processed. It yields control back
/// to the executor between polls, avoiding busy-waiting.
pub struct InvalidationWaiter<'a> {
    controller: &'a IommuController,
    /// Result of the submission phase: Ok(expected_tail) on success, Err(IommuError)
    /// if submission could not be performed (e.g. lock poisoned / not present).
    submit_result: Result<u64, IommuError>,
}

impl<'a> Future for InvalidationWaiter<'a> {
    type Output = Result<(), IommuError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // If submission failed earlier, return the error immediately
        match self.submit_result {
            Err(e) => return Poll::Ready(Err(e)),
            Ok(expected_tail) => {
                // Check if hardware has caught up
                let head = self.controller.read64(regs::IQH) >> 4;
                if head == expected_tail {
                    return Poll::Ready(Ok(()));
                }

                // Not ready yet - register waker and return Pending
                self.controller.pending_waiter.register(cx.waker());
                Poll::Pending
            }
        }
    }
}

// HardwareContext is now defined in controller.rs and re-exported via
// `pub use self::controller::*;`

/// IOMMU Controller
pub struct IommuController {
    /// MMIO base address
    pub(crate) mmio_base: u64,
    /// Capabilities
    pub(crate) cap: u64,
    /// Extended capabilities
    pub(crate) ecap: u64,
    /// Hardware/Table Lock (protects root_table and context_tables)
    /// This replaces the coarse-grained RwLock<IommuController>
    pub(crate) hardware: PoisonLock<HardwareContext>,
    /// Register Lock (protects MMIO command sequences)
    /// Prevents race conditions on multi-step register operations (e.g. IOTLB invalidation)
    pub(crate) register_lock: PoisonLock<()>,

    /// Domains (Arc<PoisonLock<IommuDomain>>) stored in a PoisonLock-protected map
    pub domains: PoisonLock<HashMap<u16, Arc<PoisonLock<IommuDomain>>>>,
    /// Device to domain mapping
    pub(crate) device_domains: PoisonLock<HashMap<DeviceId, u16>>,
    /// Next domain ID
    pub(crate) next_domain_id: AtomicU64,
    /// Translation enabled
    pub(crate) enabled: AtomicBool,
    /// Interrupt Remapping Table (optional, if supported)
    pub(crate) interrupt_remap_table: PoisonLock<Option<InterruptRemapTable>>,
    /// Interrupt remapping enabled
    pub(crate) ir_enabled: AtomicBool,
    /// Queued Invalidation Queue (optional, if supported)
    pub(crate) invalidation_queue: PoisonLock<Option<InvalidationQueue>>,
    /// Queued Invalidation enabled
    pub(crate) qi_enabled: AtomicBool,
    /// IOMMU Segment number (from ACPI DRHD)
    pub segment: u16,
    /// IOVA allocator (optional, configured via `init_iova`)
    pub(crate) iova_allocator: PoisonLock<Option<IovaAllocator>>,
    /// Set of devices with ATS enabled (for optimization)
    pub(crate) ats_enabled_devices: PoisonLock<BTreeSet<DeviceId>>,
    /// Posted Interrupt Descriptor pool (base address, allocation bitmap)
    /// Each PID is 64-byte aligned, pool can hold up to 256 PIDs
    pub(crate) pid_pool: PoisonLock<Option<PostedInterruptPool>>,
    /// Page Request Queue (PRI/ATS)
    pub(crate) page_request_queue: PoisonLock<Option<PageRequestQueue>>,
    /// Fault log ring buffer
    pub(crate) fault_log: IrqMutex<Option<FaultLog>>,
    /// Device scopes from DRHD (for proper device-to-IOMMU matching)
    pub(crate) device_scopes: Vec<IommuDeviceScope>,
    /// Include all devices (from DRHD INCLUDE_PCI_ALL flag)
    pub(crate) include_all: bool,
    /// Pending waker for async invalidation completion (ISR-safe)
    pub(crate) pending_waiter: AtomicWaker,
    /// Command Queue for offloading register sequences and serialized HW ops
    pub command_queue: Option<crate::io::iommu_cmdqueue::CommandQueue>,
    /// Phase 6: Page Table Recycling Pool (NUMA-aware)
    pub page_table_pool: Arc<PageTablePool>,
    /// Phase 7: Security event notifier (lockless, set once at init)
    security_notifier: spin::Once<Arc<dyn SecurityNotifier>>,
    /// Phase 7: Dropped security events counter (for overflow tracking)
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
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: PoisonLock::new(None),
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: PoisonLock::new(None),
            qi_enabled: AtomicBool::new(false),
            iova_allocator: PoisonLock::new(None),
            ats_enabled_devices: PoisonLock::new(BTreeSet::new()),
            pid_pool: PoisonLock::new(None),
            page_request_queue: PoisonLock::new(None),
            fault_log: IrqMutex::new(None),
            device_scopes: Vec::new(),
            include_all: false,
            pending_waiter: AtomicWaker::new(),
            command_queue: None,
            // Phase 6: Page Table Pool (default: 8 nodes, 32 tables per node)
            page_table_pool: PageTablePool::new(crate::mm::numa::num_nodes().max(1), 32),
            // Phase 7: Security notifier (set once at init)
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
            next_domain_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: PoisonLock::new(None),
            ir_enabled: AtomicBool::new(false),
            invalidation_queue: PoisonLock::new(None),
            qi_enabled: AtomicBool::new(false),
            iova_allocator: PoisonLock::new(None),
            ats_enabled_devices: PoisonLock::new(BTreeSet::new()),
            pid_pool: PoisonLock::new(None),
            page_request_queue: PoisonLock::new(None),
            fault_log: IrqMutex::new(None),
            device_scopes: scopes,
            include_all,
            pending_waiter: AtomicWaker::new(),
            command_queue: None,
            page_table_pool: PageTablePool::new(crate::mm::numa::num_nodes().max(1), 32),
            security_notifier: spin::Once::new(),
            dropped_security_events: AtomicU64::new(0),
        }
    }

    /// Check if a device is in scope for this IOMMU
    pub fn device_in_scope(&self, bus: u8, device: u8, function: u8) -> bool {
        // If include_all flag is set, this IOMMU handles all PCI devices in the segment
        if self.include_all {
            return true;
        }

        // Otherwise, check device scopes
        for scope in &self.device_scopes {
            if scope.matches(bus, device, function) {
                return true;
            }
        }

        false
    }

    /// Read 32-bit register
    pub(crate) fn read32(&self, offset: u64) -> u32 {
        crate::io::mmio::mmio_read_u32((self.mmio_base + offset) as usize)
    }

    /// Write 32-bit register
    pub(crate) fn write32(&self, offset: u64, value: u32) {
        crate::io::mmio::mmio_write_u32((self.mmio_base + offset) as usize, value);
    }

    /// Read 64-bit register
    pub(crate) fn read64(&self, offset: u64) -> u64 {
        crate::io::mmio::mmio_read_u64((self.mmio_base + offset) as usize)
    }

    /// Write 64-bit register
    pub(crate) fn write64(&self, offset: u64, value: u64) {
        crate::io::mmio::mmio_write_u64((self.mmio_base + offset) as usize, value);
    }

    // ========================================================================
    // Phase 7: Security Monitor Integration
    // ========================================================================

    /// Register a security notifier (one-time, lockless after init)
    ///
    /// Returns `true` if registration succeeded, `false` if already registered.
    ///
    /// # Thread Safety
    ///
    /// This method is safe to call from any context. The notifier is set
    /// exactly once via `spin::Once`, ensuring lock-free access thereafter.
    pub fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let mut set = false;
        self.security_notifier.call_once(|| {
            set = true;
            notifier
        });
        set
    }

    /// Send a security event to the registered notifier (if any)
    ///
    /// # Safety Contract
    ///
    /// This method is ISR-safe. It performs no locking and completes in
    /// bounded time. The notifier implementation MUST also be ISR-safe.
    pub(crate) fn notify_security(&self, event: SecurityEvent) {
        if let Some(notifier) = self.security_notifier.get() {
            notifier.notify(event);
        }
    }

    /// Record a dropped security event (for overflow tracking)
    ///
    /// Call this when the pending events buffer overflows to track lost events.
    pub(crate) fn record_dropped_security_event(&self) {
        self.dropped_security_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Report dropped security events if any, then reset counter
    ///
    /// Returns the number of events dropped since last report.
    pub(crate) fn flush_dropped_security_events(&self) -> u64 {
        self.dropped_security_events.swap(0, Ordering::Relaxed)
    }

    /// Add a device to the set of ATS-enabled devices
    pub fn enable_ats_for_device(&self, device: DeviceId) {
        match self.ats_enabled_devices.lock() {
            Ok(mut set) => {
                set.insert(device);
            }
            Err(_) => {
                // Runtime path: do NOT attempt best-effort recovery here. If the lock is
                // poisoned, the internal set may be inconsistent - skip the enable and
                // log an error.
                log::error!(
                    "[IOMMU] ats_enabled_devices lock poisoned - skipping enable for {:?}",
                    device
                );
            }
        }
    }

    /// Initialize the IOMMU
    ///
    /// # Safety
    /// Caller must ensure MMIO address is valid
    pub unsafe fn init(&mut self) -> Result<(), IommuError> {
        // Read capabilities
        self.cap = self.read64(regs::CAP);
        self.ecap = self.read64(regs::ECAP);

        // Initialize command queue to offload serialized hardware ops
        // Currently created unconditionally; make configurable later if desired
        self.command_queue = Some(crate::io::iommu_cmdqueue::CommandQueue::new());

        // Allocate root table with NUMA awareness
        // Root table: 256 RootEntry (16 bytes each = 4KB)
        let root_table = tables::HardwareTable::<RootEntry>::new(256, None)?;
        let root_phys = root_table.phys_addr();

        // Allocate context tables for all 256 buses
        // Each context table: 256 ContextEntry (16 bytes each = 4KB)
        let mut context_tables = Vec::with_capacity(256);
        for _ in 0..256 {
            let ctx_table = tables::HardwareTable::<ContextEntry>::new(256, None)?;
            context_tables.push(ctx_table);
        }

        // Initialize hardware context with type-safe tables
        {
            let mut hw = self
                .hardware
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            hw.root_table = Some(root_table);
            hw.context_tables = context_tables;
        }

        // Set root table address (use physical address from HardwareTable)
        self.write64(regs::RTADDR, root_phys);

        // Set root table pointer
        self.write32(regs::GCMD, gcmd_bits::GCMD_SRTP);

        // Wait for completion
        // Register: Global Status (GSTS)
        // Bit: RTPS (Root Table Pointer Status)
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_RTPS) != 0,
            10_000,
            false,
        )?;
        Ok(())
    }

    /// Enable DMA remapping
    pub unsafe fn enable(&self) -> Result<(), IommuError> {
        // Write buffer flush if required
        if self.cap & cap_bits::CAP_RWBF != 0 {
            self.write32(regs::GCMD, gcmd_bits::GCMD_WBF);

            self.wait_for_condition(
                || (self.read32(regs::GSTS) & gsts_bits::GSTS_WBFS) == 0,
                10_000,
                false,
            )?;
        }

        // Enable translation
        self.write32(regs::GCMD, gcmd_bits::GCMD_TE);

        // Enable Interrupt Remapping if table is present
        if let Ok(guard) = self.interrupt_remap_table.lock() {
            if guard.is_some() {
                match unsafe { self.enable_interrupt_remapping() } {
                    Ok(_) => {
                        log::info!("[IOMMU] Interrupt Remapping enabled during global enable\n")
                    }
                    Err(e) => log::warn!("[IOMMU] Failed to enable Interrupt Remapping: {:?}\n", e),
                }
            }
        } else {
            log::error!("[IOMMU] interrupt_remap_table lock poisoned while enabling");
        }

        // Wait for completion
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_TES) != 0,
            10_000,
            false,
        )?;

        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    /// Disable DMA remapping
    pub unsafe fn disable(&self) -> Result<(), IommuError> {
        // Clear translation enable
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_TE);

        // Wait for completion
        self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_TES) == 0,
            10_000,
            false,
        )?;

        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    /// Check if translation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    // =========================================================================
    // Domain & DMA Methods - MOVED TO controller/dma.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/dma.rs`:
    // - create_domain, set_domain_numa, get_domain_numa, domain
    // - attach_device, detach_device, get_domain_for_device
    // - map_dma, unmap_dma, unmap_dma_async

    /// Invalidate IOTLB for a domain
    pub unsafe fn invalidate_iotlb(&self, domain_id: u16) {
        // Use QI if enabled
        if self.is_queued_invalidation_enabled() {
            if let Err(e) = self.qi_invalidate_iotlb_domain(domain_id, true) {
                log::error!("[IOMMU] QI Domain Invalidation failed: {:?}", e);
            }
            // Wait for completion (sync)
            if let Err(e) = self.qi_wait_sync() {
                log::error!("[IOMMU] QI Wait failed: {:?}", e);
            }
            return;
        }

        // If a command_queue is present, prefer to offload the operation
        if let Some(ref cq) = self.command_queue {
            let _ = cq.submit_sync(
                crate::io::iommu_cmdqueue::IommuCommandKind::InvalidateIotlbDomain {
                    domain: domain_id,
                },
            );
            return;
        }

        // Context command register invalidation
        let cmd: u64 = (1u64 << 63) |          // ICC (Invalidate context-cache)
                       (1u64 << 61) |          // Global invalidation
                       ((domain_id as u64) << 16);

        {
            let _lock = self.register_lock.lock();
            self.write64(regs::CCMD, cmd);
            // Wait for completion (ICC bit 63 cleared)
            let _ = self.wait_for_condition(
                || (self.read64(regs::CCMD) & (1u64 << 63)) == 0,
                10_000,
                true,
            );
        }

        // Wait for completion (outside lock? no, this loop was redundant in original or for drain?)
        // The original code waited TWICE. The second wait seems redundant or is for the actual effect time?
        // But invalidation writes require checking the bit.
        // We'll trust the first wait inside the lock.
    }

    /// Invalidate IOTLB directly without offloading to a CommandQueue
    /// This variant is useful when called from a CQ worker to avoid
    /// deadlocks where the worker submitting an offload would wait for
    /// itself to process the request.
    pub unsafe fn invalidate_iotlb_direct(&self, domain_id: u16) {
        // Prefer QI when available
        if self.is_queued_invalidation_enabled() {
            if let Err(e) = self.qi_invalidate_iotlb_domain(domain_id, true) {
                log::error!("[IOMMU] QI Domain Invalidation failed: {:?}", e);
            }
            if let Err(e) = self.qi_wait_sync() {
                log::error!("[IOMMU] QI Wait failed: {:?}", e);
            }
            return;
        }

        // Fallback to Context command register invalidation (synchronous)
        let cmd: u64 = (1u64 << 63) | (1u64 << 61) | ((domain_id as u64) << 16);

        {
            let _lock = self.register_lock.lock();
            self.write64(regs::CCMD, cmd);
            // Wait for completion (ICC bit 63 cleared)
            let _ = self.wait_for_condition(
                || (self.read64(regs::CCMD) & (1u64 << 63)) == 0,
                10_000,
                true,
            );
        }
    }

    /// Invalidate IOTLB globally (all domains)
    pub unsafe fn invalidate_iotlb_global(&self) {
        // Use QI if enabled
        if self.is_queued_invalidation_enabled() {
            if let Err(e) = self.qi_invalidate_iotlb_global(true) {
                log::error!("[IOMMU] QI Global Invalidation failed: {:?}", e);
            }
            if let Err(e) = self.qi_wait_sync() {
                log::error!("[IOMMU] QI Wait failed: {:?}", e);
            }
            return;
        }

        // Get Invalidation Register Offset from CAP
        let iro = ((self.cap & cap_bits::CAP_IRO_MASK) >> 8) as u64;
        let iotlb_reg = self.mmio_base + (iro << 4) + iotlb_regs::IOTLB;

        // Global invalidation with drain
        let cmd: u64 = iotlb_bits::IOTLB_IVT
            | iotlb_bits::IOTLB_IIRG_GLOBAL
            | iotlb_bits::IOTLB_DR
            | iotlb_bits::IOTLB_DW;

        {
            let _lock = self.register_lock.lock();
            crate::io::mmio::mmio_write_u64(iotlb_reg as usize, cmd);

            // Wait for completion
            let _ = self.wait_for_condition(
                || {
                    (crate::io::mmio::mmio_read_u64(iotlb_reg as usize) & iotlb_bits::IOTLB_IVT)
                        == 0
                },
                10_000,
                false,
            );
        }
    }

    // handle_command_queue_entry moved to controller/dma.rs (DomainManager trait)
    // Fault handling methods (check_fault_status, etc.) moved to controller/fault.rs

    // =========================================================================
    // Capability Detection Methods - MOVED TO controller/init.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/init.rs`:
    // - supports_queued_invalidation, supports_interrupt_remapping
    // - supports_2mb_pages, supports_1gb_pages
    // - supports_posted_interrupts, supports_scalable_mode
    // - supports_performance_monitoring, supports_page_request
    // - capabilities

    // =========================================================================
    // Interrupt Remapping Methods
    // =========================================================================

    // =========================================================================
    // Interrupt Remapping Methods - MOVED TO controller/ir.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/ir.rs`:
    // - init_interrupt_remapping, enable_interrupt_remapping, disable_interrupt_remapping
    // - is_interrupt_remapping_enabled
    // - allocate_irte, free_irte, update_irte

    // =========================================================================
    // Fault Handling
    // =========================================================================

    // =========================================================================
    // Fault Handling Methods - MOVED TO controller/fault.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/fault.rs`:
    // - init_fault_handling
    // - process_faults
    // - recent_faults
    // - total_fault_count
    // - enable_fault_interrupt

    // =========================================================================
    // Posted Interrupts Methods - MOVED TO controller/pi.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/pi.rs`:
    // - init_posted_interrupts
    // - allocate_posted_irte, free_posted_irte
    // - post_interrupt

    // =========================================================================
    // Page Request Interface (PRI) Methods - MOVED TO controller/pri.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/pri.rs`:
    // - init_page_request
    // - process_page_requests
    // - send_page_response

    // =========================================================================
    // IOVA Management Methods - MOVED TO controller/iova.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/iova.rs`:
    // - init_iova
    // - allocate_iova_fast, free_iova_fast
    // - allocate_iova, allocate_iova_aligned, free_iova
    // - init_iova_range, allocate_global_iova, free_global_iova
    // - map_for_dma_alloc, unmap_dma_alloc

    // =========================================================================
    // Queued Invalidation Methods
    // =========================================================================

    // =========================================================================
    // Queued Invalidation Initialization - MOVED TO controller/qi_init.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/qi_init.rs`:
    // - init_queued_invalidation
    // - enable_queued_invalidation
    // - disable_queued_invalidation

    // [Moved to controller/qi_ops.rs]
    // - is_queued_invalidation_enabled
    // - submit_invalidation
    // - qi_invalidate_iotlb_global, qi_invalidate_iotlb_domain, qi_invalidate_iotlb_page
    // - qi_invalidate_context_global, qi_invalidate_iec_global
    // - qi_invalidate_device_tlb, qi_invalidate_device_tlb_page
    // - qi_wait_sync, qi_wait_async
    // - wake_invalidation_waiter

    // =========================================================================
    // Performance Monitoring Methods - MOVED TO controller/perfmon.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/perfmon.rs`:
    // - perfmon_configure_counter
    // - perfmon_read_counter
    // - perfmon_reset_counter
    // - perfmon_reset_all
    // - perfmon_read_all

    // =========================================================================
    // Legacy Helpers - MOVED TO controller/utils.rs
    // =========================================================================
    //
    // The following methods have been extracted to `controller/utils.rs`:
    // - wait_for_condition
}

// IommuCapabilities is now defined in controller.rs and re-exported via
// `pub use self::controller::*;`

// ============================================================================
// IOVA Allocator types are now defined in iova.rs and re-exported via
// `pub use self::iova::*;`
// ============================================================================

// Global functions moved to api.rs and controller/init_global.rs

// Global API functions moved to api.rs:
// map_for_dma, unmap_dma, map_for_device, unmap_for_device, with_iommu
// handle_fault, wake_invalidation_waiters

// Method process_fault_security removed (unused/legacy)

// PCI setup functions (setup_iommu_for_pci_device, setup_iommu_for_all_pci_devices) are now in api.rs

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;

// Global Interrupt Remapping Interface functions (map_interrupt, get_remap_msi_message) are now in api.rs
