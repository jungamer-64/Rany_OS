// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/mod.rs
// ============================================================================

//! Intel IOMMU Controller Implementation
//!
//! Contains `IommuController` and its implementation modules.

pub mod dma;
pub mod fault;
pub mod init;
pub mod init_global;
pub mod invalidation;
pub mod iova;
pub mod ir;
pub mod qi_init;
pub mod qi_ops;
mod scope;
pub mod utils;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use hashbrown::HashMap;

use self::init::CapabilityManager;
use self::iova::IovaManager;
use self::ir::InterruptRemapTable;
use self::utils::IommuUtils;
use crate::io::iommu::common::dma::iova_allocator::IovaAllocator;
use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::common::interface::IommuHardwareContext;
use crate::io::iommu::common::tables::HardwareTable;
use crate::io::iommu::runtime::command::queue::CommandQueue;
use crate::io::iommu::runtime::fault_log::FaultLog;
use crate::io::iommu::runtime::security::{SecurityEvent, SecurityNotifier};
use crate::io::iommu::types::{DeviceId, IommuDeviceScope, IommuError};
use crate::io::iommu::vendors::intel::qi::{InvalidationQueue, QiStats};
use crate::io::iommu::vendors::intel::registers::{fsts_bits, gcmd_bits, gsts_bits, rtaddr_bits};
use crate::io::iommu::vendors::intel::tables::{
    ContextEntry, PasidTable, RootEntry, ScalableContextEntry,
};

use crate::sync::{IrqMutex, PoisonLock, WakerQueue};

// ============================================================================
// Hardware Context
// ============================================================================

/// Hardware Tables (Root Table and Context Tables)
mod hw_context_impl;
pub use hw_context_impl::*;
mod ats;
use ats::AtsDevice;
pub(crate) use ats::AtsEnableError;
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
}

unsafe impl Send for HardwareContext {}

// ============================================================================
// IOMMU Controller
// ============================================================================

/// IOMMU Controller
pub struct IommuController {
    /// Retains the firmware register aperture through IRQs and deferred work.
    registers: super::registers::RegisterBlock,
    direct_commands: PoisonLock<()>,
    controls: PoisonLock<()>,
    initialization: crate::sync::InitOnce<Result<(), IommuError>>,
    /// Capabilities
    pub(crate) cap: u64,
    /// Extended capabilities
    pub(crate) ecap: u64,
    /// Selected adjusted guest address width code (AGAW, 0..=3)
    selected_agaw_code: u8,
    /// Selected adjusted guest address width in bits (30/39/48/57)
    selected_addr_bits: u8,
    /// Selected second-level page table levels (2..=5)
    selected_levels: u8,
    /// Hardware/Table Lock (protects root_table and context tables)
    pub(crate) hardware: PoisonLock<HardwareContext>,
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
    /// Whether IRTE destination IDs are interpreted as full-width x2APIC IDs.
    pub(crate) ir_extended_mode: AtomicBool,
    /// Queued Invalidation Queue (optional)
    pub(crate) invalidation_queue: PoisonLock<Option<InvalidationQueue>>,
    /// Queued Invalidation enabled
    pub(crate) qi_enabled: AtomicBool,
    /// Scalable Mode enabled (SMTS)
    pub(crate) scalable_mode_enabled: AtomicBool,
    /// IOMMU Segment number
    pub segment: u16,
    /// IOVA allocator (lock-free bitmap-based)
    pub(crate) iova_allocator: PoisonLock<Option<Arc<IovaAllocator>>>,
    /// PCI ATS resources remain owned through uncertain enable/disable/flush outcomes.
    ats_devices: PoisonLock<BTreeMap<DeviceId, AtsDevice>>,
    /// Fault log ring buffer
    pub(crate) fault_log: IrqMutex<Option<FaultLog>>,
    fault_events: fault::DeferredFaultQueue,
    /// Device scopes
    pub(crate) device_scopes: Vec<IommuDeviceScope>,
    scope_resources: Vec<Arc<crate::drivers::pci::resource::FunctionResources>>,
    /// Include all devices
    pub(crate) include_all: bool,
    /// Pending wakers for async invalidation completion
    pub(crate) pending_waiters: WakerQueue,
    /// Command Queue
    pub(crate) command_queue: crate::sync::InitOnce<CommandQueue>,
    /// Runtime services activated for this controller
    runtime_services_started: AtomicBool,
    /// Phase 6: Page Table Recycling Pool
    pub page_table_pool: Arc<PageTablePool>,
    /// Phase 7: Security event notifier
    security_notifier: crate::sync::InitOnce<Arc<dyn SecurityNotifier>>,
}

impl IommuController {
    /// Create a new IOMMU controller
    pub fn new(registers: hal::MappedMmio, segment: u16) -> Result<Self, IommuError> {
        let registers =
            super::registers::RegisterBlock::new(registers).map_err(IommuError::RegisterAccess)?;
        if registers.global_status().read()
            & (gsts_bits::GSTS_TES | gsts_bits::GSTS_QIES | gsts_bits::GSTS_IRES)
            != 0
        {
            // Existing firmware hardware references have no ownership transfer
            // contract here. Reject admission before publishing our table addresses.
            return Err(IommuError::InUse);
        }
        let cap = registers.capabilities().read();
        let ecap = registers.extended_capabilities().read();
        let (selected_agaw_code, selected_addr_bits, selected_levels) =
            Self::select_agaw(((cap >> 8) & 0x1f) as u8, ((cap >> 16) & 0x3f) as u8 + 1)?;
        Ok(Self {
            registers,
            direct_commands: PoisonLock::new(()),
            controls: PoisonLock::new(()),
            initialization: crate::sync::InitOnce::new(),
            segment,
            cap,
            ecap,
            selected_agaw_code,
            selected_addr_bits,
            selected_levels,
            hardware: PoisonLock::new(HardwareContext::default()),
            domains: PoisonLock::new(HashMap::new()),
            device_domains: PoisonLock::new(HashMap::new()),
            device_pasid_tables: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            interrupt_remap_table: PoisonLock::new(None),
            ir_enabled: AtomicBool::new(false),
            ir_extended_mode: AtomicBool::new(false),
            invalidation_queue: PoisonLock::new(None),
            qi_enabled: AtomicBool::new(false),
            scalable_mode_enabled: AtomicBool::new(false),
            iova_allocator: PoisonLock::new(None),
            ats_devices: PoisonLock::new(BTreeMap::new()),
            fault_log: IrqMutex::new(None),
            fault_events: fault::DeferredFaultQueue::new(),
            device_scopes: Vec::new(),
            scope_resources: Vec::new(),
            include_all: false,
            pending_waiters: WakerQueue::new(),
            command_queue: crate::sync::InitOnce::new(),
            runtime_services_started: AtomicBool::new(false),
            page_table_pool: PageTablePool::new(crate::mm::numa::topology::num_nodes().max(1), 32),
            security_notifier: crate::sync::InitOnce::new(),
        })
    }

    pub(crate) fn command_queue_ref(&self) -> Option<&CommandQueue> {
        self.command_queue.get()
    }

    pub(crate) fn ensure_command_queue(&self) -> Result<&CommandQueue, IommuError> {
        self.command_queue.try_call_once(|| CommandQueue::new(None))
    }

    pub(crate) fn runtime_services_started(&self) -> bool {
        self.runtime_services_started.load(Ordering::Acquire)
    }

    pub(crate) fn mark_runtime_services_started(&self) {
        self.runtime_services_started.store(true, Ordering::Release);
    }

    pub(crate) fn is_scalable_mode_enabled(&self) -> bool {
        self.scalable_mode_enabled.load(Ordering::Acquire)
    }

    /// Check if IOMMU translation is enabled on this controller
    pub fn is_translation_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(crate) fn set_scalable_mode_enabled(&self, enabled: bool) {
        self.scalable_mode_enabled.store(enabled, Ordering::Release);
    }

    fn sagaw_mask(&self) -> u8 {
        if self.cap == 0 {
            return 0;
        }
        ((self.cap & crate::io::iommu::vendors::intel::registers::cap_bits::CAP_SAGAW_MASK) >> 8)
            as u8
    }

    /// Get the maximum Address Mask (AM) supported by the hardware (bits 53:48 of CAP).
    fn cap_am(&self) -> u8 {
        if self.cap == 0 {
            return 0;
        }
        ((self.cap & crate::io::iommu::vendors::intel::registers::cap_bits::CAP_AM_MASK) >> 48)
            as u8
    }

    fn max_guest_address_width(&self) -> u8 {
        if self.cap == 0 {
            return 48;
        }
        let raw = ((self.cap
            & crate::io::iommu::vendors::intel::registers::cap_bits::CAP_MGAW_MASK)
            >> 16) as u8;
        raw.saturating_add(1).clamp(1, 64)
    }

    #[inline]
    pub(crate) fn selected_agaw_code(&self) -> u8 {
        self.selected_agaw_code
    }

    #[inline]
    pub(crate) fn selected_addr_bits(&self) -> u8 {
        self.selected_addr_bits
    }

    #[inline]
    pub(crate) fn selected_levels(&self) -> u8 {
        self.selected_levels
    }

    #[inline]
    fn agaw_code_to_addr_bits(code: u8) -> u8 {
        30 + code.saturating_mul(9)
    }

    pub(crate) fn select_agaw(sagaw: u8, mgaw: u8) -> Result<(u8, u8, u8), IommuError> {
        let mut selected: Option<(u8, u8, u8)> = None;
        for code in 0u8..=3 {
            if (sagaw & (1 << code)) == 0 {
                continue;
            }
            let addr_bits = Self::agaw_code_to_addr_bits(code);
            if addr_bits > mgaw {
                continue;
            }
            let levels = code + 2;
            selected = Some((code, addr_bits, levels));
        }
        selected.ok_or(IommuError::NotSupported)
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

    /// Initializes hardware whose backing this controller owns.
    ///
    /// # Safety
    /// Retain the controller through every published hardware reference, including
    /// timeout/error. Reclamation requires observed hardware quiescence; returning
    /// to the scheduler or requesting shutdown does not provide that observation.
    pub unsafe fn init(&self, enable_scalable_mode: bool) -> Result<(), IommuError> {
        // Cache failure as well as success: hardware may have accepted a pointer
        // before a timeout. Retrying must never replace that retained backing.
        *self
            .initialization
            .call_once(|| unsafe { self.initialize_hardware(enable_scalable_mode) })
    }

    unsafe fn initialize_hardware(&self, enable_scalable_mode: bool) -> Result<(), IommuError> {
        // Clear any pending faults
        self.registers
            .fault_status()
            .write(fsts_bits::FSTS_IQE | fsts_bits::FSTS_ICE | fsts_bits::FSTS_ITE);

        self.log_caps();
        let scalable_enabled = self.resolve_scalable_mode(enable_scalable_mode);
        unsafe {
            self.allocate_context_tables(scalable_enabled)?;
            self.setup_and_program_root_table()?;
        }

        Ok(())
    }

    fn log_caps(&self) {
        log::info!(
            "IOMMU: CAP={:#x}, ECAP={:#x}, AGAW={} ({} bits, {} levels)",
            self.cap,
            self.ecap,
            self.selected_agaw_code,
            self.selected_addr_bits,
            self.selected_levels
        );
    }

    /// Resolve whether scalable mode should be enabled.
    fn resolve_scalable_mode(&self, enable_scalable_mode: bool) -> bool {
        if enable_scalable_mode && !self.supports_scalable_mode() {
            log::warn!("[IOMMU] Scalable mode requested but not supported");
        }
        let scalable_enabled = enable_scalable_mode && self.supports_scalable_mode();
        self.set_scalable_mode_enabled(scalable_enabled);
        if scalable_enabled {
            log::warn!(
                "[IOMMU] Scalable mode context tables enabled (translation path is experimental)"
            );
        }
        scalable_enabled
    }

    /// Allocate root table, program its address, and wait for hardware acknowledgment.
    unsafe fn setup_and_program_root_table(&self) -> Result<(), IommuError> {
        let root_phys = {
            let mut hw = self.hardware.lock().map_err(|_| IommuError::Poisoned)?;
            let root_table = HardwareTable::new(256, None)?;
            hw.root_table = Some(root_table);

            let mut root_phys = hw
                .root_table
                .as_ref()
                .expect("root table assigned before programming")
                .phys_addr();
            if self.is_scalable_mode_enabled() {
                root_phys |= rtaddr_bits::RTADDR_SMT;
            }
            root_phys
        };
        let _control = self.controls.lock().map_err(|_| IommuError::Poisoned)?;
        self.registers.root_table_address().write(root_phys);

        self.write_gcmd_with_state(gcmd_bits::GCMD_SRTP);

        use crate::io::iommu::vendors::intel::controller::utils::IommuUtils;
        self.wait_for_condition(
            || (self.registers.global_status().read() & gsts_bits::GSTS_RTPS) != 0,
            100_000,
            false,
        )
    }

    /// Allocate context tables (legacy or scalable depending on mode).
    unsafe fn allocate_context_tables(&self, scalable: bool) -> Result<(), IommuError> {
        let mut hw = self.hardware.lock().map_err(|_| IommuError::Poisoned)?;
        if scalable {
            let mut context_tables: Vec<HardwareTable<ScalableContextEntry>> = Vec::new();
            context_tables
                .try_reserve_exact(256)
                .map_err(|_| IommuError::MetadataAllocation)?;
            // LOOP_PROOF: mode=bounded; reason=Each of the 256 PCI bus context tables is prepared before root-table publication.;
            for _ in 0..256 {
                context_tables.push(HardwareTable::new(256, None)?);
            }
            hw.scalable_context_tables = context_tables;
            hw.legacy_context_tables.clear();
        } else {
            let mut context_tables: Vec<HardwareTable<ContextEntry>> = Vec::new();
            context_tables
                .try_reserve_exact(256)
                .map_err(|_| IommuError::MetadataAllocation)?;
            // LOOP_PROOF: mode=bounded; reason=Each of the 256 PCI bus context tables is prepared before root-table publication.;
            for _ in 0..256 {
                context_tables.push(HardwareTable::new(256, None)?);
            }
            hw.legacy_context_tables = context_tables;
            hw.scalable_context_tables.clear();
        }

        Ok(())
    }

    /// Invalidate IOTLB for a specific domain (Register-based / Direct)
    pub unsafe fn invalidate_iotlb_direct(&self, domain_id: u16) -> Result<(), IommuError> {
        use crate::io::iommu::vendors::intel::registers::iotlb_bits;

        let cmd = iotlb_bits::IOTLB_IIRG_DOMAIN
            | iotlb_bits::IOTLB_DR
            | iotlb_bits::IOTLB_DW
            | ((domain_id as u64) << iotlb_bits::IOTLB_DID_SHIFT)
            | iotlb_bits::IOTLB_IVT;

        let _command = self
            .direct_commands
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        self.wait_for_condition(
            || self.registers.iotlb_command().read() & iotlb_bits::IOTLB_IVT == 0,
            100_000,
            false,
        )?;
        self.registers.iotlb_command().write(cmd);
        self.wait_for_condition(
            || self.registers.iotlb_command().read() & iotlb_bits::IOTLB_IVT == 0,
            100_000,
            false,
        )
    }

    /// Invalidate Global IOTLB (Register-based / Direct)
    unsafe fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        use crate::io::iommu::vendors::intel::registers::iotlb_bits;

        let cmd = iotlb_bits::IOTLB_IIRG_GLOBAL
            | iotlb_bits::IOTLB_DR
            | iotlb_bits::IOTLB_DW
            | iotlb_bits::IOTLB_IVT;

        let _command = self
            .direct_commands
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        self.wait_for_condition(
            || self.registers.iotlb_command().read() & iotlb_bits::IOTLB_IVT == 0,
            100_000,
            false,
        )?;
        self.registers.iotlb_command().write(cmd);

        self.wait_for_condition(
            || (self.registers.iotlb_command().read() & iotlb_bits::IOTLB_IVT) == 0,
            100_000,
            true,
        )
    }

    /// Invalidate IOTLB (Generic: uses QI if enabled, else Direct)
    pub fn invalidate_iotlb(&self, domain_id: u16, any_ats: bool) -> Result<(), IommuError> {
        self.invalidate_domain(domain_id, any_ats)
    }

    /// Invalidate IOTLB globally (synchronous).
    ///
    /// Used for emergency device isolation.
    ///
    /// # Errors
    /// Missing registers, command/ATS failures, poisoned ownership, or retirement
    /// exhaustion leave pending IOVAs quarantined. Submission is not completion.
    #[deny(unsafe_code)]
    pub fn invalidate_iotlb_global_sync(&self) -> Result<(), IommuError> {
        use crate::io::iommu::vendors::intel::controller::qi_ops::InvalidationOps;

        let flush = self.begin_iova_global_flush()?;
        self.invalidate_global_nosync()?;
        if self.is_queued_invalidation_enabled() {
            self.qi_wait_sync()?;
        }
        if let Some(flush) = flush {
            // SAFETY: the global path invalidates IOTLB and every enabled ATS
            // device, then observes hardware completion before releasing IOVAs.
            #[expect(unsafe_code, reason = "global IOTLB/ATS completion was observed above")]
            unsafe {
                flush.complete_after_global_invalidation()
            };
        }
        Ok(())
    }

    /// Invalidate context cache globally (synchronous).
    ///
    /// Used for emergency device isolation.
    pub fn invalidate_context_global_sync(&self) -> Result<(), IommuError> {
        use crate::io::iommu::vendors::intel::controller::qi_ops::InvalidationOps;

        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_context_global()?;
            self.qi_wait_sync()?;
        } else {
            // Register-based context invalidation
            unsafe {
                self.invalidate_context_global_direct()?;
            }
        }
        // Context-cache completion does not invalidate cached IOVA translations.
        Ok(())
    }

    /// Register-based global context cache invalidation.
    unsafe fn invalidate_context_global_direct(&self) -> Result<(), IommuError> {
        use crate::io::iommu::vendors::intel::registers::ccmd_bits;

        // Global context invalidation command
        let cmd: u64 = ccmd_bits::CCMD_ICC
            | ((ccmd_bits::CCMD_CIRG_GLOBAL as u64) << ccmd_bits::CCMD_CIRG_SHIFT);

        let _command = self
            .direct_commands
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        self.wait_for_condition(
            || self.registers.context_command().read() & ccmd_bits::CCMD_ICC == 0,
            100_000,
            false,
        )?;
        self.registers.context_command().write(cmd);
        self.wait_for_condition(
            || self.registers.context_command().read() & ccmd_bits::CCMD_ICC == 0,
            100_000,
            false,
        )
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
        let _control = self.controls.lock().map_err(|_| IommuError::Poisoned)?;
        if self.enabled.load(Ordering::Acquire) {
            return Ok(());
        }
        // Enable Translation (TE) while preserving already-enabled control bits.
        self.write_gcmd_with_state(gcmd_bits::GCMD_TE);

        use crate::io::iommu::vendors::intel::controller::utils::IommuUtils;
        self.wait_for_condition(
            || (self.registers.global_status().read() & gsts_bits::GSTS_TES) != 0,
            100_000,
            false,
        )?;

        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Disable translation only after hardware acknowledges the GCMD transition.
    /// A timeout retains the controller and its enabled ownership state.
    pub unsafe fn disable(&self) -> Result<(), IommuError> {
        let _control = self.controls.lock().map_err(|_| IommuError::Poisoned)?;
        self.registers
            .global_command()
            .write(self.gcmd_enabled_mask() & !gcmd_bits::GCMD_TE);
        self.wait_for_condition(
            || self.registers.global_status().read() & gsts_bits::GSTS_TES == 0,
            100_000,
            false,
        )?;
        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    /// Check if a device is in scope for this IOMMU
    pub fn device_in_scope(&self, bus: u8, device: u8, function: u8) -> bool {
        if self.include_all {
            return true;
        }
        for scope in &self.device_scopes {
            if scope.matches(DeviceId::new(self.segment, bus, device, function)) {
                return true;
            }
        }
        false
    }

    #[inline]
    pub(crate) fn gcmd_enabled_mask(&self) -> u32 {
        let mut mask = 0u32;
        if self.qi_enabled.load(Ordering::Acquire) {
            mask |= gcmd_bits::GCMD_QIE;
        }
        if self.ir_enabled.load(Ordering::Acquire) {
            mask |= gcmd_bits::GCMD_IRE;
        }
        if self.enabled.load(Ordering::Acquire) {
            mask |= gcmd_bits::GCMD_TE;
        }
        mask
    }

    #[inline]
    pub(crate) fn write_gcmd_with_state(&self, cmd_bits: u32) {
        self.registers
            .global_command()
            .write(cmd_bits | self.gcmd_enabled_mask());
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
}
