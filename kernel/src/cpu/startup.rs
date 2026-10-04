use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroU64};
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering, fence};

use crate::sync::InitOnce;
use ap_trampoline::{
    ApTrampolineLaunchInfo, PageTable32Addr, TrampolineMailboxHandle, TrampolineMailboxReadHandle,
    TrampolinePhysAddr, TrampolineVirtAddr,
};
use boot_proto::ExoBootInfo;

use crate::drivers::apic::{ApicDestination, ApicMode, ApicModePolicy, LocalApicError};
use crate::sync::PoisonLock;

use super::{
    ApicId, CpuEjectCapability, CpuFailureReason, CpuId, CpuRole, CpuSlotState,
    CpuStartupApicFailure, CpuStartupFailure, CpuStartupStage, CpuTopologyIssue,
    FirmwareCpuIdentity, FirmwareCpuUid, FirmwareError, FirmwareErrorKind, PhysicalHotplugStatus,
};

const PAGE_SIZE: u64 = 4096;
const AP_STACK_USABLE_PAGES: usize = 255;
const AP_STACK_WINDOW_PAGES: usize = AP_STACK_USABLE_PAGES + 1;
const AP_STARTUP_TIMEOUT_NS: u64 = 1_000_000_000;
const AP_STARTUP_MAX_SPINS: usize = 10_000_000;
static AP_BOOT_PROBE: u8 = 0x5a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ApStartupSignal {
    Preparing = 0,
    TrampolineEntered = 1,
    CpuLocalBound = 2,
    InterruptTablesLoaded = 3,
    LocalApicReady = 4,
    ReadyParked = 5,
    ReadyOnline = 6,
    MissingApic = 7,
    MissingSse2 = 8,
    MissingX2Apic = 9,
    MissingInvariantTsc = 10,
    CpuLocalBindingFailed = 11,
    InterruptTablesFailed = 12,
    LocalApicUnsupported = 13,
    ApicIdentityMismatch = 14,
    TimerFailed = 15,
    LocalApicInvalidMmioBase = 16,
    Draining = 17,
    CacheOwnerBorrowed = 18,
    CacheBackingBusy = 19,
    CacheBackingPoisoned = 20,
    MissingXstate = 21,
    MissingCachePolicy = 22,
}

impl ApStartupSignal {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Preparing),
            1 => Some(Self::TrampolineEntered),
            2 => Some(Self::CpuLocalBound),
            3 => Some(Self::InterruptTablesLoaded),
            4 => Some(Self::LocalApicReady),
            5 => Some(Self::ReadyParked),
            6 => Some(Self::ReadyOnline),
            7 => Some(Self::MissingApic),
            8 => Some(Self::MissingSse2),
            9 => Some(Self::MissingX2Apic),
            10 => Some(Self::MissingInvariantTsc),
            11 => Some(Self::CpuLocalBindingFailed),
            12 => Some(Self::InterruptTablesFailed),
            13 => Some(Self::LocalApicUnsupported),
            14 => Some(Self::ApicIdentityMismatch),
            15 => Some(Self::TimerFailed),
            16 => Some(Self::LocalApicInvalidMmioBase),
            17 => Some(Self::Draining),
            18 => Some(Self::CacheOwnerBorrowed),
            19 => Some(Self::CacheBackingBusy),
            20 => Some(Self::CacheBackingPoisoned),
            21 => Some(Self::MissingXstate),
            22 => Some(Self::MissingCachePolicy),
            _ => None,
        }
    }

    fn failure(self) -> Option<CpuFailureReason> {
        match self {
            Self::Preparing
            | Self::TrampolineEntered
            | Self::CpuLocalBound
            | Self::InterruptTablesLoaded
            | Self::LocalApicReady
            | Self::ReadyParked
            | Self::ReadyOnline
            | Self::Draining => None,
            Self::MissingApic => Some(CpuFailureReason::MissingRequiredFeature { feature: "APIC" }),
            Self::MissingSse2 => Some(CpuFailureReason::MissingRequiredFeature { feature: "SSE2" }),
            Self::MissingX2Apic => {
                Some(CpuFailureReason::MissingRequiredFeature { feature: "x2APIC" })
            }
            Self::MissingInvariantTsc => Some(CpuFailureReason::MissingRequiredFeature {
                feature: "invariant TSC",
            }),
            Self::MissingXstate => Some(CpuFailureReason::MissingRequiredFeature {
                feature: "xstate mask",
            }),
            Self::MissingCachePolicy => Some(CpuFailureReason::MissingRequiredFeature {
                feature: "BSP PAT/MTRR policy",
            }),
            Self::CpuLocalBindingFailed => Some(CpuFailureReason::Startup(
                CpuStartupFailure::CpuLocalBinding,
            )),
            Self::InterruptTablesFailed => Some(CpuFailureReason::Startup(
                CpuStartupFailure::InterruptTables,
            )),
            Self::LocalApicUnsupported => Some(CpuFailureReason::Startup(
                CpuStartupFailure::LocalApic(CpuStartupApicFailure::Unsupported),
            )),
            Self::LocalApicInvalidMmioBase => Some(CpuFailureReason::Startup(
                CpuStartupFailure::LocalApic(CpuStartupApicFailure::InvalidMmioBase),
            )),
            Self::ApicIdentityMismatch => Some(CpuFailureReason::Startup(
                CpuStartupFailure::ApicIdentityMismatch,
            )),
            Self::TimerFailed => Some(CpuFailureReason::Startup(CpuStartupFailure::Timer)),
            Self::CacheOwnerBorrowed => Some(CpuFailureReason::Drain(
                super::CpuDrainFailure::MemoryCache(super::CpuMemoryCacheFailure::OwnerBorrowed),
            )),
            Self::CacheBackingBusy => Some(CpuFailureReason::Drain(
                super::CpuDrainFailure::MemoryCache(super::CpuMemoryCacheFailure::BackingBusy),
            )),
            Self::CacheBackingPoisoned => Some(CpuFailureReason::Drain(
                super::CpuDrainFailure::MemoryCache(super::CpuMemoryCacheFailure::BackingPoisoned),
            )),
        }
    }

    const fn stage(self) -> Option<CpuStartupStage> {
        match self {
            Self::Preparing => Some(CpuStartupStage::Preparing),
            Self::TrampolineEntered => Some(CpuStartupStage::TrampolineEntered),
            Self::CpuLocalBound => Some(CpuStartupStage::CpuLocalBound),
            Self::InterruptTablesLoaded => Some(CpuStartupStage::InterruptTablesLoaded),
            Self::LocalApicReady => Some(CpuStartupStage::LocalApicReady),
            Self::ReadyParked => Some(CpuStartupStage::Parked),
            Self::ReadyOnline => Some(CpuStartupStage::Online),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuStartupResourceError {
    PhysicalAllocation,
    VirtualMapping,
}

pub(crate) struct CpuStartupResources {
    physical: Option<crate::mm::phys::frame_allocator::PhysicalAllocation>,
    window_base: crate::mm::virt::higher_half::VirtAddr,
    stack_top: NonZeroU64,
    signal: AtomicU8,
}

impl CpuStartupResources {
    pub(crate) fn allocate() -> Result<Pin<Box<Self>>, CpuStartupResourceError> {
        let physical_base = crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(
            AP_STACK_USABLE_PAGES,
            PAGE_SIZE as usize,
        )
        .map_err(|_| CpuStartupResourceError::PhysicalAllocation)?;
        let window_base = crate::mm::virt::higher_half::allocate_kernel_virt(AP_STACK_WINDOW_PAGES);
        let mapped_base = window_base + PAGE_SIZE;
        let mapped_size = AP_STACK_USABLE_PAGES as u64 * PAGE_SIZE;
        let map_result = unsafe {
            crate::mm::virt::higher_half::global_map_range(
                mapped_base,
                crate::mm::virt::higher_half::PhysAddr::new(physical_base.as_u64()),
                mapped_size,
                crate::mm::virt::higher_half::PageFlags::kernel_data(),
            )
        };
        if let Err(error) = map_result {
            // The range outcome is the authority for partial progress. The
            // untouched suffix has no mapping and must not be unmap's input.
            if error.modified_size != 0 {
                unsafe {
                    crate::mm::virt::higher_half::global_unmap_range(
                        error.modified_start,
                        error.modified_size,
                    )
                }
                .unwrap_or_else(|_| panic!("failed AP stack retirement cannot release its frames"));
            }
            physical_base.release();
            return Err(CpuStartupResourceError::VirtualMapping);
        }
        let stack_top =
            NonZeroU64::new(window_base.as_u64() + AP_STACK_WINDOW_PAGES as u64 * PAGE_SIZE)
                .ok_or(CpuStartupResourceError::VirtualMapping)?;
        Ok(Box::pin(Self {
            physical: Some(physical_base),
            window_base,
            stack_top,
            signal: AtomicU8::new(ApStartupSignal::Preparing as u8),
        }))
    }

    fn stack_top(&self) -> NonZeroU64 {
        self.stack_top
    }

    fn reset(&self) {
        self.signal
            .store(ApStartupSignal::Preparing as u8, Ordering::Release);
    }

    fn publish(&self, signal: ApStartupSignal) {
        self.signal.store(signal as u8, Ordering::Release);
    }

    fn signal(&self) -> Result<ApStartupSignal, CpuFailureReason> {
        let value = self.signal.load(Ordering::Acquire);
        ApStartupSignal::from_raw(value).ok_or(CpuFailureReason::Startup(
            CpuStartupFailure::InvalidSignal { value },
        ))
    }

    pub(super) fn prepare_drain(&self) {
        self.publish(ApStartupSignal::Draining);
    }

    pub(super) fn memory_drain_failure(&self) -> Option<CpuFailureReason> {
        match self.signal().ok()?.failure()? {
            failure @ CpuFailureReason::Drain(super::CpuDrainFailure::MemoryCache(_)) => {
                Some(failure)
            }
            _ => None,
        }
    }

    /// ReadyParked is published only after the owner acknowledgement. This
    /// observes a late completion without issuing another drain request.
    pub(super) fn park_completion_published(&self) -> bool {
        self.signal() == Ok(ApStartupSignal::ReadyParked)
    }
}

impl Drop for CpuStartupResources {
    fn drop(&mut self) {
        let mapped_base = self.window_base + PAGE_SIZE;
        let mapped_size = AP_STACK_USABLE_PAGES as u64 * PAGE_SIZE;
        unsafe { crate::mm::virt::higher_half::global_unmap_range(mapped_base, mapped_size) }
            .unwrap_or_else(|_| panic!("AP stack retirement must finish before RAM reuse"));
        self.physical
            .take()
            .expect("AP stack owns its backing")
            .release();
    }
}

#[derive(Debug, Clone, Copy)]
struct RequiredCpuFeatures {
    x2apic: bool,
    invariant_tsc: bool,
}

impl RequiredCpuFeatures {
    fn detect(mode: ApicMode) -> Self {
        Self {
            x2apic: mode == ApicMode::X2Apic,
            invariant_tsc: invariant_tsc_supported(),
        }
    }

    fn validate_current(self) -> Result<(), ApStartupSignal> {
        let leaf1 = core::arch::x86_64::__cpuid(1);
        if leaf1.edx & (1 << 9) == 0 {
            return Err(ApStartupSignal::MissingApic);
        }
        if leaf1.edx & (1 << 26) == 0 {
            return Err(ApStartupSignal::MissingSse2);
        }
        if self.x2apic && leaf1.ecx & (1 << 21) == 0 {
            return Err(ApStartupSignal::MissingX2Apic);
        }
        if self.invariant_tsc && !invariant_tsc_supported() {
            return Err(ApStartupSignal::MissingInvariantTsc);
        }
        Ok(())
    }
}

struct CpuStartupController {
    trampoline: TrampolinePhysAddr,
    mailbox: PoisonLock<TrampolineMailboxHandle>,
    launch: PoisonLock<()>,
    required_features: RequiredCpuFeatures,
}

impl CpuStartupController {
    fn new(boot_info: &ExoBootInfo, mode: ApicMode) -> Result<Self, CpuInitializationError> {
        let trampoline = boot_info
            .ap_trampoline
            .address()
            .map_err(CpuInitializationError::Trampoline)?;
        let trampoline_virt =
            crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(trampoline.as_u64()));
        let trampoline_virt = TrampolineVirtAddr::new(trampoline_virt.as_u64() as usize)
            .map_err(CpuInitializationError::Trampoline)?;
        let mailbox = unsafe { TrampolineMailboxHandle::from_trampoline_virt(trampoline_virt) }
            .map_err(CpuInitializationError::Trampoline)?;
        Ok(Self {
            trampoline,
            mailbox: PoisonLock::new(mailbox),
            launch: PoisonLock::new(()),
            required_features: RequiredCpuFeatures::detect(mode),
        })
    }

    fn launch(&self, id: CpuId, apic_id: ApicId) -> Result<(), CpuFailureReason> {
        let _launch = self
            .launch
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let resource = super::runtime()
            .startup_resource(id)
            .ok_or(CpuFailureReason::Startup(
                CpuStartupFailure::CpuLocalBinding,
            ))?;
        resource.reset();
        let cpu_id = NonZeroU32::new(u32::from(id.as_u16())).ok_or(CpuFailureReason::Startup(
            CpuStartupFailure::CpuLocalBinding,
        ))?;
        let page_table = PageTable32Addr::new(crate::mm::virt::higher_half::get_cr3().as_u64())
            .map_err(|_| CpuFailureReason::Startup(CpuStartupFailure::TlbState))?;
        let entry_point = NonZeroU64::new(ap_trampoline_entry as *const () as usize as u64).ok_or(
            CpuFailureReason::Startup(CpuStartupFailure::CpuLocalBinding),
        )?;
        let launch_info = ApTrampolineLaunchInfo::new(
            u32::from(id.as_u16()),
            cpu_id,
            page_table,
            resource.stack_top(),
            entry_point,
            NonZeroU64::new(core::ptr::addr_of!(AP_BOOT_PROBE) as u64),
        );
        self.mailbox
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .write_launch(launch_info);

        let destination = ApicDestination::new(apic_id.as_u32());
        let local_apic = crate::drivers::apic::local_apic().map_err(map_apic_start_error)?;
        local_apic
            .send_init(destination)
            .map_err(map_apic_start_error)?;
        crate::time::pit().delay_us(10_000);
        local_apic
            .send_sipi(destination, self.trampoline.sipi_vector())
            .map_err(map_apic_start_error)?;
        crate::time::pit().delay_us(200);
        local_apic
            .send_sipi(destination, self.trampoline.sipi_vector())
            .map_err(map_apic_start_error)?;

        let start = crate::time::best_effort_time_nanos();
        for spin in 0..AP_STARTUP_MAX_SPINS {
            let signal = resource.signal()?;
            if signal == ApStartupSignal::ReadyParked {
                return Ok(());
            }
            if let Some(failure) = signal.failure() {
                return Err(failure);
            }
            if spin & 0x3ff == 0
                && crate::time::best_effort_time_nanos().saturating_sub(start)
                    >= AP_STARTUP_TIMEOUT_NS
            {
                break;
            }
            core::hint::spin_loop();
        }
        Err(CpuFailureReason::StartupAcknowledgementTimedOut {
            stage: resource
                .signal()
                .ok()
                .and_then(ApStartupSignal::stage)
                .unwrap_or(CpuStartupStage::Preparing),
        })
    }
}

fn map_apic_start_error(error: LocalApicError) -> CpuFailureReason {
    match error {
        LocalApicError::DestinationNotAddressable { destination } => {
            CpuFailureReason::Topology(CpuTopologyIssue::UnsupportedApicDestination {
                apic_id: ApicId::new(destination.as_u32()),
            })
        }
        LocalApicError::NotSelected | LocalApicError::Unsupported => CpuFailureReason::Startup(
            CpuStartupFailure::LocalApic(CpuStartupApicFailure::Unsupported),
        ),
        LocalApicError::InvalidMmioBase { .. } => CpuFailureReason::Startup(
            CpuStartupFailure::LocalApic(CpuStartupApicFailure::InvalidMmioBase),
        ),
        LocalApicError::DeliveryTimedOut { .. } => CpuFailureReason::Startup(
            CpuStartupFailure::LocalApic(CpuStartupApicFailure::DeliveryTimedOut),
        ),
        LocalApicError::TimerNotCalibrated | LocalApicError::TimerCountOverflow => {
            CpuFailureReason::Startup(CpuStartupFailure::Timer)
        }
    }
}

fn invariant_tsc_supported() -> bool {
    let maximum = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    maximum >= 0x8000_0007 && core::arch::x86_64::__cpuid(0x8000_0007).edx & (1 << 8) != 0
}

static STARTUP_CONTROLLER: InitOnce<Result<CpuStartupController, CpuInitializationError>> =
    InitOnce::new();

struct BootCpuInventory {
    discovered: usize,
    enabled: Arc<[CpuId]>,
}

static BOOT_CPU_INVENTORY: InitOnce<BootCpuInventory> = InitOnce::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CpuBootSummary {
    pub discovered: usize,
    pub online: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CpuInitializationError {
    LocalApic(LocalApicError),
    Firmware(FirmwareError),
    NumaPlacement(crate::platform::firmware::FirmwarePlacementError),
    CpuPlacement(crate::mm::numa::placement::CpuPlacementError),
    Trampoline(&'static str),
    Topology(CpuTopologyIssue),
    BootstrapBinding,
    TransitionWorker(crate::task::SpawnError),
}

pub(crate) fn prepare_bootstrap(boot_info: &ExoBootInfo) -> Result<(), CpuInitializationError> {
    if BOOT_CPU_INVENTORY.get().is_some() {
        return Ok(());
    }
    let local_apic =
        crate::drivers::apic::initialize_bootstrap_cpu(bootstrap_apic_policy()?, |base| {
            let physical = x86_64::PhysAddr::try_new(base)
                .map_err(|_| LocalApicError::InvalidMmioBase { base })?;
            // SAFETY: IA32_APIC_BASE identifies the BSP's reserved APIC register
            // page. The bootstrap owns installation of the single local-APIC
            // backend, and the platform direct map is retained for kernel lifetime.
            unsafe { crate::mm::virt::mapping::retain_device_registers(physical, 4096) }
                .map_err(|_| LocalApicError::InvalidMmioBase { base })
        })
        .map_err(CpuInitializationError::LocalApic)?;
    let bsp_apic = ApicId::new(local_apic.id());
    let placement = crate::platform::firmware::numa_placement()
        .map_err(CpuInitializationError::NumaPlacement)?;
    let located = super::LocatedCpu::resolve(
        FirmwareCpuIdentity {
            uid: None,
            apic_id: bsp_apic,
            proximity_domain: None,
            eject: CpuEjectCapability::Fixed,
        },
        placement,
    )
    .map_err(CpuInitializationError::CpuPlacement)?;
    super::install_bootstrap(located, Some(boot_info.tls_template))
        .map_err(CpuInitializationError::Topology)?;
    super::CurrentCpu::bind(CpuId::BOOTSTRAP)
        .map_err(|_| CpuInitializationError::BootstrapBinding)?;
    let _ = crate::mm::sync::tlb::exit_lazy_mode();
    crate::task::initialize_scheduler().map_err(|_| CpuInitializationError::BootstrapBinding)?;
    super::transition::initialize().map_err(CpuInitializationError::TransitionWorker)?;

    STARTUP_CONTROLLER.call_once(|| CpuStartupController::new(boot_info, local_apic.mode()));

    let mut discovered = 1usize;
    let mut enabled = Vec::new();
    let Some(tables) = crate::platform::firmware::tables() else {
        BOOT_CPU_INVENTORY.call_once(|| BootCpuInventory {
            discovered,
            enabled: Arc::from(enabled),
        });
        return Ok(());
    };
    let firmware_cpus = match tables.firmware_cpus() {
        Ok(cpus) => cpus,
        Err(error) => {
            let _ = super::runtime()
                .set_physical_hotplug(PhysicalHotplugStatus::Unavailable(firmware_error(error)));
            BOOT_CPU_INVENTORY.call_once(|| BootCpuInventory {
                discovered,
                enabled: Arc::from(enabled),
            });
            return Ok(());
        }
    };
    let runtime = super::runtime();

    for firmware_cpu in firmware_cpus {
        if !firmware_cpu.enabled && !firmware_cpu.online_capable {
            continue;
        }
        let apic_id = ApicId::new(firmware_cpu.apic_id);
        let firmware = FirmwareCpuIdentity {
            uid: Some(FirmwareCpuUid::Integer(u64::from(
                firmware_cpu.firmware_uid,
            ))),
            apic_id,
            proximity_domain: None,
            eject: CpuEjectCapability::Fixed,
        };
        let located = super::LocatedCpu::resolve(firmware, placement)
            .map_err(CpuInitializationError::CpuPlacement)?;
        if apic_id == bsp_apic {
            runtime
                .identify_bootstrap(located)
                .map_err(CpuInitializationError::Topology)?;
            continue;
        }
        let id = runtime
            .discover_present(located)
            .map_err(CpuInitializationError::Topology)?;
        discovered += 1;
        if !firmware_cpu.enabled {
            continue;
        }
        enabled.push(id);
    }

    BOOT_CPU_INVENTORY.call_once(|| BootCpuInventory {
        discovered,
        enabled: Arc::from(enabled),
    });
    Ok(())
}

fn bootstrap_apic_policy() -> Result<ApicModePolicy, CpuInitializationError> {
    let Some(tables) = crate::platform::firmware::tables() else {
        return Ok(ApicModePolicy::PreferX2Apic);
    };
    let Some(table) = tables.first(crate::drivers::acpi::TableSignature::DMAR) else {
        return Ok(ApicModePolicy::PreferX2Apic);
    };
    let dmar = crate::drivers::acpi::dmar::parse(table.bytes())
        .map_err(firmware_error)
        .map_err(CpuInitializationError::Firmware)?;
    Ok(if dmar.x2apic_opt_out() {
        ApicModePolicy::XApicOnly
    } else {
        ApicModePolicy::PreferX2Apic
    })
}

pub(crate) fn start_boot_cpus() -> CpuBootSummary {
    let Some(inventory) = BOOT_CPU_INVENTORY.get() else {
        return CpuBootSummary {
            discovered: super::snapshot().possible().len(),
            online: super::snapshot().online().len(),
            failed: 0,
        };
    };
    let mut failed = 0usize;
    for id in inventory.enabled.iter().copied() {
        let result = online_cpu(id);
        if let Err(reason) = result {
            failed += 1;
            log::warn!("CPU {} startup rejected: {:?}", id, reason);
        }
    }
    CpuBootSummary {
        discovered: inventory.discovered,
        online: super::snapshot().online().len(),
        failed,
    }
}

fn record_unavailable_trampoline(id: CpuId) -> Result<(), CpuFailureReason> {
    let reason = CpuFailureReason::Startup(CpuStartupFailure::Trampoline);
    let runtime = super::runtime();
    runtime.begin_start(id).map_err(runtime_failure)?;
    runtime
        .startup_failed(id, reason.clone())
        .map_err(runtime_failure)?;
    Err(reason)
}

pub(crate) fn online_cpu(id: CpuId) -> Result<(), CpuFailureReason> {
    let runtime = super::runtime();
    let slot = runtime
        .snapshot()
        .slot(id)
        .cloned()
        .ok_or(CpuFailureReason::Topology(
            CpuTopologyIssue::ConflictingFirmwareIdentity,
        ))?;
    if slot.role == CpuRole::Bootstrap
        || !matches!(
            slot.state,
            CpuSlotState::PresentOffline | CpuSlotState::Parked
        )
    {
        return Err(CpuFailureReason::Topology(
            CpuTopologyIssue::ConflictingFirmwareIdentity,
        ));
    }
    let controller = STARTUP_CONTROLLER
        .get()
        .and_then(|result| result.as_ref().ok());
    let Some(controller) = controller else {
        return record_unavailable_trampoline(id);
    };
    let local = runtime.cpu_local(id).ok_or(CpuFailureReason::Startup(
        CpuStartupFailure::CpuLocalBinding,
    ))?;
    runtime.begin_start(id).map_err(runtime_failure)?;
    let resource = match runtime.prepare_startup_resource(id) {
        Ok(resource) => resource,
        Err(error) => {
            let reason = match error {
                CpuStartupResourceError::PhysicalAllocation
                | CpuStartupResourceError::VirtualMapping => {
                    CpuFailureReason::Startup(CpuStartupFailure::CpuLocalBinding)
                }
            };
            record_startup_failure(runtime, id, reason.clone());
            return Err(reason);
        }
    };
    let cpu_snapshot = runtime.snapshot();
    if crate::net::runtime::context::provision_possible_cpus(&cpu_snapshot).is_err() {
        let reason = CpuFailureReason::Startup(CpuStartupFailure::NetworkResources);
        record_startup_failure(runtime, id, reason.clone());
        return Err(reason);
    }
    crate::task::prepare_cpu_online(id);
    if slot.state == CpuSlotState::PresentOffline
        && let Err(reason) = controller.launch(id, slot.firmware.apic_id)
    {
        crate::task::abort_cpu_online(id);
        record_startup_failure(runtime, id, reason.clone());
        return Err(reason);
    }
    resource.reset();
    let acknowledgement = local.remote().online_acknowledgements();
    let activation = match local.remote().send(super::CpuControlMessage::Start) {
        Ok(()) => {
            let ipi_failure =
                super::send_ipi_to_apic(slot.firmware.apic_id, super::IpiKind::ExecutorWake)
                    .err()
                    .map(map_ipi_start_error);
            wait_for_online_acknowledgement(local, resource, acknowledgement)
                .or_else(|wait_failure| Err(ipi_failure.unwrap_or(wait_failure)))
        }
        Err(_) => Err(CpuFailureReason::Startup(
            CpuStartupFailure::CpuLocalBinding,
        )),
    };
    if let Err(reason) = activation {
        crate::task::abort_cpu_online(id);
        record_startup_failure(runtime, id, reason.clone());
        return Err(reason);
    }
    runtime.startup_ready(id).unwrap_or_else(|error| {
        panic!("CPU {id} online commit failed after AP acknowledgement: {error:?}")
    });
    crate::net::runtime::context::publish_cpu_online(id);
    crate::task::publish_cpu_online(id);
    Ok(())
}

fn record_startup_failure(runtime: &super::CpuRuntime, id: CpuId, reason: CpuFailureReason) {
    runtime.startup_failed(id, reason).unwrap_or_else(|error| {
        panic!("CPU {id} startup failure could not be committed: {error:?}")
    });
}

fn wait_for_online_acknowledgement(
    local: &super::CpuLocal,
    resource: &CpuStartupResources,
    acknowledgement: u64,
) -> Result<(), CpuFailureReason> {
    let start = crate::time::best_effort_time_nanos();
    for spin in 0..AP_STARTUP_MAX_SPINS {
        if local.remote().online_acknowledgements() != acknowledgement {
            return Ok(());
        }
        if let Some(reason) = resource.signal()?.failure() {
            return Err(reason);
        }
        if spin & 0x3ff == 0
            && crate::time::best_effort_time_nanos().saturating_sub(start) >= AP_STARTUP_TIMEOUT_NS
        {
            break;
        }
        core::hint::spin_loop();
    }
    Err(CpuFailureReason::StartupAcknowledgementTimedOut {
        stage: resource
            .signal()
            .ok()
            .and_then(ApStartupSignal::stage)
            .unwrap_or(CpuStartupStage::Preparing),
    })
}

fn online_commit_observed(current: &super::CurrentCpu, id: CpuId) -> bool {
    // LOOP_PROOF: mode=event; reason=The BSP publishes Online or startup rejection, and an accepted Park request aborts this wait.;
    loop {
        // LOOP_PROOF: mode=condition; reason=Each take consumes an accepted owner control message and exits when the queue is empty.;
        while let Some(message) = current.take_control() {
            match message {
                super::CpuControlMessage::ReclaimMemory => {
                    crate::heap::reclaim_local_caches();
                }
                super::CpuControlMessage::Park => return false,
                super::CpuControlMessage::WakeExecutor | super::CpuControlMessage::Start => {}
            }
        }
        let Some(slot) = super::snapshot().slot(id).cloned() else {
            return false;
        };
        match slot.state {
            CpuSlotState::Online => return true,
            CpuSlotState::Starting => core::hint::spin_loop(),
            _ => return false,
        }
    }
}

fn wait_for_park_commit(id: CpuId) {
    // LOOP_PROOF: mode=event; reason=The BSP commits Parked after the acknowledgement or has already begun a subsequent Starting transition.;
    loop {
        let Some(slot) = super::snapshot().slot(id).cloned() else {
            fail_stop_ap();
        };
        match slot.state {
            // Starting can follow an already committed Parked state before
            // this owner observes it. Leave the queued Start for its normal
            // lifecycle handler; consuming it here would lose its authority.
            CpuSlotState::Parked | CpuSlotState::Starting => return,
            CpuSlotState::Draining => core::hint::spin_loop(),
            _ => fail_stop_ap(),
        }
    }
}

fn run_online_lifecycle(
    current: &super::CurrentCpu,
    id: CpuId,
    resource: &CpuStartupResources,
    local_apic: &crate::drivers::apic::LocalApic,
) {
    crate::task::run_until_parked();
    crate::interrupts::disable_interrupts();
    if crate::interrupts::stop_current_cpu_runtime_timer().is_err() {
        resource.publish(ApStartupSignal::TimerFailed);
        fail_stop_ap();
    }
    let _ = crate::interrupts::retire_current_cpu_timer_event();
    crate::task::quiesce_current_cpu_deferred_work();
    crate::mm::sync::rcu::quiesce_current_cpu_for_offline();
    crate::mm::sync::tlb::enter_lazy_mode();
    local_apic.set_task_priority(0xe0);
    drain_memory_before_park(current, resource);
    current.acknowledge_parked();
    resource.publish(ApStartupSignal::ReadyParked);
    fence(Ordering::SeqCst);
    crate::interrupts::enable_interrupts();
    wait_for_park_commit(id);
}

/// A failed memory drain keeps this CPU in Draining with its cache owners.
/// It services TLB IPIs in lazy mode, but grants neither park acknowledgement
/// nor new execution. A subsequent offline request explicitly retries the drain.
fn drain_memory_before_park(current: &super::CurrentCpu, resource: &CpuStartupResources) {
    // LOOP_PROOF: mode=event; reason=Each failed return retains owner storage and waits for an explicitly accepted Park retry, and successful return ends this protocol.;
    loop {
        match crate::heap::drain_local_caches() {
            Ok(_) => return,
            Err(failure) => {
                use crate::heap::{ExchangeDrainError, LocalCacheDrainError};
                let signal = match failure.cause {
                    LocalCacheDrainError::Exchange(ExchangeDrainError::BackingBusy) => {
                        ApStartupSignal::CacheBackingBusy
                    }
                    LocalCacheDrainError::Exchange(ExchangeDrainError::BackingPoisoned) => {
                        ApStartupSignal::CacheBackingPoisoned
                    }
                    LocalCacheDrainError::Exchange(
                        ExchangeDrainError::CacheBorrowed | ExchangeDrainError::AlreadyDraining,
                    )
                    | LocalCacheDrainError::OwnerStorageBorrowed => {
                        ApStartupSignal::CacheOwnerBorrowed
                    }
                };
                resource.publish(signal);
            }
        }
        crate::interrupts::enable_interrupts();
        // LOOP_PROOF: mode=event; reason=The stopped owner retains failed cache entries and resumes only for an explicitly accepted Park retry, while interrupts continue to retire global TLB work.;
        loop {
            let mut retry = false;
            // LOOP_PROOF: mode=condition; reason=Each take consumes a message from the finite owner control queue.;
            while let Some(message) = current.take_control() {
                match message {
                    super::CpuControlMessage::Park => retry = true,
                    super::CpuControlMessage::ReclaimMemory => {
                        crate::heap::reclaim_local_caches();
                    }
                    super::CpuControlMessage::WakeExecutor | super::CpuControlMessage::Start => {}
                }
            }
            if retry {
                crate::interrupts::disable_interrupts();
                break;
            }
            // SAFETY: this CPU retains its stack, descriptor/TLB state and
            // owner storage; it has no schedulable task or park acknowledgement.
            unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
        }
    }
}

fn map_ipi_start_error(error: super::CpuIpiError) -> CpuFailureReason {
    match error {
        super::CpuIpiError::LocalApic(error) => map_apic_start_error(error),
        super::CpuIpiError::CpuNotPresent(_) | super::CpuIpiError::CpuStateIneligible { .. } => {
            CpuFailureReason::Topology(CpuTopologyIssue::ConflictingFirmwareIdentity)
        }
    }
}

fn runtime_failure(error: super::CpuRuntimeError) -> CpuFailureReason {
    match error {
        super::CpuRuntimeError::Topology(issue) => CpuFailureReason::Topology(issue),
        super::CpuRuntimeError::UnknownCpu(_) | super::CpuRuntimeError::State(_) => {
            CpuFailureReason::Topology(CpuTopologyIssue::ConflictingFirmwareIdentity)
        }
    }
}

fn firmware_error(error: crate::drivers::acpi::AcpiError) -> FirmwareError {
    let object = error.table.map(|signature| {
        alloc::sync::Arc::<str>::from(core::str::from_utf8(&signature).unwrap_or("????"))
    });
    FirmwareError {
        kind: FirmwareErrorKind::InvalidTable,
        object,
        detail: error.detail,
    }
}

#[inline(never)]
unsafe extern "C" fn ap_trampoline_entry(mailbox_ptr: *const u8) -> ! {
    super::CurrentCpu::clear_boot_binding();
    let mailbox = unsafe { TrampolineMailboxReadHandle::from_const_ptr(mailbox_ptr) }
        .and_then(|mailbox| mailbox.read_verified());
    let Ok(mailbox) = mailbox else {
        fail_stop_ap();
    };
    let id = CpuId::try_from(mailbox.cpu_id().get() as usize);
    let Ok(id) = id else {
        fail_stop_ap();
    };
    if mailbox.ap_slot() != u32::from(id.as_u16()) {
        fail_stop_ap();
    }
    if let Some(resource) = super::runtime().startup_resource(id) {
        resource.publish(ApStartupSignal::TrampolineEntered);
    }
    ap_entry(id)
}

fn ap_entry(id: CpuId) -> ! {
    let Some(resource) = super::runtime().startup_resource(id) else {
        fail_stop_ap();
    };
    let controller = STARTUP_CONTROLLER
        .get()
        .and_then(|controller| controller.as_ref().ok())
        .unwrap_or_else(|| fail_stop_ap());
    if let Err(signal) = controller.required_features.validate_current() {
        resource.publish(signal);
        fail_stop_ap();
    }
    if !super::xstate::initialize_secondary_cpu() {
        resource.publish(ApStartupSignal::MissingXstate);
        fail_stop_ap();
    }
    if !super::cache_policy::validate_secondary_cpu() {
        resource.publish(ApStartupSignal::MissingCachePolicy);
        fail_stop_ap();
    }
    if super::CurrentCpu::bind(id).is_err() {
        resource.publish(ApStartupSignal::CpuLocalBindingFailed);
        fail_stop_ap();
    }
    resource.publish(ApStartupSignal::CpuLocalBound);
    if crate::interrupts::load_for_current_cpu().is_err() {
        resource.publish(ApStartupSignal::InterruptTablesFailed);
        fail_stop_ap();
    }
    resource.publish(ApStartupSignal::InterruptTablesLoaded);
    let local_apic = match crate::drivers::apic::initialize_current_cpu() {
        Ok(local_apic) => local_apic,
        Err(LocalApicError::InvalidMmioBase { .. }) => {
            resource.publish(ApStartupSignal::LocalApicInvalidMmioBase);
            fail_stop_ap();
        }
        Err(_) => {
            resource.publish(ApStartupSignal::LocalApicUnsupported);
            fail_stop_ap();
        }
    };
    let expected_apic = super::snapshot().slot(id).map(|slot| slot.firmware.apic_id);
    if expected_apic != Some(ApicId::new(local_apic.id())) {
        resource.publish(ApStartupSignal::ApicIdentityMismatch);
        fail_stop_ap();
    }
    resource.publish(ApStartupSignal::LocalApicReady);

    crate::mm::sync::tlb::enter_lazy_mode();
    let current = super::CurrentCpu::acquire().unwrap_or_else(|| fail_stop_ap());
    local_apic.set_task_priority(0xe0);
    crate::interrupts::enable_interrupts();
    current.acknowledge_parked();
    resource.publish(ApStartupSignal::ReadyParked);
    fence(Ordering::SeqCst);

    // LOOP_PROOF: mode=halt; reason=This AP owns its permanent stack and alternates accepted lifecycle messages with an interruptible HLT until terminal failure.;
    loop {
        // LOOP_PROOF: mode=condition; reason=Each take consumes one accepted message and exits when the finite owner control queue is empty.;
        while let Some(message) = current.take_control() {
            match message {
                super::CpuControlMessage::Start => {
                    crate::interrupts::disable_interrupts();
                    local_apic.set_task_priority(0);
                    if crate::interrupts::prepare_current_cpu_runtime_timer().is_err() {
                        resource.publish(ApStartupSignal::TimerFailed);
                        crate::mm::sync::tlb::enter_lazy_mode();
                        local_apic.set_task_priority(0xe0);
                        crate::interrupts::enable_interrupts();
                        continue;
                    }
                    resource.publish(ApStartupSignal::ReadyOnline);
                    current.acknowledge_online();
                    fence(Ordering::SeqCst);
                    if online_commit_observed(&current, id) {
                        let _ = crate::mm::sync::tlb::exit_lazy_mode();
                        crate::interrupts::enable_interrupts();
                        run_online_lifecycle(&current, id, resource, local_apic);
                    } else {
                        if crate::interrupts::stop_current_cpu_runtime_timer().is_err() {
                            resource.publish(ApStartupSignal::TimerFailed);
                            fail_stop_ap();
                        }
                        let _ = crate::interrupts::retire_current_cpu_timer_event();
                        crate::task::quiesce_current_cpu_deferred_work();
                        crate::mm::sync::rcu::quiesce_current_cpu_for_offline();
                        crate::mm::sync::tlb::enter_lazy_mode();
                        local_apic.set_task_priority(0xe0);
                        drain_memory_before_park(&current, resource);
                        current.acknowledge_parked();
                        resource.publish(ApStartupSignal::ReadyParked);
                        fence(Ordering::SeqCst);
                        crate::interrupts::enable_interrupts();
                    }
                }
                super::CpuControlMessage::ReclaimMemory => {
                    crate::heap::reclaim_local_caches();
                }
                super::CpuControlMessage::WakeExecutor | super::CpuControlMessage::Park => {}
            }
        }
        unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    }
}

fn fail_stop_ap() -> ! {
    crate::interrupts::disable_interrupts();
    if super::CurrentCpu::acquire().is_some() {
        // Starting CPUs can already retain heap, Exchange and frame caches.
        // The owner drains before this terminal path abandons its execution.
        crate::heap::reclaim_local_caches();
    }
    // LOOP_PROOF: mode=halt; reason=Failed AP admission is terminal and interrupts are disabled before this permanent HLT state.;
    loop {
        x86_64::instructions::hlt();
    }
}

#[cfg(test)]
mod tests {
    use super::ApStartupSignal;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn startup_progress_signals_are_not_failures() {
        for signal in [
            ApStartupSignal::Preparing,
            ApStartupSignal::TrampolineEntered,
            ApStartupSignal::CpuLocalBound,
            ApStartupSignal::InterruptTablesLoaded,
            ApStartupSignal::LocalApicReady,
            ApStartupSignal::ReadyParked,
            ApStartupSignal::ReadyOnline,
        ] {
            assert!(signal.failure().is_none());
            assert!(signal.stage().is_some());
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn startup_failure_signals_cannot_be_observed_as_progress() {
        for signal in [
            ApStartupSignal::MissingApic,
            ApStartupSignal::MissingSse2,
            ApStartupSignal::MissingX2Apic,
            ApStartupSignal::MissingInvariantTsc,
            ApStartupSignal::CpuLocalBindingFailed,
            ApStartupSignal::InterruptTablesFailed,
            ApStartupSignal::LocalApicUnsupported,
            ApStartupSignal::ApicIdentityMismatch,
            ApStartupSignal::TimerFailed,
            ApStartupSignal::LocalApicInvalidMmioBase,
        ] {
            assert!(signal.failure().is_some());
            assert!(signal.stage().is_none());
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn startup_signal_decoder_rejects_unknown_values() {
        assert!(ApStartupSignal::from_raw(21).is_none());
        assert!(ApStartupSignal::from_raw(u8::MAX).is_none());
    }

    #[test]
    fn memory_drain_signals_preserve_failure_kind_without_park_progress() {
        use super::super::{CpuDrainFailure, CpuFailureReason, CpuMemoryCacheFailure};
        for (signal, cause) in [
            (
                ApStartupSignal::CacheOwnerBorrowed,
                CpuMemoryCacheFailure::OwnerBorrowed,
            ),
            (
                ApStartupSignal::CacheBackingBusy,
                CpuMemoryCacheFailure::BackingBusy,
            ),
            (
                ApStartupSignal::CacheBackingPoisoned,
                CpuMemoryCacheFailure::BackingPoisoned,
            ),
        ] {
            assert_eq!(ApStartupSignal::from_raw(signal as u8), Some(signal));
            assert_eq!(
                signal.failure(),
                Some(CpuFailureReason::Drain(CpuDrainFailure::MemoryCache(cause)))
            );
            assert!(signal.stage().is_none());
        }
        assert!(ApStartupSignal::Draining.failure().is_none());
        assert!(ApStartupSignal::Draining.stage().is_none());
    }
}
