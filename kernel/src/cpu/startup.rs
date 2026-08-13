use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroU64};
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering, fence};

use ap_trampoline::{
    ApTrampolineLaunchInfo, PageTable32Addr, TrampolineMailboxHandle, TrampolineMailboxReadHandle,
    TrampolinePhysAddr, TrampolineVirtAddr,
};
use boot_proto::ExoBootInfo;
use spin::Once;

use crate::drivers::apic::{ApicDestination, ApicMode, LocalApicError};
use crate::sync::PoisonLock;

use super::{
    ApicId, CpuEjectCapability, CpuFailureReason, CpuId, CpuRole, CpuSlotState, CpuStartupFailure,
    CpuTopologyIssue, FirmwareCpuIdentity, FirmwareCpuUid, FirmwareError, FirmwareErrorKind,
    PhysicalHotplugStatus,
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
    ReadyParked = 1,
    MissingApic = 2,
    MissingSse2 = 3,
    MissingX2Apic = 4,
    MissingInvariantTsc = 5,
    CpuLocalBindingFailed = 6,
    InterruptTablesFailed = 7,
    LocalApicFailed = 8,
    ApicIdentityMismatch = 9,
}

impl ApStartupSignal {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Preparing),
            1 => Some(Self::ReadyParked),
            2 => Some(Self::MissingApic),
            3 => Some(Self::MissingSse2),
            4 => Some(Self::MissingX2Apic),
            5 => Some(Self::MissingInvariantTsc),
            6 => Some(Self::CpuLocalBindingFailed),
            7 => Some(Self::InterruptTablesFailed),
            8 => Some(Self::LocalApicFailed),
            9 => Some(Self::ApicIdentityMismatch),
            _ => None,
        }
    }

    fn failure(self) -> Option<CpuFailureReason> {
        match self {
            Self::Preparing | Self::ReadyParked => None,
            Self::MissingApic => Some(CpuFailureReason::MissingRequiredFeature { feature: "APIC" }),
            Self::MissingSse2 => Some(CpuFailureReason::MissingRequiredFeature { feature: "SSE2" }),
            Self::MissingX2Apic => {
                Some(CpuFailureReason::MissingRequiredFeature { feature: "x2APIC" })
            }
            Self::MissingInvariantTsc => Some(CpuFailureReason::MissingRequiredFeature {
                feature: "invariant TSC",
            }),
            Self::CpuLocalBindingFailed => Some(CpuFailureReason::Startup(
                CpuStartupFailure::CpuLocalBinding,
            )),
            Self::InterruptTablesFailed => Some(CpuFailureReason::Startup(
                CpuStartupFailure::InterruptTables,
            )),
            Self::LocalApicFailed | Self::ApicIdentityMismatch => {
                Some(CpuFailureReason::Startup(CpuStartupFailure::LocalApic))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuStartupResourceError {
    PhysicalAllocation,
    VirtualMapping,
}

pub(crate) struct CpuStartupResources {
    physical_base: x86_64::PhysAddr,
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
        .ok_or(CpuStartupResourceError::PhysicalAllocation)?;
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
        if map_result.is_err() {
            crate::mm::phys::frame_allocator::dealloc_contiguous_frames(
                physical_base,
                AP_STACK_USABLE_PAGES,
            );
            return Err(CpuStartupResourceError::VirtualMapping);
        }
        let stack_top =
            NonZeroU64::new(window_base.as_u64() + AP_STACK_WINDOW_PAGES as u64 * PAGE_SIZE)
                .ok_or(CpuStartupResourceError::VirtualMapping)?;
        Ok(Box::pin(Self {
            physical_base,
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

    fn signal(&self) -> ApStartupSignal {
        ApStartupSignal::from_raw(self.signal.load(Ordering::Acquire))
            .unwrap_or(ApStartupSignal::LocalApicFailed)
    }
}

impl Drop for CpuStartupResources {
    fn drop(&mut self) {
        let mapped_base = self.window_base + PAGE_SIZE;
        let mapped_size = AP_STACK_USABLE_PAGES as u64 * PAGE_SIZE;
        let _ =
            unsafe { crate::mm::virt::higher_half::global_unmap_range(mapped_base, mapped_size) };
        crate::mm::phys::frame_allocator::dealloc_contiguous_frames(
            self.physical_base,
            AP_STACK_USABLE_PAGES,
        );
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
        for _ in 0..AP_STARTUP_MAX_SPINS {
            match resource.signal() {
                ApStartupSignal::Preparing => {}
                ApStartupSignal::ReadyParked => return Ok(()),
                failure => {
                    return Err(failure
                        .failure()
                        .unwrap_or(CpuFailureReason::Startup(CpuStartupFailure::LocalApic)));
                }
            }
            if crate::time::best_effort_time_nanos().saturating_sub(start) >= AP_STARTUP_TIMEOUT_NS
            {
                break;
            }
            core::hint::spin_loop();
        }
        Err(CpuFailureReason::StartupAcknowledgementTimedOut)
    }
}

fn map_apic_start_error(error: LocalApicError) -> CpuFailureReason {
    match error {
        LocalApicError::DestinationNotAddressable { destination } => {
            CpuFailureReason::Topology(CpuTopologyIssue::UnsupportedApicDestination {
                apic_id: ApicId::new(destination.as_u32()),
            })
        }
        _ => CpuFailureReason::Startup(CpuStartupFailure::LocalApic),
    }
}

fn invariant_tsc_supported() -> bool {
    let maximum = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    maximum >= 0x8000_0007 && core::arch::x86_64::__cpuid(0x8000_0007).edx & (1 << 8) != 0
}

static STARTUP_CONTROLLER: Once<Result<CpuStartupController, CpuInitializationError>> = Once::new();

struct BootCpuInventory {
    discovered: usize,
    enabled: Arc<[CpuId]>,
}

static BOOT_CPU_INVENTORY: Once<BootCpuInventory> = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CpuBootSummary {
    pub discovered: usize,
    pub online: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CpuInitializationError {
    LocalApic(LocalApicError),
    Trampoline(&'static str),
    Topology(CpuTopologyIssue),
    BootstrapBinding,
}

pub(crate) fn prepare_bootstrap(boot_info: &ExoBootInfo) -> Result<(), CpuInitializationError> {
    if BOOT_CPU_INVENTORY.get().is_some() {
        return Ok(());
    }
    let local_apic = crate::drivers::apic::initialize_current_cpu()
        .map_err(CpuInitializationError::LocalApic)?;
    let bsp_apic = ApicId::new(local_apic.id());
    super::install_bootstrap(bsp_apic, Some(boot_info.tls_template))
        .map_err(CpuInitializationError::Topology)?;
    super::CurrentCpu::bind(CpuId::BOOTSTRAP)
        .map_err(|_| CpuInitializationError::BootstrapBinding)?;
    crate::task::initialize_scheduler().map_err(|_| CpuInitializationError::BootstrapBinding)?;

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
    let affinities = tables.numa_cpu_affinity().unwrap_or_default();
    let runtime = super::runtime();

    for firmware_cpu in firmware_cpus {
        if !firmware_cpu.enabled && !firmware_cpu.online_capable {
            continue;
        }
        let apic_id = ApicId::new(firmware_cpu.apic_id);
        let proximity_domain = affinities
            .iter()
            .find(|affinity| affinity.apic_id == firmware_cpu.apic_id && affinity.enabled)
            .map(|affinity| affinity.proximity_domain);
        let firmware = FirmwareCpuIdentity {
            uid: Some(FirmwareCpuUid::Integer(u64::from(
                firmware_cpu.firmware_uid,
            ))),
            apic_id,
            proximity_domain,
            eject: CpuEjectCapability::Fixed,
        };
        if apic_id == bsp_apic {
            runtime
                .identify_bootstrap(firmware)
                .map_err(CpuInitializationError::Topology)?;
            continue;
        }
        let id = runtime
            .discover_present(firmware)
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

pub(crate) fn start_boot_cpus() -> CpuBootSummary {
    let Some(inventory) = BOOT_CPU_INVENTORY.get() else {
        return CpuBootSummary {
            discovered: super::snapshot().possible().len(),
            online: super::snapshot().online().len(),
            failed: 0,
        };
    };
    let controller = STARTUP_CONTROLLER
        .get()
        .and_then(|result| result.as_ref().ok());
    let mut failed = 0usize;
    for id in inventory.enabled.iter().copied() {
        let result = match controller {
            Some(controller) => online_during_boot(controller, id),
            None => record_unavailable_trampoline(id),
        };
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

fn online_during_boot(
    controller: &CpuStartupController,
    id: CpuId,
) -> Result<(), CpuFailureReason> {
    let runtime = super::runtime();
    let slot = runtime
        .snapshot()
        .slot(id)
        .cloned()
        .ok_or(CpuFailureReason::Topology(
            CpuTopologyIssue::ConflictingFirmwareIdentity,
        ))?;
    if slot.role == CpuRole::Bootstrap || slot.state != CpuSlotState::PresentOffline {
        return Err(CpuFailureReason::Topology(
            CpuTopologyIssue::ConflictingFirmwareIdentity,
        ));
    }
    runtime.begin_start(id).map_err(runtime_failure)?;
    if let Err(error) = runtime.prepare_startup_resource(id) {
        let reason = match error {
            CpuStartupResourceError::PhysicalAllocation
            | CpuStartupResourceError::VirtualMapping => {
                CpuFailureReason::Startup(CpuStartupFailure::CpuLocalBinding)
            }
        };
        let _ = runtime.startup_failed(id, reason.clone());
        return Err(reason);
    }
    if let Err(reason) = controller.launch(id, slot.firmware.apic_id) {
        let _ = runtime.startup_failed(id, reason.clone());
        return Err(reason);
    }

    crate::task::prepare_cpu_online(id);
    runtime.startup_ready(id).map_err(runtime_failure)?;
    crate::task::publish_cpu_online(id);
    let local = runtime.cpu_local(id).ok_or(CpuFailureReason::Startup(
        CpuStartupFailure::CpuLocalBinding,
    ))?;
    local
        .remote()
        .send(super::CpuControlMessage::Start)
        .map_err(|_| CpuFailureReason::Startup(CpuStartupFailure::CpuLocalBinding))?;
    crate::cpu::send_ipi(id, super::IpiKind::ExecutorWake).map_err(map_ipi_start_error)?;
    Ok(())
}

fn map_ipi_start_error(error: super::CpuIpiError) -> CpuFailureReason {
    match error {
        super::CpuIpiError::LocalApic(error) => map_apic_start_error(error),
        super::CpuIpiError::CpuNotPresent(_) | super::CpuIpiError::CpuNotOnline(_) => {
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

fn firmware_error(error: acpi_driver::AcpiError) -> FirmwareError {
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
    if super::CurrentCpu::bind(id).is_err() {
        resource.publish(ApStartupSignal::CpuLocalBindingFailed);
        fail_stop_ap();
    }
    if crate::interrupts::load_for_current_cpu().is_err() {
        resource.publish(ApStartupSignal::InterruptTablesFailed);
        fail_stop_ap();
    }
    let local_apic = match crate::drivers::apic::initialize_current_cpu() {
        Ok(local_apic) => local_apic,
        Err(_) => {
            resource.publish(ApStartupSignal::LocalApicFailed);
            fail_stop_ap();
        }
    };
    let expected_apic = super::snapshot().slot(id).map(|slot| slot.firmware.apic_id);
    if expected_apic != Some(ApicId::new(local_apic.id())) {
        resource.publish(ApStartupSignal::ApicIdentityMismatch);
        fail_stop_ap();
    }

    crate::mm::cache::slab_cache::init_per_core_cache_for_cpu(id.as_usize());
    crate::mm::sync::tlb_batch::enter_lazy_tlb_mode(id.as_usize());
    crate::mm::numa::topology::apply_current_cpu_locality();
    local_apic.set_task_priority(0xe0);
    crate::interrupts::enable_interrupts();
    resource.publish(ApStartupSignal::ReadyParked);
    fence(Ordering::SeqCst);

    let current = super::CurrentCpu::acquire().unwrap_or_else(|| fail_stop_ap());
    loop {
        while let Some(message) = current.take_control() {
            match message {
                super::CpuControlMessage::Start => {
                    crate::interrupts::disable_interrupts();
                    local_apic.set_task_priority(0);
                    let _ = crate::mm::sync::tlb_batch::exit_lazy_tlb_mode(id.as_usize());
                    crate::mm::numa::topology::apply_current_cpu_locality();
                    crate::interrupts::enable_interrupts();
                    crate::task::run_forever();
                }
                super::CpuControlMessage::TlbShootdown { .. } => unsafe {
                    crate::mm::sync::tlb_batch::tlb_flush_ipi_handler();
                },
                super::CpuControlMessage::RcuQuiesce { epoch } => current.record_epoch(epoch),
                super::CpuControlMessage::WakeExecutor | super::CpuControlMessage::Park => {}
            }
        }
        unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    }
}

fn fail_stop_ap() -> ! {
    crate::interrupts::disable_interrupts();
    loop {
        x86_64::instructions::hlt();
    }
}
