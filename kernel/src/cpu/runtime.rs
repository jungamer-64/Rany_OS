use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::Pin;

use spin::Once;

use crate::sync::PoisonLock;

use super::{
    ApicId, CpuFailureReason, CpuId, CpuRole, CpuSet, CpuSlot, CpuSlotState, CpuStateTransition,
    CpuStateTransitionError, CpuTopologyIssue, FirmwareCpuIdentity, MAX_POSSIBLE_CPUS,
    PhysicalHotplugStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSnapshot {
    revision: u64,
    slots: Arc<[CpuSlot]>,
    possible: CpuSet,
    present: CpuSet,
    online: CpuSet,
    physical_hotplug: PhysicalHotplugStatus,
}

impl CpuSnapshot {
    fn build(
        revision: u64,
        slots: &[CpuSlot],
        physical_hotplug: PhysicalHotplugStatus,
    ) -> Result<Self, CpuTopologyIssue> {
        let capacity = slots.len();
        let mut possible =
            CpuSet::new(capacity).map_err(|_| CpuTopologyIssue::TooManyPossibleCpus {
                limit: MAX_POSSIBLE_CPUS,
            })?;
        let mut present =
            CpuSet::new(capacity).map_err(|_| CpuTopologyIssue::TooManyPossibleCpus {
                limit: MAX_POSSIBLE_CPUS,
            })?;
        let mut online =
            CpuSet::new(capacity).map_err(|_| CpuTopologyIssue::TooManyPossibleCpus {
                limit: MAX_POSSIBLE_CPUS,
            })?;

        for slot in slots {
            possible
                .insert(slot.id)
                .map_err(|_| CpuTopologyIssue::TooManyPossibleCpus {
                    limit: MAX_POSSIBLE_CPUS,
                })?;
            if slot.state.is_present() {
                present
                    .insert(slot.id)
                    .map_err(|_| CpuTopologyIssue::TooManyPossibleCpus {
                        limit: MAX_POSSIBLE_CPUS,
                    })?;
            }
            if slot.state.is_schedulable() {
                online
                    .insert(slot.id)
                    .map_err(|_| CpuTopologyIssue::TooManyPossibleCpus {
                        limit: MAX_POSSIBLE_CPUS,
                    })?;
            }
        }

        Ok(Self {
            revision,
            slots: Arc::from(slots.to_vec()),
            possible,
            present,
            online,
            physical_hotplug,
        })
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn slots(&self) -> &[CpuSlot] {
        &self.slots
    }

    pub fn slot(&self, id: CpuId) -> Option<&CpuSlot> {
        self.slots.get(id.as_usize()).filter(|slot| slot.id == id)
    }

    pub fn possible(&self) -> &CpuSet {
        &self.possible
    }

    pub fn present(&self) -> &CpuSet {
        &self.present
    }

    pub fn online(&self) -> &CpuSet {
        &self.online
    }

    pub fn physical_hotplug(&self) -> &PhysicalHotplugStatus {
        &self.physical_hotplug
    }

    pub fn cpu_for_apic(&self, apic_id: ApicId) -> Option<CpuId> {
        self.slots
            .iter()
            .find(|slot| slot.firmware.apic_id == apic_id)
            .map(|slot| slot.id)
    }
}

struct CpuRuntimeState {
    revision: u64,
    slots: Vec<CpuSlot>,
    locals: Vec<Pin<alloc::boxed::Box<super::CpuLocal>>>,
    startup_resources: Vec<Option<Pin<alloc::boxed::Box<super::CpuStartupResources>>>>,
    tls_template: Option<boot_proto::TlsInfo>,
    physical_hotplug: PhysicalHotplugStatus,
    published: Arc<CpuSnapshot>,
}

impl CpuRuntimeState {
    fn bootstrap(
        apic_id: ApicId,
        tls_template: Option<boot_proto::TlsInfo>,
    ) -> Result<Self, super::CpuLocalAllocationError> {
        let slots = alloc::vec![CpuSlot::bootstrap(apic_id)];
        let locals = alloc::vec![super::CpuLocal::allocate(CpuId::BOOTSTRAP, tls_template)?];
        let mut startup_resources = Vec::new();
        startup_resources.push(None);
        let physical_hotplug = PhysicalHotplugStatus::Unavailable(super::FirmwareError {
            kind: super::FirmwareErrorKind::Namespace,
            object: None,
            detail: alloc::string::String::from("ACPI runtime has not completed initialization"),
        });
        let published = match CpuSnapshot::build(0, &slots, physical_hotplug.clone()) {
            Ok(snapshot) => Arc::new(snapshot),
            Err(_) => unreachable!("a single bootstrap CPU always fits the architectural limit"),
        };
        Ok(Self {
            revision: 0,
            slots,
            locals,
            startup_resources,
            tls_template,
            physical_hotplug,
            published,
        })
    }

    fn publish(&mut self) -> Result<(), CpuTopologyIssue> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(CpuTopologyIssue::RevisionExhausted)?;
        self.published = Arc::new(CpuSnapshot::build(
            self.revision,
            &self.slots,
            self.physical_hotplug.clone(),
        )?);
        Ok(())
    }
}

pub(crate) struct CpuRuntime {
    state: PoisonLock<CpuRuntimeState>,
}

impl CpuRuntime {
    pub(crate) fn bootstrap(
        apic_id: ApicId,
        tls_template: Option<boot_proto::TlsInfo>,
    ) -> Result<Self, super::CpuLocalAllocationError> {
        Ok(Self {
            state: PoisonLock::new(CpuRuntimeState::bootstrap(apic_id, tls_template)?),
        })
    }

    pub(crate) fn snapshot(&self) -> Arc<CpuSnapshot> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .published
            .clone()
    }

    pub(crate) fn set_physical_hotplug(
        &self,
        status: PhysicalHotplugStatus,
    ) -> Result<(), CpuTopologyIssue> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.physical_hotplug = status;
        state.publish()
    }

    pub(crate) fn cpu_local(&'static self, id: CpuId) -> Option<&'static super::CpuLocal> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let local = state.locals.get(id.as_usize())?;
        let pointer = local.as_ref().get_ref() as *const super::CpuLocal;
        drop(state);
        // SAFETY: CpuRuntime is static, every CpuLocal is pinned, and slot
        // allocations remain owned until a post-eject grace-period retirement.
        Some(unsafe { &*pointer })
    }

    pub(crate) fn cpu_local_by_address(
        &'static self,
        address: usize,
    ) -> Option<&'static super::CpuLocal> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let local = state
            .locals
            .iter()
            .map(|local| local.as_ref().get_ref())
            .find(|local| *local as *const super::CpuLocal as usize == address)?;
        let pointer = local as *const super::CpuLocal;
        drop(state);
        // SAFETY: the allocation is pinned and remains owned by the static
        // runtime until resource retirement after an eject grace period.
        Some(unsafe { &*pointer })
    }

    pub(crate) fn prepare_startup_resource(
        &'static self,
        id: CpuId,
    ) -> Result<&'static super::CpuStartupResources, super::CpuStartupResourceError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let index = id.as_usize();
        if state.slots.get(index).is_none_or(|slot| slot.id != id) {
            return Err(super::CpuStartupResourceError::PhysicalAllocation);
        }
        if state.startup_resources[index].is_none() {
            state.startup_resources[index] = Some(super::CpuStartupResources::allocate()?);
        }
        let resource = state.startup_resources[index]
            .as_ref()
            .expect("startup resource was installed")
            .as_ref()
            .get_ref() as *const super::CpuStartupResources;
        drop(state);
        // SAFETY: startup resources are pinned and retained by the static CPU
        // runtime across logical offline/online cycles.
        Ok(unsafe { &*resource })
    }

    pub(crate) fn startup_resource(
        &'static self,
        id: CpuId,
    ) -> Option<&'static super::CpuStartupResources> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let resource = state
            .startup_resources
            .get(id.as_usize())?
            .as_ref()?
            .as_ref()
            .get_ref() as *const super::CpuStartupResources;
        drop(state);
        // SAFETY: see prepare_startup_resource; the pinned allocation remains
        // runtime-owned until an explicit post-eject retirement path removes it.
        Some(unsafe { &*resource })
    }

    pub(crate) fn identify_bootstrap(
        &self,
        firmware: FirmwareCpuIdentity,
    ) -> Result<(), CpuTopologyIssue> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if firmware.apic_id != state.slots[CpuId::BOOTSTRAP.as_usize()].firmware.apic_id {
            return Err(CpuTopologyIssue::ConflictingFirmwareIdentity);
        }
        if let Some(uid) = firmware.uid.as_ref()
            && state
                .slots
                .iter()
                .skip(1)
                .any(|slot| slot.firmware.uid.as_ref() == Some(uid))
        {
            return Err(CpuTopologyIssue::DuplicateUid { uid: uid.clone() });
        }
        let bootstrap = &mut state.slots[CpuId::BOOTSTRAP.as_usize()];
        bootstrap.firmware.uid = firmware.uid;
        bootstrap.firmware.proximity_domain = firmware.proximity_domain;
        bootstrap.firmware.eject = super::CpuEjectCapability::Fixed;
        state.publish()
    }

    pub(crate) fn discover_present(
        &self,
        firmware: FirmwareCpuIdentity,
    ) -> Result<CpuId, CpuTopologyIssue> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let (id, metadata_changed) = ensure_possible_slot(&mut state, firmware)?;
        let slot = &mut state.slots[id.as_usize()];
        let became_present = if slot.state == CpuSlotState::FirmwareAbsent {
            slot.transition(CpuStateTransition::FirmwarePresent)
                .map_err(map_state_error)?;
            true
        } else {
            false
        };
        if metadata_changed || became_present {
            state.publish()?;
        }
        Ok(id)
    }

    /// Registers a firmware-described CPU slot without asserting presence.
    ///
    /// Repeated namespace scans return the original `CpuId`; changing either
    /// side of an established UID/APIC identity is rejected as a topology
    /// conflict rather than allocating a replacement slot.
    pub(crate) fn discover_possible(
        &self,
        firmware: FirmwareCpuIdentity,
    ) -> Result<CpuId, CpuTopologyIssue> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let (id, metadata_changed) = ensure_possible_slot(&mut state, firmware)?;
        if metadata_changed {
            state.publish()?;
        }
        Ok(id)
    }

    pub(crate) fn begin_start(&self, id: CpuId) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::BeginStart)
    }

    pub(crate) fn startup_ready(&self, id: CpuId) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::StartupReady)
    }

    pub(crate) fn startup_failed(
        &self,
        id: CpuId,
        reason: CpuFailureReason,
    ) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::StartupFailed(reason))
    }

    pub(crate) fn begin_drain(&self, id: CpuId) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::BeginDrain)
    }

    pub(crate) fn drain_aborted(
        &self,
        id: CpuId,
        reason: CpuFailureReason,
    ) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::DrainAborted(reason))
    }

    pub(crate) fn drain_failed(
        &self,
        id: CpuId,
        reason: CpuFailureReason,
    ) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::DrainFailed(reason))
    }

    pub(crate) fn drain_complete(&self, id: CpuId) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::DrainComplete)
    }

    pub(crate) fn begin_eject(&self, id: CpuId) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::BeginEject)
    }

    pub(crate) fn eject_complete(&self, id: CpuId) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::EjectComplete)
    }

    pub(crate) fn eject_failed(
        &self,
        id: CpuId,
        reason: CpuFailureReason,
    ) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::EjectFailed(reason))
    }

    fn transition(&self, id: CpuId, transition: CpuStateTransition) -> Result<(), CpuRuntimeError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let slot = state
            .slots
            .get_mut(id.as_usize())
            .filter(|slot| slot.id == id)
            .ok_or(CpuRuntimeError::UnknownCpu(id))?;
        slot.transition(transition)
            .map_err(CpuRuntimeError::State)?;
        state.publish().map_err(CpuRuntimeError::Topology)
    }
}

fn ensure_possible_slot(
    state: &mut CpuRuntimeState,
    firmware: FirmwareCpuIdentity,
) -> Result<(CpuId, bool), CpuTopologyIssue> {
    if let Some(index) = state.slots.iter().position(|slot| {
        slot.firmware.apic_id == firmware.apic_id && slot.firmware.uid == firmware.uid
    }) {
        let slot = &mut state.slots[index];
        let metadata_changed = slot.firmware.proximity_domain != firmware.proximity_domain
            || slot.firmware.eject != firmware.eject;
        slot.firmware.proximity_domain = firmware.proximity_domain;
        slot.firmware.eject = firmware.eject;
        return Ok((slot.id, metadata_changed));
    }

    if let Some(uid) = firmware.uid.as_ref()
        && state
            .slots
            .iter()
            .any(|slot| slot.firmware.uid.as_ref() == Some(uid))
    {
        return Err(CpuTopologyIssue::DuplicateUid { uid: uid.clone() });
    }
    if state
        .slots
        .iter()
        .any(|slot| slot.firmware.apic_id == firmware.apic_id)
    {
        return Err(CpuTopologyIssue::DuplicateApicId {
            apic_id: firmware.apic_id,
        });
    }
    if state.slots.len() >= MAX_POSSIBLE_CPUS {
        return Err(CpuTopologyIssue::TooManyPossibleCpus {
            limit: MAX_POSSIBLE_CPUS,
        });
    }

    let id = CpuId::from_valid_index(state.slots.len());
    let local = super::CpuLocal::allocate(id, state.tls_template)
        .map_err(|_| CpuTopologyIssue::CpuLocalAllocationFailed { id })?;
    state
        .slots
        .push(CpuSlot::absent(id, CpuRole::Application, firmware));
    state.locals.push(local);
    state.startup_resources.push(None);
    Ok((id, true))
}

fn map_state_error(error: CpuStateTransitionError) -> CpuTopologyIssue {
    match error {
        CpuStateTransitionError::BootstrapCpu => CpuTopologyIssue::ConflictingFirmwareIdentity,
        CpuStateTransitionError::Illegal { .. } => CpuTopologyIssue::ConflictingFirmwareIdentity,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CpuRuntimeError {
    UnknownCpu(CpuId),
    State(CpuStateTransitionError),
    Topology(CpuTopologyIssue),
}

static CPU_RUNTIME: Once<CpuRuntime> = Once::new();

pub(crate) fn install_bootstrap(
    apic_id: ApicId,
    tls_template: Option<boot_proto::TlsInfo>,
) -> Result<(), CpuTopologyIssue> {
    if let Some(runtime) = CPU_RUNTIME.get() {
        let snapshot = runtime.snapshot();
        let bootstrap = snapshot
            .slot(CpuId::BOOTSTRAP)
            .ok_or(CpuTopologyIssue::ConflictingFirmwareIdentity)?;
        if bootstrap.firmware.apic_id != apic_id {
            return Err(CpuTopologyIssue::ConflictingFirmwareIdentity);
        }
        return Ok(());
    }
    let runtime = CpuRuntime::bootstrap(apic_id, tls_template).map_err(|_| {
        CpuTopologyIssue::CpuLocalAllocationFailed {
            id: CpuId::BOOTSTRAP,
        }
    })?;
    CPU_RUNTIME.call_once(|| runtime);
    Ok(())
}

pub(crate) fn try_runtime() -> Option<&'static CpuRuntime> {
    CPU_RUNTIME.get()
}

pub(crate) fn runtime() -> &'static CpuRuntime {
    CPU_RUNTIME
        .get()
        .expect("CPU runtime must be installed before topology is observed")
}

pub fn snapshot() -> Arc<CpuSnapshot> {
    runtime().snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{CpuEjectCapability, FirmwareCpuUid};

    fn firmware(uid: u64, apic: u32) -> FirmwareCpuIdentity {
        FirmwareCpuIdentity {
            uid: Some(FirmwareCpuUid::Integer(uid)),
            apic_id: ApicId::new(apic),
            proximity_domain: Some(0),
            eject: CpuEjectCapability::FirmwareEject,
        }
    }

    #[test]
    fn sparse_snapshot_keeps_cpu_ids_instead_of_dense_count() {
        let runtime = CpuRuntime::bootstrap(ApicId::new(0), None).unwrap();
        let cpu1 = runtime.discover_present(firmware(1, 1)).unwrap();
        let cpu2 = runtime.discover_present(firmware(2, 2)).unwrap();
        runtime.begin_start(cpu2).unwrap();
        runtime.startup_ready(cpu2).unwrap();

        let snapshot = runtime.snapshot();
        assert_eq!(
            snapshot.online().iter().collect::<Vec<_>>(),
            [CpuId::BOOTSTRAP, cpu2]
        );
        assert!(!snapshot.online().contains(cpu1));
    }

    #[test]
    fn absent_namespace_slot_reuses_cpu_id_when_it_becomes_present() {
        let runtime = CpuRuntime::bootstrap(ApicId::new(0), None).unwrap();
        let identity = firmware(9, 9);
        let possible = runtime.discover_possible(identity.clone()).unwrap();
        assert_eq!(
            runtime.snapshot().slot(possible).unwrap().state,
            CpuSlotState::FirmwareAbsent
        );

        let present = runtime.discover_present(identity).unwrap();
        assert_eq!(present, possible);
        assert_eq!(
            runtime.snapshot().slot(present).unwrap().state,
            CpuSlotState::PresentOffline
        );
    }

    #[test]
    fn duplicate_uid_and_apic_are_rejected_before_online() {
        let runtime = CpuRuntime::bootstrap(ApicId::new(0), None).unwrap();
        runtime.discover_present(firmware(7, 10)).unwrap();
        assert!(matches!(
            runtime.discover_present(firmware(7, 11)),
            Err(CpuTopologyIssue::DuplicateUid { .. })
        ));
        assert!(matches!(
            runtime.discover_present(firmware(8, 10)),
            Err(CpuTopologyIssue::DuplicateApicId { .. })
        ));
    }

    #[test]
    fn readd_reuses_the_same_firmware_slot() {
        let runtime = CpuRuntime::bootstrap(ApicId::new(0), None).unwrap();
        let id = runtime.discover_present(firmware(9, 9)).unwrap();
        runtime.begin_start(id).unwrap();
        runtime.startup_ready(id).unwrap();
        runtime.begin_drain(id).unwrap();
        runtime.drain_complete(id).unwrap();
        runtime.begin_eject(id).unwrap();
        runtime.eject_complete(id).unwrap();

        let readded = runtime.discover_present(firmware(9, 9)).unwrap();
        assert_eq!(readded, id);
        assert_eq!(
            runtime.snapshot().slot(id).map(|slot| slot.state),
            Some(CpuSlotState::PresentOffline)
        );
    }

    #[test]
    fn immutable_snapshot_is_not_rewritten_after_publication() {
        let runtime = CpuRuntime::bootstrap(ApicId::new(0), None).unwrap();
        let before = runtime.snapshot();
        runtime.discover_present(firmware(1, 1)).unwrap();
        let after = runtime.snapshot();
        assert_eq!(before.possible().len(), 1);
        assert_eq!(after.possible().len(), 2);
        assert!(after.revision() > before.revision());
    }

    #[test]
    fn fixed_cpu_eject_capability_is_preserved() {
        let runtime = CpuRuntime::bootstrap(ApicId::new(0), None).unwrap();
        assert_eq!(
            runtime
                .snapshot()
                .slot(CpuId::BOOTSTRAP)
                .map(|slot| slot.firmware.eject),
            Some(CpuEjectCapability::Fixed)
        );
    }
}
