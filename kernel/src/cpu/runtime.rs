use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::Pin;

use crate::sync::InitOnce;

use crate::sync::PoisonLock;

use super::{
    ApicId, CpuFailureReason, CpuId, CpuRole, CpuSet, CpuSlot, CpuSlotState, CpuStateTransition,
    CpuStateTransitionError, CpuTopologyIssue, FirmwareCpuIdentity, LocatedCpu, MAX_POSSIBLE_CPUS,
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
        located: LocatedCpu,
        tls_template: Option<boot_proto::TlsInfo>,
    ) -> Result<Self, super::CpuLocalAllocationError> {
        let (mut firmware, node) = located.into_parts();
        firmware.eject = super::CpuEjectCapability::Fixed;
        let mut bootstrap = CpuSlot::bootstrap(firmware.apic_id);
        bootstrap.firmware = firmware;
        let local = super::CpuLocal::allocate(CpuId::BOOTSTRAP, tls_template)?;
        local.as_ref().get_ref().remote().set_numa_node(node);
        let slots = alloc::vec![bootstrap];
        let locals = alloc::vec![local];
        let mut startup_resources = Vec::new();
        startup_resources.push(None);
        let physical_hotplug = PhysicalHotplugStatus::Initializing;
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
        located: LocatedCpu,
        tls_template: Option<boot_proto::TlsInfo>,
    ) -> Result<Self, super::CpuLocalAllocationError> {
        Ok(Self {
            state: PoisonLock::new(CpuRuntimeState::bootstrap(located, tls_template)?),
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

    pub(crate) fn prepare_startup_resource(
        &'static self,
        id: CpuId,
    ) -> Result<&'static super::CpuStartupResources, super::CpuStartupResourceError> {
        let index = id.as_usize();
        {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.slots.get(index).is_none_or(|slot| slot.id != id) {
                return Err(super::CpuStartupResourceError::PhysicalAllocation);
            }
            if let Some(resource) = state.startup_resources[index].as_ref() {
                let resource = resource.as_ref().get_ref() as *const super::CpuStartupResources;
                drop(state);
                // SAFETY: startup resources are pinned and retained by the
                // static runtime across logical offline/online cycles.
                return Ok(unsafe { &*resource });
            }
        }

        // Allocation and mapping may publish TLB work through the CPU runtime.
        // Build the candidate without the topology lock, then atomically install
        // it after revalidating the stable slot identity.
        let candidate = super::CpuStartupResources::allocate()?;
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.slots.get(index).is_none_or(|slot| slot.id != id) {
            drop(state);
            drop(candidate);
            return Err(super::CpuStartupResourceError::PhysicalAllocation);
        }
        let unused = if state.startup_resources[index].is_none() {
            state.startup_resources[index] = Some(candidate);
            None
        } else {
            Some(candidate)
        };
        let resource = state.startup_resources[index]
            .as_ref()
            .expect("startup resource was installed")
            .as_ref()
            .get_ref() as *const super::CpuStartupResources;
        drop(state);
        // An unneeded racing candidate must unmap only after the topology lock
        // is released because teardown can publish TLB work through this runtime.
        drop(unused);
        // SAFETY: the installed resource is pinned and retained by the static
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

    pub(crate) fn identify_bootstrap(&self, located: LocatedCpu) -> Result<(), CpuTopologyIssue> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let (mut firmware, node) = located.into_parts();
        if firmware.apic_id != state.slots[0].firmware.apic_id {
            return Err(CpuTopologyIssue::ConflictingFirmwareIdentity);
        }
        check_memory_placement(&state, CpuId::BOOTSTRAP, node)?;
        if let Some(uid) = firmware.uid.as_ref()
            && state
                .slots
                .iter()
                .skip(1)
                .any(|slot| slot.firmware.uid.as_ref() == Some(uid))
        {
            return Err(CpuTopologyIssue::DuplicateUid { uid: uid.clone() });
        }
        firmware.eject = super::CpuEjectCapability::Fixed;
        state.slots[0].firmware = firmware;
        state.publish()
    }

    /// Locality is committed to stable backing before presence is published.
    /// A re-added physical generation may change node only after eject/drain.
    pub(crate) fn discover_present(&self, located: LocatedCpu) -> Result<CpuId, CpuTopologyIssue> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let (id, changed) = admit_located_slot(&mut state, located)?;
        let index = id.as_usize();
        let became_present = if state.slots[index].state == CpuSlotState::FirmwareAbsent {
            let local = state.locals[index].as_ref().get_ref();
            // SAFETY: the serialized discovery worker owns the absent slot;
            // firmware absence requires completed drain, park and eject.
            unsafe { local.rearm_physical_generation() }
                .map_err(|resource| CpuTopologyIssue::CpuGenerationNotQuiescent { id, resource })?;
            state.slots[index]
                .transition(CpuStateTransition::FirmwarePresent)
                .map_err(map_state_error)?;
            true
        } else {
            false
        };
        if changed || became_present {
            state.publish()?;
        }
        Ok(id)
    }

    pub(crate) fn discover_possible(&self, located: LocatedCpu) -> Result<CpuId, CpuTopologyIssue> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let (id, changed) = admit_located_slot(&mut state, located)?;
        if changed {
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

    pub(crate) fn drain_rejected(
        &self,
        id: CpuId,
        reason: CpuFailureReason,
    ) -> Result<(), CpuRuntimeError> {
        self.transition(id, CpuStateTransition::DrainRejected(reason))
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

fn check_memory_placement(
    state: &CpuRuntimeState,
    id: CpuId,
    requested: crate::mm::types::NumaNodeId,
) -> Result<(), CpuTopologyIssue> {
    if let Some(current) = state.locals[id.as_usize()]
        .as_ref()
        .get_ref()
        .remote()
        .numa_node()
        .map(crate::mm::types::NumaNodeId::new)
        && current != requested
        && state.slots[id.as_usize()].state != CpuSlotState::FirmwareAbsent
    {
        return Err(CpuTopologyIssue::MemoryPlacementConflict {
            id,
            current,
            requested,
        });
    }
    Ok(())
}

fn admit_located_slot(
    state: &mut CpuRuntimeState,
    located: LocatedCpu,
) -> Result<(CpuId, bool), CpuTopologyIssue> {
    let (firmware, node) = located.into_parts();
    if let Some(index) = state.slots.iter().position(|slot| {
        slot.firmware.apic_id == firmware.apic_id && slot.firmware.uid == firmware.uid
    }) {
        let id = state.slots[index].id;
        check_memory_placement(state, id, node)?;
        let local = state.locals[index].as_ref().get_ref();
        let changed = state.slots[index].firmware != firmware
            || local.remote().numa_node() != Some(node.as_u8());
        // An absent CPU has no cache borrower or running physical generation.
        // For a present CPU check_memory_placement forbids a locality change.
        local.remote().set_numa_node(node);
        state.slots[index].firmware = firmware;
        return Ok((id, changed));
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

    let id = CpuId::try_from(state.slots.len()).expect("bounded CPU index");
    let local = super::CpuLocal::allocate(id, state.tls_template)
        .map_err(|_| CpuTopologyIssue::CpuLocalAllocationFailed { id })?;
    local.as_ref().get_ref().remote().set_numa_node(node);
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

static CPU_RUNTIME: InitOnce<CpuRuntime> = InitOnce::new();

pub(crate) fn install_bootstrap(
    located: LocatedCpu,
    tls_template: Option<boot_proto::TlsInfo>,
) -> Result<(), CpuTopologyIssue> {
    if let Some(runtime) = CPU_RUNTIME.get() {
        let snapshot = runtime.snapshot();
        let bootstrap = snapshot
            .slot(CpuId::BOOTSTRAP)
            .ok_or(CpuTopologyIssue::ConflictingFirmwareIdentity)?;
        if bootstrap.firmware.apic_id != located.firmware().apic_id {
            return Err(CpuTopologyIssue::ConflictingFirmwareIdentity);
        }
        let state = runtime
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        check_memory_placement(&state, CpuId::BOOTSTRAP, located.memory_node())?;
        return Ok(());
    }
    let runtime = CpuRuntime::bootstrap(located, tls_template).map_err(|_| {
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

    fn firmware(uid: u64, apic: u32) -> LocatedCpu {
        let placement =
            crate::mm::numa::placement::NumaPlacement::try_new(&[], &[], |_, _| Some(10)).unwrap();
        LocatedCpu::resolve(
            FirmwareCpuIdentity {
                uid: Some(FirmwareCpuUid::Integer(uid)),
                apic_id: ApicId::new(apic),
                proximity_domain: Some(0),
                eject: CpuEjectCapability::FirmwareEject,
            },
            &placement,
        )
        .unwrap()
    }

    #[test]
    fn namespace_only_locality_is_bound_before_publish_and_changes_only_after_eject() {
        use crate::mm::numa::placement::{CpuAffinity, NumaPlacement};
        use crate::mm::types::NumaNodeId;
        let placement = NumaPlacement::try_new(
            &[
                CpuAffinity {
                    apic_id: ApicId::new(0),
                    proximity_domain: 2,
                },
                CpuAffinity {
                    apic_id: ApicId::new(1),
                    proximity_domain: 9,
                },
            ],
            &[],
            |a, b| Some(if a == b { 10 } else { 20 }),
        )
        .unwrap();
        let locate = |apic, domain| {
            LocatedCpu::resolve(
                FirmwareCpuIdentity {
                    uid: Some(FirmwareCpuUid::Integer(apic as u64)),
                    apic_id: ApicId::new(apic),
                    proximity_domain: Some(domain),
                    eject: CpuEjectCapability::FirmwareEject,
                },
                &placement,
            )
            .unwrap()
        };
        let runtime = CpuRuntime::bootstrap(locate(0, 2), None).unwrap();
        let id = runtime.discover_present(locate(77, 9)).unwrap();
        let local_node = || {
            runtime
                .state
                .lock()
                .unwrap_or_else(|_| panic!("fixture runtime lock poisoned"))
                .locals[id.as_usize()]
            .as_ref()
            .get_ref()
            .remote()
            .numa_node()
        };
        assert_eq!(
            runtime.snapshot().slot(id).unwrap().state,
            CpuSlotState::PresentOffline
        );
        assert_eq!(local_node(), Some(1));
        let revision = runtime.snapshot().revision();
        assert_eq!(
            runtime.discover_possible(locate(77, 2)),
            Err(CpuTopologyIssue::MemoryPlacementConflict {
                id,
                current: NumaNodeId::new(1),
                requested: NumaNodeId::NODE_0,
            })
        );
        assert_eq!(runtime.snapshot().revision(), revision);
        assert_eq!(local_node(), Some(1));
        runtime.begin_start(id).unwrap();
        runtime.startup_ready(id).unwrap();
        runtime.begin_drain(id).unwrap();
        runtime.drain_complete(id).unwrap();
        runtime.begin_eject(id).unwrap();
        runtime.eject_complete(id).unwrap();
        assert_eq!(runtime.discover_present(locate(77, 2)), Ok(id));
        assert_eq!(local_node(), Some(0));
    }

    #[test]
    fn sparse_snapshot_keeps_cpu_ids_instead_of_dense_count() {
        let runtime = CpuRuntime::bootstrap(firmware(0, 0), None).unwrap();
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
        let runtime = CpuRuntime::bootstrap(firmware(0, 0), None).unwrap();
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
        let runtime = CpuRuntime::bootstrap(firmware(0, 0), None).unwrap();
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
        let runtime = CpuRuntime::bootstrap(firmware(0, 0), None).unwrap();
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
        let runtime = CpuRuntime::bootstrap(firmware(0, 0), None).unwrap();
        let before = runtime.snapshot();
        runtime.discover_present(firmware(1, 1)).unwrap();
        let after = runtime.snapshot();
        assert_eq!(before.possible().len(), 1);
        assert_eq!(after.possible().len(), 2);
        assert!(after.revision() > before.revision());
    }

    #[test]
    fn fixed_cpu_eject_capability_is_preserved() {
        let runtime = CpuRuntime::bootstrap(firmware(0, 0), None).unwrap();
        assert_eq!(
            runtime
                .snapshot()
                .slot(CpuId::BOOTSTRAP)
                .map(|slot| slot.firmware.eject),
            Some(CpuEjectCapability::Fixed)
        );
    }
}
