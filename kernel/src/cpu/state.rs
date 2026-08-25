use alloc::string::String;
use alloc::sync::Arc;

use super::{ApicId, CpuId, CpuRole, FirmwareCpuUid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuSlotState {
    FirmwareAbsent,
    PresentOffline,
    Starting,
    Online,
    Draining,
    Parked,
    Ejecting,
}

impl CpuSlotState {
    pub const fn name(self) -> &'static str {
        match self {
            Self::FirmwareAbsent => "firmware-absent",
            Self::PresentOffline => "present-offline",
            Self::Starting => "starting",
            Self::Online => "online",
            Self::Draining => "draining",
            Self::Parked => "parked",
            Self::Ejecting => "ejecting",
        }
    }

    pub const fn is_present(self) -> bool {
        !matches!(self, Self::FirmwareAbsent)
    }

    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Online)
    }

    pub(crate) const fn participates_in_tlb(self) -> bool {
        matches!(self, Self::Starting | Self::Online | Self::Draining)
    }

    pub(crate) const fn participates_in_rcu(self) -> bool {
        matches!(self, Self::Online | Self::Draining)
    }

    pub(crate) const fn accepts_executor_wake(self) -> bool {
        matches!(self, Self::Online | Self::Draining)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuEjectCapability {
    Fixed,
    FirmwareEject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareCpuIdentity {
    pub uid: Option<FirmwareCpuUid>,
    pub apic_id: ApicId,
    pub proximity_domain: Option<u32>,
    pub eject: CpuEjectCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuFailurePhase {
    Discovery,
    Start,
    Drain,
    Eject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuFailureReason {
    MissingRequiredFeature { feature: &'static str },
    Startup(CpuStartupFailure),
    Drain(CpuDrainFailure),
    TscInconsistent,
    NumaInconsistent,
    StartupAcknowledgementTimedOut,
    DrainTimedOut,
    Firmware(FirmwareError),
    Topology(CpuTopologyIssue),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuStartupFailure {
    Trampoline,
    CpuLocalBinding,
    InterruptTables,
    LocalApic,
    Timer,
    SlabCache,
    TlbState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuDrainFailure {
    ControlQueueSaturated,
    IpiDelivery,
    Blocked { blockers: Arc<[CpuBlocker]> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuFailure {
    pub phase: CpuFailurePhase,
    pub reason: CpuFailureReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSlot {
    pub id: CpuId,
    pub role: CpuRole,
    pub firmware: FirmwareCpuIdentity,
    pub state: CpuSlotState,
    pub last_failure: Option<CpuFailure>,
    startup_origin: Option<CpuStartupOrigin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuStartupOrigin {
    PresentOffline,
    Parked,
}

impl CpuSlot {
    pub(crate) fn bootstrap(apic_id: ApicId) -> Self {
        Self {
            id: CpuId::BOOTSTRAP,
            role: CpuRole::Bootstrap,
            firmware: FirmwareCpuIdentity {
                uid: None,
                apic_id,
                proximity_domain: None,
                eject: CpuEjectCapability::Fixed,
            },
            state: CpuSlotState::Online,
            last_failure: None,
            startup_origin: None,
        }
    }

    pub(crate) fn absent(id: CpuId, role: CpuRole, firmware: FirmwareCpuIdentity) -> Self {
        Self {
            id,
            role,
            firmware,
            state: CpuSlotState::FirmwareAbsent,
            last_failure: None,
            startup_origin: None,
        }
    }

    pub(crate) fn transition(
        &mut self,
        transition: CpuStateTransition,
    ) -> Result<(), CpuStateTransitionError> {
        let from = self.state;
        let (next, failure, startup_origin) = match (from, transition) {
            (CpuSlotState::FirmwareAbsent, CpuStateTransition::FirmwarePresent) => {
                (CpuSlotState::PresentOffline, None, None)
            }
            (CpuSlotState::PresentOffline, CpuStateTransition::BeginStart) => (
                CpuSlotState::Starting,
                None,
                Some(CpuStartupOrigin::PresentOffline),
            ),
            (CpuSlotState::Parked, CpuStateTransition::BeginStart) => {
                (CpuSlotState::Starting, None, Some(CpuStartupOrigin::Parked))
            }
            (CpuSlotState::Starting, CpuStateTransition::StartupReady) => {
                (CpuSlotState::Online, None, None)
            }
            (CpuSlotState::Starting, CpuStateTransition::StartupFailed(reason)) => {
                let next = match self.startup_origin {
                    Some(CpuStartupOrigin::PresentOffline) => CpuSlotState::PresentOffline,
                    Some(CpuStartupOrigin::Parked) => CpuSlotState::Parked,
                    None => {
                        return Err(CpuStateTransitionError::Illegal {
                            from,
                            attempted: CpuStateTransitionKind::StartupFailed,
                        });
                    }
                };
                (
                    next,
                    Some(CpuFailure {
                        phase: CpuFailurePhase::Start,
                        reason,
                    }),
                    None,
                )
            }
            (CpuSlotState::Online, CpuStateTransition::BeginDrain) => {
                if self.role == CpuRole::Bootstrap {
                    return Err(CpuStateTransitionError::BootstrapCpu);
                }
                (CpuSlotState::Draining, None, None)
            }
            (CpuSlotState::Draining, CpuStateTransition::DrainAborted(reason)) => (
                CpuSlotState::Online,
                Some(CpuFailure {
                    phase: CpuFailurePhase::Drain,
                    reason,
                }),
                None,
            ),
            (CpuSlotState::Draining, CpuStateTransition::DrainFailed(reason)) => (
                CpuSlotState::Draining,
                Some(CpuFailure {
                    phase: CpuFailurePhase::Drain,
                    reason,
                }),
                None,
            ),
            (CpuSlotState::Draining, CpuStateTransition::DrainComplete) => {
                (CpuSlotState::Parked, self.last_failure.clone(), None)
            }
            (
                CpuSlotState::Parked | CpuSlotState::PresentOffline,
                CpuStateTransition::BeginEject,
            ) => (CpuSlotState::Ejecting, None, None),
            (CpuSlotState::Ejecting, CpuStateTransition::EjectComplete) => {
                (CpuSlotState::FirmwareAbsent, None, None)
            }
            (CpuSlotState::Ejecting, CpuStateTransition::EjectFailed(reason)) => (
                CpuSlotState::PresentOffline,
                Some(CpuFailure {
                    phase: CpuFailurePhase::Eject,
                    reason,
                }),
                None,
            ),
            (_, attempted) => {
                return Err(CpuStateTransitionError::Illegal {
                    from,
                    attempted: attempted.kind(),
                });
            }
        };

        self.state = next;
        self.last_failure = failure;
        self.startup_origin = startup_origin;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CpuStateTransition {
    FirmwarePresent,
    BeginStart,
    StartupReady,
    StartupFailed(CpuFailureReason),
    BeginDrain,
    DrainAborted(CpuFailureReason),
    DrainFailed(CpuFailureReason),
    DrainComplete,
    BeginEject,
    EjectComplete,
    EjectFailed(CpuFailureReason),
}

impl CpuStateTransition {
    const fn kind(&self) -> CpuStateTransitionKind {
        match self {
            Self::FirmwarePresent => CpuStateTransitionKind::FirmwarePresent,
            Self::BeginStart => CpuStateTransitionKind::BeginStart,
            Self::StartupReady => CpuStateTransitionKind::StartupReady,
            Self::StartupFailed(_) => CpuStateTransitionKind::StartupFailed,
            Self::BeginDrain => CpuStateTransitionKind::BeginDrain,
            Self::DrainAborted(_) => CpuStateTransitionKind::DrainAborted,
            Self::DrainFailed(_) => CpuStateTransitionKind::DrainFailed,
            Self::DrainComplete => CpuStateTransitionKind::DrainComplete,
            Self::BeginEject => CpuStateTransitionKind::BeginEject,
            Self::EjectComplete => CpuStateTransitionKind::EjectComplete,
            Self::EjectFailed(_) => CpuStateTransitionKind::EjectFailed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuStateTransitionKind {
    FirmwarePresent,
    BeginStart,
    StartupReady,
    StartupFailed,
    BeginDrain,
    DrainAborted,
    DrainFailed,
    DrainComplete,
    BeginEject,
    EjectComplete,
    EjectFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuStateTransitionError {
    BootstrapCpu,
    Illegal {
        from: CpuSlotState,
        attempted: CpuStateTransitionKind,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuBlocker {
    PinnedTask { task_id: u64 },
    ControlQueue,
    IrqRoute { vector: u8 },
    NetworkQueue { runtime_id: u64 },
    DeferredWake,
    Timer,
    AllocatorCache,
    RcuReader,
    TlbShootdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuTopologyIssue {
    TooManyPossibleCpus {
        limit: usize,
    },
    DuplicateUid {
        uid: FirmwareCpuUid,
    },
    DuplicateApicId {
        apic_id: ApicId,
    },
    ConflictingFirmwareIdentity,
    UnsupportedApicDestination {
        apic_id: ApicId,
    },
    InterruptDeliveryUnavailable {
        apic_id: ApicId,
    },
    TscInconsistent,
    NumaInconsistent,
    MissingRequiredFeature {
        feature: &'static str,
    },
    CpuLocalAllocationFailed {
        id: CpuId,
    },
    CpuStartupUnavailable {
        id: CpuId,
        failure: CpuStartupFailure,
    },
    PhysicalEjectUnsupported {
        id: CpuId,
    },
    RevisionExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareErrorKind {
    InvalidTable,
    InvalidObjectType,
    UnsupportedOpcode,
    BudgetExhausted,
    Namespace,
    OperationRegion,
    EventDelivery,
    Resource,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareError {
    pub kind: FirmwareErrorKind,
    pub object: Option<Arc<str>>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhysicalHotplugStatus {
    Available,
    Unavailable(FirmwareError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuTransitionError {
    BootstrapCpu,
    NotPresent,
    Busy { blockers: Arc<[CpuBlocker]> },
    UnsupportedTopology(CpuTopologyIssue),
    TimedOut { phase: CpuFailurePhase },
    Firmware(FirmwareError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application_slot() -> CpuSlot {
        CpuSlot::absent(
            CpuId::try_from(1usize).unwrap(),
            CpuRole::Application,
            FirmwareCpuIdentity {
                uid: Some(FirmwareCpuUid::Integer(1)),
                apic_id: ApicId::new(0x1234),
                proximity_domain: Some(0),
                eject: CpuEjectCapability::FirmwareEject,
            },
        )
    }

    #[test]
    fn legal_lifecycle_covers_logical_and_physical_hotplug() {
        let mut slot = application_slot();
        slot.transition(CpuStateTransition::FirmwarePresent)
            .unwrap();
        slot.transition(CpuStateTransition::BeginStart).unwrap();
        slot.transition(CpuStateTransition::StartupReady).unwrap();
        slot.transition(CpuStateTransition::BeginDrain).unwrap();
        slot.transition(CpuStateTransition::DrainComplete).unwrap();
        slot.transition(CpuStateTransition::BeginStart).unwrap();
        slot.transition(CpuStateTransition::StartupReady).unwrap();
        slot.transition(CpuStateTransition::BeginDrain).unwrap();
        slot.transition(CpuStateTransition::DrainComplete).unwrap();
        slot.transition(CpuStateTransition::BeginEject).unwrap();
        slot.transition(CpuStateTransition::EjectComplete).unwrap();
        assert_eq!(slot.state, CpuSlotState::FirmwareAbsent);
    }

    #[test]
    fn never_started_cpu_can_eject_and_retain_typed_firmware_failure() {
        let mut slot = application_slot();
        slot.transition(CpuStateTransition::FirmwarePresent)
            .unwrap();
        slot.transition(CpuStateTransition::BeginEject).unwrap();
        let firmware = FirmwareError {
            kind: FirmwareErrorKind::OperationRegion,
            object: Some(Arc::from("\\_SB_.CP01._EJ0")),
            detail: String::from("firmware rejected the eject request"),
        };
        slot.transition(CpuStateTransition::EjectFailed(CpuFailureReason::Firmware(
            firmware.clone(),
        )))
        .unwrap();

        assert_eq!(slot.state, CpuSlotState::PresentOffline);
        assert_eq!(
            slot.last_failure,
            Some(CpuFailure {
                phase: CpuFailurePhase::Eject,
                reason: CpuFailureReason::Firmware(firmware),
            })
        );
    }

    #[test]
    fn illegal_transition_is_rejected_without_mutating_state() {
        let mut slot = application_slot();
        let result = slot.transition(CpuStateTransition::StartupReady);
        assert!(matches!(
            result,
            Err(CpuStateTransitionError::Illegal {
                from: CpuSlotState::FirmwareAbsent,
                attempted: CpuStateTransitionKind::StartupReady,
            })
        ));
        assert_eq!(slot.state, CpuSlotState::FirmwareAbsent);
    }

    #[test]
    fn bootstrap_cpu_cannot_enter_draining() {
        let mut slot = CpuSlot::bootstrap(ApicId::new(0));
        assert_eq!(
            slot.transition(CpuStateTransition::BeginDrain),
            Err(CpuStateTransitionError::BootstrapCpu)
        );
        assert_eq!(slot.state, CpuSlotState::Online);
    }

    #[test]
    fn startup_failure_is_retained_as_typed_reason() {
        let mut slot = application_slot();
        slot.transition(CpuStateTransition::FirmwarePresent)
            .unwrap();
        slot.transition(CpuStateTransition::BeginStart).unwrap();
        slot.transition(CpuStateTransition::StartupFailed(
            CpuFailureReason::StartupAcknowledgementTimedOut,
        ))
        .unwrap();
        assert_eq!(slot.state, CpuSlotState::PresentOffline);
        assert_eq!(
            slot.last_failure,
            Some(CpuFailure {
                phase: CpuFailurePhase::Start,
                reason: CpuFailureReason::StartupAcknowledgementTimedOut,
            })
        );
    }

    #[test]
    fn parked_startup_failure_returns_to_parked_state() {
        let mut slot = application_slot();
        slot.transition(CpuStateTransition::FirmwarePresent)
            .unwrap();
        slot.transition(CpuStateTransition::BeginStart).unwrap();
        slot.transition(CpuStateTransition::StartupReady).unwrap();
        slot.transition(CpuStateTransition::BeginDrain).unwrap();
        slot.transition(CpuStateTransition::DrainComplete).unwrap();
        slot.transition(CpuStateTransition::BeginStart).unwrap();
        slot.transition(CpuStateTransition::StartupFailed(
            CpuFailureReason::Startup(CpuStartupFailure::Timer),
        ))
        .unwrap();

        assert_eq!(slot.state, CpuSlotState::Parked);
        assert_eq!(
            slot.last_failure,
            Some(CpuFailure {
                phase: CpuFailurePhase::Start,
                reason: CpuFailureReason::Startup(CpuStartupFailure::Timer),
            })
        );
    }

    #[test]
    fn late_park_acknowledgement_preserves_the_reported_drain_timeout() {
        let mut slot = application_slot();
        slot.transition(CpuStateTransition::FirmwarePresent)
            .unwrap();
        slot.transition(CpuStateTransition::BeginStart).unwrap();
        slot.transition(CpuStateTransition::StartupReady).unwrap();
        slot.transition(CpuStateTransition::BeginDrain).unwrap();
        slot.transition(CpuStateTransition::DrainFailed(
            CpuFailureReason::DrainTimedOut,
        ))
        .unwrap();
        slot.transition(CpuStateTransition::DrainComplete).unwrap();

        assert_eq!(slot.state, CpuSlotState::Parked);
        assert_eq!(
            slot.last_failure,
            Some(CpuFailure {
                phase: CpuFailurePhase::Drain,
                reason: CpuFailureReason::DrainTimedOut,
            })
        );
    }

    #[test]
    fn aborted_drain_retains_typed_blockers_while_restoring_online_state() {
        let mut slot = application_slot();
        slot.transition(CpuStateTransition::FirmwarePresent)
            .unwrap();
        slot.transition(CpuStateTransition::BeginStart).unwrap();
        slot.transition(CpuStateTransition::StartupReady).unwrap();
        slot.transition(CpuStateTransition::BeginDrain).unwrap();
        let blockers: Arc<[CpuBlocker]> = Arc::from([CpuBlocker::NetworkQueue { runtime_id: 19 }]);
        slot.transition(CpuStateTransition::DrainAborted(CpuFailureReason::Drain(
            CpuDrainFailure::Blocked {
                blockers: blockers.clone(),
            },
        )))
        .unwrap();

        assert_eq!(slot.state, CpuSlotState::Online);
        assert_eq!(
            slot.last_failure,
            Some(CpuFailure {
                phase: CpuFailurePhase::Drain,
                reason: CpuFailureReason::Drain(CpuDrainFailure::Blocked { blockers }),
            })
        );
    }

    #[test]
    fn coherence_participation_extends_through_draining() {
        assert!(CpuSlotState::Starting.participates_in_tlb());
        assert!(!CpuSlotState::Starting.participates_in_rcu());
        assert!(CpuSlotState::Online.participates_in_tlb());
        assert!(CpuSlotState::Online.participates_in_rcu());
        assert!(CpuSlotState::Draining.participates_in_tlb());
        assert!(CpuSlotState::Draining.participates_in_rcu());
        assert!(CpuSlotState::Draining.accepts_executor_wake());
        assert!(!CpuSlotState::Parked.participates_in_tlb());
        assert!(!CpuSlotState::Parked.participates_in_rcu());
        assert!(!CpuSlotState::Parked.accepts_executor_wake());
    }
}
