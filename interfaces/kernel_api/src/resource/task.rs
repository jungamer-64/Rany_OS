//! Task admission preserves resource failures and validated CPU eligibility.

use super::cpu::{CpuId, CpuSet, NumaNodeId};
use super::domain::DomainId;

/// An identity permits observation; it grants no execution or reclamation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TaskId(u64);

impl TaskId {
    pub const fn from_raw(id: u64) -> Self {
        Self(id)
    }
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Critical,
}

impl TaskPriority {
    pub const fn weight(self) -> u64 {
        match self {
            Self::Low => 1,
            Self::Normal => 2,
            Self::High => 4,
            Self::Critical => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    EmptyAllowedSet,
    PreferredCpuOutsideAllowedSet(CpuId),
    InvalidNumaNode(NumaNodeId),
}

/// CPU eligibility is independent from locality preference. The validated
/// value remains meaningful across CPU online and offline transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskPlacement {
    allowed: CpuSet,
    preferred_cpu: Option<CpuId>,
    preferred_node: Option<NumaNodeId>,
}

impl TaskPlacement {
    /// # Errors
    /// Rejects empty eligibility, an ineligible preferred CPU, or an invalid
    /// node coordinate. Online placement is separately admitted by spawn;
    /// validation does not reserve a CPU or prevent a later offline transition.
    pub fn new(
        allowed: CpuSet,
        preferred_cpu: Option<CpuId>,
        preferred_node: Option<NumaNodeId>,
    ) -> Result<Self, PlacementError> {
        if allowed.is_empty() {
            return Err(PlacementError::EmptyAllowedSet);
        }
        if let Some(cpu) = preferred_cpu
            && !allowed.contains(cpu)
        {
            return Err(PlacementError::PreferredCpuOutsideAllowedSet(cpu));
        }
        if let Some(node) = preferred_node
            && !node.is_valid()
        {
            return Err(PlacementError::InvalidNumaNode(node));
        }
        Ok(Self {
            allowed,
            preferred_cpu,
            preferred_node,
        })
    }

    pub const fn allowed_cpus(self) -> CpuSet {
        self.allowed
    }
    pub const fn preferred_cpu(self) -> Option<CpuId> {
        self.preferred_cpu
    }
    pub const fn preferred_node(self) -> Option<NumaNodeId> {
        self.preferred_node
    }

    pub const fn any() -> Self {
        Self {
            allowed: CpuSet::all_possible(),
            preferred_cpu: None,
            preferred_node: None,
        }
    }

    pub const fn pinned(cpu: CpuId) -> Self {
        Self {
            allowed: CpuSet::singleton(cpu),
            preferred_cpu: Some(cpu),
            preferred_node: None,
        }
    }

    pub const fn prefer_cpu(cpu: CpuId) -> Self {
        Self {
            allowed: CpuSet::all_possible(),
            preferred_cpu: Some(cpu),
            preferred_node: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskOptions {
    pub priority: TaskPriority,
    pub placement: TaskPlacement,
}

impl TaskOptions {
    pub const fn new(priority: TaskPriority, placement: TaskPlacement) -> Self {
        Self {
            priority,
            placement,
        }
    }

    pub const fn any() -> Self {
        Self::new(TaskPriority::Normal, TaskPlacement::any())
    }

    pub const fn pinned(cpu: CpuId) -> Self {
        Self::new(TaskPriority::Normal, TaskPlacement::pinned(cpu))
    }

    pub const fn prefer_cpu(cpu: CpuId) -> Self {
        Self::new(TaskPriority::Normal, TaskPlacement::prefer_cpu(cpu))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskMappingError {
    MappingChanged,
    UnsupportedPageSize,
    AlreadyMapped,
    NotMapped,
    InvalidAddress,
    Alignment,
    ParentHugePage,
    ParentPermissionDenied,
    Hardware,
}

/// No task is published on failure; every acquired resource is reclaimed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// Malformed placement or priority received at the foreign boundary.
    InvalidOptions,
    /// The foreign provider returned a malformed admission receipt.
    InvalidAbiResponse,
    /// Kernel and cell use different Rust notification representations.
    RuntimeAbiMismatch,
    SchedulerUnavailable,
    NoOnlineCpu,
    PlacementUnavailable,
    CpuNotPresent(CpuId),
    CpuOffline(CpuId),
    TaskIdentityExhausted,
    TaskSlotsExhausted,
    PhysicalMemoryExhausted,
    MappingFailed(TaskMappingError),
    DomainUnavailable(DomainId),
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "task admission failed: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_rejects_empty_and_ineligible_preferences() {
        let cpu = CpuId::new(71).unwrap();
        assert_eq!(
            TaskPlacement::new(CpuSet::empty_possible(), None, None),
            Err(PlacementError::EmptyAllowedSet)
        );
        assert_eq!(
            TaskPlacement::new(CpuSet::singleton(cpu), Some(CpuId::BOOTSTRAP), None),
            Err(PlacementError::PreferredCpuOutsideAllowedSet(
                CpuId::BOOTSTRAP
            ))
        );
        let invalid_node = NumaNodeId::new(NumaNodeId::MAX_NODES as u8);
        assert_eq!(
            TaskPlacement::new(CpuSet::singleton(cpu), None, Some(invalid_node)),
            Err(PlacementError::InvalidNumaNode(invalid_node))
        );
    }

    #[test]
    fn locality_preferences_preserve_sparse_cpu_eligibility() {
        let cpu = CpuId::new(71).unwrap();
        let other = CpuId::new(129).unwrap();
        let mut allowed = CpuSet::singleton(cpu);
        allowed.insert(other).unwrap();
        let placement = TaskPlacement::new(allowed, Some(other), Some(NumaNodeId::NODE_0)).unwrap();
        assert_eq!(placement.allowed_cpus(), allowed);
        assert_eq!(placement.preferred_cpu(), Some(other));
        assert_eq!(placement.preferred_node(), Some(NumaNodeId::NODE_0));
        assert!(!placement.allowed_cpus().contains(CpuId::BOOTSTRAP));
        assert_eq!(
            TaskPlacement::pinned(other).allowed_cpus(),
            CpuSet::singleton(other)
        );
        assert!(
            TaskPlacement::prefer_cpu(cpu)
                .allowed_cpus()
                .contains(other)
        );
    }

    #[test]
    fn every_priority_has_the_required_positive_share() {
        let weights = [
            TaskPriority::Low,
            TaskPriority::Normal,
            TaskPriority::High,
            TaskPriority::Critical,
        ]
        .map(TaskPriority::weight);
        assert_eq!(weights, [1, 2, 4, 8]);
    }
}
