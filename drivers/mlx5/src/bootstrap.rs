// ============================================================================
// drivers/mlx5/src/bootstrap.rs - Typed bootstrap planning for mlx5 bring-up
// ============================================================================

#![forbid(unsafe_code)]

use kernel_api::dma::{DmaAllocationRequest, DmaDirection};

use crate::defs::{
    MLX5_CMD_MBOX_BACKING_SIZE, MLX5_CMD_MBOX_SIZE, MLX5_CQ_DEPTH, MLX5_EQ_DEPTH, MLX5_MAX_CQS,
    MLX5_MAX_EQS, MLX5_PAGE_SIZE, MLX5_QUEUE_PAS_OFFSET, MLX5_RX_WQE_MAX_SUPPORTED_SIZE,
    MLX5_SQ_STRIDE, MLX5_WQ_DEPTH,
};
use crate::regs::{cmd_entry, cqe, eqe};
use crate::resources::MkeyParams;

mod dma;
pub use dma::{
    BootstrapAllocationCause, BootstrapAllocationFailure, BootstrapDmaInventory,
    BootstrapRetirementFailure,
};

const CMD_LOG_SIZE: u8 = 2;
const MLX5_EQ_SPARE_EQE: u32 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mlx5PciIdentity {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mlx5QueueProfile {
    pub eq_count: usize,
    pub tx_queue_count: usize,
    pub rx_queue_count: usize,
    pub log_eq_size: u8,
    pub log_cq_size: u8,
    pub log_sq_size: u8,
    pub log_rq_size: u8,
}

impl Mlx5QueueProfile {
    pub fn with_num_queues(num_queues: usize) -> Self {
        Self {
            eq_count: num_queues,
            tx_queue_count: num_queues,
            rx_queue_count: num_queues,
            log_eq_size: ceil_log2_u32(MLX5_EQ_DEPTH.saturating_add(MLX5_EQ_SPARE_EQE)),
            log_cq_size: floor_log2_u32(MLX5_CQ_DEPTH),
            log_sq_size: floor_log2_u32(MLX5_WQ_DEPTH),
            log_rq_size: floor_log2_u32(MLX5_WQ_DEPTH),
        }
    }
}

impl Default for Mlx5QueueProfile {
    fn default() -> Self {
        Self::with_num_queues(4)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Mlx5BootstrapConfig {
    pub queue_profile: Mlx5QueueProfile,
    pub mkey_params: MkeyParams,
    pub pci_identity: Mlx5PciIdentity,
    pub is_vf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapQueueKind {
    Event,
    TransmitCompletion,
    ReceiveCompletion,
    Send,
    Receive,
    ReceiveMemoryPool,
}

/// Identifies an allocation's protocol role, not an address or release authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapDmaPurpose {
    CommandQueue,
    CommandInput,
    CommandOutput,
    QueueEntries(BootstrapQueueKind, u16),
    Doorbell(BootstrapQueueKind, u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapPlanError {
    FixedExtentOverflow,
    EmptyQueues(BootstrapQueueKind),
    QueueLimitExceeded(BootstrapQueueKind),
    CompletionQueueLimitExceeded,
    RingSizeOverflow(BootstrapQueueKind),
    PasCapacityExceeded(BootstrapQueueKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapDmaRequirement {
    purpose: BootstrapDmaPurpose,
    request: DmaAllocationRequest,
}

impl BootstrapDmaRequirement {
    pub const fn purpose(self) -> BootstrapDmaPurpose {
        self.purpose
    }

    pub const fn request(self) -> DmaAllocationRequest {
        self.request
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RingLayout {
    log_size: u8,
    request: DmaAllocationRequest,
}

impl RingLayout {
    fn checked(
        kind: BootstrapQueueKind,
        log_size: u8,
        stride: usize,
        direction: DmaDirection,
    ) -> Result<Self, BootstrapPlanError> {
        // Queue indices/counters and the encoded log fields are at most 32 bits.
        let entries = 1u32
            .checked_shl(u32::from(log_size))
            .ok_or(BootstrapPlanError::RingSizeOverflow(kind))?;
        let bytes = usize::try_from(entries)
            .ok()
            .and_then(|count| count.checked_mul(stride))
            .ok_or(BootstrapPlanError::RingSizeOverflow(kind))?;
        let request = DmaAllocationRequest::new(bytes, direction)
            .ok_or(BootstrapPlanError::RingSizeOverflow(kind))?;
        let pages = bytes.div_ceil(MLX5_PAGE_SIZE);
        if pages > (MLX5_CMD_MBOX_SIZE - MLX5_QUEUE_PAS_OFFSET) / 8 {
            return Err(BootstrapPlanError::PasCapacityExceeded(kind));
        }
        Ok(Self { log_size, request })
    }
}

/// Immutable allocation admission, before any DMA allocation or hardware effect.
/// The mailbox PAS capacity bounds each ring; these are driver limits, not proof
/// that a particular HCA supports the profile. HCA admission remains separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapDmaPlan {
    command_queue: DmaAllocationRequest,
    command_mailbox: DmaAllocationRequest,
    doorbell: DmaAllocationRequest,
    eq_count: u16,
    tx_count: u16,
    rx_count: u16,
    eq: RingLayout,
    cq: RingLayout,
    sq: RingLayout,
    rq: RingLayout,
}

impl BootstrapDmaPlan {
    /// # Errors
    /// Rejects empty/excessive queue inventories, unrepresentable ring sizes, and
    /// PAS lists that cannot be completely encoded in one command mailbox, or
    /// fixed protocol extents that cannot be represented as DMA byte counts.
    pub fn new(profile: Mlx5QueueProfile) -> Result<Self, BootstrapPlanError> {
        use BootstrapQueueKind as Kind;
        let count = |kind, value: usize, limit| {
            if value == 0 {
                return Err(BootstrapPlanError::EmptyQueues(kind));
            }
            if value > limit {
                return Err(BootstrapPlanError::QueueLimitExceeded(kind));
            }
            u16::try_from(value).map_err(|_| BootstrapPlanError::QueueLimitExceeded(kind))
        };
        let eq_count = count(Kind::Event, profile.eq_count, MLX5_MAX_EQS)?;
        let tx_count = count(Kind::Send, profile.tx_queue_count, MLX5_MAX_CQS)?;
        let rx_count = count(Kind::Receive, profile.rx_queue_count, MLX5_MAX_CQS)?;
        if usize::from(tx_count) + usize::from(rx_count) > MLX5_MAX_CQS {
            return Err(BootstrapPlanError::CompletionQueueLimitExceeded);
        }
        Ok(Self {
            command_queue: DmaAllocationRequest::new(
                MLX5_PAGE_SIZE.max((1 << CMD_LOG_SIZE) * cmd_entry::ENTRY_SIZE),
                DmaDirection::Bidirectional,
            )
            .ok_or(BootstrapPlanError::FixedExtentOverflow)?,
            command_mailbox: DmaAllocationRequest::new(
                MLX5_CMD_MBOX_BACKING_SIZE,
                DmaDirection::Bidirectional,
            )
            .ok_or(BootstrapPlanError::FixedExtentOverflow)?,
            doorbell: DmaAllocationRequest::new(MLX5_PAGE_SIZE, DmaDirection::ToDevice)
                .ok_or(BootstrapPlanError::FixedExtentOverflow)?,
            eq_count,
            tx_count,
            rx_count,
            eq: RingLayout::checked(
                Kind::Event,
                profile.log_eq_size,
                eqe::EQE_SIZE,
                DmaDirection::FromDevice,
            )?,
            cq: RingLayout::checked(
                Kind::TransmitCompletion,
                profile.log_cq_size,
                cqe::SIZE,
                DmaDirection::FromDevice,
            )?,
            sq: RingLayout::checked(
                Kind::Send,
                profile.log_sq_size,
                MLX5_SQ_STRIDE,
                DmaDirection::ToDevice,
            )?,
            rq: RingLayout::checked(
                Kind::Receive,
                profile.log_rq_size,
                MLX5_RX_WQE_MAX_SUPPORTED_SIZE,
                DmaDirection::ToDevice,
            )?,
        })
    }

    pub const fn command_log_size(&self) -> u8 {
        CMD_LOG_SIZE
    }

    pub const fn ring_log_size(&self, kind: BootstrapQueueKind) -> u8 {
        self.layout(kind).log_size
    }

    pub const fn queue_count(&self, kind: BootstrapQueueKind) -> u16 {
        match kind {
            BootstrapQueueKind::Event => self.eq_count,
            BootstrapQueueKind::TransmitCompletion | BootstrapQueueKind::Send => self.tx_count,
            BootstrapQueueKind::ReceiveCompletion
            | BootstrapQueueKind::Receive
            | BootstrapQueueKind::ReceiveMemoryPool => self.rx_count,
        }
    }

    pub fn allocation_count(&self) -> usize {
        3 + usize::from(self.eq_count)
            + 4 * usize::from(self.tx_count)
            + 6 * usize::from(self.rx_count)
    }

    pub fn requirements(&self) -> impl Iterator<Item = BootstrapDmaRequirement> + '_ {
        use BootstrapDmaPurpose as Purpose;
        use BootstrapQueueKind as Kind;
        let commands = [
            (Purpose::CommandQueue, self.command_queue),
            (Purpose::CommandInput, self.command_mailbox),
            (Purpose::CommandOutput, self.command_mailbox),
        ]
        .into_iter()
        .map(|(purpose, request)| BootstrapDmaRequirement { purpose, request });
        let queues = [
            Kind::Event,
            Kind::TransmitCompletion,
            Kind::ReceiveCompletion,
            Kind::Send,
            Kind::Receive,
            Kind::ReceiveMemoryPool,
        ]
        .into_iter()
        .flat_map(move |kind| {
            (0..self.queue_count(kind)).flat_map(move |index| {
                let entries = BootstrapDmaRequirement {
                    purpose: Purpose::QueueEntries(kind, index),
                    request: self.layout(kind).request,
                };
                let doorbell = (kind != Kind::Event).then_some(BootstrapDmaRequirement {
                    purpose: Purpose::Doorbell(kind, index),
                    request: self.doorbell,
                });
                core::iter::once(entries).chain(doorbell)
            })
        });
        commands.chain(queues)
    }

    const fn layout(&self, kind: BootstrapQueueKind) -> RingLayout {
        match kind {
            BootstrapQueueKind::Event => self.eq,
            BootstrapQueueKind::TransmitCompletion | BootstrapQueueKind::ReceiveCompletion => {
                self.cq
            }
            BootstrapQueueKind::Send => self.sq,
            BootstrapQueueKind::Receive | BootstrapQueueKind::ReceiveMemoryPool => self.rq,
        }
    }
}

const fn floor_log2_u32(val: u32) -> u8 {
    if val == 0 {
        0
    } else {
        31 - val.leading_zeros() as u8
    }
}

const fn ceil_log2_u32(val: u32) -> u8 {
    if val <= 1 {
        0
    } else {
        32 - (val - 1).leading_zeros() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn default_plan_preserves_multiqueue_layout_and_mapping_permissions() {
        let plan = BootstrapDmaPlan::new(Mlx5QueueProfile::default()).unwrap();
        let requirements: Vec<_> = plan.requirements().collect();
        assert_eq!(requirements.len(), 47);
        assert_eq!(requirements.len(), plan.allocation_count());
        assert_eq!(requirements[0].request.byte_count().get(), MLX5_PAGE_SIZE);
        assert_eq!(
            requirements[1].request.byte_count().get(),
            MLX5_CMD_MBOX_BACKING_SIZE
        );
        for requirement in requirements {
            match requirement.purpose {
                BootstrapDmaPurpose::QueueEntries(kind, _) => {
                    let expected = match kind {
                        BootstrapQueueKind::Event => {
                            (256 * eqe::EQE_SIZE, DmaDirection::FromDevice)
                        }
                        BootstrapQueueKind::TransmitCompletion
                        | BootstrapQueueKind::ReceiveCompletion => {
                            (64 * cqe::SIZE, DmaDirection::FromDevice)
                        }
                        BootstrapQueueKind::Send => (256 * 64, DmaDirection::ToDevice),
                        BootstrapQueueKind::Receive | BootstrapQueueKind::ReceiveMemoryPool => {
                            (256 * MLX5_RX_WQE_MAX_SUPPORTED_SIZE, DmaDirection::ToDevice)
                        }
                    };
                    assert_eq!(requirement.request.byte_count().get(), expected.0);
                    assert_eq!(requirement.request.direction(), expected.1);
                }
                BootstrapDmaPurpose::Doorbell(_, _) => {
                    assert_eq!(requirement.request.byte_count().get(), MLX5_PAGE_SIZE);
                    assert_eq!(requirement.request.direction(), DmaDirection::ToDevice);
                }
                _ => assert_eq!(requirement.request.direction(), DmaDirection::Bidirectional),
            }
        }
    }

    #[test]
    fn queue_admission_rejects_empty_excessive_and_combined_cq_counts() {
        let cases = [
            (
                0,
                1,
                1,
                BootstrapPlanError::EmptyQueues(BootstrapQueueKind::Event),
            ),
            (
                1,
                0,
                1,
                BootstrapPlanError::EmptyQueues(BootstrapQueueKind::Send),
            ),
            (
                1,
                1,
                0,
                BootstrapPlanError::EmptyQueues(BootstrapQueueKind::Receive),
            ),
            (
                usize::MAX,
                1,
                1,
                BootstrapPlanError::QueueLimitExceeded(BootstrapQueueKind::Event),
            ),
            (
                1,
                usize::MAX,
                1,
                BootstrapPlanError::QueueLimitExceeded(BootstrapQueueKind::Send),
            ),
            (
                1,
                1,
                usize::MAX,
                BootstrapPlanError::QueueLimitExceeded(BootstrapQueueKind::Receive),
            ),
            (
                1,
                MLX5_MAX_CQS,
                1,
                BootstrapPlanError::CompletionQueueLimitExceeded,
            ),
        ];
        for (eq_count, tx_queue_count, rx_queue_count, expected) in cases {
            let profile = Mlx5QueueProfile {
                eq_count,
                tx_queue_count,
                rx_queue_count,
                ..Mlx5QueueProfile::default()
            };
            assert_eq!(BootstrapDmaPlan::new(profile), Err(expected));
        }
        let profile = Mlx5QueueProfile {
            eq_count: MLX5_MAX_EQS,
            tx_queue_count: MLX5_MAX_CQS - 1,
            rx_queue_count: 1,
            ..Mlx5QueueProfile::default()
        };
        let plan = BootstrapDmaPlan::new(profile).unwrap();
        assert_eq!(plan.requirements().count(), plan.allocation_count());
    }

    #[test]
    fn ring_extents_reject_shift_overflow_and_complete_pas_overflow() {
        for log_sq_size in [32, 63, u8::MAX] {
            let profile = Mlx5QueueProfile {
                log_sq_size,
                ..Mlx5QueueProfile::default()
            };
            assert_eq!(
                BootstrapDmaPlan::new(profile),
                Err(BootstrapPlanError::RingSizeOverflow(
                    BootstrapQueueKind::Send
                ))
            );
        }
        let profile = Mlx5QueueProfile {
            log_sq_size: 17,
            ..Mlx5QueueProfile::default()
        };
        assert_eq!(
            BootstrapDmaPlan::new(profile),
            Err(BootstrapPlanError::PasCapacityExceeded(
                BootstrapQueueKind::Send
            ))
        );
        let profile = Mlx5QueueProfile {
            log_sq_size: 16,
            ..Mlx5QueueProfile::default()
        };
        assert!(BootstrapDmaPlan::new(profile).is_ok());
    }

    #[test]
    fn asymmetric_profiles_issue_unique_roles_without_parallel_address_views() {
        let profile = Mlx5QueueProfile {
            eq_count: 2,
            tx_queue_count: 3,
            rx_queue_count: 1,
            ..Mlx5QueueProfile::default()
        };
        let plan = BootstrapDmaPlan::new(profile).unwrap();
        let requirements: Vec<_> = plan.requirements().collect();
        assert_eq!(requirements.len(), 23);
        for (index, requirement) in requirements.iter().enumerate() {
            assert!(
                !requirements[..index]
                    .iter()
                    .any(|other| other.purpose == requirement.purpose)
            );
        }
    }
}
