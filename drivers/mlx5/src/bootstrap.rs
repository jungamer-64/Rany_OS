// ============================================================================
// drivers/mlx5/src/bootstrap.rs - Typed bootstrap planning for mlx5 bring-up
// ============================================================================

extern crate alloc;

use alloc::vec::Vec;

use crate::defs::{
    MLX5_CMD_MBOX_BACKING_SIZE, MLX5_CQ_DEPTH, MLX5_EQ_DEPTH, MLX5_PAGE_SIZE,
    MLX5_RX_WQE_MAX_SUPPORTED_SIZE, MLX5_WQ_DEPTH,
};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::{cmd_entry, cqe, eqe};
use crate::resources::MkeyParams;

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

#[derive(Debug, Clone)]
pub struct Mlx5BootstrapConfig {
    pub queue_profile: Mlx5QueueProfile,
    pub mkey_params: MkeyParams,
    pub pci_identity: Mlx5PciIdentity,
    pub is_vf: bool,
}

impl Default for Mlx5BootstrapConfig {
    fn default() -> Self {
        Self {
            queue_profile: Mlx5QueueProfile::default(),
            mkey_params: MkeyParams::default(),
            pci_identity: Mlx5PciIdentity::default(),
            is_vf: false,
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
