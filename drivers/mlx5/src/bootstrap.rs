// ============================================================================
// drivers/mlx5/src/bootstrap.rs - Typed bootstrap planning for mlx5 bring-up
// ============================================================================

extern crate alloc;

use alloc::vec::Vec;

use crate::defs::{
    MLX5_CMD_MBOX_BACKING_SIZE, MLX5_CQ_DEPTH, MLX5_EQ_DEPTH, MLX5_PAGE_SIZE, MLX5_WQ_DEPTH,
};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::{cmd_entry, cqe, eqe, wqe};
use crate::resources::MkeyParams;

const CMD_LOG_SIZE: u8 = 2;
const FW_BOOT_PAGE_COUNT: usize = 16;
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

    pub fn max_queue_count(&self) -> usize {
        self.eq_count
            .max(self.tx_queue_count)
            .max(self.rx_queue_count)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mlx5DmaRegion {
    pub virt_addr: u64,
    pub device_addr: u64,
    pub len: usize,
}

impl Mlx5DmaRegion {
    pub const fn new(virt_addr: u64, device_addr: u64, len: usize) -> Self {
        Self {
            virt_addr,
            device_addr,
            len,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mlx5QueueDmaRegion {
    pub entries: Mlx5DmaRegion,
    pub doorbell: Mlx5DmaRegion,
}

#[derive(Debug, Clone)]
pub struct Mlx5AllocatedResources {
    pub cmdq: Mlx5DmaRegion,
    pub cmd_in_mbox: Mlx5DmaRegion,
    pub cmd_out_mbox: Mlx5DmaRegion,
    pub fw_pages: Vec<Mlx5DmaRegion>,
    pub eqs: Vec<Mlx5DmaRegion>,
    pub tx_cqs: Vec<Mlx5QueueDmaRegion>,
    pub rx_cqs: Vec<Mlx5QueueDmaRegion>,
    pub sqs: Vec<Mlx5QueueDmaRegion>,
    pub rqs: Vec<Mlx5QueueDmaRegion>,
}

impl Mlx5AllocatedResources {
    pub fn fw_page_device_addrs(&self) -> Vec<u64> {
        self.fw_pages.iter().map(|page| page.device_addr).collect()
    }

    pub fn eq_bufs(&self) -> Vec<(u64, u64)> {
        self.eqs
            .iter()
            .map(|queue| (queue.virt_addr, queue.device_addr))
            .collect()
    }

    pub fn tx_cq_bufs(&self) -> Vec<(u64, u64, u64, u64)> {
        queue_db_pairs(&self.tx_cqs)
    }

    pub fn rx_cq_bufs(&self) -> Vec<(u64, u64, u64, u64)> {
        queue_db_pairs(&self.rx_cqs)
    }

    pub fn sq_bufs(&self) -> Vec<(u64, u64, u64, u64)> {
        queue_db_pairs(&self.sqs)
    }

    pub fn rq_bufs(&self) -> Vec<(u64, u64, u64, u64)> {
        queue_db_pairs(&self.rqs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mlx5BootstrapPlan {
    queue_profile: Mlx5QueueProfile,
    cmdq_size: usize,
    cmd_mailbox_size: usize,
    eq_size: usize,
    cq_size: usize,
    sq_size: usize,
    rq_size: usize,
    db_record_size: usize,
}

impl Mlx5BootstrapPlan {
    pub fn new(config: &Mlx5BootstrapConfig) -> Self {
        let cmdq_size = MLX5_PAGE_SIZE.max((1usize << CMD_LOG_SIZE) * cmd_entry::ENTRY_SIZE);
        let queue_profile = config.queue_profile;
        let eq_size = (1usize << queue_profile.log_eq_size as usize) * eqe::EQE_SIZE;
        let cq_size = (1usize << queue_profile.log_cq_size as usize) * cqe::SIZE;
        let sq_size = (1usize << queue_profile.log_sq_size as usize) * 64;
        let rq_size = (1usize << queue_profile.log_rq_size as usize) * wqe::WQEBB_SIZE;

        Self {
            queue_profile,
            cmdq_size,
            cmd_mailbox_size: MLX5_CMD_MBOX_BACKING_SIZE,
            eq_size,
            cq_size,
            sq_size,
            rq_size,
            db_record_size: MLX5_PAGE_SIZE,
        }
    }

    pub const fn queue_profile(&self) -> Mlx5QueueProfile {
        self.queue_profile
    }

    pub const fn command_queue_size(&self) -> usize {
        self.cmdq_size
    }

    pub const fn command_mailbox_size(&self) -> usize {
        self.cmd_mailbox_size
    }

    pub const fn fw_boot_page_count(&self) -> usize {
        FW_BOOT_PAGE_COUNT
    }

    pub const fn fw_page_size(&self) -> usize {
        MLX5_PAGE_SIZE
    }

    pub const fn eq_size(&self) -> usize {
        self.eq_size
    }

    pub const fn cq_size(&self) -> usize {
        self.cq_size
    }

    pub const fn sq_size(&self) -> usize {
        self.sq_size
    }

    pub const fn rq_size(&self) -> usize {
        self.rq_size
    }

    pub const fn db_record_size(&self) -> usize {
        self.db_record_size
    }

    pub fn validate_resources(&self, resources: &Mlx5AllocatedResources) -> Mlx5Result<()> {
        validate_region(resources.cmdq, self.cmdq_size)?;
        validate_region(resources.cmd_in_mbox, self.cmd_mailbox_size)?;
        validate_region(resources.cmd_out_mbox, self.cmd_mailbox_size)?;

        if resources.fw_pages.len() < FW_BOOT_PAGE_COUNT {
            return Err(Mlx5Error::InvalidParameter);
        }
        for page in resources.fw_pages.iter().take(FW_BOOT_PAGE_COUNT) {
            validate_region(*page, MLX5_PAGE_SIZE)?;
        }

        validate_region_list(&resources.eqs, self.queue_profile.eq_count, self.eq_size)?;
        validate_queue_list(
            &resources.tx_cqs,
            self.queue_profile.tx_queue_count,
            self.cq_size,
            self.db_record_size,
        )?;
        validate_queue_list(
            &resources.rx_cqs,
            self.queue_profile.rx_queue_count,
            self.cq_size,
            self.db_record_size,
        )?;
        validate_queue_list(
            &resources.sqs,
            self.queue_profile.tx_queue_count,
            self.sq_size,
            self.db_record_size,
        )?;
        validate_queue_list(
            &resources.rqs,
            self.queue_profile.rx_queue_count,
            self.rq_size,
            self.db_record_size,
        )?;

        Ok(())
    }
}

fn queue_db_pairs(queues: &[Mlx5QueueDmaRegion]) -> Vec<(u64, u64, u64, u64)> {
    queues
        .iter()
        .map(|queue| {
            (
                queue.entries.virt_addr,
                queue.entries.device_addr,
                queue.doorbell.virt_addr,
                queue.doorbell.device_addr,
            )
        })
        .collect()
}

fn validate_region(region: Mlx5DmaRegion, expected_len: usize) -> Mlx5Result<()> {
    if region.virt_addr == 0 || region.device_addr == 0 || region.len < expected_len {
        return Err(Mlx5Error::InvalidParameter);
    }
    Ok(())
}

fn validate_region_list(
    regions: &[Mlx5DmaRegion],
    expected_count: usize,
    expected_len: usize,
) -> Mlx5Result<()> {
    if regions.len() < expected_count {
        return Err(Mlx5Error::InvalidParameter);
    }
    for region in regions.iter().take(expected_count) {
        validate_region(*region, expected_len)?;
    }
    Ok(())
}

fn validate_queue_list(
    queues: &[Mlx5QueueDmaRegion],
    expected_count: usize,
    queue_len: usize,
    db_len: usize,
) -> Mlx5Result<()> {
    if queues.len() < expected_count {
        return Err(Mlx5Error::InvalidParameter);
    }
    for queue in queues.iter().take(expected_count) {
        validate_region(queue.entries, queue_len)?;
        validate_region(queue.doorbell, db_len)?;
    }
    Ok(())
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

    fn queue_region(base: u64, queue_len: usize, db_len: usize) -> Mlx5QueueDmaRegion {
        Mlx5QueueDmaRegion {
            entries: Mlx5DmaRegion::new(base, base + 0x1000, queue_len),
            doorbell: Mlx5DmaRegion::new(base + 0x2000, base + 0x3000, db_len),
        }
    }

    fn valid_resources(plan: &Mlx5BootstrapPlan) -> Mlx5AllocatedResources {
        let profile = plan.queue_profile();
        Mlx5AllocatedResources {
            cmdq: Mlx5DmaRegion::new(0x1000, 0x2000, plan.command_queue_size()),
            cmd_in_mbox: Mlx5DmaRegion::new(0x3000, 0x4000, plan.command_mailbox_size()),
            cmd_out_mbox: Mlx5DmaRegion::new(0x5000, 0x6000, plan.command_mailbox_size()),
            fw_pages: (0..plan.fw_boot_page_count())
                .map(|i| {
                    let base = 0x7000 + (i as u64 * 0x1000);
                    Mlx5DmaRegion::new(base, base + 0x100000, plan.fw_page_size())
                })
                .collect(),
            eqs: (0..profile.eq_count)
                .map(|i| {
                    let base = 0x20_000 + (i as u64 * 0x2000);
                    Mlx5DmaRegion::new(base, base + 0x100000, plan.eq_size())
                })
                .collect(),
            tx_cqs: (0..profile.tx_queue_count)
                .map(|i| {
                    queue_region(
                        0x40_000 + (i as u64 * 0x4000),
                        plan.cq_size(),
                        plan.db_record_size(),
                    )
                })
                .collect(),
            rx_cqs: (0..profile.rx_queue_count)
                .map(|i| {
                    queue_region(
                        0x80_000 + (i as u64 * 0x4000),
                        plan.cq_size(),
                        plan.db_record_size(),
                    )
                })
                .collect(),
            sqs: (0..profile.tx_queue_count)
                .map(|i| {
                    queue_region(
                        0xc0_000 + (i as u64 * 0x4000),
                        plan.sq_size(),
                        plan.db_record_size(),
                    )
                })
                .collect(),
            rqs: (0..profile.rx_queue_count)
                .map(|i| {
                    queue_region(
                        0x100_000 + (i as u64 * 0x4000),
                        plan.rq_size(),
                        plan.db_record_size(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn bootstrap_plan_uses_queue_profile_sizes() {
        let mut config = Mlx5BootstrapConfig::default();
        config.queue_profile = Mlx5QueueProfile {
            eq_count: 2,
            tx_queue_count: 3,
            rx_queue_count: 1,
            log_eq_size: 5,
            log_cq_size: 4,
            log_sq_size: 6,
            log_rq_size: 5,
        };

        let plan = Mlx5BootstrapPlan::new(&config);

        assert_eq!(plan.eq_size(), (1usize << 5) * eqe::EQE_SIZE);
        assert_eq!(plan.cq_size(), (1usize << 4) * cqe::SIZE);
        assert_eq!(plan.sq_size(), (1usize << 6) * 64);
        assert_eq!(plan.rq_size(), (1usize << 5) * wqe::WQEBB_SIZE);
    }

    #[test]
    fn validate_resources_accepts_matching_layout() {
        let config = Mlx5BootstrapConfig::default();
        let plan = Mlx5BootstrapPlan::new(&config);

        assert_eq!(plan.validate_resources(&valid_resources(&plan)), Ok(()));
    }

    #[test]
    fn validate_resources_rejects_missing_queue_regions() {
        let config = Mlx5BootstrapConfig::default();
        let plan = Mlx5BootstrapPlan::new(&config);
        let mut resources = valid_resources(&plan);
        let _ = resources.sqs.pop();

        assert_eq!(
            plan.validate_resources(&resources),
            Err(Mlx5Error::InvalidParameter)
        );
    }
}
