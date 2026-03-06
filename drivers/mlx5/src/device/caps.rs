// ============================================================================
// drivers/mlx5/src/device/caps.rs - MLX5 Device Capabilities
// ============================================================================

use crate::defs::{CmdOpcode, HcaCaps};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::device::Mlx5Device;
use crate::device::MLX5_CMD_MBOX_SIZE;
use crate::cmd::CmdMailbox;
// unused import removed

impl Mlx5Device {
    /// HCA Capabilities の照会と設定
    pub unsafe fn query_and_set_hca_cap(&mut self) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        
        log::info!(target: "mlx5", "Querying HCA Capabilities...");
        *in_mbox = CmdMailbox::zeroed();
        // Query CURRENT caps (op_mod = 0)
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryHcaCap,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let cap_view = crate::structs::caps::HcaCapLayout::new(&out_mbox.data);
        
        let mut caps = HcaCaps::default();
        
        // Use structured layout accessors
        caps.max_cq = 1 << cap_view.log_max_cq();
        caps.max_sq = 1 << cap_view.log_max_sq();
        caps.max_rq = 1 << cap_view.log_max_rq();
        caps.max_eq = 1 << cap_view.log_max_eq();
        caps.max_mkey = 1 << cap_view.log_max_mkey();
        caps.num_ports = cap_view.num_ports() as u8;
        caps.max_mtu = cap_view.max_mtu();
        caps.vport_group_manager = cap_view.vport_group_manager();
        caps.scatter_fcs = cap_view.scatter_fcs();
        caps.vlan_strip = cap_view.vlan_strip();
        caps.csum_cap = cap_view.csum_cap();
        caps.cqe_compression = cap_view.cqe_compression();

        log::info!(
            target: "mlx5",
            "HCA Caps: ports={}, max_cq={}, max_sq={}, max_rq={}, max_eq={}, max_mkey={}, max_mtu={}, vport_mgr={}",
            caps.num_ports, caps.max_cq, caps.max_sq, caps.max_rq, caps.max_eq, caps.max_mkey, caps.max_mtu, caps.vport_group_manager
        );

        self.hca_caps = Some(caps);
        Ok(())
    }

    /// ドライバの起動時に必要な全 HCA Capability を一気に取得
    pub unsafe fn query_all_caps(&mut self) -> Mlx5Result<()> {
        self.query_and_set_hca_cap()
    }
}
