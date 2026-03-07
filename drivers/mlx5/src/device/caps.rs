// ============================================================================
// drivers/mlx5/src/device/caps.rs - MLX5 Device Capabilities
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::defs::{CmdOpcode, HcaCaps, MLX5_CMD_MBOX_SIZE};
use crate::device::Mlx5Device;
use crate::error::{Mlx5Error, Mlx5Result};
// unused import removed

impl Mlx5Device {
    /// HCA Capabilities の照会と設定
    pub unsafe fn query_and_set_hca_cap(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
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
        caps.vhca_id = cap_view.vhca_id() as u16;
        caps.eswitch_manager = cap_view.eswitch_manager();
        caps.num_vhca_ports = cap_view.num_vhca_ports() as u16;

        // TSO (TCP Segmentation Offload) の取得
        // byte 0x11 (dword 4): bit 29: tso_ipv4, bit 28: tso_ipv6
        caps.tso_ipv4 = (out_mbox.data[0x10 + 0x11] & 0x20) != 0;
        caps.tso_ipv6 = (out_mbox.data[0x10 + 0x11] & 0x10) != 0;

        // 最大 SGE 数 (Scatter/Gather Entry) の取得
        // byte 0x12 (dword 4): [31:24] log_max_sge_sz
        caps.max_sge = 1 << (out_mbox.data[0x10 + 0x12] >> 4);

        // MSI-X 制限の取得
        // byte 0x3c (dword 15): [31:0] max_num_eqs
        caps.max_eq = out_mbox.read_be32(0x10 + 0x3c);
        // byte 0x48 (dword 18): [31:0] max_num_msix (for VFs)
        let max_msix = out_mbox.read_be32(0x10 + 0x48);
        caps.max_msix = max_msix;

        // Timestamp formats (dw1: bits 15:14 rq_ts_format, 13:12 sq_ts_format)
        caps.rq_ts_format = (out_mbox.data[0x10 + 0x04 + 2] >> 6) & 0x03;
        caps.sq_ts_format = (out_mbox.data[0x10 + 0x04 + 2] >> 4) & 0x03;
        
        // Device frequency (dw15: 0x3C-0x3F)
        caps.device_frequency_khz = out_mbox.read_be32(0x10 + 0x3c);

        log::info!(
            target: "mlx5",
            "HCA Caps: ports={}, max_cq={}, max_sq={}, max_rq={}, max_eq={}, max_msix={}, vhca_id={:#x}, vport_mgr={}, rq_ts={}, sq_ts={}, freq={}kHz",
            caps.num_ports, caps.max_cq, caps.max_sq, caps.max_rq, caps.max_eq, caps.max_msix, caps.vhca_id, caps.vport_group_manager,
            caps.rq_ts_format, caps.sq_ts_format, caps.device_frequency_khz
        );

        // vhca_id が 0 以外であれば VF (または SF) と判定を補正する
        // ただし ECPF の場合は vhca_id が 0 以外でも PF 的な振る舞いをする場合があるため考慮が必要
        if caps.vhca_id != 0 && !self.is_ecpf {
            if !self.is_vf {
                log::info!(target: "mlx5", "Device refined as VF based on vhca_id {:#x}", caps.vhca_id);
                self.is_vf = true;
            }
        } else if caps.vport_group_manager && self.is_vf {
            log::warn!(target: "mlx5", "Device was marked as VF but has vport_group_manager; treating as PF");
            self.is_vf = false;
        }

        // VF の場合は MSI-X 制限を EQ 数に反映させる
        if self.is_vf && max_msix > 0 && max_msix < caps.max_eq {
            log::debug!(target: "mlx5", "Capping max_eq to {} based on VF max_msix", max_msix);
            caps.max_eq = max_msix;
        }

        self.hca_caps = Some(caps);
        self.sw_vhca_id = caps.vhca_id;
        self.state = crate::device::DeviceState::CapsQueried;
        Ok(())
    }

    /// ETHERNET_OFFLOADS ケーパビリティの照会
    pub unsafe fn query_hca_cap_ethernet(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        log::info!(target: "mlx5", "Querying ETHERNET_OFFLOADS Capabilities...");
        *in_mbox = CmdMailbox::zeroed();
        crate::cmd::hca::build_query_hca_cap_input(in_mbox, crate::cmd::hca::MLX5_CAP_ETHERNET_OFFLOADS);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryHcaCap,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        // byte 0x10 からペイロード。Linux ifcの ethernet_offloads_cap_bits を参照
        // RSS, LRO, Checksum 等のフラグを取得可能
        let rss_en = (out_mbox.data[0x10 + 0x01] & 0x01) != 0;
        let lro_en = (out_mbox.data[0x10 + 0x01] & 0x02) != 0;
        log::debug!(target: "mlx5", "Ethernet Caps: rss={}, lro={}", rss_en, lro_en);

        if let Some(caps) = self.hca_caps.as_mut() {
            caps.rss_en = rss_en;
            caps.lro_en = lro_en;
            caps.csum_cap = true; // Ethernetページがあれば基本csumは可能
        }

        Ok(())
    }

    /// HCA Capabilities (MAX) の照会
    pub unsafe fn query_hca_cap_max(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        log::info!(target: "mlx5", "Querying HCA Capabilities (MAX)...");
        *in_mbox = CmdMailbox::zeroed();
        // Query MAX caps (op_mod = 1)
        crate::cmd::hca::build_query_hca_cap_input(in_mbox, 0); // 0 = GENERAL
        in_mbox.data[0x10 + 0x06] |= 1; // set op_mod bit 0 for MAX

        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryHcaCap,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let cap_view = crate::structs::caps::HcaCapLayout::new(&out_mbox.data);

        log::info!(
            target: "mlx5",
            "HCA Max Limits: max_cq={}, max_sq={}, max_rq={}, max_eq={}, max_mkey={}",
            1 << cap_view.log_max_cq(),
            1 << cap_view.log_max_sq(),
            1 << cap_view.log_max_rq(),
            1 << cap_view.log_max_eq(),
            1 << cap_view.log_max_mkey(),
        );

        Ok(())
    }

    /// ドライバの起動時に必要な全 HCA Capability を一気に取得
    pub unsafe fn query_all_caps(&mut self) -> Mlx5Result<()> {
        self.query_hca_cap_max()?;
        self.query_and_set_hca_cap()?;
        self.query_hca_cap_ethernet()?;
        self.query_hca_cap_flow_table()
    }

    /// HCA Capabilities を設定 (SET_HCA_CAP)
    pub unsafe fn set_hca_cap_general(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let out_mbox = &mut *(self.cmd_out_mbox_virt as *mut CmdMailbox);

        // 1. まず現在の設定を取得 (op_mod = 0: CURRENT)
        log::info!(target: "mlx5", "Querying current HCA Capabilities for modification...");
        *in_mbox = CmdMailbox::zeroed();
        crate::cmd::hca::build_query_hca_cap_input(in_mbox, 0); // 0 = GENERAL
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryHcaCap,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        // 2. 取得した設定をベースに一部を書き換え
        let mut caps_payload = [0u8; 4096 - 16];
        caps_payload.copy_from_slice(&out_mbox.data[16..4096]);

        {
            let mut cap_view = crate::structs::caps::HcaCapLayoutMut::new(&mut caps_payload);
            
            // Linux の handle_hca_cap に倣い、いくつかのパラメータを最適化
            
            // pkey_table_size = 128 (to_fw_pkey_sz(128) = 1)
            cap_view.set_pkey_table_size(1);
            
            // log_uar_page_sz = 0 (for 4K pages)
            cap_view.set_log_uar_page_sz(0);
            
            // cmdif_checksum = 0 (disable)
            cap_view.set_cmdif_checksum(0);
        }

        log::info!(target: "mlx5", "Setting modified HCA Capabilities...");
        *in_mbox = CmdMailbox::zeroed();
        crate::cmd::hca::build_set_hca_cap_input(in_mbox, 0, &caps_payload);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::SetHcaCap,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            16,
        )?;

        Ok(())
    }

    /// FLOW_TABLE ケーパビリティの照会
    pub unsafe fn query_hca_cap_flow_table(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        log::info!(target: "mlx5", "Querying FLOW_TABLE Capabilities...");
        *in_mbox = CmdMailbox::zeroed();
        crate::cmd::hca::build_query_hca_cap_input(in_mbox, crate::cmd::hca::MLX5_CAP_FLOW_TABLE);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryHcaCap,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        // NIC Receive Flow Table サポートの確認
        let nic_rx_ft = (out_mbox.data[0x10 + 0x00] & 0x01) != 0;
        log::debug!(target: "mlx5", "Flow Table Caps: nic_rx_ft={}", nic_rx_ft);

        if let Some(caps) = self.hca_caps.as_mut() {
            caps.nic_rx_ft = nic_rx_ft;
        }

        Ok(())
    }
}
