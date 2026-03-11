// ============================================================================
// drivers/mlx5/src/device/caps.rs - MLX5 Device Capabilities
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::defs::{CmdOpcode, HcaCaps};
use crate::device::Mlx5Device;
use crate::error::{Mlx5Error, Mlx5Result};

const HCA_CAP_CMD_LEN: u32 = 16 + 4096;
const HCA_CAP_PAYLOAD_LEN: usize = 4096;
const HCA_CAP_PAGE_LEN: usize = 256;

fn checked_pow2(field: &str, shift: u32) -> u32 {
    1u32.checked_shl(shift).unwrap_or_else(|| {
        log::warn!(
            target: "mlx5",
            "Ignoring out-of-range {} shift {} from QUERY_HCA_CAP",
            field,
            shift
        );
        0
    })
}

fn read_page_dword(page: &[u8; HCA_CAP_PAGE_LEN], index: usize) -> u32 {
    let off = index * 4;
    u32::from_be_bytes([page[off], page[off + 1], page[off + 2], page[off + 3]])
}

fn log_hca_cap_page(label: &str, page: &[u8; HCA_CAP_PAGE_LEN]) {
    let view = crate::structs::caps::HcaCapLayout::new(page);
    log::info!(
        target: "mlx5",
        "[mlx5-diag] {} dw00={:#010x} dw01={:#010x} dw06={:#010x} dw07={:#010x} dw08={:#010x} dw13={:#010x} dw16={:#010x} dw27={:#010x} dw31={:#010x} dw36={:#010x} dw48={:#010x}",
        label,
        read_page_dword(page, 0),
        read_page_dword(page, 1),
        read_page_dword(page, 6),
        read_page_dword(page, 7),
        read_page_dword(page, 8),
        read_page_dword(page, 13),
        read_page_dword(page, 16),
        read_page_dword(page, 27),
        read_page_dword(page, 31),
        read_page_dword(page, 36),
        read_page_dword(page, 48),
    );
    log::info!(
        target: "mlx5",
        "[mlx5-diag] {} fields: hca_cap_2={} vhca_id={:#x} num_ports={} log_max_qp_sz={} log_max_cq_sz={} log_max_eq_sz={} log_max_cq={} log_max_eq={} log_max_mkey={} log_max_rq={} log_max_sq={} log_max_tir={} log_max_tis={} log_max_tis_per_sq={} log_max_td={} driver_version={} mkey_by_name={} vhca_state={} num_vhca_ports={} sw_owner_id={}",
        label,
        view.hca_cap_2(),
        view.vhca_id(),
        view.num_ports(),
        view.log_max_qp_sz(),
        view.log_max_cq_sz(),
        view.log_max_eq_sz(),
        view.log_max_cq(),
        view.log_max_eq(),
        view.log_max_mkey(),
        view.log_max_rq(),
        view.log_max_sq(),
        view.log_max_tir(),
        view.log_max_tis(),
        view.log_max_tis_per_sq(),
        view.log_max_transport_domain(),
        view.driver_version(),
        view.mkey_by_name(),
        view.vhca_state(),
        view.num_vhca_ports(),
        view.sw_owner_id(),
    );
    log::info!(
        target: "mlx5",
        "[mlx5-diag] {} ts: sq_ts_format={} rq_ts_format={}",
        label,
        view.sq_ts_format(),
        view.rq_ts_format(),
    );
}

impl Mlx5Device {
    unsafe fn query_hca_cap_page(
        &mut self,
        cap_type: u16,
        get_max: bool,
    ) -> Mlx5Result<[u8; HCA_CAP_PAGE_LEN]> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        *in_mbox = CmdMailbox::zeroed();
        crate::cmd::hca::build_query_hca_cap_input(in_mbox, cap_type);
        if get_max {
            in_mbox.write_be16(0x06, (cap_type << 1) | 1);
        }
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryHcaCap,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            HCA_CAP_CMD_LEN,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let mut page = [0u8; HCA_CAP_PAGE_LEN];
        page.copy_from_slice(&out_mbox.data[0x10..0x10 + HCA_CAP_PAGE_LEN]);
        Ok(page)
    }

    unsafe fn set_hca_cap_page(&mut self, cap_type: u16, payload: &[u8]) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        *in_mbox = CmdMailbox::zeroed();
        crate::cmd::hca::build_set_hca_cap_input(in_mbox, cap_type, payload);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::SetHcaCap,
            self.cmd_in_mbox_device,
            HCA_CAP_CMD_LEN,
            self.cmd_out_mbox_device,
            16,
        )
    }

    /// HCA Capabilities の照会と設定
    pub unsafe fn query_and_set_hca_cap(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Querying HCA Capabilities...");
        let general = self.query_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL, false)?;
        let general_max = self.query_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL, true)?;
        let cap_view = crate::structs::caps::HcaCapLayout::new(&general);
        let max_view = crate::structs::caps::HcaCapLayout::new(&general_max);
        let mut caps = HcaCaps::default();

        log_hca_cap_page("QUERY_HCA_CAP(CUR)", &general);
        log_hca_cap_page("QUERY_HCA_CAP(MAX)", &general_max);

        caps.max_cq = checked_pow2("log_max_cq", max_view.log_max_cq());
        caps.max_sq = checked_pow2("log_max_sq", max_view.log_max_sq());
        caps.max_rq = checked_pow2("log_max_rq", max_view.log_max_rq());
        caps.max_eq = checked_pow2("log_max_eq", max_view.log_max_eq()).max(1);
        caps.max_mkey = checked_pow2("log_max_mkey", max_view.log_max_mkey()).max(1);
        caps.max_msix = caps.max_eq;
        caps.max_mtu = crate::defs::MLX5_MAX_MTU;
        caps.num_ports = cap_view
            .num_ports()
            .clamp(1, crate::defs::MLX5_MAX_PORTS as u32) as u8;
        caps.hca_cap_2 = cap_view.hca_cap_2();
        caps.log_max_cq_sz = max_view.log_max_cq_sz() as u8;
        caps.log_max_sq_sz = max_view.log_max_qp_sz() as u8;
        caps.log_max_rq_sz = max_view.log_max_qp_sz() as u8;
        caps.log_max_tir = max_view.log_max_tir() as u8;
        caps.log_max_tis = max_view.log_max_tis() as u8;
        caps.log_max_tis_per_sq = max_view.log_max_tis_per_sq() as u8;
        caps.log_max_transport_domain = max_view.log_max_transport_domain() as u8;
        caps.log_max_eq_sz = max_view.log_max_eq_sz() as u8;
        caps.driver_version_cap = cap_view.driver_version();
        caps.vhca_state_cap = cap_view.vhca_state();
        caps.vport_group_manager = cap_view.vport_group_manager();
        caps.csum_cap = cap_view.eth_net_offloads();
        caps.cqe_compression = cap_view.cqe_compression();
        caps.mkey_by_name = cap_view.mkey_by_name();
        caps.sq_ts_format = cap_view.sq_ts_format() as u8;
        caps.rq_ts_format = cap_view.rq_ts_format() as u8;
        caps.vhca_id = cap_view.vhca_id() as u16;
        caps.eswitch_manager = cap_view.eswitch_manager();
        caps.num_vhca_ports = cap_view.num_vhca_ports() as u16;
        caps.sw_owner_id_cap = cap_view.sw_owner_id();
        caps.max_sge = max_view
            .max_sgl_for_optimized_performance()
            .min(u8::MAX as u32) as u8;

        if caps.hca_cap_2 {
            match self.query_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL_2, true) {
                Ok(general_2_max) => {
                    let general_2_view = crate::structs::caps::HcaCap2Layout::new(&general_2_max);
                    caps.sw_vhca_id_valid_cap = general_2_view.sw_vhca_id_valid();
                }
                Err(err) => {
                    log::warn!(
                        target: "mlx5",
                        "QUERY_HCA_CAP(GENERAL_2 MAX) failed: {:?}",
                        err
                    );
                }
            }
        }

        log::info!(
            target: "mlx5",
            "HCA Caps: ports={}, max_cq={}, max_sq={}, max_rq={}, max_eq={}, max_mkey={}, hw_vhca_id={:#x}, general_2={}, sw_owner_id={}, driver_version={}, sw_vhca_id_valid={}, mkey_by_name={}, sq_ts_format={}, rq_ts_format={}, log_max_tir={}, log_max_tis={}, log_max_tis_per_sq={}, log_max_td={}",
            caps.num_ports,
            caps.max_cq,
            caps.max_sq,
            caps.max_rq,
            caps.max_eq,
            caps.max_mkey,
            caps.vhca_id,
            caps.hca_cap_2,
            caps.sw_owner_id_cap,
            caps.driver_version_cap,
            caps.sw_vhca_id_valid_cap,
            caps.mkey_by_name,
            caps.sq_ts_format,
            caps.rq_ts_format,
            caps.log_max_tir,
            caps.log_max_tis,
            caps.log_max_tis_per_sq,
            caps.log_max_transport_domain,
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

        self.hca_caps = Some(caps);
        self.state = crate::device::DeviceState::CapsQueried;
        Ok(())
    }

    /// ETHERNET_OFFLOADS ケーパビリティの照会
    pub unsafe fn query_hca_cap_ethernet(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        log::info!(target: "mlx5", "Querying ETHERNET_OFFLOADS Capabilities...");
        *in_mbox = CmdMailbox::zeroed();
        crate::cmd::hca::build_query_hca_cap_input(
            in_mbox,
            crate::cmd::hca::MLX5_CAP_ETHERNET_OFFLOADS,
        );
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryHcaCap,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            HCA_CAP_CMD_LEN,
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
        log::info!(target: "mlx5", "Querying HCA Capabilities (MAX)...");
        let general = self.query_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL, true)?;
        let cap_view = crate::structs::caps::HcaCapLayout::new(&general);

        log_hca_cap_page("QUERY_HCA_CAP(MAX,standalone)", &general);

        log::info!(
            target: "mlx5",
            "HCA Max Limits: max_cq={}, max_sq={}, max_rq={}, max_eq={}, max_mkey={}",
            checked_pow2("log_max_cq(max)", cap_view.log_max_cq()),
            checked_pow2("log_max_sq(max)", cap_view.log_max_sq()),
            checked_pow2("log_max_rq(max)", cap_view.log_max_rq()),
            checked_pow2("log_max_eq(max)", cap_view.log_max_eq()),
            checked_pow2("log_max_mkey(max)", cap_view.log_max_mkey()),
        );

        Ok(())
    }

    /// ドライバの起動時に必要な全 HCA Capability を一気に取得
    pub unsafe fn query_all_caps(&mut self) -> Mlx5Result<()> {
        self.query_and_set_hca_cap()?;
        if let Err(err) = self.query_hca_cap_max() {
            log::warn!(
                target: "mlx5",
                "QUERY_HCA_CAP(MAX) failed during bootstrap: {:?}; continuing with current caps only",
                err
            );
        }
        self.query_hca_cap_ethernet()?;
        self.query_hca_cap_flow_table()
    }

    /// HCA Capabilities を設定 (SET_HCA_CAP)
    pub unsafe fn set_hca_cap_general(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Querying current HCA Capabilities for modification...");
        let general = self.query_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL, false)?;
        let general_max = self.query_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL, true)?;
        let general_max_view = crate::structs::caps::HcaCapLayout::new(&general_max);
        let mut caps_payload = [0u8; HCA_CAP_PAYLOAD_LEN];
        caps_payload[..HCA_CAP_PAGE_LEN].copy_from_slice(&general);

        {
            let mut cap_view =
                crate::structs::caps::HcaCapLayoutMut::new(&mut caps_payload[..HCA_CAP_PAGE_LEN]);
            cap_view.set_log_uar_page_sz(0);
            if cap_view.cmdif_checksum() != 0 {
                cap_view.set_cmdif_checksum(0);
            }
            if general_max_view.mkey_by_name() {
                cap_view.set_mkey_by_name(true);
            }
            if general_max_view.vhca_state() {
                cap_view.set_vhca_state(true);
                cap_view.set_event_on_vhca_state_allocated(true);
                cap_view.set_event_on_vhca_state_active(true);
                cap_view.set_event_on_vhca_state_in_use(true);
                cap_view.set_event_on_vhca_state_teardown_request(true);
            }
        }

        log::info!(target: "mlx5", "Setting modified HCA Capabilities...");
        self.set_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL, &caps_payload)
    }

    pub unsafe fn set_hca_cap_general_2(&mut self) -> Mlx5Result<()> {
        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.hca_cap_2 || !caps.sw_vhca_id_valid_cap || self.sw_vhca_id == 0 {
            return Ok(());
        }

        log::info!(
            target: "mlx5",
            "Setting GENERAL_2 HCA Capabilities (sw_vhca_id={:#x})...",
            self.sw_vhca_id
        );
        let general_2 = self.query_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL_2, false)?;
        let mut caps_payload = [0u8; HCA_CAP_PAYLOAD_LEN];
        caps_payload[..HCA_CAP_PAGE_LEN].copy_from_slice(&general_2);
        {
            let mut cap_view =
                crate::structs::caps::HcaCap2LayoutMut::new(&mut caps_payload[..HCA_CAP_PAGE_LEN]);
            cap_view.set_sw_vhca_id_valid(true);
            cap_view.set_sw_vhca_id(self.sw_vhca_id);
        }
        self.set_hca_cap_page(crate::cmd::hca::MLX5_CAP_GENERAL_2, &caps_payload)
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
            HCA_CAP_CMD_LEN,
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
