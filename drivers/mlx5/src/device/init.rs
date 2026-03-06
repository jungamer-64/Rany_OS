// ============================================================================
// drivers/mlx5/src/device/init.rs - MLX5 Device Initialization
// ============================================================================

use crate::cmd::CmdQueueTransport; // needed for layout parsing
use crate::cmd::hca::{build_enable_hca_input, build_set_issi_input};
use crate::cmd::{CmdMailbox, CmdQueue};
use crate::defs::CmdOpcode;
use crate::device::{DeviceState, Mlx5Device};
use crate::error::{Mlx5Error, Mlx5Result};
use alloc::vec; // bring `vec!` macro into scope for candidate lists
// unused MkeyParams removed

impl Mlx5Device {
    /// 起動待機 (ConnectX-4 Lx 等)
    pub unsafe fn wait_firmware(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Waiting for firmware to be ready...");
        match crate::fw::wait_fw_ready(self.bar0_base, 30000) {
            Ok(info) => {
                self.fw_info = Some(info.clone());
                self.state = DeviceState::FirmwareReady;
                log::info!(
                    target: "mlx5",
                    "Firmware is ready ({}.{}.{}, cmd_if_rev={})",
                    info.major,
                    info.minor,
                    info.subminor,
                    info.cmd_if_rev
                );
                Ok(())
            }
            Err(e) => {
                log::error!(target: "mlx5", "Firmware boot timeout or error: {:?}", e);
                Err(e)
            }
        }
    }

    /// VF 用に FW が準備できているとみなす
    pub fn assume_firmware_ready_for_vf(&mut self) {
        self.state = DeviceState::FirmwareReady;
        log::info!(target: "mlx5", "Assumed firmware ready for VF");
    }

    /// コマンドインタフェースの初期化
    pub unsafe fn init_command_interface(
        &mut self,
        cmdq_virt: u64,
        cmdq_pa: u64,
        cmd_in_mbox_virt: u64,
        cmd_in_mbox_pa: u64,
        cmd_out_mbox_virt: u64,
        cmd_out_mbox_pa: u64,
    ) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Initializing command interface...");

        // Keep the mailbox addresses for later use
        self.cmd_in_mbox_virt = cmd_in_mbox_virt;
        self.cmd_in_mbox_device = cmd_in_mbox_pa;
        self.cmd_out_mbox_virt = cmd_out_mbox_virt;
        self.cmd_out_mbox_device = cmd_out_mbox_pa;

        if cmdq_pa == 0 {
            log::error!(
                target: "mlx5",
                "CRITICAL: zero CMDQ physical address (IOMMU may block access)"
            );
        }

        // Read layout info from BAR0 registers
        let base = self.bar0_base as usize;
        let cmdq_addr_l_sz = crate::mmio_read_be32(base + crate::regs::init_seg::CMDQ_ADDR_L_SZ);
        let (log_cmdq_size, log_cmd_stride, _nic_if_supported) =
            CmdQueueTransport::parse_hw_cmdq_layout(cmdq_addr_l_sz);

        let mut cmd = CmdQueue::new(
            self.bar0_base,
            cmdq_pa,
            cmdq_virt,
            self.cmd_in_mbox_virt,
            self.cmd_out_mbox_virt,
            log_cmdq_size,
            log_cmd_stride,
        )?;
        cmd.setup_cmdq_in_bar0();

        self.cmd = Some(cmd);
        self.state = DeviceState::CommandInitialized;

        log::info!(
            target: "mlx5",
            "Command interface initialized (log_sz={} stride={})",
            log_cmdq_size,
            log_cmd_stride
        );
        Ok(())
    }

    /// HCA の有効化と ISSI セットアップ
    pub unsafe fn enable_hca_and_setup(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;

        log::info!(target: "mlx5", "Enabling HCA...");
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_enable_hca_input(in_mbox, 0);
        // enable_hca doesn't return any useful output, but the command can fail
        // when the UID isn't correct on a VF.  Try candidate UIDs.
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::EnableHca,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            16,
        )?;

        log::info!(target: "mlx5", "Querying ISSI...");
        *in_mbox = CmdMailbox::zeroed();
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryIssi,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            64,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let current_issi = out_mbox.read_be16(0x02);
        let supported_issi = out_mbox.read_be16(0x04);
        log::info!(target: "mlx5", "ISSI: current={}, supported={:#x}", current_issi, supported_issi);

        if current_issi == 0 && (supported_issi & 0x01) != 0 {
            log::info!(target: "mlx5", "Setting ISSI to 1...");
            build_set_issi_input(in_mbox, 1);
            self.execute_cmd_with_uid_candidates(
                CmdOpcode::SetIssi,
                self.cmd_in_mbox_device,
                16,
                self.cmd_out_mbox_device,
                16,
            )?;
        }

        self.state = DeviceState::HcaEnabled;
        Ok(())
    }

    /// HCA の初期化 (INIT_HCA)
    pub unsafe fn init_hca(&mut self) -> Mlx5Result<()> {
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();

        log::info!(target: "mlx5", "Executing INIT_HCA...");
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::InitHca,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            16,
        )?;

        log::info!(target: "mlx5", "HCA initialized successfully");
        Ok(())
    }

    /// デバイスの完全パイプライン初期化
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn init_full(
        &mut self,
        cmdq_virt: u64,
        cmdq_device: u64,
        cmd_in_mbox_virt: u64,
        cmd_in_mbox_device: u64,
        cmd_out_mbox_virt: u64,
        cmd_out_mbox_device: u64,
        fw_page_addrs: &[u64],
        mkey_params: &crate::resources::MkeyParams,
        eq_buf: (u64, u64),
        tx_cq_buf: (u64, u64, u64, u64),
        rx_cq_buf: (u64, u64, u64, u64),
        sq_buf: (u64, u64, u64, u64),
        rq_buf: (u64, u64, u64, u64),
        log_eq_size: u8,
        log_cq_size: u8,
        log_sq_size: u8,
        log_rq_size: u8,
    ) -> Mlx5Result<()> {
        self.init_multi_queue(
            cmdq_virt,
            cmdq_device,
            cmd_in_mbox_virt,
            cmd_in_mbox_device,
            cmd_out_mbox_virt,
            cmd_out_mbox_device,
            fw_page_addrs,
            mkey_params,
            &[eq_buf],
            &[tx_cq_buf],
            &[rx_cq_buf],
            &[sq_buf],
            &[rq_buf],
            log_eq_size,
            log_cq_size,
            log_sq_size,
            log_rq_size,
        )
    }

    /// マルチキュー対応の完全初期化パイプライン
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn init_multi_queue(
        &mut self,
        cmdq_virt: u64,
        cmdq_device: u64,
        cmd_in_mbox_virt: u64,
        cmd_in_mbox_device: u64,
        cmd_out_mbox_virt: u64,
        cmd_out_mbox_device: u64,
        fw_page_addrs: &[u64],
        mkey_params: &crate::resources::MkeyParams,
        eq_bufs: &[(u64, u64)],
        tx_cq_bufs: &[(u64, u64, u64, u64)],
        rx_cq_bufs: &[(u64, u64, u64, u64)],
        sq_bufs: &[(u64, u64, u64, u64)],
        rq_bufs: &[(u64, u64, u64, u64)],
        log_eq_size: u8,
        log_cq_size: u8,
        log_sq_size: u8,
        log_rq_size: u8,
    ) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "=== Starting multi-queue pipeline initialization ===");

        // Phase 1: Boot
        match self.wait_firmware() {
            Ok(()) => {}
            Err(Mlx5Error::DeviceNotReady) if self.is_vf() => self.assume_firmware_ready_for_vf(),
            Err(e) => return Err(e),
        }

        self.init_command_interface(
            cmdq_virt,
            cmdq_device,
            cmd_in_mbox_virt,
            cmd_in_mbox_device,
            cmd_out_mbox_virt,
            cmd_out_mbox_device,
        )?;

        // For VFs the majority of commands will only succeed when a proper UID
        // is present.  Set a sensible default before making any further calls so
        // that "simple" operations like enabling the HCA or querying caps work
        // without having to retry inside each helper.
        if self.is_vf() {
            if let Some(cmd) = self.cmd.as_mut() {
                let default_uid = if self.sw_vhca_id != 0 {
                    self.sw_vhca_id
                } else {
                    0xFFFF
                };
                cmd.set_uid(default_uid);
                log::debug!(target: "mlx5", "VF detected, initial UID set to {:#x}", default_uid);
            }
        }

        self.enable_hca_and_setup()?;

        // Phase 2: Pages & Caps
        // VF devices typically do not request additional firmware pages; the PF
        // is responsible for managing them.  Ignore any page requirements to
        // avoid failing during early boot.
        let (func_id, requested_pages) = self.query_required_pages(0x01).unwrap_or((0, 0));
        self.fw_function_id = func_id;
        if !self.is_vf() && requested_pages > 0 && !fw_page_addrs.is_empty() {
            self.provide_pages(
                func_id,
                &fw_page_addrs[..(requested_pages as usize).min(fw_page_addrs.len())],
            )?;
        }
        self.query_all_caps()?;
        self.init_hca()?;

        // Phase 3: Resources
        self.alloc_uar()?;
        self.alloc_pd()?;
        self.alloc_td()?;
        let _ = self.set_driver_version();

        // VF probe: try a short list of PD values when creating MKEY, falling
        // back to the reserved lkey only if none succeed.
        let mut pd_candidates = vec![0, 1];
        if self.pd != 0 && self.pd != 1 {
            pd_candidates.push(self.pd);
        }
        let mut td_candidates = vec![0, 1];
        if self.td != 0 && self.td != 1 {
            td_candidates.push(self.td);
        }

        let mut effective_mkey_params = mkey_params.clone();
        let mut mkey_ok = false;
        for &pd_try in &pd_candidates {
            effective_mkey_params.pd = pd_try;
            match self.create_mkey(&effective_mkey_params) {
                Ok(_) => {
                    mkey_ok = true;
                    self.pd = pd_try;
                    log::info!(target: "mlx5", "[5/8] MKEY created with PD {}", pd_try);
                    break;
                }
                Err(e) => {
                    log::warn!(target: "mlx5", "[5/8] MKEY creation failed with PD {}: {:?}", pd_try, e);
                }
            }
        }
        if !mkey_ok {
            if self.is_vf() {
                let lkey = self.query_reserved_lkey().unwrap_or(0x100);
                // directly assign fallback key; helper method not present
                self.mkey = lkey;
                log::warn!(target: "mlx5", "[5/8] Using reserved lkey={:#x}", lkey);
            } else {
                return Err(Mlx5Error::CommandFailed(0xff));
            }
        }

        let _ = self.query_port_mac(0);
        let _ = self.query_port_state(0);

        // Phase 4: Queues
        let eqn = self.create_eq_hw(eq_bufs[0].0, eq_bufs[0].1, log_eq_size, 0, 0)?;

        let tx_cqn = self.create_cq_hw(
            tx_cq_bufs[0].0,
            tx_cq_bufs[0].1,
            tx_cq_bufs[0].2,
            tx_cq_bufs[0].3,
            log_cq_size,
            eqn,
        )?;
        let rx_cqn = self.create_cq_hw(
            rx_cq_bufs[0].0,
            rx_cq_bufs[0].1,
            rx_cq_bufs[0].2,
            rx_cq_bufs[0].3,
            log_cq_size,
            eqn,
        )?;

        let tisn = self.create_tis(&crate::resources::TisParams {
            pd: self.pd,
            td: self.td,
            port: 1,
            prio: 0,
        })?;
        let _sqn = self.create_sq_hw(
            sq_bufs[0].0,
            sq_bufs[0].1,
            sq_bufs[0].2,
            sq_bufs[0].3,
            log_sq_size,
            tx_cqn,
            tisn,
        )?;

        let scatter_fcs = self.hca_caps().map(|c| c.scatter_fcs).unwrap_or(false);
        let vlan_strip = self.hca_caps().map(|c| c.vlan_strip).unwrap_or(false);
        let tirn = self.create_tir(&crate::resources::TirParams {
            receive_type: crate::resources::TirReceiveType::DirectRq,
            td: self.td,
            inline_rqn: 0, // Will be set by create_rq_hw if it transitions
            rqtn: 0,
            rss: None,
            scatter_fcs,
            vlan_strip,
        })?;

        let _rqn = self.create_rq_hw(
            rq_bufs[0].0,
            rq_bufs[0].1,
            rq_bufs[0].2,
            rq_bufs[0].3,
            log_rq_size,
            rx_cqn,
            tirn,
            scatter_fcs,
            vlan_strip,
        )?;

        // Finalize
        let _ = self.setup_rx_flow_table(tirn);
        if let Some(port) = self.ports.get_mut(0) {
            port.admin_up();
        }

        self.resources_allocated = true;
        self.state = DeviceState::Active;
        Ok(())
    }

    /// ソフトウェアリセットのトリガー
    pub unsafe fn trigger_sw_reset(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Triggering software reset via SW_RESET register...");
        crate::mmio_write_be32(self.bar0_base as usize + crate::regs::init_seg::SW_RESET, 1);

        // initializing bit がセットされるまで待機
        let start_ms = kernel_api::services::kernel().current_tick();
        while kernel_api::services::kernel().current_tick() - start_ms < 2000 {
            let initializing = crate::mmio_read_be32(
                self.bar0_base as usize + crate::regs::init_seg::INITIALIZING,
            );
            if (initializing & crate::regs::fw_state::INITIALIZING_BIT) != 0 {
                log::info!(target: "mlx5", "Software reset in progress (initializing bit set)");
                self.state = DeviceState::Uninitialized;
                return Ok(());
            }
            core::hint::spin_loop();
        }

        log::warn!(target: "mlx5", "SW reset bit check timeout (HCA might already be in reset or not responding)");
        self.state = DeviceState::Uninitialized;
        Ok(())
    }

    /// デバイスのリカバリ試行
    pub unsafe fn recover(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Attempting device recovery...");

        // 1. まずは正常なティアダウンを試みる
        // コマンドIFが生きている場合はこれが最も安全
        match self.teardown_full() {
            Ok(()) => {
                log::info!(target: "mlx5", "Graceful teardown successful");
            }
            Err(e) => {
                log::warn!(target: "mlx5", "Graceful teardown failed: {:?}. Forcing SW reset...", e);
                // 2. 失敗した場合は HW リセットを強行
                self.trigger_sw_reset()?;
            }
        }

        // 3. FW 再起動待ち
        self.wait_firmware()?;

        log::info!(target: "mlx5", "Device recovery successful: ready for re-initialization");
        Ok(())
    }
}
