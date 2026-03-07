// ============================================================================
// drivers/mlx5/src/device/init.rs - MLX5 Device Initialization
// ============================================================================

use crate::bootstrap::{Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan};
use crate::cmd::CmdQueueTransport; // needed for layout parsing
use crate::cmd::hca::{build_enable_hca_input, build_set_issi_input, VhcaState, build_init_hca_input};
use crate::cmd::{CmdMailbox, CmdQueue};
use crate::defs::CmdOpcode;
use crate::device::{DeviceState, Mlx5Device};
use crate::error::{Mlx5Error, Mlx5Result};
use alloc::vec; // bring `vec!` macro into scope for candidate lists
use alloc::vec::Vec;
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
        let sw_vhca_id = self.sw_vhca_id;
        let sw_owner_id = self.sw_owner_id;

        log::info!(target: "mlx5", "Executing INIT_HCA (sw_vhca_id={:#x})...", sw_vhca_id);
        build_init_hca_input(in_mbox, sw_vhca_id, sw_owner_id);

        self.execute_cmd_with_uid_candidates(
            CmdOpcode::InitHca,
            self.cmd_in_mbox_device,
            32, // mailbox header(16) + sw_vhca_id/sw_owner_id area
            self.cmd_out_mbox_device,
            16,
        )?;

        log::info!(target: "mlx5", "HCA initialized successfully");
        Ok(())
    }

    pub unsafe fn bootstrap(
        &mut self,
        config: &Mlx5BootstrapConfig,
        resources: &Mlx5AllocatedResources,
    ) -> Mlx5Result<()> {
        if config.is_vf != self.is_vf() {
            return Err(Mlx5Error::InvalidParameter);
        }

        let plan = Mlx5BootstrapPlan::new(config);
        plan.validate_resources(resources)?;
        self.set_pci_bdf(
            config.pci_identity.bus,
            config.pci_identity.device,
            config.pci_identity.function,
        );

        let fw_page_addrs = resources.fw_page_device_addrs();
        let eq_bufs = resources.eq_bufs();
        let tx_cq_bufs = resources.tx_cq_bufs();
        let rx_cq_bufs = resources.rx_cq_bufs();
        let sq_bufs = resources.sq_bufs();
        let rq_bufs = resources.rq_bufs();
        let profile = plan.queue_profile();

        self.init_multi_queue(
            resources.cmdq.virt_addr,
            resources.cmdq.device_addr,
            resources.cmd_in_mbox.virt_addr,
            resources.cmd_in_mbox.device_addr,
            resources.cmd_out_mbox.virt_addr,
            resources.cmd_out_mbox.device_addr,
            &fw_page_addrs,
            &config.mkey_params,
            &eq_bufs,
            &tx_cq_bufs,
            &rx_cq_bufs,
            &sq_bufs,
            &rq_bufs,
            profile.log_eq_size,
            profile.log_cq_size,
            profile.log_sq_size,
            profile.log_rq_size,
        )
    }

    /// デバイスの完全パイプライン初期化
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn init_full(
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
    pub(crate) unsafe fn init_multi_queue(
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
        log::info!(target: "mlx5", "Phase 1: Waiting for firmware/BAR0 to become accessible...");
        let mut boot_success = false;
        for retry in 0..5 {
            match self.wait_firmware() {
                Ok(()) => {
                    boot_success = true;
                    break;
                }
                Err(Mlx5Error::DeviceNotReady) if self.is_vf() => {
                    log::warn!(target: "mlx5", "VF BAR0 not ready (floating), retry {}/5...", retry + 1);
                }
                Err(e) => return Err(e),
            }
            // 200ms 待機
            let start_ms = kernel_api::service::kernel::instance().current_tick();
            while kernel_api::service::kernel::instance().current_tick() - start_ms < 200 {
                core::hint::spin_loop();
            }
        }

        if !boot_success && self.is_vf() {
            log::info!(target: "mlx5", "BAR0 still floating, assuming VF initialization can proceed to command interface...");
            self.assume_firmware_ready_for_vf();
        } else if !boot_success {
            return Err(Mlx5Error::DeviceNotReady);
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

            // Verify that the VF's VHCA is actually ready
            // PF が VF を有効化するまでに時間がかかる場合があるため、数回リトライする
            let mut vhca_ready = false;
            for _ in 0..10 {
                match self.query_vhca_state(0) {
                    Ok(vhca_ctx) => {
                        log::info!(target: "mlx5", "VF VHCA state: {:?}", vhca_ctx.state);
                        if vhca_ctx.state.is_activation_ready() {
                            vhca_ready = true;
                            break;
                        }
                        log::warn!(target: "mlx5", "VF VHCA not ready yet ({:?}), retrying...", vhca_ctx.state);
                    }
                    Err(e) => {
                        log::warn!(target: "mlx5", "Failed to query VHCA state for VF: {:?}", e);
                        // FW によってはこのコマンドを制限している場合があるため、失敗しても続行の余地あり
                        vhca_ready = true;
                        break;
                    }
                }
                // 100ms 待機
                let start_ms = kernel_api::service::kernel::instance().current_tick();
                while kernel_api::service::kernel::instance().current_tick() - start_ms < 100 {
                    core::hint::spin_loop();
                }
            }

            if !vhca_ready {
                log::error!(target: "mlx5", "VF VHCA activation timed out");
                return Err(Mlx5Error::DeviceNotReady);
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

        // Dynamic resource adjustment based on reported capabilities
        if let Some(caps) = self.hca_caps() {
            log::info!(target: "mlx5", "HCA Caps limits: max_mkey={}, max_cq={}, max_sq={}, max_rq={}", 
                caps.max_mkey, caps.max_cq, caps.max_sq, caps.max_rq);
            
            // VF では PF からのリソース割り当てが少ない場合があるため、警告を出力
            if caps.max_mkey < 16 {
                log::warn!(target: "mlx5", "Device reports very few mkeys ({}); MKEY operations might fail", caps.max_mkey);
            }
        }

        // Once caps are queried, we know the real vhca_id for the VF.
        // Update the default UID to avoid unnecessary retries in the candidate loop.
        if self.is_vf() {
            if let Some(cmd) = self.cmd.as_mut() {
                cmd.set_uid(self.sw_vhca_id);
                log::info!(target: "mlx5", "Updated VF command UID to {:#x}", self.sw_vhca_id);
            }
        }

        // VF の場合は PF から割り当てられた MAC アドレスを取得する
        if self.is_vf() {
            log::info!(target: "mlx5", "Querying VF port properties and ensuring vport is active...");
            
            // VF 自身の vport (index 0) に対して admin up を試みる
            let _ = self.set_port_admin_up(0);
            
            // query_port_mac は内部で execute_cmd_with_uid_candidates を使用している
            // 一部の VF ではこのコマンドが拒否される場合があるため、エラーを無視する
            if let Err(e) = self.query_port_mac(0) {
                log::warn!(target: "mlx5", "Failed to query VF port MAC address: {:?}", e);
            }
            if let Err(e) = self.query_port_mtu(0) {
                log::warn!(target: "mlx5", "Failed to query VF port MTU: {:?}", e);
            }
        }

        // SET_HCA_CAP を呼び出して、ドライバ固有の要件に合わせてデバイスを最適化
        // INIT_HCA の前に実行する必要がある (Linux に倣う)
        log::info!(target: "mlx5", "Configuring HCA capabilities...");
        self.set_hca_cap_general()?;

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

        // 完全に失敗した場合は、VF特有の「予約済みLKEY」をPFから取得して使用する
        if !mkey_ok && self.is_vf() {
            log::info!(target: "mlx5", "Attempting to query reserved lkey for VF fallback...");
            match self.query_reserved_lkey() {
                Ok(lkey) => {
                    self.mkey = lkey;
                    mkey_ok = true;
                    log::warn!(target: "mlx5", "[5/8] Using reserved lkey={:#x} as fallback", lkey);
                }
                Err(e) => {
                    log::error!(target: "mlx5", "[5/8] Failed to query reserved lkey: {:?}", e);
                }
            }
        }

        if !mkey_ok {
            return Err(Mlx5Error::CommandFailed(0xff));
        }

        let _ = self.refresh_port_runtime_state(0);

        // Phase 4: Queues
        let mut eqns = Vec::new();
        for (i, eq_buf) in eq_bufs.iter().enumerate() {
            // RanyOS DriverContext currently supports a single IRQ, so map all EQs to vector 0
            let eqn = self.create_eq_hw(eq_buf.0, eq_buf.1, log_eq_size, 0, 0)?;
            eqns.push(eqn);
        }

        let mut tx_cqns = Vec::new();
        for (i, cq_buf) in tx_cq_bufs.iter().enumerate() {
            let eqn = eqns[i % eqns.len()];
            let cqn = self.create_cq_hw(cq_buf.0, cq_buf.1, cq_buf.2, cq_buf.3, log_cq_size, eqn)?;
            tx_cqns.push(cqn);
        }

        let mut rx_cqns = Vec::new();
        for (i, cq_buf) in rx_cq_bufs.iter().enumerate() {
            let eqn = eqns[i % eqns.len()];
            let cqn = self.create_cq_hw(cq_buf.0, cq_buf.1, cq_buf.2, cq_buf.3, log_cq_size, eqn)?;
            rx_cqns.push(cqn);
        }

        let tisn = self.create_tis(&crate::resources::TisParams {
            pd: self.pd,
            td: self.td,
            port: 1,
            prio: 0,
        })?;
        for (i, sq_buf) in sq_bufs.iter().enumerate() {
            let cqn = tx_cqns[i % tx_cqns.len()];
            let _sqn = self.create_sq_hw(
                sq_buf.0,
                sq_buf.1,
                sq_buf.2,
                sq_buf.3,
                log_sq_size,
                cqn,
                tisn,
            )?;
        }

        let scatter_fcs = self.hca_caps().map(|c| c.scatter_fcs).unwrap_or(false);
        let vlan_strip = self.hca_caps().map(|c| c.vlan_strip).unwrap_or(false);

        let mut rqns = Vec::new();
        for (i, rq_buf) in rq_bufs.iter().enumerate() {
            let cqn = rx_cqns[i % rx_cqns.len()];
            let rqn = self.create_rq_hw(
                rq_buf.0,
                rq_buf.1,
                rq_buf.2,
                rq_buf.3,
                log_rq_size,
                cqn,
                0, // Dummy TIRN for DirectRq (unused in create_rq_hw)
                scatter_fcs,
                vlan_strip,
            )?;
            rqns.push(rqn);
        }

        let tirn = if rqns.len() > 1 {
            let log_rqt_size = (32 - (rqns.len() as u32 - 1).leading_zeros()) as u8;
            let rqtn = self.create_rqt(&rqns, log_rqt_size)?;
            self.create_tir(&crate::resources::TirParams {
                receive_type: crate::resources::TirReceiveType::Rqt,
                td: self.td,
                inline_rqn: 0,
                rqtn,
                rss: Some(crate::flow::RssConfig::default()),
                scatter_fcs,
                vlan_strip,
            })?
        } else {
            self.create_tir(&crate::resources::TirParams {
                receive_type: crate::resources::TirReceiveType::DirectRq,
                td: self.td,
                inline_rqn: rqns[0],
                rqtn: 0,
                rss: None,
                scatter_fcs,
                vlan_strip,
            })?
        };

        // Finalize
        let _ = self.setup_rx_flow_table_advanced(tirn);
        let _ = self.set_port_admin_up(0);
        if let Some(port) = self.ports.get_mut(0) {
            port.admin_up();
        }

        // Give the firmware a moment to reflect the port state change before reporting active
        let start_ms = kernel_api::service::kernel::instance().current_tick();
        while kernel_api::service::kernel::instance().current_tick() - start_ms < 50 {
            core::hint::spin_loop();
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
        let start_ms = kernel_api::service::kernel::instance().current_tick();
        while kernel_api::service::kernel::instance().current_tick() - start_ms < 2000 {
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
