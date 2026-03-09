// ============================================================================
// drivers/mlx5/src/device/init.rs - MLX5 Device Initialization
// ============================================================================

use crate::bootstrap::{Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan};
use crate::cmd::CmdQueueTransport; // needed for layout parsing
use crate::cmd::hca::{build_enable_hca_input, build_set_issi_input, build_init_hca_input};
use crate::cmd::{CmdMailbox, CmdQueue};
use crate::defs::CmdOpcode;
use crate::defs::MLX5_CMD_MBOX_SIZE;
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
        self.sw_owner_id = self.derive_sw_owner_id();
        log::info!(
            target: "mlx5",
            "Derived sw_owner_id={:08x}:{:08x}:{:08x}:{:08x}",
            self.sw_owner_id[0],
            self.sw_owner_id[1],
            self.sw_owner_id[2],
            self.sw_owner_id[3]
        );

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

    unsafe fn wait_post_cmdif_ready(&mut self, timeout_ms: u64) -> Mlx5Result<()> {
        let start_ms = kernel_api::service::kernel::instance().current_tick();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while kernel_api::service::kernel::instance().current_tick().saturating_sub(start_ms)
            < timeout_ms
        {
            let initializing =
                crate::mmio_read_be32(self.bar0_base as usize + crate::regs::init_seg::INITIALIZING);

            if initializing != 0 && initializing != u32::MAX {
                if (initializing & crate::regs::fw_state::INITIALIZING_BIT) == 0 {
                    return Ok(());
                }
            }

            core::hint::spin_loop();
        }

        Err(Mlx5Error::DeviceNotReady)
    }

    /// HCA の有効化と ISSI セットアップ
    pub unsafe fn enable_hca_and_setup(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;

        crate::boot_trace("[MLX5_BOOT] enable_hca start\n");
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
        crate::boot_trace("[MLX5_BOOT] enable_hca done\n");

        if self.is_vf() {
            log::info!(target: "mlx5", "Skipping QUERY_ISSI on VF; continuing with ISSI 0");
            self.state = DeviceState::HcaEnabled;
            return Ok(());
        }

        crate::boot_trace("[MLX5_BOOT] query_issi start\n");
        log::info!(target: "mlx5", "Querying ISSI...");
        *in_mbox = CmdMailbox::zeroed();
        match self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryIssi,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            64,
        ) {
            Ok(()) => {}
            Err(Mlx5Error::CommandFailed(status)) if status != 0 => {
                let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                let syndrome = out_mbox.read_be32(0x04);
                log::warn!(
                    target: "mlx5",
                    "QUERY_ISSI not supported or rejected by FW (status={:#x} syndrome={:#x}); continuing with ISSI 0",
                    status,
                    syndrome
                );
                self.state = DeviceState::HcaEnabled;
                return Ok(());
            }
            Err(err) => return Err(err),
        }
        crate::boot_trace("[MLX5_BOOT] query_issi done\n");
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let current_issi = out_mbox.read_be16(0x0a);
        let supported_issi = out_mbox.read_be32(0x20);
        log::info!(target: "mlx5", "ISSI: current={}, supported={:#x}", current_issi, supported_issi);

        if current_issi == 0 && (supported_issi & (1 << 1)) != 0 {
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
        let caps = self.hca_caps.as_ref();
        let sw_vhca_id = caps
            .filter(|caps| caps.sw_vhca_id_valid_cap && self.sw_vhca_id != 0)
            .map(|_| self.sw_vhca_id);
        let sw_owner_id = caps
            .filter(|caps| caps.sw_owner_id_cap)
            .map(|_| self.sw_owner_id);
        let in_len = 0x20;

        match sw_vhca_id {
            Some(sw_vhca_id) => log::info!(
                target: "mlx5",
                "Executing INIT_HCA (sw_vhca_id={:#x}, sw_owner_id={})...",
                sw_vhca_id,
                if sw_owner_id.is_some() { "enabled" } else { "disabled" }
            ),
            None => log::info!(
                target: "mlx5",
                "Executing INIT_HCA (sw_vhca_id=disabled, sw_owner_id={})...",
                if sw_owner_id.is_some() { "enabled" } else { "disabled" }
            ),
        }
        build_init_hca_input(in_mbox, sw_vhca_id, sw_owner_id);

        self.execute_cmd_with_uid_candidates(
            CmdOpcode::InitHca,
            self.cmd_in_mbox_device,
            in_len,
            self.cmd_out_mbox_device,
            16,
        )?;

        log::info!(target: "mlx5", "HCA initialized successfully");
        Ok(())
    }

    unsafe fn provide_bootstrap_pages_if_requested(
        &mut self,
        phase: &str,
        func_id: u16,
        requested_pages: i32,
        fw_page_addrs: &[u64],
    ) -> Mlx5Result<()> {
        if requested_pages <= 0 {
            return Ok(());
        }

        if fw_page_addrs.is_empty() {
            log::warn!(
                target: "mlx5",
                "FW requested {} {} pages for function {:#x}, but no bootstrap pages are available",
                requested_pages,
                phase,
                func_id
            );
            return Ok(());
        }

        let requested_pages = requested_pages as usize;
        let provided_pages = requested_pages.min(fw_page_addrs.len());
        if provided_pages < requested_pages {
            log::warn!(
                target: "mlx5",
                "FW requested {} {} pages for function {:#x}, only {} bootstrap pages available",
                requested_pages,
                phase,
                func_id,
                provided_pages
            );
        } else {
            log::info!(
                target: "mlx5",
                "Providing {} {} pages for function {:#x}",
                provided_pages,
                phase,
                func_id
            );
        }

        self.provide_pages(func_id, &fw_page_addrs[..provided_pages])
    }

    pub unsafe fn bootstrap(
        &mut self,
        config: &Mlx5BootstrapConfig,
        resources: &Mlx5AllocatedResources,
    ) -> Mlx5Result<()> {
        self.is_vf = config.is_vf;
        self.pci_bus = config.pci_identity.bus;
        self.pci_device = config.pci_identity.device;
        self.pci_function = config.pci_identity.function;

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
        
        // ECPU (Embedded CPU / ECPF) 判定
        let initializing = crate::mmio_read_be32(self.bar0_base as usize + crate::regs::init_seg::INITIALIZING);
        if (initializing & crate::regs::fw_state::EMBEDDED_CPU_BIT) != 0 {
            self.is_ecpf = true;
            log::info!(target: "mlx5", "Device recognized as ECPF (Embedded CPU / SmartNIC mode)");
        }

        let mut boot_success = false;
        // VF では PF による PCI 有効化待ちが発生するため、多めにリトライする（合計約3秒）
        let max_boot_retries = if self.is_vf() { 15 } else { 5 };
        for retry in 0..max_boot_retries {
            match self.wait_firmware() {
                Ok(()) => {
                    boot_success = true;
                    break;
                }
                Err(Mlx5Error::DeviceNotReady) if self.is_vf() => {
                    log::warn!(target: "mlx5", "VF BAR0 not ready (floating), retry {}/{}...", retry + 1, max_boot_retries);
                }
                Err(e) => return Err(e),
            }
            // 200ms 待機
            let start_ms = kernel_api::service::kernel::instance().current_tick();
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
        crate::boot_trace("[MLX5_BOOT] cmd interface ready\n");
        crate::boot_trace("[MLX5_BOOT] post-cmdif wait start\n");
        self.wait_post_cmdif_ready(30_000)?;
        crate::boot_trace("[MLX5_BOOT] post-cmdif wait done\n");

        // For VFs the majority of commands will only succeed when a proper UID
        // is present.  Set a sensible default before making any further calls so
        // that "simple" operations like enabling the HCA or querying caps work
        // without having to retry inside each helper.
        if self.is_vf() {
            if let Some(cmd) = self.cmd.as_mut() {
                let default_uid = 0;
                cmd.set_uid(default_uid);
                log::debug!(target: "mlx5", "VF detected, initial UID set to {:#x}", default_uid);
            }

            // Guest-visible VFs often expose a working command interface before the
            // firmware reports a stable software VHCA ID.  At this stage the only
            // UID candidates we have are `0xffff`/`0`, and QUERY_VHCA_STATE can
            // stall for multiple transport timeouts without adding signal.
            //
            // Instead of busy-waiting here, proceed directly to the UID-candidate
            // enable/query flow below.  If the PF truly has not enabled the VF,
            // ENABLE_HCA / QUERY_HCA_CAP will fail with a more actionable error.
            log::info!(
                target: "mlx5",
                "Skipping pre-enable VF VHCA wait (mailbox UID will stay on VF self UID 0x0 until PF exposes a dedicated UID)"
            );
        }

        crate::boot_trace("[MLX5_BOOT] enable/setup phase enter\n");
        self.enable_hca_and_setup()?;
        crate::boot_trace("[MLX5_BOOT] enable/setup phase done\n");

        // Phase 2: Pages & Caps
        // VF devices typically do not request additional firmware pages; the PF
        // is responsible for managing them.  Ignore any page requirements to
        // avoid failing during early boot.
        let (func_id, requested_pages) = self
            .query_required_pages(crate::cmd::hca::QUERY_PAGES_OP_MOD_BOOT_PAGES)
            .unwrap_or((0, 0));
        self.fw_function_id = func_id;
        self.provide_bootstrap_pages_if_requested("boot", func_id, requested_pages, fw_page_addrs)?;
        crate::boot_trace("[MLX5_BOOT] query caps start\n");
        self.query_all_caps()?;
        crate::boot_trace("[MLX5_BOOT] query caps done\n");

        if self.is_vf()
            && self.sw_vhca_id == 0
            && self
                .hca_caps()
                .map(|caps| caps.sw_vhca_id_valid_cap)
                .unwrap_or(false)
        {
            self.sw_vhca_id = self.default_sw_vhca_id();
            log::info!(
                target: "mlx5",
                "Assigned software VHCA ID {:#x} for VF INIT_HCA",
                self.sw_vhca_id
            );
        }

        // Dynamic resource adjustment based on reported capabilities
        if let Some(caps) = self.hca_caps() {
            log::info!(target: "mlx5", "HCA Caps limits: max_mkey={}, max_cq={}, max_sq={}, max_rq={}", 
                caps.max_mkey, caps.max_cq, caps.max_sq, caps.max_rq);
            
            // VF では PF からのリソース割り当てが少ない場合があるため、警告を出力
            if caps.max_mkey < 16 {
                log::warn!(target: "mlx5", "Device reports very few mkeys ({}); MKEY operations might fail", caps.max_mkey);
            }
        }

        // Keep using the broadcast mailbox UID for VF command transport until a
        // mailbox-specific UID can be queried independently from INIT_HCA's
        // software VHCA ID. If firmware does not expose a VHCA ID at all, try a
        // stable guest-visible RID-derived hint before falling back to 0xffff/0.
        if self.is_vf() {
            let hw_vhca_id = self.hca_caps().map(|caps| caps.vhca_id).unwrap_or(0);
            let active_uid = if self.sw_vhca_id != 0 {
                self.sw_vhca_id
            } else if hw_vhca_id != 0 {
                hw_vhca_id
            } else {
                self.default_sw_vhca_id()
            };
            if let Some(cmd) = self.cmd.as_mut() {
                cmd.set_uid(active_uid);
                log::info!(
                    target: "mlx5",
                    "Updated VF command UID to {:#x} (sw_vhca_id={:#x}, hw_vhca_id={:#x})",
                    active_uid,
                    self.sw_vhca_id,
                    hw_vhca_id
                );
            }
        }

        // SET_HCA_CAP を呼び出して、ドライバ固有の要件に合わせてデバイスを最適化
        // INIT_HCA の前に実行する必要がある (Linux に倣う)
        log::info!(target: "mlx5", "Configuring HCA capabilities...");
        self.set_hca_cap_general()?;
        self.set_hca_cap_general_2()?;

        // Linux issues QUERY_PAGES for init pages between SET_HCA_CAP and
        // INIT_HCA, even when the result is zero. Some VF firmware paths appear
        // to use this handshake as part of the startup state transition.
        match self.query_required_pages(crate::cmd::hca::QUERY_PAGES_OP_MOD_INIT_PAGES) {
            Ok((func_id, requested_pages)) => {
                if func_id != 0 {
                    self.fw_function_id = func_id;
                }
                self.provide_bootstrap_pages_if_requested(
                    "init",
                    func_id,
                    requested_pages,
                    fw_page_addrs,
                )?;
            }
            Err(err) => {
                log::warn!(
                    target: "mlx5",
                    "QUERY_PAGES(init) failed before INIT_HCA: {:?}",
                    err
                );
            }
        }

        crate::boot_trace("[MLX5_BOOT] init_hca start\n");
        self.init_hca()?;
        crate::boot_trace("[MLX5_BOOT] init_hca done\n");
        let _ = self.set_driver_version();

        log::info!(target: "mlx5", "Refreshing HCA capabilities after INIT_HCA...");
        if let Err(err) = self.query_all_caps() {
            log::warn!(
                target: "mlx5",
                "Post-INIT_HCA capability refresh failed: {:?}",
                err
            );
        }

        // Query adapter info (VSD)
        log::info!(target: "mlx5", "Querying Adapter info...");
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::hca::build_query_adapter_input(in_mbox);
        if let Ok(()) = self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryAdapter,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        ) {
            let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
            let vsd = crate::cmd::hca::parse_query_adapter_vsd(out_mbox);
            if let Ok(vsd_str) = core::str::from_utf8(&vsd) {
                log::info!(target: "mlx5", "Adapter VSD: {}", vsd_str.trim_matches('\0'));
            }
        }

        if self.is_vf() && self.sw_vhca_id == 0 {
            let vhca_state_capable = self
                .hca_caps()
                .map(|caps| caps.vhca_state_cap)
                .unwrap_or(false);
            if vhca_state_capable {
                match self.query_vhca_state(0) {
                    Ok(vhca_ctx) => {
                        log::info!(
                            target: "mlx5",
                            "Local VF VHCA state: {:?}, sw_function_id={:#x}",
                            vhca_ctx.state,
                            vhca_ctx.sw_function_id
                        );
                        if vhca_ctx.sw_function_id != 0
                            && vhca_ctx.sw_function_id <= u16::MAX as u32
                        {
                            self.sw_vhca_id = vhca_ctx.sw_function_id as u16;
                        }
                        if !vhca_ctx.state.is_activation_ready() {
                            log::warn!(
                                target: "mlx5",
                                "VF VHCA state {:?} is not activation-ready; later resource commands may still fail",
                                vhca_ctx.state
                            );
                        }
                    }
                    Err(err) => {
                        log::warn!(
                            target: "mlx5",
                            "Failed to query local VF VHCA state after INIT_HCA: {:?}",
                            err
                        );
                    }
                }
            } else {
                log::info!(
                    target: "mlx5",
                    "Skipping QUERY_VHCA_STATE on VF: capability bit is not set"
                );
            }
        }

        if self.is_vf() {
            log::info!(target: "mlx5", "Querying VF port properties and ensuring vport is active...");
            let _ = self.set_port_admin_up(0);
            if let Err(e) = self.query_port_mac(0) {
                log::warn!(target: "mlx5", "Failed to query VF port MAC address: {:?}", e);
            }
            if let Err(e) = self.query_port_mtu(0) {
                log::warn!(target: "mlx5", "Failed to query VF port MTU: {:?}", e);
            }
        }

        // Phase 3: Resources
        self.alloc_uar()?;
        self.alloc_pd()?;
        self.alloc_td()?;

        // VF では CREATE_MKEY が拒否される FW があるため、reserved lkey を優先する。
        let mut mkey_ok = false;
        if self.is_vf() {
            log::info!(target: "mlx5", "Attempting to use reserved lkey for VF first...");
            match self.query_reserved_lkey() {
                Ok(lkey) => {
                    self.mkey = lkey;
                    mkey_ok = true;
                    log::warn!(target: "mlx5", "[5/8] Using reserved lkey={:#x}", lkey);
                }
                Err(e) => {
                    log::warn!(
                        target: "mlx5",
                        "[5/8] Reserved lkey query failed, falling back to CREATE_MKEY: {:?}",
                        e
                    );
                }
            }
        }

        if !mkey_ok {
            // PF では通常 CREATE_MKEY、VF でも reserved lkey が得られない場合は試行。
            let mut pd_candidates = vec![0, 1];
            if self.pd != 0 && self.pd != 1 {
                pd_candidates.push(self.pd);
            }

            let mut effective_mkey_params = mkey_params.clone();
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
                        log::warn!(
                            target: "mlx5",
                            "[5/8] MKEY creation failed with PD {}: {:?}",
                            pd_try,
                            e
                        );
                    }
                }
            }
        }

        if !mkey_ok {
            return Err(Mlx5Error::CommandFailed(0xff));
        }

        let _ = self.refresh_port_runtime_state(0);

        // Phase 4: Queues
        let mut eqns = Vec::new();
        for (_i, eq_buf) in eq_bufs.iter().enumerate() {
            // RanyOS DriverContext currently supports a single IRQ, so map all EQs to vector 0
            let eqn = self.create_eq_hw(
                eq_buf.0,
                eq_buf.1,
                log_eq_size,
                0,
                // Linux creates completion EQs with an empty event mask and
                // treats command/async notifications via dedicated EQ types.
                0,
            )?;
            eqns.push(eqn);
        }
        crate::boot_trace("[MLX5_STAGE] eq_done\n");

        let mut tx_cqns = Vec::new();
        for (i, cq_buf) in tx_cq_bufs.iter().enumerate() {
            let eqn = eqns[i % eqns.len()];
            let cqn = self.create_cq_hw(cq_buf.0, cq_buf.1, cq_buf.2, cq_buf.3, log_cq_size, eqn)?;
            tx_cqns.push(cqn);
        }
        crate::boot_trace("[MLX5_STAGE] tx_cq_done\n");

        let mut rx_cqns = Vec::new();
        for (i, cq_buf) in rx_cq_bufs.iter().enumerate() {
            let eqn = eqns[i % eqns.len()];
            let cqn = self.create_cq_hw(cq_buf.0, cq_buf.1, cq_buf.2, cq_buf.3, log_cq_size, eqn)?;
            rx_cqns.push(cqn);
        }
        crate::boot_trace("[MLX5_STAGE] rx_cq_done\n");

        let mut tx_path_enabled = true;
        let mut tx_using_fallback_tis0 = false;
        crate::boot_trace("[MLX5_STAGE] create_tis_enter\n");
        let tisn = if self.is_vf() {
            // On several VF firmware variants (including CX4-Lx SR-IOV),
            // CREATE_TIS is rejected but SQ can still run with implicit TIS=0.
            // Skip noisy retries and activate the proven fallback directly.
            log::warn!(
                target: "mlx5",
                "Skipping CREATE_TIS on VF; using TX fallback with implicit TIS=0"
            );
            tx_using_fallback_tis0 = true;
            0
        } else {
            self.create_tis(&crate::resources::TisParams {
                pd: self.pd,
                td: self.td,
                port: 1,
                prio: 0,
            })?
        };
        crate::boot_trace("[MLX5_STAGE] create_tis_done\n");

        let max_hw_sq = self
            .hca_caps()
            .map(|caps| core::cmp::max(caps.max_sq as usize, 1))
            .unwrap_or(sq_bufs.len());
        let sq_queue_count = core::cmp::min(sq_bufs.len(), max_hw_sq);
        if sq_queue_count < sq_bufs.len() {
            log::warn!(
                target: "mlx5",
                "Clamping SQ queue count from {} to {} based on HW capability",
                sq_bufs.len(),
                sq_queue_count
            );
        }

        if tx_path_enabled {
            for (i, sq_buf) in sq_bufs.iter().take(sq_queue_count).enumerate() {
                let cqn = tx_cqns[i % tx_cqns.len()];
                if let Err(err) = self.create_sq_hw(
                    sq_buf.0,
                    sq_buf.1,
                    sq_buf.2,
                    sq_buf.3,
                    log_sq_size,
                    cqn,
                    tisn,
                ) {
                    if self.is_vf() {
                        log::warn!(
                            target: "mlx5",
                            "CREATE_SQ failed on VF ({:?}); disabling TX path and continuing RX-only",
                            err
                        );
                        tx_path_enabled = false;
                        break;
                    }
                    return Err(err);
                }
            }
        }

        if !tx_path_enabled {
            log::warn!(
                target: "mlx5",
                "mlx5 VF fallback active: TX path disabled (no usable TIS/SQ), continuing RX setup"
            );
        } else if tx_using_fallback_tis0 {
            log::warn!(
                target: "mlx5",
                "mlx5 VF fallback active: TX path running with implicit TIS=0"
            );
        }

        let scatter_fcs = self.hca_caps().map(|c| c.scatter_fcs).unwrap_or(false);
        let vlan_strip = self.hca_caps().map(|c| c.vlan_strip).unwrap_or(false);
        let max_hw_rq = self
            .hca_caps()
            .map(|caps| core::cmp::max(caps.max_rq as usize, 1))
            .unwrap_or(rq_bufs.len());
        let rq_queue_count = core::cmp::min(rq_bufs.len(), max_hw_rq);
        if rq_queue_count < rq_bufs.len() {
            log::warn!(
                target: "mlx5",
                "Clamping RQ queue count from {} to {} based on HW capability",
                rq_bufs.len(),
                rq_queue_count
            );
        }

        let mut rqns = Vec::new();
        for (i, rq_buf) in rq_bufs.iter().take(rq_queue_count).enumerate() {
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
        crate::boot_trace("[MLX5_STAGE] rq_done\n");

        let tirn = if rqns.len() > 1 {
            crate::boot_trace("[MLX5_STAGE] create_rqt_enter\n");
            let log_rqt_size = (32 - (rqns.len() as u32 - 1).leading_zeros()) as u8;
            let rqtn = self.create_rqt(&rqns, log_rqt_size)?;
            crate::boot_trace("[MLX5_STAGE] create_rqt_done\n");
            crate::boot_trace("[MLX5_STAGE] create_tir_rqt_enter\n");
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
            crate::boot_trace("[MLX5_STAGE] create_tir_direct_enter\n");
            let inline_rqn = rqns.first().copied().ok_or(Mlx5Error::InvalidResponse)?;
            self.create_tir(&crate::resources::TirParams {
                receive_type: crate::resources::TirReceiveType::DirectRq,
                td: self.td,
                inline_rqn,
                rqtn: 0,
                rss: None,
                scatter_fcs,
                vlan_strip,
            })?
        };
        crate::boot_trace("[MLX5_STAGE] create_tir_done\n");

        // Finalize
        if let Err(err) = self.setup_rx_flow_table_advanced(tirn) {
            if self.is_vf() {
                let _ = err;
                crate::boot_trace("[MLX5_STAGE] rx_flow_table_vf_failed\n");
            }
        }
        if self.is_vf() {
            crate::boot_trace("[MLX5_STAGE] try_port_admin_up_vf\n");
            if let Err(err) = self.set_port_admin_up(0) {
                log::warn!(
                    target: "mlx5",
                    "VF MODIFY_VPORT_STATE(admin up) failed; continuing: {:?}",
                    err
                );
            }
        } else {
            let _ = self.set_port_admin_up(0);
        }
        if let Some(port) = self.ports.get_mut(0) {
            port.admin_up();
        }

        // Give PF firmware a moment to reflect the port state change before
        // reporting active. On VF bring-up in some environments the timer tick
        // may not advance yet here, so skip this delay path.
        if !self.is_vf() {
            let start_ms = kernel_api::service::kernel::instance().current_tick();
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while kernel_api::service::kernel::instance().current_tick() - start_ms < 50 {
                core::hint::spin_loop();
            }
        }

        self.resources_allocated = true;
        self.state = DeviceState::Active;
        crate::boot_trace("[MLX5_STAGE] bootstrap_done\n");
        Ok(())
    }

    /// ソフトウェアリセットのトリガー
    pub unsafe fn trigger_sw_reset(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Triggering software reset via SW_RESET register...");
        crate::mmio_write_be32(self.bar0_base as usize + crate::regs::init_seg::SW_RESET, 1);

        // initializing bit がセットされるまで待機
        let start_ms = kernel_api::service::kernel::instance().current_tick();
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
