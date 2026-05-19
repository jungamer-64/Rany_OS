// ============================================================================
// drivers/mlx5/src/device/init.rs - MLX5 Device Initialization
// ============================================================================

use crate::bootstrap::{Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan};
use crate::cmd::CmdQueueTransport; // needed for layout parsing
use crate::cmd::hca::{
    MLX5_ACCESS_REGISTER_OP_MOD_WRITE, MLX5_REG_HOST_ENDIANNESS, build_access_register_input,
    build_enable_hca_input, build_init_hca_input, build_set_issi_input,
};
use crate::cmd::{CmdMailbox, CmdQueue};
use crate::defs::CmdOpcode;
use crate::defs::MLX5_CMD_MBOX_SIZE;
use crate::device::{DeviceState, Mlx5Device};
use crate::error::{Mlx5Error, Mlx5Result};
use alloc::vec; // bring `vec!` macro into scope for candidate lists
use alloc::vec::Vec;
// unused MkeyParams removed

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxTisAttemptKind {
    ReuseExisting,
    CreateTis,
    ImplicitTis0,
}

#[derive(Debug, Clone, Copy)]
struct TxTisSelection {
    kind: TxTisAttemptKind,
    tisn: u32,
    implicit_tis0_fallback: bool,
}

impl Mlx5Device {
    // QUERY_TIS の走査はコマンド往復が重いため、通常ブートでは探索予算を抑える。
    // PF は互換性確保のため VF より広めに残し、VF は初期化遅延を優先して小さくする。
    const PF_TIS_REUSE_SCAN_LIMIT: u32 = 2048;
    const VF_TIS_REUSE_SCAN_LIMIT: u32 = 512;
    const PF_SQ_TIS_SCAN_LIMIT: u32 = 64;
    const PF_TIS_SQ_ORACLE_CANDIDATES: [u32; 13] = [
        0x0000_0001,
        0x0000_0002,
        0x0000_0008,
        0x0000_0010,
        0x0040_0000,
        0x0040_0001,
        0x0040_0008,
        0x0080_0000,
        0x0080_0001,
        0x0080_0008,
        0x00c0_0000,
        0x00c0_0001,
        0x00c0_0008,
    ];

    fn remember_external_tis(&mut self, tisn: u32, label: &str) {
        self.record_tis_info(tisn, 1, crate::resources::TisOwnership::External);
        crate::boot_trace_tis_choice(label, tisn);
    }

    fn pf_prefers_existing_tis_profile(&self) -> bool {
        if self.is_vf() {
            return false;
        }

        self.hca_caps()
            .map(|caps| {
                caps.log_max_tis == 0
                    && caps.log_max_tis_per_sq == 0
                    && caps.log_max_transport_domain == 0
                    && caps.max_sq <= 1
            })
            .unwrap_or(false)
    }

    const fn vf_tx_tis_attempt_order() -> [TxTisAttemptKind; 3] {
        [
            TxTisAttemptKind::ReuseExisting,
            TxTisAttemptKind::CreateTis,
            TxTisAttemptKind::ImplicitTis0,
        ]
    }

    unsafe fn log_port_state_before_tis_selection(&mut self, label: &str) {
        if self.is_vf() {
            crate::boot_trace("[MLX5_STAGE] pre_tis_port_admin_up_vf\n");
        } else {
            crate::boot_trace("[MLX5_STAGE] pre_tis_port_admin_up_pf\n");
        }

        match self.set_port_admin_up(0) {
            Ok(()) => match self.query_port_state(0) {
                Ok(state) => {
                    log::info!(
                        target: "mlx5",
                        "{} port link state before TX object selection: {:?}",
                        label,
                        state
                    );
                }
                Err(err) => {
                    log::warn!(
                        target: "mlx5",
                        "Failed to query {} port state before TX object selection: {:?}",
                        label,
                        err
                    );
                }
            },
            Err(err) => {
                log::warn!(
                    target: "mlx5",
                    "{} pre-TIS admin-up failed; continuing TX object selection: {:?}",
                    label,
                    err
                );
            }
        }
    }

    unsafe fn select_vf_tis_for_tx(&mut self) -> TxTisSelection {
        let tis_params = crate::resources::TisParams {
            pd: self.pd,
            td: self.td,
            port: 1,
            prio: 0,
        };

        self.log_port_state_before_tis_selection("VF");

        for attempt in Self::vf_tx_tis_attempt_order() {
            match attempt {
                TxTisAttemptKind::ReuseExisting => {
                    match self.find_existing_tis_strict_match(
                        Self::VF_TIS_REUSE_SCAN_LIMIT,
                        self.td,
                        0,
                    ) {
                        Ok(tisn) => {
                            log::warn!(
                                target: "mlx5",
                                "Reusing strict-match existing VF TIS {:#x} before CREATE_TIS",
                                tisn
                            );
                            return TxTisSelection {
                                kind: TxTisAttemptKind::ReuseExisting,
                                tisn: self.adopt_external_tis(tisn, &tis_params),
                                implicit_tis0_fallback: false,
                            };
                        }
                        Err(err) => {
                            log::warn!(
                                target: "mlx5",
                                "No strict-match VF TIS found via QUERY_TIS before CREATE_TIS: {:?}",
                                err
                            );
                        }
                    }

                    match self.find_existing_tis_matching(Self::VF_TIS_REUSE_SCAN_LIMIT, self.td, 0)
                    {
                        Ok(tisn) => {
                            log::warn!(
                                target: "mlx5",
                                "Reusing relaxed-match existing VF TIS {:#x} after strict QUERY_TIS miss",
                                tisn
                            );
                            return TxTisSelection {
                                kind: TxTisAttemptKind::ReuseExisting,
                                tisn: self.adopt_external_tis(tisn, &tis_params),
                                implicit_tis0_fallback: false,
                            };
                        }
                        Err(err) => {
                            log::warn!(
                                target: "mlx5",
                                "No relaxed-match VF TIS candidate found via QUERY_TIS before CREATE_TIS: {:?}",
                                err
                            );
                        }
                    }
                }
                TxTisAttemptKind::CreateTis => match self.create_tis(&tis_params) {
                    Ok(tisn) => {
                        return TxTisSelection {
                            kind: TxTisAttemptKind::CreateTis,
                            tisn,
                            implicit_tis0_fallback: false,
                        };
                    }
                    Err(err) => {
                        log::warn!(
                            target: "mlx5",
                            "CREATE_TIS failed on VF; keeping implicit TIS=0 as last-resort fallback: {:?}",
                            err
                        );
                    }
                },
                TxTisAttemptKind::ImplicitTis0 => {
                    crate::boot_trace("[MLX5_STAGE] create_tis_use_implicit_tis0_vf\n");
                    log::warn!(
                        target: "mlx5",
                        "VF TX bring-up falling back to implicit TIS=0 after reusable/create TIS attempts"
                    );
                    return TxTisSelection {
                        kind: TxTisAttemptKind::ImplicitTis0,
                        tisn: 0,
                        implicit_tis0_fallback: true,
                    };
                }
            }
        }

        unreachable!("VF TX TIS attempt order always terminates with implicit TIS=0 fallback");
    }

    unsafe fn adopt_external_tis(
        &mut self,
        tisn: u32,
        requested: &crate::resources::TisParams,
    ) -> u32 {
        self.remember_external_tis(tisn, "reuse_active");
        self.trace_adopted_external_tis("reuse_active_ctx", tisn, requested, false);
        self.trace_tis_prefix_namespace(tisn, 8);
        tisn
    }

    unsafe fn trace_adopted_external_tis(
        &mut self,
        label: &str,
        tisn: u32,
        requested: &crate::resources::TisParams,
        include_pd: bool,
    ) {
        match self.query_tis_with_snapshot(tisn) {
            Ok((info, snapshot)) => {
                crate::boot_trace_tis_query(label, tisn, &info);
                crate::boot_trace_mailbox_range("query_tis_out_hdr", &snapshot, 0x00, 4);
                crate::boot_trace_mailbox_range("query_tis_out_ctx", &snapshot, 0x10, 16);
                crate::boot_trace_tis_compare(
                    "reuse_vs_create",
                    requested,
                    include_pd,
                    tisn,
                    &info,
                );
                log::info!(
                    target: "mlx5",
                    "Adopted external TIS: tisn={:#x} requested(td={} pd={} prio={} port={} include_pd={}) adopted(td={} pd={} prio={} underlay_qpn={:#x} lag_port={} strict_lag={} tls={})",
                    tisn,
                    requested.td,
                    requested.pd,
                    requested.prio,
                    requested.port,
                    include_pd,
                    info.transport_domain,
                    info.pd,
                    info.prio,
                    info.underlay_qpn,
                    info.lag_tx_port_affinity,
                    info.strict_lag_tx_port_affinity,
                    info.tls_en
                );
            }
            Err(query_err) => {
                log::warn!(
                    target: "mlx5",
                    "Failed to query adopted external TIS {:#x} for {} diagnostics: {:?}",
                    tisn,
                    label,
                    query_err
                );
            }
        }
    }

    unsafe fn create_sq_with_pf_tis_oracle(
        &mut self,
        sq_buf_virt: u64,
        sq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_sq_size: u8,
        cqn: u32,
    ) -> Mlx5Result<(u32, u32)> {
        let mut last_probe_err = Err(Mlx5Error::NotSupported);

        for &candidate_tisn in &Self::PF_TIS_SQ_ORACLE_CANDIDATES {
            log::info!(
                target: "mlx5",
                "Probing PF TX TIS candidate via CREATE_SQ: tisn={:#x}",
                candidate_tisn
            );
            match self.create_sq_hw(
                sq_buf_virt,
                sq_buf_pa,
                db_virt,
                db_pa,
                log_sq_size,
                cqn,
                candidate_tisn,
            ) {
                Ok(sqn) => {
                    self.remember_external_tis(candidate_tisn, "sq_oracle_active");
                    return Ok((sqn, candidate_tisn));
                }
                Err(err) => {
                    log::warn!(
                        target: "mlx5",
                        "PF TX TIS candidate rejected via CREATE_SQ: tisn={:#x} err={:?}",
                        candidate_tisn,
                        err
                    );
                    last_probe_err = Err(err);
                }
            }
        }

        last_probe_err
    }

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
        while kernel_api::service::kernel::instance()
            .current_tick()
            .saturating_sub(start_ms)
            < timeout_ms
        {
            let initializing = crate::mmio_read_be32(
                self.bar0_base as usize + crate::regs::init_seg::INITIALIZING,
            );

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

    unsafe fn set_hca_ctrl_pf(&mut self) -> Mlx5Result<()> {
        if self.is_vf() {
            return Ok(());
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let mut reg = [0u8; 16];
        reg[0] = if cfg!(target_endian = "big") {
            0x80
        } else {
            0x00
        };
        build_access_register_input(
            in_mbox,
            MLX5_REG_HOST_ENDIANNESS,
            0,
            MLX5_ACCESS_REGISTER_OP_MOD_WRITE,
            &reg,
        );
        log::info!(
            target: "mlx5",
            "Programming HOST_ENDIANNESS register for PF (value={:#x})...",
            reg[0]
        );
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::AccessRegister,
            self.cmd_in_mbox_device,
            0x20,
            self.cmd_out_mbox_device,
            0x20,
        )
    }

    unsafe fn provide_bootstrap_pages_if_requested(
        &mut self,
        phase: &str,
        func_id: u16,
        requested_pages: i32,
        fw_page_addrs: &mut Vec<u64>,
    ) -> Mlx5Result<()> {
        if requested_pages <= 0 {
            return Ok(());
        }

        let requested_pages = requested_pages as usize;
        let start = self.bootstrap_fw_page_cursor.min(fw_page_addrs.len());
        let target_total = start.saturating_add(requested_pages);

        if !self.is_vf() && fw_page_addrs.len() < target_total {
            let additional_needed = target_total - fw_page_addrs.len();
            let device_id = self.packed_device_id();
            let mut added_pages = 0usize;
            let allocation_start_tick = kernel_api::service::kernel::instance().current_tick();

            log::info!(
                target: "mlx5",
                "Expanding FW page pool for {} phase: need {} additional pages for function {:#x}",
                phase,
                additional_needed,
                func_id
            );

            for _ in 0..additional_needed {
                match kernel_api::service::kernel::instance()
                    .alloc_dma_for_device(crate::defs::MLX5_PAGE_SIZE, device_id)
                {
                    Ok(buf) => {
                        let dma_addr = self.page_manager.record_owned_dma_page(buf, func_id);
                        fw_page_addrs.push(dma_addr);
                        added_pages += 1;
                        if added_pages == 1 || added_pages % 256 == 0 {
                            let elapsed_ticks = kernel_api::service::kernel::instance()
                                .current_tick()
                                .saturating_sub(allocation_start_tick);
                            log::info!(
                                target: "mlx5",
                                "FW page expansion progress for {} phase: {}/{} pages allocated (elapsed_ticks={})",
                                phase,
                                added_pages,
                                additional_needed,
                                elapsed_ticks
                            );
                        }
                    }
                    Err(err) => {
                        log::warn!(
                            target: "mlx5",
                            "Failed to allocate additional FW page for {} phase after {} pages: {:?}",
                            phase,
                            added_pages,
                            err
                        );
                        break;
                    }
                }
            }

            if added_pages != 0 {
                log::info!(
                    target: "mlx5",
                    "Expanded FW page pool by {} pages for {} phase (total pages={})",
                    added_pages,
                    phase,
                    fw_page_addrs.len()
                );
            }
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

        let available = fw_page_addrs.len().saturating_sub(start);
        if available == 0 {
            log::warn!(
                target: "mlx5",
                "FW requested {} {} pages for function {:#x}, but bootstrap page pool is exhausted (cursor={} total={})",
                requested_pages,
                phase,
                func_id,
                self.bootstrap_fw_page_cursor,
                fw_page_addrs.len()
            );
            return Ok(());
        }

        let provided_pages = requested_pages.min(available);
        if provided_pages < requested_pages {
            log::warn!(
                target: "mlx5",
                "FW requested {} {} pages for function {:#x}, only {} bootstrap pages available (cursor={} total={})",
                requested_pages,
                phase,
                func_id,
                provided_pages,
                self.bootstrap_fw_page_cursor,
                fw_page_addrs.len()
            );
        } else {
            log::info!(
                target: "mlx5",
                "Providing {} {} pages for function {:#x} (page window {}..{})",
                provided_pages,
                phase,
                func_id,
                start,
                start + provided_pages
            );
        }

        let selected = &fw_page_addrs[start..start + provided_pages];
        self.bootstrap_fw_page_cursor = start + provided_pages;
        self.provide_pages(func_id, selected)
    }

    pub unsafe fn bootstrap(
        &mut self,
        config: &Mlx5BootstrapConfig,
        resources: &Mlx5AllocatedResources,
    ) -> Mlx5Result<()> {
        self.is_vf = config.is_vf;
        self.bootstrap_fw_page_cursor = 0;
        self.pci_segment = config.pci_identity.segment;
        self.pci_bus = config.pci_identity.bus;
        self.pci_device = config.pci_identity.device;
        self.pci_function = config.pci_identity.function;

        let plan = Mlx5BootstrapPlan::new(config);
        plan.validate_resources(resources)?;
        self.set_pci_location(
            config.pci_identity.segment,
            config.pci_identity.bus,
            config.pci_identity.device,
            config.pci_identity.function,
        );

        let mut fw_page_addrs = resources.fw_page_device_addrs();
        let eq_bufs = resources.eq_bufs();
        let tx_cq_bufs = resources.tx_cq_bufs();
        let rx_cq_bufs = resources.rx_cq_bufs();
        let sq_bufs = resources.sq_bufs();
        let rq_bufs = resources.rq_bufs();
        let rmp_bufs = resources.rmp_bufs();
        let profile = plan.queue_profile();

        self.init_multi_queue(
            resources.cmdq.virt_addr,
            resources.cmdq.device_addr,
            resources.cmd_in_mbox.virt_addr,
            resources.cmd_in_mbox.device_addr,
            resources.cmd_out_mbox.virt_addr,
            resources.cmd_out_mbox.device_addr,
            &mut fw_page_addrs,
            &config.mkey_params,
            &eq_bufs,
            &tx_cq_bufs,
            &rx_cq_bufs,
            &sq_bufs,
            &rq_bufs,
            &rmp_bufs,
            profile.log_eq_size,
            profile.log_cq_size,
            profile.log_sq_size,
            profile.log_rq_size,
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
        fw_page_addrs: &mut Vec<u64>,
        mkey_params: &crate::resources::MkeyParams,
        eq_bufs: &[(u64, u64)],
        tx_cq_bufs: &[(u64, u64, u64, u64)],
        rx_cq_bufs: &[(u64, u64, u64, u64)],
        sq_bufs: &[(u64, u64, u64, u64)],
        rq_bufs: &[(u64, u64, u64, u64)],
        rmp_bufs: &[(u64, u64, u64, u64)],
        log_eq_size: u8,
        log_cq_size: u8,
        log_sq_size: u8,
        log_rq_size: u8,
    ) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "=== Starting multi-queue pipeline initialization ===");

        // Phase 1: Boot
        log::info!(target: "mlx5", "Phase 1: Waiting for firmware/BAR0 to become accessible...");

        // ECPU (Embedded CPU / ECPF) 判定
        let initializing =
            crate::mmio_read_be32(self.bar0_base as usize + crate::regs::init_seg::INITIALIZING);
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
        // INIT_HCA の前に実行する必要がある
        log::info!(target: "mlx5", "Configuring HCA capabilities...");
        if let Err(err) = self.set_hca_ctrl_pf() {
            log::warn!(
                target: "mlx5",
                "HOST_ENDIANNESS register setup failed on PF; continuing anyway: {:?}",
                err
            );
        }
        self.set_hca_cap_general()?;
        if let Err(err) = self.set_hca_cap_atomic() {
            log::warn!(
                target: "mlx5",
                "SET_HCA_CAP(ATOMIC) failed; continuing without atomic tuning: {:?}",
                err
            );
        }
        if let Err(err) = self.set_hca_cap_odp() {
            log::warn!(
                target: "mlx5",
                "SET_HCA_CAP(ODP) failed; continuing without ODP tuning: {:?}",
                err
            );
        }
        if let Err(err) = self.set_hca_cap_roce() {
            log::warn!(
                target: "mlx5",
                "SET_HCA_CAP(ROCE) failed; continuing without RoCE tuning: {:?}",
                err
            );
        }
        self.set_hca_cap_general_2()?;
        if let Err(err) = self.set_hca_cap_port_selection() {
            log::warn!(
                target: "mlx5",
                "SET_HCA_CAP(PORT_SELECTION) failed; continuing without port-selection tuning: {:?}",
                err
            );
        }

        // Issue QUERY_PAGES for init pages between SET_HCA_CAP and INIT_HCA,
        // even when the result is zero. Some VF firmware paths appear to use
        // this handshake as part of the startup state transition.
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

        // VF では FW 世代によって reserved lkey / CREATE_MKEY の通り方が揺れるため、
        // まずは明示的な MKEY 作成を self.pd 優先で試し、失敗時のみ reserved lkey に戻す。
        let mut mkey_ok = false;
        if !mkey_ok {
            let mut pd_candidates = vec![self.pd, 0, 1];
            if !pd_candidates.contains(&self.pd) {
                pd_candidates.push(self.pd);
            }

            let mut effective_mkey_params = mkey_params.clone();
            if self.is_vf() {
                log::info!(
                    target: "mlx5",
                    "Attempting CREATE_MKEY for VF before reserved lkey fallback..."
                );
            }
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

        if self.is_vf() && !mkey_ok {
            log::warn!(
                target: "mlx5",
                "[5/8] CREATE_MKEY attempts failed on VF; falling back to reserved lkey"
            );
            match self.query_reserved_lkey() {
                Ok(lkey) => {
                    self.mkey = lkey;
                    mkey_ok = true;
                    log::warn!(target: "mlx5", "[5/8] Using reserved lkey={:#x}", lkey);
                }
                Err(e) => {
                    log::warn!(
                        target: "mlx5",
                        "[5/8] Reserved lkey query failed after CREATE_MKEY attempts: {:?}",
                        e
                    );
                }
            }
        }

        if !mkey_ok {
            return Err(Mlx5Error::CommandFailed(0xff));
        }

        self.tx_mkey = self.mkey;
        log::info!(
            target: "mlx5",
            "[5/8] Using TX/RX data path key {:#x}",
            self.tx_mkey
        );

        let _ = self.refresh_port_runtime_state(0);

        let mut tx_path_enabled = true;
        let mut tx_using_fallback_tis0 = false;
        let mut tx_oracle_tisn = None;
        crate::boot_trace("[MLX5_STAGE] create_tis_enter\n");
        let mut vf_tis_selection_kind = TxTisAttemptKind::CreateTis;
        let tisn = if self.is_vf() {
            let selection = self.select_vf_tis_for_tx();
            vf_tis_selection_kind = selection.kind;
            tx_using_fallback_tis0 = selection.implicit_tis0_fallback;
            selection.tisn
        } else {
            self.log_port_state_before_tis_selection("PF");
            let tis_params = crate::resources::TisParams {
                pd: self.pd,
                td: self.td,
                port: 1,
                prio: 0,
            };
            let handle_create_tis_failure =
                |this: &mut Self,
                 err: crate::error::Mlx5Error,
                 tx_oracle_tisn: &mut Option<u32>,
                 tx_using_fallback_tis0: &mut bool| {
                    crate::boot_trace("[MLX5_STAGE] create_tis_scan_existing\n");
                    log::warn!(
                        target: "mlx5",
                        "CREATE_TIS failed on PF ({:?}); scanning up to {} existing TIS objects before implicit TIS=0 fallback",
                        err,
                        Self::PF_TIS_REUSE_SCAN_LIMIT
                    );
                    match unsafe {
                        this.find_existing_tis_matching(Self::PF_TIS_REUSE_SCAN_LIMIT, this.td, 0)
                    } {
                        Ok(tisn) => {
                            log::warn!(
                                target: "mlx5",
                                "Reusing existing PF TIS {:#x} after CREATE_TIS failure",
                                tisn
                            );
                            unsafe { this.adopt_external_tis(tisn, &tis_params) }
                        }
                        Err(scan_err) => {
                            match unsafe {
                                this.find_existing_sq_tis_candidate(Self::PF_SQ_TIS_SCAN_LIMIT)
                            } {
                                Ok(discovered_tisn) => {
                                    *tx_oracle_tisn = Some(discovered_tisn);
                                    log::warn!(
                                        target: "mlx5",
                                        "No reusable TIS via QUERY_TIS, but found PF SQ-derived TIS candidate {:#x}",
                                        discovered_tisn
                                    );
                                }
                                Err(sq_scan_err) => {
                                    log::warn!(
                                        target: "mlx5",
                                        "No PF SQ-derived TIS candidate found after CREATE_TIS failure: {:?}",
                                        sq_scan_err
                                    );
                                }
                            }
                            crate::boot_trace("[MLX5_STAGE] create_tis_use_implicit_tis0\n");
                            log::warn!(
                                target: "mlx5",
                                "CREATE_TIS failed on PF ({:?}) and no reusable TIS found ({:?}); trying TX fallback with implicit TIS=0",
                                err,
                                scan_err
                            );
                            *tx_using_fallback_tis0 = true;
                            0
                        }
                    }
                };

            if self.pf_prefers_existing_tis_profile() {
                crate::boot_trace("[MLX5_STAGE] create_tis_prefers_reuse_profile\n");
                if let Some(caps) = self.hca_caps() {
                    log::info!(
                        target: "mlx5",
                        "PF caps indicate a default-only TIS profile; preferring external TIS reuse before CREATE_TIS (log_max_tis={} log_max_tis_per_sq={} log_max_td={} max_sq={})",
                        caps.log_max_tis,
                        caps.log_max_tis_per_sq,
                        caps.log_max_transport_domain,
                        caps.max_sq
                    );
                }
                match self.find_existing_tis_default_profile(Self::PF_TIS_REUSE_SCAN_LIMIT) {
                    Ok(tisn) => self.adopt_external_tis(tisn, &tis_params),
                    Err(scan_err) => {
                        log::warn!(
                            target: "mlx5",
                            "No reusable PF TIS found in default-only profile pre-scan ({:?}); falling back to CREATE_TIS probes",
                            scan_err
                        );
                        match self.create_tis(&tis_params) {
                            Ok(tisn) => tisn,
                            Err(err) => handle_create_tis_failure(
                                self,
                                err,
                                &mut tx_oracle_tisn,
                                &mut tx_using_fallback_tis0,
                            ),
                        }
                    }
                }
            } else {
                match self.create_tis(&tis_params) {
                    Ok(tisn) => tisn,
                    Err(err) => handle_create_tis_failure(
                        self,
                        err,
                        &mut tx_oracle_tisn,
                        &mut tx_using_fallback_tis0,
                    ),
                }
            }
        };
        crate::boot_trace("[MLX5_STAGE] create_tis_done\n");
        let mut active_vf_tisn = tisn;

        // Phase 4: Queues
        let mut eqns = Vec::new();
        for (_i, eq_buf) in eq_bufs.iter().enumerate() {
            // RanyOS DriverContext currently supports a single IRQ, so map all EQs to vector 0
            let eqn = self.create_eq_hw(
                eq_buf.0,
                eq_buf.1,
                log_eq_size,
                0,
                // Completion EQs use an empty event mask; command and async
                // notifications are handled by dedicated EQ types.
                0,
            )?;
            eqns.push(eqn);
        }
        crate::boot_trace("[MLX5_STAGE] eq_done\n");

        let mut tx_cqns = Vec::new();
        for (i, cq_buf) in tx_cq_bufs.iter().enumerate() {
            let eqn = eqns[i % eqns.len()];
            let cqn =
                self.create_cq_hw(cq_buf.0, cq_buf.1, cq_buf.2, cq_buf.3, log_cq_size, eqn)?;
            tx_cqns.push(cqn);
        }
        crate::boot_trace("[MLX5_STAGE] tx_cq_done\n");

        let mut rx_cqns = Vec::new();
        for (i, cq_buf) in rx_cq_bufs.iter().enumerate() {
            let eqn = eqns[i % eqns.len()];
            let cqn =
                self.create_cq_hw(cq_buf.0, cq_buf.1, cq_buf.2, cq_buf.3, log_cq_size, eqn)?;
            rx_cqns.push(cqn);
        }
        crate::boot_trace("[MLX5_STAGE] rx_cq_done\n");

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
                let sq_result = if self.is_vf() {
                    let tis_params = crate::resources::TisParams {
                        pd: self.pd,
                        td: self.td,
                        port: 1,
                        prio: 0,
                    };
                    match self.create_sq_hw(
                        sq_buf.0,
                        sq_buf.1,
                        sq_buf.2,
                        sq_buf.3,
                        log_sq_size,
                        cqn,
                        active_vf_tisn,
                    ) {
                        Ok(sqn) => Ok(sqn),
                        Err(err)
                            if active_vf_tisn != 0
                                && !tx_using_fallback_tis0
                                && matches!(
                                    vf_tis_selection_kind,
                                    TxTisAttemptKind::ReuseExisting
                                ) =>
                        {
                            log::warn!(
                                target: "mlx5",
                                "CREATE_SQ rejected reused VF TIS {:#x}; trying CREATE_TIS before implicit TIS=0 fallback: {:?}",
                                active_vf_tisn,
                                err
                            );
                            match self.create_tis(&tis_params) {
                                Ok(created_tisn) => {
                                    active_vf_tisn = created_tisn;
                                    vf_tis_selection_kind = TxTisAttemptKind::CreateTis;
                                    self.create_sq_hw(
                                        sq_buf.0,
                                        sq_buf.1,
                                        sq_buf.2,
                                        sq_buf.3,
                                        log_sq_size,
                                        cqn,
                                        active_vf_tisn,
                                    )
                                }
                                Err(create_tis_err) => {
                                    crate::boot_trace("[MLX5_STAGE] vf_sq_use_implicit_tis0\n");
                                    log::warn!(
                                        target: "mlx5",
                                        "CREATE_TIS also failed after reused VF TIS rejection; retrying with implicit TIS=0 fallback: {:?}",
                                        create_tis_err
                                    );
                                    active_vf_tisn = 0;
                                    vf_tis_selection_kind = TxTisAttemptKind::ImplicitTis0;
                                    tx_using_fallback_tis0 = true;
                                    self.create_sq_hw(
                                        sq_buf.0,
                                        sq_buf.1,
                                        sq_buf.2,
                                        sq_buf.3,
                                        log_sq_size,
                                        cqn,
                                        active_vf_tisn,
                                    )
                                }
                            }
                        }
                        Err(err) if active_vf_tisn != 0 && !tx_using_fallback_tis0 => {
                            crate::boot_trace("[MLX5_STAGE] vf_sq_use_implicit_tis0\n");
                            log::warn!(
                                target: "mlx5",
                                "CREATE_SQ rejected VF TIS {:#x}; retrying with implicit TIS=0 fallback: {:?}",
                                active_vf_tisn,
                                err
                            );
                            active_vf_tisn = 0;
                            vf_tis_selection_kind = TxTisAttemptKind::ImplicitTis0;
                            tx_using_fallback_tis0 = true;
                            self.create_sq_hw(
                                sq_buf.0,
                                sq_buf.1,
                                sq_buf.2,
                                sq_buf.3,
                                log_sq_size,
                                cqn,
                                active_vf_tisn,
                            )
                        }
                        Err(err) => Err(err),
                    }
                } else if let Some(discovered_tisn) = tx_oracle_tisn {
                    match self.create_sq_hw(
                        sq_buf.0,
                        sq_buf.1,
                        sq_buf.2,
                        sq_buf.3,
                        log_sq_size,
                        cqn,
                        discovered_tisn,
                    ) {
                        Ok(sqn) => {
                            self.remember_external_tis(discovered_tisn, "sq_scan_active");
                            tx_using_fallback_tis0 = false;
                            Ok(sqn)
                        }
                        Err(err) if tx_using_fallback_tis0 => {
                            log::warn!(
                                target: "mlx5",
                                "PF SQ-derived TIS candidate {:#x} was rejected by CREATE_SQ: {:?}; continuing with fallback probes",
                                discovered_tisn,
                                err
                            );
                            tx_oracle_tisn = None;
                            match self.create_sq_with_pf_tis_oracle(
                                sq_buf.0,
                                sq_buf.1,
                                sq_buf.2,
                                sq_buf.3,
                                log_sq_size,
                                cqn,
                            ) {
                                Ok((sqn, discovered_tisn)) => {
                                    tx_oracle_tisn = Some(discovered_tisn);
                                    tx_using_fallback_tis0 = false;
                                    log::warn!(
                                        target: "mlx5",
                                        "Using PF TX TIS discovered via CREATE_SQ oracle: tisn={:#x}",
                                        discovered_tisn
                                    );
                                    Ok(sqn)
                                }
                                Err(err) => {
                                    log::warn!(
                                        target: "mlx5",
                                        "No explicit PF TX TIS candidate worked via CREATE_SQ oracle; falling back to implicit TIS=0 after last error {:?}",
                                        err
                                    );
                                    self.create_sq_hw(
                                        sq_buf.0,
                                        sq_buf.1,
                                        sq_buf.2,
                                        sq_buf.3,
                                        log_sq_size,
                                        cqn,
                                        tisn,
                                    )
                                }
                            }
                        }
                        Err(err) => Err(err),
                    }
                } else if tx_using_fallback_tis0 {
                    match self.create_sq_with_pf_tis_oracle(
                        sq_buf.0,
                        sq_buf.1,
                        sq_buf.2,
                        sq_buf.3,
                        log_sq_size,
                        cqn,
                    ) {
                        Ok((sqn, discovered_tisn)) => {
                            tx_oracle_tisn = Some(discovered_tisn);
                            tx_using_fallback_tis0 = false;
                            log::warn!(
                                target: "mlx5",
                                "Using PF TX TIS discovered via CREATE_SQ oracle: tisn={:#x}",
                                discovered_tisn
                            );
                            Ok(sqn)
                        }
                        Err(err) => {
                            log::warn!(
                                target: "mlx5",
                                "No explicit PF TX TIS candidate worked via CREATE_SQ oracle; falling back to implicit TIS=0 after last error {:?}",
                                err
                            );
                            self.create_sq_hw(
                                sq_buf.0,
                                sq_buf.1,
                                sq_buf.2,
                                sq_buf.3,
                                log_sq_size,
                                cqn,
                                tisn,
                            )
                        }
                    }
                } else {
                    self.create_sq_hw(
                        sq_buf.0,
                        sq_buf.1,
                        sq_buf.2,
                        sq_buf.3,
                        log_sq_size,
                        cqn,
                        tisn,
                    )
                };

                if let Err(err) = sq_result {
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
                "mlx5 TX fallback active: TX path disabled (no usable TIS/SQ), continuing RX setup"
            );
        } else if let Some(discovered_tisn) = tx_oracle_tisn {
            log::warn!(
                target: "mlx5",
                "mlx5 TX fallback resolved: TX path running with PF TIS discovered via CREATE_SQ oracle ({:#x})",
                discovered_tisn
            );
        } else if tx_using_fallback_tis0 {
            log::warn!(
                target: "mlx5",
                "mlx5 TX fallback active: TX path running with implicit TIS=0"
            );
        }

        if self.is_vf() && self.sqs.is_empty() {
            log::warn!(
                target: "mlx5",
                "VF bootstrap produced no working SQ; continuing RX-only with TX unavailable"
            );
            tx_path_enabled = false;
        }

        self.set_tx_runtime_state(tx_path_enabled, tx_using_fallback_tis0);

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
            let rmp_buf = rmp_bufs[i % rmp_bufs.len()];
            let rqn = self.create_rq_hw(
                rq_buf.0,
                rq_buf.1,
                rq_buf.2,
                rq_buf.3,
                rmp_buf.0,
                rmp_buf.1,
                rmp_buf.2,
                rmp_buf.3,
                log_rq_size,
                cqn,
                0, // Dummy TIRN for DirectRq (unused in create_rq_hw)
                scatter_fcs,
                vlan_strip,
            )?;
            rqns.push(rqn);
        }
        crate::boot_trace("[MLX5_STAGE] rq_done\n");

        if self.is_vf() && rqns.is_empty() {
            log::error!(
                target: "mlx5",
                "VF bootstrap failed: no working RQ was created"
            );
            return Err(Mlx5Error::NotSupported);
        }

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

        if self.is_vf() && self.tir_list.is_empty() {
            log::error!(
                target: "mlx5",
                "VF bootstrap failed: no working TIR path was created"
            );
            return Err(Mlx5Error::NotSupported);
        }

        // Finalize
        crate::boot_trace("[MLX5_STAGE] flow_table_enter\n");
        if let Err(err) = self.setup_rx_flow_table_advanced(tirn) {
            if self.is_vf() {
                log::warn!(
                    target: "mlx5",
                    "VF RX flow-table setup failed; relying on PF default steering: {:?}",
                    err
                );
                let _ = err;
                crate::boot_trace("[MLX5_STAGE] rx_flow_table_vf_failed\n");
            }
        }
        match self.set_promiscuous_mode(true) {
            Ok(()) => {
                if self.is_vf() {
                    log::info!(
                        target: "mlx5",
                        "Enabled VF wildcard RX steering for bring-up diagnostics"
                    );
                } else {
                    log::info!(
                        target: "mlx5",
                        "Enabled PF promiscuous RX steering for bring-up"
                    );
                }
            }
            Err(err) => {
                if self.is_vf() {
                    log::warn!(
                        target: "mlx5",
                        "Failed to enable VF wildcard RX steering: {:?}",
                        err
                    );
                } else {
                    log::warn!(
                        target: "mlx5",
                        "Failed to enable PF promiscuous RX steering: {:?}",
                        err
                    );
                }
            }
        }
        if self.is_vf() {
            match self.set_nic_vport_promisc(true, true, true) {
                Ok(()) => log::info!(
                    target: "mlx5",
                    "Enabled VF NIC vport promisc (uc/mc/all) for bring-up diagnostics"
                ),
                Err(err) => log::warn!(
                    target: "mlx5",
                    "Failed to enable VF NIC vport promisc: {:?}",
                    err
                ),
            }
        }
        crate::boot_trace("[MLX5_STAGE] flow_table_done\n");
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
            crate::boot_trace("[MLX5_STAGE] try_port_admin_up_pf\n");
            let _ = self.set_port_admin_up(0);
            match self.query_port_state(0) {
                Ok(state) => {
                    log::info!(target: "mlx5", "PF port link state after admin-up: {:?}", state);
                }
                Err(err) => {
                    log::warn!(
                        target: "mlx5",
                        "Failed to query PF port link state after admin-up: {:?}",
                        err
                    );
                }
            }
            crate::boot_trace("[MLX5_STAGE] port_admin_up_pf_done\n");
        }
        if let Some(port) = self.ports.get_mut(0) {
            port.admin_up();
        }

        // Avoid tick-based busy waits here. During early PF bring-up this path
        // can run before the scheduler tick is reliably advancing, which turns
        // a 50ms delay into an indefinite stall.
        if !self.is_vf() {
            crate::boot_trace("[MLX5_STAGE] post_admin_delay_enter\n");
            for _ in 0..200_000 {
                core::hint::spin_loop();
            }
            crate::boot_trace("[MLX5_STAGE] post_admin_delay_done\n");
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

#[cfg(test)]
mod tests {
    use super::{Mlx5Device, TxTisAttemptKind};

    #[test]
    fn vf_tis_attempt_order_tries_reuse_then_create_before_implicit_fallback() {
        assert_eq!(
            Mlx5Device::vf_tx_tis_attempt_order(),
            [
                TxTisAttemptKind::ReuseExisting,
                TxTisAttemptKind::CreateTis,
                TxTisAttemptKind::ImplicitTis0,
            ]
        );
    }
}
