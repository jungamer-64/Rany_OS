// ============================================================================
// drivers/mlx5/src/device/res.rs - MLX5 Resource Management
// ============================================================================

extern crate alloc;
use crate::cmd::CmdMailbox;
use crate::cmd::CommandTransport; // needed to bring execute() method into scope
use crate::cmd::hca::*; // basic HCA commands (SET_DRIVER_VERSION etc)
use crate::cmd::res::*; // resource command builders/parsers
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE};
use crate::device::Mlx5Device;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::{FlowGroup, FlowTable, FlowTableConfig, FlowTableEntry};
use crate::resources::{MkeyInfo, MkeyParams, TirInfo, TirParams, TisInfo, TisParams};

impl Mlx5Device {
    /// ローカルTISの存在確認
    pub unsafe fn query_tis_exists(&mut self, tisn: u32) -> Mlx5Result<()> {
        self.query_tis(tisn).map(|_| ())
    }

    /// ローカル TIS コンテキストを取得
    pub unsafe fn query_tis(&mut self, tisn: u32) -> Mlx5Result<crate::cmd::res::QueryTisInfo> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_tis_input(in_mbox, tisn, 0, false);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryTis,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_tis_output(out_mbox))
    }

    /// PF passthrough 向けの既存TISを探索
    pub unsafe fn find_existing_tis(&mut self, max_scan: u32) -> Mlx5Result<u32> {
        self.find_existing_tis_matching(max_scan, self.td, 0)
    }

    /// PF passthrough 向けの既存 TIS を優先条件付きで探索
    pub unsafe fn find_existing_tis_matching(
        &mut self,
        max_scan: u32,
        preferred_td: u32,
        preferred_prio: u8,
    ) -> Mlx5Result<u32> {
        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let mut first_any = None;
        // mlx5 object IDs can live in prefixed namespaces. Probe the low
        // range first, then common high-prefix windows used by other queueing
        // objects (for example RQNs on this PF show up under 0x00c0_0000).
        let low_budget = max_scan / 2;
        let high_budget_each = (max_scan.saturating_sub(low_budget)) / 3;
        let scan_windows = [
            (0x0000_0000u32, low_budget.max(1)),
            (0x0040_0000u32, high_budget_each.max(1)),
            (0x0080_0000u32, high_budget_each.max(1)),
            (
                0x00c0_0000u32,
                max_scan
                    .saturating_sub(low_budget)
                    .saturating_sub(high_budget_each.saturating_mul(2))
                    .max(1),
            ),
        ];

        for &(base, count) in &scan_windows {
            for offset in 0..count {
                let tisn = (base + offset) & 0x00ff_ffff;
                match self.query_tis(tisn) {
                    Ok(info) => {
                        let matched = !info.tls_en
                            && info.transport_domain == preferred_td
                            && info.prio == preferred_prio
                            && info.underlay_qpn == 0;
                        if first_any.is_none() {
                            first_any = Some((tisn, info));
                        }
                        if matched {
                            log::info!(
                                target: "mlx5",
                                "Found matching existing TIS via QUERY_TIS: tisn={:#x} td={} prio={} pd={} lag_port={} strict_lag={}",
                                tisn,
                                info.transport_domain,
                                info.prio,
                                info.pd,
                                info.lag_tx_port_affinity,
                                info.strict_lag_tx_port_affinity
                            );
                            return Ok(tisn);
                        }
                        log::info!(
                            target: "mlx5",
                            "Found reusable existing TIS candidate via QUERY_TIS: tisn={:#x} td={} prio={} pd={} underlay_qpn={:#x} tls={} lag_port={} strict_lag={}",
                            tisn,
                            info.transport_domain,
                            info.prio,
                            info.pd,
                            info.underlay_qpn,
                            info.tls_en,
                            info.lag_tx_port_affinity,
                            info.strict_lag_tx_port_affinity
                        );
                    }
                    Err(err) => last_err = Err(err),
                }
            }
        }
        if let Some((tisn, info)) = first_any {
            log::warn!(
                target: "mlx5",
                "Falling back to first existing TIS candidate: tisn={:#x} td={} prio={} pd={} underlay_qpn={:#x} tls={}",
                tisn,
                info.transport_domain,
                info.prio,
                info.pd,
                info.underlay_qpn,
                info.tls_en
            );
            return Ok(tisn);
        }
        last_err
    }

    /// QUERY_SPECIAL_CONTEXTS から reserved lkey を取得
    pub unsafe fn query_reserved_lkey(&mut self) -> Mlx5Result<u32> {
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_special_contexts_input(in_mbox);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QuerySpecialContexts,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            0x40,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_special_contexts_resd_lkey(out_mbox))
    }

    /// Direct Memory Key を作成
    pub unsafe fn create_mkey(&mut self, params: &MkeyParams) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::res::build_create_mkey_input(in_mbox, params);
        log::info!(
            target: "mlx5",
            "CREATE_MKEY in(pre): pd={} start={:#x} len={:#x} access={:#x}",
            params.pd,
            params.start_addr,
            params.length,
            params.access_flags
        );

        self.execute_uid_sensitive_cmd(
            CmdOpcode::CreateMkey,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let mkey_index = crate::cmd::res::parse_create_mkey_output(out_mbox);
        let full_mkey = mkey_index << 8;

        match self.query_mkey(mkey_index) {
            Ok(ctx) => {
                log::info!(
                    target: "mlx5",
                    "QUERY_MKEY: index={:#x} key={:#x} access_mode={} free={} umr_en={} a={} lr={} lw={} rr={} rw={} qpn={:#x} pd={} start={:#x} len={:#x} length64={} xlt_octwords={} log_page_size={} mkey_7_0={:#x}",
                    mkey_index,
                    full_mkey,
                    ctx.access_mode,
                    ctx.free,
                    ctx.umr_en,
                    ctx.remote_atomic,
                    ctx.local_read,
                    ctx.local_write,
                    ctx.remote_read,
                    ctx.remote_write,
                    ctx.qpn,
                    ctx.pd,
                    ctx.start_addr,
                    ctx.len,
                    ctx.length64,
                    ctx.translations_octword_size,
                    ctx.log_page_size,
                    ctx.mkey_7_0
                );
            }
            Err(err) => {
                log::warn!(
                    target: "mlx5",
                    "QUERY_MKEY failed for index={:#x}: {:?}",
                    mkey_index,
                    err
                );
            }
        }

        let info = MkeyInfo {
            mkey_index,
            mkey: full_mkey,
            params: params.clone(),
        };

        log::info!(target: "mlx5", "MKEY created: index={:#x} mkey={:#x}", mkey_index, full_mkey);
        self.mkey = full_mkey;
        self.mkey_info = Some(info);
        Ok(full_mkey)
    }

    /// MKEY コンテキストをクエリ
    pub unsafe fn query_mkey(
        &mut self,
        mkey_index: u32,
    ) -> Mlx5Result<crate::cmd::res::QueryMkeyInfo> {
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_mkey_input(in_mbox, mkey_index);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryMkey,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_mkey_output(out_mbox))
    }

    /// CREATE_QP で Linux IPoIB 相当の最小 underlay QP を作成
    pub unsafe fn create_underlay_qp(&mut self, vhca_port: u8) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;

        let mkey_by_name = self
            .hca_caps()
            .map(|caps| caps.mkey_by_name)
            .unwrap_or(false);
        let ts_format = self
            .hca_caps()
            .map(|caps| if caps.sq_ts_format != 0 { 1 } else { 0 })
            .unwrap_or(0);
        let port_index = usize::from(vhca_port.saturating_sub(1));
        let mut input_qpn = None;

        if mkey_by_name {
            let mut mac = self
                .port(port_index)
                .map(|port| port.mac_bytes())
                .unwrap_or([0; 6]);
            if mac == [0; 6] {
                match self.query_port_mac(port_index) {
                    Ok(queried_mac) => mac = queried_mac.0,
                    Err(err) => {
                        log::warn!(
                            target: "mlx5",
                            "mkey_by_name is enabled but MAC query failed for underlay QP probe on port {}: {:?}",
                            port_index + 1,
                            err
                        );
                    }
                }
            }

            if mac != [0; 6] {
                input_qpn = Some(((mac[1] as u32) << 16) | ((mac[2] as u32) << 8) | mac[3] as u32);
            } else {
                log::warn!(
                    target: "mlx5",
                    "mkey_by_name is enabled but no valid MAC is available for underlay QP probe on port {}",
                    port_index + 1
                );
            }
        }

        log::info!(
            target: "mlx5",
            "CREATE_QP underlay probe: vhca_port={} mkey_by_name={} ts_format={} input_qpn={:?}",
            vhca_port,
            mkey_by_name,
            ts_format,
            input_qpn
        );
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::res::build_create_underlay_qp_input(in_mbox, vhca_port, input_qpn, ts_format);
        self.execute_uid_sensitive_cmd(CmdOpcode::CreateQp, 0x110, 0x10)?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let qpn = crate::cmd::res::parse_create_qp_output(out_mbox);
        log::warn!(
            target: "mlx5",
            "CREATE_QP underlay probe succeeded: qpn={:#x} vhca_port={}",
            qpn,
            vhca_port
        );
        Ok(qpn)
    }

    /// TIS (Transport Interface Send) を作成
    pub unsafe fn create_tis(&mut self, params: &TisParams) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        crate::boot_trace("[MLX5_TIS] enter\n");

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        // VF firmware behavior varies across revisions; keep a short, targeted
        // retry set that mirrors Linux-like defaults first, then conservative
        // compatibility variants.
        let attempts = [
            (
                "td-only",
                params.td,
                params.prio,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+lag-port",
                params.td,
                params.prio,
                false,
                0u32,
                0u16,
                params.port & 0x0f,
                false,
            ),
            (
                "td-only+lag-port-strict",
                params.td,
                params.prio,
                false,
                0u32,
                0u16,
                params.port & 0x0f,
                true,
            ),
            (
                "td-only+strict-lag",
                params.td,
                params.prio,
                false,
                0u32,
                0u16,
                0u8,
                true,
            ),
            (
                "td+pd",
                params.td,
                params.prio,
                true,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td+pd+lag-port",
                params.td,
                params.prio,
                true,
                0u32,
                0u16,
                params.port & 0x0f,
                false,
            ),
            (
                "td-only+underlay-1",
                params.td,
                params.prio,
                false,
                0x1u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td+pd+underlay-1",
                params.td,
                params.prio,
                true,
                0x1u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+underlay-ffff",
                params.td,
                params.prio,
                false,
                0x00ff_ffffu32,
                0u16,
                0u8,
                false,
            ),
            (
                "td+pd+underlay-ffff",
                params.td,
                params.prio,
                true,
                0x00ff_ffffu32,
                0u16,
                0u8,
                false,
            ),
            (
                "td+opmod1",
                params.td,
                params.prio,
                false,
                0u32,
                1u16,
                0u8,
                false,
            ),
            ("td0", 0u32, params.prio, false, 0u32, 0u16, 0u8, false),
            (
                "td-only+prio2",
                params.td,
                2u8,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+prio4",
                params.td,
                4u8,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+prio6",
                params.td,
                6u8,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+prio8",
                params.td,
                8u8,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+prio10",
                params.td,
                10u8,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+prio12",
                params.td,
                12u8,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
            (
                "td-only+prio14",
                params.td,
                14u8,
                false,
                0u32,
                0u16,
                0u8,
                false,
            ),
        ];
        let mut last_err = Err(Mlx5Error::NotSupported);

        for (attempt_name, td, prio, include_pd, underlay_qpn, op_mod, lag_port, strict_lag) in
            attempts
        {
            crate::cmd::res::build_create_tis_input_with_options(
                in_mbox,
                params,
                include_pd,
                underlay_qpn,
            );
            if op_mod != 0 {
                in_mbox.write_be16(0x06, op_mod);
            }
            if td != params.td {
                let mut layout =
                    crate::structs::cmd::TisContextLayout::new(&mut in_mbox.data[0x20..]);
                layout.set_transport_domain(td);
            }
            if prio != params.prio {
                let mut layout =
                    crate::structs::cmd::TisContextLayout::new(&mut in_mbox.data[0x20..]);
                layout.set_prio(prio);
            }
            if lag_port != 0 || strict_lag {
                let mut layout =
                    crate::structs::cmd::TisContextLayout::new(&mut in_mbox.data[0x20..]);
                layout.set_lag_tx_port_affinity(lag_port);
                layout.set_strict_lag_tx_port_affinity(strict_lag);
            }
            log::info!(
                target: "mlx5",
                "CREATE_TIS try {}: td={} pd={} include_pd={} port={} prio={} underlay_qpn={:#x} op_mod={} lag_port={} strict_lag={}",
                attempt_name,
                td,
                params.pd,
                include_pd,
                params.port,
                prio,
                underlay_qpn,
                op_mod,
                lag_port,
                strict_lag
            );

            match self.execute_uid_sensitive_cmd(CmdOpcode::CreateTis, 0xC0, 0x10) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    let tisn = crate::cmd::res::parse_create_tis_output(out_mbox);
                    let info = TisInfo {
                        tisn,
                        port: params.port,
                    };
                    self.tis_list.push(info);
                    crate::boot_trace("[MLX5_TIS] create ok\n");
                    return Ok(tisn);
                }
                Err(err) => {
                    crate::boot_trace("[MLX5_TIS] create fail\n");
                    log::warn!(
                        target: "mlx5",
                        "CREATE_TIS attempt {} failed: {:?}",
                        attempt_name,
                        err
                    );
                    last_err = Err(err);
                }
            }
        }

        if !self.is_vf() {
            match self.create_underlay_qp(params.port.max(1)) {
                Ok(qpn) => {
                    crate::cmd::res::build_create_tis_input_with_options(
                        in_mbox, params, false, qpn,
                    );
                    log::warn!(
                        target: "mlx5",
                        "CREATE_TIS final probe with real underlay QP: td={} pd={} port={} prio={} underlay_qpn={:#x}",
                        params.td,
                        params.pd,
                        params.port,
                        params.prio,
                        qpn
                    );
                    match self.execute_uid_sensitive_cmd(CmdOpcode::CreateTis, 0xC0, 0x10) {
                        Ok(()) => {
                            let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                            let tisn = crate::cmd::res::parse_create_tis_output(out_mbox);
                            let info = TisInfo {
                                tisn,
                                port: params.port,
                            };
                            self.underlay_qpn = qpn;
                            self.tis_list.push(info);
                            crate::boot_trace("[MLX5_TIS] create ok\n");
                            return Ok(tisn);
                        }
                        Err(err) => {
                            log::warn!(
                                target: "mlx5",
                                "CREATE_TIS with real underlay QP {:#x} failed: {:?}",
                                qpn,
                                err
                            );
                            let _ = self.destroy_qp_hw(qpn);
                            last_err = Err(err);
                        }
                    }
                }
                Err(err) => {
                    log::warn!(
                        target: "mlx5",
                        "CREATE_QP underlay probe failed before final CREATE_TIS attempt: {:?}",
                        err
                    );
                    last_err = Err(err);
                }
            }
        }
        crate::boot_trace("[MLX5_TIS] exhausted\n");
        last_err
    }

    /// TIR (Transport Interface Receive) を作成
    pub unsafe fn create_tir(&mut self, params: &TirParams) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        crate::boot_trace("[MLX5_TIR] enter\n");

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::res::build_create_tir_input(in_mbox, params);
        crate::boot_trace("[MLX5_TIR] input_built\n");

        self.execute_uid_sensitive_cmd(
            CmdOpcode::CreateTir,
            0x110, // mailbox input length (header + payload)
            0x10,  // output length
        )?;
        crate::boot_trace("[MLX5_TIR] cmd_done\n");

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let tirn = crate::cmd::res::parse_create_tir_output(out_mbox);

        let info = TirInfo {
            tirn,
            receive_type: params.receive_type,
        };
        self.tir_list.push(info);

        crate::boot_trace("[MLX5_TIR] done\n");
        Ok(tirn)
    }

    /// UAR (User Access Region) を割り当て
    pub unsafe fn alloc_uar(&mut self) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf);

        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let mut fallback_uar = None;
        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_alloc_uar_input(in_mbox);

            match cmd.execute(
                CmdOpcode::AllocUar,
                self.cmd_in_mbox_device,
                0x10,
                self.cmd_out_mbox_device,
                0x10,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    let uar_number = parse_alloc_uar_output(out_mbox);
                    self.allocated_uars.push(uar_number);
                    if self.uar_page == 0 {
                        self.uar_page = uar_number;
                        self.uar_base = self.bar0_base
                            + (uar_number as u64) * (crate::regs::uar::PAGE_SIZE as u64);
                    }
                    cmd.set_uid(prev_uid);
                    return Ok(uar_number);
                }
                Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                    fallback_uar = Some(0);
                    last_err = Err(Mlx5Error::CommandFailed(status));
                    continue;
                }
                Err(e) => {
                    last_err = Err(e);
                    continue;
                }
            }
        }
        cmd.set_uid(prev_uid);
        if let Some(uar_number) = fallback_uar {
            self.allocated_uars.push(uar_number);
            self.uar_page = uar_number;
            self.uar_base =
                self.bar0_base + (uar_number as u64) * (crate::regs::uar::PAGE_SIZE as u64);
            return Ok(uar_number);
        }
        last_err
    }

    /// Protection Domain を割り当て
    pub unsafe fn alloc_pd(&mut self) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf);

        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let mut fallback_pd = None;
        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_alloc_pd_input(in_mbox);

            match cmd.execute(
                CmdOpcode::AllocPd,
                self.cmd_in_mbox_device,
                0x10,
                self.cmd_out_mbox_device,
                0x10,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    self.pd = parse_alloc_pd_output(out_mbox);
                    log::info!(target: "mlx5", "ALLOC_PD assigned pd={}", self.pd);
                    cmd.set_uid(prev_uid);
                    return Ok(self.pd);
                }
                Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                    fallback_pd = Some(0);
                    last_err = Err(Mlx5Error::CommandFailed(status));
                    continue;
                }
                Err(e) => {
                    last_err = Err(e);
                    continue;
                }
            }
        }
        cmd.set_uid(prev_uid);
        if let Some(pd) = fallback_pd {
            self.pd = pd;
            log::warn!(target: "mlx5", "ALLOC_PD fell back to pd={}", self.pd);
            return Ok(self.pd);
        }
        last_err
    }

    /// Transport Domain を割り当て
    pub unsafe fn alloc_td(&mut self) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf);

        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let mut fallback_td = None;
        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_alloc_td_input(in_mbox);

            match cmd.execute(
                CmdOpcode::AllocTransportDomain,
                self.cmd_in_mbox_device,
                0x10,
                self.cmd_out_mbox_device,
                0x10,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    self.td = parse_alloc_td_output(out_mbox);
                    log::info!(target: "mlx5", "ALLOC_TD assigned td={}", self.td);
                    cmd.set_uid(prev_uid);
                    return Ok(self.td);
                }
                Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                    fallback_td = Some(0);
                    last_err = Err(Mlx5Error::CommandFailed(status));
                    continue;
                }
                Err(e) => {
                    last_err = Err(e);
                    continue;
                }
            }
        }
        cmd.set_uid(prev_uid);
        if let Some(td) = fallback_td {
            self.td = td;
            log::warn!(target: "mlx5", "ALLOC_TD fell back to td={}", self.td);
            return Ok(self.td);
        }
        last_err
    }

    pub unsafe fn set_driver_version(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !self
            .hca_caps
            .as_ref()
            .map(|caps| caps.driver_version_cap)
            .unwrap_or(false)
        {
            log::debug!(
                target: "mlx5",
                "Skipping SET_DRIVER_VERSION because the capability bit is not set"
            );
            return Ok(());
        }
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        // Linux format: "Linux,mlx5_core,<major>.<minor>.<patch>".
        let version = b"Linux,mlx5_core,0.1.0";
        build_set_driver_version_input(in_mbox, version);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::SetDriverVersion,
            self.cmd_in_mbox_device,
            0x50,
            self.cmd_out_mbox_device,
            0x10,
        )?;
        Ok(())
    }

    /// フローテーブルに特定のMACアドレスフィルタを追加
    pub unsafe fn add_mac_filter(
        &mut self,
        table_id: u32,
        group_id: u32,
        flow_index: u32,
        mac: [u8; 6],
        tirn: u32,
    ) -> Mlx5Result<()> {
        let mut match_value = crate::flow::MatchValue::default();
        match_value.dst_mac = Some(mac);

        self.set_flow_table_entry(
            table_id,
            flow_index,
            group_id,
            crate::flow::FlowAction::Allow,
            Some(tirn),
            &match_value,
        )
    }

    /// フローテーブルに特定のIPv4アドレスフィルタを追加
    pub unsafe fn add_ip_filter(
        &mut self,
        table_id: u32,
        group_id: u32,
        flow_index: u32,
        dst_ip: u32,
        tirn: u32,
    ) -> Mlx5Result<()> {
        let mut match_value = crate::flow::MatchValue::default();
        match_value.dst_ipv4 = Some(dst_ip);

        self.set_flow_table_entry(
            table_id,
            flow_index,
            group_id,
            crate::flow::FlowAction::Allow,
            Some(tirn),
            &match_value,
        )
    }

    pub unsafe fn setup_rx_flow_table_advanced(&mut self, tirn: u32) -> Mlx5Result<()> {
        let ft_config = FlowTableConfig {
            table_type: crate::flow::FlowTableType::NicRx,
            log_size: 7, // 128エントリ (Unicast + Multicast + Broadcast用)
            level: 0,
        };
        let table_id = self.create_flow_table(&ft_config)?;

        // グループ1: ユニキャスト/マルチキャスト用 (マッチ条件あり)
        let mut criteria = crate::flow::MatchCriteria::default();
        criteria.outer_l2 = true;
        let group_id = self.create_flow_group(table_id, 0, 63, &criteria)?;

        // 自分のMACアドレスを登録
        let my_mac = self
            .ports
            .get(0)
            .map(|p| p.mac_address().0)
            .unwrap_or([0; 6]);
        if my_mac != [0; 6] {
            self.add_mac_filter(table_id, group_id, 0, my_mac, tirn)?;
        }

        // ブロードキャストを登録
        self.add_mac_filter(table_id, group_id, 1, [0xFF; 6], tirn)?;

        // グループ2: デフォルト（マッチしなかったパケットを捨てる、またはプロミスキャス用）
        let criteria_all = crate::flow::MatchCriteria::default();
        let _ = self.create_flow_group(table_id, 64, 127, &criteria_all)?;

        Ok(())
    }

    pub unsafe fn create_flow_table(&mut self, config: &FlowTableConfig) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_create_flow_table_input(in_mbox, config);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::CreateFlowTable,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let table_id = crate::cmd::flow::parse_create_flow_table_output(out_mbox);
        self.flow_tables.push(FlowTable {
            table_id,
            table_type: config.table_type,
            size: 1 << config.log_size,
            level: config.level,
        });
        Ok(table_id)
    }

    pub unsafe fn create_flow_group(
        &mut self,
        table_id: u32,
        start_index: u32,
        end_index: u32,
        criteria: &crate::flow::MatchCriteria,
    ) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_create_flow_group_input(
            in_mbox,
            table_id,
            start_index,
            end_index,
            criteria,
        );
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::CreateFlowGroup,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let group_id = crate::cmd::flow::parse_create_flow_group_output(out_mbox);
        self.flow_groups.push(FlowGroup {
            group_id,
            table_id,
            start_index,
            end_index,
            match_criteria: criteria.clone(),
        });
        Ok(group_id)
    }

    pub unsafe fn set_flow_table_entry(
        &mut self,
        table_id: u32,
        flow_index: u32,
        group_id: u32,
        action: crate::flow::FlowAction,
        destination_tirn: Option<u32>,
        match_value: &crate::flow::MatchValue,
    ) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_set_flow_table_entry_input(
            in_mbox,
            table_id,
            flow_index,
            group_id,
            action,
            destination_tirn,
            match_value,
        );
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::SetFlowTableEntry,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        self.flow_entries.push(FlowTableEntry {
            index: flow_index,
            table_id,
            group_id,
            match_value: match_value.clone(),
            action,
            destination_tirn,
        });
        Ok(())
    }
}
