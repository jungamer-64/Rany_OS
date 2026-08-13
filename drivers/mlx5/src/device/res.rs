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
use crate::resources::{MkeyInfo, MkeyParams, TirInfo, TirParams, TisOwnership, TisParams};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreateTisAttempt {
    name: &'static str,
    td: u32,
    prio: u8,
    include_pd: bool,
    underlay_qpn: u32,
    op_mod: u16,
    lag_port: u8,
    strict_lag: bool,
}

impl Mlx5Device {
    fn tis_matches_reuse_profile(
        info: &crate::cmd::res::QueryTisInfo,
        preferred_td: u32,
        preferred_prio: u8,
    ) -> bool {
        !info.tls_en
            && info.transport_domain == preferred_td
            && info.prio == preferred_prio
            && info.underlay_qpn == 0
            && info.lag_tx_port_affinity == 0
            && !info.strict_lag_tx_port_affinity
    }

    fn is_default_profile_tis(info: &crate::cmd::res::QueryTisInfo) -> bool {
        !info.tls_en
            && info.transport_domain == 0
            && info.pd == 0
            && info.prio == 0
            && info.underlay_qpn == 0
            && info.lag_tx_port_affinity == 0
            && !info.strict_lag_tx_port_affinity
    }

    unsafe fn last_cmd_status_and_syndrome(&self) -> (u8, u32) {
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        (out_mbox.data[0], out_mbox.read_be32(0x04))
    }

    fn prepare_create_tis_attempt(
        in_mbox: &mut CmdMailbox,
        params: &TisParams,
        attempt: CreateTisAttempt,
    ) -> CmdMailbox {
        crate::cmd::res::build_create_tis_input_with_options(
            in_mbox,
            params,
            attempt.include_pd,
            attempt.underlay_qpn,
        );
        if attempt.op_mod != 0 {
            in_mbox.write_be16(0x06, attempt.op_mod);
        }

        let mut layout = crate::structs::cmd::TisContextLayout::new(&mut in_mbox.data[0x20..]);
        if attempt.td != params.td {
            layout.set_transport_domain(attempt.td);
        }
        if attempt.prio != params.prio {
            layout.set_prio(attempt.prio);
        }
        layout.set_lag_tx_port_affinity(attempt.lag_port);
        layout.set_strict_lag_tx_port_affinity(attempt.strict_lag);

        let mut pre_exec = CmdMailbox::zeroed();
        pre_exec.data[..0x110].copy_from_slice(&in_mbox.data[..0x110]);
        pre_exec
    }

    /// ローカルTISの存在確認
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_tis_exists(&mut self, tisn: u32) -> Mlx5Result<()> {
        self.query_tis(tisn).map(|_| ())
    }

    /// ローカル TIS コンテキストを取得
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_tis(&mut self, tisn: u32) -> Mlx5Result<crate::cmd::res::QueryTisInfo> {
        self.query_tis_with_snapshot(tisn).map(|(info, _)| info)
    }

    pub(crate) unsafe fn query_tis_with_snapshot(
        &mut self,
        tisn: u32,
    ) -> Mlx5Result<(crate::cmd::res::QueryTisInfo, CmdMailbox)> {
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
        let mut snapshot = CmdMailbox::zeroed();
        snapshot.data.copy_from_slice(&out_mbox.data);
        Ok((parse_query_tis_output(out_mbox), snapshot))
    }

    /// PF passthrough 向けの既存TISを探索
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn find_existing_tis(&mut self, max_scan: u32) -> Mlx5Result<u32> {
        self.find_existing_tis_matching(max_scan, self.td, 0)
    }

    /// default-only PF profile 向けに、all-zero send object を優先して探索
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn find_existing_tis_default_profile(&mut self, max_scan: u32) -> Mlx5Result<u32> {
        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let mut first_any = None;
        let scan_windows = Self::object_id_scan_windows(max_scan);

        for &(base, count) in &scan_windows {
            for offset in 0..count {
                let tisn = (base + offset) & 0x00ff_ffff;
                match self.query_tis(tisn) {
                    Ok(info) => {
                        if first_any.is_none() {
                            first_any = Some((tisn, info));
                        }
                        if Self::is_default_profile_tis(&info) {
                            log::info!(
                                target: "mlx5",
                                "Found default-profile existing TIS via QUERY_TIS: tisn={:#x} td={} prio={} pd={} underlay_qpn={:#x} lag_port={} strict_lag={}",
                                tisn,
                                info.transport_domain,
                                info.prio,
                                info.pd,
                                info.underlay_qpn,
                                info.lag_tx_port_affinity,
                                info.strict_lag_tx_port_affinity
                            );
                            return Ok(tisn);
                        }
                        if cfg!(feature = "debug_mlx5_cmd") {
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
                    }
                    Err(err) => last_err = Err(err),
                }
            }
        }

        if let Some((tisn, info)) = first_any {
            log::warn!(
                target: "mlx5",
                "Default-profile TIS scan fell back to first existing candidate: tisn={:#x} td={} prio={} pd={} underlay_qpn={:#x} tls={}",
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

    /// PF passthrough 向けの既存 TIS を優先条件付きで探索
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn find_existing_tis_matching(
        &mut self,
        max_scan: u32,
        preferred_td: u32,
        preferred_prio: u8,
    ) -> Mlx5Result<u32> {
        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let mut first_any = None;
        // mlx5 object IDs can live in prefixed namespaces. Probe the common
        // low/high windows first, then sweep the remaining 1MB prefixes within
        // the 24-bit object-ID space.
        let scan_windows = Self::object_id_scan_windows(max_scan);

        for &(base, count) in &scan_windows {
            for offset in 0..count {
                let tisn = (base + offset) & 0x00ff_ffff;
                match self.query_tis(tisn) {
                    Ok(info) => {
                        let matched =
                            Self::tis_matches_reuse_profile(&info, preferred_td, preferred_prio);
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
                        log::debug!(
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

    /// VF 向けに、既存 TIS は厳密一致のみ再利用する
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn find_existing_tis_strict_match(
        &mut self,
        max_scan: u32,
        preferred_td: u32,
        preferred_prio: u8,
    ) -> Mlx5Result<u32> {
        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let scan_windows = Self::object_id_scan_windows(max_scan);

        for &(base, count) in &scan_windows {
            for offset in 0..count {
                let tisn = (base + offset) & 0x00ff_ffff;
                match self.query_tis(tisn) {
                    Ok(info) => {
                        if Self::tis_matches_reuse_profile(&info, preferred_td, preferred_prio) {
                            log::info!(
                                target: "mlx5",
                                "Found strict-match existing TIS via QUERY_TIS: tisn={:#x} td={} prio={} pd={} lag_port={} strict_lag={}",
                                tisn,
                                info.transport_domain,
                                info.prio,
                                info.pd,
                                info.lag_tx_port_affinity,
                                info.strict_lag_tx_port_affinity
                            );
                            return Ok(tisn);
                        }

                        log::debug!(
                            target: "mlx5",
                            "Ignoring non-matching VF TIS candidate via QUERY_TIS: tisn={:#x} td={} prio={} pd={} underlay_qpn={:#x} tls={} lag_port={} strict_lag={}",
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

        last_err
    }

    pub unsafe fn trace_tis_prefix_namespace(&mut self, tisn: u32, probe_count: u32) {
        if !cfg!(feature = "debug_mlx5_cmd") {
            return;
        }
        let prefix_base = tisn & 0x00f0_0000;
        let mut hits = 0u32;
        for offset in 0..probe_count {
            let candidate = (prefix_base + offset) & 0x00ff_ffff;
            if let Ok(info) = self.query_tis(candidate) {
                hits += 1;
                log::info!(
                    target: "mlx5",
                    "TIS namespace probe: base={:#x} candidate={:#x} td={} pd={} prio={} underlay_qpn={:#x} lag_port={} strict_lag={} tls={} selected={}",
                    prefix_base,
                    candidate,
                    info.transport_domain,
                    info.pd,
                    info.prio,
                    info.underlay_qpn,
                    info.lag_tx_port_affinity,
                    info.strict_lag_tx_port_affinity,
                    info.tls_en,
                    candidate == tisn
                );
            }
        }

        if hits == 0 {
            log::warn!(
                target: "mlx5",
                "TIS namespace probe found no queryable objects near prefix base {:#x}",
                prefix_base
            );
        }
    }

    /// QUERY_SPECIAL_CONTEXTS から reserved lkey を取得
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub unsafe fn create_mkey(&mut self, params: &MkeyParams) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let (relaxed_ordering_write, relaxed_ordering_read) = self
            .hca_caps()
            .map(|caps| {
                (
                    caps.relaxed_ordering_write,
                    caps.relaxed_ordering_read || caps.relaxed_ordering_read_pci_enabled,
                )
            })
            .unwrap_or((false, false));
        crate::cmd::res::build_create_mkey_input_with_relaxed_ordering(
            in_mbox,
            params,
            relaxed_ordering_write,
            relaxed_ordering_read,
        );
        if cfg!(feature = "debug_mlx5_cmd") {
            log::info!(
                target: "mlx5",
                "CREATE_MKEY in(pre): pd={} start={:#x} len={:#x} access={:#x} ro_write={} ro_read={}",
                params.pd,
                params.start_addr,
                params.length,
                params.access_flags,
                relaxed_ordering_write,
                relaxed_ordering_read
            );
        }

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
                if cfg!(feature = "debug_mlx5_cmd") {
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
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
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

    /// CREATE_QP で最小構成の underlay QP を作成
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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
        let mut pre_exec = CmdMailbox::zeroed();
        pre_exec.data[..0x110].copy_from_slice(&in_mbox.data[..0x110]);
        match self.execute_uid_sensitive_cmd(CmdOpcode::CreateQp, 0x110, 0x10) {
            Ok(()) => {}
            Err(err) => {
                crate::boot_trace_mailbox_range("create_qp_pre", &pre_exec, 0x00, 12);
                crate::boot_trace_mailbox_range("qpc_pre", &pre_exec, 0x18, 24);
                return Err(err);
            }
        }

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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub unsafe fn create_tis(&mut self, params: &TisParams) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        crate::boot_trace("[MLX5_TIS] enter\n");

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        // VF firmware behavior varies across revisions; keep a short, targeted
        // retry set that starts with the common default profile, then tries
        // conservative compatibility variants.
        let attempts = [
            CreateTisAttempt {
                name: "td-only",
                td: params.td,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td+pd",
                td: params.td,
                prio: params.prio,
                include_pd: true,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+lag-port",
                td: params.td,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: params.port & 0x0f,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+strict-lag",
                td: params.td,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: true,
            },
            CreateTisAttempt {
                name: "td-only+underlay-1",
                td: params.td,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0x1,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td+pd+underlay-1",
                td: params.td,
                prio: params.prio,
                include_pd: true,
                underlay_qpn: 0x1,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+underlay-ffff",
                td: params.td,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0x00ff_ffff,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td+pd+underlay-ffff",
                td: params.td,
                prio: params.prio,
                include_pd: true,
                underlay_qpn: 0x00ff_ffff,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+lag-port-strict",
                td: params.td,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: params.port & 0x0f,
                strict_lag: true,
            },
            CreateTisAttempt {
                name: "td+pd+lag-port",
                td: params.td,
                prio: params.prio,
                include_pd: true,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: params.port & 0x0f,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td+opmod1",
                td: params.td,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 1,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td0",
                td: 0,
                prio: params.prio,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+prio2",
                td: params.td,
                prio: 2,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+prio4",
                td: params.td,
                prio: 4,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+prio6",
                td: params.td,
                prio: 6,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+prio8",
                td: params.td,
                prio: 8,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+prio10",
                td: params.td,
                prio: 10,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+prio12",
                td: params.td,
                prio: 12,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
            CreateTisAttempt {
                name: "td-only+prio14",
                td: params.td,
                prio: 14,
                include_pd: false,
                underlay_qpn: 0,
                op_mod: 0,
                lag_port: 0,
                strict_lag: false,
            },
        ];
        let mut last_err = Err(Mlx5Error::NotSupported);
        let attempt_count = attempts.len();

        for (attempt_idx, attempt) in attempts.into_iter().enumerate() {
            let pre_exec = Self::prepare_create_tis_attempt(in_mbox, params, attempt);
            if attempt_idx == 0 || cfg!(feature = "debug_mlx5_cmd") {
                log::info!(
                    target: "mlx5",
                    "CREATE_TIS try {}/{} {}: td={} pd={} include_pd={} port={} prio={} underlay_qpn={:#x} op_mod={} lag_port={} strict_lag={}",
                    attempt_idx + 1,
                    attempt_count,
                    attempt.name,
                    attempt.td,
                    params.pd,
                    attempt.include_pd,
                    params.port,
                    attempt.prio,
                    attempt.underlay_qpn,
                    attempt.op_mod,
                    attempt.lag_port,
                    attempt.strict_lag
                );
            } else {
                log::debug!(
                    target: "mlx5",
                    "CREATE_TIS try {}/{} {}",
                    attempt_idx + 1,
                    attempt_count,
                    attempt.name
                );
            }
            crate::boot_trace_tis_attempt(
                "try",
                attempt.name,
                attempt.td,
                params.pd,
                attempt.include_pd,
                params.port,
                attempt.prio,
                attempt.underlay_qpn,
                attempt.op_mod,
                attempt.lag_port,
                attempt.strict_lag,
            );
            crate::boot_trace_mailbox_range("tisc_try_hdr", &pre_exec, 0x00, 8);
            crate::boot_trace_mailbox_range("tisc_try_ctx", &pre_exec, 0x20, 16);

            match self.execute_uid_sensitive_cmd(CmdOpcode::CreateTis, 0x110, 0x10) {
                Ok(()) => {
                    crate::boot_trace_mailbox_range("tisc_pre", &pre_exec, 0x20, 16);
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    let tisn = crate::cmd::res::parse_create_tis_output(out_mbox);
                    self.record_tis_info(tisn, params.port, TisOwnership::DriverCreated);
                    crate::boot_trace("[MLX5_TIS] create ok\n");
                    return Ok(tisn);
                }
                Err(err) => {
                    let (fw_status, syndrome) = self.last_cmd_status_and_syndrome();
                    crate::boot_trace_mailbox_range("tisc_pre_fail", &pre_exec, 0x20, 16);
                    crate::boot_trace_tis_attempt_result("fail", attempt.name, fw_status, syndrome);
                    if cfg!(feature = "debug_mlx5_cmd") || attempt_idx + 1 == attempt_count {
                        log::warn!(
                            target: "mlx5",
                            "CREATE_TIS attempt {}/{} {} failed: err={:?} fw_status={:#x} syndrome={:#x}",
                            attempt_idx + 1,
                            attempt_count,
                            attempt.name,
                            err,
                            fw_status,
                            syndrome
                        );
                    } else {
                        log::debug!(
                            target: "mlx5",
                            "CREATE_TIS attempt {}/{} {} failed: err={:?} fw_status={:#x} syndrome={:#x}",
                            attempt_idx + 1,
                            attempt_count,
                            attempt.name,
                            err,
                            fw_status,
                            syndrome
                        );
                    }
                    crate::boot_trace("[MLX5_TIS] create fail\n");
                    last_err = Err(err);
                }
            }
        }

        if !self.is_vf() {
            match self.create_underlay_qp(params.port.max(1)) {
                Ok(qpn) => {
                    let underlay_attempt = CreateTisAttempt {
                        name: "real-underlay-qp",
                        td: params.td,
                        prio: params.prio,
                        include_pd: false,
                        underlay_qpn: qpn,
                        op_mod: 0,
                        lag_port: 0,
                        strict_lag: false,
                    };
                    let pre_exec =
                        Self::prepare_create_tis_attempt(in_mbox, params, underlay_attempt);
                    log::warn!(
                        target: "mlx5",
                        "CREATE_TIS final probe with real underlay QP: td={} pd={} port={} prio={} underlay_qpn={:#x}",
                        params.td,
                        params.pd,
                        params.port,
                        params.prio,
                        qpn
                    );
                    crate::boot_trace_tis_attempt(
                        "try",
                        underlay_attempt.name,
                        underlay_attempt.td,
                        params.pd,
                        underlay_attempt.include_pd,
                        params.port,
                        underlay_attempt.prio,
                        underlay_attempt.underlay_qpn,
                        underlay_attempt.op_mod,
                        underlay_attempt.lag_port,
                        underlay_attempt.strict_lag,
                    );
                    crate::boot_trace_mailbox_range("tisc_try_hdr", &pre_exec, 0x00, 8);
                    crate::boot_trace_mailbox_range("tisc_try_ctx", &pre_exec, 0x20, 16);
                    match self.execute_uid_sensitive_cmd(CmdOpcode::CreateTis, 0x110, 0x10) {
                        Ok(()) => {
                            crate::boot_trace_mailbox_range(
                                "tisc_pre_underlay",
                                &pre_exec,
                                0x20,
                                16,
                            );
                            let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                            let tisn = crate::cmd::res::parse_create_tis_output(out_mbox);
                            self.underlay_qpn = qpn;
                            self.record_tis_info(tisn, params.port, TisOwnership::DriverCreated);
                            crate::boot_trace("[MLX5_TIS] create ok\n");
                            return Ok(tisn);
                        }
                        Err(err) => {
                            let (fw_status, syndrome) = self.last_cmd_status_and_syndrome();
                            crate::boot_trace_mailbox_range(
                                "tisc_pre_underlay_fail",
                                &pre_exec,
                                0x20,
                                16,
                            );
                            crate::boot_trace_tis_attempt_result(
                                "fail",
                                underlay_attempt.name,
                                fw_status,
                                syndrome,
                            );
                            log::warn!(
                                target: "mlx5",
                                "CREATE_TIS with real underlay QP {:#x} failed: err={:?} fw_status={:#x} syndrome={:#x}",
                                qpn,
                                err,
                                fw_status,
                                syndrome
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
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

        // Driver-reported version string: "<os>,mlx5_core,<major>.<minor>.<patch>".
        let version = b"RanyOS,mlx5_core,0.1.0";
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
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
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
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
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

    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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

    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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

    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
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

#[cfg(test)]
mod tests {
    use super::Mlx5Device;
    use crate::cmd::res::QueryTisInfo;

    #[test]
    fn tis_reuse_profile_requires_exact_td_and_no_underlay() {
        let mut info = QueryTisInfo {
            strict_lag_tx_port_affinity: false,
            tls_en: false,
            lag_tx_port_affinity: 0,
            prio: 0,
            transport_domain: 1,
            underlay_qpn: 0,
            pd: 17,
        };

        assert!(Mlx5Device::tis_matches_reuse_profile(&info, 1, 0));

        info.transport_domain = 0;
        assert!(!Mlx5Device::tis_matches_reuse_profile(&info, 1, 0));

        info.transport_domain = 1;
        info.underlay_qpn = 1;
        assert!(!Mlx5Device::tis_matches_reuse_profile(&info, 1, 0));
    }
}
