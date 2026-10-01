// ============================================================================
// drivers/mlx5/src/device/queues.rs - MLX5 Queue Management
// ============================================================================

extern crate alloc;
// unused import Vec removed
use crate::cmd::CmdMailbox;
use crate::cmd::queues::*; // bring in helper builders/parsers
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, MLX5_RX_WQE_MAX_SUPPORTED_SIZE, WqState};
use crate::device::Mlx5Device;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::RqTable;
use crate::wq::{ReceiveQueue, ResolvedRqLayout, SendQueue};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RqProfileAttempt {
    name: &'static str,
    flush_in_error_en: bool,
    wq_type: u8,
    end_padding_mode: u8,
    log_wq_stride: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RqExpectations {
    cqn: u32,
    log_rq_size: u8,
    pd: u32,
    dbr_addr: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QueueBacking {
    buf_virt: u64,
    buf_device: u64,
    db_virt: u64,
    db_device: u64,
}

const DIRECT_RQ_PROFILE_ATTEMPTS: [RqProfileAttempt; 3] = [
    RqProfileAttempt {
        name: "cyclic/64",
        flush_in_error_en: true,
        wq_type: 1,
        end_padding_mode: 1,
        log_wq_stride: 6,
    },
    RqProfileAttempt {
        name: "cyclic/16",
        flush_in_error_en: true,
        wq_type: 1,
        end_padding_mode: 1,
        log_wq_stride: 4,
    },
    RqProfileAttempt {
        name: "linked/64",
        flush_in_error_en: true,
        wq_type: 0,
        end_padding_mode: 0,
        log_wq_stride: 6,
    },
];

const RMP_RQ_PROFILE_ATTEMPTS: [RqProfileAttempt; 3] = [
    RqProfileAttempt {
        name: "rmp/cyclic/16",
        flush_in_error_en: true,
        wq_type: 1,
        end_padding_mode: 1,
        log_wq_stride: 4,
    },
    RqProfileAttempt {
        name: "rmp/cyclic/64",
        flush_in_error_en: true,
        wq_type: 1,
        end_padding_mode: 1,
        log_wq_stride: 6,
    },
    RqProfileAttempt {
        name: "rmp/linked/64",
        flush_in_error_en: true,
        wq_type: 0,
        end_padding_mode: 0,
        log_wq_stride: 6,
    },
];

fn resolve_direct_rq_layout(
    rqn: u32,
    expected: RqExpectations,
    ctx: QueryRqInfo,
) -> Result<ResolvedRqLayout, &'static str> {
    let rmpn = (ctx.rmpn != 0).then_some(ctx.rmpn);
    if ctx.state != WqState::Ready as u8 {
        return Err("QUERY_RQ returned an unexpected state");
    }
    if ctx.mem_rq_type != 0 {
        return Err("mem_rq_type=1 requires RMP handling and is not supported");
    }
    if ctx.cqn != expected.cqn {
        return Err("QUERY_RQ returned an unexpected CQN");
    }
    if ctx.log_wq_sz != expected.log_rq_size {
        return Err("QUERY_RQ returned an unexpected queue depth");
    }
    if ctx.pd != expected.pd {
        return Err("QUERY_RQ returned an unexpected PD");
    }
    if ctx.dbr_addr != expected.dbr_addr {
        return Err("QUERY_RQ returned an unexpected doorbell address");
    }

    match (ctx.wq_type, ctx.log_wq_stride) {
        (1, 4) => Ok(ResolvedRqLayout::cyclic(
            rqn,
            expected.cqn,
            crate::defs::WQEBB_SIZE,
            ctx.mem_rq_type,
            ctx.wq_type,
            ctx.log_wq_stride,
            ctx.end_padding_mode,
            ctx.log_wq_sz,
            rmpn,
        )),
        (1, 6) => Ok(ResolvedRqLayout::cyclic(
            rqn,
            expected.cqn,
            64,
            ctx.mem_rq_type,
            ctx.wq_type,
            ctx.log_wq_stride,
            ctx.end_padding_mode,
            ctx.log_wq_sz,
            rmpn,
        )),
        (0, 6) => Ok(ResolvedRqLayout::linked(
            rqn,
            expected.cqn,
            64,
            ctx.mem_rq_type,
            ctx.wq_type,
            ctx.log_wq_stride,
            ctx.end_padding_mode,
            ctx.log_wq_sz,
            rmpn,
        )),
        (0, 4) => Err("linked RQ requires a 64B stride"),
        (0, _) | (1, _) => Err("unsupported RQ stride"),
        _ => Err("unsupported wq_type"),
    }
}

fn resolve_rmp_backed_rq_layout(
    rqn: u32,
    expected: RqExpectations,
    expected_rmpn: u32,
    ctx: QueryRqInfo,
) -> Result<ResolvedRqLayout, &'static str> {
    let rmpn = (ctx.rmpn != 0).then_some(ctx.rmpn);
    if ctx.state != WqState::Ready as u8 {
        return Err("QUERY_RQ returned an unexpected state");
    }
    if ctx.mem_rq_type != 1 {
        return Err("QUERY_RQ did not switch to mem_rq_type=1");
    }
    if ctx.cqn != expected.cqn {
        return Err("QUERY_RQ returned an unexpected CQN");
    }
    if ctx.log_wq_sz != expected.log_rq_size {
        return Err("QUERY_RQ returned an unexpected queue depth");
    }
    if ctx.pd != expected.pd {
        return Err("QUERY_RQ returned an unexpected PD");
    }
    if ctx.dbr_addr != expected.dbr_addr {
        return Err("QUERY_RQ returned an unexpected doorbell address");
    }
    if ctx.rmpn != expected_rmpn {
        return Err("QUERY_RQ returned an unexpected RMP number");
    }

    match (ctx.wq_type, ctx.log_wq_stride) {
        (1, 4) | (1, 6) => Ok(ResolvedRqLayout::cyclic(
            rqn,
            expected.cqn,
            MLX5_RX_WQE_MAX_SUPPORTED_SIZE,
            ctx.mem_rq_type,
            ctx.wq_type,
            ctx.log_wq_stride,
            ctx.end_padding_mode,
            ctx.log_wq_sz,
            rmpn,
        )),
        (0, 4) | (0, 6) => Ok(ResolvedRqLayout::linked(
            rqn,
            expected.cqn,
            MLX5_RX_WQE_MAX_SUPPORTED_SIZE,
            ctx.mem_rq_type,
            ctx.wq_type,
            ctx.log_wq_stride,
            ctx.end_padding_mode,
            ctx.log_wq_sz,
            rmpn,
        )),
        (0, _) | (1, _) => Err("unsupported RMP-backed RQ stride"),
        _ => Err("unsupported wq_type"),
    }
}

impl Mlx5Device {
    /// CQモデレーション（割り込み抑制）を設定
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn modify_cq_moderation(
        &mut self,
        cqn: u32,
        period_usec: u16,
        count: u16,
    ) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_modify_cq_moderation_input(in_mbox, cqn, period_usec, count);

        self.execute_uid_sensitive_cmd(
            CmdOpcode::ModifyCq,
            in_mbox,
            0x40, // input length
            0x10, // output length
        )?;
        Ok(())
    }

    /// Send Queueを作成
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub unsafe fn create_sq_hw(
        &mut self,
        sq_buf_virt: u64,
        sq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_sq_size: u8,
        cqn: u32,
        tisn: u32,
    ) -> Mlx5Result<u32> {
        let uar = self.uar.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let uar_page = uar.number();
        if log_sq_size >= 30 {
            return Err(Mlx5Error::InvalidParameter);
        }
        let doorbell = uar.sq()?;
        let storage = crate::wq::SendQueueStorage::new(log_sq_size)?;
        self.sqs
            .try_reserve(1)
            .map_err(|_| Mlx5Error::NoResources)?;
        self.tx_cq_by_sq
            .try_reserve(1)
            .map_err(|_| Mlx5Error::NoResources)?;
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidParameter)?;
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let sq_db_ptr = db_virt as *mut u32;
        core::ptr::write_volatile(sq_db_ptr, 0u32.to_be());
        core::ptr::write_volatile(sq_db_ptr.add(1), 0u32.to_be());
        let sq_bytes = (1usize << (log_sq_size as usize)) * 64usize;
        let sq_pages = (sq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let sq_in_len = (0x110 + sq_pages * 8) as u32;
        let min_inline_mode = self
            .ports
            .first()
            .map(|port| port.min_wqe_inline_mode())
            .unwrap_or(0);
        let sq_program_min_inline_mode = self
            .hca_caps()
            .map(|caps| caps.wqe_inline_mode == 1)
            .unwrap_or(false);
        // Program the SQ timestamp format from the SQ cap, preferring
        // real-time when supported and otherwise leaving free-running (0).
        let sq_ts_format = self
            .hca_caps()
            .map(|caps| if caps.sq_ts_format != 0 { 1 } else { 0 })
            .unwrap_or(0);
        let fallback_tis0 = tisn == 0 && self.tis_list.iter().all(|t| t.tisn != 0);
        let attempts: &[(&str, bool)] = if fallback_tis0 {
            &[("explicit-tis0", false), ("implicit-tis0", true)]
        } else {
            &[("normal", false)]
        };
        for (idx, (mode, implicit_tis)) in attempts.iter().enumerate() {
            build_create_sq_input(
                in_mbox,
                log_sq_size,
                sq_buf_pa,
                db_pa,
                cqn,
                self.pd,
                uar_page,
                tisn,
                if sq_program_min_inline_mode {
                    min_inline_mode
                } else {
                    0
                },
                false,
                sq_ts_format,
            );
            if *implicit_tis {
                let mut layout =
                    crate::structs::queues::SqContextLayout::new(&mut in_mbox.data[0x20..]);
                layout.set_tis_lst_sz(0);
                layout.set_tis_num_0(0);
            }
            let mut pre_exec = CmdMailbox::zeroed();
            pre_exec.data[..sq_in_len as usize]
                .copy_from_slice(&in_mbox.data[..sq_in_len as usize]);
            match self.execute_uid_sensitive_cmd(CmdOpcode::CreateSq, in_mbox, sq_in_len, 0x10) {
                Ok(()) => {
                    if fallback_tis0 {
                        log::warn!(
                            target: "mlx5",
                            "CREATE_SQ accepted with {} fallback on {} (tisn={})",
                            mode,
                            if self.is_vf() { "VF" } else { "PF" },
                            tisn
                        );
                    }
                    if cfg!(feature = "debug_mlx5_cmd") {
                        log::info!(
                            target: "mlx5",
                            "CREATE_SQ accepted: mode={} implicit_tis={} tisn={} min_inline_mode={}",
                            mode,
                            implicit_tis,
                            tisn,
                            min_inline_mode
                        );
                    }
                    Self::debug_dump_mailbox_range("CREATE_SQ ctx(pre)", &pre_exec, 0x20, 64);
                    Self::debug_dump_mailbox_range(
                        "CREATE_SQ pas(pre)",
                        &pre_exec,
                        0x110,
                        sq_pages.saturating_mul(2),
                    );
                    crate::boot_trace_mailbox_range("sqc_pre", &pre_exec, 0x20, 64);
                    crate::boot_trace_mailbox_range(
                        "sq_pas_pre",
                        &pre_exec,
                        0x110,
                        sq_pages.saturating_mul(2),
                    );
                    break;
                }
                Err(err) => {
                    if fallback_tis0 {
                        crate::boot_trace_mailbox_range("sqc_pre_fail", &pre_exec, 0x20, 64);
                    }
                    if fallback_tis0 {
                        log::warn!(
                            target: "mlx5",
                            "CREATE_SQ failed with {} fallback (tisn={}): {:?}",
                            mode,
                            tisn,
                            err
                        );
                    }
                    if idx + 1 == attempts.len() {
                        return Err(err);
                    }
                }
            }
        }
        let out_mbox = &*self.cmd_output;
        let sqn = parse_create_sq_output(out_mbox);
        if let Err(err) = self.transition_sq_to_ready(sqn) {
            if self.is_vf() {
                log::warn!(
                    target: "mlx5",
                    "MODIFY_SQ to Ready failed on VF for sqn={:#x}; continuing to inspect/query SQ state: {:?}",
                    sqn,
                    err
                );
                crate::boot_trace("[MLX5_SQ] modify_sq failed on VF; continue\n");
            } else {
                return Err(err);
            }
        }
        let mut effective_tisn = tisn;
        match self.query_sq_hw(sqn) {
            Ok(ctx) => {
                let out_mbox = &*self.cmd_output;
                Self::debug_dump_mailbox_range("QUERY_SQ sq_context", out_mbox, 0x20, 64);
                crate::boot_trace_mailbox_range("sqc_out", out_mbox, 0x20, 64);
                if ctx.tis_num_0 != 0 {
                    effective_tisn = ctx.tis_num_0;
                }
                crate::boot_trace_sq_state(
                    sqn,
                    ctx.min_wqe_inline_mode,
                    ctx.tis_lst_sz,
                    ctx.tis_num_0,
                    ctx.wq_type,
                    effective_tisn,
                );
                if self.is_vf() {
                    log::warn!(
                        target: "mlx5",
                        "VF QUERY_SQ: sqn={:#x} state={} min_inline={} tis_lst_sz={} tis_num_0={:#x} wq_type={} cqn={:#x} pd={} dbr_addr={:#x}",
                        sqn,
                        ctx.state,
                        ctx.min_wqe_inline_mode,
                        ctx.tis_lst_sz,
                        ctx.tis_num_0,
                        ctx.wq_type,
                        ctx.cqn,
                        ctx.pd,
                        ctx.dbr_addr
                    );
                }
                if cfg!(feature = "debug_mlx5_cmd") {
                    log::info!(
                        target: "mlx5",
                        "QUERY_SQ: sqn={:#x} state={} flush={} min_inline={} cqn={:#x} tis_lst_sz={} tis_num_0={:#x} wq_type={} pd={} uar_page={} dbr_addr={:#x} log_stride={} log_pg_sz={} log_sz={}",
                        sqn,
                        ctx.state,
                        ctx.flush_in_error_en,
                        ctx.min_wqe_inline_mode,
                        ctx.cqn,
                        ctx.tis_lst_sz,
                        ctx.tis_num_0,
                        ctx.wq_type,
                        ctx.pd,
                        ctx.uar_page,
                        ctx.dbr_addr,
                        ctx.log_wq_stride,
                        ctx.log_wq_pg_sz,
                        ctx.log_wq_sz
                    );
                }
            }
            Err(err) => {
                log::warn!(target: "mlx5", "QUERY_SQ failed for sqn={:#x}: {:?}", sqn, err);
            }
        }
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        let sq = SendQueue::from_created_queue(
            sqn,
            sq_buf_virt,
            db_virt,
            doorbell,
            storage,
            effective_tisn,
            cqn,
            self.tx_mkey,
            csum_offload,
        );
        self.sqs.push(sq);
        self.tx_cq_by_sq.push(cq_index);
        Ok(sqn)
    }

    /// Receive Queueを作成
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub unsafe fn create_rq_hw(
        &mut self,
        rq_buf_virt: u64,
        rq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        rmp_buf_virt: u64,
        rmp_buf_pa: u64,
        rmp_db_virt: u64,
        rmp_db_pa: u64,
        log_rq_size: u8,
        cqn: u32,
        _tirn: u32,
        scatter_fcs: bool,
        vlan_strip: bool,
    ) -> Mlx5Result<u32> {
        let uar = self.uar.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let uar_page = uar.number();
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let rq_bytes = (1usize << (log_rq_size as usize)) * MLX5_RX_WQE_MAX_SUPPORTED_SIZE;
        let rq_pages = (rq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let rq_in_len = (0x110 + rq_pages * 8) as u32;
        let expected = RqExpectations {
            cqn,
            log_rq_size,
            pd: self.pd,
            dbr_addr: db_pa,
        };
        let rq_backing = QueueBacking {
            buf_virt: rq_buf_virt,
            buf_device: rq_buf_pa,
            db_virt,
            db_device: db_pa,
        };
        let rmp_backing = QueueBacking {
            buf_virt: rmp_buf_virt,
            buf_device: rmp_buf_pa,
            db_virt: rmp_db_virt,
            db_device: rmp_db_pa,
        };

        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        let mut last_rejection_reason: Option<alloc::string::String> = None;
        let mut selected: Option<(
            u32,
            ResolvedRqLayout,
            RqProfileAttempt,
            QueueBacking,
            Option<u32>,
        )> = None;
        let mut should_try_rmp_fallback = false;

        for attempt in DIRECT_RQ_PROFILE_ATTEMPTS {
            log::info!(
                target: "mlx5",
                "CREATE_RQ try: mem_rq_type=0 profile={} cqn={:#x} pd={} uar_page={} log_rq_size={} stride={} wq_type={} end_pad={} flush={}",
                attempt.name,
                cqn,
                self.pd,
                uar_page,
                log_rq_size,
                attempt.log_wq_stride,
                attempt.wq_type,
                attempt.end_padding_mode,
                attempt.flush_in_error_en
            );
            build_create_rq_input_with_options(
                in_mbox,
                log_rq_size,
                rq_buf_pa,
                db_pa,
                cqn,
                self.pd,
                uar_page,
                scatter_fcs,
                vlan_strip,
                0,
                None,
                attempt.flush_in_error_en,
                attempt.wq_type,
                attempt.end_padding_mode,
                attempt.log_wq_stride,
            );

            match self.execute_uid_sensitive_cmd(CmdOpcode::CreateRq, in_mbox, rq_in_len, 0x10) {
                Ok(()) => {
                    let out_mbox = &*self.cmd_output;
                    let rqn = parse_create_rq_output(out_mbox);
                    if let Err(err) = self.transition_rq_to_ready(rqn) {
                        if self.is_vf() {
                            crate::boot_trace("[MLX5_RQ] modify_rq failed on VF; continue\n");
                        } else {
                            let reason = alloc::format!("transition to ready failed: {:?}", err);
                            log::warn!(
                                target: "mlx5",
                                "CREATE_RQ rejected: profile={} rqn={:#x} reason={}",
                                attempt.name,
                                rqn,
                                reason
                            );
                            let _ = self.destroy_rq_hw(rqn);
                            last_rejection_reason = Some(reason);
                            last_err = Err(err);
                            continue;
                        }
                    }

                    match self.query_rq_hw(rqn) {
                        Ok(ctx) => {
                            log::info!(
                                target: "mlx5",
                                "QUERY_RQ: rqn={:#x} state={} mem_rq_type={} flush={} scatter_fcs={} vlan_strip={} cqn={:#x} rmpn={:#x} wq_type={} end_pad={} pd={} uar_page={} dbr_addr={:#x} log_stride={} log_pg_sz={} log_sz={}",
                                rqn,
                                ctx.state,
                                ctx.mem_rq_type,
                                ctx.flush_in_error_en,
                                ctx.scatter_fcs,
                                ctx.vlan_strip,
                                ctx.cqn,
                                ctx.rmpn,
                                ctx.wq_type,
                                ctx.end_padding_mode,
                                ctx.pd,
                                ctx.uar_page,
                                ctx.dbr_addr,
                                ctx.log_wq_stride,
                                ctx.log_wq_pg_sz,
                                ctx.log_wq_sz
                            );

                            if ctx.mem_rq_type != 0 {
                                let reason = alloc::format!(
                                    "firmware returned mem_rq_type={} rmpn={:#x}; switching to RMP-backed RX fallback",
                                    ctx.mem_rq_type,
                                    ctx.rmpn
                                );
                                log::warn!(
                                    target: "mlx5",
                                    "CREATE_RQ requires RMP fallback: profile={} rqn={:#x} reason={}",
                                    attempt.name,
                                    rqn,
                                    reason
                                );
                                let _ = self.destroy_rq_hw(rqn);
                                last_rejection_reason = Some(reason);
                                last_err = Err(Mlx5Error::NotSupported);
                                should_try_rmp_fallback = true;
                                break;
                            }

                            if ctx.wq_type != attempt.wq_type
                                || ctx.log_wq_stride != attempt.log_wq_stride
                            {
                                let reason = alloc::format!(
                                    "query mismatch expected(wq_type={}, stride={}) got(wq_type={}, stride={})",
                                    attempt.wq_type,
                                    attempt.log_wq_stride,
                                    ctx.wq_type,
                                    ctx.log_wq_stride
                                );
                                log::warn!(
                                    target: "mlx5",
                                    "CREATE_RQ dropped fallback: profile={} rqn={:#x} reason={}",
                                    attempt.name,
                                    rqn,
                                    reason
                                );
                                let _ = self.destroy_rq_hw(rqn);
                                last_rejection_reason = Some(reason);
                                last_err = Err(Mlx5Error::NotSupported);
                                continue;
                            }

                            match resolve_direct_rq_layout(rqn, expected, ctx) {
                                Ok(layout) => {
                                    log::info!(
                                        target: "mlx5",
                                        "CREATE_RQ accepted: profile={} rqn={:#x} cqn={:#x} pd={} uar_page={} dbr_addr={:#x} mode={} slot_size={} data_seg_offset={} next_seg={} raw_mem_rq_type={} raw_wq_type={} raw_stride={} rmpn={}",
                                        attempt.name,
                                        rqn,
                                        expected.cqn,
                                        expected.pd,
                                        ctx.uar_page,
                                        expected.dbr_addr,
                                        layout.wq_mode.label(),
                                        layout.slot_size_bytes,
                                        layout.data_seg_offset,
                                        layout.has_next_segment,
                                        layout.raw_mem_rq_type,
                                        layout.raw_wq_type,
                                        layout.raw_log_wq_stride,
                                        layout
                                            .rmpn
                                            .map(|value| alloc::format!("{:#x}", value))
                                            .unwrap_or_else(|| "none".into())
                                    );
                                    selected = Some((rqn, layout, attempt, rq_backing, None));
                                    last_err = Ok(());
                                    break;
                                }
                                Err(reason) => {
                                    log::warn!(
                                        target: "mlx5",
                                        "CREATE_RQ dropped fallback: profile={} rqn={:#x} reason={}",
                                        attempt.name,
                                        rqn,
                                        reason
                                    );
                                    let _ = self.destroy_rq_hw(rqn);
                                    last_rejection_reason = Some(reason.into());
                                    last_err = Err(Mlx5Error::NotSupported);
                                }
                            }
                        }
                        Err(err) => {
                            let reason = alloc::format!("query failed: {:?}", err);
                            log::warn!(
                                target: "mlx5",
                                "CREATE_RQ rejected: profile={} rqn={:#x} reason={}",
                                attempt.name,
                                rqn,
                                reason
                            );
                            let _ = self.destroy_rq_hw(rqn);
                            last_rejection_reason = Some(reason);
                            last_err = Err(err);
                        }
                    }
                }
                Err(err) => {
                    let reason = alloc::format!("command failed: {:?}", err);
                    log::warn!(
                        target: "mlx5",
                        "CREATE_RQ attempt failed: mem_rq_type=0 profile={} reason={}",
                        attempt.name,
                        reason
                    );
                    last_rejection_reason = Some(reason);
                    last_err = Err(err);
                }
            }
        }

        if selected.is_none() && should_try_rmp_fallback {
            match self.create_rmp_hw(rmp_buf_pa, rmp_db_pa, log_rq_size) {
                Ok(rmpn) => {
                    for attempt in RMP_RQ_PROFILE_ATTEMPTS {
                        log::info!(
                            target: "mlx5",
                            "CREATE_RQ try: mem_rq_type=1 profile={} cqn={:#x} pd={} uar_page={} log_rq_size={} stride={} wq_type={} end_pad={} flush={} rmpn={:#x}",
                            attempt.name,
                            cqn,
                            self.pd,
                            uar_page,
                            log_rq_size,
                            attempt.log_wq_stride,
                            attempt.wq_type,
                            attempt.end_padding_mode,
                            attempt.flush_in_error_en,
                            rmpn
                        );
                        build_create_rq_input_with_options(
                            in_mbox,
                            log_rq_size,
                            rq_buf_pa,
                            db_pa,
                            cqn,
                            self.pd,
                            uar_page,
                            scatter_fcs,
                            vlan_strip,
                            1,
                            Some(rmpn),
                            attempt.flush_in_error_en,
                            attempt.wq_type,
                            attempt.end_padding_mode,
                            attempt.log_wq_stride,
                        );

                        match self.execute_uid_sensitive_cmd(
                            CmdOpcode::CreateRq,
                            in_mbox,
                            rq_in_len,
                            0x10,
                        ) {
                            Ok(()) => {
                                let out_mbox = &*self.cmd_output;
                                let rqn = parse_create_rq_output(out_mbox);
                                if let Err(err) = self.transition_rq_to_ready(rqn) {
                                    if self.is_vf() {
                                        crate::boot_trace(
                                            "[MLX5_RQ] modify_rq failed on VF; continue\n",
                                        );
                                    } else {
                                        let reason =
                                            alloc::format!("transition to ready failed: {:?}", err);
                                        log::warn!(
                                            target: "mlx5",
                                            "CREATE_RQ rejected: profile={} rqn={:#x} reason={}",
                                            attempt.name,
                                            rqn,
                                            reason
                                        );
                                        let _ = self.destroy_rq_hw(rqn);
                                        last_rejection_reason = Some(reason);
                                        last_err = Err(err);
                                        continue;
                                    }
                                }

                                match self.query_rq_hw(rqn) {
                                    Ok(ctx) => {
                                        log::info!(
                                            target: "mlx5",
                                            "QUERY_RQ: rqn={:#x} state={} mem_rq_type={} flush={} scatter_fcs={} vlan_strip={} cqn={:#x} rmpn={:#x} wq_type={} end_pad={} pd={} uar_page={} dbr_addr={:#x} log_stride={} log_pg_sz={} log_sz={}",
                                            rqn,
                                            ctx.state,
                                            ctx.mem_rq_type,
                                            ctx.flush_in_error_en,
                                            ctx.scatter_fcs,
                                            ctx.vlan_strip,
                                            ctx.cqn,
                                            ctx.rmpn,
                                            ctx.wq_type,
                                            ctx.end_padding_mode,
                                            ctx.pd,
                                            ctx.uar_page,
                                            ctx.dbr_addr,
                                            ctx.log_wq_stride,
                                            ctx.log_wq_pg_sz,
                                            ctx.log_wq_sz
                                        );

                                        match resolve_rmp_backed_rq_layout(rqn, expected, rmpn, ctx)
                                        {
                                            Ok(layout) => {
                                                log::info!(
                                                    target: "mlx5",
                                                    "CREATE_RQ accepted: profile={} rqn={:#x} cqn={:#x} pd={} uar_page={} dbr_addr={:#x} mode={} slot_size={} data_seg_offset={} next_seg={} raw_mem_rq_type={} raw_wq_type={} raw_stride={} rmpn={}",
                                                    attempt.name,
                                                    rqn,
                                                    expected.cqn,
                                                    expected.pd,
                                                    ctx.uar_page,
                                                    expected.dbr_addr,
                                                    layout.wq_mode.label(),
                                                    layout.slot_size_bytes,
                                                    layout.data_seg_offset,
                                                    layout.has_next_segment,
                                                    layout.raw_mem_rq_type,
                                                    layout.raw_wq_type,
                                                    layout.raw_log_wq_stride,
                                                    layout
                                                        .rmpn
                                                        .map(|value| alloc::format!("{:#x}", value))
                                                        .unwrap_or_else(|| "none".into())
                                                );
                                                selected = Some((
                                                    rqn,
                                                    layout,
                                                    attempt,
                                                    rmp_backing,
                                                    Some(rmpn),
                                                ));
                                                last_err = Ok(());
                                                break;
                                            }
                                            Err(reason) => {
                                                log::warn!(
                                                    target: "mlx5",
                                                    "CREATE_RQ dropped fallback: profile={} rqn={:#x} reason={}",
                                                    attempt.name,
                                                    rqn,
                                                    reason
                                                );
                                                let _ = self.destroy_rq_hw(rqn);
                                                last_rejection_reason = Some(reason.into());
                                                last_err = Err(Mlx5Error::NotSupported);
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        let reason = alloc::format!("query failed: {:?}", err);
                                        log::warn!(
                                            target: "mlx5",
                                            "CREATE_RQ rejected: profile={} rqn={:#x} reason={}",
                                            attempt.name,
                                            rqn,
                                            reason
                                        );
                                        let _ = self.destroy_rq_hw(rqn);
                                        last_rejection_reason = Some(reason);
                                        last_err = Err(err);
                                    }
                                }
                            }
                            Err(err) => {
                                let reason = alloc::format!("command failed: {:?}", err);
                                log::warn!(
                                    target: "mlx5",
                                    "CREATE_RQ attempt failed: mem_rq_type=1 profile={} reason={}",
                                    attempt.name,
                                    reason
                                );
                                last_rejection_reason = Some(reason);
                                last_err = Err(err);
                            }
                        }
                    }

                    if selected.is_none() {
                        let _ = self.destroy_rmp_hw(rmpn);
                    }
                }
                Err(err) => {
                    let reason = alloc::format!("CREATE_RMP failed: {:?}", err);
                    log::warn!(target: "mlx5", "{}", reason);
                    last_rejection_reason = Some(reason);
                    last_err = Err(err);
                }
            }
        }

        let (rqn, layout, _attempt, backing, created_rmpn) = if let Some(selected) = selected {
            selected
        } else {
            if let Some(reason) = last_rejection_reason.as_deref() {
                log::error!(
                    target: "mlx5",
                    "CREATE_RQ failed after probing all RX profiles: last_reason={}",
                    reason
                );
            }
            last_err?;
            return Err(Mlx5Error::NotSupported);
        };
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        crate::boot_trace("[MLX5_RQ] build rq object\n");
        let rq = ReceiveQueue::new(
            rqn,
            backing.buf_virt,
            backing.buf_device,
            backing.db_virt,
            log_rq_size,
            cqn,
            layout,
            self.mkey,
            csum_offload,
        );
        crate::boot_trace("[MLX5_RQ] rq object ready\n");
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidResponse)?;
        if let Some(rmpn) = created_rmpn {
            self.rmp_list.push(rmpn);
        }
        self.rqs.push(rq);
        self.rx_cq_by_rq.push(cq_index);
        crate::boot_trace("[MLX5_RQ] done\n");
        Ok(rqn)
    }

    unsafe fn create_rmp_hw(
        &mut self,
        rmp_buf_pa: u64,
        db_pa: u64,
        log_rmp_size: u8,
    ) -> Mlx5Result<u32> {
        let uar = self.uar.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let uar_page = uar.number();
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let rmp_bytes = (1usize << (log_rmp_size as usize)) * MLX5_RX_WQE_MAX_SUPPORTED_SIZE;
        let rmp_pages = (rmp_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let rmp_in_len = (0x110 + rmp_pages * 8) as u32;
        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);

        // VF firmware revisions differ on acceptable RMPC fields.
        // Probe a minimal compatibility set to find an accepted tuple.
        let attempts = [
            ("rst+basic+cyclic+align", 0u8, true, 1u8, 1u8),
            ("rst+basic+cyclic+nopad", 0u8, true, 1u8, 0u8),
            ("rst+basic+linked+align", 0u8, true, 0u8, 1u8),
            ("rst+basic+linked+nopad", 0u8, true, 0u8, 0u8),
            ("rst+nobasic+cyclic+align", 0u8, false, 1u8, 1u8),
            ("rst+nobasic+linked+nopad", 0u8, false, 0u8, 0u8),
            ("rdy+basic+cyclic+align", 1u8, true, 1u8, 1u8),
        ];
        for (name, state, basic_cyclic, wq_type, end_padding_mode) in attempts {
            build_create_rmp_input_with_options(
                in_mbox,
                log_rmp_size,
                rmp_buf_pa,
                db_pa,
                self.pd,
                uar_page,
                state,
                basic_cyclic,
                wq_type,
                end_padding_mode,
            );
            match self.execute_uid_sensitive_cmd(CmdOpcode::CreateRmp, in_mbox, rmp_in_len, 0x10) {
                Ok(()) => {
                    let out_mbox = &*self.cmd_output;
                    let rmpn = parse_create_rmp_output(out_mbox);
                    self.transition_rmp_to_ready(rmpn)?;
                    log::info!(
                        target: "mlx5",
                        "CREATE_RMP accepted with {} (state={} basic={} wq_type={} end_pad={})",
                        name,
                        state,
                        basic_cyclic,
                        wq_type,
                        end_padding_mode
                    );
                    return Ok(rmpn);
                }
                Err(err) => {
                    last_err = Err(err);
                }
            }
        }
        last_err
    }

    /// RQTを作成
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub unsafe fn create_rqt(&mut self, rq_numbers: &[u32], log_rqt_size: u8) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        crate::cmd::flow::build_create_rqt_input(in_mbox, rq_numbers, log_rqt_size);

        self.execute_uid_sensitive_cmd(
            CmdOpcode::CreateRqt,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*self.cmd_output;
        let rqtn = crate::cmd::flow::parse_create_rqt_output(out_mbox);
        self.rq_tables.push(RqTable {
            rqtn,
            rq_list: rq_numbers.to_vec(),
            log_rqt_size,
        });
        Ok(rqtn)
    }

    unsafe fn query_sq_hw(&mut self, sqn: u32) -> Mlx5Result<QuerySqInfo> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_query_sq_input(in_mbox, sqn);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QuerySq,
            in_mbox,
            0x10,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*self.cmd_output;
        Ok(parse_query_sq_output(out_mbox))
    }

    pub(crate) unsafe fn find_existing_sq_tis_candidate(
        &mut self,
        max_scan: u32,
    ) -> Mlx5Result<u32> {
        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        let mut first_any = None;
        let scan_windows = Self::object_id_scan_windows(max_scan);

        for &(base, count) in &scan_windows {
            for offset in 0..count {
                let sqn = (base + offset) & 0x00ff_ffff;
                match self.query_sq_hw(sqn) {
                    Ok(ctx) => {
                        let candidate = ctx.tis_lst_sz != 0 && ctx.tis_num_0 != 0;
                        if candidate && first_any.is_none() {
                            first_any = Some((sqn, ctx));
                        }
                        if candidate && ctx.pd == self.pd && ctx.wq_type == 1 {
                            log::warn!(
                                target: "mlx5",
                                "Found matching PF SQ-derived TIS candidate: sqn={:#x} tisn={:#x} pd={} cqn={:#x} state={} tis_lst_sz={}",
                                sqn,
                                ctx.tis_num_0,
                                ctx.pd,
                                ctx.cqn,
                                ctx.state,
                                ctx.tis_lst_sz
                            );
                            return Ok(ctx.tis_num_0);
                        }
                    }
                    Err(err) => last_err = Err(err),
                }
            }
        }

        if let Some((sqn, ctx)) = first_any {
            log::warn!(
                target: "mlx5",
                "Falling back to first PF SQ-derived TIS candidate: sqn={:#x} tisn={:#x} pd={} cqn={:#x} state={} tis_lst_sz={}",
                sqn,
                ctx.tis_num_0,
                ctx.pd,
                ctx.cqn,
                ctx.state,
                ctx.tis_lst_sz
            );
            return Ok(ctx.tis_num_0);
        }

        last_err
    }

    unsafe fn query_rq_hw(&mut self, rqn: u32) -> Mlx5Result<QueryRqInfo> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_query_rq_input(in_mbox, rqn);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryRq,
            in_mbox,
            0x10,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*self.cmd_output;
        Ok(parse_query_rq_output(out_mbox))
    }

    unsafe fn transition_sq_to_ready(&mut self, sqn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        let mut tried = [false; 16];
        for current_state in [WqState::Reset as u8, WqState::Ready as u8] {
            tried[current_state as usize] = true;
            build_modify_sq_input(in_mbox, sqn, current_state, WqState::Ready as u8);
            match self.execute_uid_sensitive_cmd(CmdOpcode::ModifySq, in_mbox, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Err(err),
            }
        }

        if let Ok(ctx) = self.query_sq_hw(sqn) {
            let current_state = ctx.state & 0x0f;
            if usize::from(current_state) < tried.len() && !tried[current_state as usize] {
                build_modify_sq_input(in_mbox, sqn, current_state, WqState::Ready as u8);
                match self.execute_uid_sensitive_cmd(CmdOpcode::ModifySq, in_mbox, 0x110, 0x10) {
                    Ok(()) => return Ok(()),
                    Err(err) => last_err = Err(err),
                }
            }
        }

        last_err
    }

    unsafe fn transition_rq_to_ready(&mut self, rqn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for current_state in [WqState::Reset as u8, WqState::Ready as u8] {
            build_modify_rq_input(in_mbox, rqn, current_state, WqState::Ready as u8);
            match self.execute_uid_sensitive_cmd(CmdOpcode::ModifyRq, in_mbox, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Err(err),
            }
        }
        last_err
    }

    unsafe fn transition_rmp_to_ready(&mut self, rmpn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for current_state in [WqState::Reset as u8, WqState::Ready as u8] {
            build_modify_rmp_input(in_mbox, rmpn, current_state, WqState::Ready as u8);
            match self.execute_uid_sensitive_cmd(CmdOpcode::ModifyRmp, in_mbox, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Err(err),
            }
        }
        last_err
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wq::RxWqMode;

    fn expected_rq() -> RqExpectations {
        RqExpectations {
            cqn: 0x55,
            log_rq_size: 8,
            pd: 0x77,
            dbr_addr: 0x1000,
        }
    }

    fn query_rq_info(mem_rq_type: u8, wq_type: u8, log_wq_stride: u8) -> QueryRqInfo {
        QueryRqInfo {
            state: WqState::Ready as u8,
            mem_rq_type,
            flush_in_error_en: true,
            scatter_fcs: false,
            vlan_strip: false,
            cqn: 0x55,
            rmpn: 0,
            wq_type,
            end_padding_mode: 0,
            pd: 0x77,
            uar_page: 0x88,
            dbr_addr: 0x1000,
            log_wq_stride,
            log_wq_pg_sz: 0,
            log_wq_sz: 8,
        }
    }

    #[test]
    fn resolve_direct_rq_layout_accepts_linked_64b() {
        let layout = resolve_direct_rq_layout(0x44, expected_rq(), query_rq_info(0, 0, 6)).unwrap();
        assert_eq!(layout.wq_mode, RxWqMode::LinkedList);
        assert_eq!(layout.slot_size_bytes, 64);
        assert_eq!(layout.data_seg_offset, 16);
        assert!(layout.has_next_segment);
    }

    #[test]
    fn resolve_direct_rq_layout_rejects_mem_rq_type_one() {
        let err =
            resolve_direct_rq_layout(0x44, expected_rq(), query_rq_info(1, 1, 4)).unwrap_err();
        assert_eq!(
            err,
            "mem_rq_type=1 requires RMP handling and is not supported"
        );
    }

    #[test]
    fn resolve_direct_rq_layout_rejects_linked_16b() {
        let err =
            resolve_direct_rq_layout(0x44, expected_rq(), query_rq_info(0, 0, 4)).unwrap_err();
        assert_eq!(err, "linked RQ requires a 64B stride");
    }

    #[test]
    fn resolve_direct_rq_layout_rejects_pd_mismatch() {
        let mut ctx = query_rq_info(0, 1, 4);
        ctx.pd = 0x66;
        let err = resolve_direct_rq_layout(0x44, expected_rq(), ctx).unwrap_err();
        assert_eq!(err, "QUERY_RQ returned an unexpected PD");
    }

    #[test]
    fn resolve_direct_rq_layout_ignores_uar_page_mismatch() {
        let mut ctx = query_rq_info(0, 1, 4);
        ctx.uar_page = 0x99;
        let layout = resolve_direct_rq_layout(0x44, expected_rq(), ctx).unwrap();
        assert_eq!(layout.wq_mode, RxWqMode::Cyclic);
        assert_eq!(layout.slot_size_bytes, crate::defs::WQEBB_SIZE);
    }

    #[test]
    fn resolve_direct_rq_layout_rejects_doorbell_mismatch() {
        let mut ctx = query_rq_info(0, 1, 4);
        ctx.dbr_addr = 0x2000;
        let err = resolve_direct_rq_layout(0x44, expected_rq(), ctx).unwrap_err();
        assert_eq!(err, "QUERY_RQ returned an unexpected doorbell address");
    }

    #[test]
    fn resolve_rmp_backed_rq_layout_accepts_cyclic_mem_rq_type_one() {
        let mut ctx = query_rq_info(1, 1, 4);
        ctx.rmpn = 0x88;
        let layout = resolve_rmp_backed_rq_layout(0x44, expected_rq(), 0x88, ctx).unwrap();
        assert_eq!(layout.wq_mode, RxWqMode::Cyclic);
        assert_eq!(layout.slot_size_bytes, MLX5_RX_WQE_MAX_SUPPORTED_SIZE);
        assert_eq!(layout.rmpn, Some(0x88));
    }

    #[test]
    fn resolve_rmp_backed_rq_layout_rejects_unexpected_rmp_number() {
        let mut ctx = query_rq_info(1, 1, 4);
        ctx.rmpn = 0x99;
        let err = resolve_rmp_backed_rq_layout(0x44, expected_rq(), 0x88, ctx).unwrap_err();
        assert_eq!(err, "QUERY_RQ returned an unexpected RMP number");
    }
}
