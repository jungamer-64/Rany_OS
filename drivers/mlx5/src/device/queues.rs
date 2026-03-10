// ============================================================================
// drivers/mlx5/src/device/queues.rs - MLX5 Queue Management
// ============================================================================

extern crate alloc;
// unused import Vec removed
use crate::cmd::CmdMailbox;
use crate::cmd::CommandTransport;
use crate::cmd::queues::*; // bring in helper builders/parsers
use crate::cq::CompletionQueue;
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, WqState};
use crate::device::Mlx5Device;
use crate::eq::EventQueue;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::RqTable;
use crate::wq::{ReceiveQueue, SendQueue};

impl Mlx5Device {
    /// Event Queueを作成
    pub unsafe fn create_eq_hw(
        &mut self,
        eq_buf_virt: u64,
        eq_buf_pa: u64,
        log_eq_size: u8,
        msix_vector: u32,
        event_bitmask: u64,
    ) -> Mlx5Result<u32> {
        // VF 特有の MSI-X / EQ 数上限チェック
        if let Some(caps) = self.hca_caps.as_ref() {
            if msix_vector >= caps.max_eq {
                log::error!(target: "mlx5", "Requested MSI-X vector {} exceeds hardware max_eq {}", msix_vector, caps.max_eq);
                return Err(Mlx5Error::NoResources);
            }
            if self.eqs.len() >= caps.max_eq as usize {
                log::error!(target: "mlx5", "Maximum EQ count reached ({})", caps.max_eq);
                return Err(Mlx5Error::NoResources);
            }
        }

        let eq_depth = 1u32 << log_eq_size;
        let eq_ptr = eq_buf_virt as *mut u8;
        core::ptr::write_bytes(eq_ptr, 0, (eq_depth as usize) * crate::regs::eqe::EQE_SIZE);
        for i in 0..eq_depth {
            let offset = (i as usize * crate::regs::eqe::EQE_SIZE) + crate::regs::eqe::STATUS_OWN;
            core::ptr::write_volatile(eq_ptr.add(offset), 0x01);
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_eq_input(
            in_mbox,
            log_eq_size,
            eq_buf_pa,
            self.uar_page,
            msix_vector,
            event_bitmask,
        );

        let eq_bytes = (1usize << (log_eq_size as usize)) * crate::regs::eqe::EQE_SIZE;
        let eq_pages = (eq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let eq_in_len = (0x110 + eq_pages * 8) as u32;

        if let Err(err) = self.execute_uid_sensitive_cmd(CmdOpcode::CreateEq, eq_in_len, 0x10) {
            log::info!(
                target: "mlx5",
                "CREATE_EQ input: log_eq_size={} eq_buf_pa={:#x} uar_page={} msix_vector={} event_mask={:#x} in_len={:#x}",
                log_eq_size,
                eq_buf_pa,
                self.uar_page,
                msix_vector,
                event_bitmask,
                eq_in_len
            );
            Self::debug_dump_mailbox_words("CREATE_EQ in", in_mbox, 32);
            return Err(err);
        }

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let eqn = parse_create_eq_output(out_mbox);
        log::info!(
            target: "mlx5",
            "CREATE_EQ output: status={:#x} syndrome={:#x} eqn8={} eqn24@0x05={} eqn24@0x09={} dw0={:#010x} dw1={:#010x} dw2={:#010x} dw3={:#010x}",
            out_mbox.data[0],
            out_mbox.read_be32(0x04),
            out_mbox.data[0x0B] as u32,
            out_mbox.read_be24(0x05),
            out_mbox.read_be24(0x09),
            out_mbox.read_be32(0x00),
            out_mbox.read_be32(0x04),
            out_mbox.read_be32(0x08),
            out_mbox.read_be32(0x0C),
        );
        let eq = EventQueue::new(
            eqn,
            eq_buf_virt,
            eq_buf_pa,
            self.uar_base,
            log_eq_size,
            msix_vector,
        );
        self.eqs.push(eq);
        Ok(eqn)
    }

    /// Completion Queueを作成
    pub unsafe fn create_cq_hw(
        &mut self,
        cq_buf_virt: u64,
        cq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_cq_size: u8,
        eqn: u32,
    ) -> Mlx5Result<u32> {
        let cq_depth = 1u32 << log_cq_size;
        let cq_ptr = cq_buf_virt as *mut u8;
        core::ptr::write_bytes(cq_ptr, 0, (cq_depth as usize) * crate::regs::cqe::SIZE);
        for i in 0..cq_depth {
            let offset = (i as usize * crate::regs::cqe::SIZE) + crate::regs::cqe::OP_OWN;
            core::ptr::write_volatile(cq_ptr.add(offset), 0x01);
        }
        let cq_db_ptr = db_virt as *mut u32;
        core::ptr::write_volatile(cq_db_ptr, 0u32.to_be());
        // Linux initializes arm_db with MLX5_CQ_INIT_CMD_SN = cpu_to_be32(2 << 28).
        core::ptr::write_volatile(cq_db_ptr.add(1), (2u32 << 28).to_be());

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        // Keep CQE compression disabled in the generic CREATE_CQ path.
        // Linux enables it selectively for RX CQs after programming
        // companion CQC fields (mini_cqe_res_format/layout).
        let cqe_comp = false;
        build_create_cq_input(
            in_mbox,
            log_cq_size,
            cq_buf_pa,
            db_pa,
            self.uar_page,
            eqn,
            cqe_comp,
        );

        let cq_bytes = (1usize << (log_cq_size as usize)) * crate::regs::cqe::SIZE;
        let cq_pages = (cq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let cq_in_len = (0x110 + cq_pages * 8) as u32;

        let cqc = &in_mbox.data[0x10..];
        log::info!(
            target: "mlx5",
            "CREATE_CQ in(pre): st={} cqe_comp={} page_offset={} log_cq_size={} uar_page={} c_eqn={:#x} log_page_size={} dbr_addr={:#x} pas0={:#x}",
            crate::structs::get_bits_u32(cqc, 20, 4),
            crate::structs::get_bits_u32(cqc, 17, 1),
            crate::structs::get_bits_u32(cqc, 84, 6),
            crate::structs::get_bits_u32(cqc, 99, 5),
            crate::structs::get_bits_u32(cqc, 104, 24),
            crate::structs::get_bits_u32(cqc, 160, 32),
            crate::structs::get_bits_u32(cqc, 195, 5),
            in_mbox.read_be64(0x48),
            in_mbox.read_be64(0x110),
        );
        if let Err(err) = self.execute_uid_sensitive_cmd(CmdOpcode::CreateCq, cq_in_len, 0x10) {
            log::info!(
                target: "mlx5",
                "CREATE_CQ input: log_cq_size={} cq_buf_pa={:#x} db_pa={:#x} uar_page={} eqn={} cqe_comp={} in_len={:#x}",
                log_cq_size,
                cq_buf_pa,
                db_pa,
                self.uar_page,
                eqn,
                cqe_comp,
                cq_in_len
            );
            Self::debug_dump_mailbox_words("CREATE_CQ in", in_mbox, 32);
            let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
            log::info!(
                target: "mlx5",
                "CREATE_CQ output(last): status={:#x} syndrome={:#x} cqn24@0x05={} cqn24@0x09={} dw0={:#010x} dw1={:#010x} dw2={:#010x} dw3={:#010x}",
                out_mbox.data[0],
                out_mbox.read_be32(0x04),
                out_mbox.read_be24(0x05),
                out_mbox.read_be24(0x09),
                out_mbox.read_be32(0x00),
                out_mbox.read_be32(0x04),
                out_mbox.read_be32(0x08),
                out_mbox.read_be32(0x0C),
            );
            return Err(err);
        }

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let cqn = parse_create_cq_output(out_mbox);
        let cq = CompletionQueue::new(
            cqn,
            cq_buf_virt,
            cq_buf_pa,
            self.uar_base,
            db_virt,
            log_cq_size,
            eqn,
        );
        self.cqs.push(cq);
        self.cq_db_records.push((db_virt, db_pa));
        Ok(cqn)
    }

    /// CQモデレーション（割り込み抑制）を設定
    pub unsafe fn modify_cq_moderation(
        &mut self,
        cqn: u32,
        period_usec: u16,
        count: u16,
    ) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_cq_moderation_input(in_mbox, cqn, period_usec, count);

        self.execute_uid_sensitive_cmd(
            CmdOpcode::ModifyCq,
            0x40, // input length
            0x10, // output length
        )?;
        Ok(())
    }

    /// Send Queueを作成
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
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let sq_db_ptr = db_virt as *mut u32;
        core::ptr::write_volatile(sq_db_ptr, 0u32.to_be());
        core::ptr::write_volatile(sq_db_ptr.add(1), 0u32.to_be());
        let sq_bytes = (1usize << (log_sq_size as usize)) * 64usize;
        let sq_pages = (sq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let sq_in_len = (0x110 + sq_pages * 8) as u32;
        let fallback_tis0 = tisn == 0 && self.tis_list.iter().all(|t| t.tisn != 0);
        let attempts: &[(&str, bool)] = if fallback_tis0 {
            if self.is_vf() {
                &[("implicit-tis0", true)]
            } else {
                &[("explicit-tis0", false), ("implicit-tis0", true)]
            }
        } else {
            &[("normal", false)]
        };
        let mut last_err = Err(Mlx5Error::NotSupported);
        for (idx, (mode, implicit_tis)) in attempts.iter().enumerate() {
            build_create_sq_input(
                in_mbox,
                log_sq_size,
                sq_buf_pa,
                db_pa,
                cqn,
                self.pd,
                self.uar_page,
                tisn,
            );
            if *implicit_tis {
                let mut layout =
                    crate::structs::queues::SqContextLayout::new(&mut in_mbox.data[0x20..]);
                layout.set_tis_lst_sz(0);
                layout.set_tis_num_0(0);
            }
            match self.execute_uid_sensitive_cmd(CmdOpcode::CreateSq, sq_in_len, 0x10) {
                Ok(()) => {
                    if fallback_tis0 {
                        log::info!(
                            target: "mlx5",
                            "CREATE_SQ accepted with {} fallback (tisn={})",
                            mode,
                            tisn
                        );
                    }
                    break;
                }
                Err(err) => {
                    if !self.is_vf() {
                        let extra_uid = self.default_sw_vhca_id();
                        let prev_uid = self.cmd.as_ref().map(|cmd| cmd.uid()).unwrap_or(0);
                        if extra_uid != 0 && extra_uid != 0xffff && extra_uid != prev_uid {
                            let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
                            cmd.set_uid(extra_uid);
                            match cmd.execute(
                                CmdOpcode::CreateSq,
                                self.cmd_in_mbox_device,
                                sq_in_len,
                                self.cmd_out_mbox_device,
                                0x10,
                            ) {
                                Ok(()) => {
                                    cmd.set_uid(prev_uid);
                                    log::info!(
                                        target: "mlx5",
                                        "CREATE_SQ accepted with PF RID-derived UID {:#x} (mode={}, tisn={})",
                                        extra_uid,
                                        mode,
                                        tisn
                                    );
                                    break;
                                }
                                Err(extra_err) => {
                                    cmd.set_uid(prev_uid);
                                    if fallback_tis0 {
                                        log::warn!(
                                            target: "mlx5",
                                            "CREATE_SQ also failed with PF RID-derived UID {:#x} (mode={}, tisn={}): {:?}",
                                            extra_uid,
                                            mode,
                                            tisn,
                                            extra_err
                                        );
                                    }
                                }
                            }
                        }
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
                    last_err = Err(err);
                    if idx + 1 == attempts.len() {
                        return last_err;
                    }
                }
            }
        }
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let sqn = parse_create_sq_output(out_mbox);
        if let Err(err) = self.transition_sq_to_ready(sqn) {
            if self.is_vf() {
                let _ = err;
                crate::boot_trace("[MLX5_SQ] modify_sq failed on VF; continue\n");
            } else {
                return Err(err);
            }
        }
        match self.query_sq_hw(sqn) {
            Ok(ctx) => {
                log::info!(
                    target: "mlx5",
                    "QUERY_SQ: sqn={:#x} state={} flush={} cqn={:#x} tis_lst_sz={} tis_num_0={:#x} wq_type={} pd={} uar_page={} dbr_addr={:#x} log_stride={} log_pg_sz={} log_sz={}",
                    sqn,
                    ctx.state,
                    ctx.flush_in_error_en,
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
            Err(err) => {
                log::warn!(target: "mlx5", "QUERY_SQ failed for sqn={:#x}: {:?}", sqn, err);
            }
        }
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        let sq = SendQueue::new(
            sqn,
            sq_buf_virt,
            sq_buf_pa,
            db_virt,
            self.uar_base,
            log_sq_size,
            tisn,
            cqn,
            self.mkey,
            csum_offload,
        );
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidResponse)?;
        self.sqs.push(sq);
        self.tx_cq_by_sq.push(cq_index);
        Ok(sqn)
    }

    /// Receive Queueを作成
    pub unsafe fn create_rq_hw(
        &mut self,
        rq_buf_virt: u64,
        rq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_rq_size: u8,
        cqn: u32,
        _tirn: u32,
        scatter_fcs: bool,
        vlan_strip: bool,
    ) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let rq_bytes = (1usize << (log_rq_size as usize)) * crate::defs::WQEBB_SIZE;
        let rq_pages = (rq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let rq_in_len = (0x110 + rq_pages * 8) as u32;

        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        let mut selected_mem_rq_type = 0u8;
        let mut selected_rmpn: Option<u32> = None;
        // Prefer inline RQ first because the current RX runtime is built
        // around inline memory RQ WQEs. On PF we still widen the probe set
        // when the strict default profile is rejected, because some FW
        // variants accept only a narrower context tuple.
        let mem_rq_type_attempts: &[u8] = &[0, 1];
        let mut selected_profile = "default";
        let mut inline_rq_rejected = false;
        let inline_profiles: &[(&str, bool, u8, u8, u8)] = &[
            ("cyclic+align+flush", true, 1, 1, 4),
            ("cyclic+align+noflush", false, 1, 1, 4),
            ("cyclic+nopad+flush", true, 1, 0, 4),
            ("linked+nopad+flush", true, 0, 0, 4),
            ("linked+nopad+noflush", false, 0, 0, 4),
            ("cyclic+align+stride64", true, 1, 1, 6),
        ];
        'mem_type: for &mem_rq_type in mem_rq_type_attempts {
            let mut rmpn_for_attempt = None;
            if mem_rq_type == 1 {
                match self.create_rmp_hw(rq_buf_pa, db_pa, log_rq_size) {
                    Ok(rmpn) => {
                        rmpn_for_attempt = Some(rmpn);
                    }
                    Err(err) => {
                        log::warn!(
                            target: "mlx5",
                            "CREATE_RMP failed for mem_rq_type=1 fallback ({:?}); retrying CREATE_RQ without explicit rmpn",
                            err
                        );
                    }
                }
            }

            let profiles: &[(&str, bool, u8, u8, u8)] = if mem_rq_type == 0 {
                inline_profiles
            } else {
                &[("rmp+cyclic+align+flush", true, 1, 1, 4)]
            };

            for &(profile_name, flush_in_error_en, wq_type, end_padding_mode, log_wq_stride) in
                profiles
            {
                log::info!(
                    target: "mlx5",
                    "CREATE_RQ try: mem_rq_type={} profile={} cqn={:#x} pd={} uar_page={} log_rq_size={} stride={} wq_type={} end_pad={} flush={}",
                    mem_rq_type,
                    profile_name,
                    cqn,
                    self.pd,
                    self.uar_page,
                    log_rq_size,
                    log_wq_stride,
                    wq_type,
                    end_padding_mode,
                    flush_in_error_en
                );
                build_create_rq_input_with_options(
                    in_mbox,
                    log_rq_size,
                    rq_buf_pa,
                    db_pa,
                    cqn,
                    self.pd,
                    self.uar_page,
                    scatter_fcs,
                    vlan_strip,
                    mem_rq_type,
                    rmpn_for_attempt,
                    flush_in_error_en,
                    wq_type,
                    end_padding_mode,
                    log_wq_stride,
                );

                match self.execute_uid_sensitive_cmd(CmdOpcode::CreateRq, rq_in_len, 0x10) {
                    Ok(()) => {
                        selected_mem_rq_type = mem_rq_type;
                        selected_rmpn = rmpn_for_attempt;
                        selected_profile = profile_name;
                        last_err = Ok(());
                        break 'mem_type;
                    }
                    Err(err) => {
                        if mem_rq_type == 0 {
                            inline_rq_rejected = true;
                        }
                        log::warn!(
                            target: "mlx5",
                            "CREATE_RQ attempt failed: mem_rq_type={} profile={} rmpn={} err={:?}",
                            mem_rq_type,
                            profile_name,
                            rmpn_for_attempt
                                .map(|v| alloc::format!("{:#x}", v))
                                .unwrap_or_else(|| "none".into()),
                            err
                        );
                        last_err = Err(err);
                    }
                }
            }

            if let Some(rmpn) = rmpn_for_attempt {
                let _ = self.destroy_rmp_hw(rmpn);
            }
        }
        last_err?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqn = parse_create_rq_output(out_mbox);
        if let Some(rmpn) = selected_rmpn {
            self.rmp_list.push(rmpn);
        }
        log::info!(
            target: "mlx5",
            "CREATE_RQ accepted: mem_rq_type={} profile={} rmpn={}",
            selected_mem_rq_type,
            selected_profile,
            selected_rmpn
                .map(|v| alloc::format!("{:#x}", v))
                .unwrap_or_else(|| "none".into())
        );
        if selected_mem_rq_type != 0 {
            log::warn!(
                target: "mlx5",
                "CREATE_RQ fell back to mem_rq_type={} (inline mode rejected={}): RX runtime may require RMP-specific handling",
                selected_mem_rq_type,
                inline_rq_rejected
            );
        }
        if let Err(err) = self.transition_rq_to_ready(rqn) {
            if self.is_vf() {
                let _ = err;
                crate::boot_trace("[MLX5_RQ] modify_rq failed on VF; continue\n");
            } else {
                return Err(err);
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
            }
            Err(err) => {
                log::warn!(target: "mlx5", "QUERY_RQ failed for rqn={:#x}: {:?}", rqn, err);
            }
        }
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        crate::boot_trace("[MLX5_RQ] build rq object\n");
        let rq = ReceiveQueue::new(
            rqn,
            rq_buf_virt,
            rq_buf_pa,
            db_virt,
            log_rq_size,
            cqn,
            self.mkey,
            csum_offload,
        );
        crate::boot_trace("[MLX5_RQ] rq object ready\n");
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidResponse)?;
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
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let rmp_bytes = (1usize << (log_rmp_size as usize)) * crate::defs::WQEBB_SIZE;
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
                self.uar_page,
                state,
                basic_cyclic,
                wq_type,
                end_padding_mode,
            );
            match self.execute_uid_sensitive_cmd(CmdOpcode::CreateRmp, rmp_in_len, 0x10) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
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
    pub unsafe fn create_rqt(&mut self, rq_numbers: &[u32], log_rqt_size: u8) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_create_rqt_input(in_mbox, rq_numbers, log_rqt_size);

        self.execute_uid_sensitive_cmd(
            CmdOpcode::CreateRqt,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
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
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_sq_input(in_mbox, sqn);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QuerySq,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_sq_output(out_mbox))
    }

    unsafe fn query_rq_hw(&mut self, rqn: u32) -> Mlx5Result<QueryRqInfo> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_rq_input(in_mbox, rqn);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryRq,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_rq_output(out_mbox))
    }

    unsafe fn transition_sq_to_ready(&mut self, sqn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for current_state in [WqState::Reset as u8, WqState::Ready as u8] {
            build_modify_sq_input(in_mbox, sqn, current_state, WqState::Ready as u8);
            match self.execute_uid_sensitive_cmd(CmdOpcode::ModifySq, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Err(err),
            }
        }
        last_err
    }

    unsafe fn transition_rq_to_ready(&mut self, rqn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for current_state in [WqState::Reset as u8, WqState::Ready as u8] {
            build_modify_rq_input(in_mbox, rqn, current_state, WqState::Ready as u8);
            match self.execute_uid_sensitive_cmd(CmdOpcode::ModifyRq, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Err(err),
            }
        }
        last_err
    }

    unsafe fn transition_rmp_to_ready(&mut self, rmpn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for current_state in [WqState::Reset as u8, WqState::Ready as u8] {
            build_modify_rmp_input(in_mbox, rmpn, current_state, WqState::Ready as u8);
            match self.execute_uid_sensitive_cmd(CmdOpcode::ModifyRmp, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Err(err),
            }
        }
        last_err
    }
}
