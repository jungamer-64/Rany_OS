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

#[derive(Clone, Copy)]
pub(crate) enum SendTisBinding {
    Explicit(u32),
    Implicit,
}
impl SendTisBinding {
    fn number(self) -> u32 {
        match self {
            Self::Explicit(number) => number,
            Self::Implicit => 0,
        }
    }
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
    rmpn: u32,
    ctx: QueryRqInfo,
    pool: QueryRmpInfo,
) -> Result<ResolvedRqLayout, &'static str> {
    if ctx.state != WqState::Ready as u8 || pool.state != WqState::Ready as u8 {
        return Err("receive queue or pool is not ready");
    }
    if ctx.mem_rq_type != 1 || ctx.cqn != expected.cqn {
        return Err("unexpected RQ pool binding");
    }
    if ctx.rmpn != rmpn {
        return Err("QUERY_RQ returned an unexpected RMP number");
    }
    if pool.pd != expected.pd
        || pool.dbr_addr != expected.dbr_addr
        || pool.log_size != expected.log_rq_size
    {
        return Err("unexpected RMP backing geometry");
    }
    if pool.signature {
        return Err("receive signatures are not enabled by this driver");
    }
    let stride = 1usize
        .checked_shl(u32::from(pool.log_stride))
        .ok_or("unrepresentable RMP stride")?;
    let mut layout = match (pool.wq_type, pool.log_stride) {
        (1, 4 | 6) => ResolvedRqLayout::cyclic(
            rqn,
            expected.cqn,
            stride,
            1,
            pool.wq_type,
            pool.log_stride,
            pool.padding,
            pool.log_size,
            Some(rmpn),
        ),
        (0, 6) => ResolvedRqLayout::linked(
            rqn,
            expected.cqn,
            stride,
            1,
            pool.wq_type,
            pool.log_stride,
            pool.padding,
            pool.log_size,
            Some(rmpn),
        ),
        _ => return Err("unsupported RMP work queue layout"),
    };
    if pool.wq_type == 1 && !pool.basic_cyclic {
        layout.data_seg_offset = 16;
    }
    if layout.data_seg_offset + 16 > stride {
        return Err("RMP stride does not contain its control and data segments");
    }
    Ok(layout)
}

impl Mlx5Device {
    fn queue_identity(&mut self) -> Mlx5Result<kernel_api::dma::DmaQueueIdentity> {
        let index = self.next_queue_identity;
        let next = index.checked_add(1).ok_or(Mlx5Error::NoResources)?;
        let identity = kernel_api::dma::DmaQueueIdentity::new(
            self.packed_device_id(),
            index,
            self.command_generation,
        )
        .ok_or(Mlx5Error::DeviceNotReady)?;
        self.next_queue_identity = next;
        Ok(identity)
    }

    fn checked_completion_ring(log_size: u8, stride: usize) -> Mlx5Result<(usize, u32)> {
        let count = 1u32
            .checked_shl(u32::from(log_size))
            .ok_or(Mlx5Error::InvalidParameter)?;
        let bytes = (count as usize)
            .checked_mul(stride)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let pages = bytes.div_ceil(crate::defs::MLX5_PAGE_SIZE);
        let input = 0x110usize
            .checked_add(pages.checked_mul(8).ok_or(Mlx5Error::InvalidParameter)?)
            .ok_or(Mlx5Error::InvalidParameter)?;
        if input > MLX5_CMD_MBOX_SIZE {
            return Err(Mlx5Error::InvalidParameter);
        }
        Ok((bytes, input as u32))
    }

    /// Inventory transfer precedes preparation. The stored queue retains RAM
    /// even when activation or firmware acceptance cannot be established.
    pub(crate) fn create_event_queue(
        &mut self,
        inventory: &mut crate::bootstrap::BootstrapDmaInventory,
        index: u16,
        log_size: u8,
        msix_vector: u32,
        event_mask: u64,
    ) -> Mlx5Result<u32> {
        use crate::bootstrap::{BootstrapDmaPurpose as Purpose, BootstrapQueueKind as Kind};
        let (_, input_length) =
            Self::checked_completion_ring(log_size, crate::regs::eqe::EQE_SIZE)?;
        let uar = self.uar.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let uar_page = uar.number();
        let doorbell = uar.eq()?;
        if let Some(caps) = &self.hca_caps
            && (msix_vector >= caps.max_eq || self.eqs.len() >= caps.max_eq as usize)
        {
            return Err(Mlx5Error::NoResources);
        }
        self.eqs
            .try_reserve(1)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        let identity = self.queue_identity()?;
        let [lease] = inventory
            .take_group([Purpose::QueueEntries(Kind::Event, index)])
            .ok_or(Mlx5Error::NoResources)?;
        let slot = self.eqs.len();
        self.eqs.push(crate::eq::EventQueue::new(
            identity,
            lease,
            doorbell,
            log_size,
            msix_vector,
        ));
        self.eqs[slot].prepare()?;
        let address = self.eqs[slot].memory.address(0)?.get();
        let mut input = CmdMailbox::zeroed();
        build_create_eq_input(
            &mut input,
            log_size,
            address,
            uar_page,
            msix_vector,
            event_mask,
        );
        self.eqs[slot].grant.begin_creation()?;
        let result = self
            .execute_command(CmdOpcode::CreateEq, &input, input_length, 0x10)
            .map(|()| parse_create_eq_output(&self.cmd_output));
        self.eqs[slot].grant.finish_creation(result)
    }

    pub(crate) fn create_completion_queue(
        &mut self,
        inventory: &mut crate::bootstrap::BootstrapDmaInventory,
        kind: crate::bootstrap::BootstrapQueueKind,
        index: u16,
        log_size: u8,
        eq_number: u32,
    ) -> Mlx5Result<u32> {
        use crate::bootstrap::{BootstrapDmaPurpose as Purpose, BootstrapQueueKind as Kind};
        if !matches!(kind, Kind::TransmitCompletion | Kind::ReceiveCompletion)
            || !self.eqs.iter().any(|eq| eq.number() == Some(eq_number))
        {
            return Err(Mlx5Error::InvalidParameter);
        }
        let (_, input_length) = Self::checked_completion_ring(log_size, crate::regs::cqe::SIZE)?;
        let uar = self.uar.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let uar_page = uar.number();
        let doorbell = uar.cq()?;
        if self
            .hca_caps
            .as_ref()
            .is_some_and(|caps| self.cqs.len() >= caps.max_cq as usize)
        {
            return Err(Mlx5Error::NoResources);
        }
        self.cqs
            .try_reserve(1)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        let identity = self.queue_identity()?;
        let leases = inventory
            .take_group([
                Purpose::QueueEntries(kind, index),
                Purpose::Doorbell(kind, index),
            ])
            .ok_or(Mlx5Error::NoResources)?;
        let slot = self.cqs.len();
        self.cqs.push(crate::cq::CompletionQueue::new(
            identity, leases, doorbell, log_size, eq_number,
        ));
        self.cqs[slot].prepare()?;
        let address = self.cqs[slot].memory.address(0)?.get();
        let record = self.cqs[slot].memory.address(1)?.get();
        let mut input = CmdMailbox::zeroed();
        build_create_cq_input(
            &mut input, log_size, address, record, uar_page, eq_number, false,
        );
        self.cqs[slot].grant.begin_creation()?;
        let result = self
            .execute_command(CmdOpcode::CreateCq, &input, input_length, 0x10)
            .map(|()| parse_create_cq_output(&self.cmd_output));
        self.cqs[slot].grant.finish_creation(result)
    }

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

        self.execute_command(
            CmdOpcode::ModifyCq,
            in_mbox,
            0x40, // input length
            0x10, // output length
        )?;
        Ok(())
    }

    /// Transfer RAM once before attempting any firmware profile. Every accepted
    /// or uncertain creation already has a retained owner in this device.
    pub(crate) fn create_send_queue(
        &mut self,
        inventory: &mut crate::bootstrap::BootstrapDmaInventory,
        index: u16,
        log_size: u8,
        cqn: u32,
        bindings: &[SendTisBinding],
    ) -> Mlx5Result<u32> {
        use crate::bootstrap::{BootstrapDmaPurpose as Purpose, BootstrapQueueKind as Kind};
        let uar = self.uar.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let page = uar.number();
        let doorbell = uar.sq()?;
        let storage = crate::wq::SendStorage::reserve(log_size)?;
        let (_, input_len) = Self::checked_completion_ring(log_size, 64)?;
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidParameter)?;
        if bindings.is_empty() {
            return Err(Mlx5Error::InvalidParameter);
        }
        self.sqs
            .try_reserve(1)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        self.tx_cq_by_sq
            .try_reserve(1)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        let identity = self.queue_identity()?;
        let leases = inventory
            .take_group([
                Purpose::QueueEntries(Kind::Send, index),
                Purpose::Doorbell(Kind::Send, index),
            ])
            .ok_or(Mlx5Error::InvalidParameter)?;
        let checksum = self.hca_caps.as_ref().is_some_and(|caps| caps.csum_cap);
        let slot = self.sqs.len();
        self.sqs.push(SendQueue::new(
            identity,
            leases,
            doorbell,
            storage,
            cqn,
            self.tx_mkey,
            checksum,
        ));
        self.sqs[slot].prepare()?;
        let address = self.sqs[slot].memory.address(0)?.get();
        let record = self.sqs[slot].memory.address(1)?.get();
        let inline = self
            .ports
            .first()
            .map(|port| port.min_wqe_inline_mode())
            .unwrap_or(0);
        let program_inline = self
            .hca_caps()
            .is_some_and(|caps| caps.wqe_inline_mode == 1);
        let timestamp = u8::from(self.hca_caps().is_some_and(|caps| caps.sq_ts_format != 0));
        let mut last = Mlx5Error::NotSupported;
        for binding in bindings {
            let tisn = binding.number();
            let mut input = CmdMailbox::zeroed();
            build_create_sq_input(
                &mut input,
                log_size,
                address,
                record,
                cqn,
                self.pd,
                page,
                tisn,
                if program_inline { inline } else { 0 },
                false,
                timestamp,
            );
            if matches!(binding, SendTisBinding::Implicit) {
                let mut context =
                    crate::structs::queues::SqContextLayout::new(&mut input.data[0x20..]);
                context.set_tis_lst_sz(0);
                context.set_tis_num_0(0);
            }
            self.sqs[slot].grant.begin_creation()?;
            let result = self.execute_command(CmdOpcode::CreateSq, &input, input_len, 0x10);
            let retry = matches!(result, Err(crate::error::CommandFailure::Rejected(_)));
            let result = result.map(|()| parse_create_sq_output(&self.cmd_output));
            match self.sqs[slot].grant.finish_creation(result) {
                Ok(number) => {
                    // SAFETY: the retained grant owns this SQ and its configured RAM.
                    unsafe { self.transition_sq_to_ready(number) }?;
                    // SAFETY: QUERY reads CPU mailbox output for the retained grant.
                    let context = unsafe { self.query_sq_hw(number) }?;
                    if context.state != WqState::Ready as u8
                        || context.cqn != cqn
                        || context.pd != self.pd
                        || context.dbr_addr != record
                        || context.log_wq_stride != 6
                        || context.log_wq_sz != log_size
                    {
                        return Err(Mlx5Error::InvalidResponse);
                    }
                    self.sqs[slot].accept_configuration(context.tis_num_0);
                    self.tx_cq_by_sq.push(cq_index);
                    return Ok(number);
                }
                Err(cause) if retry => last = cause,
                Err(cause) => return Err(cause),
            }
        }
        Err(last)
    }

    pub(crate) fn create_receive_queue(
        &mut self,
        inventory: &mut crate::bootstrap::BootstrapDmaInventory,
        index: u16,
        log_size: u8,
        cqn: u32,
        scatter_fcs: bool,
        vlan_strip: bool,
    ) -> Mlx5Result<u32> {
        use crate::bootstrap::{BootstrapDmaPurpose as Purpose, BootstrapQueueKind as Kind};
        let page = self.uar.as_ref().ok_or(Mlx5Error::DeviceNotReady)?.number();
        let storage = crate::wq::ReceiveStorage::reserve(log_size)?;
        let (_, input_len) =
            Self::checked_completion_ring(log_size, MLX5_RX_WQE_MAX_SUPPORTED_SIZE)?;
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidParameter)?;
        self.rqs
            .try_reserve(1)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        self.rx_cq_by_rq
            .try_reserve(1)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        let identity = self.queue_identity()?;
        let leases = inventory
            .take_group([
                Purpose::QueueEntries(Kind::Receive, index),
                Purpose::Doorbell(Kind::Receive, index),
                Purpose::QueueEntries(Kind::ReceiveMemoryPool, index),
                Purpose::Doorbell(Kind::ReceiveMemoryPool, index),
            ])
            .ok_or(Mlx5Error::InvalidParameter)?;
        let slot = self.rqs.len();
        self.rqs
            .push(ReceiveQueue::new(identity, leases, storage, cqn, self.mkey));
        self.rqs[slot].prepare()?;
        let direct = self.rqs[slot].memory.address(0)?.get();
        let record = self.rqs[slot].memory.address(1)?.get();
        let mut last = Mlx5Error::NotSupported;
        // Known firmware rejection alone permits another creation profile.
        for pool in [false, true] {
            let rmp = if pool {
                Some(self.create_receive_pool(slot, log_size, page, input_len)?)
            } else {
                None
            };
            let db = self.rqs[slot]
                .memory
                .address(if pool { 3 } else { 1 })?
                .get();
            let profiles = if pool {
                &RMP_RQ_PROFILE_ATTEMPTS
            } else {
                &DIRECT_RQ_PROFILE_ATTEMPTS
            };
            for attempt in profiles {
                let mut input = CmdMailbox::zeroed();
                build_create_rq_input_with_options(
                    &mut input,
                    log_size,
                    direct,
                    record,
                    cqn,
                    self.pd,
                    page,
                    scatter_fcs,
                    vlan_strip,
                    u8::from(pool),
                    rmp,
                    attempt.flush_in_error_en,
                    attempt.wq_type,
                    attempt.end_padding_mode,
                    attempt.log_wq_stride,
                );
                self.rqs[slot].grant.begin_creation()?;
                let result = self.execute_command(CmdOpcode::CreateRq, &input, input_len, 0x10);
                let retry = matches!(result, Err(crate::error::CommandFailure::Rejected(_)));
                let result = result.map(|()| parse_create_rq_output(&self.cmd_output));
                let number = match self.rqs[slot].grant.finish_creation(result) {
                    Ok(number) => number,
                    Err(cause) if retry => {
                        last = cause;
                        continue;
                    }
                    Err(cause) => return Err(cause),
                };
                // SAFETY: this retained queue owns the newly accepted RQ.
                unsafe { self.transition_rq_to_ready(number) }?;
                // SAFETY: QUERY reads CPU output for the retained firmware grant.
                let context = unsafe { self.query_rq_hw(number) }?;
                let expected = RqExpectations {
                    cqn,
                    log_rq_size: log_size,
                    pd: self.pd,
                    dbr_addr: db,
                };
                let layout = match rmp {
                    Some(pool) => {
                        let mut input = CmdMailbox::zeroed();
                        input.write_be32(8, pool);
                        self.execute_command(
                            CmdOpcode::QueryRmp,
                            &input,
                            16,
                            MLX5_CMD_MBOX_SIZE as u32,
                        )?;
                        let pool_context = parse_query_rmp_output(&self.cmd_output);
                        resolve_rmp_backed_rq_layout(number, expected, pool, context, pool_context)
                    }
                    None => resolve_direct_rq_layout(number, expected, context),
                }
                .map_err(|_| Mlx5Error::InvalidResponse)?;
                if layout.slot_size_bytes * self.rqs[slot].depth()
                    > MLX5_RX_WQE_MAX_SUPPORTED_SIZE * self.rqs[slot].depth()
                {
                    return Err(Mlx5Error::InvalidResponse);
                }
                self.rqs[slot].layout = Some(layout);
                self.rx_cq_by_rq.push(cq_index);
                return Ok(number);
            }
        }
        Err(last)
    }

    fn create_receive_pool(
        &mut self,
        slot: usize,
        log_size: u8,
        page: u32,
        input_len: u32,
    ) -> Mlx5Result<u32> {
        let address = self.rqs[slot].memory.address(2)?.get();
        let record = self.rqs[slot].memory.address(3)?.get();
        let mut last = Mlx5Error::NotSupported;
        // RMPs are created Ready. Basic cyclic omits the control segment;
        // non-basic cyclic and linked layouts reserve a full control segment.
        for (basic, kind, padding, stride) in [
            (true, 1, 1, 4),
            (true, 1, 0, 4),
            (false, 1, 1, 6),
            (false, 0, 0, 6),
        ] {
            let mut input = CmdMailbox::zeroed();
            build_create_rmp_input_with_options(
                &mut input,
                log_size,
                address,
                record,
                self.pd,
                page,
                WqState::Ready as u8,
                basic,
                kind,
                padding,
                stride,
            );
            self.rqs[slot].rmp_grant.begin_creation()?;
            let result = self.execute_command(CmdOpcode::CreateRmp, &input, input_len, 0x10);
            let retry = matches!(result, Err(crate::error::CommandFailure::Rejected(_)));
            let result = result.map(|()| parse_create_rmp_output(&self.cmd_output));
            match self.rqs[slot].rmp_grant.finish_creation(result) {
                Ok(number) => {
                    return Ok(number);
                }
                Err(cause) if retry => last = cause,
                Err(cause) => return Err(cause),
            }
        }
        Err(last)
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

        self.execute_command(
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
        self.execute_command(CmdOpcode::QuerySq, in_mbox, 0x10, MLX5_CMD_MBOX_SIZE as u32)?;
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
        self.execute_command(CmdOpcode::QueryRq, in_mbox, 0x10, MLX5_CMD_MBOX_SIZE as u32)?;
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
            match self.execute_command(CmdOpcode::ModifySq, in_mbox, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if !matches!(err, crate::error::CommandFailure::Rejected(_)) {
                        return Err(err.cause());
                    }
                    last_err = Err(err.cause());
                }
            }
        }

        if let Ok(ctx) = self.query_sq_hw(sqn) {
            let current_state = ctx.state & 0x0f;
            if usize::from(current_state) < tried.len() && !tried[current_state as usize] {
                build_modify_sq_input(in_mbox, sqn, current_state, WqState::Ready as u8);
                match self.execute_command(CmdOpcode::ModifySq, in_mbox, 0x110, 0x10) {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        if !matches!(err, crate::error::CommandFailure::Rejected(_)) {
                            return Err(err.cause());
                        }
                        last_err = Err(err.cause());
                    }
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
            match self.execute_command(CmdOpcode::ModifyRq, in_mbox, 0x110, 0x10) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if !matches!(err, crate::error::CommandFailure::Rejected(_)) {
                        return Err(err.cause());
                    }
                    last_err = Err(err.cause());
                }
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
        let layout = resolve_rmp_backed_rq_layout(
            0x44,
            expected_rq(),
            0x88,
            ctx,
            QueryRmpInfo {
                state: WqState::Ready as u8,
                basic_cyclic: true,
                signature: false,
                wq_type: 1,
                padding: 1,
                pd: expected_rq().pd,
                dbr_addr: expected_rq().dbr_addr,
                log_stride: 4,
                log_size: expected_rq().log_rq_size,
            },
        )
        .unwrap();
        assert_eq!(layout.wq_mode, RxWqMode::Cyclic);
        assert_eq!(layout.slot_size_bytes, 16);
        assert_eq!(layout.rmpn, Some(0x88));
    }

    #[test]
    fn resolve_rmp_backed_rq_layout_rejects_unexpected_rmp_number() {
        let mut ctx = query_rq_info(1, 1, 4);
        ctx.rmpn = 0x99;
        let err = resolve_rmp_backed_rq_layout(
            0x44,
            expected_rq(),
            0x88,
            ctx,
            QueryRmpInfo {
                state: WqState::Ready as u8,
                basic_cyclic: true,
                signature: false,
                wq_type: 1,
                padding: 1,
                pd: expected_rq().pd,
                dbr_addr: expected_rq().dbr_addr,
                log_stride: 4,
                log_size: expected_rq().log_rq_size,
            },
        )
        .unwrap_err();
        assert_eq!(err, "QUERY_RQ returned an unexpected RMP number");
    }
}
