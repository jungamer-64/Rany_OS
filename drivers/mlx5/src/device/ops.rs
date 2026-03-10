// ============================================================================
// drivers/mlx5/src/device/ops.rs - MLX5 Device Operations
// ============================================================================

extern crate alloc;
use crate::cmd::CmdMailbox;
use crate::cmd::CommandTransport; // for execute() method
use crate::cmd::hca::*; // bring HCA command builders/parsers
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, PortLinkState, VportCounters};
use crate::device::{DeviceState, Mlx5Device};
use crate::eq::EqEvent;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::health::HealthStatus;
use crate::port::MacAddr;
use alloc::vec::Vec;

impl Mlx5Device {
    unsafe fn execute_rebuilt_with_uid_candidates<T, B, F, R>(
        cmd: &mut T,
        in_mbox: &mut CmdMailbox,
        is_vf: bool,
        mut build: B,
        mut execute: F,
    ) -> Mlx5Result<R>
    where
        T: CommandTransport,
        B: FnMut(&mut CmdMailbox, u16),
        F: FnMut(&mut T, &CmdMailbox) -> Mlx5Result<R>,
    {
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf);
        let mut last_err = Err(Mlx5Error::NotSupported);

        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            build(in_mbox, uid);
            match execute(cmd, in_mbox) {
                Ok(value) => {
                    cmd.set_uid(prev_uid);
                    return Ok(value);
                }
                Err(err) => last_err = Err(err),
            }
        }

        cmd.set_uid(prev_uid);
        last_err
    }

    unsafe fn activate_vfs_with_transport<T: CommandTransport>(
        cmd: &mut T,
        in_mbox: &mut CmdMailbox,
        in_mbox_phys: u64,
        out_mbox: &mut CmdMailbox,
        out_mbox_phys: u64,
        is_vf: bool,
        num_vfs: u16,
    ) -> Mlx5Result<()> {
        for vf in 0..num_vfs {
            let function_id = vf + 1;
            let vhca_ctx = Self::execute_rebuilt_with_uid_candidates(
                cmd,
                in_mbox,
                is_vf,
                |in_mbox, uid| build_query_vhca_state_input(in_mbox, uid, function_id),
                |cmd, _| {
                    cmd.execute(
                        CmdOpcode::QueryVhcaState,
                        in_mbox_phys,
                        0x10,
                        out_mbox_phys,
                        0x20,
                    )?;
                    Ok(parse_query_vhca_state_output(out_mbox))
                },
            )?;

            if !vhca_ctx.state.is_activation_ready() {
                log::warn!(
                    target: "mlx5",
                    "VF {} VHCA state {:?} is not activation-ready",
                    function_id,
                    vhca_ctx.state
                );
                return Err(Mlx5Error::InvalidResponse);
            }

            // Linux と同様に EnableHca を呼び出し、VF の HCA を有効化する
            build_enable_hca_input(in_mbox, function_id);
            cmd.execute(
                CmdOpcode::EnableHca,
                in_mbox_phys,
                0x10,
                out_mbox_phys,
                0x10,
            )?;

            build_modify_vport_state_input(
                in_mbox,
                MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT,
                function_id,
                true,
                VPORT_ADMIN_STATE_UP,
            );
            cmd.execute(
                CmdOpcode::ModifyVportState,
                in_mbox_phys,
                0x10,
                out_mbox_phys,
                0x10,
            )?;
        }

        Ok(())
    }

    unsafe fn deactivate_vfs_with_transport<T: CommandTransport>(
        cmd: &mut T,
        in_mbox: &mut CmdMailbox,
        in_mbox_phys: u64,
        out_mbox_phys: u64,
        num_vfs: u16,
    ) -> Mlx5Result<()> {
        for vf in 0..num_vfs {
            let function_id = vf + 1;
            build_modify_vport_state_input(
                in_mbox,
                MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT,
                function_id,
                true,
                VPORT_ADMIN_STATE_DOWN,
            );
            cmd.execute(
                CmdOpcode::ModifyVportState,
                in_mbox_phys,
                0x10,
                out_mbox_phys,
                0x10,
            )?;

            // Linux と同様に DisableHca を呼び出し、VF の HCA を無効化する
            build_enable_hca_input(in_mbox, function_id);
            cmd.execute(CmdOpcode::DisableHca, in_mbox_phys, 0x10, 0, 0)?;
        }

        Ok(())
    }

    /// パケットを送信
    pub unsafe fn transmit(
        &mut self,
        sq_index: usize,
        data_phys: u64,
        data_virt: u64,
        data_len: u32,
        inline_hdr: &[u8],
        options: crate::wq::TxOptions,
    ) -> Mlx5Result<u16> {
        if self.state != DeviceState::Active {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let sq = self
            .sqs
            .get_mut(sq_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let inline_len = core::cmp::min(inline_hdr.len(), data_len as usize) as u32;
        let payload_len = data_len.saturating_sub(inline_len);
        if payload_len == 0 {
            return Err(Mlx5Error::InvalidParameter);
        }

        let segments = [crate::wq::DmaSegment {
            device_addr: data_phys + inline_len as u64,
            virt_addr: data_virt + inline_len as u64,
            len: payload_len,
        }];

        sq.post_send(&segments, inline_hdr, options)
            .ok_or(Mlx5Error::NoResources)
    }

    /// 受信バッファを投入
    pub unsafe fn post_receive(
        &mut self,
        rq_index: usize,
        buf_phys: u64,
        buf_virt: u64,
        buf_size: u32,
    ) -> Mlx5Result<u16> {
        if self.state != DeviceState::Active && self.state != DeviceState::QueuesReady {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let rq = self
            .rqs
            .get_mut(rq_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        rq.post_recv(buf_phys, buf_virt, buf_size)
            .ok_or(Mlx5Error::NoResources)
    }

    pub unsafe fn handle_eq_interrupt(&mut self, eq_index: usize) -> Vec<EqEvent> {
        let mut events = Vec::new();
        if let Some(eq) = self.eqs.get_mut(eq_index) {
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                match eq.poll_eqe() {
                    Some(eqe) => {
                        events.push(crate::eq::decode_eqe(eqe));
                        eq.advance_consumer();
                    }
                    None => break,
                }
            }
            if !events.is_empty() {
                eq.update_doorbell();
            }
        }
        events
    }

    pub unsafe fn poll_cq(&mut self, cq_index: usize, max_batch: u32) -> Vec<crate::cq::CqeInfo> {
        let batch = self.polling_state.max_batch_size().min(max_batch);
        let result = if let Some(cq) = self.cqs.get_mut(cq_index) {
            cq.poll_batch(batch)
        } else {
            Vec::new()
        };
        let need_rearm = self.polling_state.record_poll_cycle(result.len() as u32);
        if need_rearm {
            if let Some(cq) = self.cqs.get(cq_index) {
                cq.arm();
            }
        }
        result
    }

    /// RX Queue のデバッグ状態を取得
    ///
    /// # Safety
    /// - RQ メモリとドアベル領域が有効であること
    pub unsafe fn debug_rx_queue_state(
        &self,
        rq_index: usize,
    ) -> Option<crate::wq::RxQueueDebugState> {
        self.rqs.get(rq_index).map(|rq| rq.debug_state())
    }

    /// TX Queue のデバッグ状態を取得
    ///
    /// # Safety
    /// - SQ メモリとドアベル領域が有効であること
    pub unsafe fn debug_tx_queue_state(
        &self,
        sq_index: usize,
    ) -> Option<crate::wq::TxQueueDebugState> {
        self.sqs.get(sq_index).map(|sq| sq.debug_state())
    }

    /// Completion Queue のデバッグ状態を取得
    ///
    /// # Safety
    /// - CQ メモリとドアベル領域が有効であること
    pub unsafe fn debug_cq_state(&self, cq_index: usize) -> Option<crate::cq::CqDebugState> {
        self.cqs.get(cq_index).map(|cq| cq.debug_state())
    }

    pub fn process_tx_completions(
        &mut self,
        sq_index: usize,
        wqe_counter: u16,
    ) -> Vec<crate::wq::TxBufferInfo> {
        self.sqs
            .get_mut(sq_index)
            .map(|sq| sq.complete_tx(wqe_counter))
            .unwrap_or_default()
    }

    /// デバイスの現在時刻を取得（ハードウェアタイマー）
    ///
    /// # Safety
    /// - bar0_base が有効であること
    pub unsafe fn query_time(&self) -> u64 {
        use crate::regs::init_seg;
        let base = self.bar0_base as usize;

        // 64ビットカウンタを32ビットずつ2回に分けて読み取る（一貫性確保のためループ）
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let hi = crate::mmio_read_be32(base + init_seg::INTERNAL_TIMER_H);
            let lo = crate::mmio_read_be32(base + init_seg::INTERNAL_TIMER_L);
            let hi2 = crate::mmio_read_be32(base + init_seg::INTERNAL_TIMER_H);

            if hi == hi2 {
                return ((hi as u64) << 32) | (lo as u64);
            }
        }
    }

    /// PTP (Precision Time Protocol) サポート状況を確認
    pub fn ptp_caps(&self) -> Option<(u8, u32)> {
        self.hca_caps
            .as_ref()
            .map(|caps| (caps.rq_ts_format, caps.device_frequency_khz))
    }

    pub fn process_rx_completion(
        &mut self,
        rq_index: usize,
        wqe_counter: u16,
        l3_ok: bool,
        l4_ok: bool,
    ) -> Option<crate::wq::RxBufferInfo> {
        self.rqs
            .get_mut(rq_index)
            .and_then(|rq| rq.complete_rx(wqe_counter, l3_ok, l4_ok))
    }

    pub unsafe fn query_vhca_state(&mut self, function_id: u16) -> Mlx5Result<VhcaStateContext> {
        let is_vf = self.is_vf();
        let in_mbox_phys = self.cmd_in_mbox_device;
        let out_mbox_phys = self.cmd_out_mbox_device;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let out_mbox = &mut *(self.cmd_out_mbox_virt as *mut CmdMailbox);

        Self::execute_rebuilt_with_uid_candidates(
            cmd,
            in_mbox,
            is_vf,
            |in_mbox, uid| build_query_vhca_state_input(in_mbox, uid, function_id),
            |cmd, _| {
                cmd.execute(
                    CmdOpcode::QueryVhcaState,
                    in_mbox_phys,
                    0x10,
                    out_mbox_phys,
                    0x20,
                )?;
                Ok(parse_query_vhca_state_output(out_mbox))
            },
        )
    }

    pub unsafe fn activate_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_vf() {
            return Err(Mlx5Error::NotSupported);
        }
        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.vport_group_manager {
            return Err(Mlx5Error::NotSupported);
        }
        let is_vf = self.is_vf();
        let in_mbox_phys = self.cmd_in_mbox_device;
        let out_mbox_phys = self.cmd_out_mbox_device;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let out_mbox = &mut *(self.cmd_out_mbox_virt as *mut CmdMailbox);
        Self::activate_vfs_with_transport(
            cmd,
            in_mbox,
            in_mbox_phys,
            out_mbox,
            out_mbox_phys,
            is_vf,
            num_vfs,
        )
    }

    pub unsafe fn deactivate_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_vf() {
            return Err(Mlx5Error::NotSupported);
        }
        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.vport_group_manager {
            return Err(Mlx5Error::NotSupported);
        }
        let in_mbox_phys = self.cmd_in_mbox_device;
        let out_mbox_phys = self.cmd_out_mbox_device;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        Self::deactivate_vfs_with_transport(cmd, in_mbox, in_mbox_phys, out_mbox_phys, num_vfs)
    }

    pub unsafe fn query_port_state(&mut self, port_index: usize) -> Mlx5Result<PortLinkState> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_vport_state_input(in_mbox, query_vport_state_op_mod_vnic_vport(), 0, false);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryVportState,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let (admin, oper, _max_tx_speed) = parse_query_vport_state_output(out_mbox);
        let link_state = match oper {
            0x01 => PortLinkState::Up,
            0x00 => PortLinkState::Down,
            _ => PortLinkState::Unknown,
        };
        if let Some(port) = self.ports.get_mut(port_index) {
            if admin == 0 {
                port.admin_down();
            } else {
                port.admin_up();
            }
            port.set_link_state(link_state);
        }
        Ok(link_state)
    }

    /// EQエントリを処理 (MSI-X 割り込みハンドラ等から呼び出し)
    pub unsafe fn process_events(&mut self) -> Mlx5Result<u32> {
        enum DeferredEvent {
            RefreshPort(usize),
            RefreshPrimaryPortConfig,
        }

        let mut processed = 0;
        let mut deferred = Vec::new();
        for eq in &mut self.eqs {
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while let Some(eqe) = eq.poll_eqe() {
                processed += 1;
                match eqe.event_type() {
                    Some(crate::defs::EventType::PortStateChange) => {
                        let port_num = eqe.port_number();
                        log::info!(target: "mlx5", "Port state change event for port {}", port_num);
                        deferred.push(DeferredEvent::RefreshPort(
                            (port_num as usize).saturating_sub(1),
                        ));
                    }
                    Some(crate::defs::EventType::NicVportChange) => {
                        log::info!(target: "mlx5", "NIC VPort change event detected (PF modified VF config)");
                        deferred.push(DeferredEvent::RefreshPrimaryPortConfig);
                    }
                    Some(crate::defs::EventType::PageRequest) => {
                        let func_id = eqe.function_id();
                        let num_pages = eqe.requested_pages();
                        log::info!(target: "mlx5", "Page request: func_id={:#x}, num_pages={}", func_id, num_pages);
                    }
                    _ => {
                        log::debug!(target: "mlx5", "Unhandled event type: {:?}", eqe.event_type());
                    }
                }
                eq.advance_consumer();
            }
            eq.update_doorbell();
        }

        for event in deferred {
            match event {
                DeferredEvent::RefreshPort(port_index) => {
                    let _ = self.refresh_port_runtime_state(port_index);
                }
                DeferredEvent::RefreshPrimaryPortConfig => {
                    let _ = self.query_port_mac(0);
                    let _ = self.query_port_mtu(0);
                }
            }
        }
        Ok(processed)
    }

    pub unsafe fn query_port_mac(&mut self, port_index: usize) -> Mlx5Result<MacAddr> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let query_patterns: &[(bool, Option<u8>, &str)] = &[
            (false, None, "self-permanent"),
            (false, Some(0), "self-uc-list"),
            (true, None, "other-vport-permanent"),
            (true, Some(0), "other-vport-uc-list"),
        ];

        let mut last_cmd_status = None;

        for (other_vport, allowed_list_type, label) in query_patterns {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_query_nic_vport_context_input(in_mbox, 0, *other_vport, *allowed_list_type);
            match self.execute_cmd_with_uid_candidates(
                CmdOpcode::QueryNicVportContext,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    Self::debug_dump_mailbox_words("QUERY_NIC_VPORT_CONTEXT", out_mbox, 48);
                    let mac_bytes = if allowed_list_type.is_some() {
                        let list_size = parse_query_nic_vport_context_allowed_list_size(out_mbox);
                        (0..list_size)
                            .find_map(|index| {
                                parse_query_nic_vport_context_allowed_list_mac(out_mbox, index)
                            })
                            .unwrap_or([0; 6])
                    } else {
                        parse_query_nic_vport_context_mac(out_mbox)
                    };
                    if mac_bytes != [0; 6] {
                        let mac = MacAddr(mac_bytes);
                        if let Some(port) = self.ports.get_mut(port_index) {
                            port.set_mac_address(mac);
                        }
                        log::info!(target: "mlx5", "Port {} MAC: {}", port_index + 1, mac);
                        return Ok(mac);
                    }
                    log::debug!(
                        target: "mlx5",
                        "QUERY_NIC_VPORT_CONTEXT ({}) returned zero MAC",
                        label
                    );
                }
                Err(Mlx5Error::CommandFailed(status)) => {
                    last_cmd_status = Some(status);
                    log::debug!(
                        target: "mlx5",
                        "QUERY_NIC_VPORT_CONTEXT ({}) failed with status={:#x}",
                        label,
                        status
                    );
                }
                Err(err) => return Err(err),
            }
        }

        if let Some(status) = last_cmd_status {
            log::warn!(
                target: "mlx5",
                "Failed to query NIC vport MAC (status={:#x}); MAC remains unset",
                status
            );
        } else {
            log::warn!(target: "mlx5", "Failed to query NIC vport MAC; MAC remains unset");
        }

        Ok(MacAddr::ZERO)
    }

    /// VPort カウンタをクエリして統計情報を取得
    pub unsafe fn query_vport_stats(
        &mut self,
        port_index: usize,
    ) -> Mlx5Result<crate::defs::VportCounters> {
        let is_vf = self.is_vf();
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let vport_num = if is_vf { 0 } else { (port_index + 1) as u16 };

        crate::cmd::hca::build_query_vport_counter_input(
            in_mbox, vport_num, false, // self
            None, false, // clear=false
        );

        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryVportCounter,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let counters = crate::cmd::hca::parse_query_vport_counter_output(out_mbox);

        log::debug!(
            target: "mlx5::stats",
            "VPort {}: RX={}/{}B, TX={}/{}B, RX_ERR={}, TX_ERR={}",
            vport_num,
            counters.rx_unicast_packets,
            counters.rx_unicast_bytes,
            counters.tx_unicast_packets,
            counters.tx_unicast_bytes,
            counters.rx_error_packets,
            counters.tx_error_packets
        );

        Ok(counters)
    }

    pub(crate) unsafe fn query_port_mtu(&mut self, port_index: usize) -> Mlx5Result<u32> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_nic_vport_context_input(in_mbox, 0, false, None);
        cmd.execute(
            CmdOpcode::QueryNicVportContext,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let mtu = parse_query_nic_vport_context_mtu(out_mbox) as u32;
        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidResponse)?;
        }
        Ok(mtu)
    }

    unsafe fn query_vnic_env(
        &mut self,
        vport_number: u16,
        other_vport: bool,
    ) -> Mlx5Result<VnicEnvCounters> {
        if self.is_vf() {
            if !self.vnic_env_query_logged {
                log::info!(
                    target: "mlx5",
                    "Skipping QUERY_VNIC_ENV on VF; using zero vNIC environment counters"
                );
                self.vnic_env_query_logged = true;
            }
            return Ok(VnicEnvCounters {
                receive_discard_vport_down: 0,
                transmit_discard_vport_down: 0,
            });
        }

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_vnic_env_input(in_mbox, vport_number, other_vport);
        cmd.execute(
            CmdOpcode::QueryVnicEnv,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            0x40,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_vnic_env_output(out_mbox))
    }

    pub unsafe fn refresh_port_runtime_state(&mut self, port_index: usize) -> Mlx5Result<()> {
        let _ = self.query_port_mac(port_index)?;
        let _ = self.query_port_state(port_index)?;
        let _ = self.query_port_mtu(port_index)?;
        let vnic_env = match self.query_vnic_env(0, false) {
            Ok(env) => Some(env),
            Err(err) => {
                log::warn!(
                    target: "mlx5",
                    "QUERY_VNIC_ENV unavailable during port refresh; keeping drop counters unchanged: {:?}",
                    err
                );
                None
            }
        };

        if let (Some(port), Some(vnic_env)) = (self.ports.get_mut(port_index), vnic_env) {
            let stats = port.stats_mut();
            stats.rx_dropped = vnic_env.receive_discard_vport_down;
            stats.tx_dropped = vnic_env.transmit_discard_vport_down;
        }

        Ok(())
    }

    pub unsafe fn update_port_stats(&mut self, port_index: usize) -> Mlx5Result<()> {
        let port_num = self
            .ports
            .get(port_index)
            .map(|p| p.port_number())
            .ok_or(Mlx5Error::InvalidParameter)?;

        let counters = self.query_vport_counters(port_num, false)?;
        let vnic_env = match self.query_vnic_env(0, false) {
            Ok(env) => Some(env),
            Err(err) => {
                log::warn!(
                    target: "mlx5",
                    "QUERY_VNIC_ENV unavailable during stats update; using counter-only stats: {:?}",
                    err
                );
                None
            }
        };

        if let Some(port) = self.ports.get_mut(port_index) {
            let stats = port.stats_mut();
            stats.rx_packets = counters.rx_unicast_packets
                + counters.rx_multicast_packets
                + counters.rx_broadcast_packets;
            stats.rx_bytes = counters.rx_unicast_bytes
                + counters.rx_multicast_bytes
                + counters.rx_broadcast_bytes;
            stats.tx_packets = counters.tx_unicast_packets
                + counters.tx_multicast_packets
                + counters.tx_broadcast_packets;
            stats.tx_bytes = counters.tx_unicast_bytes
                + counters.tx_multicast_bytes
                + counters.tx_broadcast_bytes;
            stats.rx_errors = counters.rx_error_packets;
            stats.tx_errors = counters.tx_error_packets;
            if let Some(vnic_env) = vnic_env {
                stats.rx_dropped = vnic_env.receive_discard_vport_down;
                stats.tx_dropped = vnic_env.transmit_discard_vport_down;
            }
        }

        Ok(())
    }

    pub unsafe fn set_port_mac(&mut self, port_index: usize, mac: MacAddr) -> Mlx5Result<()> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        build_modify_nic_vport_mac_input(in_mbox, 0, false, mac.0);
        cmd.execute(
            CmdOpcode::ModifyNicVportContext,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mac_address(mac);
        }

        log::info!(target: "mlx5", "Port {} MAC updated to {}", port_index + 1, mac);
        Ok(())
    }

    pub unsafe fn query_vport_counters(
        &mut self,
        port_num: u8,
        clear_on_read: bool,
    ) -> Mlx5Result<VportCounters> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let include_port_num = self
            .hca_caps
            .as_ref()
            .map(|caps| caps.num_ports > 1)
            .unwrap_or(false);
        build_query_vport_counter_input(
            in_mbox,
            0,
            false,
            if include_port_num {
                Some(port_num)
            } else {
                None
            },
            clear_on_read,
        );

        cmd.execute(
            CmdOpcode::QueryVportCounter,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let counters = parse_query_vport_counter_output(out_mbox);

        log::trace!(
            target: "mlx5",
            "VPORT counters: rx_unicast={} tx_unicast={} rx_errors={} tx_errors={}",
            counters.rx_unicast_packets,
            counters.tx_unicast_packets,
            counters.rx_error_packets,
            counters.tx_error_packets
        );

        Ok(counters)
    }

    pub fn set_port_mtu(&mut self, port_index: usize, mtu: u32) -> Mlx5Result<()> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        if !(68..=crate::defs::MLX5_MAX_MTU).contains(&mtu) {
            return Err(Mlx5Error::InvalidParameter);
        }

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        unsafe {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_modify_nic_vport_mtu_input(in_mbox, 0, false, mtu as u16);
            cmd.execute(
                CmdOpcode::ModifyNicVportContext,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            )?;
        }

        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidParameter)?;
        }
        Ok(())
    }

    pub fn set_port_admin_up(&mut self, port_index: usize) -> Mlx5Result<()> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        unsafe {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_modify_vport_state_input(in_mbox, 0, 0, false, VPORT_ADMIN_STATE_UP);
            self.execute_cmd_with_uid_candidates(
                CmdOpcode::ModifyVportState,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            )?;
        }

        if let Some(port) = self.ports.get_mut(port_index) {
            port.admin_up();
        }
        Ok(())
    }

    pub unsafe fn health_status(&mut self) -> HealthStatus {
        self.health_monitor.check(self.bar0_base)
    }

    pub unsafe fn health_check(&mut self) -> bool {
        !matches!(self.health_status(), HealthStatus::Critical)
    }

    /// プロミスキャスモードを設定
    pub unsafe fn set_promiscuous_mode(&mut self, enable: bool) -> Mlx5Result<()> {
        if self.flow_tables.is_empty() {
            return Err(Mlx5Error::NotSupported);
        }
        let table_id = self.flow_tables[0].table_id;
        let tirn = self
            .tir_list
            .first()
            .map(|t| t.tirn)
            .ok_or(Mlx5Error::NotSupported)?;

        let group_id = self
            .flow_groups
            .iter()
            .find(|g| g.start_index == 64)
            .map(|g| g.group_id)
            .ok_or(Mlx5Error::NotSupported)?;

        if enable {
            let match_value = crate::flow::MatchValue::default();
            self.set_flow_table_entry(
                table_id,
                64,
                group_id,
                crate::flow::FlowAction::Allow,
                Some(tirn),
                &match_value,
            )?;
        } else {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            crate::cmd::flow::build_delete_flow_table_entry_input(in_mbox, table_id, 64);
            self.execute_cmd_with_uid_candidates(
                CmdOpcode::DeleteFlowTableEntry,
                self.cmd_in_mbox_device,
                0x10,
                self.cmd_out_mbox_device,
                0x10,
            )?;
        }

        log::info!(target: "mlx5", "Promiscuous mode: {}", if enable { "enabled" } else { "disabled" });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::{get_bits_u32, set_bits_u32};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CallSnapshot {
        opcode: CmdOpcode,
        uid: u16,
        encoded_uid: u16,
        function_id: u16,
        op_mod: u16,
        other_vport: bool,
        vport_number: u16,
        admin_state: u8,
    }

    struct FakeTransport {
        uid: u16,
        in_mbox: *const CmdMailbox,
        out_mbox: *mut CmdMailbox,
        valid_query_uid: u16,
        query_state: VhcaState,
        calls: Vec<CallSnapshot>,
    }

    impl FakeTransport {
        fn new(
            in_mbox: &CmdMailbox,
            out_mbox: &mut CmdMailbox,
            valid_query_uid: u16,
            query_state: VhcaState,
        ) -> Self {
            Self {
                uid: 0,
                in_mbox: in_mbox as *const CmdMailbox,
                out_mbox: out_mbox as *mut CmdMailbox,
                valid_query_uid,
                query_state,
                calls: Vec::new(),
            }
        }
    }

    impl CommandTransport for FakeTransport {
        unsafe fn execute(
            &mut self,
            opcode: CmdOpcode,
            _in_mbox_phys: u64,
            _in_len: u32,
            _out_mbox_phys: u64,
            _out_len: u32,
        ) -> Mlx5Result<()> {
            let in_mbox = &*self.in_mbox;
            match opcode {
                CmdOpcode::QueryVhcaState => {
                    let encoded_uid = get_bits_u32(&in_mbox.data[..], 16, 16) as u16;
                    let function_id = get_bits_u32(&in_mbox.data[..], 80, 16) as u16;
                    self.calls.push(CallSnapshot {
                        opcode,
                        uid: self.uid,
                        encoded_uid,
                        function_id,
                        op_mod: 0,
                        other_vport: false,
                        vport_number: 0,
                        admin_state: 0,
                    });

                    if self.uid != self.valid_query_uid {
                        return Err(Mlx5Error::CommandFailed(0x03));
                    }

                    let out_mbox = &mut *self.out_mbox;
                    *out_mbox = CmdMailbox::zeroed();
                    set_bits_u32(&mut out_mbox.data[..], 140, 4, self.query_state as u32);
                    Ok(())
                }
                CmdOpcode::ModifyVportState => {
                    self.calls.push(CallSnapshot {
                        opcode,
                        uid: self.uid,
                        encoded_uid: 0,
                        function_id: 0,
                        op_mod: get_bits_u32(&in_mbox.data[..], 48, 16) as u16,
                        other_vport: get_bits_u32(&in_mbox.data[..], 64, 1) != 0,
                        vport_number: get_bits_u32(&in_mbox.data[..], 80, 16) as u16,
                        admin_state: get_bits_u32(&in_mbox.data[..], 120, 4) as u8,
                    });
                    Ok(())
                }
                CmdOpcode::ModifyVhcaState => {
                    self.calls.push(CallSnapshot {
                        opcode,
                        uid: self.uid,
                        encoded_uid: get_bits_u32(&in_mbox.data[..], 16, 16) as u16,
                        function_id: get_bits_u32(&in_mbox.data[..], 80, 16) as u16,
                        op_mod: 0,
                        other_vport: false,
                        vport_number: 0,
                        admin_state: 0,
                    });
                    Ok(())
                }
                CmdOpcode::EnableHca | CmdOpcode::DisableHca => {
                    self.calls.push(CallSnapshot {
                        opcode,
                        uid: self.uid,
                        encoded_uid: 0,
                        function_id: get_bits_u32(&in_mbox.data[..], 80, 16) as u16,
                        op_mod: 0,
                        other_vport: false,
                        vport_number: 0,
                        admin_state: 0,
                    });
                    Ok(())
                }
                _ => Err(Mlx5Error::InvalidParameter),
            }
        }

        fn set_uid(&mut self, uid: u16) {
            self.uid = uid;
        }

        fn uid(&self) -> u16 {
            self.uid
        }
    }

    #[test]
    fn activate_vfs_rebuilds_vhca_query_mailboxes_and_only_admins_up_after_validation() {
        let mut in_mbox = CmdMailbox::zeroed();
        let mut out_mbox = CmdMailbox::zeroed();
        let mut transport =
            FakeTransport::new(&in_mbox, &mut out_mbox, 0xffff, VhcaState::Allocated);

        unsafe {
            Mlx5Device::activate_vfs_with_transport(
                &mut transport,
                &mut in_mbox,
                0,
                &mut out_mbox,
                0,
                true,
                1,
            )
        }
        .unwrap();

        assert_eq!(transport.calls.len(), 4);
        assert_eq!(transport.calls[0].opcode, CmdOpcode::QueryVhcaState);
        assert_eq!(transport.calls[0].uid, 0);
        assert_eq!(transport.calls[0].encoded_uid, 0);
        assert_eq!(transport.calls[0].function_id, 1);
        assert_eq!(transport.calls[1].opcode, CmdOpcode::QueryVhcaState);
        assert_eq!(transport.calls[1].uid, 0xffff);
        assert_eq!(transport.calls[1].encoded_uid, 0xffff);
        assert_eq!(transport.calls[1].function_id, 1);
        assert_eq!(transport.calls[2].opcode, CmdOpcode::EnableHca);
        assert_eq!(transport.calls[2].function_id, 1);
        assert_eq!(transport.calls[3].opcode, CmdOpcode::ModifyVportState);
        assert_eq!(
            transport.calls[3].op_mod,
            MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT
        );
        assert!(transport.calls[3].other_vport);
        assert_eq!(transport.calls[3].vport_number, 1);
        assert_eq!(transport.calls[3].admin_state, VPORT_ADMIN_STATE_UP);
        assert!(
            !transport
                .calls
                .iter()
                .any(|call| call.opcode == CmdOpcode::ModifyVhcaState)
        );
    }

    #[test]
    fn activate_vfs_stops_before_admin_up_when_vhca_state_is_invalid() {
        let mut in_mbox = CmdMailbox::zeroed();
        let mut out_mbox = CmdMailbox::zeroed();
        let mut transport = FakeTransport::new(&in_mbox, &mut out_mbox, 0, VhcaState::Invalid);

        let err = unsafe {
            Mlx5Device::activate_vfs_with_transport(
                &mut transport,
                &mut in_mbox,
                0,
                &mut out_mbox,
                0,
                true,
                1,
            )
        }
        .unwrap_err();

        assert_eq!(err, Mlx5Error::InvalidResponse);
        assert_eq!(transport.calls.len(), 1);
        assert_eq!(transport.calls[0].opcode, CmdOpcode::QueryVhcaState);
        assert!(
            !transport
                .calls
                .iter()
                .any(|call| call.opcode == CmdOpcode::ModifyVportState)
        );
    }

    #[test]
    fn deactivate_vfs_only_admins_down_vports() {
        let mut in_mbox = CmdMailbox::zeroed();
        let mut out_mbox = CmdMailbox::zeroed();
        let mut transport = FakeTransport::new(&in_mbox, &mut out_mbox, 0, VhcaState::Allocated);

        unsafe { Mlx5Device::deactivate_vfs_with_transport(&mut transport, &mut in_mbox, 0, 0, 2) }
            .unwrap();

        assert_eq!(transport.calls.len(), 4);
        assert_eq!(transport.calls[0].opcode, CmdOpcode::ModifyVportState);
        assert_eq!(transport.calls[1].opcode, CmdOpcode::DisableHca);
        assert_eq!(transport.calls[1].function_id, 1);
        assert_eq!(transport.calls[2].opcode, CmdOpcode::ModifyVportState);
        assert_eq!(transport.calls[3].opcode, CmdOpcode::DisableHca);
        assert_eq!(transport.calls[3].function_id, 2);
        assert!(
            transport
                .calls
                .iter()
                .filter(|call| call.opcode == CmdOpcode::ModifyVportState)
                .count()
                == 2
        );
        assert_eq!(
            transport.calls[0].op_mod,
            MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT
        );
        assert!(transport.calls[0].other_vport);
        assert_eq!(transport.calls[0].vport_number, 1);
        assert_eq!(transport.calls[0].admin_state, VPORT_ADMIN_STATE_DOWN);
        assert_eq!(transport.calls[2].vport_number, 2);
        assert_eq!(transport.calls[2].admin_state, VPORT_ADMIN_STATE_DOWN);
        assert!(
            !transport
                .calls
                .iter()
                .any(|call| call.opcode == CmdOpcode::QueryVhcaState)
        );
    }
}
