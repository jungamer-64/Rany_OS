// ============================================================================
// drivers/mlx5/src/device/mod.rs - MLX5 Device Core
// ============================================================================

extern crate alloc;
use crate::cmd::{CmdQueue, CommandTransport};
use crate::cq::CompletionQueue;
use crate::defs::{CmdOpcode, ConnectXVariant, HcaCaps};
use crate::eq::EventQueue;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::{FlowGroup, FlowTable, FlowTableEntry, RqTable};
use crate::fw::FwInfo;
use crate::health::HealthMonitor;
use crate::pages::PageManager;
use crate::polling::AdaptivePollingState;
use crate::port::Mlx5Port;
use crate::resources::{MkeyInfo, TirInfo, TisInfo};
use crate::wq::{ReceiveQueue, SendQueue};
use alloc::vec;
use alloc::vec::Vec;

pub mod caps;
pub mod init;
pub mod ops;
pub mod pages;
pub mod queues;
pub mod res;
pub mod teardown;

/// デバイスの初期化状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Uninitialized,
    FirmwareReady,
    CommandInitialized,
    HcaEnabled,
    CapsQueried,
    PagesProvided,
    QueuesReady,
    Active,
    Error,
}

/// ConnectX デバイス抽象化
pub struct Mlx5Device {
    // Hardware info
    pub(crate) bar0_base: u64,
    pub(crate) bar0_size: usize,
    pub(crate) device_id: u16,
    pub(crate) variant: ConnectXVariant,

    // Core state
    pub(crate) state: DeviceState,
    pub(crate) fw_info: Option<FwInfo>,
    pub(crate) hca_caps: Option<HcaCaps>,

    // Command IF
    pub(crate) cmd: Option<CmdQueue>,
    pub(crate) cmd_in_mbox_virt: u64,
    pub(crate) cmd_in_mbox_device: u64,
    pub(crate) cmd_out_mbox_virt: u64,
    pub(crate) cmd_out_mbox_device: u64,

    // Memory/Pages
    pub(crate) fw_function_id: u16,
    pub(crate) page_manager: PageManager,

    // Resources
    pub(crate) uar_page: u32,
    pub(crate) uar_base: u64,
    pub(crate) pd: u32,
    pub(crate) td: u32,
    pub(crate) mkey: u32,
    pub(crate) mkey_info: Option<MkeyInfo>,
    pub(crate) sw_vhca_id: u16,
    pub(crate) resources_allocated: bool,
    pub(crate) pci_bus: u8,
    pub(crate) pci_device: u8,
    pub(crate) pci_function: u8,

    // Queues
    pub(crate) eqs: Vec<EventQueue>,
    pub(crate) cqs: Vec<CompletionQueue>,
    pub(crate) sqs: Vec<SendQueue>,
    pub(crate) rqs: Vec<ReceiveQueue>,
    pub(crate) rq_tables: Vec<RqTable>,
    pub(crate) cq_db_records: Vec<(u64, u64)>,
    pub(crate) tx_cq_by_sq: Vec<usize>,
    pub(crate) rx_cq_by_rq: Vec<usize>,

    // Port & Steering
    pub(crate) ports: Vec<Mlx5Port>,
    pub(crate) tis_list: Vec<TisInfo>,
    pub(crate) tir_list: Vec<TirInfo>,
    pub(crate) flow_tables: Vec<FlowTable>,
    pub(crate) flow_groups: Vec<FlowGroup>,
    pub(crate) flow_entries: Vec<FlowTableEntry>,

    // Management
    pub(crate) polling_state: AdaptivePollingState,
    pub(crate) health_monitor: HealthMonitor,
    pub(crate) allocated_uars: Vec<u32>,
}

// Types moved to crate::flow

impl Mlx5Device {
    pub fn new(bar0_base: u64, bar0_size: usize, device_id: u16) -> Self {
        let variant = ConnectXVariant::from_device_id(device_id);
        Self {
            bar0_base,
            bar0_size,
            device_id,
            variant,
            state: DeviceState::Uninitialized,
            fw_info: None,
            hca_caps: None,
            cmd: None,
            cmd_in_mbox_virt: 0,
            cmd_in_mbox_device: 0,
            cmd_out_mbox_virt: 0,
            cmd_out_mbox_device: 0,
            fw_function_id: 0,
            page_manager: PageManager::new(),
            uar_page: 0,
            uar_base: 0,
            pd: 0,
            td: 0,
            mkey: 0,
            mkey_info: None,
            sw_vhca_id: 0,
            resources_allocated: false,
            pci_bus: 0,
            pci_device: 0,
            pci_function: 0,
            eqs: Vec::new(),
            cqs: Vec::new(),
            sqs: Vec::new(),
            rqs: Vec::new(),
            rq_tables: Vec::new(),
            cq_db_records: Vec::new(),
            tx_cq_by_sq: Vec::new(),
            rx_cq_by_rq: Vec::new(),
            ports: vec![Mlx5Port::new(1)],
            tis_list: Vec::new(),
            tir_list: Vec::new(),
            flow_tables: Vec::new(),
            flow_groups: Vec::new(),
            flow_entries: Vec::new(),
            polling_state: AdaptivePollingState::with_defaults(),
            health_monitor: HealthMonitor::new(),
            allocated_uars: Vec::new(),
        }
    }

    pub fn state(&self) -> DeviceState {
        self.state
    }

    pub fn variant(&self) -> ConnectXVariant {
        self.variant
    }

    pub fn bar0_base(&self) -> u64 {
        self.bar0_base
    }

    pub fn fw_info(&self) -> Option<&FwInfo> {
        self.fw_info.as_ref()
    }

    pub fn is_vf(&self) -> bool {
        ConnectXVariant::is_vf_device_id(self.device_id)
    }

    pub fn hca_caps(&self) -> Option<&HcaCaps> {
        self.hca_caps.as_ref()
    }

    pub fn port(&self, index: usize) -> Option<&Mlx5Port> {
        self.ports.get(index)
    }

    pub fn port_mut(&mut self, index: usize) -> Option<&mut Mlx5Port> {
        self.ports.get_mut(index)
    }

    pub fn num_ports(&self) -> usize {
        self.ports.len()
    }

    pub fn is_active(&self) -> bool {
        self.state == DeviceState::Active
    }

    pub fn pd(&self) -> u32 {
        self.pd
    }

    pub fn td(&self) -> u32 {
        self.td
    }

    pub fn eqn_msix_vector(&self, eq_index: usize) -> Option<u32> {
        self.eqs.get(eq_index).map(|eq| eq.msix_vector)
    }

    pub fn set_pci_bdf(&mut self, bus: u8, device: u8, function: u8) {
        self.pci_bus = bus;
        self.pci_device = device;
        self.pci_function = function;
    }

    pub fn num_rqs(&self) -> usize {
        self.rqs.len()
    }

    pub fn num_sqs(&self) -> usize {
        self.sqs.len()
    }

    pub fn tx_cq_index_for_sq(&self, sq_index: usize) -> Option<usize> {
        self.tx_cq_by_sq.get(sq_index).copied()
    }

    pub fn rx_cq_index_for_rq(&self, rq_index: usize) -> Option<usize> {
        self.rx_cq_by_rq.get(rq_index).copied()
    }

    pub(crate) fn cq_index_by_cqn(&self, cqn: u32) -> Option<usize> {
        self.cqs.iter().position(|cq| cq.cqn == cqn)
    }

    pub unsafe fn teardown(&mut self) -> Mlx5Result<()> {
        self.teardown_full()
    }

    fn debug_dump_mailbox_words(tag: &str, mbox: &crate::cmd::CmdMailbox, dwords: usize) {
        let count = dwords.min(32);
        for i in 0..count {
            let off = i * 4;
            log::debug!(
                target: "mlx5",
                "[mlx5-diag] {} out[{:#04x}]={:#010x}",
                tag,
                off,
                mbox.read_be32(off)
            );
        }
    }

    /// Build the list of UID candidates that should be tried for commands when
    /// running in VF mode.  The first entry is always the previous UID stored
    /// in the transport; additional entries may include the broadcast sentinel
    /// (0xFFFF), zero and the software VHCA ID if available.
    pub(crate) fn uid_candidates(prev_uid: u16, is_vf: bool, sw_vhca_id: u16) -> ([u16; 4], usize) {
        let mut uids = [0u16; 4];
        let mut len = 0usize;

        let mut push_uid = |uid: u16| {
            if !uids[..len].contains(&uid) {
                uids[len] = uid;
                len += 1;
            }
        };

        push_uid(prev_uid);
        if is_vf {
            push_uid(0xFFFF);
            push_uid(0);
            if sw_vhca_id != 0 {
                push_uid(sw_vhca_id);
            }
        }

        (uids, len)
    }

    pub(crate) unsafe fn execute_with_uid_candidates<T, F, R>(
        cmd: &mut T,
        uid_candidates: &[u16],
        mut f: F,
    ) -> Mlx5Result<R>
    where
        T: CommandTransport,
        F: FnMut(&mut T) -> Mlx5Result<R>,
    {
        let prev_uid = cmd.uid();
        let mut last_err = Err(Mlx5Error::NotSupported);
        for &uid in uid_candidates {
            cmd.set_uid(uid);
            match f(cmd) {
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

    /// Execute a command, automatically cycling through reasonable UID values
    /// when running as a VF.  The transport UID is restored to its previous
    /// value on return.  This helper is heavily used during initialization where
    /// firmware may reject commands unless the correct VHCA UID is present.
    /// Internal implementation generic over any transport.  Allows tests to
    /// inject a fake `CommandTransport` instance and exercise UID cycling.
    pub(crate) unsafe fn execute_cmd_with_uid_candidates_impl<T: crate::cmd::CommandTransport>(
        cmd: &mut T,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
        is_vf: bool,
        sw_vhca_id: u16,
    ) -> Mlx5Result<()> {
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf, sw_vhca_id);
        Self::execute_with_uid_candidates(cmd, &uids[..len], |cmd| {
            cmd.execute(opcode, in_mbox_phys, in_len, out_mbox_phys, out_len)
        })
    }

    /// Execute a command through the standard UID candidate retry path used by
    /// opcodes whose mailbox UID lives at the fixed transport-managed offset.
    pub(crate) unsafe fn execute_uid_sensitive_cmd_impl<T: crate::cmd::CommandTransport>(
        cmd: &mut T,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
        is_vf: bool,
        sw_vhca_id: u16,
    ) -> Mlx5Result<()> {
        if !crate::cmd::CmdQueueTransport::opcode_uses_uid(opcode) {
            return Err(Mlx5Error::InvalidParameter);
        }

        Self::execute_cmd_with_uid_candidates_impl(
            cmd,
            opcode,
            in_mbox_phys,
            in_len,
            out_mbox_phys,
            out_len,
            is_vf,
            sw_vhca_id,
        )
    }

    /// Convenience wrapper that uses the device's own command transport.
    unsafe fn execute_cmd_with_uid_candidates(
        &mut self,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
    ) -> Mlx5Result<()> {
        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        if let Some(cmd) = self.cmd.as_mut() {
            Self::execute_cmd_with_uid_candidates_impl(
                cmd,
                opcode,
                in_mbox_phys,
                in_len,
                out_mbox_phys,
                out_len,
                is_vf,
                sw_vhca_id,
            )
        } else {
            Err(Mlx5Error::DeviceNotReady)
        }
    }

    /// Convenience wrapper for UID-sensitive opcodes that use the transport's
    /// fixed-offset UID injection logic.
    pub(crate) unsafe fn execute_uid_sensitive_cmd(
        &mut self,
        opcode: CmdOpcode,
        in_len: u32,
        out_len: u32,
    ) -> Mlx5Result<()> {
        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        if let Some(cmd) = self.cmd.as_mut() {
            Self::execute_uid_sensitive_cmd_impl(
                cmd,
                opcode,
                self.cmd_in_mbox_device,
                in_len,
                self.cmd_out_mbox_device,
                out_len,
                is_vf,
                sw_vhca_id,
            )
        } else {
            Err(Mlx5Error::DeviceNotReady)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTransport {
        uid: u16,
        success_uid: u16,
        calls: Vec<(CmdOpcode, u16)>,
    }

    impl FakeTransport {
        fn new(initial_uid: u16, success_uid: u16) -> Self {
            Self {
                uid: initial_uid,
                success_uid,
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
            self.calls.push((opcode, self.uid));
            if self.uid == self.success_uid {
                Ok(())
            } else {
                Err(Mlx5Error::CommandFailed(0x03))
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
    fn execute_uid_sensitive_cmd_impl_retries_create_sq_and_restores_uid() {
        let mut transport = FakeTransport::new(0x1234, 0xffff);

        unsafe {
            Mlx5Device::execute_uid_sensitive_cmd_impl(
                &mut transport,
                CmdOpcode::CreateSq,
                0x1000,
                0x120,
                0x2000,
                0x10,
                true,
                0x2222,
            )
        }
        .unwrap();

        assert_eq!(
            transport.calls,
            vec![(CmdOpcode::CreateSq, 0x1234), (CmdOpcode::CreateSq, 0xffff),]
        );
        assert_eq!(transport.uid(), 0x1234);
    }

    #[test]
    fn execute_uid_sensitive_cmd_impl_retries_destroy_mkey_through_all_candidates() {
        let mut transport = FakeTransport::new(0x1234, 0x2222);

        unsafe {
            Mlx5Device::execute_uid_sensitive_cmd_impl(
                &mut transport,
                CmdOpcode::DestroyMkey,
                0x1000,
                0x10,
                0x2000,
                0x10,
                true,
                0x2222,
            )
        }
        .unwrap();

        assert_eq!(
            transport.calls,
            vec![
                (CmdOpcode::DestroyMkey, 0x1234),
                (CmdOpcode::DestroyMkey, 0xffff),
                (CmdOpcode::DestroyMkey, 0),
                (CmdOpcode::DestroyMkey, 0x2222),
            ]
        );
        assert_eq!(transport.uid(), 0x1234);
    }

    #[test]
    fn execute_uid_sensitive_cmd_impl_rejects_vhca_state_opcodes() {
        let mut transport = FakeTransport::new(0x1234, 0x1234);

        let err = unsafe {
            Mlx5Device::execute_uid_sensitive_cmd_impl(
                &mut transport,
                CmdOpcode::QueryVhcaState,
                0x1000,
                0x10,
                0x2000,
                0x20,
                true,
                0x2222,
            )
        }
        .unwrap_err();

        assert_eq!(err, Mlx5Error::InvalidParameter);
        assert!(transport.calls.is_empty());
    }
}
