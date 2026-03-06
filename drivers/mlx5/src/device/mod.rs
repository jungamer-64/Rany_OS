// ============================================================================
// drivers/mlx5/src/device/mod.rs - MLX5 Device Core
// ============================================================================

extern crate alloc;
use alloc::vec; // bring `vec!` macro
use alloc::vec::Vec;
use crate::cmd::{CmdQueue, CmdMailbox, CommandTransport};
// CmdOpcode/Status are defined in defs and are re-exported there.
use crate::defs::{CmdOpcode, CmdStatus, ConnectXVariant, HcaCaps, MLX5_CMD_MBOX_SIZE, PortLinkState};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::eq::{EventQueue, decode_eqe};
use crate::cq::CompletionQueue;
use crate::flow::{FlowTable, FlowGroup, FlowTableEntry, RqTable};
use crate::resources::{MkeyInfo, TisInfo, TirInfo, MkeyParams};
use crate::pages::PageManager;
use crate::port::Mlx5Port;
use crate::polling::AdaptivePollingState;
use crate::health::HealthMonitor;
use crate::wq::{SendQueue, ReceiveQueue};

pub mod init;
pub mod caps;
pub mod res;
pub mod pages;
pub mod queues;
pub mod ops;
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
    
    // Queues
    pub(crate) eqs: Vec<EventQueue>,
    pub(crate) cqs: Vec<CompletionQueue>,
    pub(crate) sqs: Vec<SendQueue>,
    pub(crate) rqs: Vec<ReceiveQueue>,
    pub(crate) rq_tables: Vec<RqTable>,
    pub(crate) cq_db_records: Vec<(u64, u64)>,
    
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
            eqs: Vec::new(),
            cqs: Vec::new(),
            sqs: Vec::new(),
            rqs: Vec::new(),
            rq_tables: Vec::new(),
            cq_db_records: Vec::new(),
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

    pub fn is_vf(&self) -> bool {
        ConnectXVariant::is_vf_device_id(self.device_id)
    }

    pub fn hca_caps(&self) -> Option<&HcaCaps> {
        self.hca_caps.as_ref()
    }

    /// Build the list of UID candidates that should be tried for commands when
    /// running in VF mode.  The first entry is always the previous UID stored
    /// in the transport; additional entries may include the broadcast sentinel
    /// (0xFFFF), zero and the software VHCA ID if available.
    pub(crate) fn uid_candidates(&self, prev_uid: u16) -> Vec<u16> {
        let mut uids = Vec::new();
        uids.push(prev_uid);
        if self.is_vf() {
            // common fallbacks observed in vendor driver
            uids.push(0xFFFF);
            uids.push(0);
            if self.sw_vhca_id != 0 && !uids.contains(&self.sw_vhca_id) {
                uids.push(self.sw_vhca_id);
            }
        }
        uids
    }

    /// Execute a command, automatically cycling through reasonable UID values
    /// when running as a VF.  The transport UID is restored to its previous
    /// value on return.  This helper is heavily used during initialization where
    /// firmware may reject commands unless the correct VHCA UID is present.
    /// Internal implementation generic over any transport.  Allows tests to
    /// inject a fake `CommandTransport` instance and exercise UID cycling.
    pub(crate) unsafe fn execute_cmd_with_uid_candidates_impl<T: crate::cmd::CommandTransport>(
        &mut self,
        cmd: &mut T,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
    ) -> Mlx5Result<()> {
        // record previous UID and build candidate list before mutably borrowing cmd
        let prev_uid = cmd.uid();
        let uids = self.uid_candidates(prev_uid);
        let mut last_err: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for &uid in &uids {
            cmd.set_uid(uid);
            let res = cmd.execute(opcode, in_mbox_phys, in_len, out_mbox_phys, out_len);
            if res.is_ok() {
                last_err = Ok(());
                break;
            }
            last_err = res;
        }
        cmd.set_uid(prev_uid);
        last_err
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
        // avoid holding a borrow across the method call by performing the
        // borrow inside the argument expression
        if let Some(cmd) = self.cmd.as_mut() {
            self.execute_cmd_with_uid_candidates_impl(
                cmd,
                opcode,
                in_mbox_phys,
                in_len,
                out_mbox_phys,
                out_len,
            )
        } else {
            Err(Mlx5Error::DeviceNotReady)
        }
    }
}

