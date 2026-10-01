// ============================================================================
// drivers/mlx5/src/device/mod.rs - MLX5 Device Core
// ============================================================================

extern crate alloc;
use crate::cmd::{CmdMailbox, CmdQueue};
use crate::cq::CompletionQueue;
use crate::defs::{CmdOpcode, ConnectXVariant, HcaCaps};
use crate::eq::EventQueue;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::{FlowGroup, FlowTable, FlowTableEntry, RqTable};
use crate::fw::FwInfo;
use crate::health::HealthMonitor;
use crate::pages::FirmwarePages;
use crate::polling::AdaptivePollingState;
use crate::port::Mlx5Port;
use crate::resources::{MkeyInfo, TirInfo, TisInfo, TisOwnership};
use crate::wq::{ReceiveQueue, SendQueue};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use kernel_api::abi::driver::PackedPciLocation;

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
    /// Reset was requested; no DMA-revocation authority follows from this state.
    ResetPending,
    /// Reset acknowledgement was not observed; all prior resources stay retained.
    ResetOutcomeUnknown,
}

/// ConnectX デバイス抽象化
pub struct Mlx5Device {
    // Hardware info
    pub(crate) registers: crate::registers::InitializationRegisters,
    pub(crate) device_id: u16,
    pub(crate) variant: ConnectXVariant,

    // Core state
    pub(crate) state: DeviceState,
    pub(crate) fw_info: Option<FwInfo>,
    pub(crate) hca_caps: Option<HcaCaps>,

    // Command IF
    pub(crate) cmd: Option<CmdQueue>,
    pub(crate) cmd_output: Box<CmdMailbox>,

    // Memory/Pages
    pub(crate) fw_function_id: u16,
    pub(crate) firmware_pages: Option<FirmwarePages>,
    pub(crate) command_generation: u64,

    // Resources
    pub(crate) uar: Option<crate::registers::UarRegisters>,
    pub(crate) pd: u32,
    pub(crate) td: u32,
    pub(crate) mkey: u32,
    pub(crate) tx_mkey: u32,
    pub(crate) underlay_qpn: u32,
    pub(crate) mkey_info: Option<MkeyInfo>,
    pub(crate) sw_vhca_id: u16,
    pub(crate) sw_owner_id: [u32; 4],
    pub(crate) vnic_env_query_logged: bool,
    pub(crate) resources_allocated: bool,
    pub(crate) is_vf: bool,
    pub(crate) is_ecpf: bool,

    pub(crate) pci_segment: u16,
    pub(crate) pci_bus: u8,
    pub(crate) pci_device: u8,
    pub(crate) pci_function: u8,

    // Queues
    pub(crate) eqs: Vec<EventQueue>,
    pub(crate) cqs: Vec<CompletionQueue>,
    pub(crate) sqs: Vec<SendQueue>,
    pub(crate) rqs: Vec<ReceiveQueue>,
    pub(crate) rmp_list: Vec<u32>,
    pub(crate) rq_tables: Vec<RqTable>,
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
    allocated_uars: Vec<UarAllocation>,
    pub(crate) tx_path_enabled: bool,
    pub(crate) tx_probe_pending: bool,
    pub(crate) tx_probe_verified: bool,
    pub(crate) tx_implicit_tis0_fallback: bool,
}

// Types moved to crate::flow

/// A firmware grant is retained even if its BAR geometry is unusable. UID is
/// part of the release identity and must not be rediscovered through retries.
struct UarAllocation {
    number: u32,
    uid: u16,
}

impl Mlx5Device {
    fn splitmix64_step(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn derive_sw_owner_id(&self) -> [u32; 4] {
        let mut seed = self.command_generation
            ^ ((self.device_id as u64) << 32)
            ^ ((self.pci_segment as u64) << 40)
            ^ ((self.pci_bus as u64) << 24)
            ^ ((self.pci_device as u64) << 16)
            ^ ((self.pci_function as u64) << 8);
        if seed == 0 {
            seed = 0x6A09_E667_F3BC_C909;
        }

        let mut words = [0u32; 4];
        for word in &mut words {
            let mixed = Self::splitmix64_step(&mut seed);
            *word = (mixed as u32) ^ ((mixed >> 32) as u32);
        }
        if words == [0; 4] {
            words[0] = 1;
        }
        words
    }

    /// Acquires register authority by consuming the mapping, never an address.
    ///
    /// # Errors
    /// Returns the original mapping with a geometry or staging allocation error,
    /// before device I/O or DMA publication.
    pub fn new(
        mapping: hal::mmio::MappedMmio,
        device_id: u16,
    ) -> Result<Self, (hal::mmio::MappedMmio, Mlx5Error)> {
        if let Err(error) = crate::registers::InitializationRegisters::validate(&mapping) {
            return Err((mapping, error.into()));
        }
        let cmd_output = match CmdMailbox::allocate() {
            Ok(mailbox) => mailbox,
            Err(cause) => return Err((mapping, cause)),
        };
        let variant = ConnectXVariant::from_device_id(device_id);
        Ok(Self {
            registers: crate::registers::InitializationRegisters::new(mapping),
            device_id,
            variant,
            state: DeviceState::Uninitialized,
            fw_info: None,
            hca_caps: None,
            cmd: None,
            cmd_output,
            fw_function_id: 0,
            firmware_pages: None,
            command_generation: 0,
            uar: None,
            pd: 0,
            td: 0,
            mkey: 0,
            tx_mkey: 0,
            underlay_qpn: 0,
            mkey_info: None,
            sw_vhca_id: 0,
            sw_owner_id: [0; 4],
            vnic_env_query_logged: false,
            resources_allocated: false,
            is_vf: ConnectXVariant::is_vf_device_id(device_id),
            is_ecpf: false,
            pci_segment: 0,
            pci_bus: 0,
            pci_device: 0,
            pci_function: 0,
            eqs: Vec::new(),
            cqs: Vec::new(),
            sqs: Vec::new(),
            rqs: Vec::new(),
            rmp_list: Vec::new(),
            rq_tables: Vec::new(),
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
            tx_path_enabled: false,
            tx_probe_pending: false,
            tx_probe_verified: false,
            tx_implicit_tis0_fallback: false,
        })
    }

    pub fn state(&self) -> DeviceState {
        self.state
    }

    pub fn variant(&self) -> ConnectXVariant {
        self.variant
    }

    pub fn fw_info(&self) -> Option<&FwInfo> {
        self.fw_info.as_ref()
    }

    pub fn is_vf(&self) -> bool {
        self.is_vf
    }

    pub(crate) fn packed_device_id(&self) -> PackedPciLocation {
        PackedPciLocation::new(
            self.pci_segment,
            self.pci_bus,
            self.pci_device,
            self.pci_function,
        )
    }

    pub fn dma_device_id(&self) -> u64 {
        self.packed_device_id().raw()
    }

    /// Physical Function かどうか判定
    pub fn is_pf(&self) -> bool {
        !self.is_vf && !self.is_ecpf
    }

    /// SmartNIC / DPU 内蔵 CPU (ECPU) かどうか判定
    pub fn is_ecpf(&self) -> bool {
        self.is_ecpf
    }

    /// VF 判定 (device-id 優先)
    ///
    /// SR-IOV capability の可視性は仮想化経路で欠落することがあるため、
    /// PF を VF と誤判定しないよう device-id ベース判定を優先する。
    pub fn is_vf_robust(&self, _has_sriov_cap: bool) -> bool {
        self.is_vf()
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

    /// # Errors
    /// A live command/page owner cannot be rebound to another PCI identity.
    pub fn set_pci_location(
        &mut self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Mlx5Result<()> {
        if self.cmd.is_some() || self.firmware_pages.is_some() {
            return Err(Mlx5Error::DeviceNotReady);
        }
        self.pci_segment = segment;
        self.pci_bus = bus;
        self.pci_device = device;
        self.pci_function = function;
        Ok(())
    }

    pub fn pci_location(&self) -> (u16, u8, u8, u8) {
        (
            self.pci_segment,
            self.pci_bus,
            self.pci_device,
            self.pci_function,
        )
    }

    pub fn num_rqs(&self) -> usize {
        self.rqs.len()
    }

    pub fn num_sqs(&self) -> usize {
        self.sqs.len()
    }

    pub fn tx_path_enabled(&self) -> bool {
        self.tx_path_enabled
    }

    pub fn tx_uses_implicit_tis0(&self) -> bool {
        self.tx_implicit_tis0_fallback
    }

    pub fn tx_is_runtime_healthy(&self) -> bool {
        self.tx_path_enabled && (!self.tx_probe_pending || self.tx_probe_verified)
    }

    pub(crate) fn set_tx_runtime_state(
        &mut self,
        tx_path_enabled: bool,
        implicit_tis0_fallback: bool,
    ) {
        self.tx_path_enabled = tx_path_enabled;
        self.tx_implicit_tis0_fallback = tx_path_enabled && implicit_tis0_fallback;
        self.tx_probe_pending = tx_path_enabled && self.is_vf();
        self.tx_probe_verified = tx_path_enabled && !self.tx_probe_pending;
    }

    pub fn mark_tx_runtime_probe_success(&mut self) -> bool {
        if !self.tx_path_enabled || !self.tx_probe_pending {
            return false;
        }

        self.tx_probe_pending = false;
        self.tx_probe_verified = true;
        true
    }

    pub fn mark_tx_runtime_broken(&mut self) -> bool {
        let changed = self.tx_path_enabled
            || self.tx_probe_pending
            || self.tx_probe_verified
            || self.tx_implicit_tis0_fallback;
        self.tx_path_enabled = false;
        self.tx_probe_pending = false;
        self.tx_probe_verified = false;
        self.tx_implicit_tis0_fallback = false;
        changed
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

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn teardown(&mut self) -> Mlx5Result<()> {
        self.teardown_full()
    }

    fn debug_dump_mailbox_words(tag: &str, mbox: &crate::cmd::CmdMailbox, dwords: usize) {
        Self::debug_dump_mailbox_range(tag, mbox, 0, dwords);
    }

    fn debug_dump_mailbox_range(
        tag: &str,
        mbox: &crate::cmd::CmdMailbox,
        start: usize,
        dwords: usize,
    ) {
        if !cfg!(feature = "debug_mlx5_cmd") {
            return;
        }
        let aligned_start = start & !0x3;
        let max_bytes = crate::defs::MLX5_CMD_MBOX_SIZE.saturating_sub(aligned_start);
        let count = dwords.min(max_bytes / 4).min(128);
        for i in 0..count {
            let off = aligned_start + i * 4;
            log::info!(
                target: "mlx5",
                "[mlx5-diag] {} out[{:#04x}]={:#010x}",
                tag,
                off,
                mbox.read_be32(off)
            );
        }
    }

    fn object_id_scan_windows(max_scan: u32) -> Vec<(u32, u32)> {
        const PREFIXES: [u32; 16] = [
            0x0000_0000,
            0x0040_0000,
            0x0080_0000,
            0x00c0_0000,
            0x0010_0000,
            0x0020_0000,
            0x0030_0000,
            0x0050_0000,
            0x0060_0000,
            0x0070_0000,
            0x0090_0000,
            0x00a0_0000,
            0x00b0_0000,
            0x00d0_0000,
            0x00e0_0000,
            0x00f0_0000,
        ];

        let window_count = core::cmp::min(max_scan.max(1) as usize, PREFIXES.len());
        let base_budget = max_scan / window_count as u32;
        let mut remainder = max_scan % window_count as u32;
        let mut windows = Vec::with_capacity(window_count);

        for &base in &PREFIXES[..window_count] {
            let extra = if remainder != 0 {
                remainder -= 1;
                1
            } else {
                0
            };
            windows.push((base, (base_budget + extra).max(1)));
        }

        windows
    }

    pub(crate) fn record_tis_info(&mut self, tisn: u32, port: u8, ownership: TisOwnership) {
        if let Some(existing) = self.tis_list.iter_mut().find(|info| info.tisn == tisn) {
            existing.port = port;
            if matches!(ownership, TisOwnership::DriverCreated) {
                existing.ownership = TisOwnership::DriverCreated;
            }
            return;
        }

        self.tis_list.push(TisInfo {
            tisn,
            port,
            ownership,
        });
    }

    /// Build the list of mailbox UID candidates that should be tried for
    /// transport-managed commands.  This is distinct from INIT_HCA's
    /// software VHCA ID and should only carry mailbox header UID values.
    pub(crate) fn uid_candidates(prev_uid: u16, is_vf: bool) -> ([u16; 3], usize) {
        let mut uids = [0u16; 3];
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
        } else {
            // PF mailbox commands should stay in the base namespace (UID 0).
            // If a stale non-zero UID leaked in, try UID 0 as the only fallback.
            push_uid(0);
        }

        (uids, len)
    }

    fn uid_candidates_for_opcode(
        prev_uid: u16,
        is_vf: bool,
        opcode: CmdOpcode,
    ) -> ([u16; 4], usize) {
        let (base, base_len) = Self::uid_candidates(prev_uid, is_vf);
        let mut uids = [0u16; 4];
        let mut len = 0usize;

        let mut push_uid = |uid: u16| {
            if !uids[..len].contains(&uid) {
                uids[len] = uid;
                len += 1;
            }
        };

        if is_vf {
            match opcode {
                // VF の CREATE_EQ は 0xffff が先に通る個体が多い。
                CmdOpcode::CreateEq => push_uid(0xFFFF),
                // VF の CREATE_RQ / CREATE_RMP / CREATE_TIR は UID 0 が先に通りやすい。
                CmdOpcode::CreateRq | CmdOpcode::CreateRmp | CmdOpcode::CreateTir => push_uid(0),
                _ => {}
            }
        }

        for &uid in &base[..base_len] {
            push_uid(uid);
        }

        (uids, len)
    }

    /// Only a completed firmware rejection admits another UID attempt. A
    /// timeout, malformed response, registry failure or delivery error stops
    /// immediately with the command owner retained.
    fn execute_cmd_with_uid_candidates(
        &mut self,
        opcode: CmdOpcode,
        input: &CmdMailbox,
        in_len: u32,
        out_len: u32,
    ) -> Mlx5Result<()> {
        let is_vf = self.is_vf();
        let command = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let previous = command.uid();
        let result = if CmdQueue::opcode_uses_uid(opcode) {
            let (uids, count) = Self::uid_candidates_for_opcode(previous, is_vf, opcode);
            try_uid_candidates(&uids[..count], |uid| {
                command.set_uid(uid);
                command.execute(opcode, input, in_len, &mut self.cmd_output, out_len)
            })
        } else {
            command.execute(opcode, input, in_len, &mut self.cmd_output, out_len)
        };
        command.set_uid(previous);
        result
    }

    pub(crate) fn execute_uid_sensitive_cmd(
        &mut self,
        opcode: CmdOpcode,
        input: &CmdMailbox,
        in_len: u32,
        out_len: u32,
    ) -> Mlx5Result<()> {
        if !CmdQueue::opcode_uses_uid(opcode) {
            return Err(Mlx5Error::InvalidParameter);
        }
        self.execute_cmd_with_uid_candidates(opcode, input, in_len, out_len)
    }

    pub(crate) fn default_sw_vhca_id(&self) -> u16 {
        let raw = ((self.pci_bus as u16) << 8)
            | ((self.pci_device as u16) << 3)
            | (self.pci_function as u16);
        let masked = raw & 0x3fff;
        if masked == 0 { 1 } else { masked }
    }
}

/// The callback reports CommandFailed only after a known firmware response;
/// side-effecting page supply has its own one-shot publication protocol.
fn try_uid_candidates<T>(
    uids: &[u16],
    mut execute: impl FnMut(u16) -> Mlx5Result<T>,
) -> Mlx5Result<T> {
    let mut rejection = Mlx5Error::NotSupported;
    for &uid in uids {
        match execute(uid) {
            Ok(value) => return Ok(value),
            Err(cause @ Mlx5Error::CommandFailed(_)) => rejection = cause,
            Err(cause) => return Err(cause),
        }
    }
    Err(rejection)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_rejection_can_advance_but_uncertain_outcome_cannot() {
        let mut seen = Vec::new();
        let chosen = try_uid_candidates(&[0x1234, 0xffff, 0], |uid| {
            seen.push(uid);
            if uid == 0xffff {
                Ok(uid)
            } else {
                Err(Mlx5Error::CommandFailed(3))
            }
        })
        .unwrap();
        assert_eq!(chosen, 0xffff);
        assert_eq!(seen, [0x1234, 0xffff]);
        for failure in [
            Mlx5Error::CommandTimeout,
            Mlx5Error::InvalidResponse,
            Mlx5Error::CommandDelivery(3),
            Mlx5Error::DeviceNotReady,
        ] {
            let mut attempts = 0;
            let result: Mlx5Result<()> = try_uid_candidates(&[0x1234, 0xffff, 0], |_| {
                attempts += 1;
                Err(failure)
            });
            assert_eq!(result, Err(failure));
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn uid_candidates_preserve_vf_command_selection_and_pf_scope() {
        let (uids, count) = Mlx5Device::uid_candidates(0x1234, false);
        assert_eq!(&uids[..count], [0x1234, 0]);
        let (uids, count) = Mlx5Device::uid_candidates(0, false);
        assert_eq!(&uids[..count], [0]);
        let (uids, count) =
            Mlx5Device::uid_candidates_for_opcode(0x1234, true, CmdOpcode::CreateEq);
        assert_eq!(&uids[..count], [0xffff, 0x1234, 0]);
    }
}
