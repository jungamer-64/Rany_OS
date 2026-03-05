// ============================================================================
// drivers/mlx5/src/device.rs - Device Management
// ============================================================================
//! ConnectX ファミリ デバイス管理
//!
//! HCA (Host Channel Adapter) の完全なライフサイクル管理:
//! 1. PCIデバイス検出とBAR0マッピング
//! 2. FW初期化・コマンドインタフェースセットアップ
//! 3. HCA有効化・初期化シーケンス
//! 4. キュー作成（EQ, CQ, SQ, RQ）
//! 5. NICポート設定
//! 6. パケット送受信

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::cmd::{CmdMailbox, CmdQueueTransport, CommandTransport};
use crate::cq::CompletionQueue;
use crate::defs::ConnectXVariant;
use crate::defs::*;
use crate::eq::{decode_eqe, EqEvent, EventQueue};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::{FlowGroup, FlowTable, FlowTableConfig, FlowTableEntry, RqTable, RssConfig};
use crate::fw::{self, FwInfo};
use crate::pages::PageManager;
use crate::polling::AdaptivePollingState;
use crate::port::{MacAddr, Mlx5Port};
use crate::resources::{
    MkeyInfo, MkeyParams, TirInfo, TirParams, TirReceiveType, TisInfo, TisParams,
};
use crate::wq::{ReceiveQueue, SendQueue};

/// デバイスの初期化状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// 未初期化
    Uninitialized,
    /// FWレディ
    FirmwareReady,
    /// HCA有効化済み
    HcaEnabled,
    /// HCA初期化済み
    HcaInitialized,
    /// キュー作成済み
    QueuesReady,
    /// アクティブ（送受信可能）
    Active,
    /// エラー状態
    Error,
}

/// mlx5 デバイス
///
/// ConnectX ファミリ NIC の完全な状態を管理する。
/// BAR0マッピング、コマンドインタフェース、キュー、ポートを含む。
pub struct Mlx5Device {
    /// デバイスバリアント (ConnectX-4 / 5 / 6 / 7 etc.)
    variant: ConnectXVariant,
    /// PCI Device ID (PF/VF 判別を含む初期化ポリシー判定に使用)
    device_id: u16,
    /// デバイス状態
    state: DeviceState,
    /// BAR0 仮想ベースアドレス
    bar0_base: u64,
    /// BAR0 サイズ
    bar0_size: usize,

    /// ファームウェア情報
    fw_info: Option<FwInfo>,
    /// HCAキャパビリティ
    hca_caps: Option<HcaCaps>,

    /// コマンド転送インタフェース
    cmd: Option<Box<dyn CommandTransport + Send>>,
    /// コマンド入力メールボックス（仮想アドレス）
    cmd_in_mbox_virt: u64,
    /// コマンド入力メールボックス（DMA物理アドレス）
    cmd_in_mbox_phys: u64,
    /// コマンド出力メールボックス（仮想アドレス）
    cmd_out_mbox_virt: u64,
    /// コマンド出力メールボックス（DMA物理アドレス）
    cmd_out_mbox_phys: u64,

    /// Event Queues
    eqs: Vec<EventQueue>,
    /// Completion Queues
    cqs: Vec<CompletionQueue>,
    /// Send Queues
    sqs: Vec<SendQueue>,
    /// Receive Queues
    rqs: Vec<ReceiveQueue>,

    /// NICポート（最大2）
    ports: Vec<Mlx5Port>,

    /// Memory Key (Direct Memory Key for all DMA)
    mkey: u32,

    /// UAR (User Access Region) ベースアドレス
    uar_base: u64,
    /// UAR番号
    uar_page: u32,

    /// PCI BDF情報
    pci_bus: u8,
    pci_device: u8,
    pci_function: u8,

    /// ページマネージャ（FW ページ管理）
    page_manager: PageManager,
    /// FW command pathで使用する function_id（QUERY_PAGESで更新）
    fw_function_id: u16,
    /// INIT_HCA で使用する software VHCA ID（query_hca_cap 由来）
    sw_vhca_id: u16,

    /// TIS (Transport Interface Send) 情報
    tis_list: Vec<TisInfo>,

    /// TIR (Transport Interface Receive) 情報
    tir_list: Vec<TirInfo>,

    /// MKEY 情報
    mkey_info: Option<MkeyInfo>,

    /// フローテーブル
    flow_tables: Vec<FlowTable>,

    /// フローグループ
    flow_groups: Vec<FlowGroup>,

    /// フローテーブルエントリ
    flow_entries: Vec<FlowTableEntry>,

    /// RQT（RSSテーブル）
    rq_tables: Vec<RqTable>,

    /// 適応的ポーリング状態
    polling_state: AdaptivePollingState,

    /// Protection Domain 番号
    pd: u32,
    /// Transport Domain 番号
    td: u32,

    /// 割り当て済みUAR番号リスト（teardown時に解放）
    allocated_uars: Vec<u32>,

    /// CQドアベルレコードの仮想/物理アドレスペア
    cq_db_records: Vec<(u64, u64)>,

    /// ドライバ初期化済みフラグ（リソース割り当て完了）
    resources_allocated: bool,
}

impl Mlx5Device {
    /// デバイスを作成（未初期化状態）
    ///
    /// `device_id` から `ConnectXVariant` を自動判別する。
    pub fn new(bar0_base: u64, bar0_size: usize, device_id: u16) -> Self {
        Self {
            variant: ConnectXVariant::from_device_id(device_id),
            device_id,
            state: DeviceState::Uninitialized,
            bar0_base,
            bar0_size,
            fw_info: None,
            hca_caps: None,
            cmd: None,
            cmd_in_mbox_virt: 0,
            cmd_in_mbox_phys: 0,
            cmd_out_mbox_virt: 0,
            cmd_out_mbox_phys: 0,
            eqs: Vec::new(),
            cqs: Vec::new(),
            sqs: Vec::new(),
            rqs: Vec::new(),
            ports: Vec::new(),
            mkey: 0,
            uar_base: 0,
            uar_page: 0,
            pci_bus: 0,
            pci_device: 0,
            pci_function: 0,
            page_manager: PageManager::new(),
            fw_function_id: 0,
            sw_vhca_id: 0,
            tis_list: Vec::new(),
            tir_list: Vec::new(),
            mkey_info: None,
            flow_tables: Vec::new(),
            flow_groups: Vec::new(),
            flow_entries: Vec::new(),
            rq_tables: Vec::new(),
            polling_state: AdaptivePollingState::with_defaults(),
            pd: 0,
            td: 0,
            allocated_uars: Vec::new(),
            cq_db_records: Vec::new(),
            resources_allocated: false,
        }
    }

    /// ConnectX バリアントを取得
    pub fn variant(&self) -> ConnectXVariant {
        self.variant
    }

    /// EQ番号に対応するMSI-Xベクタを取得
    pub fn eqn_msix_vector(&self, eq_index: usize) -> Option<u32> {
        self.eqs.get(eq_index).map(|eq| eq.msix_vector)
    }

    /// このデバイスが SR-IOV Virtual Function かどうかを返す。
    pub fn is_virtual_function(&self) -> bool {
        ConnectXVariant::is_vf_device_id(self.device_id)
    }

    /// PCI BDF情報を設定
    pub fn set_pci_bdf(&mut self, bus: u8, device: u8, function: u8) {
        self.pci_bus = bus;
        self.pci_device = device;
        self.pci_function = function;
    }

    /// デバイス状態を取得
    pub fn state(&self) -> DeviceState {
        self.state
    }

    /// Force firmware-ready state for VF fallback paths.
    ///
    /// Some VF passthrough environments do not expose PF-style FW boot phase
    /// transitions via init-segment state bits, causing `wait_fw_ready()` to fail even
    /// though command interface operations can still succeed.
    pub fn assume_firmware_ready_for_vf(&mut self) {
        if self.state == DeviceState::Uninitialized {
            self.state = DeviceState::FirmwareReady;
        }
    }

    /// BAR0ベースアドレス
    pub fn bar0_base(&self) -> u64 {
        self.bar0_base
    }

    /// ファームウェア情報
    pub fn fw_info(&self) -> Option<&FwInfo> {
        self.fw_info.as_ref()
    }

    /// HCAキャパビリティ
    pub fn hca_caps(&self) -> Option<&HcaCaps> {
        self.hca_caps.as_ref()
    }

    /// ポート情報を取得（0-indexed）
    pub fn port(&self, index: usize) -> Option<&Mlx5Port> {
        self.ports.get(index)
    }

    /// ポート情報を取得（可変）
    pub fn port_mut(&mut self, index: usize) -> Option<&mut Mlx5Port> {
        self.ports.get_mut(index)
    }

    /// ポート数
    pub fn num_ports(&self) -> usize {
        self.ports.len()
    }

    /// アクティブかどうか
    pub fn is_active(&self) -> bool {
        self.state == DeviceState::Active
    }

    /// Protection Domain 番号
    pub fn pd(&self) -> u32 {
        self.pd
    }

    /// Transport Domain 番号
    pub fn td(&self) -> u32 {
        self.td
    }

    fn debug_dump_mailbox_words(tag: &str, mbox: &CmdMailbox, dwords: usize) {
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

    // ========================================================================
    // Phase 1: Firmware Ready Wait
    // ========================================================================

    /// ファームウェアの準備を待つ
    ///
    /// # Safety
    /// - bar0_base が有効なMMIOマッピングであること
    pub unsafe fn wait_firmware(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Waiting for firmware ready...");

        let fw_info = fw::wait_fw_ready(self.bar0_base)?;

        log::info!(
            target: "mlx5",
            "FW version: {}.{}.{}, CMD IF rev: {}",
            fw_info.major, fw_info.minor, fw_info.subminor, fw_info.cmd_if_rev
        );

        self.fw_info = Some(fw_info);
        self.state = DeviceState::FirmwareReady;
        Ok(())
    }

    // ========================================================================
    // Phase 2: Command Interface Setup
    // ========================================================================

    /// コマンドインタフェースを初期化
    ///
    /// DMAメモリを割り当ててコマンドキューとメールボックスを設定する。
    ///
    /// # Safety
    /// - DMA関連の物理/仮想アドレスが有効であること
    pub unsafe fn init_command_interface(
        &mut self,
        cmdq_virt: u64,
        cmdq_phys: u64,
        in_mbox_virt: u64,
        in_mbox_phys: u64,
        out_mbox_virt: u64,
        out_mbox_phys: u64,
    ) -> Mlx5Result<()> {
        if self.state != DeviceState::FirmwareReady {
            return Err(Mlx5Error::DeviceNotReady);
        }

        self.cmd_in_mbox_virt = in_mbox_virt;
        self.cmd_in_mbox_phys = in_mbox_phys;
        self.cmd_out_mbox_virt = out_mbox_virt;
        self.cmd_out_mbox_phys = out_mbox_phys;

        let base = self.bar0_base as usize;
        let cmdif_rev_fw_sub =
            crate::mmio_read_be32(base + crate::regs::init_seg::CMDIF_REV_FW_SUB);
        let cmd_if_rev = (cmdif_rev_fw_sub >> 16) as u16;
        let fw_subminor = (cmdif_rev_fw_sub & 0xFFFF) as u16;
        let cmdq_addr_h = crate::mmio_read_be32(base + crate::regs::init_seg::CMDQ_ADDR_H);
        let cmdq_addr_l_sz = crate::mmio_read_be32(base + crate::regs::init_seg::CMDQ_ADDR_L_SZ);
        let (log_cmdq_size, log_cmd_stride, nic_if_supported) =
            CmdQueueTransport::parse_hw_cmdq_layout(cmdq_addr_l_sz);

        let cmd = CmdQueueTransport::new(
            self.bar0_base,
            cmdq_phys,
            cmdq_virt,
            self.cmd_in_mbox_virt,
            self.cmd_out_mbox_virt,
            log_cmdq_size,
            log_cmd_stride,
        )?;
        cmd.setup_cmdq_in_bar0();

        let cmdq_prog_h = crate::mmio_read_be32(base + crate::regs::init_seg::CMDQ_ADDR_H);
        let cmdq_prog_l_sz = crate::mmio_read_be32(base + crate::regs::init_seg::CMDQ_ADDR_L_SZ);
        log::debug!(
            target: "mlx5",
            "CMD IF regs: nic_if_sup={} cmd_if_rev={:#06x} fw_sub={:#06x} log_sz={} stride_log={} hw_cmdq_h={:#010x} hw_cmdq_l_sz={:#010x} prog_cmdq_h={:#010x} prog_cmdq_l_sz={:#010x}",
            nic_if_supported,
            cmd_if_rev,
            fw_subminor,
            log_cmdq_size,
            log_cmd_stride,
            cmdq_addr_h,
            cmdq_addr_l_sz,
            cmdq_prog_h,
            cmdq_prog_l_sz
        );

        self.cmd = Some(Box::new(cmd));

        log::info!(target: "mlx5", "Command interface initialized");
        Ok(())
    }

    // ========================================================================
    // Phase 3: HCA Enable & Capability Setup
    // ========================================================================

    /// HCA有効化と能力設定シーケンスを実行（INIT_HCA は実行しない）
    ///
    /// # Safety
    /// - コマンドインタフェースが初期化済みであること
    pub unsafe fn enable_hca_and_setup(&mut self) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        // 1. ENABLE_HCA
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_enable_hca_input(in_mbox, 0);
        cmd.execute(
            CmdOpcode::EnableHca,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        log::info!(target: "mlx5", "HCA enabled");

        self.state = DeviceState::HcaEnabled;

        // 2. QUERY_ISSI → SET_ISSI
        {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            *in_mbox = CmdMailbox::zeroed();
            let issi = match cmd.execute(
                CmdOpcode::QueryIssi,
                self.cmd_in_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    Self::debug_dump_mailbox_words("QUERY_ISSI", out_mbox, 12);
                    crate::cmd::parse_query_issi(out_mbox)
                }
                Err(Mlx5Error::CommandFailed(code))
                    if code == CmdStatus::BadOpcode as u8 || code == CmdStatus::BadParam as u8 =>
                {
                    log::debug!(
                        target: "mlx5",
                        "QUERY_ISSI unsupported by FW/status={:#x}; fallback to ISSI=0",
                        code
                    );
                    0
                }
                Err(err) => return Err(err),
            };
            log::info!(target: "mlx5", "ISSI version: {}", issi);

            if issi > 0 {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_set_issi_input(in_mbox, 1);
                cmd.execute(
                    CmdOpcode::SetIssi,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                )?;
            }
        }

        // 3. QUERY_HCA_CAP (General)
        {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            crate::cmd::build_query_hca_cap_input(in_mbox, 0x0); // General
            cmd.execute(
                CmdOpcode::QueryHcaCap,
                self.cmd_in_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
            )?;

            let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
            Self::debug_dump_mailbox_words("QUERY_HCA_CAP", out_mbox, 24);
            let mut queried_capability = [0u8; MLX5_CMD_MBOX_SIZE - 0x10];
            let queried_cap_len = queried_capability.len();
            queried_capability.copy_from_slice(&out_mbox.data[0x10..0x10 + queried_cap_len]);
            // mlx5_ifc_cmd_hca_cap_bits.vhca_id is at cap offset bytes [6..8).
            let vhca_id = out_mbox
                .data
                .get(0x16..0x18)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                .unwrap_or(0);
            if vhca_id != 0 {
                self.sw_vhca_id = vhca_id & 0x3FFF;
                log::debug!(
                    target: "mlx5",
                    "Observed HCA caps vhca_id={:#06x}; init_hca sw_vhca_id={:#06x}, command uid remains {}",
                    vhca_id,
                    self.sw_vhca_id,
                    cmd.uid()
                );
            }
            let caps = fw::parse_hca_caps(&out_mbox.data);
            log::info!(
                target: "mlx5",
                "HCA caps: ports={}, max_cq={}, max_sq={}, max_rq={}, csum={}",
                caps.num_ports, caps.max_cq, caps.max_sq, caps.max_rq, caps.csum_cap
            );

            let num_ports = caps.num_ports.max(1).min(MLX5_MAX_PORTS as u8);
            for i in 0..num_ports {
                self.ports.push(Mlx5Port::new(i + 1));
            }
            self.hca_caps = Some(caps);

            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            crate::cmd::build_set_hca_cap_input(in_mbox, 0x0, &queried_capability);
            match cmd.execute(
                CmdOpcode::SetHcaCap,
                self.cmd_in_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
            ) {
                Ok(()) => {
                    log::info!(target: "mlx5", "HCA caps set");
                }
                Err(Mlx5Error::CommandFailed(code))
                    if code == CmdStatus::BadOpcode as u8 || code == CmdStatus::BadParam as u8 =>
                {
                    log::debug!(
                        target: "mlx5",
                        "SET_HCA_CAP unsupported by FW/status={:#x}; continuing",
                        code
                    );
                }
                Err(e) => return Err(e),
            }

        }

        log::info!(target: "mlx5", "HCA capability setup complete");
        Ok(())
    }

    /// INIT_HCA を実行してHCAを運用状態へ遷移
    ///
    /// # Safety
    /// - enable_hca_and_setup および必要ページ供給が完了していること
    pub unsafe fn init_hca(&mut self) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_init_hca_input(in_mbox, self.sw_vhca_id);
        cmd.execute(
            CmdOpcode::InitHca,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        log::info!(target: "mlx5", "HCA initialized");
        self.state = DeviceState::HcaInitialized;
        Ok(())
    }

    // ========================================================================
    // Phase 4: Query Port MAC Address
    // ========================================================================

    /// VPORTコンテキストをクエリしてMACアドレスを取得
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn query_port_mac(&mut self, port_index: usize) -> Mlx5Result<MacAddr> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let query_patterns: &[(bool, Option<u8>, &str)] = &[
            (false, None, "self"),
            (false, Some(0), "self-uc-list"),
            (true, None, "other-vport"),
            (true, Some(0), "other-vport-uc-list"),
        ];

        let mut last_cmd_status: Option<u8> = None;

        for (other_vport, allowed_list_type, label) in query_patterns {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            crate::cmd::build_query_nic_vport_input_ex(
                in_mbox,
                0,
                *other_vport,
                *allowed_list_type,
            );
            match cmd.execute(
                CmdOpcode::QueryNicVportContext,
                self.cmd_in_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    Self::debug_dump_mailbox_words("QUERY_NIC_VPORT_CONTEXT", out_mbox, 48);
                    let mac_bytes = crate::cmd::parse_vport_mac(out_mbox);
                    if mac_bytes != [0; 6] {
                        let mac = MacAddr(mac_bytes);
                        if let Some(port) = self.ports.get_mut(port_index) {
                            port.set_mac_address(mac);
                            log::info!(
                                target: "mlx5",
                                "Port {} MAC: {}",
                                port.port_number(),
                                mac
                            );
                        }
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
            log::warn!(
                target: "mlx5",
                "Failed to query NIC vport MAC; MAC remains unset"
            );
        }

        Ok(MacAddr([0; 6]))
    }

    // ========================================================================
    // Phase 5: Queue Setup
    // ========================================================================

    /// UAR (User Access Region) を設定
    pub fn set_uar(&mut self, uar_base: u64, uar_page: u32) {
        self.uar_base = uar_base;
        self.uar_page = uar_page;
    }

    /// Memory Keyを設定
    pub fn set_mkey(&mut self, mkey: u32) {
        self.mkey = mkey;
    }

    /// Event Queueを追加
    pub fn add_eq(&mut self, eq: EventQueue) {
        self.eqs.push(eq);
    }

    /// Completion Queueを追加
    pub fn add_cq(&mut self, cq: CompletionQueue) {
        self.cqs.push(cq);
    }

    /// Send Queueを追加
    pub fn add_sq(&mut self, sq: SendQueue) {
        self.sqs.push(sq);
    }

    /// Receive Queueを追加
    pub fn add_rq(&mut self, rq: ReceiveQueue) {
        self.rqs.push(rq);
    }

    /// キューセットアップ完了を通知
    pub fn mark_queues_ready(&mut self) {
        self.state = DeviceState::QueuesReady;
        log::info!(
            target: "mlx5",
            "Queues ready: {} EQs, {} CQs, {} SQs, {} RQs",
            self.eqs.len(), self.cqs.len(), self.sqs.len(), self.rqs.len()
        );
    }

    /// デバイスをアクティブにする
    pub fn activate(&mut self) {
        self.state = DeviceState::Active;
        for port in &mut self.ports {
            port.admin_up();
        }
        log::info!(target: "mlx5", "Device activated");
    }

    // ========================================================================
    // Phase 5b: MANAGE_PAGES — FWページ管理
    // ========================================================================

    /// FWが要求するページを提供
    ///
    /// QUERY_PAGES でブート/初期化ページ数を取得し、
    /// DMA対応ページを割り当てて MANAGE_PAGES (give_pages) で提供する。
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    /// - page_addrs の各アドレスが有効なDMAメモリであること
    pub unsafe fn provide_pages(&mut self, function_id: u16, page_addrs: &[u64]) -> Mlx5Result<()> {
        if page_addrs.is_empty() {
            return Ok(());
        }

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let num_pages = page_addrs.len() as u32;

        log::info!(
            target: "mlx5",
            "Providing {} pages to FW (function_id={})",
            num_pages, function_id
        );

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_manage_pages_input(
            in_mbox,
            crate::pages::ManagePagesOp::GivePages as u8,
            function_id,
            num_pages,
            page_addrs,
        );

        cmd.execute(
            CmdOpcode::ManagePages,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        // ページトラッキング
        for &pa in page_addrs {
            self.page_manager
                .record_allocation(crate::pages::PageAllocation {
                    phys_addr: pa,
                    virt_addr: pa, // SAS identity map
                    function_id,
                });
        }

        log::info!(
            target: "mlx5",
            "Provided {} pages (total given: {})",
            num_pages, self.page_manager.total_given_pages()
        );

        Ok(())
    }

    /// QUERY_PAGES で startup pages 要求を取得する
    ///
    /// # Arguments
    /// - `op_mod`: 0x01=boot pages, 0x02=init pages, 0x03=regular pages
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn query_required_pages(&mut self, op_mod: u16) -> Mlx5Result<(u16, i32)> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::pages::build_query_pages_input(in_mbox, op_mod);
        cmd.execute(
            CmdOpcode::QueryPages,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(crate::pages::parse_query_pages_output(out_mbox))
    }

    /// ページマネージャの参照を取得
    pub fn page_manager(&self) -> &PageManager {
        &self.page_manager
    }

    // ========================================================================
    // Phase 5c: MKEY 作成
    // ========================================================================

    /// QUERY_SPECIAL_CONTEXTS から reserved lkey を取得
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn query_reserved_lkey(&mut self) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_query_special_contexts_input(in_mbox);
        cmd.execute(
            CmdOpcode::QuerySpecialContexts,
            self.cmd_in_mbox_phys,
            0x10,
            self.cmd_out_mbox_phys,
            0x20,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(crate::cmd::parse_query_special_contexts_resd_lkey(out_mbox))
    }

    /// Direct Memory Key を作成
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn create_mkey(&mut self, params: &MkeyParams) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::resources::build_create_mkey_input(in_mbox, params);

        cmd.execute(
            CmdOpcode::CreateMkey,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let mkey_index = crate::resources::parse_create_mkey_output(out_mbox);
        let full_mkey = mkey_index << 8; // key portion from HW

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

    // ========================================================================
    // Phase 5d: TIS/TIR 作成
    // ========================================================================

    /// TIS (Transport Interface Send) を作成
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn create_tis(&mut self, params: &TisParams) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::resources::build_create_tis_input(in_mbox, params);

        cmd.execute(
            CmdOpcode::CreateTis,
            self.cmd_in_mbox_phys,
            0xC0,
            self.cmd_out_mbox_phys,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let tisn = crate::resources::parse_create_tis_output(out_mbox);

        let info = TisInfo {
            tisn,
            port: params.port,
        };
        self.tis_list.push(info);

        log::info!(target: "mlx5", "TIS created: tisn={}", tisn);
        Ok(tisn)
    }

    /// TIR (Transport Interface Receive) を作成
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn create_tir(&mut self, params: &TirParams) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::resources::build_create_tir_input(in_mbox, params);

        cmd.execute(
            CmdOpcode::CreateTir,
            self.cmd_in_mbox_phys,
            0x110,
            self.cmd_out_mbox_phys,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let tirn = crate::resources::parse_create_tir_output(out_mbox);

        let info = TirInfo {
            tirn,
            receive_type: params.receive_type,
        };
        self.tir_list.push(info);

        log::info!(target: "mlx5", "TIR created: tirn={}", tirn);
        Ok(tirn)
    }

    /// TIS一覧
    pub fn tis_list(&self) -> &[TisInfo] {
        &self.tis_list
    }

    /// TIR一覧
    pub fn tir_list(&self) -> &[TirInfo] {
        &self.tir_list
    }

    // ========================================================================
    // Phase 5e: フローテーブル設定
    // ========================================================================

    /// NIC RXフローテーブル・フローグループ・catch-allエントリを作成
    ///
    /// 全パケットをデフォルトTIRにフォワードする設定を行う。
    ///
    /// # Arguments
    /// - `tirn`: フォワード先TIR番号
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn setup_rx_flow_table(&mut self, tirn: u32) -> Mlx5Result<()> {
        // 1. フローテーブル作成
        let ft_config = FlowTableConfig::default();
        let table_id = self.create_flow_table(&ft_config)?;

        // 2. Catch-all フローグループ（全パケットマッチ）
        let criteria = crate::flow::MatchCriteria::default();
        let group_id = self.create_flow_group(table_id, 0, 0, &criteria)?;

        // 3. Catch-all フローテーブルエントリ（TIRにフォワード）
        let match_value = crate::flow::MatchValue::default();
        self.set_flow_table_entry(
            table_id,
            0,
            group_id,
            crate::flow::FlowAction::Allow,
            Some(tirn),
            &match_value,
        )?;

        log::info!(
            target: "mlx5",
            "RX flow table configured: FT={} FG={} → TIR={}",
            table_id, group_id, tirn
        );

        Ok(())
    }

    /// フローテーブルを作成
    unsafe fn create_flow_table(&mut self, config: &FlowTableConfig) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::flow::build_create_flow_table_input(in_mbox, config);

        cmd.execute(
            CmdOpcode::CreateFlowTable,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let table_id = crate::flow::parse_create_flow_table_output(out_mbox);

        self.flow_tables.push(FlowTable {
            table_id,
            table_type: config.table_type,
            size: 1 << config.log_size,
            level: config.level,
        });

        Ok(table_id)
    }

    /// フローグループを作成
    unsafe fn create_flow_group(
        &mut self,
        table_id: u32,
        start_index: u32,
        end_index: u32,
        criteria: &crate::flow::MatchCriteria,
    ) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::flow::build_create_flow_group_input(
            in_mbox,
            table_id,
            start_index,
            end_index,
            criteria,
        );

        cmd.execute(
            CmdOpcode::CreateFlowGroup,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let group_id = crate::flow::parse_create_flow_group_output(out_mbox);

        self.flow_groups.push(FlowGroup {
            group_id,
            table_id,
            start_index,
            end_index,
            match_criteria: criteria.clone(),
        });

        Ok(group_id)
    }

    /// フローテーブルエントリを設定
    unsafe fn set_flow_table_entry(
        &mut self,
        table_id: u32,
        flow_index: u32,
        group_id: u32,
        action: crate::flow::FlowAction,
        destination_tirn: Option<u32>,
        match_value: &crate::flow::MatchValue,
    ) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::flow::build_set_flow_table_entry_input(
            in_mbox,
            table_id,
            flow_index,
            group_id,
            action,
            destination_tirn,
            match_value,
        );

        cmd.execute(
            CmdOpcode::SetFlowTableEntry,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
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

    // ========================================================================
    // Phase 5f: Resource Allocation (UAR, PD, TD)
    // ========================================================================

    /// UAR (User Access Region) を割り当て
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn alloc_uar(&mut self) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_alloc_uar_input(in_mbox);

        match cmd.execute(
            CmdOpcode::AllocUar,
            self.cmd_in_mbox_phys,
            0x10,
            self.cmd_out_mbox_phys,
            0x10,
        ) {
            Ok(()) => {}
            Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                let uar_number = 0;
                self.allocated_uars.push(uar_number);
                self.uar_page = uar_number;
                self.uar_base =
                    self.bar0_base + (uar_number as u64) * (crate::regs::uar::PAGE_SIZE as u64);
                log::warn!(
                    target: "mlx5",
                    "ALLOC_UAR returned status=0x04; falling back to UAR {}",
                    uar_number
                );
                return Ok(uar_number);
            }
            Err(e) => return Err(e),
        }

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let uar_number = crate::cmd::parse_alloc_uar_output(out_mbox);

        self.allocated_uars.push(uar_number);
        log::info!(target: "mlx5", "UAR allocated: {}", uar_number);

        if self.uar_page == 0 {
            self.uar_page = uar_number;
            // UAR base address = BAR0 base + UAR_number * PAGE_SIZE
            self.uar_base =
                self.bar0_base + (uar_number as u64) * (crate::regs::uar::PAGE_SIZE as u64);
        }

        Ok(uar_number)
    }

    /// Protection Domain を割り当て
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn alloc_pd(&mut self) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_alloc_pd_input(in_mbox);

        match cmd.execute(
            CmdOpcode::AllocPd,
            self.cmd_in_mbox_phys,
            0x10,
            self.cmd_out_mbox_phys,
            0x10,
        ) {
            Ok(()) => {}
            Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                self.pd = 0;
                log::warn!(
                    target: "mlx5",
                    "ALLOC_PD returned status=0x04; falling back to PD 0"
                );
                return Ok(self.pd);
            }
            Err(e) => return Err(e),
        }

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        self.pd = crate::cmd::parse_alloc_pd_output(out_mbox);
        log::info!(target: "mlx5", "PD allocated: {}", self.pd);
        Ok(self.pd)
    }

    /// Transport Domain を割り当て
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn alloc_td(&mut self) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_alloc_td_input(in_mbox);

        match cmd.execute(
            CmdOpcode::AllocTransportDomain,
            self.cmd_in_mbox_phys,
            0x10,
            self.cmd_out_mbox_phys,
            0x10,
        ) {
            Ok(()) => {}
            Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                self.td = 0;
                log::warn!(
                    target: "mlx5",
                    "ALLOC_TRANSPORT_DOMAIN returned status=0x04; falling back to TD 0"
                );
                return Ok(self.td);
            }
            Err(e) => return Err(e),
        }

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        self.td = crate::cmd::parse_alloc_td_output(out_mbox);
        log::info!(target: "mlx5", "TD allocated: {}", self.td);
        Ok(self.td)
    }

    /// ドライババージョンをFWに通知
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn set_driver_version(&mut self) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let version = b"RanyOS mlx5 0.1.0";
        crate::cmd::build_set_driver_version_input(in_mbox, version);

        cmd.execute(
            CmdOpcode::SetDriverVersion,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "Driver version set");
        Ok(())
    }

    // ========================================================================
    // Phase 5g: HW Queue Creation via FW Commands
    // ========================================================================

    /// Event Queueを作成（FWコマンド経由）
    ///
    /// # Arguments
    /// - `eq_buf_virt`: EQバッファの仮想アドレス
    /// - `eq_buf_phys`: EQバッファの物理アドレス
    /// - `log_eq_size`: ログ2 EQサイズ
    /// - `msix_vector`: MSI-Xベクタ番号
    /// - `event_bitmask`: 受信イベントのビットマスク
    ///
    /// # Safety
    /// - バッファアドレスが有効であること
    pub unsafe fn create_eq_hw(
        &mut self,
        eq_buf_virt: u64,
        eq_buf_phys: u64,
        log_eq_size: u8,
        msix_vector: u32,
        event_bitmask: u64,
    ) -> Mlx5Result<u32> {
        let is_vf = self.is_virtual_function();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_eq_input(
            in_mbox,
            log_eq_size,
            eq_buf_phys,
            self.uar_page,
            msix_vector,
            event_bitmask,
        );

        let eq_bytes = (1usize << (log_eq_size as usize)) * crate::regs::eqe::EQE_SIZE;
        let eq_pages = (eq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let eq_in_len = (0x110 + eq_pages * 8) as u32;

        // Completion EQ on VF follows shared-resource UID semantics in mlx5 Linux path.
        // Keep this scoped to CREATE_EQ and restore previous UID immediately.
        let prev_uid = cmd.uid();
        let use_shared_uid = is_vf && event_bitmask == 0;
        if use_shared_uid {
            cmd.set_uid(0xFFFF);
        }

        let exec_res = cmd.execute(
            CmdOpcode::CreateEq,
            self.cmd_in_mbox_phys,
            eq_in_len,
            self.cmd_out_mbox_phys,
            0x10,
        );

        if use_shared_uid {
            cmd.set_uid(prev_uid);
        }

        exec_res?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let eqn = crate::cmd::parse_create_eq_output(out_mbox);

        let eq = EventQueue::new(
            eqn,
            eq_buf_virt,
            eq_buf_phys,
            self.uar_base,
            log_eq_size,
            msix_vector,
        );
        self.eqs.push(eq);

        log::info!(target: "mlx5", "EQ created: eqn={} msix_vec={}", eqn, msix_vector);
        Ok(eqn)
    }

    /// Completion Queueを作成（FWコマンド経由）
    ///
    /// # Arguments
    /// - `cq_buf_virt`: CQバッファの仮想アドレス
    /// - `cq_buf_phys`: CQバッファの物理アドレス
    /// - `db_virt`: ドアベルレコードの仮想アドレス
    /// - `db_phys`: ドアベルレコードの物理アドレス
    /// - `log_cq_size`: ログ2 CQサイズ
    /// - `eqn`: 紐づくEQ番号
    ///
    /// # Safety
    /// - バッファアドレスが有効であること
    pub unsafe fn create_cq_hw(
        &mut self,
        cq_buf_virt: u64,
        cq_buf_phys: u64,
        db_virt: u64,
        db_phys: u64,
        log_cq_size: u8,
        eqn: u32,
    ) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_cq_input(
            in_mbox,
            log_cq_size,
            cq_buf_phys,
            db_phys,
            self.uar_page,
            eqn,
            false, // CQE compression disabled by default
        );

        let cq_bytes = (1usize << (log_cq_size as usize)) * crate::regs::cqe::SIZE;
        let cq_pages = (cq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let cq_in_len = (0x110 + cq_pages * 8) as u32;

        cmd.execute(
            CmdOpcode::CreateCq,
            self.cmd_in_mbox_phys,
            cq_in_len,
            self.cmd_out_mbox_phys,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let cqn = crate::cmd::parse_create_cq_output(out_mbox);

        let cq = CompletionQueue::new(
            cqn,
            cq_buf_virt,
            cq_buf_phys,
            self.uar_base,
            db_virt,
            log_cq_size,
            eqn,
        );
        self.cqs.push(cq);
        self.cq_db_records.push((db_virt, db_phys));

        log::info!(target: "mlx5", "CQ created: cqn={} eqn={}", cqn, eqn);
        Ok(cqn)
    }

    /// Send Queueを作成（FWコマンド経由）
    ///
    /// # Arguments
    /// - `sq_buf_virt`: SQバッファの仮想アドレス
    /// - `sq_buf_phys`: SQバッファの物理アドレス
    /// - `db_virt`: SQドアベルレコードの仮想アドレス
    /// - `db_phys`: SQドアベルレコードの物理アドレス
    /// - `log_sq_size`: ログ2 SQサイズ
    /// - `cqn`: 紐づくCQ番号
    /// - `tisn`: 紐づくTIS番号
    ///
    /// # Safety
    /// - バッファアドレスが有効であること
    pub unsafe fn create_sq_hw(
        &mut self,
        sq_buf_virt: u64,
        sq_buf_phys: u64,
        db_virt: u64,
        db_phys: u64,
        log_sq_size: u8,
        cqn: u32,
        tisn: u32,
    ) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_sq_input(
            in_mbox,
            log_sq_size,
            sq_buf_phys,
            db_phys,
            cqn,
            tisn,
            self.uar_page,
            self.pd,
        );

        let sq_bytes = (1usize << (log_sq_size as usize)) * 64usize;
        let sq_pages = (sq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let sq_in_len = (0x90 + sq_pages * 8) as u32;

        cmd.execute(
            CmdOpcode::CreateSq,
            self.cmd_in_mbox_phys,
            sq_in_len,
            self.cmd_out_mbox_phys,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let sqn = crate::cmd::parse_create_sq_output(out_mbox);

        // Transition SQ from RESET to RDY
        self.transition_sq_to_ready(sqn)?;

        let sq = SendQueue::new(
            sqn,
            sq_buf_virt,
            sq_buf_phys,
            db_virt,
            self.uar_base,
            log_sq_size,
            tisn,
            cqn,
            self.mkey,
        );
        self.sqs.push(sq);

        log::info!(target: "mlx5", "SQ created: sqn={} cqn={} tisn={}", sqn, cqn, tisn);
        Ok(sqn)
    }

    /// SQをRESET→RDY状態に遷移
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    unsafe fn transition_sq_to_ready(&mut self, sqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_modify_sq_input(in_mbox, sqn, WqState::Reset as u8, WqState::Ready as u8);

        cmd.execute(
            CmdOpcode::ModifySq,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::trace!(target: "mlx5", "SQ {} transitioned to RDY", sqn);
        Ok(())
    }

    /// Receive Queueを作成（FWコマンド経由）
    ///
    /// # Arguments
    /// - `rq_buf_virt`: RQバッファの仮想アドレス
    /// - `rq_buf_phys`: RQバッファの物理アドレス
    /// - `db_virt`: RQドアベルレコードの仮想アドレス
    /// - `db_phys`: RQドアベルレコードの物理アドレス
    /// - `log_rq_size`: ログ2 RQサイズ
    /// - `cqn`: 紐づくCQ番号
    /// - `tirn`: 紐づくTIR番号
    ///
    /// # Safety
    /// - バッファアドレスが有効であること
    pub unsafe fn create_rq_hw(
        &mut self,
        rq_buf_virt: u64,
        rq_buf_phys: u64,
        db_virt: u64,
        db_phys: u64,
        log_rq_size: u8,
        cqn: u32,
        tirn: u32,
    ) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_rq_input(
            in_mbox,
            log_rq_size,
            rq_buf_phys,
            db_phys,
            cqn,
            self.pd,
        );

        let rq_bytes = (1usize << (log_rq_size as usize)) * crate::defs::WQEBB_SIZE;
        let rq_pages = (rq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let rq_in_len = (0x90 + rq_pages * 8) as u32;

        cmd.execute(
            CmdOpcode::CreateRq,
            self.cmd_in_mbox_phys,
            rq_in_len,
            self.cmd_out_mbox_phys,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqn = crate::cmd::parse_create_rq_output(out_mbox);

        // Transition RQ from RESET to RDY
        self.transition_rq_to_ready(rqn)?;

        let rq = ReceiveQueue::new(
            rqn,
            rq_buf_virt,
            rq_buf_phys,
            db_virt,
            log_rq_size,
            cqn,
            tirn,
            self.mkey,
        );
        self.rqs.push(rq);

        log::info!(target: "mlx5", "RQ created: rqn={} cqn={} tirn={}", rqn, cqn, tirn);
        Ok(rqn)
    }

    /// RQをRESET→RDY状態に遷移
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    unsafe fn transition_rq_to_ready(&mut self, rqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_modify_rq_input(in_mbox, rqn, WqState::Reset as u8, WqState::Ready as u8);

        cmd.execute(
            CmdOpcode::ModifyRq,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::trace!(target: "mlx5", "RQ {} transitioned to RDY", rqn);
        Ok(())
    }

    // ========================================================================
    // Phase 5h: RSS (Receive Side Scaling) / RQT
    // ========================================================================

    /// RQT (Receive Queue Table) を作成（RSS用）
    ///
    /// # Arguments
    /// - `rq_numbers`: RQ番号のリスト
    /// - `log_rqt_size`: ログ2 RQTサイズ
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn create_rqt(&mut self, rq_numbers: &[u32], log_rqt_size: u8) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::flow::build_create_rqt_input(in_mbox, rq_numbers, log_rqt_size);

        cmd.execute(
            CmdOpcode::CreateRqt,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqtn = crate::flow::parse_create_rqt_output(out_mbox);

        self.rq_tables.push(RqTable {
            rqtn,
            rq_list: rq_numbers.to_vec(),
            log_rqt_size,
        });

        log::info!(target: "mlx5", "RQT created: rqtn={} rq_count={}", rqtn, rq_numbers.len());
        Ok(rqtn)
    }

    /// RSS付きTIRを作成してRQTに紐づける
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn create_tir_with_rss(
        &mut self,
        rqtn: u32,
        rss_config: &RssConfig,
    ) -> Mlx5Result<u32> {
        let params = TirParams {
            receive_type: TirReceiveType::Rqt,
            td: self.td,
            inline_rqn: 0,
            rqtn,
            rss: Some(rss_config.clone()),
            scatter_fcs: false,
            vlan_strip: false,
        };

        self.create_tir(&params)
    }

    /// マルチキューRSSセットアップ
    ///
    /// 複数のRQをRQTにまとめ、RSS付きTIRを作成し、
    /// フローテーブルで全パケットをそのTIRにフォワードする。
    ///
    /// # Arguments
    /// - `rq_numbers`: RQ番号のリスト
    /// - `rss_config`: RSS設定（None=デフォルト設定を使用）
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn setup_multi_queue_rss(
        &mut self,
        rq_numbers: &[u32],
        rss_config: Option<&RssConfig>,
    ) -> Mlx5Result<u32> {
        if rq_numbers.is_empty() {
            return Err(Mlx5Error::InvalidParameter);
        }

        // RQTサイズ: 最小は対象RQ数を包含する2のべき乗 (ceil(log2(n)))
        let log_rqt_size = (usize::BITS - (rq_numbers.len() - 1).leading_zeros()) as u8;
        let rqtn = self.create_rqt(rq_numbers, log_rqt_size)?;

        // RSS付きTIR作成
        let default_rss = RssConfig::default();
        let rss = rss_config.unwrap_or(&default_rss);
        let tirn = self.create_tir_with_rss(rqtn, rss)?;

        // フローテーブル設定
        self.setup_rx_flow_table(tirn)?;

        log::info!(
            target: "mlx5",
            "Multi-queue RSS configured: {} RQs → RQT={} → TIR={} → FlowTable",
            rq_numbers.len(), rqtn, tirn
        );

        Ok(tirn)
    }

    // ========================================================================
    // Phase 5i: Port Operations
    // ========================================================================

    /// VPORTの状態をクエリ
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn query_port_state(&mut self, port_index: usize) -> Mlx5Result<PortLinkState> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_query_vport_state_input(in_mbox, 0);

        cmd.execute(
            CmdOpcode::QueryVportState,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let (_admin, oper) = crate::cmd::parse_query_vport_state_output(out_mbox);

        let link_state = match oper {
            0x01 => PortLinkState::Up,
            _ => PortLinkState::Down,
        };

        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_link_state(link_state);
            log::info!(
                target: "mlx5",
                "Port {} link state: {:?}",
                port.port_number(),
                link_state
            );
        }

        Ok(link_state)
    }

    /// VPORTカウンタを取得
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn query_vport_counters(
        &mut self,
        port_num: u8,
        clear_on_read: bool,
    ) -> Mlx5Result<VportCounters> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_query_vport_counter_input(in_mbox, port_num, clear_on_read);

        cmd.execute(
            CmdOpcode::QueryVportCounter,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let counters = crate::cmd::parse_query_vport_counter_output(out_mbox);

        log::trace!(
            target: "mlx5",
            "VPORT counters: rx_unicast={} tx_unicast={} rx_errors={} tx_errors={}",
            counters.rx_unicast_packets,
            counters.tx_unicast_packets,
            counters.rx_error_packets,
            counters.tx_error_packets,
        );

        Ok(counters)
    }

    /// プロミスキャスモードを設定
    ///
    /// # Arguments
    /// - `uc_promisc`: ユニキャストプロミスキャス
    /// - `mc_promisc`: マルチキャストプロミスキャス
    /// - `all_promisc`: 全プロミスキャス
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn set_promisc_mode(
        &mut self,
        uc_promisc: bool,
        mc_promisc: bool,
        all_promisc: bool,
    ) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_modify_nic_vport_promisc_input(
            in_mbox,
            uc_promisc,
            mc_promisc,
            all_promisc,
        );

        cmd.execute(
            CmdOpcode::ModifyNicVportContext,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(
            target: "mlx5",
            "Promisc mode set: uc={} mc={} all={}",
            uc_promisc, mc_promisc, all_promisc
        );

        Ok(())
    }

    /// MTUを設定
    ///
    /// ポートのMTU設定とVPORTコンテキストの更新。
    ///
    /// # Arguments
    /// - `port_index`: ポートインデックス（0-based）
    /// - `mtu`: 新しいMTU値
    pub fn set_port_mtu(&mut self, port_index: usize, mtu: u32) -> Mlx5Result<()> {
        let port = self
            .ports
            .get_mut(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidParameter)?;
        log::info!(target: "mlx5", "Port {} MTU set to {}", port.port_number(), mtu);
        Ok(())
    }

    // ========================================================================
    // Phase 5j: CQ Moderation
    // ========================================================================

    /// CQモデレーション（割り込み結合）を設定
    ///
    /// # Arguments
    /// - `cq_index`: CQインデックス
    /// - `max_count`: 結合する最大CQE数
    /// - `max_period_us`: 結合の最大遅延（マイクロ秒）
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn set_cq_moderation(
        &mut self,
        cq_index: usize,
        max_count: u16,
        max_period_us: u16,
    ) -> Mlx5Result<()> {
        let cqn = self
            .cqs
            .get(cq_index)
            .ok_or(Mlx5Error::InvalidParameter)?
            .cqn;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_modify_cq_moderation_input(in_mbox, cqn, max_count, max_period_us);

        cmd.execute(
            CmdOpcode::ModifyCq,
            self.cmd_in_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_phys,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(
            target: "mlx5",
            "CQ {} moderation: count={} period={}us",
            cqn, max_count, max_period_us
        );

        Ok(())
    }

    /// HWカウンタをポート統計情報に同期
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn sync_port_stats(&mut self, port_index: usize) -> Mlx5Result<()> {
        let port_num = self
            .ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?
            .port_number();

        let counters = self.query_vport_counters(port_num, false)?;

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
            stats.rx_dropped = counters.rx_dropped;
            stats.tx_dropped = counters.tx_dropped;
        }

        Ok(())
    }

    // ========================================================================
    // Adaptive Polling
    // ========================================================================

    /// 適応的ポーリング状態の参照
    pub fn polling_state(&self) -> &AdaptivePollingState {
        &self.polling_state
    }

    /// 適応的ポーリング状態の可変参照
    pub fn polling_state_mut(&mut self) -> &mut AdaptivePollingState {
        &mut self.polling_state
    }

    // ========================================================================
    // Phase 6: Data Path (TX/RX)
    // ========================================================================

    /// パケットを送信
    ///
    /// # Arguments
    /// - `sq_index`: SQインデックス（複数SQ時の選択）
    /// - `data_phys`: 送信データのDMA物理アドレス
    /// - `data_virt`: 仮想アドレス（完了時の解放追跡用）
    /// - `data_len`: データ長
    /// - `inline_hdr`: インラインEthernetヘッダ
    ///
    /// # Safety
    /// - アドレスが有効であること
    pub unsafe fn transmit(
        &mut self,
        sq_index: usize,
        data_phys: u64,
        data_virt: u64,
        data_len: u32,
        inline_hdr: &[u8],
    ) -> Mlx5Result<u16> {
        if self.state != DeviceState::Active {
            return Err(Mlx5Error::DeviceNotReady);
        }

        let sq = self
            .sqs
            .get_mut(sq_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        sq.post_send(data_phys, data_virt, data_len, inline_hdr)
            .ok_or(Mlx5Error::NoResources)
    }

    /// 受信バッファを投入
    ///
    /// # Safety
    /// - アドレスが有効であること
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

    // ========================================================================
    // Phase 7: Interrupt Handling
    // ========================================================================

    /// EQ割り込みを処理
    ///
    /// # Safety
    /// - EQバッファが有効であること
    pub unsafe fn handle_eq_interrupt(&mut self, eq_index: usize) -> Vec<EqEvent> {
        let mut events = Vec::new();

        if let Some(eq) = self.eqs.get_mut(eq_index) {
            loop {
                match eq.poll_eqe() {
                    Some(eqe) => {
                        let event = decode_eqe(eqe);
                        events.push(event);
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

    /// CQ完了を処理する（適応的ポーリング対応）
    ///
    /// # Safety
    /// - CQバッファが有効であること
    ///
    /// # Returns
    /// 完了情報のリスト
    pub unsafe fn poll_cq(&mut self, cq_index: usize, max_batch: u32) -> Vec<crate::cq::CqeInfo> {
        let batch = self.polling_state.max_batch_size().min(max_batch);
        let result = if let Some(cq) = self.cqs.get_mut(cq_index) {
            cq.poll_batch(batch)
        } else {
            Vec::new()
        };

        // 適応的ポーリング状態更新
        let need_rearm = self.polling_state.record_poll_cycle(result.len() as u32);
        if need_rearm {
            // CQを再ARM（割り込みモード時）
            if let Some(cq) = self.cqs.get(cq_index) {
                cq.arm();
            }
        }

        result
    }

    /// 送信完了を処理してバッファを解放
    pub fn process_tx_completions(
        &mut self,
        sq_index: usize,
        wqe_counter: u16,
    ) -> Option<crate::wq::TxBufferInfo> {
        self.sqs
            .get_mut(sq_index)
            .and_then(|sq| sq.complete_tx(wqe_counter))
    }

    /// 受信完了を処理してバッファ情報を返す
    pub fn process_rx_completion(
        &mut self,
        rq_index: usize,
        wqe_counter: u16,
    ) -> Option<crate::wq::RxBufferInfo> {
        self.rqs
            .get_mut(rq_index)
            .and_then(|rq| rq.complete_rx(wqe_counter))
    }

    // ========================================================================
    // Phase 8: Teardown
    // ========================================================================

    /// HCAティアダウン（シャットダウン）
    ///
    /// リソースの逆順破壊:
    /// FlowTableEntry → FlowGroup → FlowTable → SQ → RQ → RQT → TIR → TIS
    /// → CQ → EQ → MKEY → TD → PD → UAR → Pages → TeardownHCA → DisableHCA
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn teardown(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "Starting full teardown sequence...");

        if let Some(cmd) = self.cmd.as_mut() {
            // 1. Destroy Flow Table Entries (逆順)
            for entry in self.flow_entries.iter().rev() {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_delete_flow_table_entry_input(
                    in_mbox,
                    entry.table_id,
                    entry.index,
                );
                let _ = cmd.execute(
                    CmdOpcode::DeleteFlowTableEntry,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.flow_entries.clear();

            // 2. Destroy Flow Groups (逆順)
            for group in self.flow_groups.iter().rev() {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_destroy_flow_group_input(in_mbox, group.table_id, group.group_id);
                let _ = cmd.execute(
                    CmdOpcode::DestroyFlowGroup,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.flow_groups.clear();

            // 3. Destroy Flow Tables (逆順)
            for ft in self.flow_tables.iter().rev() {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_destroy_flow_table_input(in_mbox, ft.table_id);
                let _ = cmd.execute(
                    CmdOpcode::DestroyFlowTable,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.flow_tables.clear();
            log::trace!(target: "mlx5", "Flow tables destroyed");

            // 2. Destroy SQs
            for sq in &self.sqs {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_destroy_sq_input(in_mbox, sq.sqn);
                let _ = cmd.execute(
                    CmdOpcode::DestroySq,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.sqs.clear();
            log::trace!(target: "mlx5", "SQs destroyed");

            // 3. Destroy RQs
            for rq in &self.rqs {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_destroy_rq_input(in_mbox, rq.rqn);
                let _ = cmd.execute(
                    CmdOpcode::DestroyRq,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.rqs.clear();
            log::trace!(target: "mlx5", "RQs destroyed");

            // 4. Destroy RQTs
            for rqt in &self.rq_tables {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_destroy_rqt_input(in_mbox, rqt.rqtn);
                let _ = cmd.execute(
                    CmdOpcode::DestroyRqt,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.rq_tables.clear();
            log::trace!(target: "mlx5", "RQTs destroyed");

            // 5. Destroy TIRs
            for tir in &self.tir_list {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::resources::build_destroy_tir_input(in_mbox, tir.tirn);
                let _ = cmd.execute(
                    CmdOpcode::DestroyTir,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.tir_list.clear();
            log::trace!(target: "mlx5", "TIRs destroyed");

            // 6. Destroy TISs
            for tis in &self.tis_list {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::resources::build_destroy_tis_input(in_mbox, tis.tisn);
                let _ = cmd.execute(
                    CmdOpcode::DestroyTis,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.tis_list.clear();
            log::trace!(target: "mlx5", "TISs destroyed");

            // 7. Destroy CQs
            for cq in &self.cqs {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_destroy_cq_input(in_mbox, cq.cqn);
                let _ = cmd.execute(
                    CmdOpcode::DestroyCq,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.cqs.clear();
            self.cq_db_records.clear();
            log::trace!(target: "mlx5", "CQs destroyed");

            // 8. Destroy EQs
            for eq in &self.eqs {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_destroy_eq_input(in_mbox, eq.eqn);
                let _ = cmd.execute(
                    CmdOpcode::DestroyEq,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.eqs.clear();
            log::trace!(target: "mlx5", "EQs destroyed");

            // 9. Destroy MKEY
            if let Some(ref mkey_info) = self.mkey_info {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::resources::build_destroy_mkey_input(in_mbox, mkey_info.mkey_index);
                let _ = cmd.execute(
                    CmdOpcode::DestroyMkey,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.mkey_info = None;
            self.mkey = 0;
            log::trace!(target: "mlx5", "MKEY destroyed");

            // 10. Dealloc Transport Domain
            if self.td != 0 {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_dealloc_td_input(in_mbox, self.td);
                let _ = cmd.execute(
                    CmdOpcode::DeallocTransportDomain,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
                self.td = 0;
            }
            log::trace!(target: "mlx5", "TD deallocated");

            // 11. Dealloc Protection Domain
            if self.pd != 0 {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_dealloc_pd_input(in_mbox, self.pd);
                let _ = cmd.execute(
                    CmdOpcode::DeallocPd,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
                self.pd = 0;
            }
            log::trace!(target: "mlx5", "PD deallocated");

            // 12. Dealloc UARs
            for uar in &self.allocated_uars {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_dealloc_uar_input(in_mbox, *uar);
                let _ = cmd.execute(
                    CmdOpcode::DeallocUar,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            self.allocated_uars.clear();
            self.uar_page = 0;
            self.uar_base = 0;
            log::trace!(target: "mlx5", "UARs deallocated");

            // 13. Reclaim pages from FW
            if self.page_manager.total_given_pages() > 0 {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                let num_pages = self.page_manager.total_given_pages();
                let pas: Vec<u64> = self
                    .page_manager
                    .all_pages()
                    .iter()
                    .map(|p| p.phys_addr)
                    .collect();
                crate::cmd::build_manage_pages_input(
                    in_mbox,
                    crate::pages::ManagePagesOp::ReclaimPages as u8,
                    0, // function_id
                    num_pages,
                    &pas,
                );
                let _ = cmd.execute(
                    CmdOpcode::ManagePages,
                    self.cmd_in_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_phys,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            log::trace!(target: "mlx5", "Pages reclaimed");

            // 14. TEARDOWN_HCA
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            crate::cmd::build_teardown_hca_input(in_mbox, true);

            let _ = cmd.execute(
                CmdOpcode::TeardownHca,
                self.cmd_in_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
            );
            log::trace!(target: "mlx5", "HCA torn down");

            // 15. DISABLE_HCA
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            *in_mbox = CmdMailbox::zeroed();

            let _ = cmd.execute(
                CmdOpcode::DisableHca,
                self.cmd_in_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_phys,
                MLX5_CMD_MBOX_SIZE as u32,
            );
            log::trace!(target: "mlx5", "HCA disabled");
        }

        // ポートをダウンに
        for port in &mut self.ports {
            port.admin_down();
            port.set_link_state(PortLinkState::Down);
        }

        self.resources_allocated = false;
        self.state = DeviceState::Uninitialized;
        log::info!(target: "mlx5", "Full teardown completed");
        Ok(())
    }

    // ========================================================================
    // Phase 9: Full Initialization Orchestration
    // ========================================================================

    /// デバイスの完全パイプライン初期化
    ///
    /// 以下の順序でHCAの初期化を行い、パケット送受信可能な状態にする:
    ///
    /// 1. FW待機 → コマンドIF初期化 → HCA有効化&初期化
    /// 2. UAR割り当て → PD割り当て → TD割り当て
    /// 3. ドライババージョン通知 → ページ提供
    /// 4. MACアドレス取得 → MKEY作成
    /// 5. EQ作成 → CQ(TX/RX)作成
    /// 6. TIS作成 → SQ作成&RDY遷移
    /// 7. TIR作成 → RQ作成&RDY遷移
    /// 8. フローテーブル設定 → ポートUp
    ///
    /// # Arguments
    /// - `eq_buf`: (virt, phys) EQバッファ
    /// - `tx_cq_buf`: (virt, phys, db_virt, db_phys) TX CQバッファ
    /// - `rx_cq_buf`: (virt, phys, db_virt, db_phys) RX CQバッファ
    /// - `sq_buf`: (virt, phys, db_virt, db_phys) SQバッファ
    /// - `rq_buf`: (virt, phys, db_virt, db_phys) RQバッファ
    /// - `log_eq_size`: EQエントリ数のlog2
    /// - `log_cq_size`: CQエントリ数のlog2
    /// - `log_sq_size`: SQエントリ数のlog2
    /// - `log_rq_size`: RQエントリ数のlog2
    ///
    /// # Safety
    /// - 全バッファアドレスが有効であること
    /// - BAR0がマッピング済みであること
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn init_full(
        &mut self,
        // Phase 1: コマンドIF用DMAバッファ
        cmdq_virt: u64,
        cmdq_phys: u64,
        cmd_in_mbox_virt: u64,
        cmd_in_mbox_phys: u64,
        cmd_out_mbox_virt: u64,
        cmd_out_mbox_phys: u64,
        // Phase 3: FWページ
        fw_page_addrs: &[u64],
        // Phase 4: MKEY
        mkey_params: &MkeyParams,
        // Phase 5-7: キューバッファ (virt, phys) or (virt, phys, db_virt, db_phys)
        eq_buf: (u64, u64),
        tx_cq_buf: (u64, u64, u64, u64),
        rx_cq_buf: (u64, u64, u64, u64),
        sq_buf: (u64, u64, u64, u64),
        rq_buf: (u64, u64, u64, u64),
        // キューサイズ (log2)
        log_eq_size: u8,
        log_cq_size: u8,
        log_sq_size: u8,
        log_rq_size: u8,
    ) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "=== Starting full pipeline initialization ===");

        // Phase 1: Boot sequence
        match self.wait_firmware() {
            Ok(()) => {
                log::info!(target: "mlx5", "[1/8] Firmware ready");
            }
            Err(Mlx5Error::DeviceNotReady) if self.is_virtual_function() => {
                // VF passthrough では PF と同じ FW ブート状態が露出しない場合がある。
                // FW wait だけを緩和し、以降のコマンドIF/HCA初期化で実際の可否を判定する。
                log::warn!(
                    target: "mlx5",
                    "[1/8] Firmware ready wait skipped for VF (device_id={:#06x})",
                    self.device_id
                );
                self.assume_firmware_ready_for_vf();
            }
            Err(e) => return Err(e),
        }

        self.init_command_interface(
            cmdq_virt,
            cmdq_phys,
            cmd_in_mbox_virt,
            cmd_in_mbox_phys,
            cmd_out_mbox_virt,
            cmd_out_mbox_phys,
        )?;
        log::info!(target: "mlx5", "[1/8] Command interface initialized");

        self.enable_hca_and_setup()?;
        log::info!(target: "mlx5", "[1/8] HCA enabled and caps configured");

        // Phase 2: FW startup pages
        let mut page_function_id = self.fw_function_id;
        let mut requested_pages = fw_page_addrs.len();
        let mut pages_consumed = 0usize;
        match self.query_required_pages(0x01) {
            Ok((func_id, num_pages)) => {
                page_function_id = func_id;
                self.fw_function_id = func_id;
                requested_pages = core::cmp::max(num_pages, 0) as usize;
                log::info!(
                    target: "mlx5",
                    "[2/8] QUERY_PAGES boot: function_id={} requested_pages={}",
                    func_id,
                    requested_pages
                );
            }
            Err(Mlx5Error::CommandFailed(code))
                if code == CmdStatus::BadOpcode as u8 || code == CmdStatus::BadParam as u8 =>
            {
                log::debug!(
                    target: "mlx5",
                    "[2/8] QUERY_PAGES boot unsupported (status={:#x}); fallback function_id={} pages={}",
                    code,
                    page_function_id,
                    requested_pages
                );
            }
            Err(e) => {
                log::warn!(
                    target: "mlx5",
                    "[2/8] QUERY_PAGES boot failed ({:?}); fallback function_id={} pages={}",
                    e,
                    page_function_id,
                    requested_pages
                );
            }
        }

        if requested_pages > 0 && !fw_page_addrs.is_empty() {
            let give_pages = core::cmp::min(requested_pages, fw_page_addrs.len());
            self.provide_pages(page_function_id, &fw_page_addrs[..give_pages])?;
            pages_consumed = give_pages;
            if give_pages < requested_pages {
                log::warn!(
                    target: "mlx5",
                    "[2/8] Startup pages shortfall: requested={} provided={}",
                    requested_pages,
                    give_pages
                );
            }
        } else {
            log::info!(
                target: "mlx5",
                "[2/8] No startup pages provided (requested={} available={})",
                requested_pages,
                fw_page_addrs.len()
            );
        }

        // Linux mlx5 と同様に、INIT_HCA 前に init pages も供給する。
        let mut init_page_function_id = self.fw_function_id;
        let mut init_requested_pages = 0usize;
        match self.query_required_pages(0x02) {
            Ok((func_id, num_pages)) => {
                init_page_function_id = func_id;
                self.fw_function_id = func_id;
                init_requested_pages = core::cmp::max(num_pages, 0) as usize;
                log::info!(
                    target: "mlx5",
                    "[2/8] QUERY_PAGES init: function_id={} requested_pages={}",
                    func_id,
                    init_requested_pages
                );
            }
            Err(Mlx5Error::CommandFailed(code))
                if code == CmdStatus::BadOpcode as u8 || code == CmdStatus::BadParam as u8 =>
            {
                log::debug!(
                    target: "mlx5",
                    "[2/8] QUERY_PAGES init unsupported (status={:#x}); skipping",
                    code
                );
            }
            Err(e) => {
                log::warn!(target: "mlx5", "[2/8] QUERY_PAGES init failed ({:?})", e);
            }
        }

        if init_requested_pages > 0 && pages_consumed < fw_page_addrs.len() {
            let remaining = &fw_page_addrs[pages_consumed..];
            let give_pages = core::cmp::min(init_requested_pages, remaining.len());
            self.provide_pages(init_page_function_id, &remaining[..give_pages])?;
            if give_pages < init_requested_pages {
                log::warn!(
                    target: "mlx5",
                    "[2/8] Init pages shortfall: requested={} provided={}",
                    init_requested_pages,
                    give_pages
                );
            }
        } else if init_requested_pages > 0 {
            log::warn!(
                target: "mlx5",
                "[2/8] Init pages requested={} but no free page buffers remain (available={})",
                init_requested_pages,
                fw_page_addrs.len().saturating_sub(pages_consumed)
            );
        }

        self.init_hca()?;
        log::info!(target: "mlx5", "[2/8] HCA initialized");
        log::info!(target: "mlx5", "[2/8] Startup/init pages setup complete");

        // Phase 3: Resource allocation
        self.alloc_uar().map_err(|e| {
            log::error!(target: "mlx5", "alloc_uar failed: {:?}", e);
            e
        })?;
        log::info!(target: "mlx5", "[3/8] UAR allocated");

        self.alloc_pd().map_err(|e| {
            log::error!(target: "mlx5", "alloc_pd failed: {:?}", e);
            e
        })?;
        log::info!(target: "mlx5", "[3/8] PD allocated");

        self.alloc_td().map_err(|e| {
            log::error!(target: "mlx5", "alloc_td failed: {:?}", e);
            e
        })?;
        log::info!(target: "mlx5", "[3/8] TD allocated");

        // Phase 4: FW setup
        let _ = self.set_driver_version(); // Non-fatal if fails
        log::info!(target: "mlx5", "[4/8] Driver version set");

        // Phase 5: Key resources
        self.query_port_mac(0)?;
        log::info!(target: "mlx5", "[5/8] MAC address obtained");

        let mut effective_mkey_params = mkey_params.clone();
        effective_mkey_params.pd = self.pd;
        match self.create_mkey(&effective_mkey_params) {
            Ok(_) => {
                log::info!(target: "mlx5", "[5/8] MKEY created");
            }
            Err(Mlx5Error::CommandFailed(status))
                if self.is_virtual_function() && status == CmdStatus::BadResourceState as u8 =>
            {
                let reserved_lkey = match self.query_reserved_lkey() {
                    Ok(lkey) if lkey != 0 => lkey,
                    Ok(_) => 0x100,
                    Err(_) => 0x100,
                };
                self.set_mkey(reserved_lkey);
                log::warn!(
                    target: "mlx5",
                    "[5/8] CREATE_MKEY unavailable on VF (status={:#x}); using reserved lkey={:#010x}",
                    status,
                    reserved_lkey
                );
            }
            Err(e) => return Err(e),
        }

        // Phase 6: Event & Completion queues
        // Completion EQ follows the Linux path: mask[0] = 0 for comp EQ creation.
        // Setting CQ completion bits explicitly can be rejected with BadParam on VF FW.
        let event_mask = 0u64;

        let eqn = match self.create_eq_hw(
            eq_buf.0,
            eq_buf.1,
            log_eq_size,
            0, // MSI-X vector 0
            event_mask,
        ) {
            Ok(eqn) => {
                log::info!(target: "mlx5", "[6/8] EQ created (eqn={})", eqn);
                eqn
            }
            Err(Mlx5Error::CommandFailed(status))
                if self.is_virtual_function() && status == CmdStatus::BadResourceState as u8 =>
            {
                let fallback_eqn = 0;
                log::warn!(
                    target: "mlx5",
                    "[6/8] CREATE_EQ unavailable on VF (status={:#x}); using fallback eqn={}",
                    status,
                    fallback_eqn
                );
                fallback_eqn
            }
            Err(e) => return Err(e),
        };

        let tx_cqn = self.create_cq_hw(
            tx_cq_buf.0,
            tx_cq_buf.1,
            tx_cq_buf.2,
            tx_cq_buf.3,
            log_cq_size,
            eqn,
        )?;
        log::info!(target: "mlx5", "[6/8] TX CQ created (cqn={})", tx_cqn);

        let rx_cqn = self.create_cq_hw(
            rx_cq_buf.0,
            rx_cq_buf.1,
            rx_cq_buf.2,
            rx_cq_buf.3,
            log_cq_size,
            eqn,
        )?;
        log::info!(target: "mlx5", "[6/8] RX CQ created (cqn={})", rx_cqn);

        // Phase 7: TX path
        let tis_params = crate::resources::TisParams {
            pd: self.pd,
            td: self.td,
            port: 1,
            prio: 0,
        };
        let tisn = self.create_tis(&tis_params)?;
        log::info!(target: "mlx5", "[7/8] TIS created (tisn={})", tisn);

        let sqn = self.create_sq_hw(
            sq_buf.0,
            sq_buf.1,
            sq_buf.2,
            sq_buf.3,
            log_sq_size,
            tx_cqn,
            tisn,
        )?;
        log::info!(target: "mlx5", "[7/8] SQ created and RDY (sqn={})", sqn);

        // Phase 8: RX path
        let rqn = self.create_rq_hw(
            rq_buf.0,
            rq_buf.1,
            rq_buf.2,
            rq_buf.3,
            log_rq_size,
            rx_cqn,
            0, // TIR is created after RQ for direct-rq binding.
        )?;
        log::info!(target: "mlx5", "[8/8] RQ created and RDY (rqn={})", rqn);

        let tir_params = crate::resources::TirParams {
            receive_type: TirReceiveType::DirectRq,
            td: self.td,
            inline_rqn: rqn,
            rqtn: 0,
            rss: None,
            scatter_fcs: false,
            vlan_strip: false,
        };
        let tirn = self.create_tir(&tir_params)?;
        if let Some(rq) = self.rqs.last_mut() {
            rq.tirn = tirn;
        }
        log::info!(target: "mlx5", "[8/8] TIR created (tirn={})", tirn);

        // Phase 8: Flow steering & finalize
        self.setup_rx_flow_table(tirn)?;
        log::info!(target: "mlx5", "[8/8] Flow table configured");

        // Set CQ moderation defaults (moderate for latency)
        let _ = self.set_cq_moderation(0, 16, 64); // TX CQ: 16 CQEs or 64us
        let _ = self.set_cq_moderation(1, 16, 64); // RX CQ: 16 CQEs or 64us

        // ポートUp
        if let Some(port) = self.ports.get_mut(0) {
            port.admin_up();
            log::info!(target: "mlx5", "[8/8] Port 1 administratively up");
        }

        self.resources_allocated = true;
        self.state = DeviceState::Active;

        log::info!(target: "mlx5", "=== Full pipeline initialization complete ===");
        log::info!(
            target: "mlx5",
            "  EQ={} TX_CQ={} RX_CQ={} SQ={} RQ={} TIS={} TIR={}",
            eqn, tx_cqn, rx_cqn, sqn, rqn, tisn, tirn
        );
        log::info!(
            target: "mlx5",
            "  UAR={} PD={} TD={} MKEY=0x{:08x}",
            self.uar_page, self.pd, self.td, self.mkey
        );

        Ok(())
    }

    /// ヘルスチェック
    ///
    /// # Safety
    /// - bar0_base が有効であること
    pub unsafe fn health_check(&self) -> bool {
        fw::check_health(self.bar0_base)
    }
}
