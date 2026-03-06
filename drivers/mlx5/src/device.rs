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
    /// コマンド入力メールボックス（デバイスアドレス）
    cmd_in_mbox_device: u64,
    /// コマンド出力メールボックス（仮想アドレス）
    cmd_out_mbox_virt: u64,
    /// コマンド出力メールボックス（デバイスアドレス）
    cmd_out_mbox_device: u64,

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
            cmd_in_mbox_device: 0,
            cmd_out_mbox_virt: 0,
            cmd_out_mbox_device: 0,
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
        cmdq_pa: u64,
        in_mbox_virt: u64,
        in_mbox_pa: u64,
        out_mbox_virt: u64,
        out_mbox_pa: u64,
    ) -> Mlx5Result<()> {
        if cmdq_pa == 0 || in_mbox_pa == 0 || out_mbox_pa == 0 {
            log::error!(
                target: "mlx5",
                "CRITICAL: Zero DMA address detected (cmdq={:#x} in={:#x} out={:#x}). IOMMU will likely block access.",
                cmdq_pa, in_mbox_pa, out_mbox_pa
            );
        }

        if self.state != DeviceState::FirmwareReady {
            return Err(Mlx5Error::DeviceNotReady);
        }

        self.cmd_in_mbox_virt = in_mbox_virt;
        self.cmd_in_mbox_device = in_mbox_pa;
        self.cmd_out_mbox_virt = out_mbox_virt;
        self.cmd_out_mbox_device = out_mbox_pa;

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
            cmdq_pa,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
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
                "HCA caps: ports={} max_cq={} max_sq={} max_rq={} csum={} log_max_tir={} log_max_tis={} log_max_tis_per_sq={} log_max_td={} tis_tir_td_order={}",
                caps.num_ports,
                caps.max_cq,
                caps.max_sq,
                caps.max_rq,
                caps.csum_cap,
                caps.log_max_tir,
                caps.log_max_tis,
                caps.log_max_tis_per_sq,
                caps.log_max_transport_domain,
                caps.tis_tir_td_order
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
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(crate::pages::parse_query_pages_output(out_mbox))
    }

    /// FWに提供したページを回収
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn reclaim_pages(&mut self, function_id: u16, num_pages: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        log::info!(
            target: "mlx5",
            "Reclaiming {} pages from FW (function_id={})",
            num_pages, function_id
        );

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_manage_pages_input(
            in_mbox,
            crate::pages::ManagePagesOp::ReclaimPages as u8,
            function_id,
            num_pages,
            &[], // No PAS for reclaim
        );

        cmd.execute(
            CmdOpcode::ManagePages,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        // 本来は回収したページアドレスをout_mboxから読み取るべき
        // self.page_manager.record_reclaim(...)
        
        log::info!(target: "mlx5", "Reclaimed pages from FW");
        Ok(())
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
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            0x40,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
        let is_vf = self.is_virtual_function();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let vhca_uid = self.sw_vhca_id;
        log::debug!(
            target: "mlx5",
            "[mlx5-diag] CREATE_TIS uid-base prev_uid={} vhca_uid={} is_vf={}",
            prev_uid,
            vhca_uid,
            is_vf
        );

        let mut uid_candidates = [0u16; 3];
        let mut uid_count = 0usize;
        let mut push_uid = |uid: u16| {
            if uid_candidates[..uid_count].contains(&uid) {
                return;
            }
            uid_candidates[uid_count] = uid;
            uid_count += 1;
        };
        if is_vf {
            push_uid(0xFFFF);
            push_uid(0);
        } else {
            push_uid(prev_uid);
        }

        let mut attempts = [(0u16, 0u32, 0u32); 16];
        let mut attempt_count = 0usize;
        let mut push_attempt = |uid: u16, td: u32, pd: u32| {
            if attempts[..attempt_count]
                .iter()
                .any(|&(u, t, p)| u == uid && t == td && p == pd)
            {
                return;
            }
            attempts[attempt_count] = (uid, td, pd);
            attempt_count += 1;
        };

        for &uid in &uid_candidates[..uid_count] {
            if is_vf {
                push_attempt(uid, 0, params.pd);
                push_attempt(uid, params.td, params.pd);
                push_attempt(uid, 0, 0);
            } else {
                // ...
            }
        }

        let in_len_candidates = [0xC0u32; 1];
        let in_len_count = 1usize;

        let underlay_qpn_candidates = [0u32; 1];
        let underlay_qpn_count = 1usize;

        let total_attempts = attempt_count * underlay_qpn_count * in_len_count;
        let mut executed = 0usize;
        let mut exec_res: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        'attempt_loop: for i in 0..attempt_count {
            let (uid, td, pd) = attempts[i];
            cmd.set_uid(uid);

            for underlay_idx in 0..underlay_qpn_count {
                let underlay_qpn = underlay_qpn_candidates[underlay_idx];

                for len_idx in 0..in_len_count {
                    let in_len = in_len_candidates[len_idx];
                    executed += 1;

                    let attempt_params = TisParams {
                        pd,
                        td,
                        port: params.port,
                        prio: params.prio,
                    };
                    let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                    crate::resources::build_create_tis_input(in_mbox, &attempt_params);
                    if underlay_qpn != 0 {
                        // tisc.underlay_qpn[23:0] at ctx+0x28 (dword 0x48 in command input).
                        in_mbox.write_be32(0x48, underlay_qpn & 0x00FF_FFFF);
                    }

                    log::debug!(
                        target: "mlx5",
                        "[mlx5-diag] CREATE_TIS attempt={}/{} uid={} td={} pd={} underlay_qpn={:#x} in_len={:#x} in[0x20]={:#010x} in[0x44]={:#010x} in[0x48]={:#010x} in[0x4c]={:#010x}",
                        executed,
                        total_attempts,
                        uid,
                        td,
                        pd,
                        underlay_qpn,
                        in_len,
                        in_mbox.read_be32(0x20),
                        in_mbox.read_be32(0x44),
                        in_mbox.read_be32(0x48),
                        in_mbox.read_be32(0x4c),
                    );

                    let res = cmd.execute(
                        CmdOpcode::CreateTis,
                        self.cmd_in_mbox_device,
                        in_len,
                        self.cmd_out_mbox_device,
                        0x10,
                    );
                    match res {
                        Ok(()) => {
                            exec_res = Ok(());
                            break 'attempt_loop;
                        }
                        Err(Mlx5Error::CommandFailed(status))
                            if is_vf
                                && (status == CmdStatus::BadParam as u8
                                    || status == CmdStatus::BadResourceState as u8)
                                && executed < total_attempts =>
                        {
                            log::debug!(
                                target: "mlx5",
                                "CREATE_TIS retrying after status={:#x} (next attempt)",
                                status
                            );
                            exec_res = Err(Mlx5Error::CommandFailed(status));
                        }
                        other => {
                            exec_res = other;
                            break 'attempt_loop;
                        }
                    }
                }
            }
        }

        cmd.set_uid(prev_uid);
        
        match exec_res {
            Ok(()) => {
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
            Err(e) => {
                if self.is_virtual_function() {
                    log::warn!(target: "mlx5", "CREATE_TIS failed ({:?}), attempting to discover existing TISN", e);
                    if let Some(tisn) = self.discover_existing_tisn()? {
                        let info = TisInfo {
                            tisn,
                            port: params.port,
                        };
                        self.tis_list.push(info);
                        log::info!(target: "mlx5", "Discovered existing TIS: tisn={}", tisn);
                        Ok(tisn)
                    } else {
                        log::warn!(target: "mlx5", "No TIS found, using TISN 0 as final fallback for VF");
                        Ok(0)
                    }
                } else {
                    Err(e)
                }
            }
        }
    }

    unsafe fn discover_existing_tisn(&mut self) -> Mlx5Result<Option<u32>> {
        let is_vf = self.is_virtual_function();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();

        let mut candidates = [0u32; 16];
        let mut candidate_count = 0usize;
        let mut push_candidate = |tisn: u32| {
            if candidate_count >= candidates.len() {
                return;
            }
            if candidates[..candidate_count].contains(&tisn) {
                return;
            }
            candidates[candidate_count] = tisn;
            candidate_count += 1;
        };

        for tisn in 0..16u32 {
            push_candidate(tisn);
        }

        let uids: &[u16] = if is_vf { &[0xFFFFu16, 0u16] } else { core::slice::from_ref(&prev_uid) };

        for &uid in uids {
            cmd.set_uid(uid);
            for &tisn in &candidates[..candidate_count] {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::resources::build_query_tis_input(in_mbox, tisn, 0, false);
                match cmd.execute(
                    CmdOpcode::QueryTis,
                    self.cmd_in_mbox_device,
                    0x40, // Full input size
                    self.cmd_out_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                ) {
                    Ok(()) => {
                        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                        let (prio, td, underlay_qpn, pd) = crate::resources::parse_query_tis_output(out_mbox);
                        log::debug!(
                            target: "mlx5",
                            "QUERY_TIS (uid={}) found tisn={} prio={} td={} underlay_qpn={:#x} pd={}",
                            uid,
                            tisn,
                            prio,
                            td,
                            underlay_qpn,
                            pd
                        );
                        cmd.set_uid(prev_uid);
                        return Ok(Some(tisn));
                    }
                    Err(_) => {}
                }
            }
        }

        cmd.set_uid(prev_uid);
        Ok(None)
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
            self.cmd_in_mbox_device,
            0x110,
            self.cmd_out_mbox_device,
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

    /// ユニキャストMACアドレスフィルタを追加
    ///
    /// 指定されたMACアドレス宛のパケットをTIRにフォワードする。
    ///
    /// # Arguments
    /// - `table_id`: 登録先のフローテーブルID
    /// - `group_id`: 登録先のフローグループID
    /// - `flow_index`: フローテーブル内のインデックス
    /// - `mac`: 宛先MACアドレス
    /// - `tirn`: フォワード先TIR番号
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn add_unicast_filter(
        &mut self,
        table_id: u32,
        group_id: u32,
        flow_index: u32,
        mac: MacAddr,
        tirn: u32,
    ) -> Mlx5Result<()> {
        let mut match_value = crate::flow::MatchValue::default();
        match_value.dst_mac = Some(mac.0);

        self.set_flow_table_entry(
            table_id,
            flow_index,
            group_id,
            crate::flow::FlowAction::Allow,
            Some(tirn),
            &match_value,
        )?;

        log::info!(target: "mlx5", "Unicast filter added: MAC {} -> TIR {}", mac, tirn);
        Ok(())
    }

    /// ブロードキャストフィルタを追加
    pub unsafe fn add_broadcast_filter(
        &mut self,
        table_id: u32,
        group_id: u32,
        flow_index: u32,
        tirn: u32,
    ) -> Mlx5Result<()> {
        self.add_unicast_filter(table_id, group_id, flow_index, MacAddr::BROADCAST, tirn)
    }

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
    pub unsafe fn create_flow_table(&mut self, config: &FlowTableConfig) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::flow::build_create_flow_table_input(in_mbox, config);

        cmd.execute(
            CmdOpcode::CreateFlowTable,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
    pub unsafe fn create_flow_group(
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
    pub unsafe fn set_flow_table_entry(
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

    /// フローテーブルにルールを追加
    ///
    /// # Safety
    /// - table_id, group_id, tirn が有効であること
    pub unsafe fn add_flow_rule(
        &mut self,
        table_id: u32,
        flow_index: u32,
        group_id: u32,
        tirn: u32,
        match_value: &crate::flow::MatchValue,
    ) -> Mlx5Result<()> {
        self.set_flow_table_entry(
            table_id,
            flow_index,
            group_id,
            crate::flow::FlowAction::Allow,
            Some(tirn),
            match_value,
        )
    }

    /// フロールールを削除
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn delete_flow_rule(
        &mut self,
        table_id: u32,
        flow_index: u32,
    ) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        crate::cmd::build_delete_flow_table_entry_input(in_mbox, table_id, flow_index);

        cmd.execute(
            CmdOpcode::DeleteFlowTableEntry,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        // キャッシュからも削除
        self.flow_entries.retain(|e| !(e.table_id == table_id && e.index == flow_index));

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
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
        eq_buf_pa: u64,
        log_eq_size: u8,
        msix_vector: u32,
        event_bitmask: u64,
    ) -> Mlx5Result<u32> {
        let is_vf = self.is_virtual_function();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        // EQメモリの初期化 (cycle bit = 1 to indicate HW ownership)
        let eq_depth = 1u32 << log_eq_size;
        let eq_ptr = eq_buf_virt as *mut u8;
        core::ptr::write_bytes(eq_ptr, 0, (eq_depth as usize) * crate::regs::eqe::EQE_SIZE);
        for i in 0..eq_depth {
            let offset = (i as usize * crate::regs::eqe::EQE_SIZE) + crate::regs::eqe::STATUS_OWN;
            core::ptr::write_volatile(eq_ptr.add(offset), 0x01);
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_eq_input(
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

        // Completion EQ on VF follows shared-resource UID semantics in mlx5 Linux path.
        // Keep this scoped to CREATE_EQ and restore previous UID immediately.
        let prev_uid = cmd.uid();
        let use_shared_uid = is_vf && event_bitmask == 0;
        if use_shared_uid {
            cmd.set_uid(0xFFFF);
        }

        let exec_res = cmd.execute(
            CmdOpcode::CreateEq,
            self.cmd_in_mbox_device,
            eq_in_len,
            self.cmd_out_mbox_device,
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
            eq_buf_pa,
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
        cq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_cq_size: u8,
        eqn: u32,
    ) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        // CQメモリの初期化 (cycle bit = 1 to indicate HW ownership)
        let cq_depth = 1u32 << log_cq_size;
        let cq_ptr = cq_buf_virt as *mut u8;
        core::ptr::write_bytes(cq_ptr, 0, (cq_depth as usize) * crate::regs::cqe::SIZE);
        for i in 0..cq_depth {
            let offset = (i as usize * crate::regs::cqe::SIZE) + crate::regs::cqe::OP_OWN;
            core::ptr::write_volatile(cq_ptr.add(offset), 0x01);
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_cq_input(
            in_mbox,
            log_cq_size,
            cq_buf_pa,
            db_pa,
            self.uar_page,
            eqn,
            false, // CQE compression disabled by default
        );

        let cq_bytes = (1usize << (log_cq_size as usize)) * crate::regs::cqe::SIZE;
        let cq_pages = (cq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let cq_in_len = (0x110 + cq_pages * 8) as u32;

        cmd.execute(
            CmdOpcode::CreateCq,
            self.cmd_in_mbox_device,
            cq_in_len,
            self.cmd_out_mbox_device,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let cqn = crate::cmd::parse_create_cq_output(out_mbox);

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
        sq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_sq_size: u8,
        cqn: u32,
        tisn: u32,
    ) -> Mlx5Result<u32> {
        let is_vf = self.is_virtual_function();
        let vhca_uid = self.sw_vhca_id;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        log::debug!(
            target: "mlx5",
            "[mlx5-diag] CREATE_SQ uid-base prev_uid={} vhca_uid={} is_vf={}",
            prev_uid,
            vhca_uid,
            is_vf
        );

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_sq_input(
            in_mbox,
            log_sq_size,
            sq_buf_pa,
            db_pa,
            cqn,
            tisn,
            self.uar_page,
            self.pd,
        );

        let sq_bytes = (1usize << (log_sq_size as usize)) * 64usize;
        let sq_pages = (sq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let sq_in_len = (0x110 + sq_pages * 8) as u32;
        log::debug!(
            target: "mlx5",
            "[mlx5-diag] CREATE_SQ in_len={:#x} pages={} cqn={} tisn={} log_sq_size={}",
            sq_in_len,
            sq_pages,
            cqn,
            tisn,
            log_sq_size
        );
        let mut uid_candidates = [0u16; 3];
        let mut uid_count = 0usize;
        let mut push_uid = |uid: u16| {
            if uid_candidates[..uid_count].contains(&uid) {
                return;
            }
            uid_candidates[uid_count] = uid;
            uid_count += 1;
        };
        push_uid(prev_uid);
        if is_vf {
            push_uid(0xFFFF);
            push_uid(0);
        }

        let mut exec_res: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        let tisn_candidates = if tisn == 0 { &[0u32, 1, 2, 3] } else { core::slice::from_ref(&tisn) };

        'outer: for &uid in &uid_candidates[..uid_count] {
            cmd.set_uid(uid);
            for &try_tisn in tisn_candidates {
                // Re-build input with the new TISN
                crate::cmd::build_create_sq_input(
                    &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox),
                    log_sq_size,
                    sq_buf_pa,
                    db_pa,
                    cqn,
                    self.pd,
                    self.uar_page,
                    try_tisn,
                );

                let res = cmd.execute(
                    CmdOpcode::CreateSq,
                    self.cmd_in_mbox_device,
                    sq_in_len,
                    self.cmd_out_mbox_device,
                    0x10,
                );
                match res {
                    Ok(()) => {
                        exec_res = Ok(());
                        log::info!(target: "mlx5", "SQ created with tisn={} uid={}", try_tisn, uid);
                        break 'outer;
                    }
                    Err(_) => {
                        exec_res = res;
                    }
                }
            }
        }
        cmd.set_uid(prev_uid);
        exec_res?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let sqn = crate::cmd::parse_create_sq_output(out_mbox);

        // Transition SQ from RESET to RDY
        self.transition_sq_to_ready(sqn)?;

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
        crate::cmd::build_modify_sq_input(in_mbox, sqn, WqState::Reset as u8, WqState::Ready as u8, 0, false);

        cmd.execute(
            CmdOpcode::ModifySq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
        rq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_rq_size: u8,
        cqn: u32,
        tirn: u32,
        scatter_fcs: bool,
        vlan_strip: bool,
    ) -> Mlx5Result<u32> {
        let is_vf = self.is_virtual_function();
        let pd = self.pd;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_create_rq_input(
            in_mbox,
            log_rq_size,
            rq_buf_pa,
            db_pa,
            cqn,
            pd,
            scatter_fcs,
            vlan_strip,
        );

        let rq_bytes = (1usize << (log_rq_size as usize)) * crate::defs::WQEBB_SIZE;
        let rq_pages = (rq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let rq_in_len = (0x110 + rq_pages * 8) as u32;

        cmd.execute(
            CmdOpcode::CreateRq,
            self.cmd_in_mbox_device,
            rq_in_len,
            self.cmd_out_mbox_device,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqn = crate::cmd::parse_create_rq_output(out_mbox);

        // Transition RQ from RESET to RDY
        self.transition_rq_to_ready(rqn)?;

        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
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

        // Substantial delay
        for _ in 0..1_000_000 { core::hint::spin_loop(); }

        log::debug!(target: "mlx5", "Transitioning RQN {} to RDY", rqn);
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_modify_rq_input(in_mbox, rqn, WqState::Reset as u8, WqState::Ready as u8, 0, false);

        match cmd.execute(
            CmdOpcode::ModifyRq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        ) {
            Ok(()) => {
                log::trace!(target: "mlx5", "RQ {} transitioned to RDY", rqn);
                Ok(())
            }
            Err(e) => {
                log::warn!(target: "mlx5", "MODIFY_RQ failed for rqn={} (status=0x3 usually means invalid TD/TIS but for RQ it often means state mismatch), continuing: {:?}", rqn, e);
                Ok(())
            }
        }
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
    /// SQを破棄
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn destroy_sq_hw(&mut self, sqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_destroy_sq_input(in_mbox, sqn);

        cmd.execute(
            CmdOpcode::DestroySq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "SQ {} destroyed", sqn);
        Ok(())
    }

    /// RQを破棄
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn destroy_rq_hw(&mut self, rqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_destroy_rq_input(in_mbox, rqn);

        cmd.execute(
            CmdOpcode::DestroyRq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "RQ {} destroyed", rqn);
        Ok(())
    }

    /// CQを破棄
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn destroy_cq_hw(&mut self, cqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_destroy_cq_input(in_mbox, cqn);

        cmd.execute(
            CmdOpcode::DestroyCq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "CQ {} destroyed", cqn);
        Ok(())
    }

    /// EQを破棄
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn destroy_eq_hw(&mut self, eqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_destroy_eq_input(in_mbox, eqn);

        cmd.execute(
            CmdOpcode::DestroyEq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "EQ {} destroyed", eqn);
        Ok(())
    }

    /// TIRを破棄
    pub unsafe fn destroy_tir_hw(&mut self, tirn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, tirn & 0x00FF_FFFF);

        cmd.execute(
            CmdOpcode::DestroyTir,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "TIR {} destroyed", tirn);
        Ok(())
    }

    /// TISを破棄
    pub unsafe fn destroy_tis_hw(&mut self, tisn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);

        cmd.execute(
            CmdOpcode::DestroyTis,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "TIS {} destroyed", tisn);
        Ok(())
    }

    /// RQTを破棄
    pub unsafe fn destroy_rqt_hw(&mut self, rqtn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_destroy_rqt_input(in_mbox, rqtn);

        cmd.execute(
            CmdOpcode::DestroyRqt,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "RQT {} destroyed", rqtn);
        Ok(())
    }

    /// フローテーブルを破棄
    pub unsafe fn destroy_flow_table_hw(&mut self, table_id: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_destroy_flow_table_input(in_mbox, table_id);

        cmd.execute(
            CmdOpcode::DestroyFlowTable,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "Flow Table {} destroyed", table_id);
        Ok(())
    }

    /// フローグループを破棄
    pub unsafe fn destroy_flow_group_hw(&mut self, table_id: u32, group_id: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_destroy_flow_group_input(in_mbox, table_id, group_id);

        cmd.execute(
            CmdOpcode::DestroyFlowGroup,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "Flow Group {} (FT={}) destroyed", group_id, table_id);
        Ok(())
    }

    /// フローテーブルエントリを削除
    pub unsafe fn delete_flow_table_entry_hw(&mut self, table_id: u32, flow_index: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_delete_flow_table_entry_input(in_mbox, table_id, flow_index);

        cmd.execute(
            CmdOpcode::DeleteFlowTableEntry,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "Flow Table Entry {} (FT={}) deleted", flow_index, table_id);
        Ok(())
    }

    /// MKEYを破棄
    pub unsafe fn destroy_mkey_hw(&mut self, mkey_index: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, mkey_index & 0x00FF_FFFF);

        cmd.execute(
            CmdOpcode::DestroyMkey,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "MKEY index {} destroyed", mkey_index);
        Ok(())
    }

    /// PDを解放
    pub unsafe fn dealloc_pd_hw(&mut self, pd: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_dealloc_pd_input(in_mbox, pd);

        cmd.execute(
            CmdOpcode::DeallocPd,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "PD {} deallocated", pd);
        Ok(())
    }

    /// RSS付きTIRを作成してRQTに紐づける
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn create_tir_with_rss(
        &mut self,
        rqtn: u32,
        rss_config: &RssConfig,
        td: u32,
    ) -> Mlx5Result<u32> {
        let params = TirParams {
            receive_type: TirReceiveType::Rqt,
            td,
            inline_rqn: 0,
            rqtn,
            rss: Some(rss_config.clone()),
            scatter_fcs: false,
            vlan_strip: false,
        };

        self.create_tir(&params)
    }

    /// TDを解放
    pub unsafe fn dealloc_td_hw(&mut self, td: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_dealloc_td_input(in_mbox, td);

        cmd.execute(
            CmdOpcode::DeallocTransportDomain,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "TD {} deallocated", td);
        Ok(())
    }

    /// UARを解放
    pub unsafe fn dealloc_uar_hw(&mut self, uar_page: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_dealloc_uar_input(in_mbox, uar_page);

        cmd.execute(
            CmdOpcode::DeallocUar,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "UAR page {} deallocated", uar_page);
        Ok(())
    }

    /// HCAを停止
    pub unsafe fn teardown_hca_hw(&mut self, graceful: bool) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_teardown_hca_input(in_mbox, graceful);

        cmd.execute(
            CmdOpcode::TeardownHca,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "HCA torn down (graceful={})", graceful);
        Ok(())
    }

    /// HCAを無効化
    pub unsafe fn disable_hca_hw(&mut self) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();

        cmd.execute(
            CmdOpcode::DisableHca,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "HCA disabled");
        Ok(())
    }

    /// SQをReadyからErrorに遷移（停止用）
    pub unsafe fn transition_sq_to_error(&mut self, sqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_modify_sq_input(in_mbox, sqn, WqState::Ready as u8, WqState::Error as u8, 0, false);

        cmd.execute(
            CmdOpcode::ModifySq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::trace!(target: "mlx5", "SQ {} transitioned to ERR", sqn);
        Ok(())
    }

    /// RQをReadyからErrorに遷移
    pub unsafe fn transition_rq_to_error(&mut self, rqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_modify_rq_input(in_mbox, rqn, WqState::Ready as u8, WqState::Error as u8, 0, false);

        cmd.execute(
            CmdOpcode::ModifyRq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::trace!(target: "mlx5", "RQ {} transitioned to ERR", rqn);
        Ok(())
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
        td: u32,
    ) -> Mlx5Result<u32> {
        if rq_numbers.is_empty() {
            return Err(Mlx5Error::InvalidParameter);
        }

        // RQTサイズ: 最小は対象RQ数を包含する2のべき乗 (ceil(log2(n)))
        let log_rqt_size = ((usize::BITS - (rq_numbers.len() - 1).leading_zeros()) as u8).max(1);
        let rqtn = self.create_rqt(rq_numbers, log_rqt_size)?;

        // RSS付きTIR作成
        let default_rss = RssConfig::default();
        let rss = rss_config.unwrap_or(&default_rss);
        let tirn = self.create_tir_with_rss(rqtn, rss, td)?;

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

    /// SR-IOV Virtual Functions を有効化・アクティブ化する
    ///
    /// # Arguments
    /// - `num_vfs`: 有効化する VF 数
    ///
    /// # Safety
    /// - PF デバイスであること
    /// - PCI 側で VF が有効化済みであること
    pub unsafe fn activate_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_virtual_function() {
            return Err(Mlx5Error::NotSupported);
        }

        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.vport_group_manager {
            log::warn!(target: "mlx5", "Device is not a VPORT group manager; cannot activate VFs");
            return Err(Mlx5Error::NotSupported);
        }

        log::info!(target: "mlx5", "Activating {} VFs...", num_vfs);

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        for i in 0..num_vfs {
            let vhca_id = i + 1; // VF vhca_id start from 1 usually, but it can depend on FW.
                                 // For mlx5, vhca_id for VFs are typically [1..num_vfs].

            // 1. ALLOCATED 状態へ遷移
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_modify_vhca_state_input(in_mbox, vhca_id, 0, 1); // 1 = ALLOCATED
                cmd.execute(
                    CmdOpcode::ModifyVhcaState,
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                )?;
            }

            // 2. ACTIVE 状態へ遷移
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_modify_vhca_state_input(in_mbox, vhca_id, 0, 2); // 2 = ACTIVE
                cmd.execute(
                    CmdOpcode::ModifyVhcaState,
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                )?;
            }

            // 3. VPORT admin state を UP に設定
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_modify_nic_vport_state_input(in_mbox, vhca_id, true);
                cmd.execute(
                    CmdOpcode::ModifyNicVportContext,
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                )?;
            }

            log::debug!(target: "mlx5", "VF {} (vhca_id={}) activated", i, vhca_id);
        }

        log::info!(target: "mlx5", "Successfully activated {} VFs", num_vfs);
        Ok(())
    }

    /// SR-IOV Virtual Functions を無効化する
    ///
    /// # Arguments
    /// - `num_vfs`: 無効化する VF 数
    ///
    /// # Safety
    /// - PF デバイスであること
    pub unsafe fn disable_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_virtual_function() {
            return Err(Mlx5Error::NotSupported);
        }

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        log::info!(target: "mlx5", "Disabling {} VFs...", num_vfs);

        for i in 0..num_vfs {
            let vhca_id = i + 1;

            // 1. VPORT admin state を DOWN に設定
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_modify_nic_vport_state_input(in_mbox, vhca_id, false);
                let _ = cmd.execute(
                    CmdOpcode::ModifyNicVportContext,
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }

            // 2. INVALID/TEARDOWN 状態へ遷移
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                crate::cmd::build_modify_vhca_state_input(in_mbox, vhca_id, 0, 3); // 3 = TEARDOWN
                let _ = cmd.execute(
                    CmdOpcode::ModifyVhcaState,
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                )?;
            }

            log::debug!(target: "mlx5", "VF {} (vhca_id={}) disabled", i, vhca_id);
        }

        Ok(())
    }

    /// VF の VHCA 状態をクエリする
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn query_vhca_state(&mut self, vhca_id: u16) -> Mlx5Result<u8> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be16(0x06, vhca_id);

        cmd.execute(
            CmdOpcode::QueryVhcaState,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        // vhca_state is at bits 24:27 of byte 0x10 in the output context
        let state = (out_mbox.read_be32(0x10) >> 24) as u8 & 0x0F;
        Ok(state)
    }

    /// VF の MAC アドレスを取得する（PF用）
    ///
    /// # Safety
    /// - PF デバイスであること
    pub unsafe fn query_vf_mac(&mut self, vf_index: u16) -> Mlx5Result<[u8; 6]> {
        if self.is_virtual_function() {
            return Err(Mlx5Error::NotSupported);
        }

        let vhca_id = vf_index + 1;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_query_nic_vport_input_ex(
            in_mbox,
            vhca_id,
            true, // other_vport
            None,
        );

        cmd.execute(
            CmdOpcode::QueryNicVportContext,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(crate::cmd::parse_vport_mac(out_mbox))
    }

    /// VF の MAC アドレスを設定する
    ///
    /// # Safety
    /// - PF デバイスであること
    pub unsafe fn set_vf_mac(&mut self, vf_index: u16, mac: [u8; 6]) -> Mlx5Result<()> {
        if self.is_virtual_function() {
            return Err(Mlx5Error::NotSupported);
        }

        let vhca_id = vf_index + 1;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_set_vf_mac_input(in_mbox, vhca_id, mac);
        cmd.execute(
            CmdOpcode::ModifyNicVportContext,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(
            target: "mlx5",
            "VF {} (vhca_id={}) MAC set to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            vf_index, vhca_id, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        Ok(())
    }

    /// VF の VLAN ID を設定する
    ///
    /// # Safety
    /// - PF デバイスであること
    pub unsafe fn set_vf_vlan(&mut self, vf_index: u16, vlan: u16, qos: u8) -> Mlx5Result<()> {
        if self.is_virtual_function() {
            return Err(Mlx5Error::NotSupported);
        }

        let vhca_id = vf_index + 1;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::build_set_vf_vlan_input(in_mbox, vhca_id, vlan, qos);
        cmd.execute(
            CmdOpcode::ModifyNicVportContext,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(
            target: "mlx5",
            "VF {} (vhca_id={}) VLAN set to {}, QoS={}",
            vf_index, vhca_id, vlan, qos
        );
        Ok(())
    }

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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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

    /// VPORTカウンタを取得してポート統計を更新
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn update_port_stats(&mut self, port_index: usize) -> Mlx5Result<()> {
        let port_num = self
            .ports
            .get(port_index)
            .map(|p| p.port_number())
            .ok_or(Mlx5Error::InvalidParameter)?;

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

    /// ポートのMACアドレスを変更
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn set_port_mac(&mut self, port_index: usize, mac: MacAddr) -> Mlx5Result<()> {
        let vport_num = self
            .ports
            .get(port_index)
            .map(|p| p.port_number())
            .ok_or(Mlx5Error::InvalidParameter)? as u16;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        // VPORT context modify
        crate::cmd::build_modify_nic_vport_mac_input(
            in_mbox,
            vport_num,
            false, // PF vport
            mac.0,
        );

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

        log::info!(target: "mlx5", "Port {} MAC updated to {}", vport_num, mac);
        Ok(())
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
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

        let segments = [crate::wq::DmaSegment {
            device_addr: data_phys,
            virt_addr: data_virt,
            len: data_len,
        }];

        sq.post_send(&segments, inline_hdr)
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
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
                    self.cmd_in_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                    self.cmd_out_mbox_device,
                    MLX5_CMD_MBOX_SIZE as u32,
                );
            }
            log::trace!(target: "mlx5", "Pages reclaimed");

            // 14. TEARDOWN_HCA
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            crate::cmd::build_teardown_hca_input(in_mbox, true);

            let _ = cmd.execute(
                CmdOpcode::TeardownHca,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            );
            log::trace!(target: "mlx5", "HCA torn down");

            // 15. DISABLE_HCA
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            *in_mbox = CmdMailbox::zeroed();

            let _ = cmd.execute(
                CmdOpcode::DisableHca,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
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
        cmdq_device: u64,
        cmd_in_mbox_virt: u64,
        cmd_in_mbox_device: u64,
        cmd_out_mbox_virt: u64,
        cmd_out_mbox_device: u64,
        // Phase 3: FWページ
        fw_page_addrs: &[u64],
        // Phase 4: MKEY
        mkey_params: &MkeyParams,
        // Phase 5-7: キューバッファ (virt, device) or (virt, device, db_virt, db_device)
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
        self.init_multi_queue(
            cmdq_virt,
            cmdq_device,
            cmd_in_mbox_virt,
            cmd_in_mbox_device,
            cmd_out_mbox_virt,
            cmd_out_mbox_device,
            fw_page_addrs,
            mkey_params,
            &[eq_buf],
            &[tx_cq_buf],
            &[rx_cq_buf],
            &[sq_buf],
            &[rq_buf],
            log_eq_size,
            log_cq_size,
            log_sq_size,
            log_rq_size,
        )
    }

    /// マルチキュー対応の完全初期化パイプライン
    pub unsafe fn init_multi_queue(
        &mut self,
        cmdq_virt: u64,
        cmdq_device: u64,
        cmd_in_mbox_virt: u64,
        cmd_in_mbox_device: u64,
        cmd_out_mbox_virt: u64,
        cmd_out_mbox_device: u64,
        fw_page_addrs: &[u64],
        mkey_params: &MkeyParams,
        eq_bufs: &[(u64, u64)],
        tx_cq_bufs: &[(u64, u64, u64, u64)],
        rx_cq_bufs: &[(u64, u64, u64, u64)],
        sq_bufs: &[(u64, u64, u64, u64)],
        rq_bufs: &[(u64, u64, u64, u64)],
        log_eq_size: u8,
        log_cq_size: u8,
        log_sq_size: u8,
        log_rq_size: u8,
    ) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "=== Starting multi-queue pipeline initialization ===");

        let res = (|| -> Mlx5Result<()> {
            // Phase 1: Boot sequence
            match self.wait_firmware() {
                Ok(()) => {
                    log::info!(target: "mlx5", "[1/8] Firmware ready");
                }
                Err(Mlx5Error::DeviceNotReady) if self.is_virtual_function() => {
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
            cmdq_device,
            cmd_in_mbox_virt,
            cmd_in_mbox_device,
            cmd_out_mbox_virt,
            cmd_out_mbox_device,
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
                log::warn!(target: "mlx5", "[2/8] QUERY_PAGES boot failed ({:?})", e);
            }
        }

        if requested_pages > 0 && !fw_page_addrs.is_empty() {
            let give_pages = core::cmp::min(requested_pages, fw_page_addrs.len());
            self.provide_pages(page_function_id, &fw_page_addrs[..give_pages])?;
            pages_consumed = give_pages;
        }

        // INIT_HCA 前に init pages も供給
        let mut init_page_function_id = self.fw_function_id;
        let mut init_requested_pages = 0usize;
        match self.query_required_pages(0x02) {
            Ok((func_id, num_pages)) => {
                init_page_function_id = func_id;
                self.fw_function_id = func_id;
                init_requested_pages = core::cmp::max(num_pages, 0) as usize;
            }
            Err(_) => {}
        }

        if init_requested_pages > 0 && pages_consumed < fw_page_addrs.len() {
            let remaining = &fw_page_addrs[pages_consumed..];
            let give_pages = core::cmp::min(init_requested_pages, remaining.len());
            let _ = self.provide_pages(init_page_function_id, &remaining[..give_pages]);
        }

        self.init_hca()?;
        log::info!(target: "mlx5", "[2/8] HCA initialized");

        if self.is_virtual_function() {
            if let Some(cmd) = self.cmd.as_mut() {
                cmd.set_uid(0xFFFF);
            }
        }

        // Phase 3: Resource allocation
        self.alloc_uar()?;
        self.alloc_pd()?;
        self.alloc_td()?;
        
        // VF Probe: Try to find a valid PD/TD by testing different values if allocated ones fail
        let mut pd_candidates = Vec::new();
        if self.pd != 0 { pd_candidates.push(self.pd); }
        pd_candidates.extend_from_slice(&[0, 1, 17]);
        
        let mut td_candidates = Vec::new();
        if self.td != 0 { td_candidates.push(self.td); }
        td_candidates.extend_from_slice(&[0, 1]);

        log::info!(target: "mlx5", "[3/8] Core resources allocated (UAR, PD, TD)");

        // Phase 4: FW setup
        let _ = self.set_driver_version();
        log::info!(target: "mlx5", "[4/8] Driver version set");

        // Phase 5: Key resources
        self.query_port_mac(0)?;
        log::info!(target: "mlx5", "[5/8] MAC address obtained");

        let mut mkey_created = false;
        for &pd in &pd_candidates {
            let mut effective_mkey_params = mkey_params.clone();
            effective_mkey_params.pd = pd;
            match self.create_mkey(&effective_mkey_params) {
                Ok(_) => {
                    log::info!(target: "mlx5", "[5/8] MKEY created with PD {}", pd);
                    mkey_created = true;
                    break;
                }
                Err(e) => {
                    log::warn!(target: "mlx5", "[5/8] MKEY creation failed with PD {}: {:?}", pd, e);
                }
            }
        }

        if !mkey_created && self.is_virtual_function() {
            let lkey = self.query_reserved_lkey().unwrap_or(0x100);
            self.set_mkey(lkey);
            log::warn!(target: "mlx5", "[5/8] Using reserved lkey={:#x}", lkey);
        } else if !mkey_created {
            return Err(Mlx5Error::NotSupported);
        }

        // Phase 6: Queues (Multi-queue)
        let mut eqn_list = Vec::with_capacity(eq_bufs.len());
        for (i, buf) in eq_bufs.iter().enumerate() {
            let eqn = self.create_eq_hw(buf.0, buf.1, log_eq_size, i as u32, 0)?;
            eqn_list.push(eqn);
        }
        let primary_eqn = eqn_list[0];
        log::info!(target: "mlx5", "[6/8] {} EQs created", eqn_list.len());

        // Wait for EQs to be fully initialized in FW
        for _ in 0..1_000_000 { core::hint::spin_loop(); }

        let mut tx_cqn_list = Vec::with_capacity(tx_cq_bufs.len());
        for buf in tx_cq_bufs {
            let cqn = self.create_cq_hw(buf.0, buf.1, buf.2, buf.3, log_cq_size, primary_eqn)?;
            tx_cqn_list.push(cqn);
        }
        log::info!(target: "mlx5", "[6/8] {} TX CQs created", tx_cqn_list.len());

        let mut rx_cqn_list = Vec::with_capacity(rx_cq_bufs.len());
        for buf in rx_cq_bufs {
            let cqn = self.create_cq_hw(buf.0, buf.1, buf.2, buf.3, log_cq_size, primary_eqn)?;
            rx_cqn_list.push(cqn);
        }
        log::info!(target: "mlx5", "[6/8] {} RX CQs created", rx_cqn_list.len());

        // Phase 7: TX path
        let tis_params = crate::resources::TisParams {
            pd: self.pd,
            td: self.td,
            port: 1,
            prio: 0,
        };
        let tisn = match self.create_tis(&tis_params) {
            Ok(n) => n,
            Err(_) => {
                log::warn!(target: "mlx5", "CREATE_TIS failed, fallback to discover");
                self.discover_existing_tisn()?.unwrap_or(0)
            }
        };
        
        let mut sqn_list = Vec::with_capacity(sq_bufs.len());
        for (i, buf) in sq_bufs.iter().enumerate() {
            let cqn = tx_cqn_list[i % tx_cqn_list.len()];
            match self.create_sq_hw(buf.0, buf.1, buf.2, buf.3, log_sq_size, cqn, tisn) {
                Ok(sqn) => sqn_list.push(sqn),
                Err(e) => log::warn!(target: "mlx5", "SQ {} creation failed: {:?}", i, e),
            }
        }
        log::info!(target: "mlx5", "[7/8] {} SQs created", sqn_list.len());

        // Phase 8: RX path
        let (scatter_fcs, vlan_strip) = {
            let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
            (caps.scatter_fcs, caps.vlan_strip)
        };

        let mut rqn_list = Vec::with_capacity(rq_bufs.len());
        for (i, buf) in rq_bufs.iter().enumerate() {
            let cqn = rx_cqn_list[i % rx_cqn_list.len()];
            let rqn = self.create_rq_hw(buf.0, buf.1, buf.2, buf.3, log_rq_size, cqn, 0, scatter_fcs, vlan_strip)?;
            rqn_list.push(rqn);
        }
        log::info!(target: "mlx5", "[8/8] {} RQs created", rqn_list.len());

        // Multi-queue RSS setup
        let tir_td = if self.is_virtual_function() { 0 } else { self.td };

        let tir_res = if rqn_list.len() > 1 {
            self.setup_multi_queue_rss(&rqn_list, None, tir_td)
        } else {
            let tir_params = crate::resources::TirParams {
                receive_type: TirReceiveType::DirectRq,
                td: tir_td,
                inline_rqn: rqn_list[0],
                rqtn: 0,
                rss: None,
                scatter_fcs,
                vlan_strip,
            };
            match self.create_tir(&tir_params) {
                Ok(tirn) => {
                    if let Some(rq) = self.rqs.last_mut() {
                        rq.tirn = tirn;
                    }
                    let _ = self.setup_rx_flow_table(tirn);
                    Ok(tirn)
                }
                Err(e) => Err(e),
            }
        };

        match tir_res {
            Ok(tirn) => log::info!(target: "mlx5", "[8/8] RX path setup complete (TIR={})", tirn),
            Err(e) => log::warn!(target: "mlx5", "[8/8] RX path setup failed but continuing: {:?}", e),
        }

        // Set CQ moderation defaults for all CQs (Non-fatal)
        let total_cqs = self.cqs.len();
        for i in 0..total_cqs {
            let _ = self.set_cq_moderation(i, 16, 64);
        }

        // Finalize
        if let Some(port) = self.ports.get_mut(0) {
            port.admin_up();
        }

        self.resources_allocated = true;
        self.state = DeviceState::Active;

        log::info!(target: "mlx5", "=== Multi-queue initialization complete ===");
        Ok(())
        })();

        if let Err(e) = res {
            log::error!(
                target: "mlx5",
                "Full init failed: {:?}. (Hint: if on VFIO, ensure Bus Master is enabled on host: 'sudo setpci -s <bdf> COMMAND=0x7')",
                e
            );
            return Err(e);
        }

        Ok(())
    }

    /// デバイスの完全なシャットダウンとリソース解放
    ///
    /// # Safety
    /// - コマンドインタフェースが使用可能であること
    pub unsafe fn teardown_full(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "=== Starting full teardown sequence ===");

        if self.state == DeviceState::Uninitialized || self.state == DeviceState::Error {
            log::warn!(target: "mlx5", "Device in state {:?}, attempting best-effort teardown", self.state);
        }

        // 1. パケット送受信の停止
        let sqns: Vec<u32> = self.sqs.iter().map(|sq| sq.sqn).collect();
        for sqn in sqns {
            let _ = self.transition_sq_to_error(sqn);
        }
        let rqns: Vec<u32> = self.rqs.iter().map(|rq| rq.rqn).collect();
        for rqn in rqns {
            let _ = self.transition_rq_to_error(rqn);
        }
        log::info!(target: "mlx5", "[1/10] Traffic stopped");

        // 2. フローテーブルの破棄
        let entries = core::mem::take(&mut self.flow_entries);
        for entry in entries {
            let _ = self.delete_flow_table_entry_hw(entry.table_id, entry.index);
        }
        let groups = core::mem::take(&mut self.flow_groups);
        for group in groups {
            let _ = self.destroy_flow_group_hw(group.table_id, group.group_id);
        }
        let tables = core::mem::take(&mut self.flow_tables);
        for table in tables {
            let _ = self.destroy_flow_table_hw(table.table_id);
        }
        log::info!(target: "mlx5", "[2/10] Flow steering resources destroyed");

        // 3. TIR / TIS / RQT の破棄
        let tir_list = core::mem::take(&mut self.tir_list);
        for tir in tir_list {
            let _ = self.destroy_tir_hw(tir.tirn);
        }
        let tis_list = core::mem::take(&mut self.tis_list);
        for tis in tis_list {
            let _ = self.destroy_tis_hw(tis.tisn);
        }
        let rq_tables = core::mem::take(&mut self.rq_tables);
        for rqt in rq_tables {
            let _ = self.destroy_rqt_hw(rqt.rqtn);
        }
        log::info!(target: "mlx5", "[3/10] Transport resources (TIR/TIS/RQT) destroyed");

        // 4. SQ / RQ の破棄
        while let Some(sq) = self.sqs.pop() {
            let _ = self.destroy_sq_hw(sq.sqn);
        }
        while let Some(rq) = self.rqs.pop() {
            let _ = self.destroy_rq_hw(rq.rqn);
        }
        log::info!(target: "mlx5", "[4/10] Work Queues (SQ/RQ) destroyed");

        // 5. CQ の破棄
        while let Some(cq) = self.cqs.pop() {
            let _ = self.destroy_cq_hw(cq.cqn);
        }
        log::info!(target: "mlx5", "[5/10] Completion Queues (CQ) destroyed");

        // 6. EQ の破棄
        while let Some(eq) = self.eqs.pop() {
            let _ = self.destroy_eq_hw(eq.eqn);
        }
        log::info!(target: "mlx5", "[6/10] Event Queues (EQ) destroyed");

        // 7. MKEY の破棄
        if let Some(info) = self.mkey_info.take() {
            let _ = self.destroy_mkey_hw(info.mkey_index);
        }
        log::info!(target: "mlx5", "[7/10] Memory Key destroyed");

        // 8. PD / TD / UAR の解放
        if self.pd != 0 {
            let _ = self.dealloc_pd_hw(self.pd);
            self.pd = 0;
        }
        if self.td != 0 {
            let _ = self.dealloc_td_hw(self.td);
            self.td = 0;
        }
        while let Some(uar) = self.allocated_uars.pop() {
            let _ = self.dealloc_uar_hw(uar);
        }
        log::info!(target: "mlx5", "[8/10] Core resources (PD/TD/UAR) deallocated");

        // 9. HCA Teardown & Disable
        let _ = self.teardown_hca_hw(true);
        let _ = self.disable_hca_hw();
        log::info!(target: "mlx5", "[9/10] HCA torn down and disabled");

        // 10. FW ページの回収 (MANAGE_PAGES reclaiming)
        let total_pages = self.page_manager.total_given_pages();
        if total_pages > 0 {
            log::info!(target: "mlx5", "[10/10] Reclaiming {} pages from FW", total_pages);
            let _ = self.reclaim_pages(self.fw_function_id, total_pages as u32);
        }

        self.state = DeviceState::Uninitialized;
        self.resources_allocated = false;

        log::info!(target: "mlx5", "=== Full teardown complete ===");
        Ok(())
    }

    /// 稼働中の RQ 数を取得
    pub fn num_rqs(&self) -> usize {
        self.rqs.len()
    }

    /// 稼働中の SQ 数を取得
    pub fn num_sqs(&self) -> usize {
        self.sqs.len()
    }

    /// ヘルスチェック
    ///
    /// # Safety
    /// - bar0_base が有効であること
    pub unsafe fn health_check(&self) -> bool {
        fw::check_health(self.bar0_base)
    }
}
