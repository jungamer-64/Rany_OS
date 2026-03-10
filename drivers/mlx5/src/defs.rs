// ============================================================================
// drivers/mlx5/src/defs.rs - Constants and common definitions
// ============================================================================
//! ConnectX ファミリ (mlx5) ハードウェア定数・共通定義
//!
//! ConnectX-4 / 4 Lx / 5 / 5 Ex / 6 / 6 Dx / 6 Lx / 7 をサポート。

// ============================================================================
// PCI Identification
// ============================================================================

/// Mellanox (NVIDIA Networking) PCI Vendor ID
pub const MELLANOX_VENDOR_ID: u16 = 0x15B3;

// -- Connect-IB --
/// Connect-IB PCI Device ID (Physical Function)
pub const CONNECTIB_DEVICE_ID: u16 = 0x1011;
/// Connect-IB VF PCI Device ID
pub const CONNECTIB_VF_DEVICE_ID: u16 = 0x1012;

// -- ConnectX-4 --
/// ConnectX-4 EN PCI Device ID (Physical Function)
pub const CONNECTX4_DEVICE_ID: u16 = 0x1013;
/// ConnectX-4 EN VF PCI Device ID
pub const CONNECTX4_VF_DEVICE_ID: u16 = 0x1014;
/// ConnectX-4 Lx EN PCI Device ID (Physical Function)
pub const CONNECTX4_LX_DEVICE_ID: u16 = 0x1015;
/// ConnectX-4 Lx EN PCI Device ID (Virtual Function)
pub const CONNECTX4_LX_VF_DEVICE_ID: u16 = 0x1016;

// -- ConnectX-5 --
/// ConnectX-5 EN PCI Device ID (Physical Function)
pub const CONNECTX5_DEVICE_ID: u16 = 0x1017;
/// ConnectX-5 EN VF PCI Device ID
pub const CONNECTX5_VF_DEVICE_ID: u16 = 0x1018;
/// ConnectX-5 Ex EN PCI Device ID (Physical Function)
pub const CONNECTX5_EX_DEVICE_ID: u16 = 0x1019;
/// ConnectX-5 Ex EN VF PCI Device ID
pub const CONNECTX5_EX_VF_DEVICE_ID: u16 = 0x101A;

// -- ConnectX-6 --
/// ConnectX-6 EN PCI Device ID (Physical Function)
pub const CONNECTX6_DEVICE_ID: u16 = 0x101B;
/// ConnectX-6 EN VF PCI Device ID
pub const CONNECTX6_VF_DEVICE_ID: u16 = 0x101C;
/// ConnectX-6 Dx EN PCI Device ID (Physical Function)
pub const CONNECTX6_DX_DEVICE_ID: u16 = 0x101D;
/// ConnectX-6 Dx EN VF PCI Device ID
pub const CONNECTX6_DX_VF_DEVICE_ID: u16 = 0x101E;
/// ConnectX-6 Lx EN PCI Device ID (Physical Function)
pub const CONNECTX6_LX_DEVICE_ID: u16 = 0x101F;
/// ConnectX-6 Lx EN VF PCI Device ID
pub const CONNECTX6_LX_VF_DEVICE_ID: u16 = 0x1020;

// -- ConnectX-7 --
/// ConnectX-7 EN PCI Device ID (Physical Function)
pub const CONNECTX7_DEVICE_ID: u16 = 0x1021;
/// ConnectX-7 EN VF PCI Device ID
pub const CONNECTX7_VF_DEVICE_ID: u16 = 0x1022;

// ============================================================================
// Supported Device ID Table
// ============================================================================

/// ドライバがサポートする全デバイスの (Vendor ID, Device ID) ペア
pub static SUPPORTED_DEVICE_IDS: &[(u16, u16)] = &[
    // Connect-IB
    (MELLANOX_VENDOR_ID, CONNECTIB_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTIB_VF_DEVICE_ID),
    // ConnectX-4
    (MELLANOX_VENDOR_ID, CONNECTX4_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX4_VF_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX4_LX_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX4_LX_VF_DEVICE_ID),
    // ConnectX-5
    (MELLANOX_VENDOR_ID, CONNECTX5_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX5_VF_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX5_EX_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX5_EX_VF_DEVICE_ID),
    // ConnectX-6
    (MELLANOX_VENDOR_ID, CONNECTX6_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX6_VF_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX6_DX_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX6_DX_VF_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX6_LX_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX6_LX_VF_DEVICE_ID),
    // ConnectX-7
    (MELLANOX_VENDOR_ID, CONNECTX7_DEVICE_ID),
    (MELLANOX_VENDOR_ID, CONNECTX7_VF_DEVICE_ID),
];

// ============================================================================
// ConnectX Variant Identification
// ============================================================================

/// ConnectX ファミリのバリアント識別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectXVariant {
    /// Connect-IB
    ConnectIB,
    /// ConnectX-4
    CX4,
    /// ConnectX-4 Lx
    CX4Lx,
    /// ConnectX-5
    CX5,
    /// ConnectX-5 Ex
    CX5Ex,
    /// ConnectX-6
    CX6,
    /// ConnectX-6 Dx
    CX6Dx,
    /// ConnectX-6 Lx
    CX6Lx,
    /// ConnectX-7
    CX7,
    /// 不明なバリアント（新規デバイス等）
    Unknown(u16),
}

impl ConnectXVariant {
    /// PCI Device ID からバリアントを判別
    pub fn from_device_id(device_id: u16) -> Self {
        match device_id {
            CONNECTIB_DEVICE_ID | CONNECTIB_VF_DEVICE_ID => Self::ConnectIB,
            CONNECTX4_DEVICE_ID | CONNECTX4_VF_DEVICE_ID => Self::CX4,
            CONNECTX4_LX_DEVICE_ID | CONNECTX4_LX_VF_DEVICE_ID => Self::CX4Lx,
            CONNECTX5_DEVICE_ID | CONNECTX5_VF_DEVICE_ID => Self::CX5,
            CONNECTX5_EX_DEVICE_ID | CONNECTX5_EX_VF_DEVICE_ID => Self::CX5Ex,
            CONNECTX6_DEVICE_ID | CONNECTX6_VF_DEVICE_ID => Self::CX6,
            CONNECTX6_DX_DEVICE_ID | CONNECTX6_DX_VF_DEVICE_ID => Self::CX6Dx,
            CONNECTX6_LX_DEVICE_ID | CONNECTX6_LX_VF_DEVICE_ID => Self::CX6Lx,
            CONNECTX7_DEVICE_ID | CONNECTX7_VF_DEVICE_ID => Self::CX7,
            other => Self::Unknown(other),
        }
    }

    /// 人間可読なデバイス名を返す
    pub fn name(&self) -> &'static str {
        match self {
            Self::ConnectIB => "Connect-IB",
            Self::CX4 => "ConnectX-4",
            Self::CX4Lx => "ConnectX-4 Lx",
            Self::CX5 => "ConnectX-5",
            Self::CX5Ex => "ConnectX-5 Ex",
            Self::CX6 => "ConnectX-6",
            Self::CX6Dx => "ConnectX-6 Dx",
            Self::CX6Lx => "ConnectX-6 Lx",
            Self::CX7 => "ConnectX-7",
            Self::Unknown(_) => "ConnectX (unknown)",
        }
    }

    /// Virtual Function かどうか判定
    pub fn is_vf_device_id(device_id: u16) -> bool {
        matches!(
            device_id,
            CONNECTIB_VF_DEVICE_ID
                | CONNECTX4_VF_DEVICE_ID
                | CONNECTX4_LX_VF_DEVICE_ID
                | CONNECTX5_VF_DEVICE_ID
                | CONNECTX5_EX_VF_DEVICE_ID
                | CONNECTX6_VF_DEVICE_ID
                | CONNECTX6_DX_VF_DEVICE_ID
                | CONNECTX6_LX_VF_DEVICE_ID
                | CONNECTX7_VF_DEVICE_ID
        )
    }
}

// ============================================================================
// Device Limits
// ============================================================================

/// 最大ポート数
pub const MLX5_MAX_PORTS: usize = 2;

/// 最大Event Queue数
pub const MLX5_MAX_EQS: usize = 64;

/// 最大Completion Queue数
pub const MLX5_MAX_CQS: usize = 256;

/// EQエントリ数（2のべき乗）
pub const MLX5_EQ_DEPTH: u32 = 64;

/// CQエントリ数（2のべき乗）
pub const MLX5_CQ_DEPTH: u32 = 64;

/// SQ/RQエントリ数（2のべき乗）
pub const MLX5_WQ_DEPTH: u32 = 256;

/// 最大MTU
pub const MLX5_MAX_MTU: u32 = 9216;

/// デフォルトMTU
pub const MLX5_DEFAULT_MTU: u32 = 1500;

/// 受信バッファサイズ（MTU + Ethernetヘッダ + VLAN + FCS）
pub const MLX5_RX_BUF_SIZE: usize = 2048;

/// ページサイズ
pub const MLX5_PAGE_SIZE: usize = 4096;

// ============================================================================
// Command Interface
// ============================================================================

/// コマンドメールボックスの論理サイズ (16KB)
pub const MLX5_CMD_MBOX_SIZE: usize = 16384;

/// 記述子に inline で載る mailbox 先頭データ長
pub const MLX5_CMD_INLINE_SIZE: usize = 16;

/// chained mailbox block の payload サイズ
pub const MLX5_CMD_DATA_BLOCK_SIZE: usize = 512;

/// Linux `struct mlx5_cmd_prot_block` の実サイズ
pub const MLX5_CMD_PROT_BLOCK_SIZE: usize = 576;

/// Linux dma_pool と同じ mailbox block のアラインメント
pub const MLX5_CMD_PROT_BLOCK_ALIGN: usize = 1024;

pub const fn mlx5_cmd_chained_blocks(len: usize) -> usize {
    if len <= MLX5_CMD_INLINE_SIZE {
        0
    } else {
        (len - MLX5_CMD_INLINE_SIZE + MLX5_CMD_DATA_BLOCK_SIZE - 1) / MLX5_CMD_DATA_BLOCK_SIZE
    }
}

pub const fn mlx5_cmd_mailbox_backing_size(len: usize) -> usize {
    mlx5_cmd_chained_blocks(len) * MLX5_CMD_PROT_BLOCK_ALIGN
}

/// 16KB 論理 mailbox を保持するために必要な DMA backing size
pub const MLX5_CMD_MBOX_BACKING_SIZE: usize = mlx5_cmd_mailbox_backing_size(MLX5_CMD_MBOX_SIZE);

/// コマンドインタフェースの最大同時実行コマンド数
pub const MLX5_MAX_COMMANDS: usize = 32;

/// コマンドタイムアウト（ミリ秒）
pub const MLX5_CMD_TIMEOUT_MS: u64 = 60_000;

/// FWブート待ちタイムアウト（ミリ秒）
pub const MLX5_FW_BOOT_TIMEOUT_MS: u64 = 30_000;

// ============================================================================
// Command Opcodes (mlx5 IFC specification)
// ============================================================================

/// mlx5 コマンドオペコード
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdOpcode {
    /// FW状態クエリ
    QueryHcaCap = 0x0100,
    /// アダプタ情報クエリ
    QueryAdapter = 0x0101,
    /// HCA初期化
    InitHca = 0x0102,
    /// HCA停止
    TeardownHca = 0x0103,
    /// HCA有効化
    EnableHca = 0x0104,
    /// HCA無効化
    DisableHca = 0x0105,

    /// ページ要求クエリ
    QueryPages = 0x0107,
    /// ページ管理
    ManagePages = 0x0108,
    /// HCA capability 設定
    SetHcaCap = 0x0109,

    /// ISSI（Interface Stepping-Stone Identifier）クエリ
    QueryIssi = 0x010A,
    /// ISSI設定
    SetIssi = 0x010B,

    /// EQ作成
    CreateEq = 0x0301,
    /// EQ破棄
    DestroyEq = 0x0302,

    /// CQ作成
    CreateCq = 0x0400,
    /// CQ破棄
    DestroyCq = 0x0401,

    /// SQ作成
    CreateSq = 0x0904,
    /// SQ状態変更
    ModifySq = 0x0905,
    /// SQ破棄
    DestroySq = 0x0906,
    /// SQクエリ
    QuerySq = 0x0907,

    /// RQ作成
    CreateRq = 0x0908,
    /// RQ状態変更
    ModifyRq = 0x0909,
    /// RQ破棄
    DestroyRq = 0x090A,
    /// RQクエリ
    QueryRq = 0x090B,
    /// RMP (Receive Memory Pool) 作成
    CreateRmp = 0x090C,
    /// RMP状態変更
    ModifyRmp = 0x090D,
    /// RMP破棄
    DestroyRmp = 0x090E,

    /// TIR (Transport Interface Receive) 作成
    CreateTir = 0x0900,
    /// TIR状態変更
    ModifyTir = 0x0901,
    /// TIR破棄
    DestroyTir = 0x0902,

    /// TIS (Transport Interface Send) 作成
    CreateTis = 0x0912,
    /// TIS状態変更
    ModifyTis = 0x0913,
    /// TIS破棄
    DestroyTis = 0x0914,
    /// TISクエリ
    QueryTis = 0x0915,

    /// MACアドレスクエリ
    QueryNicVportContext = 0x0754,
    /// VPORT状態変更
    ModifyNicVportContext = 0x0755,

    /// ポート状態クエリ
    QueryVportState = 0x0750,
    /// ポート状態変更
    ModifyVportState = 0x0751,

    /// MKEYアロケーション
    CreateMkey = 0x0200,
    /// MKEYクエリ
    QueryMkey = 0x0201,
    /// MKEY破棄
    DestroyMkey = 0x0202,
    /// 特殊コンテキスト（reserved lkey 等）クエリ
    QuerySpecialContexts = 0x0203,

    /// アクセスレジスタ
    AccessRegister = 0x0805,

    /// UAR (User Access Region) 割り当て
    AllocUar = 0x0802,
    /// UAR解放
    DeallocUar = 0x0803,

    /// Protection Domain 割り当て
    AllocPd = 0x0800,
    /// Protection Domain解放
    DeallocPd = 0x0801,

    /// Transport Domain 割り当て
    AllocTransportDomain = 0x0816,
    /// Transport Domain解放
    DeallocTransportDomain = 0x0817,

    /// RQT (Receive Queue Table) 作成
    CreateRqt = 0x0916,
    /// RQT状態変更
    ModifyRqt = 0x0917,
    /// RQT破棄
    DestroyRqt = 0x0918,

    /// フローテーブル作成
    CreateFlowTable = 0x0930,
    /// フローテーブル破棄
    DestroyFlowTable = 0x0931,
    /// フローグループ作成
    CreateFlowGroup = 0x0933,
    /// フローグループ破棄
    DestroyFlowGroup = 0x0934,
    /// フローテーブルエントリ設定
    SetFlowTableEntry = 0x0936,
    /// フローテーブルエントリ削除
    DeleteFlowTableEntry = 0x0938,

    /// VPORTカウンタクエリ
    QueryVportCounter = 0x0770,
    /// VNIC environment クエリ
    QueryVnicEnv = 0x076F,

    /// VHCA 状態変更 (SR-IOV VF 有効化等)
    ModifyVhcaState = 0x0B0E,
    /// VHCA 状態クエリ
    QueryVhcaState = 0x0B0D,

    /// ドライババージョン設定
    SetDriverVersion = 0x010D,

    /// CQモデレーション設定
    ModifyCq = 0x0402,

    /// NOP (テスト用)
    Nop = 0x080D,
}

// ============================================================================
// Command Status Codes
// ============================================================================

/// コマンド descriptor delivery ステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdDeliveryStatus {
    Ok,
    SignatureError,
    TokenError,
    BadBlockNumber,
    OutPointerAlignment,
    InPointerAlignment,
    FirmwareError,
    InputLengthError,
    OutputLengthError,
    ReservedFieldsNotClear,
    DescriptorError,
    Unknown(u8),
}

impl CmdDeliveryStatus {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x00 => Self::Ok,
            0x01 => Self::SignatureError,
            0x02 => Self::TokenError,
            0x03 => Self::BadBlockNumber,
            0x04 => Self::OutPointerAlignment,
            0x05 => Self::InPointerAlignment,
            0x06 => Self::FirmwareError,
            0x07 => Self::InputLengthError,
            0x08 => Self::OutputLengthError,
            0x09 => Self::ReservedFieldsNotClear,
            0x10 => Self::DescriptorError,
            other => Self::Unknown(other),
        }
    }
}

// ============================================================================
// Event Types
// ============================================================================

/// イベントタイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// CQ完了通知
    CompletionEvent = 0x00,
    /// ポート状態変更
    PortStateChange = 0x09,
    /// コマンド完了
    CommandCompletion = 0x0A,
    /// ページ要求
    PageRequest = 0x0B,
    /// 内部エラー (Health Event)
    InternalError = 0x08,
    /// NICアラート
    NicVportChange = 0x0D,
    /// ポートモジュールイベント
    PortModule = 0x0F,
    /// 温度アラート
    TempWarning = 0x17,
    /// 一般イベント
    GeneralEvent = 0x22,
}

impl EventType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::CompletionEvent),
            0x09 => Some(Self::PortStateChange),
            0x0A => Some(Self::CommandCompletion),
            0x0B => Some(Self::PageRequest),
            0x08 => Some(Self::InternalError),
            0x0D => Some(Self::NicVportChange),
            0x0F => Some(Self::PortModule),
            0x17 => Some(Self::TempWarning),
            0x22 => Some(Self::GeneralEvent),
            _ => None,
        }
    }
}

// ============================================================================
// HCA Capabilities Fields
// ============================================================================

/// HCA Capability 応答の主要フィールド
#[derive(Debug, Clone, Copy, Default)]
pub struct HcaCaps {
    /// 最大CQ数
    pub max_cq: u32,
    /// 最大SQ数
    pub max_sq: u32,
    /// 最大RQ数
    pub max_rq: u32,
    /// 最大EQ数
    pub max_eq: u32,
    /// 最大MSI-X数 (VFs)
    pub max_msix: u32,
    /// 最大MKEY数
    pub max_mkey: u32,
    /// 最大MTU
    pub max_mtu: u32,
    /// ポート数
    pub num_ports: u8,
    /// GENERAL_2 capability page が存在する
    pub hca_cap_2: bool,
    /// ログ最大CQサイズ（2^n）
    pub log_max_cq_sz: u8,
    /// ログ最大SQサイズ
    pub log_max_sq_sz: u8,
    /// ログ最大RQサイズ
    pub log_max_rq_sz: u8,
    /// ログ最大TIR数
    pub log_max_tir: u8,
    /// ログ最大TIS数
    pub log_max_tis: u8,
    /// 1SQあたりのログ最大TIS参照数
    pub log_max_tis_per_sq: u8,
    /// ログ最大Transport Domain数
    pub log_max_transport_domain: u8,
    /// ログ最大EQサイズ
    pub log_max_eq_sz: u8,
    /// Scatter FCS 対応
    pub scatter_fcs: bool,
    /// VLAN stripping 対応
    pub vlan_strip: bool,
    /// チェックサムオフロード対応
    pub csum_cap: bool,
    /// CQE圧縮対応
    pub cqe_compression: bool,
    /// CQEバージョン
    pub cqe_version: u8,
    /// TIS/TIR/TD ordering capability bit
    pub tis_tir_td_order: bool,
    /// VPORT グループマネージャ（PFでVF管理可能か）
    pub vport_group_manager: bool,
    /// E-Switch マネージャ
    pub eswitch_manager: bool,
    /// INIT_HCA で sw_owner_id を渡せる
    pub sw_owner_id_cap: bool,
    /// SET_DRIVER_VERSION を受け付ける
    pub driver_version_cap: bool,
    /// QUERY_VHCA_STATE / MODIFY_VHCA_STATE を受け付ける
    pub vhca_state_cap: bool,
    /// GENERAL_2 で sw_vhca_id_valid を有効化できる
    pub sw_vhca_id_valid_cap: bool,
    /// VHCA ポート数
    pub num_vhca_ports: u16,
    /// VHCA ID (VF identification)
    pub vhca_id: u16,
    /// 1WQEあたりの最大SGE数
    pub max_sge: u8,
    /// TSO (TCP Segmentation Offload) IPv4 対応
    pub tso_ipv4: bool,
    /// TSO (TCP Segmentation Offload) IPv6 対応
    pub tso_ipv6: bool,
    /// RSS サポート (Ethernet Offloads)
    pub rss_en: bool,
    /// LRO サポート (Ethernet Offloads)
    pub lro_en: bool,
    /// NIC Receive Flow Table サポート
    pub nic_rx_ft: bool,
    /// 受信タイムスタンプ形式 (0: none, 1: free running, 2: real time)
    pub rq_ts_format: u8,
    /// 送信タイムスタンプ形式 (0: none, 1: free running, 2: real time)
    pub sq_ts_format: u8,
    /// デバイス内部タイマー周波数 (kHz)
    pub device_frequency_khz: u32,
}

// ============================================================================
// Port State
// ============================================================================

/// NIC ポートの物理リンク状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortLinkState {
    Down,
    Up,
    Unknown,
}

/// NIC ポートの管理状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortAdminState {
    Down,
    Up,
}

// ============================================================================
// Completion Queue Entry (CQE) Format
// ============================================================================

/// CQEサイズ (64 bytes)
pub const CQE_SIZE: usize = 64;

/// CQEオペコード
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CqeOpcode {
    /// 要求完了（成功）
    ReqOk = 0x00,
    /// 応答完了（Write with Immediate）
    RespWriteImm = 0x01,
    /// 受信完了（Send）
    RespOk = 0x02,
    /// 受信完了（Send with Immediate）
    RespSendImm = 0x03,
    /// 受信完了（Send with Invalidate）
    RespSendInv = 0x04,
    /// CQ リサイズ完了
    ResizeCq = 0x05,
    /// シグネチャエラー
    SigErr = 0x0C,
    /// 要求エラー
    ReqErr = 0x0D,
    /// 受信エラー
    RespErr = 0x0E,
    /// 無効
    Invalid = 0x0F,
}

impl CqeOpcode {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0x00 => Self::ReqOk,
            0x01 => Self::RespWriteImm,
            0x02 => Self::RespOk,
            0x03 => Self::RespSendImm,
            0x04 => Self::RespSendInv,
            0x05 => Self::ResizeCq,
            0x0C => Self::SigErr,
            0x0D => Self::ReqErr,
            0x0E => Self::RespErr,
            _ => Self::Invalid,
        }
    }
}

// ============================================================================
// Work Queue Entry (WQE) Format
// ============================================================================

/// WQEサイズ単位 (16 bytes = 1 WQEBB)
pub const WQEBB_SIZE: usize = 16;

/// 送信WQE最大WQEBBs
pub const MAX_SQ_WQEBBS: usize = 4;

/// WQEオペコード（送信）
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WqeOpcode {
    /// NOP
    Nop = 0x00,
    /// Ethernet送信
    EthSend = 0x0A,
    /// Enhanced Multi-Packet WQE
    EnhancedMpwqe = 0x0D,
    /// MPWQE with Ethernet segment
    MpwqeEthSeg = 0x0E,
}

// ============================================================================
// Memory Key (MKEY) types
// ============================================================================

/// Memory Key タイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkeyType {
    /// 間接的MR
    Indirect = 0x00,
    /// 物理ブロックリスト
    Klm = 0x01,
}

// ============================================================================
// SQ/RQ State Transitions
// ============================================================================

/// SQ / RQ の状態
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WqState {
    /// リセット状態（初期状態）
    Reset = 0x00,
    /// Ready to Send/Receive
    Ready = 0x01,
    /// エラー状態
    Error = 0x03,
}

// ============================================================================
// EQ Event Bitmask
// ============================================================================

/// EQイベントビットマスク生成用
pub mod eq_event_mask {
    use super::EventType;

    /// 全CQ完了イベント
    pub const COMPLETION: u64 = 1 << (EventType::CompletionEvent as u64);
    /// ポート状態変更
    pub const PORT_STATE_CHANGE: u64 = 1 << (EventType::PortStateChange as u64);
    /// コマンド完了
    pub const COMMAND_COMPLETION: u64 = 1 << (EventType::CommandCompletion as u64);
    /// ページ要求
    pub const PAGE_REQUEST: u64 = 1 << (EventType::PageRequest as u64);
    /// VPORT変更
    pub const NIC_VPORT_CHANGE: u64 = 1 << (EventType::NicVportChange as u64);

    /// 全受信イベント（標準的な組み合わせ）
    pub const STANDARD: u64 =
        COMPLETION | PORT_STATE_CHANGE | COMMAND_COMPLETION | PAGE_REQUEST | NIC_VPORT_CHANGE;
}

// ============================================================================
// VPORT Counter Fields
// ============================================================================

/// VPORTカウンタ情報
#[derive(Debug, Clone, Default)]
pub struct VportCounters {
    /// 受信ユニキャストパケット数
    pub rx_unicast_packets: u64,
    /// 受信ユニキャストバイト数
    pub rx_unicast_bytes: u64,
    /// 受信マルチキャストパケット数
    pub rx_multicast_packets: u64,
    /// 受信マルチキャストバイト数
    pub rx_multicast_bytes: u64,
    /// 受信ブロードキャストパケット数
    pub rx_broadcast_packets: u64,
    /// 受信ブロードキャストバイト数
    pub rx_broadcast_bytes: u64,
    /// 送信ユニキャストパケット数
    pub tx_unicast_packets: u64,
    /// 送信ユニキャストバイト数
    pub tx_unicast_bytes: u64,
    /// 送信マルチキャストパケット数
    pub tx_multicast_packets: u64,
    /// 送信マルチキャストバイト数
    pub tx_multicast_bytes: u64,
    /// 送信ブロードキャストパケット数
    pub tx_broadcast_packets: u64,
    /// 送信ブロードキャストバイト数
    pub tx_broadcast_bytes: u64,
    /// 受信エラーパケット数
    pub rx_error_packets: u64,
    /// 送信エラーパケット数
    pub tx_error_packets: u64,
    /// 受信ドロップパケット数
    pub rx_dropped: u64,
    /// 送信ドロップパケット数
    pub tx_dropped: u64,
}
