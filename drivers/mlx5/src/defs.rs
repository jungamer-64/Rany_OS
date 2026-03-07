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
            CONNECTX4_VF_DEVICE_ID
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

/// コマンドメールボックスサイズ (16KB)
/// Chained blocks を考慮して 16KB に拡張（以前は 8KB）
pub const MLX5_CMD_MBOX_SIZE: usize = 16384;

/// コマンド入力最大サイズ (512 - 64 = 448 bytes per block)
pub const MLX5_CMD_DATA_BLOCK_SIZE: usize = 448;

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

    /// RQ作成
    CreateRq = 0x0908,
    /// RQ状態変更
    ModifyRq = 0x0909,
    /// RQ破棄
    DestroyRq = 0x090A,

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
    /// 特殊コンテキスト（reserved lkey 等）クエリ
    QuerySpecialContexts = 0x0203,
    /// MKEY破棄
    DestroyMkey = 0x0201,

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

/// コマンド実行ステータス
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdStatus {
    /// 成功
    Ok = 0x00,
    /// 内部エラー
    InternalError = 0x01,
    /// 不正なオペコード
    BadOpcode = 0x02,
    /// 不正な引数
    BadParam = 0x03,
    /// 不正なリソース状態
    BadResourceState = 0x04,
    /// リソース不足
    NoResources = 0x05,
    /// リソースが使用中
    ResourceBusy = 0x06,
    /// 入力長エラー
    InputLenErr = 0x07,
    /// 出力長エラー
    OutputLenErr = 0x08,
    /// 不正なリソースID
    BadResource = 0x09,
    /// 不正なサイズ
    BadInputLen = 0x0A,
    /// 不正な出力サイズ
    BadOutputLen = 0x0B,
    /// 未知のコマンド
    UnknownCommand = 0x51,
}

impl CmdStatus {
    /// Convert from raw u8 value
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x00 => Self::Ok,
            0x01 => Self::InternalError,
            0x02 => Self::BadOpcode,
            0x03 => Self::BadParam,
            0x04 => Self::BadResourceState,
            0x05 => Self::NoResources,
            0x06 => Self::ResourceBusy,
            0x07 => Self::InputLenErr,
            0x08 => Self::OutputLenErr,
            0x09 => Self::BadResource,
            0x0A => Self::BadInputLen,
            0x0B => Self::BadOutputLen,
            0x51 => Self::UnknownCommand,
            _ => Self::InternalError,
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
    /// 最大MKEY数
    pub max_mkey: u32,
    /// 最大MTU
    pub max_mtu: u32,
    /// ポート数
    pub num_ports: u8,
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
    /// VHCA ポート数
    pub num_vhca_ports: u16,
    /// VHCA ID (VF identification)
    pub vhca_id: u16,
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
    /// 受信完了
    RespOk = 0x01,
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
            0x01 => Self::RespOk,
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
