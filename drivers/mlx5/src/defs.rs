// ============================================================================
// drivers/mlx5/src/defs.rs - Constants and common definitions
// ============================================================================
//! ConnectX-4 Lx (mlx5) ハードウェア定数・共通定義

// ============================================================================
// PCI Identification
// ============================================================================

/// Mellanox (NVIDIA Networking) PCI Vendor ID
pub const MELLANOX_VENDOR_ID: u16 = 0x15B3;

/// ConnectX-4 Lx EN PCI Device ID (Physical Function)
pub const CONNECTX4_LX_DEVICE_ID: u16 = 0x1015;

/// ConnectX-4 Lx EN PCI Device ID (Virtual Function)
pub const CONNECTX4_LX_VF_DEVICE_ID: u16 = 0x1016;

/// ConnectX-4 EN PCI Device ID (非-Lx版)
pub const CONNECTX4_DEVICE_ID: u16 = 0x1013;

/// ConnectX-4 EN VF PCI Device ID
pub const CONNECTX4_VF_DEVICE_ID: u16 = 0x1014;

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
pub const MLX5_EQ_DEPTH: u32 = 256;

/// CQエントリ数（2のべき乗）
pub const MLX5_CQ_DEPTH: u32 = 256;

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

/// コマンドメールボックスサイズ (512 bytes)
pub const MLX5_CMD_MBOX_SIZE: usize = 512;

/// コマンド入力最大サイズ
pub const MLX5_CMD_DATA_BLOCK_SIZE: usize = 512;

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
    QueryHcaCap               = 0x0100,
    /// HCA初期化
    InitHca                   = 0x0102,
    /// HCA停止
    TeardownHca               = 0x0103,
    /// HCA有効化
    EnableHca                 = 0x0104,
    /// HCA無効化
    DisableHca                = 0x0105,

    /// ページ要求クエリ
    QueryPages                = 0x0107,
    /// ページ管理
    ManagePages               = 0x0108,

    /// ISSI（Interface Stepping-Stone Identifier）クエリ
    QueryIssi                 = 0x010A,
    /// ISSI設定
    SetIssi                   = 0x010B,

    /// EQ作成
    CreateEq                  = 0x0301,
    /// EQ破棄
    DestroyEq                 = 0x0302,

    /// CQ作成
    CreateCq                  = 0x0400,
    /// CQ破棄
    DestroyCq                 = 0x0401,

    /// SQ作成
    CreateSq                  = 0x0904,
    /// SQ破棄
    DestroySq                 = 0x0905,
    /// SQ状態変更
    ModifySq                  = 0x0906,

    /// RQ作成
    CreateRq                  = 0x0908,
    /// RQ破棄
    DestroyRq                 = 0x0909,
    /// RQ状態変更
    ModifyRq                  = 0x090A,

    /// TIR (Transport Interface Receive) 作成
    CreateTir                 = 0x0900,
    /// TIR破棄
    DestroyTir                = 0x0901,

    /// TIS (Transport Interface Send) 作成
    CreateTis                 = 0x0912,
    /// TIS破棄
    DestroyTis                = 0x0913,

    /// MACアドレスクエリ
    QueryNicVportContext      = 0x0754,
    /// VPORT状態変更
    ModifyNicVportContext     = 0x0755,

    /// ポート状態クエリ
    QueryVportState           = 0x0750,

    /// MKEYアロケーション
    CreateMkey                = 0x0200,
    /// MKEY破棄
    DestroyMkey               = 0x0201,

    /// アクセスレジスタ
    AccessRegister            = 0x0805,

    /// NOP (テスト用)
    Nop                       = 0x80FD,
}

// ============================================================================
// Command Status Codes
// ============================================================================

/// コマンド実行ステータス
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdStatus {
    /// 成功
    Ok                   = 0x00,
    /// 内部エラー
    InternalError        = 0x01,
    /// 不正なオペコード
    BadOpcode            = 0x02,
    /// 不正な引数
    BadParam             = 0x03,
    /// 不正なリソース状態
    BadResourceState     = 0x04,
    /// リソース不足
    NoResources          = 0x05,
    /// リソースが使用中
    ResourceBusy         = 0x06,
    /// 入力長エラー
    InputLenErr          = 0x07,
    /// 出力長エラー
    OutputLenErr         = 0x08,
    /// 不正なリソースID
    BadResource          = 0x09,
    /// 不正なサイズ
    BadInputLen          = 0x0A,
    /// 不正な出力サイズ
    BadOutputLen         = 0x0B,
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
    CompletionEvent      = 0x00,
    /// ポート状態変更
    PortStateChange      = 0x09,
    /// コマンド完了
    CommandCompletion    = 0x0A,
    /// ページ要求
    PageRequest          = 0x0B,
    /// NICアラート
    NicVportChange       = 0x0D,
    /// ポートモジュールイベント
    PortModule           = 0x0F,
    /// 温度アラート
    TempWarning          = 0x17,
    /// 一般イベント
    GeneralEvent         = 0x22,
}

impl EventType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::CompletionEvent),
            0x09 => Some(Self::PortStateChange),
            0x0A => Some(Self::CommandCompletion),
            0x0B => Some(Self::PageRequest),
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
    ReqOk         = 0x00,
    /// 受信完了
    RespOk        = 0x01,
    /// 要求エラー
    ReqErr        = 0x0D,
    /// 受信エラー
    RespErr       = 0x0E,
    /// 無効
    Invalid       = 0x0F,
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
    Nop           = 0x00,
    /// Ethernet送信
    EthSend       = 0x0A,
}

// ============================================================================
// Memory Key (MKEY) types
// ============================================================================

/// Memory Key タイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkeyType {
    /// 間接的MR
    Indirect    = 0x00,
    /// 物理ブロックリスト
    Klm         = 0x01,
}
