// ============================================================================
// drivers/mlx5/src/flow.rs - Flow Table / Flow Steering
// ============================================================================
//! フローテーブルとフローステアリング
//!
//! ConnectX ファミリの受信パケットをキューにステアリングするための
//! フローテーブル / フローグループ / フローテーブルエントリを管理する。
//!
//! ## 階層構造
//! ```text
//! Flow Table (FT)
//!   └─ Flow Group (FG)
//!       └─ Flow Table Entry (FTE)
//!           ├─ Match criteria (Ethertype, MAC, IP, ...)
//!           └─ Action (Forward to TIR / Drop / ...)
//! ```
//!
//! ## RSS (Receive Side Scaling)
//!
//! 複数RQへのハッシュベース分散。RQT (Receive Queue Table) を作成し、
//! TIR にハッシュ設定とともに紐づける。

use crate::cmd::CmdMailbox;

// ============================================================================
// Flow Table / Flow Group Constants
// ============================================================================

/// フローテーブルタイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowTableType {
    /// NIC RX (受信ステアリング)
    NicRx = 0x00,
    /// NIC TX (送信ステアリング)
    NicTx = 0x01,
}

/// フローテーブルエントリのアクション
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowAction {
    /// パケット許可（TIRにフォワード）
    Allow = 0x01,
    /// パケット破棄
    Drop = 0x02,
}

/// RSS ハッシュ関数タイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssHashFunction {
    /// Toeplitz ハッシュ
    Toeplitz = 0x00,
    /// XOR ハッシュ
    Xor = 0x01,
}

/// RSS ハッシュフィールド選択ビットマスク
pub mod rss_field {
    /// IPv4 ソースアドレス
    pub const SRC_IPV4: u32 = 1 << 0;
    /// IPv4 宛先アドレス
    pub const DST_IPV4: u32 = 1 << 1;
    /// IPv6 ソースアドレス
    pub const SRC_IPV6: u32 = 1 << 2;
    /// IPv6 宛先アドレス
    pub const DST_IPV6: u32 = 1 << 3;
    /// TCP ソースポート
    pub const SRC_TCP: u32 = 1 << 4;
    /// TCP 宛先ポート
    pub const DST_TCP: u32 = 1 << 5;
    /// UDP ソースポート
    pub const SRC_UDP: u32 = 1 << 6;
    /// UDP 宛先ポート
    pub const DST_UDP: u32 = 1 << 7;

    /// IPv4 + TCP の標準的なRSSフィールド
    pub const IPV4_TCP: u32 = SRC_IPV4 | DST_IPV4 | SRC_TCP | DST_TCP;
    /// IPv4 + UDP の標準的なRSSフィールド
    pub const IPV4_UDP: u32 = SRC_IPV4 | DST_IPV4 | SRC_UDP | DST_UDP;
    /// IPv4 のみ
    pub const IPV4_ONLY: u32 = SRC_IPV4 | DST_IPV4;
}

/// Toeplitz RSSハッシュキー（デフォルト値: Microsoft推奨ハッシュキー）
pub const DEFAULT_RSS_KEY: [u8; 40] = [
    0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2, 0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
    0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4, 0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
    0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA,
];

// ============================================================================
// Flow Table Definitions
// ============================================================================

/// フローテーブル設定
#[derive(Debug, Clone)]
pub struct FlowTableConfig {
    /// テーブルタイプ
    pub table_type: FlowTableType,
    /// ログ2テーブルサイズ
    pub log_size: u8,
    /// テーブルレベル（優先度）
    pub level: u8,
}

impl Default for FlowTableConfig {
    fn default() -> Self {
        Self {
            table_type: FlowTableType::NicRx,
            log_size: 4, // 16エントリ
            level: 0,
        }
    }
}

/// フローテーブル
#[derive(Debug)]
pub struct FlowTable {
    /// HWが割り当てたテーブルID
    pub table_id: u32,
    /// テーブルタイプ
    pub table_type: FlowTableType,
    /// テーブルサイズ（エントリ数）
    pub size: u32,
    /// テーブルレベル
    pub level: u8,
}

/// フローグループ
#[derive(Debug)]
pub struct FlowGroup {
    /// HWが割り当てたグループID
    pub group_id: u32,
    /// 所属するフローテーブルID
    pub table_id: u32,
    /// グループ開始インデックス
    pub start_index: u32,
    /// グループ終了インデックス
    pub end_index: u32,
    /// マッチ条件ビットマスク
    pub match_criteria: MatchCriteria,
}

/// フローテーブルエントリ
#[derive(Debug)]
pub struct FlowTableEntry {
    /// エントリインデックス
    pub index: u32,
    /// 所属するフローテーブルID
    pub table_id: u32,
    /// 所属するフローグループID
    pub group_id: u32,
    /// マッチ値
    pub match_value: MatchValue,
    /// アクション
    pub action: FlowAction,
    /// フォワード先TIR番号（Allow時）
    pub destination_tirn: Option<u32>,
}

/// マッチ条件（ヘッダフィールドの有効化ビットマスク）
#[derive(Debug, Clone, Default)]
pub struct MatchCriteria {
    /// L2 (Ethernet) ヘッダマッチを有効化
    pub outer_l2: bool,
    /// L3 (IP) ヘッダマッチを有効化
    pub outer_l3: bool,
    /// L4 (TCP/UDP) ヘッダマッチを有効化
    pub outer_l4: bool,
}

/// マッチ値（具体的なヘッダフィールド値）
#[derive(Debug, Clone)]
pub struct MatchValue {
    /// 宛先MACアドレス
    pub dst_mac: Option<[u8; 6]>,
    /// ソースMACアドレス
    pub src_mac: Option<[u8; 6]>,
    /// EtherType
    pub ethertype: Option<u16>,
    /// 宛先IPv4アドレス
    pub dst_ipv4: Option<u32>,
    /// ソースIPv4アドレス
    pub src_ipv4: Option<u32>,
}

impl Default for MatchValue {
    fn default() -> Self {
        Self {
            dst_mac: None,
            src_mac: None,
            ethertype: None,
            dst_ipv4: None,
            src_ipv4: None,
        }
    }
}

// ============================================================================
// RSS Configuration
// ============================================================================

/// RSS (Receive Side Scaling) 設定
#[derive(Debug, Clone)]
pub struct RssConfig {
    /// ハッシュ関数
    pub hash_function: RssHashFunction,
    /// ハッシュフィールド選択
    pub hash_fields: u32,
    /// ハッシュキー（40バイト）
    pub hash_key: [u8; 40],
}

impl Default for RssConfig {
    fn default() -> Self {
        Self {
            hash_function: RssHashFunction::Toeplitz,
            hash_fields: rss_field::IPV4_TCP | rss_field::IPV4_UDP,
            hash_key: DEFAULT_RSS_KEY,
        }
    }
}

/// RQT (Receive Queue Table) — 複数RQへの分散テーブル
#[derive(Debug)]
pub struct RqTable {
    /// HWが割り当てたRQT番号
    pub rqtn: u32,
    /// RQ番号のリスト
    pub rq_list: alloc::vec::Vec<u32>,
    /// ログ2テーブルサイズ
    pub log_rqt_size: u8,
}

// ============================================================================
// Command Helpers for Flow Steering
// ============================================================================

// These have been moved to crate::cmd::flow
