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

/// CREATE_FLOW_TABLE コマンドオペコード
pub const CMD_CREATE_FLOW_TABLE: u16 = 0x0930;
/// DESTROY_FLOW_TABLE コマンドオペコード
pub const CMD_DESTROY_FLOW_TABLE: u16 = 0x0931;
/// CREATE_FLOW_GROUP コマンドオペコード
pub const CMD_CREATE_FLOW_GROUP: u16 = 0x0933;
/// DESTROY_FLOW_GROUP コマンドオペコード
pub const CMD_DESTROY_FLOW_GROUP: u16 = 0x0934;
/// SET_FLOW_TABLE_ENTRY コマンドオペコード
pub const CMD_SET_FLOW_TABLE_ENTRY: u16 = 0x0936;
/// DELETE_FLOW_TABLE_ENTRY コマンドオペコード
pub const CMD_DELETE_FLOW_TABLE_ENTRY: u16 = 0x0938;
/// CREATE_RQT コマンドオペコード
pub const CMD_CREATE_RQT: u16 = 0x0916;
/// DESTROY_RQT コマンドオペコード
pub const CMD_DESTROY_RQT: u16 = 0x0917;

/// CREATE_FLOW_TABLE コマンド入力の構築
pub fn build_create_flow_table_input(in_mbox: &mut CmdMailbox, config: &FlowTableConfig) {
    *in_mbox = CmdMailbox::zeroed();
    // Flow Table Context at offset 0x10
    let ctx_base = 0x10;
    // table_type at bits [31:24]
    in_mbox.write_be32(ctx_base, (config.table_type as u32) << 24);
    // log_size at bits [4:0] of word at offset +0x04
    in_mbox.write_be32(ctx_base + 0x04, config.log_size as u32);
    // level at word offset +0x08
    in_mbox.write_be32(ctx_base + 0x08, config.level as u32);
}

/// CREATE_FLOW_TABLE 出力からテーブルIDを解析
pub fn parse_create_flow_table_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_flow_table_out_bits: table_id[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// CREATE_FLOW_GROUP コマンド入力の構築
pub fn build_create_flow_group_input(
    in_mbox: &mut CmdMailbox,
    table_id: u32,
    start_index: u32,
    end_index: u32,
    criteria: &MatchCriteria,
) {
    *in_mbox = CmdMailbox::zeroed();
    // table_id at offset 0x04
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    // Flow Group Context at offset 0x10
    let ctx_base = 0x10;
    // start_flow_index
    in_mbox.write_be32(ctx_base, start_index);
    // end_flow_index
    in_mbox.write_be32(ctx_base + 0x04, end_index);
    // match_criteria_enable bit mask
    let mut criteria_enable: u8 = 0;
    if criteria.outer_l2 {
        criteria_enable |= 0x01;
    }
    if criteria.outer_l3 {
        criteria_enable |= 0x02;
    }
    if criteria.outer_l4 {
        criteria_enable |= 0x04;
    }
    in_mbox.write_be32(ctx_base + 0x08, criteria_enable as u32);
}

/// CREATE_FLOW_GROUP 出力からグループIDを解析
pub fn parse_create_flow_group_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_flow_group_out_bits: group_id[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// SET_FLOW_TABLE_ENTRY コマンド入力の構築
pub fn build_set_flow_table_entry_input(
    in_mbox: &mut CmdMailbox,
    table_id: u32,
    flow_index: u32,
    group_id: u32,
    action: FlowAction,
    destination_tirn: Option<u32>,
    match_value: &MatchValue,
) {
    *in_mbox = CmdMailbox::zeroed();
    // table_id at offset 0x04
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    // flow_index at offset 0x08
    in_mbox.write_be32(0x08, flow_index);
    // Flow Table Entry Context at offset 0x10
    let ctx_base = 0x10;
    // group_id
    in_mbox.write_be32(ctx_base, group_id & 0x00FF_FFFF);
    // action
    in_mbox.write_be32(ctx_base + 0x04, action as u32);
    // destination (TIR)
    if let Some(tirn) = destination_tirn {
        // destination_type = TIR (0x02), destination_id = tirn
        let dest = (0x02u32 << 24) | (tirn & 0x00FF_FFFF);
        in_mbox.write_be32(ctx_base + 0x08, dest);
        // num_destinations = 1
        in_mbox.write_be32(ctx_base + 0x0C, 1);
    }

    // Match value at offset 0x40+
    let match_base = 0x40;
    // 宛先MACアドレス
    if let Some(mac) = match_value.dst_mac {
        in_mbox.data[match_base..match_base + 6].copy_from_slice(&mac);
    }
    // ソースMACアドレス
    if let Some(mac) = match_value.src_mac {
        in_mbox.data[match_base + 6..match_base + 12].copy_from_slice(&mac);
    }
    // EtherType
    if let Some(etype) = match_value.ethertype {
        in_mbox.write_be16(match_base + 12, etype);
    }
}

/// CREATE_RQT コマンド入力の構築
///
/// # Arguments
/// - `rq_numbers`: RQ番号のリスト
/// - `log_rqt_size`: ログ2テーブルサイズ
pub fn build_create_rqt_input(in_mbox: &mut CmdMailbox, rq_numbers: &[u32], log_rqt_size: u8) {
    *in_mbox = CmdMailbox::zeroed();
    // RQT Context at offset 0x10
    let ctx_base = 0x10;
    // ログサイズ
    in_mbox.write_be32(ctx_base, log_rqt_size as u32);
    // actual_size
    in_mbox.write_be32(ctx_base + 0x04, rq_numbers.len() as u32);
    // RQ numbers start at offset 0x20 (each 4 bytes)
    for (i, &rqn) in rq_numbers.iter().enumerate() {
        let off = 0x20 + i * 4;
        if off + 4 <= crate::defs::MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be32(off, rqn);
        }
    }
}

/// CREATE_RQT 出力からRQT番号を解析
pub fn parse_create_rqt_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_rqt_out_bits: rqtn[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}
