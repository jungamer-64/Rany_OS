// ============================================================================
// drivers/mlx5/src/resources.rs - HCA Resource Management
// ============================================================================
//! HCA リソース管理 — MKEY, TIS, TIR の作成・破棄
//!
//! ## MKEY (Memory Key)
//! DMAアクセス制御用のメモリ登録キー。ConnectX ファミリでは
//! Direct Memory Key を使用してDMAバッファを保護する。
//!
//! ## TIS (Transport Interface Send)
//! 送信パスのインタフェース。SQに紐づけてトランスポート設定を適用する。
//!
//! ## TIR (Transport Interface Receive)
//! 受信パスのインタフェース。RQまたはRQTに紐づけてRSSなどを設定する。

use crate::cmd::CmdMailbox;
use crate::flow::RssConfig;

// ============================================================================
// Memory Key (MKEY) — DMA Memory Registration
// ============================================================================

/// MKEYの種別
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkeyAccessFlags {
    /// ローカル読み取り
    LocalRead = 0x01,
    /// ローカル書き込み
    LocalWrite = 0x02,
    /// リモート読み取り
    RemoteRead = 0x04,
    /// リモート書き込み
    RemoteWrite = 0x08,
}

/// MKEY作成パラメータ
#[derive(Debug, Clone)]
pub struct MkeyParams {
    /// メモリ領域開始アドレス
    pub start_addr: u64,
    /// メモリ領域サイズ
    pub length: u64,
    /// アクセスフラグ（ビットOR）
    pub access_flags: u8,
    /// Protection Domain 番号
    pub pd: u32,
    /// ログ2ページサイズ（12 = 4KB, 21 = 2MB, etc）
    pub log_page_size: u8,
}

impl Default for MkeyParams {
    fn default() -> Self {
        Self {
            start_addr: 0,
            length: 0xFFFF_FFFF_FFFF_FFFF, // 全アドレス空間
            access_flags: MkeyAccessFlags::LocalRead as u8 | MkeyAccessFlags::LocalWrite as u8,
            pd: 0,
            log_page_size: 12, // 4KB
        }
    }
}

/// MKEY情報（作成後の管理用）
#[derive(Debug, Clone)]
pub struct MkeyInfo {
    /// HWが割り当てたMKEY番号
    pub mkey_index: u32,
    /// 完全なMKEY値（index << 8 | key）
    pub mkey: u32,
    /// パラメータ
    pub params: MkeyParams,
}

// ============================================================================
// TIS (Transport Interface Send)
// ============================================================================

/// TIS作成パラメータ
#[derive(Debug, Clone)]
pub struct TisParams {
    /// Protection Domain 番号
    pub pd: u32,
    /// Transport Domain 番号
    pub td: u32,
    /// ポート番号 (1-based)
    pub port: u8,
    /// 優先度 (0-7)
    pub prio: u8,
}

impl Default for TisParams {
    fn default() -> Self {
        Self {
            pd: 0,
            td: 0,
            port: 1,
            prio: 0,
        }
    }
}

/// TIS情報（作成後の管理用）
#[derive(Debug, Clone)]
pub struct TisInfo {
    /// HWが割り当てたTIS番号
    pub tisn: u32,
    /// ポート番号
    pub port: u8,
}

// ============================================================================
// TIR (Transport Interface Receive)
// ============================================================================

/// TIR 受信先の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TirReceiveType {
    /// 単一RQに直接配送
    DirectRq,
    /// RQT (Receive Queue Table) 経由のRSS分散
    Rqt,
}

/// TIR作成パラメータ
#[derive(Debug, Clone)]
pub struct TirParams {
    /// 受信タイプ
    pub receive_type: TirReceiveType,
    /// Transport Domain 番号
    pub td: u32,
    /// 直接RQの場合のRQ番号
    pub inline_rqn: u32,
    /// RQTの場合のRQT番号
    pub rqtn: u32,
    /// RSS設定（RQT使用時）
    pub rss: Option<RssConfig>,
    /// Scatter FCS を有効化するか
    pub scatter_fcs: bool,
    /// VLAN strippingを有効化するか
    pub vlan_strip: bool,
}

impl Default for TirParams {
    fn default() -> Self {
        Self {
            receive_type: TirReceiveType::DirectRq,
            td: 0,
            inline_rqn: 0,
            rqtn: 0,
            rss: None,
            scatter_fcs: false,
            vlan_strip: false,
        }
    }
}

/// TIR情報（作成後の管理用）
#[derive(Debug, Clone)]
pub struct TirInfo {
    /// HWが割り当てたTIR番号
    pub tirn: u32,
    /// 受信タイプ
    pub receive_type: TirReceiveType,
}

// ============================================================================
// Command Builders
// ============================================================================

/// CREATE_MKEY コマンド入力の構築
pub fn build_create_mkey_input(in_mbox: &mut CmdMailbox, params: &MkeyParams) {
    *in_mbox = CmdMailbox::zeroed();
    // MKEY Context at offset 0x10
    let ctx = 0x10;
    // access_flags at offset +0x00 bits [7:0]
    in_mbox.write_be32(ctx, params.access_flags as u32);
    // PD at offset +0x04
    in_mbox.write_be32(ctx + 0x04, params.pd & 0x00FF_FFFF);
    // start_addr at offset +0x08
    in_mbox.write_be64(ctx + 0x08, params.start_addr);
    // length at offset +0x10
    in_mbox.write_be64(ctx + 0x10, params.length);
    // log_page_size at offset +0x18 bits [4:0]
    in_mbox.write_be32(ctx + 0x18, params.log_page_size as u32);
    // MKey type: PA-based (0x00) with "free" bit set for Direct MKey
    in_mbox.write_be32(ctx + 0x1C, 0x01 << 24); // free=1
}

/// CREATE_MKEY 出力からMKEY値を解析
pub fn parse_create_mkey_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_mkey_out_bits: mkey_index[23:0] at byte offset 0x09.
    let mkey_index = out_mbox.read_be24(0x09);
    // Full mkey = (index << 8) — key portion is from HW
    mkey_index
}

/// CREATE_TIS コマンド入力の構築
pub fn build_create_tis_input(in_mbox: &mut CmdMailbox, params: &TisParams) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_create_tis_in_bits:
    // - header/reserved up to 0x20
    // - tisc context starts at 0x20
    let ctx = 0x20usize;

    // tisc first dword:
    // - lag_tx_port_affinity[3:0] at bits 27:24
    // - prio[3:0] at bits 19:16
    // Keep strict_lag_tx_port_affinity/tls_en cleared for regular Ethernet VF path.
    let lag_affinity = (params.port as u32) & 0x0F;
    let tisc0 = (lag_affinity << 24) | (((params.prio as u32) & 0x0F) << 16);
    in_mbox.write_be32(ctx, tisc0);
    // tisc.transport_domain[23:0] in dword @ ctx+0x24
    in_mbox.write_be32(ctx + 0x24, params.td & 0x00FF_FFFF);
    // For regular Ethernet TIS, leave tisc.pd cleared.
    // Linux only programs this field for TLS-enabled TIS objects.
    let _ = params.pd;
}

/// CREATE_TIS 出力からTIS番号を解析
pub fn parse_create_tis_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_tis_out_bits: tisn[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// QUERY_TIS コマンド入力の構築
pub fn build_query_tis_input(in_mbox: &mut CmdMailbox, tisn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_query_tis_in_bits: tisn[23:0] at dword offset 0x04.
    in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);
}

/// QUERY_TIS 出力から TIS context の主要フィールドを解析
///
/// Returns: (prio, transport_domain, underlay_qpn, pd)
pub fn parse_query_tis_output(out_mbox: &CmdMailbox) -> (u8, u32, u32, u32) {
    // mlx5_ifc_query_tis_out_bits has tisc at byte offset 0x10.
    let ctx = 0x10usize;
    let prio = ((out_mbox.read_be32(ctx) >> 16) & 0x0F) as u8;
    let td = out_mbox.read_be32(ctx + 0x24) & 0x00FF_FFFF;
    let underlay_qpn = out_mbox.read_be32(ctx + 0x28) & 0x00FF_FFFF;
    let pd = out_mbox.read_be32(ctx + 0x2C) & 0x00FF_FFFF;
    (prio, td, underlay_qpn, pd)
}

/// CREATE_TIR コマンド入力の構築
pub fn build_create_tir_input(in_mbox: &mut CmdMailbox, params: &TirParams) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_create_tir_in_bits:
    // - header/reserved up to 0x20
    // - tirc context starts at 0x20
    let ctx = 0x20usize;

    // tirc.disp_type[3:0] in dword @ ctx+0x04 (bits 31:28)
    let disp_type: u32 = match params.receive_type {
        TirReceiveType::DirectRq => 0x0,
        TirReceiveType::Rqt => 0x1,
    };
    in_mbox.write_be32(ctx + 0x04, (disp_type & 0x0F) << 28);

    match params.receive_type {
        TirReceiveType::DirectRq => {
            // tirc.inline_rqn[23:0] at dword @ ctx+0x1C
            in_mbox.write_be32(ctx + 0x1C, params.inline_rqn & 0x00FF_FFFF);
        }
        TirReceiveType::Rqt => {
            // tirc.indirect_table[23:0] at dword @ ctx+0x20
            in_mbox.write_be32(ctx + 0x20, params.rqtn & 0x00FF_FFFF);
            if let Some(ref rss) = params.rss {
                // MLX5 RX hash fn encoding: NONE=0, XOR=1, TOEPLITZ=2.
                let rx_hash_fn = match rss.hash_function {
                    crate::flow::RssHashFunction::Toeplitz => 0x2u32,
                    crate::flow::RssHashFunction::Xor => 0x1u32,
                };
                let td_hash = ((rx_hash_fn & 0x0F) << 28) | (params.td & 0x00FF_FFFF);
                in_mbox.write_be32(ctx + 0x24, td_hash);

                // tirc.rx_hash_toeplitz_key[10] starts at ctx+0x28 (40 bytes).
                let key_off = ctx + 0x28;
                let copy_len = rss.hash_key.len().min(40);
                in_mbox.data[key_off..key_off + copy_len]
                    .copy_from_slice(&rss.hash_key[..copy_len]);
            }
        }
    }

    // tirc.transport_domain[23:0] at dword @ ctx+0x24.
    // If RQT+RSS path set this dword above, keep only TD low24 here.
    let dword_124 = in_mbox.read_be32(ctx + 0x24) & 0xFF00_0000;
    in_mbox.write_be32(ctx + 0x24, dword_124 | (params.td & 0x00FF_FFFF));

    // NOTE: scatter_fcs / vlan_strip are RQ context settings, not TIR context bits.
    let _ = (params.scatter_fcs, params.vlan_strip);
}

/// CREATE_TIR 出力からTIR番号を解析
pub fn parse_create_tir_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_tir_out_bits: tirn[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// DESTROY_MKEY コマンド入力の構築
pub fn build_destroy_mkey_input(in_mbox: &mut CmdMailbox, mkey_index: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, mkey_index & 0x00FF_FFFF);
}

/// DESTROY_TIS コマンド入力の構築
pub fn build_destroy_tis_input(in_mbox: &mut CmdMailbox, tisn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);
}

/// DESTROY_TIR コマンド入力の構築
pub fn build_destroy_tir_input(in_mbox: &mut CmdMailbox, tirn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, tirn & 0x00FF_FFFF);
}
