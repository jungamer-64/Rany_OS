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
use crate::structs::cmd::{MkeyContextLayout, TisContextLayout, TirContextLayout};

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
            log_page_size: 0, // Direct MKey usually uses 0
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

// These have been moved to crate::cmd::res
