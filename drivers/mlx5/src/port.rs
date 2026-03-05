// ============================================================================
// drivers/mlx5/src/port.rs - NIC Port Management
// ============================================================================
//! NICポート管理
//!
//! ConnectX ファミリのイーサネットポート設定とリンク管理。
//! デュアルポート構成のNICではポートごとに独立して管理する。

use crate::defs::{PortAdminState, PortLinkState, MLX5_DEFAULT_MTU, MLX5_MAX_MTU};

/// MACアドレス（6バイト）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// すべてゼロのMACアドレス
    pub const ZERO: Self = Self([0u8; 6]);

    /// ブロードキャストMACアドレス
    pub const BROADCAST: Self = Self([0xFF; 6]);

    /// MACアドレスが有効（非ゼロ）か
    pub fn is_valid(&self) -> bool {
        self.0 != [0u8; 6]
    }

    /// ローカル管理MACアドレスか
    pub fn is_locally_administered(&self) -> bool {
        (self.0[0] & 0x02) != 0
    }

    /// フォーマット表示
    pub fn format(&self) -> alloc::string::String {
        alloc::format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl core::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// ポートのリンク速度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSpeed {
    /// 1 Gbps
    Speed1G,
    /// 10 Gbps
    Speed10G,
    /// 25 Gbps
    Speed25G,
    /// 40 Gbps
    Speed40G,
    /// 50 Gbps
    Speed50G,
    /// 100 Gbps
    Speed100G,
    /// 不明
    Unknown,
}

impl LinkSpeed {
    /// Mbps表現
    pub fn mbps(&self) -> u32 {
        match self {
            Self::Speed1G => 1_000,
            Self::Speed10G => 10_000,
            Self::Speed25G => 25_000,
            Self::Speed40G => 40_000,
            Self::Speed50G => 50_000,
            Self::Speed100G => 100_000,
            Self::Unknown => 0,
        }
    }
}

impl core::fmt::Display for LinkSpeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Speed1G => write!(f, "1 Gbps"),
            Self::Speed10G => write!(f, "10 Gbps"),
            Self::Speed25G => write!(f, "25 Gbps"),
            Self::Speed40G => write!(f, "40 Gbps"),
            Self::Speed50G => write!(f, "50 Gbps"),
            Self::Speed100G => write!(f, "100 Gbps"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// NICポートの統計情報
#[derive(Debug, Clone, Default)]
pub struct PortStats {
    /// 送信パケット数
    pub tx_packets: u64,
    /// 受信パケット数
    pub rx_packets: u64,
    /// 送信バイト数
    pub tx_bytes: u64,
    /// 受信バイト数
    pub rx_bytes: u64,
    /// 送信エラー数
    pub tx_errors: u64,
    /// 受信エラー数
    pub rx_errors: u64,
    /// 受信ドロップ数
    pub rx_dropped: u64,
    /// 送信ドロップ数
    pub tx_dropped: u64,
}

/// mlx5 NICポート
///
/// ポートごとに独立したリンク管理、MTU設定、統計情報を持つ。
pub struct Mlx5Port {
    /// ポート番号（1-based, HW仕様に準拠）
    port_number: u8,
    /// MACアドレス（VPORTコンテキストから取得）
    mac_address: MacAddr,
    /// リンク状態
    link_state: PortLinkState,
    /// 管理状態
    admin_state: PortAdminState,
    /// リンク速度
    link_speed: LinkSpeed,
    /// MTU
    mtu: u32,
    /// 統計情報
    stats: PortStats,
}

impl Mlx5Port {
    /// 新しいポートを作成
    pub fn new(port_number: u8) -> Self {
        Self {
            port_number,
            mac_address: MacAddr::ZERO,
            link_state: PortLinkState::Down,
            admin_state: PortAdminState::Down,
            link_speed: LinkSpeed::Unknown,
            mtu: MLX5_DEFAULT_MTU,
            stats: PortStats::default(),
        }
    }

    /// ポート番号を取得
    pub fn port_number(&self) -> u8 {
        self.port_number
    }

    /// MACアドレスを取得
    pub fn mac_address(&self) -> MacAddr {
        self.mac_address
    }

    /// MACアドレスを設定（VPORTコンテキストから読み取った値）
    pub fn set_mac_address(&mut self, mac: MacAddr) {
        self.mac_address = mac;
    }

    /// MACアドレスのバイト配列を取得
    pub fn mac_bytes(&self) -> [u8; 6] {
        self.mac_address.0
    }

    /// リンク状態を取得
    pub fn link_state(&self) -> PortLinkState {
        self.link_state
    }

    /// リンク状態を設定
    pub fn set_link_state(&mut self, state: PortLinkState) {
        self.link_state = state;
    }

    /// リンクがアップしているか
    pub fn is_link_up(&self) -> bool {
        self.link_state == PortLinkState::Up
    }

    /// 管理状態をアップに設定
    pub fn admin_up(&mut self) {
        self.admin_state = PortAdminState::Up;
    }

    /// 管理状態をダウンに設定
    pub fn admin_down(&mut self) {
        self.admin_state = PortAdminState::Down;
    }

    /// MTUを取得
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// MTUを設定
    pub fn set_mtu(&mut self, mtu: u32) -> Result<(), &'static str> {
        if mtu > MLX5_MAX_MTU {
            return Err("MTU exceeds maximum");
        }
        if mtu < 68 {
            return Err("MTU below minimum");
        }
        self.mtu = mtu;
        Ok(())
    }

    /// リンク速度を取得
    pub fn link_speed(&self) -> LinkSpeed {
        self.link_speed
    }

    /// リンク速度を設定
    pub fn set_link_speed(&mut self, speed: LinkSpeed) {
        self.link_speed = speed;
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &PortStats {
        &self.stats
    }

    /// 統計情報の可変参照を取得
    pub fn stats_mut(&mut self) -> &mut PortStats {
        &mut self.stats
    }

    /// 送信パケットカウントを増加
    pub fn inc_tx(&mut self, bytes: u64) {
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += bytes;
    }

    /// 受信パケットカウントを増加
    pub fn inc_rx(&mut self, bytes: u64) {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += bytes;
    }

    /// 送信エラーカウントを増加
    pub fn inc_tx_error(&mut self) {
        self.stats.tx_errors += 1;
    }

    /// 受信エラーカウントを増加
    pub fn inc_rx_error(&mut self) {
        self.stats.rx_errors += 1;
    }
}
