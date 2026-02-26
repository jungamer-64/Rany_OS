// ============================================================================
// kernel/src/net/dhcp.rs
// ============================================================================
//! DHCP (Dynamic Host Configuration Protocol) クライアント実装
//!
//! DHCPを使用してIPアドレス、サブネットマスク、ゲートウェイ、
//! DNSサーバーなどのネットワーク設定を自動取得する。


use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::ethernet::MacAddress;
use super::ipv4::Ipv4Address;

/// DHCPクライアントポート
mod client_impl;
pub use client_impl::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use client_impl::tests as qemu_v4_tests;

mod v6;
pub use v6::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use v6::tests as qemu_v6_tests;
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCPサーバーポート
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCPメッセージの最大サイズ
pub const DHCP_MAX_MESSAGE_SIZE: usize = 576;

/// DHCPマジッククッキー
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// DHCPオペレーションタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOperation {
    /// クライアント要求
    Request = 1,
    /// サーバー応答
    Reply = 2,
}

/// DHCPメッセージタイプ (オプション53)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    /// DHCPDISCOVER
    Discover = 1,
    /// DHCPOFFER
    Offer = 2,
    /// DHCPREQUEST
    Request = 3,
    /// DHCPDECLINE
    Decline = 4,
    /// DHCPACK
    Ack = 5,
    /// DHCPNAK
    Nak = 6,
    /// DHCPRELEASE
    Release = 7,
    /// DHCPINFORM
    Inform = 8,
}

impl DhcpMessageType {
    /// u8から変換
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }
}

/// DHCPオプションコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOption {
    /// パディング
    Pad = 0,
    /// サブネットマスク
    SubnetMask = 1,
    /// ルーター (デフォルトゲートウェイ)
    Router = 3,
    /// DNSサーバー
    DnsServer = 6,
    /// ホスト名
    Hostname = 12,
    /// ドメイン名
    DomainName = 15,
    /// 要求されたIPアドレス
    RequestedIp = 50,
    /// リース時間
    LeaseTime = 51,
    /// Renewal (T1)
    RenewalTime = 58,
    /// Rebinding (T2)
    RebindingTime = 59,
    /// メッセージタイプ
    MessageType = 53,
    /// サーバー識別子
    ServerIdentifier = 54,
    /// パラメータ要求リスト
    ParameterRequestList = 55,
    /// クライアント識別子
    ClientIdentifier = 61,
    /// 終端
    End = 255,
} 

/// DHCPヘッダ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DhcpHeader {
    /// オペレーション (1 = Request, 2 = Reply)
    pub op: u8,
    /// ハードウェアタイプ (1 = Ethernet)
    pub htype: u8,
    /// ハードウェアアドレス長 (6 for Ethernet)
    pub hlen: u8,
    /// ホップ数
    pub hops: u8,
    /// トランザクションID
    pub xid: [u8; 4],
    /// 経過秒数
    pub secs: [u8; 2],
    /// フラグ
    pub flags: [u8; 2],
    /// クライアントIPアドレス
    pub ciaddr: [u8; 4],
    /// 提供されたIPアドレス
    pub yiaddr: [u8; 4],
    /// サーバーIPアドレス
    pub siaddr: [u8; 4],
    /// リレーエージェントIPアドレス
    pub giaddr: [u8; 4],
    /// クライアントハードウェアアドレス (16バイト)
    pub chaddr: [u8; 16],
    /// サーバー名 (64バイト)
    pub sname: [u8; 64],
    /// ブートファイル名 (128バイト)
    pub file: [u8; 128],
}

impl DhcpHeader {
    /// ヘッダサイズ
    pub const SIZE: usize = 236;

    /// トランザクションIDを取得
    pub fn xid(&self) -> u32 {
        u32::from_be_bytes(self.xid)
    }

    /// 経過秒数を取得
    pub fn secs(&self) -> u16 {
        u16::from_be_bytes(self.secs)
    }

    /// フラグを取得
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes(self.flags)
    }

    /// クライアントIPを取得
    pub fn ciaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.ciaddr)
    }

    /// 提供されたIPを取得
    pub fn yiaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.yiaddr)
    }

    /// サーバーIPを取得
    pub fn siaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.siaddr)
    }
}

/// 取得したDHCP設定
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// 割り当てられたIPアドレス
    pub ip_address: Ipv4Address,
    /// サブネットマスク
    pub subnet_mask: Ipv4Address,
    /// デフォルトゲートウェイ
    pub gateway: Option<Ipv4Address>,
    /// DNSサーバー (最大3つ)
    pub dns_servers: Vec<Ipv4Address>,
    /// DHCPサーバーのIPアドレス
    pub server_ip: Ipv4Address,
    /// リース時間 (秒)
    pub lease_time: u32,
    /// Renewal time (T1)
    pub t1: u32,
    /// Rebinding time (T2)
    pub t2: u32,
    /// 取得時刻 (tick)
    pub obtained_at: u64,
    /// ホスト名
    pub hostname: Option<Vec<u8>>,
    /// ドメイン名
    pub domain_name: Option<Vec<u8>>,
} 

impl DhcpLease {
    /// リースが期限切れか判定
    pub fn is_expired(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs > self.lease_time as u64
    }

    /// 更新が必要か判定 (T1到達)
    pub fn needs_renewal(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs >= self.t1 as u64
    }

    /// 再バインドが必要か判定 (T2到達)
    pub fn needs_rebind(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs >= self.t2 as u64
    }
} 

/// DHCPクライアントの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// 初期状態
    Init,
    /// DISCOVER送信済み、OFFER待ち
    Selecting,
    /// REQUEST送信済み、ACK待ち
    Requesting,
    /// リース取得済み
    Bound,
    /// 更新中
    Renewing,
    /// 再バインド中
    Rebinding,
}

/// DHCPクライアント
pub struct DhcpClient {
    /// MACアドレス
    mac_address: MacAddress,
    /// 現在の状態
    state: PoisonLock<DhcpState>,
    /// 現在のトランザクションID
    xid: AtomicU32,
    /// 現在のリース
    lease: PoisonLock<Option<DhcpLease>>,
    /// 提案されたリース (OFFER受信後)
    offered_lease: PoisonLock<Option<DhcpLease>>,
    /// offered lease の ARP probe 送信時刻 (tick)
    offered_probe_at: AtomicU64,
    /// Last declined IP (u32 network-order, 0 when none)
    last_declined: AtomicU32,
    /// Last released IP (u32 network-order, 0 when none)
    last_released: AtomicU32,
    /// 状態遷移時刻
    state_time: AtomicU64,
    /// 再試行回数
    retry_count: AtomicU32,
}

/// DHCP応答から解析されたオプション群
struct ParsedOptions {
    message_type: Option<DhcpMessageType>,
    subnet_mask: Option<Ipv4Address>,
    router: Option<Ipv4Address>,
    dns_servers: Vec<Ipv4Address>,
    lease_time: u32,
    renewal_time: Option<u32>,
    rebinding_time: Option<u32>,
    server_id: Option<Ipv4Address>,
    hostname: Option<Vec<u8>>,
    domain_name: Option<Vec<u8>>,
}
