// ============================================================================
// kernel/src/net/dhcp.rs
// ============================================================================
//! DHCP (Dynamic Host Configuration Protocol) クライアント実装
//!
//! DHCPを使用してIPアドレス、サブネットマスク、ゲートウェイ、
//! DNSサーバーなどのネットワーク設定を自動取得する。

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::ethernet::MacAddress;
use super::ipv4::Ipv4Address;

/// DHCPクライアントポート
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

impl DhcpClient {
    /// 最大再試行回数
    pub const MAX_RETRIES: u32 = 4;

    /// ARP probe waiting time (seconds)
    const PROBE_WAIT_SECS: u64 = 1;

    /// Default retry interval used for retransmits (seconds)
    const RETRY_INTERVAL_SECS: u64 = 4; 

    /// 新しいDHCPクライアントを作成
    pub fn new(mac_address: MacAddress) -> Self {
        Self {
            mac_address,
            state: PoisonLock::new(DhcpState::Init),
            xid: AtomicU32::new(0),
            lease: PoisonLock::new(None),
            offered_lease: PoisonLock::new(None),
            offered_probe_at: AtomicU64::new(0),
            last_declined: AtomicU32::new(0),
            last_released: AtomicU32::new(0),
            state_time: AtomicU64::new(0),
            retry_count: AtomicU32::new(0),
        }
    }

    /// 現在の状態を取得
    pub fn state(&self) -> DhcpState { 
        match self.state.lock() {
            Ok(g) => *g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (state) - returning Init");
                DhcpState::Init
            }
        }
    }

    /// 現在のリースを取得
    pub fn lease(&self) -> Option<DhcpLease> {
        match self.lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => {
                log::error!("[NET] DHCP Lease lock poisoned (lease) - returning None");
                None
            }
        }
    }

    /// Return last declined IP recorded (if any)
    pub fn last_declined_ip(&self) -> Option<Ipv4Address> {
        let v = self.last_declined.load(Ordering::SeqCst);
        if v == 0 {
            None
        } else {
            Some(Ipv4Address::from_u32(v))
        }
    }

    /// Return last released IP recorded (if any)
    pub fn last_released_ip(&self) -> Option<Ipv4Address> {
        let v = self.last_released.load(Ordering::SeqCst);
        if v == 0 {
            None
        } else {
            Some(Ipv4Address::from_u32(v))
        }
    }

    /// DHCPDISCOVER メッセージを構築
    pub fn build_discover(
        &self,
        buffer: &mut [u8],
        current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
        }

        // Acquire state and only generate a new XID when starting a new discovery
        let mut state_guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (build_discover) - aborting");
                return Err("State lock poisoned");
            }
        };

        if *state_guard == DhcpState::Init {
            let xid = (current_tick as u32) ^ 0xDEADBEEF;
            self.xid.store(xid, Ordering::SeqCst);
        }
        let xid = self.xid.load(Ordering::SeqCst);

        // ヘッダを構築
        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
        buffer[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
        // ciaddr, yiaddr, siaddr, giaddr = 0
        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        // オプション開始
        let mut offset = DhcpHeader::SIZE;

        // マジッククッキー
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // メッセージタイプ: DISCOVER
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Discover as u8;
        offset += 3;

        // パラメータ要求リスト (SubnetMask, Router, DNS, DomainName, LeaseTime, ServerIdentifier, Renewal (T1), Rebinding (T2))
        buffer[offset] = DhcpOption::ParameterRequestList as u8;
        buffer[offset + 1] = 8;
        buffer[offset + 2] = DhcpOption::SubnetMask as u8;
        buffer[offset + 3] = DhcpOption::Router as u8;
        buffer[offset + 4] = DhcpOption::DnsServer as u8;
        buffer[offset + 5] = DhcpOption::DomainName as u8;
        buffer[offset + 6] = DhcpOption::LeaseTime as u8;
        buffer[offset + 7] = DhcpOption::ServerIdentifier as u8;
        buffer[offset + 8] = DhcpOption::RenewalTime as u8;
        buffer[offset + 9] = DhcpOption::RebindingTime as u8;
        offset += 10;

        // クライアント識別子
        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        // ホスト名 (Option 12)
        {
            let hostname = b"ranyos";
            buffer[offset] = DhcpOption::Hostname as u8;
            buffer[offset + 1] = hostname.len() as u8;
            buffer[offset + 2..offset + 2 + hostname.len()].copy_from_slice(hostname);
            offset += 2 + hostname.len();
        }

        // 終端
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        // 状態を更新 (we already hold the lock)
        *state_guard = DhcpState::Selecting;
        drop(state_guard);

        self.state_time.store(current_tick, Ordering::SeqCst);

        Ok(offset)
    }

    /// DHCPREQUEST メッセージを構築
    pub fn build_request(
        &self,
        buffer: &mut [u8],
        current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
        }

        // Decide behavior based on current state (Selecting=Requesting path, Renewing/Rebinding=renewal path)
        let current_state = match self.state.lock() {
            Ok(g) => *g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (build_request) - cannot determine state");
                return Err("State lock poisoned");
            }
        };

        let (lease, is_renewal) = match current_state {
            DhcpState::Requesting => {
                // Use the offered lease when requesting after an OFFER
                let offered = match self.offered_lease.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        log::error!("[NET] DHCP Offer lock poisoned (build_request) - cannot use offer");
                        return Err("Offer lock poisoned");
                    }
                };
                (offered.clone().ok_or("No offer available")?, false)
            }
            DhcpState::Renewing | DhcpState::Rebinding => {
                // Use the currently bound lease for renewal/rebind
                let l = match self.lease.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        log::error!("[NET] DHCP Lease lock poisoned (build_request) - cannot use lease");
                        return Err("Lease lock poisoned");
                    }
                };
                (l.clone().ok_or("No active lease")?, true)
            }
            _ => return Err("Invalid state for building request"),
        };

        let xid = self.xid.load(Ordering::SeqCst);

        // ヘッダを構築
        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs

        // Flags: unicast for renewing, broadcast for rebinding and normal REQUEST
        let flags: u16 = match current_state {
            DhcpState::Renewing => 0,
            DhcpState::Rebinding => 0x8000,
            _ => 0x8000,
        };
        buffer[10..12].copy_from_slice(&flags.to_be_bytes());

        // ciaddr must be set for renewals; cleared for new requests
        if is_renewal {
            buffer[12..16].copy_from_slice(lease.ip_address.as_bytes());
        } else {
            buffer[12..16].fill(0);
        }

        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        // オプション開始
        let mut offset = DhcpHeader::SIZE;

        // マジッククッキー
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // メッセージタイプ: REQUEST
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Request as u8;
        offset += 3;

        // For requests in the SELECTING flow include Requested IP and Server Identifier.
        // In RENEW/REBIND do not include Server Identifier (and Requested IP is unnecessary because ciaddr is set).
        if !is_renewal {
            // 要求するIPアドレス
            buffer[offset] = DhcpOption::RequestedIp as u8;
            buffer[offset + 1] = 4;
            buffer[offset + 2..offset + 6].copy_from_slice(lease.ip_address.as_bytes());
            offset += 6;

            // サーバー識別子
            buffer[offset] = DhcpOption::ServerIdentifier as u8;
            buffer[offset + 1] = 4;
            buffer[offset + 2..offset + 6].copy_from_slice(lease.server_ip.as_bytes());
            offset += 6;
        }

        // パラメータ要求リスト (SubnetMask, Router, DNS, DomainName, LeaseTime, ServerIdentifier, Renewal (T1), Rebinding (T2))
        buffer[offset] = DhcpOption::ParameterRequestList as u8;
        buffer[offset + 1] = 8;
        buffer[offset + 2] = DhcpOption::SubnetMask as u8;
        buffer[offset + 3] = DhcpOption::Router as u8;
        buffer[offset + 4] = DhcpOption::DnsServer as u8;
        buffer[offset + 5] = DhcpOption::DomainName as u8;
        buffer[offset + 6] = DhcpOption::LeaseTime as u8;
        buffer[offset + 7] = DhcpOption::ServerIdentifier as u8;
        buffer[offset + 8] = DhcpOption::RenewalTime as u8;
        buffer[offset + 9] = DhcpOption::RebindingTime as u8;
        offset += 10;

        // クライアント識別子
        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        // 終端
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        // 状態を更新
        match self.state.lock() {
            Ok(mut g) => {
                match current_state {
                    DhcpState::Requesting => *g = DhcpState::Requesting,
                    DhcpState::Renewing => *g = DhcpState::Renewing,
                    DhcpState::Rebinding => *g = DhcpState::Rebinding,
                    _ => {}
                }
            }
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (build_request) - state not updated");
                return Err("State lock poisoned");
            }
        }
        self.state_time.store(current_tick, Ordering::SeqCst);

        Ok(offset)
    }

    /// DHCP応答を処理
    pub fn process_response(
        &self,
        data: &[u8],
        current_tick: u64,
    ) -> Result<DhcpResponseResult, &'static str> {
        if data.len() < DhcpHeader::SIZE + 4 {
            return Err("Packet too small");
        }

        // ヘッダを解析
        let header =
            crate::util::get_ref::<DhcpHeader>(data, 0).expect("Dhcp header slice out of bounds");

        // トランザクションIDを確認
        if header.xid() != self.xid.load(Ordering::SeqCst) {
            return Err("Transaction ID mismatch");
        }

        // オペレーションを確認
        if header.op != DhcpOperation::Reply as u8 {
            return Err("Not a DHCP reply");
        }

        // CHADDR must match our MAC (first 6 bytes)
        let hlen = header.hlen as usize;
        if hlen < 6 {
            log::warn!("[NET] DHCP header hlen ({}) too small - rejecting", hlen);
            return Err("Invalid hardware address length in DHCP header");
        }
        {
            let mut mac_bytes = [0u8; 6];
            mac_bytes.copy_from_slice(&header.chaddr[0..6]);
            if mac_bytes != *self.mac_address.as_bytes() {
                log::warn!("[NET] DHCP CHADDR does not match client MAC - rejecting (chaddr={:?} expected={:?})", &header.chaddr[0..6], self.mac_address.as_bytes());
                return Err("CHADDR does not match client MAC");
            }
        }

        // マジッククッキーを確認
        let options_start = DhcpHeader::SIZE;
        if data[options_start..options_start + 4] != DHCP_MAGIC_COOKIE {
            return Err("Invalid magic cookie");
        }

        // オプションを解析
        let mut message_type = None;
        let mut subnet_mask = None;
        let mut router = None;
        let mut dns_servers = Vec::new();
        let mut lease_time = 86400u32; // デフォルト1日
        let mut renewal_time: Option<u32> = None;
        let mut rebinding_time: Option<u32> = None;
        let mut server_id = None;
        let mut hostname = None;
        let mut domain_name = None; 

        let mut offset = options_start + 4;
        while offset < data.len() {
            let opt = data[offset];

            if opt == DhcpOption::Pad as u8 {
                offset += 1;
                continue;
            }

            if opt == DhcpOption::End as u8 {
                break;
            }

            if offset + 1 >= data.len() {
                break;
            }

            let len = data[offset + 1] as usize;
            // Ensure the option length does not overrun the packet
            if offset + 2 + len > data.len() {
                log::warn!("[NET] DHCP option length {} at offset {} overruns packet (len {}) - stopping parse", len, offset, data.len());
                break;
            }
            let opt_data = &data[offset + 2..offset + 2 + len];

            match opt {
                53 => {
                    // Message Type
                    if !opt_data.is_empty() {
                        message_type = DhcpMessageType::from_u8(opt_data[0]);
                    }
                }
                1 => {
                    // Subnet Mask
                    if opt_data.len() >= 4 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&opt_data[..4]);
                        subnet_mask = Some(Ipv4Address::new(bytes));
                    }
                }
                3 => {
                    // Router
                    if opt_data.len() >= 4 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&opt_data[..4]);
                        router = Some(Ipv4Address::new(bytes));
                    }
                }
                6 => {
                    // DNS Servers
                    for chunk in opt_data.chunks(4) {
                        if chunk.len() == 4 {
                            let mut bytes = [0u8; 4];
                            bytes.copy_from_slice(chunk);
                            dns_servers.push(Ipv4Address::new(bytes));
                        }
                    }
                }
                51 => {
                    // Lease Time
                    if opt_data.len() >= 4 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&opt_data[..4]);
                        lease_time = u32::from_be_bytes(bytes);
                    }
                }
                58 => {
                    // Renewal (T1)
                    if opt_data.len() >= 4 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&opt_data[..4]);
                        renewal_time = Some(u32::from_be_bytes(bytes));
                    }
                }
                59 => {
                    // Rebinding (T2)
                    if opt_data.len() >= 4 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&opt_data[..4]);
                        rebinding_time = Some(u32::from_be_bytes(bytes));
                    }
                }
                54 => {
                    // Server Identifier
                    if opt_data.len() >= 4 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&opt_data[..4]);
                        server_id = Some(Ipv4Address::new(bytes));
                    }
                }
                12 => {
                    // Hostname
                    hostname = Some(opt_data.to_vec());
                }
                15 => {
                    // Domain Name
                    domain_name = Some(opt_data.to_vec());
                }
                _ => {}
            }

            offset += 2 + len;
        }

        let msg_type = message_type.ok_or("No message type in response")?;

        // Additional integrity checks for OFFER/ACK
        if matches!(msg_type, DhcpMessageType::Offer | DhcpMessageType::Ack) {
            // Server Identifier (option 54) is required in DHCPOFFER and DHCPACK
            let sid = server_id.ok_or("No server identifier in response")?;

            // If siaddr is set, it must match the Server Identifier option
            let siaddr = header.siaddr();
            if siaddr != Ipv4Address::new([0, 0, 0, 0]) && siaddr != sid {
                log::warn!("[NET] DHCP server identifier ({:?}) and siaddr ({:?}) mismatch", sid, siaddr);
                return Err("Server identifier mismatch");
            }

            // yiaddr must be present in Offer/Ack
            if header.yiaddr() == Ipv4Address::new([0, 0, 0, 0]) {
                return Err("Missing yiaddr in Offer/Ack");
            }

            // State-dependent consistency checks
            let current_state = match self.state.lock() {
                Ok(g) => *g,
                Err(_) => {
                    log::error!("[NET] DHCP State lock poisoned (process_response) - cannot verify response");
                    return Err("State lock poisoned");
                }
            };

            if msg_type == DhcpMessageType::Offer {
                // If we already have an offered lease, ensure server matches
                match self.offered_lease.lock() {
                    Ok(off) => {
                        if let Some(ref o) = *off {
                            if o.server_ip != sid {
                                return Err("Offer server identifier does not match existing offer");
                            }
                        }
                    }
                    Err(_) => {
                        log::error!("[NET] DHCP Offer lock poisoned (process_response Offer) - cannot verify offer");
                        return Err("Offer lock poisoned");
                    }
                }
            } else {
                // ACK handling: ensure ACK corresponds to our offer (when requesting) or bound lease (when renewing)
                match current_state {
                    DhcpState::Requesting => {
                        match self.offered_lease.lock() {
                            Ok(off) => {
                                let offered = off.as_ref().ok_or("No offer for ACK")?;
                                if offered.server_ip != sid {
                                    return Err("ACK server identifier does not match offered server");
                                }
                                if offered.ip_address != header.yiaddr() {
                                    return Err("ACK yiaddr does not match offered IP");
                                }
                            }
                            Err(_) => {
                                log::error!("[NET] DHCP Offer lock poisoned (process_response Ack) - cannot verify ACK");
                                return Err("Offer lock poisoned");
                            }
                        }
                    }
                    DhcpState::Renewing | DhcpState::Rebinding => {
                        match self.lease.lock() {
                            Ok(l) => {
                                let lease_guard = l.as_ref().ok_or("No active lease for ACK")?;
                                if lease_guard.server_ip != sid {
                                    return Err("ACK server identifier does not match bound server");
                                }
                                if lease_guard.ip_address != header.yiaddr() {
                                    return Err("ACK yiaddr does not match bound IP");
                                }
                            }
                            Err(_) => {
                                log::error!("[NET] DHCP Lease lock poisoned (process_response Ack) - cannot verify ACK");
                                return Err("Lease lock poisoned");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        match msg_type {
            DhcpMessageType::Offer => {
                // Compute T1/T2 defaults if not present
                let t1 = renewal_time.unwrap_or(lease_time / 2);
                let t2 = rebinding_time.unwrap_or((lease_time * 7) / 8);

                let lease = DhcpLease {
                    ip_address: header.yiaddr(),
                    subnet_mask: subnet_mask.unwrap_or(Ipv4Address::new([255, 255, 255, 0])),
                    gateway: router,
                    dns_servers,
                    server_ip: server_id.unwrap_or(header.siaddr()),
                    lease_time,
                    t1,
                    t2,
                    obtained_at: current_tick,
                    hostname,
                    domain_name,
                };

                match self.offered_lease.lock() {
                    Ok(mut g) => *g = Some(lease.clone()),
                    Err(_) => log::error!("[NET] DHCP Offer lock poisoned (process_response Offer) - skipping storing offer"),
                }

                // Best-effort: ARP probe the offered IP to detect conflicts
                match crate::net::stack::stack().lock() {
                    Ok(mut s) => {
                        if let Some(stack) = s.as_mut() {
                            stack.send_arp_request(lease.ip_address);
                        }
                    }
                    Err(_) => log::error!("[NET] DHCP Global Stack lock poisoned (process_response Offer) - cannot send ARP probe"),
                }
                self.offered_probe_at.store(current_tick, Ordering::SeqCst);

                Ok(DhcpResponseResult::Offer(lease))
            }
            DhcpMessageType::Ack => {
                // Compute T1/T2 defaults if not present
                let t1 = renewal_time.unwrap_or(lease_time / 2);
                let t2 = rebinding_time.unwrap_or((lease_time * 7) / 8);

                let lease = DhcpLease {
                    ip_address: header.yiaddr(),
                    subnet_mask: subnet_mask.unwrap_or(Ipv4Address::new([255, 255, 255, 0])),
                    gateway: router,
                    dns_servers,
                    server_ip: server_id.unwrap_or(header.siaddr()),
                    lease_time,
                    t1,
                    t2,
                    obtained_at: current_tick,
                    hostname,
                    domain_name,
                };

                match self.lease.lock() {
                    Ok(mut g) => *g = Some(lease.clone()),
                    Err(_) => log::error!("[NET] DHCP Lease lock poisoned (process_response Ack) - skipping storing lease"),
                }
                // Clear any offer probe state
                self.offered_probe_at.store(0, Ordering::SeqCst);
                match self.state.lock() {
                    Ok(mut g) => *g = DhcpState::Bound,
                    Err(_) => log::error!("[NET] DHCP State lock poisoned (process_response Ack) - state not updated"),
                }
                self.state_time.store(current_tick, Ordering::SeqCst);
                self.retry_count.store(0, Ordering::SeqCst);

                Ok(DhcpResponseResult::Ack(lease))
            }
            DhcpMessageType::Nak => {
                match self.state.lock() {
                    Ok(mut g) => *g = DhcpState::Init,
                    Err(_) => log::error!("[NET] DHCP State lock poisoned (process_response Nak) - state not updated"),
                }
                match self.offered_lease.lock() {
                    Ok(mut g) => *g = None,
                    Err(_) => log::error!("[NET] DHCP Offer lock poisoned (process_response Nak) - skipping clear"),
                }
                // Clear any probe timestamp
                self.offered_probe_at.store(0, Ordering::SeqCst);
                Ok(DhcpResponseResult::Nak)
            }
            _ => Err("Unexpected message type"),
        }
    }

    /// Build DHCPDECLINE packet for a conflicting IP
    pub fn build_decline(
        &self,
        buffer: &mut [u8],
        declined_ip: Ipv4Address,
        server_ip: Option<Ipv4Address>,
        current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
        }

        let xid = self.xid.load(Ordering::SeqCst);

        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
        buffer[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Message Type: DECLINE
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Decline as u8;
        offset += 3;

        // Requested IP (the offending IP)
        buffer[offset] = DhcpOption::RequestedIp as u8;
        buffer[offset + 1] = 4;
        buffer[offset + 2..offset + 6].copy_from_slice(declined_ip.as_bytes());
        offset += 6;

        // Server Identifier (if provided)
        if let Some(sip) = server_ip {
            buffer[offset] = DhcpOption::ServerIdentifier as u8;
            buffer[offset + 1] = 4;
            buffer[offset + 2..offset + 6].copy_from_slice(sip.as_bytes());
            offset += 6;
        }

        // Client identifier
        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        // End
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        Ok(offset)
    }

    /// Send a DHCPDECLINE (best-effort)
    pub fn send_decline(&self, declined_ip: Ipv4Address, server_ip: Option<Ipv4Address>) -> bool {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
        match self.build_decline(&mut buf, declined_ip, server_ip, 0) {
            Ok(len) => {
                // Record for tests/diagnostics
                self.last_declined.store(declined_ip.to_u32(), Ordering::SeqCst);

                let dst = server_ip.unwrap_or(Ipv4Address::new([255, 255, 255, 255]));
                crate::net::stack::send_udp(DHCP_CLIENT_PORT, dst, DHCP_SERVER_PORT, &buf[..len])
            }
            Err(_) => false,
        }
    }

    /// Build DHCPRELEASE packet
    pub fn build_release(&self, buffer: &mut [u8], current_tick: u64) -> Result<usize, &'static str> {
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
        }

        let xid = self.xid.load(Ordering::SeqCst);

        // Need an active lease
        let lease = match self.lease.lock() {
            Ok(g) => g.clone().ok_or("No active lease")?,
            Err(_) => return Err("Lease lock poisoned"),
        };

        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
        buffer[10..12].copy_from_slice(&0u16.to_be_bytes()); // flags

        // ciaddr = current IP
        buffer[12..16].copy_from_slice(lease.ip_address.as_bytes());
        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Message Type: RELEASE
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Release as u8;
        offset += 3;

        // Server Identifier
        buffer[offset] = DhcpOption::ServerIdentifier as u8;
        buffer[offset + 1] = 4;
        buffer[offset + 2..offset + 6].copy_from_slice(lease.server_ip.as_bytes());
        offset += 6;

        // Client identifier
        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        // End
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        Ok(offset)
    }

    /// Send DHCPRELEASE (best-effort)
    pub fn send_release(&self) -> bool {
        // Acquire lease to get server
        let lease = match self.lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => return false,
        };

        let lease = match lease {
            Some(l) => l,
            None => return false,
        };

        // Record for tests/diagnostics
        self.last_released.store(lease.ip_address.to_u32(), Ordering::SeqCst);

        let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
        match self.build_release(&mut buf, 0) {
            Ok(len) => crate::net::stack::send_udp(DHCP_CLIENT_PORT, lease.server_ip, DHCP_SERVER_PORT, &buf[..len]),
            Err(_) => false,
        }
    }

    /// リースを解放
    pub fn release(&self) {
        // Attempt to send RELEASE (best-effort)
        let _ = self.send_release();

        match self.state.lock() {
            Ok(mut g) => *g = DhcpState::Init,
            Err(_) => log::error!("[NET] DHCP State lock poisoned (release) - state not updated"),
        }
        match self.lease.lock() {
            Ok(mut g) => *g = None,
            Err(_) => log::error!("[NET] DHCP Lease lock poisoned (release) - skipping clear"),
        }
        match self.offered_lease.lock() {
            Ok(mut g) => *g = None,
            Err(_) => log::error!("[NET] DHCP Offer lock poisoned (release) - skipping clear"),
        }
        // Reset probe timestamp
        self.offered_probe_at.store(0, Ordering::SeqCst);
    }

    /// タイムアウトをチェック
    pub fn check_timeout(&self, current_tick: u64, tick_rate: u64) -> bool {
        let state = match self.state.lock() {
            Ok(g) => *g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (check_timeout) - treating as Init");
                DhcpState::Init
            }
        };
        let state_time = self.state_time.load(Ordering::SeqCst);
        let elapsed_secs = (current_tick.saturating_sub(state_time)) / tick_rate;

        match state {
            DhcpState::Selecting => {
                // If we have an offered lease, perform ARP probe & check for conflicts before moving to Requesting
                if let Ok(off) = self.offered_lease.lock() {
                    if let Some(ref offered) = *off {
                        let probe_at = self.offered_probe_at.load(Ordering::SeqCst);
                        if probe_at == 0 {
                            // Send ARP probe (best-effort)
                            match crate::net::stack::stack().lock() {
                                Ok(mut s) => {
                                    if let Some(stack) = s.as_mut() {
                                        stack.send_arp_request(offered.ip_address);
                                        self.offered_probe_at.store(current_tick, Ordering::SeqCst);
                                        return false; // wait for probe reply
                                    }
                                }
                                Err(_) => log::error!("[NET] DHCP Global Stack lock poisoned (check_timeout Selecting) - cannot send ARP probe"),
                            }
                        } else {
                            let probe_elapsed = (current_tick.saturating_sub(probe_at)) / tick_rate;
                            if probe_elapsed < Self::PROBE_WAIT_SECS {
                                return false; // still waiting for ARP replies
                            }

                            // Probe timeout elapsed; check ARP cache for conflict
                            if let Ok(mut s) = crate::net::stack::stack().lock() {
                                if let Some(stack) = s.as_mut() {
                                    if let Some(mac) = stack.arp_resolve(offered.ip_address, current_tick) {
                                        // If resolved to a MAC different from ours, it's a conflict
                                        if mac != self.mac_address && !mac.is_broadcast() {
                                            // Send DECLINE to the server
                                            let server = Some(offered.server_ip);
                                            let _ = self.send_decline(offered.ip_address, server);

                                            // Clear offered lease and probe state
                                            match self.offered_lease.lock() {
                                                Ok(mut og) => *og = None,
                                                Err(_) => log::error!("[NET] DHCP Offer lock poisoned (check_timeout) - cannot clear after decline"),
                                            }
                                            self.offered_probe_at.store(0, Ordering::SeqCst);

                                            // Prompt caller to retry discovery
                                            return true;
                                        }
                                    }
                                }
                            }

                            // No conflict detected -> move to Requesting to accept offer
                            match self.state.lock() {
                                Ok(mut g) => *g = DhcpState::Requesting,
                                Err(_) => log::error!("[NET] DHCP State lock poisoned (check_timeout) - cannot move to Requesting"),
                            }
                            // reset retry count for request flow
                            self.retry_count.store(0, Ordering::SeqCst);
                            return true;
                        }
                    }
                }

                // No offer yet or fallback to retransmit DISCOVER
                if elapsed_secs > Self::RETRY_INTERVAL_SECS {
                    let retry = self.retry_count.fetch_add(1, Ordering::SeqCst);
                    if retry >= Self::MAX_RETRIES {
                        match self.state.lock() {
                            Ok(mut s) => *s = DhcpState::Init,
                            Err(_) => log::error!("[NET] DHCP State lock poisoned (check_timeout) - cannot reset to Init"),
                        }
                        self.retry_count.store(0, Ordering::SeqCst);
                    }
                    return true;
                }
            }
            DhcpState::Requesting => {
                // 4秒でタイムアウト / retransmit
                if elapsed_secs > Self::RETRY_INTERVAL_SECS {
                    let retry = self.retry_count.fetch_add(1, Ordering::SeqCst);
                    if retry >= Self::MAX_RETRIES {
                        match self.state.lock() {
                            Ok(mut s) => *s = DhcpState::Init,
                            Err(_) => log::error!("[NET] DHCP State lock poisoned (check_timeout) - cannot reset to Init"),
                        }
                        self.retry_count.store(0, Ordering::SeqCst);
                    }
                    return true;
                }
            }
            DhcpState::Bound => {
                if let Ok(guard) = self.lease.lock() {
                    if let Some(lease) = guard.as_ref() {
                        if lease.needs_renewal(current_tick, tick_rate) {
                            match self.state.lock() {
                                Ok(mut g) => *g = DhcpState::Renewing,
                                Err(_) => log::error!("[NET] DHCP State lock poisoned (check_timeout) - state not updated"),
                            }
                            // initialize retry counter and timestamp
                            self.state_time.store(current_tick, Ordering::SeqCst);
                            self.retry_count.store(0, Ordering::SeqCst);
                            return true;
                        }
                    }
                } else {
                    log::error!("[NET] DHCP Lease lock poisoned (check_timeout) - skipping renewal check");
                }
            }
            DhcpState::Renewing => {
                // If T2 is reached, move to Rebinding
                if let Ok(guard) = self.lease.lock() {
                    if let Some(lease) = guard.as_ref() {
                        if lease.needs_rebind(current_tick, tick_rate) {
                            match self.state.lock() {
                                Ok(mut g) => *g = DhcpState::Rebinding,
                                Err(_) => log::error!("[NET] DHCP State lock poisoned (check_timeout) - cannot move to Rebinding"),
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                            self.retry_count.store(0, Ordering::SeqCst);
                            return true;
                        }
                    }
                }

                // Retransmit renewal requests at retry interval
                if elapsed_secs > Self::RETRY_INTERVAL_SECS {
                    let retry = self.retry_count.fetch_add(1, Ordering::SeqCst);
                    if retry >= Self::MAX_RETRIES {
                        // Escalate to Rebinding
                        match self.state.lock() {
                            Ok(mut g) => *g = DhcpState::Rebinding,
                            Err(_) => log::error!("[NET] DHCP State lock poisoned (check_timeout) - cannot escalate to Rebinding"),
                        }
                        self.retry_count.store(0, Ordering::SeqCst);
                    }
                    return true;
                }
            }
            DhcpState::Rebinding => {
                // Retransmit rebind requests; if retried too many times, give up and start over
                if elapsed_secs > Self::RETRY_INTERVAL_SECS {
                    let retry = self.retry_count.fetch_add(1, Ordering::SeqCst);
                    if retry >= Self::MAX_RETRIES {
                        // Give up
                        match self.state.lock() {
                            Ok(mut s) => *s = DhcpState::Init,
                            Err(_) => log::error!("[NET] DHCP State lock poisoned (check_timeout) - cannot reset to Init"),
                        }
                        self.retry_count.store(0, Ordering::SeqCst);
                        // Clear leases
                        match self.lease.lock() {
                            Ok(mut g) => *g = None,
                            Err(_) => log::error!("[NET] DHCP Lease lock poisoned (check_timeout) - cannot clear lease"),
                        }
                        match self.offered_lease.lock() {
                            Ok(mut g) => *g = None,
                            Err(_) => log::error!("[NET] DHCP Offer lock poisoned (check_timeout) - cannot clear offer"),
                        }
                        self.offered_probe_at.store(0, Ordering::SeqCst);
                    }
                    return true;
                }
            }
            _ => {}
        }

        false
    }
}

/// DHCP応答処理結果
#[derive(Debug)]
pub enum DhcpResponseResult {
    /// OFFERを受信
    Offer(DhcpLease),
    /// ACKを受信 (リース取得成功)
    Ack(DhcpLease),
    /// NAKを受信 (リース取得失敗)
    Nak,
}

/// グローバルDHCPクライアント
static DHCP_CLIENT: PoisonLock<Option<DhcpClient>> = PoisonLock::new(None);

/// DHCPクライアントを初期化
pub fn init(mac_address: MacAddress) {
    let client = DhcpClient::new(mac_address);
    match DHCP_CLIENT.lock() {
        Ok(mut g) => *g = Some(client),
        Err(_) => log::error!("[NET] DHCP Global lock poisoned (init) - initialization skipped"),
    }
}

/// DHCPクライアントを取得
pub fn client() -> Option<&'static PoisonLock<Option<DhcpClient>>> {
    Some(&DHCP_CLIENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::set_panicking;
    use core::sync::atomic::Ordering;

    #[test_case]
    fn test_check_timeout_poisoned_state_reset_skips() {
        let client = DhcpClient::new(crate::net::ethernet::MacAddress::ZERO);
        {
            let mut s = client.state.lock().unwrap();
            *s = DhcpState::Selecting;
        }
        client.state_time.store(0, Ordering::SeqCst);
        client.retry_count.store(DhcpClient::MAX_RETRIES - 1, Ordering::SeqCst);

        set_panicking(true);
        // Should not panic even if state lock is poisoned
        let _ = client.check_timeout(10, 1);
        set_panicking(false);
    }

    #[test_case]
    fn test_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip() {
        let client = DhcpClient::new(crate::net::ethernet::MacAddress::ZERO);

        let lease = DhcpLease {
            ip_address: Ipv4Address::new([192, 168, 0, 42]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Some(Ipv4Address::new([192, 168, 0, 1])),
            dns_servers: Vec::new(),
            server_ip: Ipv4Address::new([192, 168, 0, 1]),
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
            obtained_at: 0,
            hostname: None,
            domain_name: None,
        };

        {
            let mut l = client.lease.lock().unwrap();
            *l = Some(lease.clone());
        }
        {
            let mut s = client.state.lock().unwrap();
            *s = DhcpState::Renewing;
        }

        let mut buf = vec![0u8; 512];
        let len = client.build_request(&mut buf, 123).expect("build_request failed");

        // ciaddr should be set to the current IP
        assert_eq!(&buf[12..16], lease.ip_address.as_bytes());

        // Options area should NOT include Server Identifier or Requested IP for renewal
        let opts = &buf[DhcpHeader::SIZE..len];
        assert!(!opts.iter().any(|b| *b == DhcpOption::ServerIdentifier as u8));
        assert!(!opts.iter().any(|b| *b == DhcpOption::RequestedIp as u8));
    }

    #[test_case]
    fn test_build_request_requesting_includes_serverid_and_requestedip() {
        let client = DhcpClient::new(crate::net::ethernet::MacAddress::ZERO);

        let offered = DhcpLease {
            ip_address: Ipv4Address::new([10, 0, 0, 5]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Some(Ipv4Address::new([10, 0, 0, 1])),
            dns_servers: Vec::new(),
            server_ip: Ipv4Address::new([10, 0, 0, 1]),
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
            obtained_at: 0,
            hostname: None,
            domain_name: None,
        };

        {
            let mut o = client.offered_lease.lock().unwrap();
            *o = Some(offered.clone());
        }
        {
            let mut s = client.state.lock().unwrap();
            *s = DhcpState::Requesting;
        }

        let mut buf = vec![0u8; 512];
        let len = client.build_request(&mut buf, 42).expect("build_request failed");
        let opts = &buf[DhcpHeader::SIZE..len];
        assert!(opts.iter().any(|b| *b == DhcpOption::ServerIdentifier as u8));
        assert!(opts.iter().any(|b| *b == DhcpOption::RequestedIp as u8));
    }

    #[test_case]
    fn test_build_discover_reuse_xid_on_retransmit() {
        let client = DhcpClient::new(crate::net::ethernet::MacAddress::ZERO);

        // Pre-set XID and state to Selecting (retransmit scenario)
        client.xid.store(0x1234_5678, Ordering::SeqCst);
        {
            let mut s = client.state.lock().unwrap();
            *s = DhcpState::Selecting;
        }

        let mut buf1 = vec![0u8; 512];
        let _ = client.build_discover(&mut buf1, 10).expect("build_discover failed");
        let xid1 = u32::from_be_bytes(buf1[4..8].try_into().unwrap());
        assert_eq!(xid1, 0x1234_5678);

        let mut buf2 = vec![0u8; 512];
        let _ = client.build_discover(&mut buf2, 20).expect("build_discover failed");
        let xid2 = u32::from_be_bytes(buf2[4..8].try_into().unwrap());
        assert_eq!(xid2, 0x1234_5678);
    }

    #[test_case]
    fn test_build_discover_state_lock_poison_returns_err() {
        let client = DhcpClient::new(crate::net::ethernet::MacAddress::ZERO);

        // Poison the state lock by dropping a guard while marked as panicking
        {
            let g = client.state.lock().unwrap();
            set_panicking(true);
            drop(g); // dropping while panicking should poison
            set_panicking(false);
        }

        let mut buf = vec![0u8; 512];
        assert!(client.build_discover(&mut buf, 100).is_err());
    }

    #[test_case]
    fn test_process_response_chaddr_mismatch() {
        use crate::net::ethernet::MacAddress;

        let client = DhcpClient::new(MacAddress::new([1, 2, 3, 4, 5, 6]));
        client.xid.store(0x1234_5678, Ordering::SeqCst);

        let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
        buf[0] = DhcpOperation::Reply as u8;
        buf[1] = 1;
        buf[2] = 6;
        buf[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr
        buf[20..24].copy_from_slice(&[192, 168, 0, 1]); // siaddr
        // CHADDR does not match client MAC
        buf[28..34].copy_from_slice(&[7, 7, 7, 7, 7, 7]);

        let mut offset = DhcpHeader::SIZE;
        buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        buf[offset] = DhcpOption::MessageType as u8;
        buf[offset + 1] = 1;
        buf[offset + 2] = DhcpMessageType::Offer as u8;
        offset += 3;

        buf[offset] = DhcpOption::ServerIdentifier as u8;
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&[192, 168, 0, 1]);
        offset += 6;

        buf[offset] = DhcpOption::End as u8;
        offset += 1;

        assert!(client.process_response(&buf, 100).is_err());
    }

    #[test_case]
    fn test_process_response_offer_missing_serverid_returns_err() {
        use crate::net::ethernet::MacAddress;

        let client = DhcpClient::new(MacAddress::new([1, 2, 3, 4, 5, 6]));
        client.xid.store(0x2222_3333, Ordering::SeqCst);

        let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
        buf[0] = DhcpOperation::Reply as u8;
        buf[1] = 1;
        buf[2] = 6;
        buf[4..8].copy_from_slice(&0x2222_3333u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr
        buf[28..34].copy_from_slice(client.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        buf[offset] = DhcpOption::MessageType as u8;
        buf[offset + 1] = 1;
        buf[offset + 2] = DhcpMessageType::Offer as u8;
        offset += 3;

        // No Server Identifier option

        buf[offset] = DhcpOption::End as u8;
        offset += 1;

        assert!(client.process_response(&buf, 200).is_err());
    }

    #[test_case]
    fn test_process_response_siaddr_serverid_mismatch() {
        use crate::net::ethernet::MacAddress;

        let client = DhcpClient::new(MacAddress::new([1, 2, 3, 4, 5, 6]));
        client.xid.store(0x4444_5555, Ordering::SeqCst);

        let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
        buf[0] = DhcpOperation::Reply as u8;
        buf[1] = 1;
        buf[2] = 6;
        buf[4..8].copy_from_slice(&0x4444_5555u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr
        buf[20..24].copy_from_slice(&[192, 168, 0, 5]); // siaddr
        buf[28..34].copy_from_slice(client.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        buf[offset] = DhcpOption::MessageType as u8;
        buf[offset + 1] = 1;
        buf[offset + 2] = DhcpMessageType::Offer as u8;
        offset += 3;

        // Server Identifier different from siaddr
        buf[offset] = DhcpOption::ServerIdentifier as u8;
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&[192, 168, 0, 1]);
        offset += 6;

        buf[offset] = DhcpOption::End as u8;
        offset += 1;

        assert!(client.process_response(&buf, 300).is_err());
    }

    #[test_case]
    fn test_process_response_ack_requesting_mismatch() {
        use crate::net::ethernet::MacAddress;

        let client = DhcpClient::new(MacAddress::new([8, 8, 8, 8, 8, 8]));
        client.xid.store(0x6666_7777, Ordering::SeqCst);

        // Offered lease does not match incoming ACK server identifier
        let offered = DhcpLease {
            ip_address: Ipv4Address::new([10, 0, 0, 5]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Some(Ipv4Address::new([10, 0, 0, 1])),
            dns_servers: Vec::new(),
            server_ip: Ipv4Address::new([10, 0, 0, 1]),
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
            obtained_at: 0,
            hostname: None,
            domain_name: None,
        };

        {
            let mut o = client.offered_lease.lock().unwrap();
            *o = Some(offered.clone());
        }
        {
            let mut s = client.state.lock().unwrap();
            *s = DhcpState::Requesting;
        }

        let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
        buf[0] = DhcpOperation::Reply as u8;
        buf[1] = 1;
        buf[2] = 6;
        buf[4..8].copy_from_slice(&0x6666_7777u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr matches offered
        buf[28..34].copy_from_slice(client.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        buf[offset] = DhcpOption::MessageType as u8;
        buf[offset + 1] = 1;
        buf[offset + 2] = DhcpMessageType::Ack as u8; // ACK comes from different server
        offset += 3;

        // Server Identifier that does NOT match offered.server_ip
        buf[offset] = DhcpOption::ServerIdentifier as u8;
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 2]);
        offset += 6;

        buf[offset] = DhcpOption::End as u8;
        offset += 1;

        assert!(client.process_response(&buf, 400).is_err());
    }

    #[test_case]
    fn test_process_response_ack_renewal_success() {
        use crate::net::ethernet::MacAddress;

        let client = DhcpClient::new(MacAddress::new([9, 9, 9, 9, 9, 9]));
        client.xid.store(0x9999_aaaa, Ordering::SeqCst);

        let lease = DhcpLease {
            ip_address: Ipv4Address::new([192, 168, 0, 42]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Some(Ipv4Address::new([192, 168, 0, 1])),
            dns_servers: Vec::new(),
            server_ip: Ipv4Address::new([192, 168, 0, 1]),
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
            obtained_at: 0,
            hostname: None,
            domain_name: None,
        };

        {
            let mut l = client.lease.lock().unwrap();
            *l = Some(lease.clone());
        }
        {
            let mut s = client.state.lock().unwrap();
            *s = DhcpState::Renewing;
        }

        // Build ACK matching current lease
        let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
        buf[0] = DhcpOperation::Reply as u8;
        buf[1] = 1;
        buf[2] = 6;
        buf[4..8].copy_from_slice(&0x9999_aaaau32.to_be_bytes());
        buf[16..20].copy_from_slice(lease.ip_address.as_bytes()); // yiaddr
        buf[28..34].copy_from_slice(client.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        buf[offset] = DhcpOption::MessageType as u8;
        buf[offset + 1] = 1;
        buf[offset + 2] = DhcpMessageType::Ack as u8;
        offset += 3;

        buf[offset] = DhcpOption::ServerIdentifier as u8;
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(lease.server_ip.as_bytes());
        offset += 6;

        buf[offset] = DhcpOption::End as u8;
        offset += 1;

        let res = client.process_response(&buf, 500).expect("ACK should be accepted");
        match res {
            DhcpResponseResult::Ack(l) => {
                assert_eq!(l.ip_address, lease.ip_address);
            }
            _ => panic!("expected Ack"),
        }
    }

    #[test_case]
    fn test_build_decline_and_build_release_contents() {
        use crate::net::ethernet::MacAddress;

        let client = DhcpClient::new(MacAddress::new([1,2,3,4,5,6]));
        client.xid.store(0xabab_cdef, Ordering::SeqCst);

        // build_decline
        let mut dbuf = [0u8; 256];
        let declined_ip = Ipv4Address::new([10,0,0,99]);
        let server_ip = Some(Ipv4Address::new([10,0,0,1]));
        let len = client.build_decline(&mut dbuf, declined_ip, server_ip, 0).expect("build_decline failed");
        let opts = &dbuf[DhcpHeader::SIZE..len];
        // check MessageType Decline present
        assert!(opts.windows(3).any(|w| w[0] == DhcpOption::MessageType as u8 && w[1] == 1 && w[2] == DhcpMessageType::Decline as u8));
        // check Requested IP option present
        assert!(opts.windows(6).any(|w| w[0] == DhcpOption::RequestedIp as u8 && w[1] == 4 && &w[2..6] == declined_ip.as_bytes()));
        // check Server Identifier present
        assert!(opts.windows(6).any(|w| w[0] == DhcpOption::ServerIdentifier as u8 && w[1] == 4 && &w[2..6] == server_ip.unwrap().as_bytes()));

        // build_release
        let lease = DhcpLease {
            ip_address: Ipv4Address::new([172,16,0,5]),
            subnet_mask: Ipv4Address::new([255,255,0,0]),
            gateway: None,
            dns_servers: Vec::new(),
            server_ip: Ipv4Address::new([10,0,0,1]),
            lease_time: 1200,
            t1: 600,
            t2: 900,
            obtained_at: 0,
            hostname: None,
            domain_name: None,
        };
        {
            let mut l = client.lease.lock().unwrap();
            *l = Some(lease.clone());
        }

        let mut rbuf = [0u8; 256];
        let rlen = client.build_release(&mut rbuf, 0).expect("build_release failed");
        // ciaddr should be set
        assert_eq!(&rbuf[12..16], lease.ip_address.as_bytes());
        let ropts = &rbuf[DhcpHeader::SIZE..rlen];
        assert!(ropts.windows(3).any(|w| w[0] == DhcpOption::MessageType as u8 && w[1] == 1 && w[2] == DhcpMessageType::Release as u8));
        assert!(ropts.windows(6).any(|w| w[0] == DhcpOption::ServerIdentifier as u8 && w[1] == 4 && &w[2..6] == lease.server_ip.as_bytes()));
    }

    #[test_case]
    fn test_release_clears_lease_and_sets_last_released() {
        use crate::net::ethernet::MacAddress;

        let client = DhcpClient::new(MacAddress::new([5,5,5,5,5,5]));
        let lease = DhcpLease {
            ip_address: Ipv4Address::new([192,168,10,10]),
            subnet_mask: Ipv4Address::new([255,255,255,0]),
            gateway: None,
            dns_servers: Vec::new(),
            server_ip: Ipv4Address::new([10,0,0,1]),
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
            obtained_at: 0,
            hostname: None,
            domain_name: None,
        };
        {
            let mut l = client.lease.lock().unwrap();
            *l = Some(lease.clone());
        }
        {
            let mut s = client.state.lock().unwrap();
            *s = DhcpState::Bound;
        }

        // Call release (best-effort send) - should clear lease and set last_released
        client.release();
        assert!(client.lease.lock().unwrap().is_none());
        assert_eq!(client.last_released_ip(), Some(lease.ip_address));
    }

    #[test_case]
    fn test_parse_t1_t2_and_timeout_transitions() {
        let client = DhcpClient::new(crate::net::ethernet::MacAddress::ZERO);
        client.xid.store(0x1111_2222, Ordering::SeqCst);

        let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
        buf[0] = DhcpOperation::Reply as u8;
        buf[1] = 1;
        buf[2] = 6;
        buf[4..8].copy_from_slice(&0x1111_2222u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 8]); // yiaddr
        buf[28..34].copy_from_slice(client.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Message Type: ACK
        buf[offset] = DhcpOption::MessageType as u8;
        buf[offset + 1] = 1;
        buf[offset + 2] = DhcpMessageType::Ack as u8;
        offset += 3;

        // Server Identifier
        buf[offset] = DhcpOption::ServerIdentifier as u8;
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 1]);
        offset += 6;

        // Lease Time
        buf[offset] = DhcpOption::LeaseTime as u8;
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&100u32.to_be_bytes());
        offset += 6;

        // Renewal (T1)
        buf[offset] = 58u8; // RenewalTime
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&30u32.to_be_bytes());
        offset += 6;

        // Rebinding (T2)
        buf[offset] = 59u8; // RebindingTime
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&60u32.to_be_bytes());
        offset += 6;

        buf[offset] = DhcpOption::End as u8;
        offset += 1;

        let res = client.process_response(&buf, 0).expect("ACK should be accepted");
        match res {
            DhcpResponseResult::Ack(lease) => {
                assert_eq!(lease.lease_time, 100);
                assert_eq!(lease.t1, 30);
                assert_eq!(lease.t2, 60);

                // Verify T1 transition to Renewing
                {
                    let mut s = client.state.lock().unwrap();
                    *s = DhcpState::Bound;
                }
                client.lease.lock().unwrap().as_mut().unwrap().obtained_at = 0;
                // current_tick passes T1
                assert!(client.check_timeout(31, 1));
                assert_eq!(client.state(), DhcpState::Renewing);

                // advance past T2 -> Rebinding
                assert!(client.check_timeout(61, 1));
                assert_eq!(client.state(), DhcpState::Rebinding);
            }
            _ => panic!("expected Ack"),
        }
    }

    #[test_case]
    fn test_offer_probe_and_decline_flow() {
        use crate::net::stack;
        use crate::net::ethernet::MacAddress;

        // Initialize global stack for ARP facilities (best-effort)
        stack::init_default();

        let client = DhcpClient::new(MacAddress::new([7, 7, 7, 7, 7, 7]));
        client.xid.store(0x3333_4444, Ordering::SeqCst);

        // Build an OFFER packet
        let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
        buf[0] = DhcpOperation::Reply as u8;
        buf[1] = 1;
        buf[2] = 6;
        buf[4..8].copy_from_slice(&0x3333_4444u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 9]); // yiaddr
        buf[28..34].copy_from_slice(client.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        buf[offset] = DhcpOption::MessageType as u8;
        buf[offset + 1] = 1;
        buf[offset + 2] = DhcpMessageType::Offer as u8;
        offset += 3;

        // Server Identifier
        buf[offset] = DhcpOption::ServerIdentifier as u8;
        buf[offset + 1] = 4;
        buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 1]);
        offset += 6;

        buf[offset] = DhcpOption::End as u8;
        offset += 1;

        // Process offer (should send ARP probe and set probe timestamp)
        let _ = client.process_response(&buf, 100).expect("Offer should be processed");
        assert!(client.offered_lease.lock().unwrap().is_some());
        assert!(client.offered_probe_at.load(Ordering::SeqCst) != 0);

        // Simulate ARP reply from another host for the offered IP
        if let Ok(mut s) = stack::stack().lock() {
            if let Some(ref mut st) = s.as_mut() {
                st.arp_cache_insert(Ipv4Address::new([10, 0, 0, 9]), MacAddress::from_octets(0xaa,0xbb,0xcc,0xdd,0xee,0xff), 200);
            }
        }

        // Advance time beyond PROBE_WAIT_SECS
        assert!(client.check_timeout(200, 1));
        // Offer should have been cleared due to conflict
        assert!(client.offered_lease.lock().unwrap().is_none());
        // Decline should have been recorded
        assert_eq!(client.last_declined_ip(), Some(Ipv4Address::new([10, 0, 0, 9])));
    }
}


