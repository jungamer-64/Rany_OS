//! DHCP (Dynamic Host Configuration Protocol) クライアント実装
//!
//! DHCPを使用してIPアドレス、サブネットマスク、ゲートウェイ、
//! DNSサーバーなどのネットワーク設定を自動取得する。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::ethernet::MacAddress;
use super::ipv4::Ipv4Address;
use super::udp::{UdpAddr, UdpSocket};

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

    /// 更新が必要か判定 (リース時間の50%経過)
    pub fn needs_renewal(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs > (self.lease_time / 2) as u64
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
    state: Mutex<DhcpState>,
    /// 現在のトランザクションID
    xid: AtomicU32,
    /// 現在のリース
    lease: Mutex<Option<DhcpLease>>,
    /// 提案されたリース (OFFER受信後)
    offered_lease: Mutex<Option<DhcpLease>>,
    /// 状態遷移時刻
    state_time: AtomicU64,
    /// 再試行回数
    retry_count: AtomicU32,
}

impl DhcpClient {
    /// 最大再試行回数
    pub const MAX_RETRIES: u32 = 4;

    /// 新しいDHCPクライアントを作成
    pub fn new(mac_address: MacAddress) -> Self {
        Self {
            mac_address,
            state: Mutex::new(DhcpState::Init),
            xid: AtomicU32::new(0),
            lease: Mutex::new(None),
            offered_lease: Mutex::new(None),
            state_time: AtomicU64::new(0),
            retry_count: AtomicU32::new(0),
        }
    }

    /// 現在の状態を取得
    pub fn state(&self) -> DhcpState {
        *self.state.lock()
    }

    /// 現在のリースを取得
    pub fn lease(&self) -> Option<DhcpLease> {
        self.lease.lock().clone()
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

        // 新しいトランザクションIDを生成
        let xid = (current_tick as u32) ^ 0xDEADBEEF;
        self.xid.store(xid, Ordering::SeqCst);

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

        // パラメータ要求リスト
        buffer[offset] = DhcpOption::ParameterRequestList as u8;
        buffer[offset + 1] = 4;
        buffer[offset + 2] = DhcpOption::SubnetMask as u8;
        buffer[offset + 3] = DhcpOption::Router as u8;
        buffer[offset + 4] = DhcpOption::DnsServer as u8;
        buffer[offset + 5] = DhcpOption::DomainName as u8;
        offset += 6;

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
        *self.state.lock() = DhcpState::Selecting;
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

        let offered = self.offered_lease.lock();
        let lease = offered.as_ref().ok_or("No offer available")?;

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
        // ciaddr = 0 (新規リクエスト時)
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

        // パラメータ要求リスト
        buffer[offset] = DhcpOption::ParameterRequestList as u8;
        buffer[offset + 1] = 4;
        buffer[offset + 2] = DhcpOption::SubnetMask as u8;
        buffer[offset + 3] = DhcpOption::Router as u8;
        buffer[offset + 4] = DhcpOption::DnsServer as u8;
        buffer[offset + 5] = DhcpOption::DomainName as u8;
        offset += 6;

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
        *self.state.lock() = DhcpState::Requesting;
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
        let header = unsafe { &*(data.as_ptr() as *const DhcpHeader) };

        // トランザクションIDを確認
        if header.xid() != self.xid.load(Ordering::SeqCst) {
            return Err("Transaction ID mismatch");
        }

        // オペレーションを確認
        if header.op != DhcpOperation::Reply as u8 {
            return Err("Not a DHCP reply");
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
            let opt_data = &data[offset + 2..offset + 2 + len.min(data.len() - offset - 2)];

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

        match msg_type {
            DhcpMessageType::Offer => {
                let lease = DhcpLease {
                    ip_address: header.yiaddr(),
                    subnet_mask: subnet_mask.unwrap_or(Ipv4Address::new([255, 255, 255, 0])),
                    gateway: router,
                    dns_servers,
                    server_ip: server_id.unwrap_or(header.siaddr()),
                    lease_time,
                    obtained_at: current_tick,
                    hostname,
                    domain_name,
                };

                *self.offered_lease.lock() = Some(lease.clone());

                Ok(DhcpResponseResult::Offer(lease))
            }
            DhcpMessageType::Ack => {
                let lease = DhcpLease {
                    ip_address: header.yiaddr(),
                    subnet_mask: subnet_mask.unwrap_or(Ipv4Address::new([255, 255, 255, 0])),
                    gateway: router,
                    dns_servers,
                    server_ip: server_id.unwrap_or(header.siaddr()),
                    lease_time,
                    obtained_at: current_tick,
                    hostname,
                    domain_name,
                };

                *self.lease.lock() = Some(lease.clone());
                *self.state.lock() = DhcpState::Bound;
                self.state_time.store(current_tick, Ordering::SeqCst);
                self.retry_count.store(0, Ordering::SeqCst);

                Ok(DhcpResponseResult::Ack(lease))
            }
            DhcpMessageType::Nak => {
                *self.state.lock() = DhcpState::Init;
                *self.offered_lease.lock() = None;
                Ok(DhcpResponseResult::Nak)
            }
            _ => Err("Unexpected message type"),
        }
    }

    /// リースを解放
    pub fn release(&self) {
        *self.state.lock() = DhcpState::Init;
        *self.lease.lock() = None;
        *self.offered_lease.lock() = None;
    }

    /// タイムアウトをチェック
    pub fn check_timeout(&self, current_tick: u64, tick_rate: u64) -> bool {
        let state = *self.state.lock();
        let state_time = self.state_time.load(Ordering::SeqCst);
        let elapsed_secs = (current_tick.saturating_sub(state_time)) / tick_rate;

        match state {
            DhcpState::Selecting | DhcpState::Requesting => {
                // 4秒でタイムアウト
                if elapsed_secs > 4 {
                    let retry = self.retry_count.fetch_add(1, Ordering::SeqCst);
                    if retry >= Self::MAX_RETRIES {
                        *self.state.lock() = DhcpState::Init;
                        self.retry_count.store(0, Ordering::SeqCst);
                    }
                    return true;
                }
            }
            DhcpState::Bound => {
                if let Some(lease) = self.lease.lock().as_ref() {
                    if lease.needs_renewal(current_tick, tick_rate) {
                        *self.state.lock() = DhcpState::Renewing;
                        return true;
                    }
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
static DHCP_CLIENT: Mutex<Option<DhcpClient>> = Mutex::new(None);

/// DHCPクライアントを初期化
pub fn init(mac_address: MacAddress) {
    let client = DhcpClient::new(mac_address);
    *DHCP_CLIENT.lock() = Some(client);
}

/// DHCPクライアントを取得
pub fn client() -> Option<&'static Mutex<Option<DhcpClient>>> {
    Some(&DHCP_CLIENT)
}
