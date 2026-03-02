// ============================================================================
// kernel/src/net/dns.rs
// ============================================================================
//! DNS (Domain Name System) クライアント実装
//!
//! ドメイン名からIPアドレスへの解決を行うDNSリゾルバ。
//! 簡易的なキャッシュ機能付き。


use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;

/// DNSポート
mod tcp_constants;
pub use tcp_constants::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
mod client_impl;
pub const DNS_PORT: u16 = 53;

/// DNSクエリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQueryType {
    /// IPv4アドレス
    A = 1,
    /// ネームサーバー
    NS = 2,
    /// 正規名
    CNAME = 5,
    /// ドメイン認証
    SOA = 6,
    /// ポインター (逆引き)
    PTR = 12,
    /// メール交換
    MX = 15,
    /// テキストレコード
    TXT = 16,
    /// IPv6アドレス
    AAAA = 28,
    /// サービスロケーション (RFC 2782)
    SRV = 33,
    /// EDNS0 オプション (RFC 6891)
    OPT = 41,
    /// 全タイプ
    ALL = 255,
}

impl DnsQueryType {
    /// u16から変換
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::A),
            2 => Some(Self::NS),
            5 => Some(Self::CNAME),
            6 => Some(Self::SOA),
            12 => Some(Self::PTR),
            15 => Some(Self::MX),
            16 => Some(Self::TXT),
            28 => Some(Self::AAAA),
            33 => Some(Self::SRV),
            41 => Some(Self::OPT),
            255 => Some(Self::ALL),
            _ => None,
        }
    }
}

/// DNSクエリクラス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQueryClass {
    /// インターネット
    IN = 1,
}

/// DNS応答コード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsResponseCode {
    /// 成功
    NoError = 0,
    /// フォーマットエラー
    FormatError = 1,
    /// サーバー障害
    ServerFailure = 2,
    /// 名前が存在しない
    NameError = 3,
    /// 未実装
    NotImplemented = 4,
    /// 拒否
    Refused = 5,
}

impl DnsResponseCode {
    /// u8から変換
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            _ => Self::ServerFailure,
        }
    }
}

/// DNSヘッダ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DnsHeader {
    /// トランザクションID
    pub id: [u8; 2],
    /// フラグ
    pub flags: [u8; 2],
    /// 質問数
    pub qdcount: [u8; 2],
    /// 回答数
    pub ancount: [u8; 2],
    /// 権威サーバー数
    pub nscount: [u8; 2],
    /// 追加レコード数
    pub arcount: [u8; 2],
}

impl DnsHeader {
    /// ヘッダサイズ
    pub const SIZE: usize = 12;

    /// トランザクションIDを取得
    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.id)
    }

    /// フラグを取得
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes(self.flags)
    }

    /// QRビット (応答かどうか)
    pub fn is_response(&self) -> bool {
        (self.flags() >> 15) & 1 == 1
    }

    /// 応答コードを取得
    pub fn rcode(&self) -> DnsResponseCode {
        DnsResponseCode::from_u8((self.flags() & 0x0F) as u8)
    }

    /// TC (Truncated) ビットを取得
    /// 応答が512バイトを超えてUDPで切り捨てられた場合にtrue
    pub fn is_truncated(&self) -> bool {
        (self.flags() >> 9) & 1 == 1
    }

    /// RD (Recursion Desired) ビットを取得
    pub fn recursion_desired(&self) -> bool {
        (self.flags() >> 8) & 1 == 1
    }

    /// RA (Recursion Available) ビットを取得
    pub fn recursion_available(&self) -> bool {
        (self.flags() >> 7) & 1 == 1
    }

    /// 質問数を取得
    pub fn question_count(&self) -> u16 {
        u16::from_be_bytes(self.qdcount)
    }

    /// 回答数を取得
    pub fn answer_count(&self) -> u16 {
        u16::from_be_bytes(self.ancount)
    }
}

/// DNSリソースレコード (解析済み)
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// レコード名
    pub name: String,
    /// レコードタイプ
    pub rtype: DnsQueryType,
    /// レコードクラス
    pub rclass: DnsQueryClass,
    /// TTL (秒)
    pub ttl: u32,
    /// レコードデータ
    pub data: DnsRecordData,
}

/// DNSレコードデータ
#[derive(Debug, Clone)]
pub enum DnsRecordData {
    /// IPv4アドレス (Aレコード)
    A(Ipv4Address),
    /// IPv6アドレス (AAAAレコード)
    AAAA(Ipv6Address),
    /// ドメイン名 (CNAME, NS, PTRなど)
    Name(String),
    /// MXレコード (優先度, ドメイン名)
    MX(u16, String),
    /// TXTレコード
    TXT(String),
    /// SRVレコード (優先度, ウェイト, ポート, ターゲット)
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// その他/未解析
    Raw(Vec<u8>),
}

/// DNSキャッシュエントリ
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// レコード
    pub records: Vec<DnsRecord>,
    /// キャッシュ時刻 (tick)
    pub cached_at: u64,
    /// 最小TTL
    pub min_ttl: u32,
}

impl DnsCacheEntry {
    /// 期限切れか判定
    pub fn is_expired(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.cached_at)) / tick_rate;
        elapsed_secs > self.min_ttl as u64
    }
}

/// DNSキャッシュ
pub struct DnsCache {
    /// キャッシュエントリ (ドメイン名 → エントリ)
    entries: BTreeMap<String, DnsCacheEntry>,
    /// 最大エントリ数
    max_entries: usize,
    /// ティックレート
    tick_rate: u64,
}

impl DnsCache {
    /// デフォルトの最大エントリ数
    pub const DEFAULT_MAX_ENTRIES: usize = 256;

    /// 新しいDNSキャッシュを作成
    pub const fn new(tick_rate: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            tick_rate,
        }
    }

    /// キャッシュを検索
    pub fn lookup(&self, name: &str, current_tick: u64) -> Option<&DnsCacheEntry> {
        self.entries
            .get(name)
            .filter(|entry| !entry.is_expired(current_tick, self.tick_rate))
    }

    /// キャッシュにエントリを追加
    pub fn insert(&mut self, name: String, records: Vec<DnsRecord>, current_tick: u64) {
        // 最小TTLを計算
        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300); // デフォルト5分

        // テーブルが満杯の場合、古いエントリを削除
        if self.entries.len() >= self.max_entries {
            self.cleanup(current_tick);
            
            // それでも満杯の場合は、DoS攻撃を防ぐために最も古いエントリを強制削除
            if self.entries.len() >= self.max_entries {
                if let Some(oldest_key) = self.entries.iter()
                    .min_by_key(|(_, entry)| entry.cached_at)
                    .map(|(k, _)| k.clone()) 
                {
                    self.entries.remove(&oldest_key);
                }
            }
        }

        self.entries.insert(
            name,
            DnsCacheEntry {
                records,
                cached_at: current_tick,
                min_ttl,
            },
        );
    }

    /// 期限切れエントリをクリーンアップ
    pub fn cleanup(&mut self, current_tick: u64) {
        self.entries
            .retain(|_, entry| !entry.is_expired(current_tick, self.tick_rate));
    }

    /// エントリを削除
    pub fn remove(&mut self, name: &str) {
        self.entries.remove(name);
    }

    /// キャッシュをクリア
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// DNSクライアント
pub struct DnsClient {
    /// IPv4 DNSサーバーアドレス
    ipv4_servers: PoisonLock<Vec<Ipv4Address>>,
    /// IPv6 DNSサーバーアドレス
    ipv6_servers: PoisonLock<Vec<Ipv6Address>>,
    /// DNSキャッシュ
    cache: PoisonLock<DnsCache>,
    /// 統計情報
    stats: DnsStats,
    /// 保留中クエリのトランザクションIDセット (Security: RFC 5452 - キャッシュポイズニング防止)
    pending_ids: PoisonLock<BTreeMap<u16, u64>>,
}

/// DNS応答あたりの最大回答数 (DoS防止)
const DNS_MAX_ANSWER_COUNT: usize = 256;

/// DNS retry configuration
pub const DNS_MAX_RETRIES: u8 = 3;
/// DNS retry timeout (2 seconds in milliseconds)
pub const DNS_RETRY_TIMEOUT_MS: u64 = 2000;

/// DNS統計情報
pub struct DnsStats {
    /// クエリ送信数
    pub queries_sent: AtomicU64,
    /// 応答受信数
    pub responses_received: AtomicU64,
    /// キャッシュヒット数
    pub cache_hits: AtomicU64,
    /// キャッシュミス数
    pub cache_misses: AtomicU64,
    /// エラー数
    pub errors: AtomicU64,
}

impl DnsStats {
    /// 新しい統計情報を作成
    pub const fn new() -> Self {
        Self {
            queries_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Global Instance
// ============================================================================

pub static DNS_CLIENT: PoisonLock<Option<DnsClient>> = PoisonLock::new(None);

/// DNSクライアントを初期化
pub fn init(tick_rate: u64) {
    let client = DnsClient::new(tick_rate);
    if let Ok(mut guard) = DNS_CLIENT.lock() {
        *guard = Some(client);
    }
}

/// DNSクライアントを取得
pub fn client() -> &'static PoisonLock<Option<DnsClient>> {
    &DNS_CLIENT
}

/// DNSキャッシュをクリーンアップ (periodic maintenance)
pub fn cleanup_cache(current_tick: u64) {
    if let Ok(guard) = DNS_CLIENT.lock() {
        if let Some(ref client) = *guard {
            if let Ok(mut cache) = client.cache.lock() {
                cache.cleanup(current_tick);
            }
        }
    }
}
