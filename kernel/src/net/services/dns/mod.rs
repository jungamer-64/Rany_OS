// ============================================================================
// kernel/src/net/services/dns/mod.rs
// ============================================================================
//! DNS (Domain Name System) クライアント実装
//!
//! ドメイン名からIPアドレスへの解決を行うDNSリゾルバ。
//! 簡易的なキャッシュ機能付き。

use crate::net::payload::PayloadSpan;
use crate::net::runtime::context::default_runtime_context;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;
use kernel_api::resource::net::PacketPayload;

/// DNSポート
mod tcp_constants;
pub use tcp_constants::*;
mod cache_ops;
mod client_impl;
mod parser;
mod parser_rdata_extra;
mod parser_records;
mod query_builder;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
mod transport;
mod transport_tcp;
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

#[derive(Debug, Clone)]
pub struct DnsNameView {
    labels: Vec<PayloadSpan>,
    text_len: usize,
}

impl DnsNameView {
    pub fn from_labels(labels: Vec<PayloadSpan>) -> Self {
        let text_len = labels
            .iter()
            .map(PayloadSpan::total_len)
            .sum::<usize>()
            .saturating_add(labels.len().saturating_sub(1));
        Self { labels, text_len }
    }

    pub fn eq_ignore_ascii_case(&self, name: &str) -> bool {
        let mut parts = name.split('.');
        for label in &self.labels {
            let Some(part) = parts.next() else {
                return false;
            };
            if !label.eq_ignore_ascii_case(part.as_bytes()) {
                return false;
            }
        }
        parts.next().is_none()
    }

    pub fn to_owned_string(&self) -> String {
        let mut out = String::with_capacity(self.text_len);
        for (index, label) in self.labels.iter().enumerate() {
            if index > 0 {
                out.push('.');
            }
            if let Some(slice) = label.as_contiguous_slice() {
                out.push_str(&String::from_utf8_lossy(slice));
            } else {
                let mut bytes = vec![0u8; label.total_len()];
                let copied = label.copy_into(&mut bytes);
                bytes.truncate(copied);
                out.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        out
    }

    pub fn to_lowercase_string(&self) -> String {
        self.to_owned_string().to_ascii_lowercase()
    }
}

#[derive(Debug, Clone)]
pub struct DnsTxtView {
    spans: Vec<PayloadSpan>,
    text_len: usize,
}

impl DnsTxtView {
    pub fn from_spans(spans: Vec<PayloadSpan>) -> Self {
        let text_len = spans.iter().map(PayloadSpan::total_len).sum();
        Self { spans, text_len }
    }

    pub fn to_owned_string(&self) -> String {
        let mut out = String::with_capacity(self.text_len);
        for span in &self.spans {
            if let Some(slice) = span.as_contiguous_slice() {
                out.push_str(&String::from_utf8_lossy(slice));
            } else {
                let mut bytes = vec![0u8; span.total_len()];
                let copied = span.copy_into(&mut bytes);
                bytes.truncate(copied);
                out.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        out
    }
}

/// DNSリソースレコード metadata。
#[derive(Debug, Clone)]
pub struct DnsRecordMeta {
    /// レコード名
    pub name: DnsNameView,
    /// レコードタイプ
    pub rtype: DnsQueryType,
    /// レコードクラス
    pub rclass: DnsQueryClass,
    /// TTL (秒)
    pub ttl: u32,
    /// レコードデータ
    pub data: DnsRecordData,
}

/// DNS 応答 view。
#[derive(Debug, Clone)]
pub struct DnsResponseView {
    /// 応答 payload ownership
    pub payload: PacketPayload,
    /// packet-backed レコード metadata
    pub records: Vec<DnsRecordMeta>,
}

/// DNSレコードデータ
#[derive(Debug, Clone)]
pub enum DnsRecordData {
    /// IPv4アドレス (Aレコード)
    A(Ipv4Address),
    /// IPv6アドレス (AAAAレコード)
    AAAA(Ipv6Address),
    /// ドメイン名 (CNAME, NS, PTRなど)
    Name(DnsNameView),
    /// MXレコード (優先度, ドメイン名)
    MX(u16, DnsNameView),
    /// TXTレコード
    TXT(DnsTxtView),
    /// SRVレコード (優先度, ウェイト, ポート, ターゲット)
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsNameView,
    },
    /// その他/未解析
    Raw(PayloadSpan),
}

/// DNSキャッシュエントリ
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// 応答 payload ownership
    pub response: PacketPayload,
    /// packet-backed レコード metadata
    pub records: Vec<DnsRecordMeta>,
    /// キャッシュ時刻 (tick)
    pub cached_at: u64,
    /// 最小TTL
    pub min_ttl: u32,
    /// ネガティブキャッシュか
    pub negative: bool,
    /// ネガティブ時の応答コード
    pub rcode: Option<DnsResponseCode>,
}

impl DnsCacheEntry {
    /// 期限切れか判定
    pub fn is_expired(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.cached_at)) / tick_rate;
        elapsed_secs >= self.min_ttl as u64
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
    pub fn insert(
        &mut self,
        name: String,
        response: PacketPayload,
        records: Vec<DnsRecordMeta>,
        current_tick: u64,
    ) {
        // 最小TTLを計算
        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300); // デフォルト5分

        // テーブルが満杯の場合、古いエントリを削除
        if self.entries.len() >= self.max_entries {
            self.cleanup(current_tick);

            // それでも満杯の場合は、DoS攻撃を防ぐために最も古いエントリを強制削除
            if self.entries.len() >= self.max_entries {
                if let Some(oldest_key) = self
                    .entries
                    .iter()
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
                response,
                records,
                cached_at: current_tick,
                min_ttl,
                negative: false,
                rcode: None,
            },
        );
    }

    /// ネガティブキャッシュを追加
    pub fn insert_negative(
        &mut self,
        name: String,
        rcode: DnsResponseCode,
        current_tick: u64,
        ttl_secs: u32,
    ) {
        self.entries.insert(
            name,
            DnsCacheEntry {
                response: PacketPayload::default(),
                records: Vec::new(),
                cached_at: current_tick,
                min_ttl: ttl_secs,
                negative: true,
                rcode: Some(rcode),
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
/// サーバー設定の最大件数
pub const DNS_MAX_SERVERS: usize = 3;
/// CNAME チェーン追跡の上限
pub const DNS_MAX_CNAME_DEPTH: usize = 8;
/// ネガティブキャッシュTTL（秒）
pub const DNS_NEGATIVE_CACHE_TTL_SECS: u32 = 30;
/// pending transaction ID の寿命（tick）
pub const DNS_PENDING_ID_TTL_TICKS: u64 = 30_000;

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

pub(crate) struct DnsRuntimeState {
    shared_client: PoisonLock<Option<Arc<DnsClient>>>,
}

impl DnsRuntimeState {
    pub const fn new() -> Self {
        Self {
            shared_client: PoisonLock::new(None),
        }
    }
}

pub(crate) fn runtime_state() -> &'static DnsRuntimeState {
    &default_runtime_context().dns
}

pub(crate) fn shared_client_lock() -> &'static PoisonLock<Option<Arc<DnsClient>>> {
    &runtime_state().shared_client
}

pub(crate) fn cloned_client() -> Option<Arc<DnsClient>> {
    shared_client_lock()
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}
