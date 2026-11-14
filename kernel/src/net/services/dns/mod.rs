// ============================================================================
// kernel/src/net/services/dns/mod.rs - サービス / DNS モジュール
// ============================================================================
//! DNS (Domain Name System) クライアント実装
//!
//! ドメイン名からIPアドレスへの解決を行うDNSリゾルバ。
//! 簡易的なキャッシュ機能付き。

use crate::net::payload::{GeneratedPacketWriter, PayloadRange};
use crate::net::runtime::NetRuntimeHandle;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;
use core::cmp::Ordering as CmpOrdering;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

/// DNSポート
mod tcp_constants;
pub use tcp_constants::*;
mod cache_ops;
mod client_impl;
mod parser;
mod parser_rdata_extra;
mod parser_records;
mod query_builder;
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

/// DNSレコードタイプ（未知タイプを保持）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    /// 既知の DNS クエリタイプ
    Known(DnsQueryType),
    /// 未知/未対応のレコードタイプ（生の `u16`）
    Unknown(u16),
}

impl DnsRecordType {
    /// `u16` からレコードタイプを構築
    pub fn from_u16(value: u16) -> Self {
        DnsQueryType::from_u16(value)
            .map(Self::Known)
            .unwrap_or(Self::Unknown(value))
    }

    /// 既知タイプかつ指定 `DnsQueryType` と一致するか
    pub fn is(self, expected: DnsQueryType) -> bool {
        matches!(self, Self::Known(kind) if kind == expected)
    }
}

/// DNSクエリクラス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQueryClass {
    /// インターネット
    IN = 1,
}

/// Class of a received resource record; classes other than IN stay distinct
/// so they never satisfy an IN query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordClass {
    Known(DnsQueryClass),
    Unknown(u16),
}

impl DnsRecordClass {
    pub fn from_u16(value: u16) -> Self {
        if value == DnsQueryClass::IN as u16 {
            Self::Known(DnsQueryClass::IN)
        } else {
            Self::Unknown(value)
        }
    }
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
}

#[derive(Debug)]
pub struct DnsNameView {
    labels: Vec<PayloadRange>,
    text_len: usize,
}

impl DnsNameView {
    pub fn from_parsed_labels(labels: Vec<PayloadRange>, text_len: usize) -> Self {
        Self { labels, text_len }
    }

    pub fn labels(&self) -> &[PayloadRange] {
        &self.labels
    }

    pub fn text_len(&self) -> usize {
        self.text_len
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsNameError {
    EmptyName,
    EmptyLabel,
    LabelTooLong,
    NonAsciiLabel,
    AllocationFailed,
}

#[derive(Debug)]
pub struct DnsNameOwned {
    payload: PacketPayload,
    labels: Vec<PayloadRange>,
}

impl DnsNameOwned {
    pub fn parse_ascii(name: &str) -> Result<Self, DnsNameError> {
        let trimmed = name.strip_suffix('.').unwrap_or(name);
        if trimmed.is_empty() {
            return Err(DnsNameError::EmptyName);
        }

        let mut payload_len = 0usize;
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(DnsNameError::EmptyLabel);
            }

            let bytes = label.as_bytes();
            if bytes.len() > 63 {
                return Err(DnsNameError::LabelTooLong);
            }
            if !bytes.is_ascii() {
                return Err(DnsNameError::NonAsciiLabel);
            }

            payload_len = payload_len.saturating_add(bytes.len());
        }

        let mut writer = GeneratedPacketWriter::new(payload_len, DEFAULT_PACKET_HEADROOM)
            .ok_or(DnsNameError::AllocationFailed)?;
        let mut label_bounds = Vec::new();
        let mut payload_offset = 0usize;
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            writer
                .write_generated_bytes(bytes)
                .ok_or(DnsNameError::AllocationFailed)?;
            label_bounds.push((payload_offset, bytes.len()));
            payload_offset = payload_offset.saturating_add(bytes.len());
        }
        let payload = writer.finish().ok_or(DnsNameError::AllocationFailed)?;
        let mut labels = Vec::new();
        for (offset, len) in label_bounds {
            labels.push(
                PayloadRange::checked(&payload, offset, len)
                    .ok_or(DnsNameError::AllocationFailed)?,
            );
        }

        Ok(Self { payload, labels })
    }

    pub fn labels(&self) -> &[PayloadRange] {
        &self.labels
    }

    pub fn payload(&self) -> &PacketPayload {
        &self.payload
    }
}

impl PartialEq for DnsNameOwned {
    fn eq(&self, other: &Self) -> bool {
        compare_dns_name_owned(self, other) == CmpOrdering::Equal
    }
}

impl Eq for DnsNameOwned {}

impl PartialOrd for DnsNameOwned {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for DnsNameOwned {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        compare_dns_name_owned(self, other)
    }
}

#[derive(Debug)]
pub struct DnsTxtView {
    spans: Vec<PayloadRange>,
    text_len: usize,
}

impl DnsTxtView {
    pub fn from_ranges(spans: Vec<PayloadRange>, text_len: usize) -> Self {
        Self { spans, text_len }
    }

    pub fn spans(&self) -> &[PayloadRange] {
        &self.spans
    }

    pub fn text_len(&self) -> usize {
        self.text_len
    }
}

/// DNSリソースレコード metadata。
#[derive(Debug)]
pub struct DnsRecordMeta {
    /// レコード名
    pub name: DnsNameView,
    /// レコードタイプ
    pub rtype: DnsRecordType,
    /// レコードクラス
    pub rclass: DnsRecordClass,
    /// TTL (秒)
    pub ttl: u32,
    /// レコードデータ
    pub data: DnsRecordData,
}

/// SRV resolve API の出力型。
#[derive(Debug)]
pub struct DnsSrvRecord {
    /// 優先度
    pub priority: u16,
    /// ウェイト
    pub weight: u16,
    /// ポート
    pub port: u16,
    /// ターゲット
    pub target: String,
}

/// MX resolve API の出力型。
#[derive(Debug)]
pub struct DnsMxRecord {
    /// 優先度（小さいほど優先）
    pub preference: u16,
    /// 交換サーバー名
    pub exchange: String,
}

/// DNS 応答 view。
#[derive(Debug)]
pub struct DnsResponseView {
    /// 応答 payload ownership
    pub payload: PacketPayload,
    /// packet-backed レコード metadata
    pub records: Vec<DnsRecordMeta>,
}

/// DNSレコードデータ
#[derive(Debug)]
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
    /// 未対応タイプ、または RDATA が不正なレコード
    Raw,
}

/// Validated, ASCII-lowercased DNS name without a trailing dot.
///
/// It owns plain bytes instead of a packet-backed name so that long-lived
/// holders (the answer cache, the search list) never pin packet pool slots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnsNormalizedName(String);

impl DnsNormalizedName {
    /// Validates `text` with the same label rules as [`DnsNameOwned`].
    pub fn parse_ascii(text: &str) -> Option<Self> {
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        if trimmed.is_empty() || trimmed.len() > 253 {
            return None;
        }
        let valid = trimmed.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| byte.is_ascii_graphic())
        });
        if !valid {
            return None;
        }
        let mut name = String::new();
        name.try_reserve_exact(trimmed.len()).ok()?;
        name.extend(trimmed.chars().map(|ch| ch.to_ascii_lowercase()));
        Some(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds the normalized form of a validated packet-backed name.
    pub fn from_name(name: &DnsNameOwned) -> Option<Self> {
        Self::from_labels(name.payload(), name.labels())
    }

    /// Builds the normalized form of labels held in `payload`.
    pub fn from_labels(payload: &PacketPayload, labels: &[PayloadRange]) -> Option<Self> {
        let mut key = String::new();
        for (index, label) in labels.iter().enumerate() {
            let span = label.span(payload)?;
            key.try_reserve(span.total_len() + 1).ok()?;
            if index > 0 {
                key.push('.');
            }
            for byte_index in 0..span.total_len() {
                key.push(char::from(span.byte_at(byte_index)?.to_ascii_lowercase()));
            }
        }
        (!key.is_empty()).then_some(Self(key))
    }
}

/// Cached answer for one name and one address family.
#[derive(Debug)]
pub enum DnsCachedAnswer<A> {
    /// The server returned these addresses.
    Positive(Vec<A>),
    /// NXDOMAIN, or NODATA for this family (RFC 2308 Sections 2.1 and 2.2).
    Negative,
}

#[derive(Debug)]
struct DnsCacheEntry<A> {
    answer: DnsCachedAnswer<A>,
    expires_at_tick: u64,
}

/// TTL-bounded cache of decoded DNS address answers.
///
/// Admission evicts expired entries first and then the entry closest to
/// expiry, so the cache never exceeds [`DnsCache::MAX_ENTRIES`].
pub struct DnsCache<A> {
    entries: BTreeMap<DnsNormalizedName, DnsCacheEntry<A>>,
    tick_rate: u64,
}

impl<A: Copy> DnsCache<A> {
    /// Maximum number of cached names per address family.
    pub const MAX_ENTRIES: usize = 256;

    pub const fn new(tick_rate: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            tick_rate,
        }
    }

    /// Returns the live answer for `key`, if any.
    pub fn lookup(
        &self,
        key: &DnsNormalizedName,
        current_tick: u64,
    ) -> Option<&DnsCachedAnswer<A>> {
        self.entries
            .get(key)
            .filter(|entry| entry.expires_at_tick > current_tick)
            .map(|entry| &entry.answer)
    }

    /// Stores `answer` for `ttl_secs`. A zero TTL is not cached (RFC 1035
    /// Section 3.2.1).
    pub fn insert(
        &mut self,
        key: DnsNormalizedName,
        answer: DnsCachedAnswer<A>,
        ttl_secs: u32,
        current_tick: u64,
    ) {
        if ttl_secs == 0 {
            self.entries.remove(&key);
            return;
        }
        let expires_at_tick =
            current_tick.saturating_add(u64::from(ttl_secs).saturating_mul(self.tick_rate));
        if !self.entries.contains_key(&key) && self.entries.len() >= Self::MAX_ENTRIES {
            self.cleanup(current_tick);
            if self.entries.len() >= Self::MAX_ENTRIES {
                let soonest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at_tick)
                    .map(|(key, _)| key.clone());
                if let Some(soonest) = soonest {
                    self.entries.remove(&soonest);
                }
            }
        }
        self.entries.insert(
            key,
            DnsCacheEntry {
                answer,
                expires_at_tick,
            },
        );
    }

    /// Removes expired entries.
    pub fn cleanup(&mut self, current_tick: u64) {
        self.entries
            .retain(|_, entry| entry.expires_at_tick > current_tick);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn compare_dns_label_ranges(
    lhs_payload: &PacketPayload,
    lhs: PayloadRange,
    rhs_payload: &PacketPayload,
    rhs: PayloadRange,
) -> CmpOrdering {
    let Some(left) = lhs.span(lhs_payload) else {
        return CmpOrdering::Less;
    };
    let Some(right) = rhs.span(rhs_payload) else {
        return CmpOrdering::Greater;
    };
    let shared = left.total_len().min(right.total_len());
    for byte_index in 0..shared {
        let Some(left_byte) = left
            .byte_at(byte_index)
            .map(|byte| byte.to_ascii_lowercase())
        else {
            return CmpOrdering::Less;
        };
        let Some(right_byte) = right
            .byte_at(byte_index)
            .map(|byte| byte.to_ascii_lowercase())
        else {
            return CmpOrdering::Greater;
        };
        match left_byte.cmp(&right_byte) {
            CmpOrdering::Equal => {}
            ordering => return ordering,
        }
    }
    left.total_len().cmp(&right.total_len())
}

fn compare_dns_name_ranges(
    lhs_payload: &PacketPayload,
    lhs: &[PayloadRange],
    rhs_payload: &PacketPayload,
    rhs: &[PayloadRange],
) -> CmpOrdering {
    let mut index = 0usize;
    // LOOP_PROOF: mode=bounded; reason=Every equal label pair increments index through the two finite DNS label arrays, and the first differing label returns.;
    while index < lhs.len() && index < rhs.len() {
        match compare_dns_label_ranges(lhs_payload, lhs[index], rhs_payload, rhs[index]) {
            CmpOrdering::Equal => {}
            ordering => return ordering,
        }
        index += 1;
    }
    lhs.len().cmp(&rhs.len())
}

pub(crate) fn compare_dns_name_owned(lhs: &DnsNameOwned, rhs: &DnsNameOwned) -> CmpOrdering {
    compare_dns_name_ranges(lhs.payload(), lhs.labels(), rhs.payload(), rhs.labels())
}

pub(crate) fn compare_dns_name_view_to_owned(
    view_payload: &PacketPayload,
    view: &DnsNameView,
    owned: &DnsNameOwned,
) -> CmpOrdering {
    compare_dns_name_ranges(view_payload, view.labels(), owned.payload(), owned.labels())
}

/// DNSクライアント
pub struct DnsClient {
    /// Runtime that owns this DNS client.
    runtime: NetRuntimeHandle,
    /// IPv4 DNSサーバーアドレス
    ipv4_servers: PoisonLock<Vec<Ipv4Address>>,
    /// IPv6 DNSサーバーアドレス
    ipv6_servers: PoisonLock<Vec<Ipv6Address>>,
    /// A レコードキャッシュ
    ipv4_cache: PoisonLock<DnsCache<Ipv4Address>>,
    /// AAAA レコードキャッシュ
    ipv6_cache: PoisonLock<DnsCache<Ipv6Address>>,
    /// 単一ラベル名に付加する検索ドメイン (RFC 1536 Section 6)
    search_domains: PoisonLock<Vec<DnsNormalizedName>>,
    /// 統計情報
    stats: DnsStats,
    /// 保留中クエリのトランザクションIDセット (Security: RFC 5452 - キャッシュポイズニング防止)
    pending_ids: PoisonLock<BTreeMap<u16, u64>>,
}

/// DNSサーバーアドレス（IPv4 / IPv6）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsServerAddr {
    /// IPv4 DNS サーバー
    V4(Ipv4Address),
    /// IPv6 DNS サーバー
    V6(Ipv6Address),
}

/// DNS応答あたりの最大回答数 (DoS防止)
const DNS_MAX_ANSWER_COUNT: usize = 256;
/// サーバー設定の最大件数
pub const DNS_MAX_SERVERS: usize = 3;
/// 検索ドメインの最大件数
pub const DNS_MAX_SEARCH_DOMAINS: usize = 6;
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
    shared_client: PoisonLock<Option<&'static DnsClient>>,
}

impl DnsRuntimeState {
    pub const fn new() -> Self {
        Self {
            shared_client: PoisonLock::new(None),
        }
    }
}

pub(crate) fn runtime_state_in(runtime: NetRuntimeHandle) -> &'static DnsRuntimeState {
    &runtime.context().dns
}

pub(crate) fn shared_client_lock_in(
    runtime: NetRuntimeHandle,
) -> &'static PoisonLock<Option<&'static DnsClient>> {
    &runtime_state_in(runtime).shared_client
}

pub(crate) fn shared_client_in(runtime: NetRuntimeHandle) -> Option<&'static DnsClient> {
    shared_client_lock_in(runtime)
        .lock()
        .ok()
        .and_then(|guard| *guard)
}
