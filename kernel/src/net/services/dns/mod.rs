// ============================================================================
// kernel/src/net/services/dns/mod.rs - サービス / DNS モジュール
// ============================================================================
//! DNS (Domain Name System) クライアント実装
//!
//! ドメイン名からIPアドレスへの解決を行うDNSリゾルバ。
//! 簡易的なキャッシュ機能付き。

use crate::net::payload::{GeneratedPacketWriter, PayloadRange, PayloadSpanRef};
use crate::net::runtime::context::default_runtime_context;
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

    /// 生の type 値を取得
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Known(kind) => kind as u16,
            Self::Unknown(value) => value,
        }
    }

    /// 既知タイプかつ指定 `DnsQueryType` と一致するか
    pub fn is(self, expected: DnsQueryType) -> bool {
        matches!(self, Self::Known(kind) if kind == expected)
    }

    /// 既知タイプなら `DnsQueryType` を返す
    pub fn as_known(self) -> Option<DnsQueryType> {
        match self {
            Self::Known(kind) => Some(kind),
            Self::Unknown(_) => None,
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

#[derive(Debug)]
pub struct DnsNameView {
    labels: Vec<PayloadRange>,
    text_len: usize,
}

impl DnsNameView {
    pub fn from_parsed_labels(labels: Vec<PayloadRange>, text_len: usize) -> Self {
        Self { labels, text_len }
    }

    pub fn eq_ignore_ascii_case_in(&self, payload: &PacketPayload, name: &str) -> bool {
        let mut parts = name.split('.');
        for label in &self.labels {
            let Some(part) = parts.next() else {
                return false;
            };
            let Some(span) = label.span(payload) else {
                return false;
            };
            if !span.eq_ignore_ascii_case(part.as_bytes()) {
                return false;
            }
        }
        parts.next().is_none()
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
    text_len: usize,
}

impl DnsNameOwned {
    pub(crate) fn from_payload_labels(
        payload: PacketPayload,
        labels: Vec<PayloadRange>,
        text_len: usize,
    ) -> Self {
        Self {
            payload,
            labels,
            text_len,
        }
    }

    pub fn parse_ascii(name: &str) -> Result<Self, DnsNameError> {
        let trimmed = name.strip_suffix('.').unwrap_or(name);
        if trimmed.is_empty() {
            return Err(DnsNameError::EmptyName);
        }

        let mut payload_len = 0usize;
        let mut text_len = 0usize;
        for (index, label) in trimmed.split('.').enumerate() {
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
            text_len = text_len.saturating_add(bytes.len());
            if index > 0 {
                text_len = text_len.saturating_add(1);
            }
        }

        let mut writer = GeneratedPacketWriter::new(payload_len, DEFAULT_PACKET_HEADROOM)
            .ok_or(DnsNameError::AllocationFailed)?;
        let mut labels = Vec::new();
        let mut payload_offset = 0usize;
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            writer
                .write_bytes(bytes)
                .ok_or(DnsNameError::AllocationFailed)?;
            labels.push(PayloadRange::new(payload_offset, bytes.len()));
            payload_offset = payload_offset.saturating_add(bytes.len());
        }

        Ok(Self::from_payload_labels(
            writer.finish().ok_or(DnsNameError::AllocationFailed)?,
            labels,
            text_len,
        ))
    }

    pub fn labels(&self) -> &[PayloadRange] {
        &self.labels
    }

    pub fn payload(&self) -> &PacketPayload {
        &self.payload
    }

    pub fn label_span(&self, index: usize) -> Option<PayloadSpanRef<'_>> {
        self.labels.get(index)?.span(&self.payload)
    }

    pub fn label_eq_ignore_ascii_case(&self, index: usize, bytes: &[u8]) -> bool {
        self.label_span(index)
            .map(|span| span.eq_ignore_ascii_case(bytes))
            .unwrap_or(false)
    }

    pub fn text_len(&self) -> usize {
        self.text_len
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
    pub rclass: DnsQueryClass,
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
    /// その他/未解析
    Raw(PayloadRange),
}

/// DNSキャッシュエントリ
#[derive(Debug)]
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
    entries: BTreeMap<DnsNameOwned, DnsCacheEntry>,
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
    pub fn lookup(&self, name: &DnsNameOwned, current_tick: u64) -> Option<&DnsCacheEntry> {
        self.entries
            .get(name)
            .filter(|entry| !entry.is_expired(current_tick, self.tick_rate))
    }

    pub fn lookup_view(
        &self,
        payload: &PacketPayload,
        name: &DnsNameView,
        current_tick: u64,
    ) -> Option<&DnsCacheEntry> {
        self.entries.iter().find_map(|(key, entry)| {
            (compare_dns_name_view_to_owned(payload, name, key) == CmpOrdering::Equal
                && !entry.is_expired(current_tick, self.tick_rate))
            .then_some(entry)
        })
    }

    /// キャッシュにエントリを追加
    pub fn insert(
        &mut self,
        name: DnsNameOwned,
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
                let mut dropped_oldest = false;
                let old_entries = core::mem::take(&mut self.entries);
                let oldest_tick = old_entries.values().map(|entry| entry.cached_at).min();
                for (entry_key, entry_value) in old_entries {
                    if !dropped_oldest && Some(entry_value.cached_at) == oldest_tick {
                        dropped_oldest = true;
                        continue;
                    }
                    self.entries.insert(entry_key, entry_value);
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
        name: DnsNameOwned,
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
    pub fn remove(&mut self, name: &DnsNameOwned) {
        self.entries.remove(name);
    }

    /// キャッシュをクリア
    pub fn clear(&mut self) {
        self.entries.clear();
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

pub(crate) fn runtime_state() -> &'static DnsRuntimeState {
    &default_runtime_context().dns
}

pub(crate) fn shared_client_lock() -> &'static PoisonLock<Option<&'static DnsClient>> {
    &runtime_state().shared_client
}

pub(crate) fn shared_client() -> Option<&'static DnsClient> {
    shared_client_lock().lock().ok().and_then(|guard| *guard)
}
