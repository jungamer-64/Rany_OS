// ============================================================================
// kernel/src/net/services/mdns/mod.rs - サービス / mDNS モジュール
// ============================================================================
//! mDNS (Multicast DNS) プロトコル実装 (RFC 6762)
//!
//! ローカルネットワーク上でDNSサーバーなしにホスト名を解決する
//! マルチキャストDNSプロトコルの実装。
//!
//! ## 機能
//! - mDNSクエリの送受信
//! - mDNS応答の送受信
//! - ホスト名キャッシュ管理
//! - DNSワイヤーフォーマットのエンコード/デコード
//! - ラベル圧縮対応の名前解析

// Building block: mDNS implementation
#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::udp::UdpAddr;
use crate::net::payload::{PacketPayloadBuilder, PacketPayloadView, PayloadRange};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::services::dns::DnsNameOwned;
use crate::sync::PoisonLock;

extern crate alloc;

// ============================================================================
// Constants
// ============================================================================

/// mDNSポート (RFC 6762)
pub const MDNS_PORT: u16 = 5353;

/// mDNSマルチキャストグループアドレス (224.0.0.251)
pub const MDNS_MULTICAST_GROUP: Ipv4Address = Ipv4Address::new([224, 0, 0, 251]);

/// mDNSレコードのデフォルトTTL (秒)
pub const MDNS_DEFAULT_TTL: u32 = 120;

/// DNSヘッダサイズ (バイト)
const DNS_HEADER_SIZE: usize = 12;

/// Aレコードタイプ
const DNS_TYPE_A: u16 = 1;

/// INクラス
const DNS_CLASS_IN: u16 = 1;

/// mDNSキャッシュフラッシュビット (クラスフィールドのビット15)
const MDNS_CACHE_FLUSH_BIT: u16 = 0x8000;

/// mDNS応答フラグ (QR=1, AA=1)
const MDNS_RESPONSE_FLAGS: u16 = 0x8400;

/// mDNSクエリフラグ (QR=0, 標準クエリ)
const MDNS_QUERY_FLAGS: u16 = 0x0000;

/// DNSラベルの最大長
const DNS_LABEL_MAX_LEN: usize = 63;

/// DNS名の最大全体長
const DNS_NAME_MAX_LEN: usize = 255;

/// DNS名前圧縮ポインターマスク
const DNS_COMPRESSION_MASK: u8 = 0xC0;

/// mDNS最大キャッシュエントリ数
const MDNS_MAX_CACHE_ENTRIES: usize = 64;

// ============================================================================
// Types and Enums
// ============================================================================

/// mDNS処理結果
#[derive(Debug)]
pub enum MdnsResult {
    /// クエリ送信が必要
    SendQuery {
        /// 解決対象のホスト名
        target_name: DnsNameOwned,
    },
    /// 応答送信が必要
    SendResponse {
        /// 応答するホスト名
        name: DnsNameOwned,
        /// ホストのIPアドレス
        ip: Ipv4Address,
        /// TTL (秒)
        ttl: u32,
    },
    /// 名前解決に成功
    Resolved {
        /// 解決されたホスト名
        name: DnsNameOwned,
        /// 解決されたIPアドレス
        ip: Ipv4Address,
    },
    /// キャッシュが更新された
    CacheUpdated,
    /// パケットを無視
    Ignored,
    /// 無効なパケット
    InvalidPacket,
}

/// mDNS送信レポート (送信待ちパケット情報)
#[derive(Debug)]
pub struct MdnsReport {
    /// 送信先ホスト名
    pub name: DnsNameOwned,
    /// IPアドレス (応答の場合)
    pub ip: Option<Ipv4Address>,
    /// TTL (応答の場合)
    pub ttl: u32,
    /// クエリかレスポンスか
    pub is_response: bool,
    /// タイムスタンプ
    pub timestamp: u64,
}

// ============================================================================
// Structs
// ============================================================================

/// mDNSキャッシュエントリ
#[derive(Debug)]
pub struct MdnsCacheEntry {
    /// 解決されたIPアドレス
    pub ip: Ipv4Address,
    /// 有効期限 (秒単位のタイムスタンプ)
    pub expiry_time: u64,
}

/// mDNSサービス
///
/// ローカルネットワーク上でホスト名の解決と公開を行う。
pub struct MdnsService {
    runtime: NetRuntimeHandle,
    /// 自ホスト名 (例: "myhost")
    hostname: String,
    /// 自ホストのIPアドレス
    local_ip: Ipv4Address,
    /// 名前解決キャッシュ (ホスト名 → キャッシュエントリ)
    cache: BTreeMap<DnsNameOwned, MdnsCacheEntry>,
    /// 送信待ちレポート
    pending_reports: Vec<MdnsReport>,
}

// ============================================================================
// MdnsService Implementation
// ============================================================================

impl MdnsService {
    /// 新しいmDNSサービスを作成
    ///
    /// # Arguments
    /// - `hostname` - 自ホスト名 (".local" 接尾辞なし)
    /// - `local_ip` - 自ホストのIPアドレス
    pub fn new_in(runtime: NetRuntimeHandle, hostname: String, local_ip: Ipv4Address) -> Self {
        Self {
            runtime,
            hostname,
            local_ip,
            cache: BTreeMap::new(),
            pending_reports: Vec::new(),
        }
    }

    /// mDNSサービスのメインループ（非同期）
    pub async fn run(&mut self) -> Result<(), &'static str> {
        log::info!(
            "[NET][boot] mDNS task entered run loop on CPU {}",
            crate::cpu::try_current_id().unwrap_or(0)
        );
        let socket = crate::net::l4::udp::UdpEndpoint::bind_in(
            self.runtime,
            crate::net::types::InterfaceScope::Any,
            MDNS_PORT,
            None,
        )
        .map_err(|_| "Failed to bind mDNS socket")?;

        if self.local_ip.is_any() {
            log::info!("[NET] mDNS: deferring multicast join until IPv4 address is assigned");
        }
        while self.local_ip.is_any() {
            crate::task::sleep_ms(100).await;
        }

        // SECURITY: RFC 6762 Section 11 に従い、mDNS packet の IP TTL は 255 でなければならない。
        socket.set_ttl(255);
        // mDNSマルチキャストグループに参加（非同期・イベントキュー経由）
        if !socket.join_multicast_group(MDNS_MULTICAST_GROUP).await {
            return Err("Failed to join mDNS multicast group");
        }

        log::info!(
            "[NET] mDNS service task started (hostname: {}.local)",
            self.hostname
        );

        loop {
            // パケット受信を待機
            if let Some((_if_id, src, ttl, packet)) = socket.recv().await {
                let now = crate::task::current_tick() / 1000;

                // SECURITY: RFC 6762 Section 11 に従い、IP TTL / Hop Limit が
                // 255 以外の Multicast DNS query を破棄する。
                let is_loopback = match src {
                    UdpAddr::V4 { ip, .. } => ip.is_loopback(),
                    UdpAddr::V6 { ip, .. } => ip.is_loopback(),
                };

                if ttl != 255 && !is_loopback {
                    log::warn!(
                        "[NET] mDNS: Ignoring packet with TTL {} (RFC 6762 Section 11 mandate)",
                        ttl
                    );
                    continue;
                }

                // 受信パケットを処理
                let src_ip = src.ip_v4().unwrap_or(Ipv4Address::ANY);
                let result = self.process_packet_payload(&packet, src_ip, ttl, now);

                match result {
                    MdnsResult::SendResponse { name, ip, ttl } => {
                        if let Some(payload) = Self::build_response_payload(&name, ip, ttl) {
                            let dst = UdpAddr::new(MDNS_MULTICAST_GROUP, MDNS_PORT);
                            let _ = socket.send(payload, dst).await;
                        }
                    }
                    _ => {}
                }

                // 保留中のレポート（クエリなど）があれば送信
                let reports = self.take_pending_reports();
                for report in reports {
                    if report.is_response {
                        if let Some(ip) = report.ip {
                            if let Some(payload) =
                                Self::build_response_payload(&report.name, ip, report.ttl)
                            {
                                let dst = UdpAddr::new(MDNS_MULTICAST_GROUP, MDNS_PORT);
                                let _ = socket.send(payload, dst).await;
                            }
                        }
                    } else {
                        if let Some(payload) = Self::build_query_payload(&report.name) {
                            let dst = UdpAddr::new(MDNS_MULTICAST_GROUP, MDNS_PORT);
                            let _ = socket.send(payload, dst).await;
                        }
                    }
                }
            }

            // 定期的なキャッシュクリーンアップ
            let now = crate::task::current_tick() / 1000;
            self.cleanup_expired(now);
        }
    }

    /// ホスト名を取得
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// ローカルIPを取得
    pub fn local_ip(&self) -> Ipv4Address {
        self.local_ip
    }

    /// ローカルIPを設定
    pub fn set_local_ip(&mut self, ip: Ipv4Address) {
        self.local_ip = ip;
    }

    /// キャッシュエントリ数を取得
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// 送信待ちレポートを取得してクリア
    pub fn take_pending_reports(&mut self) -> Vec<MdnsReport> {
        core::mem::take(&mut self.pending_reports)
    }

    fn try_process_dns_answer_view(
        &mut self,
        view: &PacketPayloadView<'_>,
        offset: &mut usize,
        current_time: u64,
    ) -> Result<bool, ()> {
        let record = match parse_dns_answer_record_view(view, *offset) {
            Some(r) => r,
            None => return Err(()),
        };
        *offset = record.3;
        if !is_inet_a_record(record.0, record.1, record.2) {
            return Ok(false);
        }
        let rdata = view.read_array::<4>(record.4).ok_or(())?;
        let ip = Ipv4Address::new(rdata);
        let name = record.5;
        Ok(self.cache_a_record_owned(name, ip, record.6, current_time))
    }

    /// Aレコードをキャッシュに追加・更新する。TTL=0のgoodbyeパケットはキャッシュ削除。
    /// 正常にキャッシュ更新された場合trueを返す。
    fn cache_a_record_owned(
        &mut self,
        name: DnsNameOwned,
        ip: Ipv4Address,
        ttl: u32,
        current_time: u64,
    ) -> bool {
        let Some(last_label_index) = name.labels().len().checked_sub(1) else {
            return false;
        };
        if !name.label_eq_ignore_ascii_case(last_label_index, b"local") {
            log::warn!("[NET] mDNS: Ignoring non-local name");
            return false;
        }

        if ttl == 0 {
            self.cache.remove(&name);
            return false;
        }

        let expiry = current_time + ttl as u64;

        if !self.cache.contains_key(&name) && self.cache.len() >= MDNS_MAX_CACHE_ENTRIES {
            self.evict_oldest();
        }

        self.cache.insert(
            name,
            MdnsCacheEntry {
                ip,
                expiry_time: expiry,
            },
        );
        true
    }

    pub fn build_query_payload(
        name: &DnsNameOwned,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        let mut builder = PacketPayloadBuilder::new();
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        builder.append_generated_bytes(&MDNS_QUERY_FLAGS.to_be_bytes())?;
        builder.append_generated_bytes(&1u16.to_be_bytes())?;
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        push_dns_name_payload(&mut builder, name)?;
        builder.append_generated_bytes(&DNS_TYPE_A.to_be_bytes())?;
        builder.append_generated_bytes(&DNS_CLASS_IN.to_be_bytes())?;
        Some(builder.build())
    }

    pub fn build_response_payload(
        name: &DnsNameOwned,
        ip: Ipv4Address,
        ttl: u32,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        let mut builder = PacketPayloadBuilder::new();
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        builder.append_generated_bytes(&MDNS_RESPONSE_FLAGS.to_be_bytes())?;
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        builder.append_generated_bytes(&1u16.to_be_bytes())?;
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        builder.append_generated_bytes(&0u16.to_be_bytes())?;
        push_dns_name_payload(&mut builder, name)?;
        builder.append_generated_bytes(&DNS_TYPE_A.to_be_bytes())?;
        builder.append_generated_bytes(&(DNS_CLASS_IN | MDNS_CACHE_FLUSH_BIT).to_be_bytes())?;
        builder.append_generated_bytes(&ttl.to_be_bytes())?;
        builder.append_generated_bytes(&4u16.to_be_bytes())?;
        builder.append_generated_bytes(ip.as_bytes())?;
        Some(builder.build())
    }

    /// 期限切れキャッシュエントリを削除
    ///
    /// # Arguments
    /// - `current_time` - 現在時刻 (秒単位)
    pub fn cleanup_expired(&mut self, current_time: u64) {
        self.cache
            .retain(|_, entry| current_time < entry.expiry_time);
    }

    /// 最も古いキャッシュエントリを削除 (キャッシュが一杯の場合)
    fn evict_oldest(&mut self) {
        let oldest_expiry = self.cache.values().map(|entry| entry.expiry_time).min();
        if oldest_expiry.is_none() {
            return;
        }
        let mut dropped_oldest = false;
        let old_cache = core::mem::take(&mut self.cache);
        for (entry_key, entry_value) in old_cache {
            if !dropped_oldest && Some(entry_value.expiry_time) == oldest_expiry {
                dropped_oldest = true;
                continue;
            }
            self.cache.insert(entry_key, entry_value);
        }
    }

    /// Process a single mDNS payload in DNS wire format.
    ///
    /// TTL=255 validation is enforced by the caller (`run`) before this method
    /// is invoked, so this function focuses on DNS-layer parsing and state updates.
    pub fn process_packet_payload(
        &mut self,
        packet: &kernel_api::resource::net::PacketPayload,
        _src_ip: Ipv4Address,
        _ttl: u8,
        current_time: u64,
    ) -> MdnsResult {
        let view = PacketPayloadView::new(packet);
        if view.total_len() < DNS_HEADER_SIZE {
            return MdnsResult::InvalidPacket;
        }

        let flags = match view.read_array::<2>(2) {
            Some(bytes) => u16::from_be_bytes(bytes),
            None => return MdnsResult::InvalidPacket,
        };
        let qdcount = match view.read_array::<2>(4) {
            Some(bytes) => u16::from_be_bytes(bytes) as usize,
            None => return MdnsResult::InvalidPacket,
        };
        let ancount = match view.read_array::<2>(6) {
            Some(bytes) => u16::from_be_bytes(bytes) as usize,
            None => return MdnsResult::InvalidPacket,
        };

        let mut offset = DNS_HEADER_SIZE;
        if flags & 0x8000 == 0 {
            // Query path: answer A/ANY IN questions targeting `<hostname>.local`.
            for _ in 0..qdcount {
                let Some((name, next_offset)) = decode_dns_name_owned_view(&view, offset) else {
                    return MdnsResult::InvalidPacket;
                };
                let Some(qtype) = view.read_array::<2>(next_offset).map(u16::from_be_bytes) else {
                    return MdnsResult::InvalidPacket;
                };
                let Some(qclass) = view
                    .read_array::<2>(next_offset + 2)
                    .map(u16::from_be_bytes)
                else {
                    return MdnsResult::InvalidPacket;
                };
                offset = next_offset + 4;
                if (qtype == DNS_TYPE_A || qtype == 255)
                    && (qclass & 0x7FFF) == DNS_CLASS_IN
                    && self.matches_local_name(&name)
                {
                    return MdnsResult::SendResponse {
                        name,
                        ip: self.local_ip,
                        ttl: MDNS_DEFAULT_TTL,
                    };
                }
            }
            return MdnsResult::Ignored;
        }

        // Response path: skip question section, then parse answer records into cache.
        let mut saw_update = false;
        for _ in 0..qdcount {
            let Some((_, next_offset)) = decode_dns_name_owned_view(&view, offset) else {
                return MdnsResult::InvalidPacket;
            };
            if next_offset + 4 > view.total_len() {
                return MdnsResult::InvalidPacket;
            }
            offset = next_offset + 4;
        }
        for _ in 0..ancount {
            match self.try_process_dns_answer_view(&view, &mut offset, current_time) {
                Ok(updated) => saw_update |= updated,
                Err(()) => return MdnsResult::InvalidPacket,
            }
        }

        if saw_update {
            MdnsResult::CacheUpdated
        } else {
            MdnsResult::Ignored
        }
    }

    /// Case-insensitive check for `<hostname>.local`.
    fn matches_local_name(&self, name: &DnsNameOwned) -> bool {
        let labels = name.labels();
        labels.len() == 2
            && name.label_eq_ignore_ascii_case(0, self.hostname.as_bytes())
            && name.label_eq_ignore_ascii_case(1, b"local")
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// DNS名をエンコード
///
/// ドメイン名 (例: "foo.local") をDNSラベル形式にエンコードする。
/// 各ラベルは長さバイト + データの形式で、末尾にゼロバイトが付く。
///
/// # Arguments
/// - `buffer` - 出力バッファ
/// - `offset` - 書き込み開始位置
/// - `name` - エンコードするドメイン名
///
/// # Returns
/// 書き込み後のオフセット。バッファが小さすぎる場合はNone。
pub fn encode_dns_name(buffer: &mut [u8], mut offset: usize, name: &str) -> Option<usize> {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }

        let len = label.len();

        // Each label must be 63 bytes or less
        if len > DNS_LABEL_MAX_LEN {
            return None;
        }

        // Need space for length byte + label data
        if offset + 1 + len > buffer.len() {
            return None;
        }

        buffer[offset] = len as u8;
        offset += 1;

        buffer[offset..offset + len].copy_from_slice(label.as_bytes());
        offset += len;
    }

    // Null terminator
    if offset >= buffer.len() {
        return None;
    }
    buffer[offset] = 0;
    offset += 1;

    Some(offset)
}

fn push_dns_name_payload(builder: &mut PacketPayloadBuilder, name: &DnsNameOwned) -> Option<()> {
    for label in name.labels() {
        let len = label.total_len();
        if len > DNS_LABEL_MAX_LEN {
            return None;
        }
        builder.append_generated_bytes(&[len as u8])?;
        let span = label.span(name.payload())?;
        let mut pushed = true;
        span.for_each_chunk(|chunk| {
            if pushed && builder.append_generated_bytes(chunk).is_none() {
                pushed = false;
            }
        });
        if !pushed {
            return None;
        }
    }
    builder.append_generated_bytes(&[0])
}

/// DNS名をデコード (ラベル圧縮対応)
///
/// DNSワイヤーフォーマットの名前をデコードし、ドット区切りの文字列に変換する。
/// RFC 1035のラベル圧縮ポインター (0xC0プレフィックス) にも対応。
///
/// Handle a DNS compression pointer. Returns `Some(new_current)` on success,
/// or `None` if the pointer is invalid or jump limit exceeded.
/// Updates `final_offset` and `jumped` on the first jump.
#[inline]
fn handle_compression_pointer_view(
    view: &PacketPayloadView<'_>,
    current: usize,
    final_offset: &mut usize,
    jumped: &mut bool,
    jump_count: &mut usize,
    max_jumps: usize,
) -> Option<usize> {
    let first = view.read_array::<1>(current).map(|bytes| bytes[0])?;
    let second = view.read_array::<1>(current + 1).map(|bytes| bytes[0])?;
    if !*jumped {
        *final_offset = current + 2;
    }
    let pointer = ((first as usize & 0x3F) << 8) | second as usize;
    if pointer >= view.total_len() {
        return None;
    }
    *jump_count += 1;
    if *jump_count > max_jumps {
        return None;
    }
    *jumped = true;
    Some(pointer)
}

pub fn decode_dns_name_view(
    view: &PacketPayloadView<'_>,
    offset: usize,
) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut current = offset;
    let mut jumped = false;
    let mut final_offset = offset;
    let mut jump_count = 0;
    let max_jumps = 128;

    loop {
        if current >= view.total_len() {
            return None;
        }

        let len_byte = view.read_array::<1>(current).map(|bytes| bytes[0])?;

        if len_byte == 0 {
            if !jumped {
                final_offset = current + 1;
            }
            break;
        }

        if len_byte & DNS_COMPRESSION_MASK == DNS_COMPRESSION_MASK {
            current = handle_compression_pointer_view(
                view,
                current,
                &mut final_offset,
                &mut jumped,
                &mut jump_count,
                max_jumps,
            )?;
            continue;
        }

        let label_len = len_byte as usize;
        if label_len > DNS_LABEL_MAX_LEN {
            return None;
        }
        current += 1;

        if current + label_len > view.total_len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }

        if name.len() + label_len > DNS_NAME_MAX_LEN {
            return None;
        }

        let label = view.read_fixed_bytes::<DNS_LABEL_MAX_LEN>(current, label_len)?;
        for &byte in label.as_slice() {
            name.push(byte as char);
        }

        current += label_len;
    }

    Some((name, final_offset))
}

pub fn decode_dns_name_owned_view(
    view: &PacketPayloadView<'_>,
    offset: usize,
) -> Option<(DnsNameOwned, usize)> {
    let mut labels = Vec::new();
    let mut text_len = 0usize;
    let mut current = offset;
    let mut jumped = false;
    let mut final_offset = offset;
    let mut jump_count = 0;
    let max_jumps = 128;

    loop {
        if current >= view.total_len() {
            return None;
        }

        let len_byte = view.read_array::<1>(current).map(|bytes| bytes[0])?;

        if len_byte == 0 {
            if !jumped {
                final_offset = current + 1;
            }
            break;
        }

        if len_byte & DNS_COMPRESSION_MASK == DNS_COMPRESSION_MASK {
            current = handle_compression_pointer_view(
                view,
                current,
                &mut final_offset,
                &mut jumped,
                &mut jump_count,
                max_jumps,
            )?;
            continue;
        }

        let label_len = len_byte as usize;
        if label_len > DNS_LABEL_MAX_LEN {
            return None;
        }
        current += 1;

        if current + label_len > view.total_len() {
            return None;
        }

        let label_range = PayloadRange::new(current, label_len);
        label_range.span(view.payload())?;
        if !labels.is_empty() {
            text_len = text_len.saturating_add(1);
        }
        text_len = text_len.saturating_add(label_len);
        labels.push(label_range);
        current += label_len;
    }

    crate::net::services::dns::dns_name_owned_from_view(view, &labels, text_len)
        .map(|name| (name, final_offset))
}

/// mDNSマルチキャストMACアドレスを取得
///
/// mDNSマルチキャストグループ 224.0.0.251 に対応するイーサネット
/// マルチキャストMACアドレス (01:00:5E:00:00:FB) を返す。
///
/// IEEE 802.3マルチキャストMACマッピング:
/// - プレフィックス: 01:00:5E
/// - 下位23ビットにIPマルチキャストアドレスの下位23ビットをマッピング
pub fn multicast_mac() -> [u8; 6] {
    [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]
}

/// 大文字小文字を無視した名前比較
///
/// DNS名はケースインセンシティブであるため、比較時には
/// ASCII小文字に正規化して比較する。
fn names_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .all(|(ca, cb)| ca.to_ascii_lowercase() == cb.to_ascii_lowercase())
}

fn skip_dns_questions_view(
    view: &PacketPayloadView<'_>,
    mut offset: usize,
    qdcount: u16,
) -> Option<usize> {
    for _ in 0..qdcount {
        let (_, new_offset) = decode_dns_name_owned_view(view, offset)?;
        offset = new_offset;
        if offset + 4 > view.total_len() {
            return None;
        }
        offset += 4;
    }
    Some(offset)
}

/// DNS応答レコードをパースする
/// 返り値: (rtype, rclass_masked, rdlength, next_offset, rdata_start, name, ttl)
fn parse_dns_answer_record_view(
    view: &PacketPayloadView<'_>,
    offset: usize,
) -> Option<(u16, u16, usize, usize, usize, DnsNameOwned, u32)> {
    let (name, new_offset) = decode_dns_name_owned_view(view, offset)?;
    let mut offset = new_offset;

    if offset + 10 > view.total_len() {
        return None;
    }

    let rtype = u16::from_be_bytes(view.read_array::<2>(offset)?);
    let rclass = u16::from_be_bytes(view.read_array::<2>(offset + 2)?);
    let ttl = u32::from_be_bytes(view.read_array::<4>(offset + 4)?);
    let rdlength = u16::from_be_bytes(view.read_array::<2>(offset + 8)?) as usize;
    offset += 10;

    if offset + rdlength > view.total_len() {
        return None;
    }

    let rdata_start = offset;
    let rclass_masked = rclass & 0x7FFF;

    Some((
        rtype,
        rclass_masked,
        rdlength,
        offset + rdlength,
        rdata_start,
        name,
        ttl,
    ))
}

/// Aレコード（INクラス、4バイト）かどうか判定
fn is_inet_a_record(rtype: u16, rclass_masked: u16, rdlength: usize) -> bool {
    rtype == DNS_TYPE_A && rclass_masked == DNS_CLASS_IN && rdlength == 4
}

pub(crate) struct MdnsRuntimeState {
    service: PoisonLock<Option<MdnsService>>,
}

impl MdnsRuntimeState {
    pub const fn new() -> Self {
        Self {
            service: PoisonLock::new(None),
        }
    }
}

pub(crate) fn runtime_state_for(runtime: NetRuntimeHandle) -> &'static MdnsRuntimeState {
    &runtime.context().mdns
}

pub fn init_in(runtime: NetRuntimeHandle, hostname: String, local_ip: Ipv4Address) {
    let service = MdnsService::new_in(runtime, hostname, local_ip);
    if let Ok(mut guard) = runtime_state_for(runtime).service.lock() {
        *guard = Some(service);
    }
}

pub fn service_in(runtime: NetRuntimeHandle) -> &'static PoisonLock<Option<MdnsService>> {
    &runtime_state_for(runtime).service
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod tests;
