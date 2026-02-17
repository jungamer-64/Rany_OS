// ============================================================================
// kernel/src/net/mdns.rs
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

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::ipv4::Ipv4Address;

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
#[derive(Debug, Clone)]
pub enum MdnsResult {
    /// クエリ送信が必要
    SendQuery {
        /// 解決対象のホスト名
        target_name: String,
    },
    /// 応答送信が必要
    SendResponse {
        /// 応答するホスト名
        name: String,
        /// ホストのIPアドレス
        ip: Ipv4Address,
        /// TTL (秒)
        ttl: u32,
    },
    /// 名前解決に成功
    Resolved {
        /// 解決されたホスト名
        name: String,
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
#[derive(Debug, Clone)]
pub struct MdnsReport {
    /// 送信先ホスト名
    pub name: String,
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
#[derive(Debug, Clone)]
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
    /// 自ホスト名 (例: "myhost")
    hostname: String,
    /// 自ホストのIPアドレス
    local_ip: Ipv4Address,
    /// 名前解決キャッシュ (ホスト名 → キャッシュエントリ)
    cache: BTreeMap<String, MdnsCacheEntry>,
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
    pub fn new(hostname: String, local_ip: Ipv4Address) -> Self {
        Self {
            hostname,
            local_ip,
            cache: BTreeMap::new(),
            pending_reports: Vec::new(),
        }
    }

    /// 自ホストの完全修飾mDNS名を取得 (例: "myhost.local")
    pub fn fqdn(&self) -> String {
        let mut name = self.hostname.clone();
        name.push_str(".local");
        name
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

    /// 受信パケットを処理
    ///
    /// DNSワイヤーフォーマットのパケットを解析し、クエリへの応答や
    /// レスポンスのキャッシュ更新を行う。
    ///
    /// # Arguments
    /// - `data` - 受信したUDPペイロード (DNSワイヤーフォーマット)
    /// - `src_ip` - 送信元IPアドレス
    /// - `current_time` - 現在時刻 (秒単位)
    pub fn process_packet(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        current_time: u64,
    ) -> MdnsResult {
        // Minimum packet size: DNS header (12 bytes)
        if data.len() < DNS_HEADER_SIZE {
            return MdnsResult::InvalidPacket;
        }

        // Parse DNS header
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);

        // QR bit: bit 15 of flags
        let is_response = (flags & 0x8000) != 0;

        if is_response {
            self.process_response(data, ancount, qdcount, src_ip, current_time)
        } else {
            self.process_query(data, qdcount, src_ip, current_time)
        }
    }

    /// mDNSクエリを処理
    fn process_query(
        &mut self,
        data: &[u8],
        qdcount: u16,
        src_ip: Ipv4Address,
        current_time: u64,
    ) -> MdnsResult {
        let mut offset = DNS_HEADER_SIZE;
        let our_fqdn = self.fqdn();

        for _ in 0..qdcount {
            // Decode the question name
            let (name, new_offset) = match decode_dns_name(data, offset) {
                Some(result) => result,
                None => return MdnsResult::InvalidPacket,
            };
            offset = new_offset;

            // Need at least 4 more bytes for QTYPE and QCLASS
            if offset + 4 > data.len() {
                return MdnsResult::InvalidPacket;
            }

            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            // Strip the cache-flush / unicast-response bit from class
            let qclass_masked = qclass & 0x7FFF;

            // Check if this is an A record query for our hostname
            if qtype == DNS_TYPE_A && qclass_masked == DNS_CLASS_IN {
                if names_equal(&name, &our_fqdn) {
                    // This query is for us - queue a pending report
                    self.pending_reports.push(MdnsReport {
                        name: our_fqdn.clone(),
                        ip: Some(self.local_ip),
                        ttl: MDNS_DEFAULT_TTL,
                        is_response: true,
                        timestamp: current_time,
                    });

                    return MdnsResult::SendResponse {
                        name: our_fqdn,
                        ip: self.local_ip,
                        ttl: MDNS_DEFAULT_TTL,
                    };
                }
            }
        }

        MdnsResult::Ignored
    }

    /// mDNS応答を処理
    fn process_response(
        &mut self,
        data: &[u8],
        ancount: u16,
        qdcount: u16,
        src_ip: Ipv4Address,
        current_time: u64,
    ) -> MdnsResult {
        let mut offset = match skip_dns_questions(data, DNS_HEADER_SIZE, qdcount) {
            Some(o) => o,
            None => return MdnsResult::InvalidPacket,
        };

        // Parse answer section
        let mut last_resolved_name: Option<String> = None;
        let mut last_resolved_ip: Option<Ipv4Address> = None;

        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }

            let record = match parse_dns_answer_record(data, offset) {
                Some(r) => r,
                None => return MdnsResult::InvalidPacket,
            };
            offset = record.3;

            // Only process A records (IN class)
            if is_inet_a_record(record.0, record.1, record.2) {
                let rdata = &data[record.4..record.4 + record.2];
                let ip = Ipv4Address::new([rdata[0], rdata[1], rdata[2], rdata[3]]);
                let name_lower = to_lowercase(&record.5);

                if !self.cache_a_record(&name_lower, ip, record.6, current_time) {
                    continue;
                }

                last_resolved_name = Some(name_lower);
                last_resolved_ip = Some(ip);
            }
        }

        // Return the most appropriate result
        match (last_resolved_name, last_resolved_ip) {
            (Some(name), Some(ip)) => MdnsResult::Resolved { name, ip },
            _ => {
                if ancount > 0 {
                    MdnsResult::CacheUpdated
                } else {
                    MdnsResult::Ignored
                }
            }
        }
    }

    /// Aレコードをキャッシュに追加・更新する。TTL=0のgoodbyeパケットはキャッシュ削除。
    /// 正常にキャッシュ更新された場合trueを返す。
    fn cache_a_record(&mut self, name_lower: &str, ip: Ipv4Address, ttl: u32, current_time: u64) -> bool {
        if ttl == 0 {
            self.cache.remove(name_lower);
            return false;
        }

        let expiry = current_time + ttl as u64;

        if !self.cache.contains_key(name_lower) && self.cache.len() >= MDNS_MAX_CACHE_ENTRIES {
            self.evict_oldest();
        }

        self.cache.insert(
            String::from(name_lower),
            MdnsCacheEntry { ip, expiry_time: expiry },
        );
        true
    }

    /// キャッシュからホスト名を解決
    ///
    /// # Arguments
    /// - `name` - 解決するホスト名 (例: "host.local")
    /// - `current_time` - 現在時刻 (秒単位)
    ///
    /// # Returns
    /// キャッシュにエントリが存在し有効期限内であればIPアドレスを返す
    pub fn resolve(&self, name: &str, current_time: u64) -> Option<Ipv4Address> {
        let name_lower = to_lowercase(name);
        if let Some(entry) = self.cache.get(&name_lower) {
            if current_time < entry.expiry_time {
                return Some(entry.ip);
            }
        }
        None
    }

    /// mDNSクエリパケットを構築
    ///
    /// 指定されたホスト名に対するAレコードクエリをDNSワイヤーフォーマットで構築する。
    ///
    /// # Arguments
    /// - `buffer` - 出力バッファ
    /// - `name` - クエリ対象ホスト名 (例: "host.local")
    ///
    /// # Returns
    /// 書き込んだバイト数。バッファが小さすぎる場合はNone。
    pub fn build_query(buffer: &mut [u8], name: &str) -> Option<usize> {
        if buffer.len() < DNS_HEADER_SIZE {
            return None;
        }

        // DNS Header
        // ID: 0 for mDNS (RFC 6762 section 18.1)
        buffer[0] = 0;
        buffer[1] = 0;

        // Flags: standard query (QR=0)
        let flags = MDNS_QUERY_FLAGS;
        buffer[2] = (flags >> 8) as u8;
        buffer[3] = flags as u8;

        // QDCOUNT = 1
        buffer[4] = 0;
        buffer[5] = 1;

        // ANCOUNT = 0
        buffer[6] = 0;
        buffer[7] = 0;

        // NSCOUNT = 0
        buffer[8] = 0;
        buffer[9] = 0;

        // ARCOUNT = 0
        buffer[10] = 0;
        buffer[11] = 0;

        let mut offset = DNS_HEADER_SIZE;

        // Encode the question name
        offset = encode_dns_name(buffer, offset, name)?;

        // QTYPE = A (1)
        if offset + 4 > buffer.len() {
            return None;
        }
        buffer[offset] = (DNS_TYPE_A >> 8) as u8;
        buffer[offset + 1] = DNS_TYPE_A as u8;
        offset += 2;

        // QCLASS = IN (1) with unicast-response bit cleared for multicast
        buffer[offset] = (DNS_CLASS_IN >> 8) as u8;
        buffer[offset + 1] = DNS_CLASS_IN as u8;
        offset += 2;

        Some(offset)
    }

    /// mDNS応答パケットを構築
    ///
    /// 指定されたホスト名とIPアドレスに対するAレコード応答を
    /// DNSワイヤーフォーマットで構築する。
    ///
    /// # Arguments
    /// - `buffer` - 出力バッファ
    /// - `name` - 応答するホスト名 (例: "host.local")
    /// - `ip` - ホストのIPアドレス
    /// - `ttl` - レコードのTTL (秒)
    ///
    /// # Returns
    /// 書き込んだバイト数。バッファが小さすぎる場合はNone。
    pub fn build_response(
        buffer: &mut [u8],
        name: &str,
        ip: Ipv4Address,
        ttl: u32,
    ) -> Option<usize> {
        if buffer.len() < DNS_HEADER_SIZE {
            return None;
        }

        // DNS Header
        // ID: 0 for mDNS
        buffer[0] = 0;
        buffer[1] = 0;

        // Flags: response with authoritative answer (QR=1, AA=1)
        let flags = MDNS_RESPONSE_FLAGS;
        buffer[2] = (flags >> 8) as u8;
        buffer[3] = flags as u8;

        // QDCOUNT = 0
        buffer[4] = 0;
        buffer[5] = 0;

        // ANCOUNT = 1
        buffer[6] = 0;
        buffer[7] = 1;

        // NSCOUNT = 0
        buffer[8] = 0;
        buffer[9] = 0;

        // ARCOUNT = 0
        buffer[10] = 0;
        buffer[11] = 0;

        let mut offset = DNS_HEADER_SIZE;

        // Encode the answer name
        offset = encode_dns_name(buffer, offset, name)?;

        // TYPE = A (1)
        if offset + 10 > buffer.len() {
            return None;
        }
        buffer[offset] = (DNS_TYPE_A >> 8) as u8;
        buffer[offset + 1] = DNS_TYPE_A as u8;
        offset += 2;

        // CLASS = IN (1) with cache-flush bit set (RFC 6762 section 10.2)
        let class_with_flush = DNS_CLASS_IN | MDNS_CACHE_FLUSH_BIT;
        buffer[offset] = (class_with_flush >> 8) as u8;
        buffer[offset + 1] = class_with_flush as u8;
        offset += 2;

        // TTL (4 bytes, big-endian)
        let ttl_bytes = ttl.to_be_bytes();
        buffer[offset] = ttl_bytes[0];
        buffer[offset + 1] = ttl_bytes[1];
        buffer[offset + 2] = ttl_bytes[2];
        buffer[offset + 3] = ttl_bytes[3];
        offset += 4;

        // RDLENGTH = 4 (IPv4 address)
        if offset + 6 > buffer.len() {
            return None;
        }
        buffer[offset] = 0;
        buffer[offset + 1] = 4;
        offset += 2;

        // RDATA: IPv4 address
        let octets = ip.octets();
        buffer[offset] = octets[0];
        buffer[offset + 1] = octets[1];
        buffer[offset + 2] = octets[2];
        buffer[offset + 3] = octets[3];
        offset += 4;

        Some(offset)
    }

    /// 期限切れキャッシュエントリを削除
    ///
    /// # Arguments
    /// - `current_time` - 現在時刻 (秒単位)
    pub fn cleanup_expired(&mut self, current_time: u64) {
        let expired_keys: Vec<String> = self
            .cache
            .iter()
            .filter(|(_, entry)| current_time >= entry.expiry_time)
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            self.cache.remove(&key);
        }
    }

    /// 最も古いキャッシュエントリを削除 (キャッシュが一杯の場合)
    fn evict_oldest(&mut self) {
        let oldest_key = self
            .cache
            .iter()
            .min_by_key(|(_, entry)| entry.expiry_time)
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            self.cache.remove(&key);
        }
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

/// DNS名をデコード (ラベル圧縮対応)
///
/// DNSワイヤーフォーマットの名前をデコードし、ドット区切りの文字列に変換する。
/// RFC 1035のラベル圧縮ポインター (0xC0プレフィックス) にも対応。
///
/// Handle a DNS compression pointer. Returns `Some(new_current)` on success,
/// or `None` if the pointer is invalid or jump limit exceeded.
/// Updates `final_offset` and `jumped` on the first jump.
#[inline]
fn handle_compression_pointer(
    data: &[u8],
    current: usize,
    final_offset: &mut usize,
    jumped: &mut bool,
    jump_count: &mut usize,
    max_jumps: usize,
) -> Option<usize> {
    if current + 1 >= data.len() {
        return None;
    }
    if !*jumped {
        *final_offset = current + 2;
    }
    let pointer = ((data[current] as usize & 0x3F) << 8) | data[current + 1] as usize;
    if pointer >= data.len() {
        return None;
    }
    *jump_count += 1;
    if *jump_count > max_jumps {
        return None;
    }
    *jumped = true;
    Some(pointer)
}

/// DNS名をデコードする（圧縮ポインタにも対応）
///
/// # Arguments
/// - `data` - パケット全体のバイト列
/// - `offset` - 名前の開始位置
///
/// # Returns
/// (デコードされた名前, 次のフィールドのオフセット) のタプル。
/// パースに失敗した場合はNone。
pub fn decode_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut current = offset;
    let mut jumped = false;
    let mut final_offset = offset;
    let mut jump_count = 0;
    let max_jumps = 128;

    loop {
        if current >= data.len() {
            return None;
        }

        let len_byte = data[current];

        // Null terminator: end of name
        if len_byte == 0 {
            if !jumped {
                final_offset = current + 1;
            }
            break;
        }

        // Compression pointer (top 2 bits set = 0xC0)
        if len_byte & DNS_COMPRESSION_MASK == DNS_COMPRESSION_MASK {
            current = handle_compression_pointer(
                data, current, &mut final_offset, &mut jumped, &mut jump_count, max_jumps,
            )?;
            continue;
        }

        // Normal label
        let label_len = len_byte as usize;
        current += 1;

        if current + label_len > data.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }

        let label_bytes = &data[current..current + label_len];
        for &b in label_bytes {
            name.push(b as char);
        }

        current += label_len;
    }

    Some((name, final_offset))
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

/// DNS質問セクションをスキップし、新しいオフセットを返す
fn skip_dns_questions(data: &[u8], mut offset: usize, qdcount: u16) -> Option<usize> {
    for _ in 0..qdcount {
        let (_, new_offset) = decode_dns_name(data, offset)?;
        offset = new_offset;
        if offset + 4 > data.len() {
            return None;
        }
        offset += 4;
    }
    Some(offset)
}

/// DNS応答レコードをパースする
/// 返り値: (rtype, rclass_masked, rdlength, next_offset, rdata_start, name, ttl)
fn parse_dns_answer_record(data: &[u8], offset: usize) -> Option<(u16, u16, usize, usize, usize, String, u32)> {
    let (name, new_offset) = decode_dns_name(data, offset)?;
    let mut offset = new_offset;

    if offset + 10 > data.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
    let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
    offset += 10;

    if offset + rdlength > data.len() {
        return None;
    }

    let rdata_start = offset;
    let rclass_masked = rclass & 0x7FFF;

    Some((rtype, rclass_masked, rdlength, offset + rdlength, rdata_start, name, ttl))
}

/// Aレコード（INクラス、4バイト）かどうか判定
fn is_inet_a_record(rtype: u16, rclass_masked: u16, rdlength: usize) -> bool {
    rtype == DNS_TYPE_A && rclass_masked == DNS_CLASS_IN && rdlength == 4
}

/// 文字列をASCII小文字に変換
fn to_lowercase(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            result.push((c as u8 + 32) as char);
        } else {
            result.push(c);
        }
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_constants() {
        assert_eq!(MDNS_PORT, 5353);
        assert_eq!(MDNS_MULTICAST_GROUP, Ipv4Address::new([224, 0, 0, 251]));
        assert_eq!(MDNS_DEFAULT_TTL, 120);
    }

    #[test_case]
    fn test_multicast_mac() {
        let mac = multicast_mac();
        assert_eq!(mac, [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]);
    }

    #[test_case]
    fn test_mdns_service_new() {
        let service =
            MdnsService::new(String::from("myhost"), Ipv4Address::new([192, 168, 1, 100]));
        assert_eq!(service.hostname(), "myhost");
        assert_eq!(service.fqdn(), "myhost.local");
        assert_eq!(service.local_ip(), Ipv4Address::new([192, 168, 1, 100]));
        assert_eq!(service.cache_len(), 0);
    }

    #[test_case]
    fn test_encode_decode_dns_name() {
        let mut buffer = [0u8; 256];
        let name = "myhost.local";

        let end = encode_dns_name(&mut buffer, 0, name).expect("encode should succeed");

        // Expected: [6, 'm', 'y', 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0]
        assert_eq!(buffer[0], 6); // "myhost" length
        assert_eq!(&buffer[1..7], b"myhost");
        assert_eq!(buffer[7], 5); // "local" length
        assert_eq!(&buffer[8..13], b"local");
        assert_eq!(buffer[13], 0); // null terminator
        assert_eq!(end, 14);

        // Decode it back
        let (decoded, offset) = decode_dns_name(&buffer, 0).expect("decode should succeed");
        assert_eq!(decoded, "myhost.local");
        assert_eq!(offset, 14);
    }

    #[test_case]
    fn test_build_query() {
        let mut buffer = [0u8; 256];
        let len = MdnsService::build_query(&mut buffer, "test.local").expect("build_query should succeed");

        // Check header
        assert_eq!(u16::from_be_bytes([buffer[0], buffer[1]]), 0); // ID = 0
        assert_eq!(u16::from_be_bytes([buffer[2], buffer[3]]), 0x0000); // flags: query
        assert_eq!(u16::from_be_bytes([buffer[4], buffer[5]]), 1); // QDCOUNT = 1
        assert_eq!(u16::from_be_bytes([buffer[6], buffer[7]]), 0); // ANCOUNT = 0
    }

    #[test_case]
    fn test_build_response() {
        let mut buffer = [0u8; 256];
        let ip = Ipv4Address::new([192, 168, 1, 42]);
        let len = MdnsService::build_response(&mut buffer, "test.local", ip, 120)
            .expect("build_response should succeed");

        // Check header
        assert_eq!(u16::from_be_bytes([buffer[0], buffer[1]]), 0); // ID = 0
        assert_eq!(u16::from_be_bytes([buffer[2], buffer[3]]), 0x8400); // flags: response + AA
        assert_eq!(u16::from_be_bytes([buffer[4], buffer[5]]), 0); // QDCOUNT = 0
        assert_eq!(u16::from_be_bytes([buffer[6], buffer[7]]), 1); // ANCOUNT = 1

        // Verify the IP address is in the packet
        // The RDATA should contain 192.168.1.42
        let rdata_start = len - 4;
        assert_eq!(buffer[rdata_start], 192);
        assert_eq!(buffer[rdata_start + 1], 168);
        assert_eq!(buffer[rdata_start + 2], 1);
        assert_eq!(buffer[rdata_start + 3], 42);
    }

    #[test_case]
    fn test_process_query_for_our_hostname() {
        let mut service =
            MdnsService::new(String::from("myhost"), Ipv4Address::new([10, 0, 0, 5]));

        // Build a query for "myhost.local"
        let mut query_buf = [0u8; 256];
        let query_len =
            MdnsService::build_query(&mut query_buf, "myhost.local").expect("build_query");

        let result = service.process_packet(&query_buf[..query_len], Ipv4Address::new([10, 0, 0, 1]), 100);

        match result {
            MdnsResult::SendResponse { name, ip, ttl } => {
                assert_eq!(name, "myhost.local");
                assert_eq!(ip, Ipv4Address::new([10, 0, 0, 5]));
                assert_eq!(ttl, MDNS_DEFAULT_TTL);
            }
            _ => panic!("Expected SendResponse"),
        }
    }

    #[test_case]
    fn test_process_query_for_other_hostname() {
        let mut service =
            MdnsService::new(String::from("myhost"), Ipv4Address::new([10, 0, 0, 5]));

        // Build a query for a different host
        let mut query_buf = [0u8; 256];
        let query_len =
            MdnsService::build_query(&mut query_buf, "otherhost.local").expect("build_query");

        let result = service.process_packet(&query_buf[..query_len], Ipv4Address::new([10, 0, 0, 1]), 100);

        match result {
            MdnsResult::Ignored => {} // expected
            _ => panic!("Expected Ignored"),
        }
    }

    #[test_case]
    fn test_process_response_updates_cache() {
        let mut service =
            MdnsService::new(String::from("myhost"), Ipv4Address::new([10, 0, 0, 5]));

        // Build a response for "other.local" -> 10.0.0.42
        let mut resp_buf = [0u8; 256];
        let resp_len = MdnsService::build_response(
            &mut resp_buf,
            "other.local",
            Ipv4Address::new([10, 0, 0, 42]),
            120,
        )
        .expect("build_response");

        let result = service.process_packet(&resp_buf[..resp_len], Ipv4Address::new([10, 0, 0, 42]), 1000);

        match result {
            MdnsResult::Resolved { name, ip } => {
                assert_eq!(name, "other.local");
                assert_eq!(ip, Ipv4Address::new([10, 0, 0, 42]));
            }
            _ => panic!("Expected Resolved"),
        }

        // Verify cache was updated
        let resolved = service.resolve("other.local", 1000);
        assert_eq!(resolved, Some(Ipv4Address::new([10, 0, 0, 42])));

        // Verify cache expires
        let resolved_expired = service.resolve("other.local", 1200);
        assert_eq!(resolved_expired, None);
    }

    #[test_case]
    fn test_cleanup_expired() {
        let mut service =
            MdnsService::new(String::from("myhost"), Ipv4Address::new([10, 0, 0, 5]));

        // Manually insert a cache entry that will expire
        service.cache.insert(
            String::from("expired.local"),
            MdnsCacheEntry {
                ip: Ipv4Address::new([10, 0, 0, 99]),
                expiry_time: 100,
            },
        );
        service.cache.insert(
            String::from("valid.local"),
            MdnsCacheEntry {
                ip: Ipv4Address::new([10, 0, 0, 88]),
                expiry_time: 500,
            },
        );

        assert_eq!(service.cache_len(), 2);

        // Cleanup at time 200 should remove the expired entry
        service.cleanup_expired(200);

        assert_eq!(service.cache_len(), 1);
        assert!(service.resolve("expired.local", 200).is_none());
        assert_eq!(
            service.resolve("valid.local", 200),
            Some(Ipv4Address::new([10, 0, 0, 88]))
        );
    }

    #[test_case]
    fn test_invalid_packet_too_short() {
        let mut service =
            MdnsService::new(String::from("myhost"), Ipv4Address::new([10, 0, 0, 5]));

        // Packet shorter than DNS header
        let short_data = [0u8; 6];
        let result = service.process_packet(&short_data, Ipv4Address::new([10, 0, 0, 1]), 0);

        match result {
            MdnsResult::InvalidPacket => {} // expected
            _ => panic!("Expected InvalidPacket"),
        }
    }

    #[test_case]
    fn test_names_equal_case_insensitive() {
        assert!(names_equal("MyHost.Local", "myhost.local"));
        assert!(names_equal("HOST.LOCAL", "host.local"));
        assert!(!names_equal("host1.local", "host2.local"));
    }

    #[test_case]
    fn test_dns_name_compression() {
        // Craft a packet with compression pointer
        // Name at offset 0: [4, 't', 'e', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0]
        // Compressed name pointing back to offset 0: [0xC0, 0x00]
        let mut data = [0u8; 64];
        data[0] = 4;
        data[1] = b't';
        data[2] = b'e';
        data[3] = b's';
        data[4] = b't';
        data[5] = 5;
        data[6] = b'l';
        data[7] = b'o';
        data[8] = b'c';
        data[9] = b'a';
        data[10] = b'l';
        data[11] = 0;

        // Compressed pointer at offset 14 pointing to offset 0
        data[14] = 0xC0;
        data[15] = 0x00;

        // Decode original name
        let (name1, off1) = decode_dns_name(&data, 0).expect("decode original");
        assert_eq!(name1, "test.local");
        assert_eq!(off1, 12);

        // Decode compressed name
        let (name2, off2) = decode_dns_name(&data, 14).expect("decode compressed");
        assert_eq!(name2, "test.local");
        assert_eq!(off2, 16); // past the 2-byte pointer
    }

    #[test_case]
    fn test_encode_dns_name_label_too_long() {
        let mut buffer = [0u8; 256];
        // Create a label longer than 63 chars
        let long_label = "a".repeat(64);
        let long_name = alloc::format!("{}.local", long_label);

        let result = encode_dns_name(&mut buffer, 0, &long_name);
        assert!(result.is_none());
    }

    #[test_case]
    fn test_roundtrip_query_response() {
        let mut server =
            MdnsService::new(String::from("server"), Ipv4Address::new([192, 168, 1, 10]));
        let mut client =
            MdnsService::new(String::from("client"), Ipv4Address::new([192, 168, 1, 20]));

        // Client builds a query for server.local
        let mut query_buf = [0u8; 512];
        let query_len =
            MdnsService::build_query(&mut query_buf, "server.local").expect("build_query");

        // Server processes the query
        let result = server.process_packet(
            &query_buf[..query_len],
            Ipv4Address::new([192, 168, 1, 20]),
            1000,
        );

        // Server should want to send a response
        match result {
            MdnsResult::SendResponse { name, ip, ttl } => {
                // Server builds the response
                let mut resp_buf = [0u8; 512];
                let resp_len = MdnsService::build_response(&mut resp_buf, &name, ip, ttl)
                    .expect("build_response");

                // Client processes the response
                let client_result = client.process_packet(
                    &resp_buf[..resp_len],
                    Ipv4Address::new([192, 168, 1, 10]),
                    1000,
                );

                match client_result {
                    MdnsResult::Resolved { name, ip } => {
                        assert_eq!(name, "server.local");
                        assert_eq!(ip, Ipv4Address::new([192, 168, 1, 10]));
                    }
                    _ => panic!("Expected Resolved"),
                }

                // Client should now have the entry cached
                let cached =
                    client.resolve("server.local", 1000).expect("should be cached");
                assert_eq!(cached, Ipv4Address::new([192, 168, 1, 10]));
            }
            _ => panic!("Expected SendResponse"),
        }
    }
}
