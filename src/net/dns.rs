//! DNS (Domain Name System) クライアント実装
//!
//! ドメイン名からIPアドレスへの解決を行うDNSリゾルバ。
//! 簡易的なキャッシュ機能付き。

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use spin::Mutex;

use super::ipv4::Ipv4Address;

/// DNSポート
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
    /// ドメイン名 (CNAME, NS, PTRなど)
    Name(String),
    /// MXレコード (優先度, ドメイン名)
    MX(u16, String),
    /// TXTレコード
    TXT(String),
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
    /// DNSサーバーアドレス (最大3つ)
    servers: Mutex<Vec<Ipv4Address>>,
    /// DNSキャッシュ
    cache: Mutex<DnsCache>,
    /// 次のトランザクションID
    next_id: AtomicU16,
    /// 統計情報
    stats: DnsStats,
}

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

impl DnsClient {
    /// 新しいDNSクライアントを作成
    pub fn new(tick_rate: u64) -> Self {
        Self {
            servers: Mutex::new(Vec::new()),
            cache: Mutex::new(DnsCache::new(tick_rate)),
            next_id: AtomicU16::new(1),
            stats: DnsStats::new(),
        }
    }

    /// DNSサーバーを設定
    pub fn set_servers(&self, servers: Vec<Ipv4Address>) {
        *self.servers.lock() = servers;
    }

    /// DNSサーバーを追加
    pub fn add_server(&self, server: Ipv4Address) {
        let mut servers = self.servers.lock();
        if !servers.contains(&server) && servers.len() < 3 {
            servers.push(server);
        }
    }

    /// キャッシュからIPアドレスを検索
    pub fn resolve_cached(&self, name: &str, current_tick: u64) -> Option<Ipv4Address> {
        let cache = self.cache.lock();
        if let Some(entry) = cache.lookup(name, current_tick) {
            for record in &entry.records {
                if let DnsRecordData::A(ip) = &record.data {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(*ip);
                }
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// DNSクエリパケットを構築
    pub fn build_query(
        &self,
        buffer: &mut [u8],
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DnsHeader::SIZE + name.len() + 6 {
            return Err("Buffer too small");
        }

        // トランザクションIDを生成
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // ヘッダを構築
        buffer[0..2].copy_from_slice(&id.to_be_bytes());
        // フラグ: 標準クエリ、再帰希望
        buffer[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        buffer[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buffer[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buffer[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        // 質問セクション - ドメイン名をエンコード
        let mut offset = DnsHeader::SIZE;

        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            let len = label.len();
            if len > 63 {
                return Err("Label too long");
            }
            buffer[offset] = len as u8;
            offset += 1;
            buffer[offset..offset + len].copy_from_slice(label.as_bytes());
            offset += len;
        }

        // 終端のゼロ
        buffer[offset] = 0;
        offset += 1;

        // QTYPE
        buffer[offset..offset + 2].copy_from_slice(&(qtype as u16).to_be_bytes());
        offset += 2;

        // QCLASS (IN = 1)
        buffer[offset..offset + 2].copy_from_slice(&(DnsQueryClass::IN as u16).to_be_bytes());
        offset += 2;

        self.stats.queries_sent.fetch_add(1, Ordering::Relaxed);

        Ok(offset)
    }

    /// DNS応答を解析
    pub fn parse_response(
        &self,
        data: &[u8],
        current_tick: u64,
    ) -> Result<Vec<DnsRecord>, DnsResponseCode> {
        if data.len() < DnsHeader::SIZE {
            return Err(DnsResponseCode::FormatError);
        }

        let header = unsafe { &*(data.as_ptr() as *const DnsHeader) };

        if !header.is_response() {
            return Err(DnsResponseCode::FormatError);
        }

        let rcode = header.rcode();
        if rcode as u8 != DnsResponseCode::NoError as u8 {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            return Err(rcode);
        }

        let qcount = header.question_count() as usize;
        let acount = header.answer_count() as usize;

        // 質問セクションをスキップ
        let mut offset = DnsHeader::SIZE;
        for _ in 0..qcount {
            // ドメイン名をスキップ
            offset = self.skip_name(data, offset)?;
            offset += 4; // QTYPE + QCLASS
        }

        // 回答セクションを解析
        let mut records = Vec::new();
        for _ in 0..acount {
            if offset >= data.len() {
                break;
            }

            let (name, new_offset) = self.parse_name(data, offset)?;
            offset = new_offset;

            if offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            let rdata = &data[offset..offset + rdlength];
            offset += rdlength;

            let record_data = match DnsQueryType::from_u16(rtype) {
                Some(DnsQueryType::A) if rdlength == 4 => {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(rdata);
                    DnsRecordData::A(Ipv4Address::new(bytes))
                }
                Some(DnsQueryType::CNAME) | Some(DnsQueryType::NS) | Some(DnsQueryType::PTR) => {
                    if let Ok((cname, _)) = self.parse_name(data, offset - rdlength) {
                        DnsRecordData::Name(cname)
                    } else {
                        DnsRecordData::Raw(rdata.to_vec())
                    }
                }
                Some(DnsQueryType::MX) if rdlength >= 3 => {
                    let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                    if let Ok((exchange, _)) = self.parse_name(data, offset - rdlength + 2) {
                        DnsRecordData::MX(preference, exchange)
                    } else {
                        DnsRecordData::Raw(rdata.to_vec())
                    }
                }
                Some(DnsQueryType::TXT) => {
                    // TXTレコードは長さプレフィックス付き
                    if !rdata.is_empty() {
                        let txt_len = rdata[0] as usize;
                        if txt_len < rdlength {
                            DnsRecordData::TXT(
                                String::from_utf8_lossy(&rdata[1..1 + txt_len]).into_owned(),
                            )
                        } else {
                            DnsRecordData::Raw(rdata.to_vec())
                        }
                    } else {
                        DnsRecordData::Raw(rdata.to_vec())
                    }
                }
                _ => DnsRecordData::Raw(rdata.to_vec()),
            };

            records.push(DnsRecord {
                name,
                rtype: DnsQueryType::from_u16(rtype).unwrap_or(DnsQueryType::A),
                rclass: if rclass == 1 {
                    DnsQueryClass::IN
                } else {
                    DnsQueryClass::IN
                },
                ttl,
                data: record_data,
            });
        }

        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);

        // キャッシュに追加
        if !records.is_empty() {
            if let Some(first) = records.first() {
                let mut cache = self.cache.lock();
                cache.insert(first.name.clone(), records.clone(), current_tick);
            }
        }

        Ok(records)
    }

    /// ドメイン名をスキップ
    fn skip_name(&self, data: &[u8], mut offset: usize) -> Result<usize, DnsResponseCode> {
        loop {
            if offset >= data.len() {
                return Err(DnsResponseCode::FormatError);
            }

            let len = data[offset];

            if len == 0 {
                return Ok(offset + 1);
            }

            if len & 0xC0 == 0xC0 {
                // 圧縮ポインター
                return Ok(offset + 2);
            }

            offset += 1 + len as usize;
        }
    }

    /// ドメイン名を解析 (圧縮対応)
    fn parse_name(
        &self,
        data: &[u8],
        mut offset: usize,
    ) -> Result<(String, usize), DnsResponseCode> {
        let mut name = String::new();
        let mut jumped = false;
        let original_offset = offset;
        let mut final_offset = offset;

        loop {
            if offset >= data.len() {
                return Err(DnsResponseCode::FormatError);
            }

            let len = data[offset];

            if len == 0 {
                if !jumped {
                    final_offset = offset + 1;
                }
                break;
            }

            if len & 0xC0 == 0xC0 {
                // 圧縮ポインター
                if offset + 1 >= data.len() {
                    return Err(DnsResponseCode::FormatError);
                }

                if !jumped {
                    final_offset = offset + 2;
                }

                let pointer = ((len as usize & 0x3F) << 8) | data[offset + 1] as usize;
                if pointer >= original_offset {
                    return Err(DnsResponseCode::FormatError);
                }

                offset = pointer;
                jumped = true;
                continue;
            }

            offset += 1;

            if offset + len as usize > data.len() {
                return Err(DnsResponseCode::FormatError);
            }

            if !name.is_empty() {
                name.push('.');
            }

            name.push_str(&String::from_utf8_lossy(
                &data[offset..offset + len as usize],
            ));
            offset += len as usize;
        }

        Ok((name, final_offset))
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &DnsStats {
        &self.stats
    }

    /// プライマリDNSサーバーを取得
    pub fn primary_server(&self) -> Option<Ipv4Address> {
        self.servers.lock().first().copied()
    }
}

/// グローバルDNSクライアント
static DNS_CLIENT: Mutex<Option<DnsClient>> = Mutex::new(None);

/// DNSクライアントを初期化
pub fn init(tick_rate: u64) {
    let client = DnsClient::new(tick_rate);
    *DNS_CLIENT.lock() = Some(client);
}

/// DNSサーバーを設定
pub fn set_servers(servers: Vec<Ipv4Address>) {
    if let Some(client) = DNS_CLIENT.lock().as_ref() {
        client.set_servers(servers);
    }
}

/// キャッシュからIPアドレスを解決
pub fn resolve_cached(name: &str, current_tick: u64) -> Option<Ipv4Address> {
    DNS_CLIENT
        .lock()
        .as_ref()
        .and_then(|c| c.resolve_cached(name, current_tick))
}
