// ============================================================================
// kernel/src/net/services/dns/cache_ops.rs - サービス / DNS / cache ops
// ============================================================================

use super::*;
use alloc::string::String;

fn dns_public_span_to_string(span: crate::net::payload::PayloadSpanRef<'_>) -> String {
    let mut out = String::with_capacity(span.total_len());
    for index in 0..span.total_len() {
        if let Some(byte) = span.byte_at(index) {
            out.push(byte as char);
        }
    }
    out
}

fn dns_name_view_to_string(payload: &PacketPayload, name: &DnsNameView) -> Option<String> {
    let mut out = String::with_capacity(name.text_len());
    for (index, label) in name.labels().iter().enumerate() {
        if index > 0 {
            out.push('.');
        }
        out.push_str(&dns_public_span_to_string(label.span(payload)?));
    }
    Some(out)
}

fn dns_txt_view_to_string(payload: &PacketPayload, txt: &DnsTxtView) -> Option<String> {
    let mut out = String::with_capacity(txt.text_len());
    for span in txt.spans() {
        out.push_str(&dns_public_span_to_string(span.span(payload)?));
    }
    Some(out)
}

enum CacheLookup<A> {
    Hit(A),
    Negative,
    Miss,
}

fn lookup_cached<A: Copy>(
    cache: &PoisonLock<DnsCache<A>>,
    key: &DnsCacheKey,
    current_tick: u64,
) -> CacheLookup<A> {
    let Ok(cache) = cache.lock() else {
        return CacheLookup::Miss;
    };
    match cache.lookup(key, current_tick) {
        Some(DnsCachedAnswer::Positive(addresses)) => addresses
            .first()
            .copied()
            .map_or(CacheLookup::Miss, CacheLookup::Hit),
        Some(DnsCachedAnswer::Negative) => CacheLookup::Negative,
        None => CacheLookup::Miss,
    }
}

/// Owner name that the next answer record must carry.
enum ChainOwner<'a> {
    Query(&'a DnsNameOwned),
    Alias(&'a DnsNameView),
}

impl ChainOwner<'_> {
    fn owns(&self, payload: &PacketPayload, record: &DnsRecordMeta) -> bool {
        let ordering = match self {
            Self::Query(name) => compare_dns_name_view_to_owned(payload, &record.name, name),
            Self::Alias(alias) => {
                compare_dns_name_ranges(payload, record.name.labels(), payload, alias.labels())
            }
        };
        ordering == CmpOrdering::Equal
    }
}

/// Addresses of `qtype` reached from the query name through at most
/// [`DNS_MAX_CNAME_DEPTH`] CNAME records (RFC 1034 Section 3.6.2), with the
/// smallest TTL along the chain.
fn chain_addresses<A>(
    response: &DnsResponseView,
    query: &DnsNameOwned,
    qtype: DnsQueryType,
    select: &impl Fn(&DnsRecordData) -> Option<A>,
) -> (Vec<A>, u32) {
    let payload = &response.payload;
    let answers = || {
        response
            .records
            .iter()
            .filter(|record| record.rclass == DnsRecordClass::Known(DnsQueryClass::IN))
    };
    let mut owner = ChainOwner::Query(query);
    let mut ttl = u32::MAX;
    let mut addresses = Vec::new();
    for _ in 0..=DNS_MAX_CNAME_DEPTH {
        for record in
            answers().filter(|record| record.rtype.is(qtype) && owner.owns(payload, record))
        {
            if let Some(address) = select(&record.data) {
                if addresses.try_reserve(1).is_err() {
                    break;
                }
                addresses.push(address);
                ttl = ttl.min(record.ttl);
            }
        }
        if !addresses.is_empty() {
            return (addresses, ttl);
        }
        let alias = answers().find_map(|record| match &record.data {
            DnsRecordData::Name(target)
                if record.rtype.is(DnsQueryType::CNAME) && owner.owns(payload, record) =>
            {
                Some((target, record.ttl))
            }
            _ => None,
        });
        let Some((target, alias_ttl)) = alias else {
            break;
        };
        ttl = ttl.min(alias_ttl);
        owner = ChainOwner::Alias(target);
    }
    (addresses, ttl)
}

/// Caches the chained addresses of `response`, or NODATA when the chain
/// reached none, and returns the first address.
fn admit_answer<A: Copy>(
    cache: &PoisonLock<DnsCache<A>>,
    key: DnsCacheKey,
    query: &DnsNameOwned,
    qtype: DnsQueryType,
    response: &DnsResponseView,
    select: impl Fn(&DnsRecordData) -> Option<A>,
    current_tick: u64,
) -> Option<A> {
    let (addresses, ttl) = chain_addresses(response, query, qtype, &select);
    let first = addresses.first().copied();
    let (answer, ttl) = if addresses.is_empty() {
        (DnsCachedAnswer::Negative, DNS_NEGATIVE_CACHE_TTL_SECS)
    } else {
        (DnsCachedAnswer::Positive(addresses), ttl)
    };
    if let Ok(mut cache) = cache.lock() {
        cache.insert(key, answer, ttl, current_tick);
    }
    first
}

impl DnsClient {
    async fn resolve_address<A: Copy>(
        &self,
        name_text: &str,
        qtype: DnsQueryType,
        cache: &PoisonLock<DnsCache<A>>,
        select: impl Fn(&DnsRecordData) -> Option<A>,
    ) -> Option<A> {
        let current_tick = crate::task::current_tick();
        let name = DnsNameOwned::parse_ascii(name_text).ok()?;
        let key = DnsCacheKey::from_name(&name)?;
        match lookup_cached(cache, &key, current_tick) {
            CacheLookup::Hit(address) => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some(address);
            }
            CacheLookup::Negative => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            CacheLookup::Miss => {
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        let query = DnsNameOwned::parse_ascii(name_text).ok()?;
        let response = self.query_internal_name(name, qtype).await.ok()?;
        admit_answer(
            cache,
            key,
            &query,
            qtype,
            &response,
            select,
            crate::task::current_tick(),
        )
    }

    pub async fn resolve_ipv4(&self, name: &str) -> Option<Ipv4Address> {
        self.resolve_address(name, DnsQueryType::A, &self.ipv4_cache, |data| match data {
            DnsRecordData::A(addr) => Some(*addr),
            _ => None,
        })
        .await
    }

    pub async fn resolve_ipv6(&self, name: &str) -> Option<Ipv6Address> {
        self.resolve_address(
            name,
            DnsQueryType::AAAA,
            &self.ipv6_cache,
            |data| match data {
                DnsRecordData::AAAA(addr) => Some(*addr),
                _ => None,
            },
        )
        .await
    }

    pub async fn resolve_txt(&self, name: &str) -> Option<Vec<String>> {
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        let response = self
            .query_internal_name(name, DnsQueryType::TXT)
            .await
            .ok()?;
        let payload = &response.payload;
        let records = response
            .records
            .iter()
            .filter_map(|record| match &record.data {
                DnsRecordData::TXT(value) => dns_txt_view_to_string(payload, value),
                _ => None,
            })
            .collect::<Vec<_>>();
        (!records.is_empty()).then_some(records)
    }

    pub async fn resolve_srv(&self, name: &str) -> Option<Vec<DnsSrvRecord>> {
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        let response = self
            .query_internal_name(name, DnsQueryType::SRV)
            .await
            .ok()?;
        let payload = &response.payload;
        let records = response
            .records
            .iter()
            .filter_map(|record| match &record.data {
                DnsRecordData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                } => Some(DnsSrvRecord {
                    priority: *priority,
                    weight: *weight,
                    port: *port,
                    target: dns_name_view_to_string(payload, target)?,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        (!records.is_empty()).then_some(records)
    }

    pub async fn resolve_mx(&self, name: &str) -> Option<Vec<DnsMxRecord>> {
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        let response = self
            .query_internal_name(name, DnsQueryType::MX)
            .await
            .ok()?;
        let payload = &response.payload;
        let records = response
            .records
            .iter()
            .filter_map(|record| match &record.data {
                DnsRecordData::MX(preference, exchange) => Some(DnsMxRecord {
                    preference: *preference,
                    exchange: dns_name_view_to_string(payload, exchange)?,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        (!records.is_empty()).then_some(records)
    }

    pub async fn resolve_ptr_ipv4(&self, ip: Ipv4Address) -> Option<String> {
        let octets = ip.octets();
        let query = alloc::format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3],
            octets[2],
            octets[1],
            octets[0]
        );
        let name = DnsNameOwned::parse_ascii(&query).ok()?;
        let response = self
            .query_internal_name(name, DnsQueryType::PTR)
            .await
            .ok()?;
        let payload = &response.payload;
        response
            .records
            .iter()
            .find_map(|record| match &record.data {
                DnsRecordData::Name(name) => dns_name_view_to_string(payload, name),
                _ => None,
            })
    }

    pub async fn resolve_ptr_ipv6(&self, ip: Ipv6Address) -> Option<String> {
        let octets = ip.octets();
        let mut query = alloc::string::String::new();
        for byte in octets.iter().rev() {
            use alloc::fmt::Write as _;
            let _ = write!(query, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
        }
        query.push_str("ip6.arpa");
        let name = DnsNameOwned::parse_ascii(&query).ok()?;
        let response = self
            .query_internal_name(name, DnsQueryType::PTR)
            .await
            .ok()?;
        let payload = &response.payload;
        response
            .records
            .iter()
            .find_map(|record| match &record.data {
                DnsRecordData::Name(name) => dns_name_view_to_string(payload, name),
                _ => None,
            })
    }

    /// DNSクライアントのメインループ（非同期）
    ///
    /// キャッシュの定期的なクリーンアップなどを行います。
    pub async fn run(&self) -> Result<(), &'static str> {
        let cpu = crate::cpu::CurrentCpu::acquire()
            .map(|current| current.id())
            .ok_or("DNS service requires a CPU-local execution context")?;
        log::info!("[NET] DNS client task started on CPU {}", cpu);
        log::info!("[NET][boot] DNS client task stage: registering first cleanup timer");

        // LOOP_PROOF: mode=event; reason=The DNS service awaits its five-second cleanup timer on each iteration and returns when timer admission fails.;
        loop {
            crate::task::sleep_ms(5000)
                .await
                .map_err(|_| "DNS cleanup timer failed")?;

            let now = crate::task::current_tick();
            if let Ok(mut cache) = self.ipv4_cache.lock() {
                cache.cleanup(now);
            }
            if let Ok(mut cache) = self.ipv6_cache.lock() {
                cache.cleanup(now);
            }
            self.cleanup_stale_pending_ids(now);
        }
    }

    /// IPv4 DNSサーバーを設定
    pub fn set_ipv4_servers(&self, servers: &[Ipv4Address]) {
        match self.ipv4_servers.lock() {
            Ok(mut guard) => {
                guard.clear();
                guard.extend(servers.iter().copied().take(DNS_MAX_SERVERS));
            }
            Err(_) => log::error!(
                "[NET] DNS IPv4 Servers lock poisoned (set_ipv4_servers) - operation skipped"
            ),
        }
    }

    /// IPv6 DNSサーバーを設定
    pub fn set_ipv6_servers(&self, servers: &[Ipv6Address]) {
        match self.ipv6_servers.lock() {
            Ok(mut guard) => {
                guard.clear();
                guard.extend(servers.iter().copied().take(DNS_MAX_SERVERS));
            }
            Err(_) => log::error!(
                "[NET] DNS IPv6 Servers lock poisoned (set_ipv6_servers) - operation skipped"
            ),
        }
    }

    /// IPv4 DNSサーバーを追加
    pub fn add_ipv4_server(&self, server: Ipv4Address) {
        match self.ipv4_servers.lock() {
            Ok(mut servers) => {
                if !servers.contains(&server) && servers.len() < DNS_MAX_SERVERS {
                    servers.push(server);
                }
            }
            Err(_) => log::error!(
                "[NET] DNS IPv4 Servers lock poisoned (add_ipv4_server) - operation skipped"
            ),
        }
    }

    /// IPv6 DNSサーバーを追加
    pub fn add_ipv6_server(&self, server: Ipv6Address) {
        match self.ipv6_servers.lock() {
            Ok(mut servers) => {
                if !servers.contains(&server) && servers.len() < DNS_MAX_SERVERS {
                    servers.push(server);
                }
            }
            Err(_) => log::error!(
                "[NET] DNS IPv6 Servers lock poisoned (add_ipv6_server) - operation skipped"
            ),
        }
    }

    pub(crate) fn ipv4_servers_snapshot(&self) -> Vec<Ipv4Address> {
        match self.ipv4_servers.lock() {
            Ok(servers) => servers.iter().take(DNS_MAX_SERVERS).copied().collect(),
            Err(_) => {
                log::error!("[NET] DNS IPv4 Servers lock poisoned - no servers available");
                Vec::new()
            }
        }
    }

    pub(crate) fn ipv6_servers_snapshot(&self) -> Vec<Ipv6Address> {
        match self.ipv6_servers.lock() {
            Ok(servers) => servers.iter().take(DNS_MAX_SERVERS).copied().collect(),
            Err(_) => {
                log::error!("[NET] DNS IPv6 Servers lock poisoned - no servers available");
                Vec::new()
            }
        }
    }

    /// NXDOMAIN applies to every record type of the name (RFC 2308 Section 2.1).
    pub(super) fn cache_negative_response_for_name(
        &self,
        name: &DnsNameOwned,
        rcode: DnsResponseCode,
        current_tick: u64,
    ) {
        if rcode != DnsResponseCode::NameError {
            return;
        }
        let Some(key) = DnsCacheKey::from_name(name) else {
            return;
        };
        if let Ok(mut cache) = self.ipv4_cache.lock() {
            cache.insert(
                key.clone(),
                DnsCachedAnswer::Negative,
                DNS_NEGATIVE_CACHE_TTL_SECS,
                current_tick,
            );
        }
        if let Ok(mut cache) = self.ipv6_cache.lock() {
            cache.insert(
                key,
                DnsCachedAnswer::Negative,
                DNS_NEGATIVE_CACHE_TTL_SECS,
                current_tick,
            );
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &DnsStats {
        &self.stats
    }

    /// Number of live cache entries per address family `(A, AAAA)`.
    pub fn cache_len(&self) -> (usize, usize) {
        let v4 = self.ipv4_cache.lock().map_or(0, |cache| cache.len());
        let v6 = self.ipv6_cache.lock().map_or(0, |cache| cache.len());
        (v4, v6)
    }
}
