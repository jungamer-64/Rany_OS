// ============================================================================
// kernel/src/net/services/dns/cache_ops.rs - サービス / DNS / cache ops
// ============================================================================

use super::*;

enum Ipv4CacheLookup {
    Hit(Ipv4Address),
    Negative,
    Miss,
}

enum Ipv6CacheLookup {
    Hit(Ipv6Address),
    Negative,
    Miss,
}

impl DnsClient {
    fn cached_ipv4_lookup(&self, name: &DnsNameOwned, current_tick: u64) -> Ipv4CacheLookup {
        let Ok(cache) = self.cache.lock() else {
            return Ipv4CacheLookup::Miss;
        };
        let Some(entry) = cache.lookup(name, current_tick) else {
            return Ipv4CacheLookup::Miss;
        };
        if entry.negative {
            return Ipv4CacheLookup::Negative;
        }
        entry.records
            .iter()
            .find_map(|record| match record.data {
                DnsRecordData::A(addr) => Some(Ipv4CacheLookup::Hit(addr)),
                _ => None,
            })
            .unwrap_or(Ipv4CacheLookup::Miss)
    }

    fn cached_ipv6_lookup(&self, name: &DnsNameOwned, current_tick: u64) -> Ipv6CacheLookup {
        let Ok(cache) = self.cache.lock() else {
            return Ipv6CacheLookup::Miss;
        };
        let Some(entry) = cache.lookup(name, current_tick) else {
            return Ipv6CacheLookup::Miss;
        };
        if entry.negative {
            return Ipv6CacheLookup::Negative;
        }
        entry.records
            .iter()
            .find_map(|record| match record.data {
                DnsRecordData::AAAA(addr) => Some(Ipv6CacheLookup::Hit(addr)),
                _ => None,
            })
            .unwrap_or(Ipv6CacheLookup::Miss)
    }

    pub fn resolve_cached(&self, name: &str, current_tick: u64) -> Option<Ipv4Address> {
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        match self.cached_ipv4_lookup(&name, current_tick) {
            Ipv4CacheLookup::Hit(addr) => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                Some(addr)
            }
            Ipv4CacheLookup::Negative | Ipv4CacheLookup::Miss => {
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub async fn resolve_ipv4(&self, name: &str) -> Option<Ipv4Address> {
        let current_tick = crate::task::current_tick();
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        match self.cached_ipv4_lookup(&name, current_tick) {
            Ipv4CacheLookup::Hit(addr) => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some(addr);
            }
            Ipv4CacheLookup::Negative => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            Ipv4CacheLookup::Miss => {
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        let response = self.query_internal_name(name, DnsQueryType::A).await.ok()?;
        response.records.iter().find_map(|record| match record.data {
            DnsRecordData::A(addr) => Some(addr),
            _ => None,
        })
    }

    pub async fn resolve_ipv6(&self, name: &str) -> Option<Ipv6Address> {
        let current_tick = crate::task::current_tick();
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        match self.cached_ipv6_lookup(&name, current_tick) {
            Ipv6CacheLookup::Hit(addr) => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some(addr);
            }
            Ipv6CacheLookup::Negative => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            Ipv6CacheLookup::Miss => {
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        let response = self.query_internal_name(name, DnsQueryType::AAAA).await.ok()?;
        response.records.iter().find_map(|record| match record.data {
            DnsRecordData::AAAA(addr) => Some(addr),
            _ => None,
        })
    }

    pub async fn resolve_txt(&self, name: &str) -> Option<Vec<DnsTxtView>> {
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        let response = self.query_internal_name(name, DnsQueryType::TXT).await.ok()?;
        let records = response
            .records
            .into_iter()
            .filter_map(|record| match record.data {
                DnsRecordData::TXT(value) => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();
        (!records.is_empty()).then_some(records)
    }

    pub async fn resolve_srv(&self, name: &str) -> Option<Vec<DnsSrvRecord>> {
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        let response = self.query_internal_name(name, DnsQueryType::SRV).await.ok()?;
        let records = response
            .records
            .into_iter()
            .filter_map(|record| match record.data {
                DnsRecordData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                } => Some(DnsSrvRecord {
                    priority,
                    weight,
                    port,
                    target,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        (!records.is_empty()).then_some(records)
    }

    pub async fn resolve_mx(&self, name: &str) -> Option<Vec<DnsMxRecord>> {
        let name = DnsNameOwned::parse_ascii(name).ok()?;
        let response = self.query_internal_name(name, DnsQueryType::MX).await.ok()?;
        let records = response
            .records
            .into_iter()
            .filter_map(|record| match record.data {
                DnsRecordData::MX(preference, exchange) => Some(DnsMxRecord {
                    preference,
                    exchange,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        (!records.is_empty()).then_some(records)
    }

    pub async fn resolve_ptr_ipv4(&self, ip: Ipv4Address) -> Option<DnsNameView> {
        let octets = ip.octets();
        let query = alloc::format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        );
        let name = DnsNameOwned::parse_ascii(&query).ok()?;
        let response = self.query_internal_name(name, DnsQueryType::PTR).await.ok()?;
        response.records.into_iter().find_map(|record| match record.data {
            DnsRecordData::Name(name) => Some(name),
            _ => None,
        })
    }

    pub async fn resolve_ptr_ipv6(&self, ip: Ipv6Address) -> Option<DnsNameView> {
        let octets = ip.octets();
        let mut query = alloc::string::String::new();
        for byte in octets.iter().rev() {
            use alloc::fmt::Write as _;
            let _ = write!(query, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
        }
        query.push_str("ip6.arpa");
        let name = DnsNameOwned::parse_ascii(&query).ok()?;
        let response = self.query_internal_name(name, DnsQueryType::PTR).await.ok()?;
        response.records.into_iter().find_map(|record| match record.data {
            DnsRecordData::Name(name) => Some(name),
            _ => None,
        })
    }

    /// DNSクライアントのメインループ（非同期）
    ///
    /// キャッシュの定期的なクリーンアップなどを行います。
    pub async fn run(&self) -> Result<(), &'static str> {
        log::info!(
            "[NET] DNS client task started on CPU {}",
            crate::cpu::try_current_id().unwrap_or(0)
        );
        log::info!("[NET][boot] DNS client task stage: registering first cleanup timer");

        loop {
            crate::task::sleep_ms(5000).await;

            let now = crate::task::current_tick();
            if let Ok(mut cache) = self.cache.lock() {
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

    pub(super) fn ipv4_servers_snapshot(&self) -> Vec<Ipv4Address> {
        match self.ipv4_servers.lock() {
            Ok(servers) => servers.iter().take(DNS_MAX_SERVERS).copied().collect(),
            Err(_) => {
                log::error!("[NET] DNS IPv4 Servers lock poisoned - no servers available");
                Vec::new()
            }
        }
    }

    pub(super) fn ipv6_servers_snapshot(&self) -> Vec<Ipv6Address> {
        match self.ipv6_servers.lock() {
            Ok(servers) => servers.iter().take(DNS_MAX_SERVERS).copied().collect(),
            Err(_) => {
                log::error!("[NET] DNS IPv6 Servers lock poisoned - no servers available");
                Vec::new()
            }
        }
    }

    /// 期限切れキャッシュエントリをクリーンアップ
    pub fn cleanup_cache(&self, current_tick: u64) {
        match self.cache.lock() {
            Ok(mut cache) => cache.cleanup(current_tick),
            Err(_) => {
                log::error!("[NET] DNS Cache lock poisoned (cleanup_cache) - operation skipped")
            }
        }
    }

    pub(super) fn cache_dns_response_for_name(
        &self,
        name: &DnsNameOwned,
        response: &DnsResponseView,
        current_tick: u64,
    ) {
        let _ = (name, response, current_tick);
    }

    pub(super) fn cache_negative_response_for_name(
        &self,
        name: &DnsNameOwned,
        rcode: DnsResponseCode,
        current_tick: u64,
    ) {
        let _ = (name, rcode, current_tick);
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &DnsStats {
        &self.stats
    }

    /// プライマリIPv4 DNSサーバーを取得
    pub fn primary_ipv4_server(&self) -> Option<Ipv4Address> {
        match self.ipv4_servers.lock() {
            Ok(servers) => servers.first().copied(),
            Err(_) => {
                log::error!("[NET] DNS IPv4 Servers lock poisoned - returning None");
                None
            }
        }
    }

    /// プライマリIPv6 DNSサーバーを取得
    pub fn primary_ipv6_server(&self) -> Option<Ipv6Address> {
        match self.ipv6_servers.lock() {
            Ok(servers) => servers.first().copied(),
            Err(_) => {
                log::error!("[NET] DNS IPv6 Servers lock poisoned - returning None");
                None
            }
        }
    }
}
