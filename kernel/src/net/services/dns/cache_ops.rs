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
    pub fn set_ipv4_servers(&self, servers: Vec<Ipv4Address>) {
        match self.ipv4_servers.lock() {
            Ok(mut guard) => *guard = servers,
            Err(_) => log::error!(
                "[NET] DNS IPv4 Servers lock poisoned (set_ipv4_servers) - operation skipped"
            ),
        }
    }

    /// IPv6 DNSサーバーを設定
    pub fn set_ipv6_servers(&self, servers: Vec<Ipv6Address>) {
        match self.ipv6_servers.lock() {
            Ok(mut guard) => *guard = servers,
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

    /// キャッシュからIPアドレスを検索
    pub fn resolve_cached(&self, name: &str, current_tick: u64) -> Option<Ipv4Address> {
        match self.lookup_ipv4_cache(name, current_tick) {
            Ipv4CacheLookup::Hit(ip) => Some(ip),
            Ipv4CacheLookup::Negative | Ipv4CacheLookup::Miss => None,
        }
    }

    /// 非同期でIPアドレスを解決 (IPv4)
    pub async fn resolve_ipv4(&self, name: &str) -> Option<Ipv4Address> {
        let tick = crate::task::current_tick();

        match self.lookup_ipv4_cache(name, tick) {
            Ipv4CacheLookup::Hit(ip) => return Some(ip),
            Ipv4CacheLookup::Negative => return None,
            Ipv4CacheLookup::Miss => {}
        }

        let response = self.query_internal(name, DnsQueryType::A).await.ok()?;
        self.resolve_ipv4_from_records(&response.records, name)
    }

    /// 非同期でIPアドレスを解決 (IPv6)
    pub async fn resolve_ipv6(&self, name: &str) -> Option<Ipv6Address> {
        let tick = crate::task::current_tick();

        match self.lookup_ipv6_cache(name, tick) {
            Ipv6CacheLookup::Hit(ip) => return Some(ip),
            Ipv6CacheLookup::Negative => return None,
            Ipv6CacheLookup::Miss => {}
        }

        let response = self.query_internal(name, DnsQueryType::AAAA).await.ok()?;
        self.resolve_ipv6_from_records(&response.records, name)
    }

    fn lookup_ipv4_cache(&self, name: &str, current_tick: u64) -> Ipv4CacheLookup {
        let key = name.to_ascii_lowercase();
        let result = match self.cache.lock() {
            Ok(cache) => {
                if let Some(entry) = cache.lookup(&key, current_tick) {
                    if entry.negative {
                        Ipv4CacheLookup::Negative
                    } else if let Some(ip) = self.resolve_ipv4_from_records(&entry.records, name) {
                        Ipv4CacheLookup::Hit(ip)
                    } else {
                        Ipv4CacheLookup::Miss
                    }
                } else {
                    Ipv4CacheLookup::Miss
                }
            }
            Err(_) => {
                log::error!(
                    "[NET] DNS Cache lock poisoned (lookup_ipv4_cache) - treating as cache miss"
                );
                Ipv4CacheLookup::Miss
            }
        };

        match result {
            Ipv4CacheLookup::Hit(_) | Ipv4CacheLookup::Negative => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            Ipv4CacheLookup::Miss => {
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }

    fn lookup_ipv6_cache(&self, name: &str, current_tick: u64) -> Ipv6CacheLookup {
        let key = name.to_ascii_lowercase();
        let result = match self.cache.lock() {
            Ok(cache) => {
                if let Some(entry) = cache.lookup(&key, current_tick) {
                    if entry.negative {
                        Ipv6CacheLookup::Negative
                    } else if let Some(ip) = self.resolve_ipv6_from_records(&entry.records, name) {
                        Ipv6CacheLookup::Hit(ip)
                    } else {
                        Ipv6CacheLookup::Miss
                    }
                } else {
                    Ipv6CacheLookup::Miss
                }
            }
            Err(_) => {
                log::error!(
                    "[NET] DNS Cache lock poisoned (lookup_ipv6_cache) - treating as cache miss"
                );
                Ipv6CacheLookup::Miss
            }
        };

        match result {
            Ipv6CacheLookup::Hit(_) | Ipv6CacheLookup::Negative => {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            Ipv6CacheLookup::Miss => {
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }

    fn cname_target_for_name(&self, records: &[DnsRecordMeta], name: &str) -> Option<String> {
        records.iter().find_map(|record| {
            if record.rtype == DnsQueryType::CNAME && record.name.eq_ignore_ascii_case(name) {
                if let DnsRecordData::Name(alias) = &record.data {
                    return Some(alias.to_lowercase_string());
                }
            }
            None
        })
    }

    pub(super) fn resolve_ipv4_from_records(
        &self,
        records: &[DnsRecordMeta],
        query_name: &str,
    ) -> Option<Ipv4Address> {
        let mut current = query_name.to_ascii_lowercase();

        for _ in 0..DNS_MAX_CNAME_DEPTH {
            if let Some(ip) = records.iter().find_map(|record| {
                if record.name.eq_ignore_ascii_case(&current) {
                    if let DnsRecordData::A(ip) = &record.data {
                        return Some(*ip);
                    }
                }
                None
            }) {
                return Some(ip);
            }

            let Some(next) = self.cname_target_for_name(records, &current) else {
                return None;
            };
            if next == current {
                return None;
            }
            current = next;
        }

        None
    }

    pub(super) fn resolve_ipv6_from_records(
        &self,
        records: &[DnsRecordMeta],
        query_name: &str,
    ) -> Option<Ipv6Address> {
        let mut current = query_name.to_ascii_lowercase();

        for _ in 0..DNS_MAX_CNAME_DEPTH {
            if let Some(ip) = records.iter().find_map(|record| {
                if record.name.eq_ignore_ascii_case(&current) {
                    if let DnsRecordData::AAAA(ip) = &record.data {
                        return Some(*ip);
                    }
                }
                None
            }) {
                return Some(ip);
            }

            let Some(next) = self.cname_target_for_name(records, &current) else {
                return None;
            };
            if next == current {
                return None;
            }
            current = next;
        }

        None
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

    /// 期限切れキャッシュエントリをクリーンアップ
    pub fn cleanup_cache(&self, current_tick: u64) {
        match self.cache.lock() {
            Ok(mut cache) => cache.cleanup(current_tick),
            Err(_) => {
                log::error!("[NET] DNS Cache lock poisoned (cleanup_cache) - operation skipped")
            }
        }
    }

    /// DNSレコードをキャッシュに追加する
    pub(super) fn cache_dns_response(
        &self,
        name: &str,
        response: &DnsResponseView,
        current_tick: u64,
    ) {
        if response.records.is_empty() {
            return;
        }

        match self.cache.lock() {
            Ok(mut cache) => {
                cache.insert(
                    name.to_ascii_lowercase(),
                    response.payload.clone(),
                    response.records.clone(),
                    current_tick,
                );
            }
            Err(_) => {
                log::error!(
                    "[NET] DNS Cache lock poisoned (cache_dns_response) - skipping cache insert"
                )
            }
        }
    }

    pub(super) fn cache_negative_response(
        &self,
        name: &str,
        rcode: DnsResponseCode,
        current_tick: u64,
    ) {
        if rcode != DnsResponseCode::NameError {
            return;
        }

        match self.cache.lock() {
            Ok(mut cache) => {
                cache.insert_negative(
                    name.to_ascii_lowercase(),
                    rcode,
                    current_tick,
                    DNS_NEGATIVE_CACHE_TTL_SECS,
                );
            }
            Err(_) => {
                log::error!(
                    "[NET] DNS Cache lock poisoned (cache_negative_response) - skipping cache insert"
                )
            }
        }
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
