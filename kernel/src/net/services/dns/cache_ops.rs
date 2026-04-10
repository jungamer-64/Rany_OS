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
    fn cache_key_for_name(name: &str) -> Option<DnsNameOwned> {
        DnsNameOwned::from_ascii_name(name)
    }

    fn cache_key_for_view(name: &DnsNameView) -> DnsNameOwned {
        DnsNameOwned::from_view(name)
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

    /// 非同期でTXTレコードを解決
    pub async fn resolve_txt(&self, name: &str) -> Option<Vec<DnsTxtView>> {
        let tick = crate::task::current_tick();
        let key = Self::cache_key_for_name(name)?;

        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.lookup(&key, tick) {
                if entry.negative {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                let cached = self.resolve_txt_from_records(&entry.records, name);
                if !cached.is_empty() {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(cached);
                }
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let response = self.query_internal(name, DnsQueryType::TXT).await.ok()?;
        let records = self.resolve_txt_from_records(&response.records, name);
        (!records.is_empty()).then_some(records)
    }

    /// 非同期でMXレコードを解決
    pub async fn resolve_mx(&self, name: &str) -> Option<Vec<DnsMxRecord>> {
        let tick = crate::task::current_tick();
        let key = Self::cache_key_for_name(name)?;

        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.lookup(&key, tick) {
                if entry.negative {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                let cached = self.resolve_mx_from_records(&entry.records, name);
                if !cached.is_empty() {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(cached);
                }
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let response = self.query_internal(name, DnsQueryType::MX).await.ok()?;
        let records = self.resolve_mx_from_records(&response.records, name);
        (!records.is_empty()).then_some(records)
    }

    /// 非同期でSRVレコードを解決
    pub async fn resolve_srv(&self, name: &str) -> Option<Vec<DnsSrvRecord>> {
        let tick = crate::task::current_tick();
        let key = Self::cache_key_for_name(name)?;

        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.lookup(&key, tick) {
                if entry.negative {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                let cached = self.resolve_srv_from_records(&entry.records, name);
                if !cached.is_empty() {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(cached);
                }
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let response = self.query_internal(name, DnsQueryType::SRV).await.ok()?;
        let records = self.resolve_srv_from_records(&response.records, name);
        (!records.is_empty()).then_some(records)
    }

    /// 非同期でIPv4アドレスの逆引き（PTR）を解決
    pub async fn resolve_ptr_ipv4(&self, ip: Ipv4Address) -> Option<DnsNameView> {
        let query_name = Self::ptr_ipv4_query_name(ip);
        let tick = crate::task::current_tick();
        let key = Self::cache_key_for_view(&query_name.as_view());

        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.lookup(&key, tick) {
                if entry.negative {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                if let Some(cached) = self.resolve_ptr_from_records(&entry.records, &query_name) {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(cached);
                }
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let response = self
            .query_internal_name(query_name.clone(), DnsQueryType::PTR)
            .await
            .ok()?;
        self.resolve_ptr_from_records(&response.records, &query_name)
    }

    /// 非同期でIPv6アドレスの逆引き（PTR）を解決
    pub async fn resolve_ptr_ipv6(&self, ip: Ipv6Address) -> Option<DnsNameView> {
        let query_name = Self::ptr_ipv6_query_name(ip);
        let tick = crate::task::current_tick();
        let key = Self::cache_key_for_view(&query_name.as_view());

        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.lookup(&key, tick) {
                if entry.negative {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                if let Some(cached) = self.resolve_ptr_from_records(&entry.records, &query_name) {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(cached);
                }
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let response = self
            .query_internal_name(query_name.clone(), DnsQueryType::PTR)
            .await
            .ok()?;
        self.resolve_ptr_from_records(&response.records, &query_name)
    }

    fn lookup_ipv4_cache(&self, name: &str, current_tick: u64) -> Ipv4CacheLookup {
        let Some(key) = Self::cache_key_for_name(name) else {
            return Ipv4CacheLookup::Miss;
        };
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
        let Some(key) = Self::cache_key_for_name(name) else {
            return Ipv6CacheLookup::Miss;
        };
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

    fn cname_target_for_name(
        &self,
        records: &[DnsRecordMeta],
        name: &DnsNameOwned,
    ) -> Option<DnsNameOwned> {
        records.iter().find_map(|record| {
            if record.rtype.is(DnsQueryType::CNAME)
                && compare_dns_name_labels(record.name.labels(), name.labels())
                    == core::cmp::Ordering::Equal
            {
                if let DnsRecordData::Name(alias) = &record.data {
                    return Some(DnsNameOwned::from_view(alias));
                }
            }
            None
        })
    }

    fn resolve_txt_from_records(
        &self,
        records: &[DnsRecordMeta],
        query_name: &str,
    ) -> Vec<DnsTxtView> {
        records
            .iter()
            .filter(|record| {
                record.rtype.is(DnsQueryType::TXT) && record.name.eq_ignore_ascii_case(query_name)
            })
            .filter_map(|record| {
                if let DnsRecordData::TXT(txt) = &record.data {
                    Some(txt.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    fn resolve_mx_from_records(
        &self,
        records: &[DnsRecordMeta],
        query_name: &str,
    ) -> Vec<DnsMxRecord> {
        records
            .iter()
            .filter(|record| {
                record.rtype.is(DnsQueryType::MX) && record.name.eq_ignore_ascii_case(query_name)
            })
            .filter_map(|record| {
                if let DnsRecordData::MX(preference, exchange) = &record.data {
                    Some(DnsMxRecord {
                        preference: *preference,
                        exchange: exchange.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn resolve_srv_from_records(
        &self,
        records: &[DnsRecordMeta],
        query_name: &str,
    ) -> Vec<DnsSrvRecord> {
        records
            .iter()
            .filter(|record| {
                record.rtype.is(DnsQueryType::SRV) && record.name.eq_ignore_ascii_case(query_name)
            })
            .filter_map(|record| {
                if let DnsRecordData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                } = &record.data
                {
                    Some(DnsSrvRecord {
                        priority: *priority,
                        weight: *weight,
                        port: *port,
                        target: target.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn resolve_ptr_from_records(
        &self,
        records: &[DnsRecordMeta],
        query_name: &DnsNameOwned,
    ) -> Option<DnsNameView> {
        let mut current = query_name.clone();

        for _ in 0..DNS_MAX_CNAME_DEPTH {
            if let Some(hostname) = records.iter().find_map(|record| {
                if compare_dns_name_labels(record.name.labels(), current.labels())
                    == core::cmp::Ordering::Equal
                    && record.rtype.is(DnsQueryType::PTR)
                {
                    if let DnsRecordData::Name(hostname) = &record.data {
                        return Some(hostname.clone());
                    }
                }
                None
            }) {
                return Some(hostname);
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

    pub(super) fn ptr_ipv4_query_name(ip: Ipv4Address) -> DnsNameOwned {
        let octets = ip.octets();
        DnsNameOwned::from_ascii_name(&alloc::format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3],
            octets[2],
            octets[1],
            octets[0]
        ))
        .expect("PTR IPv4 query name must be valid")
    }

    fn hex_nibble(value: u8) -> char {
        match value & 0x0f {
            0..=9 => (b'0' + (value & 0x0f)) as char,
            _ => (b'a' + ((value & 0x0f) - 10)) as char,
        }
    }

    pub(super) fn ptr_ipv6_query_name(ip: Ipv6Address) -> DnsNameOwned {
        let octets = ip.octets();
        let mut out = String::with_capacity(32 * 2 + "ip6.arpa".len());
        for byte in octets.iter().rev() {
            out.push(Self::hex_nibble(*byte));
            out.push('.');
            out.push(Self::hex_nibble(*byte >> 4));
            out.push('.');
        }
        out.push_str("ip6.arpa");
        DnsNameOwned::from_ascii_name(&out).expect("PTR IPv6 query name must be valid")
    }

    pub(super) fn resolve_ipv4_from_records(
        &self,
        records: &[DnsRecordMeta],
        query_name: &str,
    ) -> Option<Ipv4Address> {
        let mut current = Self::cache_key_for_name(query_name)?;

        for _ in 0..DNS_MAX_CNAME_DEPTH {
            if let Some(ip) = records.iter().find_map(|record| {
                if compare_dns_name_labels(record.name.labels(), current.labels())
                    == core::cmp::Ordering::Equal
                    && record.rtype.is(DnsQueryType::A)
                {
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
        let mut current = Self::cache_key_for_name(query_name)?;

        for _ in 0..DNS_MAX_CNAME_DEPTH {
            if let Some(ip) = records.iter().find_map(|record| {
                if compare_dns_name_labels(record.name.labels(), current.labels())
                    == core::cmp::Ordering::Equal
                    && record.rtype.is(DnsQueryType::AAAA)
                {
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

    /// DNSレコードをキャッシュに追加する
    pub(super) fn cache_dns_response(
        &self,
        name: &str,
        response: &DnsResponseView,
        current_tick: u64,
    ) {
        let Some(key) = Self::cache_key_for_name(name) else {
            return;
        };
        self.cache_dns_response_for_key(key, response, current_tick);
    }

    pub(super) fn cache_dns_response_for_name(
        &self,
        name: &DnsNameView,
        response: &DnsResponseView,
        current_tick: u64,
    ) {
        self.cache_dns_response_for_key(Self::cache_key_for_view(name), response, current_tick);
    }

    fn cache_dns_response_for_key(
        &self,
        key: DnsNameOwned,
        response: &DnsResponseView,
        current_tick: u64,
    ) {
        if response.records.is_empty() {
            return;
        }

        match self.cache.lock() {
            Ok(mut cache) => {
                cache.insert(
                    key,
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
        let Some(key) = Self::cache_key_for_name(name) else {
            return;
        };
        self.cache_negative_response_for_key(key, rcode, current_tick);
    }

    pub(super) fn cache_negative_response_for_name(
        &self,
        name: &DnsNameView,
        rcode: DnsResponseCode,
        current_tick: u64,
    ) {
        self.cache_negative_response_for_key(Self::cache_key_for_view(name), rcode, current_tick);
    }

    fn cache_negative_response_for_key(
        &self,
        key: DnsNameOwned,
        rcode: DnsResponseCode,
        current_tick: u64,
    ) {
        if rcode != DnsResponseCode::NameError {
            return;
        }

        match self.cache.lock() {
            Ok(mut cache) => {
                cache.insert_negative(key, rcode, current_tick, DNS_NEGATIVE_CACHE_TTL_SECS);
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
