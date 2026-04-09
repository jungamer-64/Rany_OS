use super::*;
use crate::net::l4::udp::UdpAddr;
use crate::task::{self, TimeoutResult};

impl DnsClient {
    /// 新しいDNSクライアントを作成
    pub fn new(tick_rate: u64) -> Self {
        Self {
            ipv4_servers: PoisonLock::new(Vec::new()),
            ipv6_servers: PoisonLock::new(Vec::new()),
            cache: PoisonLock::new(DnsCache::new(tick_rate)),
            stats: DnsStats::new(),
            pending_ids: PoisonLock::new(BTreeMap::new()),
        }
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
            // 5秒ごとにキャッシュをクリーンアップ
            crate::task::sleep_ms(5000).await;

            let now = crate::task::current_tick();
            if let Ok(mut cache) = self.cache.lock() {
                cache.cleanup(now);
            }
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
                if !servers.contains(&server) && servers.len() < 3 {
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
                if !servers.contains(&server) && servers.len() < 3 {
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
        match self.cache.lock() {
            Ok(cache) => {
                if let Some(entry) = cache.lookup(name, current_tick) {
                    for record in &entry.records {
                        if let DnsRecordData::A(ip) = &record.data {
                            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                            return Some(*ip);
                        }
                    }
                }
            }
            Err(_) => {
                log::error!(
                    "[NET] DNS Cache lock poisoned (resolve_cached) - treating as cache miss"
                );
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// 非同期でIPアドレスを解決 (IPv4)
    pub async fn resolve_ipv4(&self, name: &str) -> Option<Ipv4Address> {
        let tick = crate::task::current_tick();

        // 1. まずキャッシュをチェック
        if let Some(ip) = self.resolve_cached(name, tick) {
            return Some(ip);
        }

        // 2. キャッシュになければネットワーククエリを実行
        let records = self.query_internal(name, DnsQueryType::A).await.ok()?;

        // Security: 結果を名前でフィルタリング (RFC 5452)
        for record in records {
            if record.name.to_lowercase() == name.to_lowercase() {
                if let DnsRecordData::A(ip) = record.data {
                    return Some(ip);
                }
            }
        }
        None
    }

    /// 非同期でIPアドレスを解決 (IPv6)
    pub async fn resolve_ipv6(&self, name: &str) -> Option<Ipv6Address> {
        let tick = crate::task::current_tick();

        // 1. まずキャッシュをチェック
        match self.cache.lock() {
            Ok(cache) => {
                if let Some(entry) = cache.lookup(name, tick) {
                    for record in &entry.records {
                        if let DnsRecordData::AAAA(ip) = &record.data {
                            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                            return Some(*ip);
                        }
                    }
                }
            }
            Err(_) => {}
        }

        // 2. キャッシュになければネットワーククエリを実行
        let records = self.query_internal(name, DnsQueryType::AAAA).await.ok()?;

        // Security: 結果を名前でフィルタリング (RFC 5452)
        for record in records {
            if record.name.to_lowercase() == name.to_lowercase() {
                if let DnsRecordData::AAAA(ip) = record.data {
                    return Some(ip);
                }
            }
        }
        None
    }

    /// Internal DNS query logic with UDP-to-TCP fallback (RFC 7766)
    async fn query_internal(
        &self,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<Vec<DnsRecord>, &'static str> {
        let tick = crate::task::current_tick();
        let server = self
            .primary_ipv4_server()
            .ok_or("No DNS server configured")?;

        // Try UDP first
        let socket = crate::net::l4::udp::UdpEndpoint::bind_in(
            crate::net::runtime::default_runtime(),
            crate::net::types::InterfaceScope::Any,
            0,
            None,
        )
        .map_err(|_| "Failed to bind UDP")?;
        let mut buffer = [0u8; 512];
        let query_len = self.build_query(&mut buffer, name, qtype)?;

        let dest = UdpAddr::new(server, DNS_PORT);
        let query_payload = crate::net::payload::payload_from_bytes(&buffer[..query_len])
            .ok_or("UDP send failed")?;
        if socket.send(query_payload, dest).await.is_err() {
            return Err("UDP send failed");
        }

        let mut attempt = 0;
        let mut udp_response = None;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while attempt < DNS_MAX_RETRIES {
            match task::with_timeout(socket.recv(), DNS_RETRY_TIMEOUT_MS).await {
                TimeoutResult::Completed(Some((_if_id, src, _ttl, packet))) => {
                    // Security: Verify source (RFC 5452)
                    if src.ip_v4() == Some(server) && src.port() == DNS_PORT {
                        udp_response = Some(packet);
                        break;
                    }
                }
                _ => {
                    attempt += 1;
                    if attempt < DNS_MAX_RETRIES {
                        if let Some(query_payload) =
                            crate::net::payload::payload_from_bytes(&buffer[..query_len])
                        {
                            let _ = socket.send(query_payload, dest).await;
                        }
                    }
                }
            }
        }

        if let Some(data) = udp_response {
            let parsed = self.parse_response_payload(&data, tick, name, qtype);

            if let Some(parsed) = parsed {
                return parsed.map_err(|_| "Parse error");
            }

            log::info!("[NET] DNS: UDP response truncated, retrying with TCP (RFC 7766 fallback)");
            return self.query_tcp(server, name, qtype).await;
        }

        Err("DNS query timed out")
    }

    /// DNS query over TCP (RFC 7766)
    async fn query_tcp(
        &self,
        server: Ipv4Address,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<Vec<DnsRecord>, &'static str> {
        fn payload_to_vec(
            payload: &kernel_api::resource::net::PacketPayload,
        ) -> Result<alloc::vec::Vec<u8>, &'static str> {
            let view = crate::net::payload::PacketPayloadView::new(payload);
            let len = view.total_len();
            let mut buf = alloc::vec![0u8; len];
            if view.copy_all_into(&mut buf) != len {
                return Err("TCP payload copy failed");
            }
            Ok(buf)
        }

        async fn read_exact_payload(
            connection: &mut crate::net::l4::tcp::TcpConnection,
            stash: &mut alloc::vec::Vec<u8>,
            dst: &mut [u8],
        ) -> Result<usize, &'static str> {
            let mut copied = 0usize;
            while copied < dst.len() {
                if !stash.is_empty() {
                    let take = (dst.len() - copied).min(stash.len());
                    dst[copied..copied + take].copy_from_slice(&stash[..take]);
                    stash.drain(..take);
                    copied += take;
                    continue;
                }

                let Some(payload) = connection.recv_payload().await else {
                    break;
                };
                let bytes = payload_to_vec(&payload)?;
                if bytes.is_empty() {
                    break;
                }
                stash.extend_from_slice(&bytes);
            }
            Ok(copied)
        }

        use crate::net::l4::endpoint::types::EndpointAddr;
        let dest = EndpointAddr::new(server.octets(), DNS_PORT);

        let mut connection =
            crate::net::l4::tcp::TcpConnection::dial_in(crate::net::runtime::default_runtime(), dest)
                .await
                .map_err(|_| "TCP connection failed")?;

        let mut buffer = [0u8; 1024];
        let query_len = self.build_tcp_query(&mut buffer, name, qtype)?;

        let payload = crate::net::payload::payload_from_bytes(&buffer[..query_len])
            .ok_or("TCP payload allocation failed")?;
        connection
            .send_payload(payload)
            .await
            .map_err(|_| "TCP write failed")?;
        connection
            .drain_tx()
            .await
            .map_err(|_| "TCP write drain failed")?;

        let mut stash = alloc::vec::Vec::new();

        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        let len_read = read_exact_payload(&mut connection, &mut stash, &mut len_buf).await?;
        if len_read != 2 {
            return Err("TCP read length prefix failed (connection closed or incomplete)");
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > 65535 {
            return Err("TCP message too long");
        }

        let mut msg_data = alloc::vec![0u8; msg_len];
        let total_read = read_exact_payload(&mut connection, &mut stash, &mut msg_data).await?;

        if total_read != msg_len {
            return Err("TCP read incomplete message");
        }

        let tick = crate::task::current_tick();
        self.parse_response(&msg_data, tick, name, qtype)
            .map_err(|_| "Parse error")
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

        // トランザクションIDを生成 (RFC 5452: 予測困難なIDを使用)
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let id = u16::from_le_bytes([random_bytes[0], random_bytes[1]]);

        // ヘッダを構築
        buffer[0..2].copy_from_slice(&id.to_be_bytes());
        // フラグ: 標準クエリ、再帰希望
        buffer[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        buffer[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        buffer[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buffer[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1 (EDNS0)

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
            // Security: Check bounds before writing
            if offset + 1 + len > buffer.len() {
                return Err("Buffer too small for name");
            }
            buffer[offset] = len as u8;
            offset += 1;
            buffer[offset..offset + len].copy_from_slice(label.as_bytes());
            offset += len;
        }

        // 終端のゼロ
        if offset >= buffer.len() {
            return Err("Buffer too small for zero terminator");
        }
        buffer[offset] = 0;
        offset += 1;

        // QTYPE
        if offset + 2 > buffer.len() {
            return Err("Buffer too small for QTYPE");
        }
        buffer[offset..offset + 2].copy_from_slice(&(qtype as u16).to_be_bytes());
        offset += 2;

        // QCLASS (IN = 1)
        if offset + 2 > buffer.len() {
            return Err("Buffer too small for QCLASS");
        }
        buffer[offset..offset + 2].copy_from_slice(&(DnsQueryClass::IN as u16).to_be_bytes());
        offset += 2;

        // EDNS0 OPT RR (RFC 6891)
        if offset + 11 > buffer.len() {
            return Err("Buffer too small for EDNS0 OPT");
        }
        buffer[offset] = 0; // Name: root (empty)
        offset += 1;
        buffer[offset..offset + 2].copy_from_slice(&(DnsQueryType::OPT as u16).to_be_bytes());
        offset += 2;
        // UDP Payload Size: 4096 (0x1000)
        buffer[offset..offset + 2].copy_from_slice(&4096u16.to_be_bytes());
        offset += 2;
        // Extended RCODE and flags
        buffer[offset..offset + 4].copy_from_slice(&0u32.to_be_bytes());
        offset += 4;
        // RDLENGTH: 0
        buffer[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes());
        offset += 2;

        self.stats.queries_sent.fetch_add(1, Ordering::Relaxed);

        // Security: トランザクションIDを保留中クエリに登録 (RFC 5452 キャッシュポイズニング防止)
        if let Ok(mut pending) = self.pending_ids.lock() {
            // 膨張防止: 256件を超えたら最も古いエントリを削除
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while pending.len() >= 256 {
                if let Some(&oldest_id) = pending.keys().next() {
                    pending.remove(&oldest_id);
                } else {
                    break;
                }
            }
            pending.insert(id, 0); // tickは呼び出し元で設定可
        }

        Ok(offset)
    }

    /// Check if a DNS query should be retried based on attempt count and elapsed time
    pub fn should_retry(&self, attempt: u8, elapsed_ms: u64) -> bool {
        attempt < DNS_MAX_RETRIES && elapsed_ms >= DNS_RETRY_TIMEOUT_MS
    }

    /// Build a retry query using the same transaction ID
    pub fn build_retry_query(
        &self,
        buffer: &mut [u8],
        name: &str,
        qtype: DnsQueryType,
        transaction_id: u16,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DnsHeader::SIZE + name.len() + 6 {
            return Err("Buffer too small");
        }

        // Use provided transaction ID (same as original query for correlation)
        buffer[0..2].copy_from_slice(&transaction_id.to_be_bytes());
        buffer[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        buffer[4..6].copy_from_slice(&1u16.to_be_bytes());
        buffer[6..8].copy_from_slice(&0u16.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes());
        buffer[10..12].copy_from_slice(&0u16.to_be_bytes());

        let mut offset = DnsHeader::SIZE;

        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            let len = label.len();
            if len > 63 {
                return Err("Label too long");
            }
            // Security: Check bounds before writing
            if offset + 1 + len > buffer.len() {
                return Err("Buffer too small for name");
            }
            buffer[offset] = len as u8;
            offset += 1;
            buffer[offset..offset + len].copy_from_slice(label.as_bytes());
            offset += len;
        }

        // 終端のゼロ
        if offset >= buffer.len() {
            return Err("Buffer too small for zero terminator");
        }
        buffer[offset] = 0;
        offset += 1;

        // QTYPE
        if offset + 2 > buffer.len() {
            return Err("Buffer too small for QTYPE");
        }
        buffer[offset..offset + 2].copy_from_slice(&(qtype as u16).to_be_bytes());
        offset += 2;

        // QCLASS (IN = 1)
        if offset + 2 > buffer.len() {
            return Err("Buffer too small for QCLASS");
        }
        buffer[offset..offset + 2].copy_from_slice(&(DnsQueryClass::IN as u16).to_be_bytes());
        offset += 2;

        self.stats.queries_sent.fetch_add(1, Ordering::Relaxed);

        Ok(offset)
    }

    /// DNSレコードをキャッシュに追加する
    pub(super) fn cache_dns_records(&self, records: &[DnsRecord], current_tick: u64) {
        if records.is_empty() {
            return;
        }

        match self.cache.lock() {
            Ok(mut cache) => {
                // 各レコードを個別にキャッシュに追加する
                // 同じ名前を持つレコードはグループ化して一つのエントリにする
                let mut groups: BTreeMap<String, Vec<DnsRecord>> = BTreeMap::new();
                for record in records {
                    groups
                        .entry(record.name.clone())
                        .or_insert_with(Vec::new)
                        .push(record.clone());
                }

                for (name, group_records) in groups {
                    cache.insert(name, group_records, current_tick);
                }
            }
            Err(_) => {
                log::error!(
                    "[NET] DNS Cache lock poisoned (cache_dns_records) - skipping cache insert"
                )
            }
        }
    }

    /// DNS応答を解析
    pub fn parse_response(
        &self,
        data: &[u8],
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Result<Vec<DnsRecord>, DnsResponseCode> {
        if data.len() < DnsHeader::SIZE {
            return Err(DnsResponseCode::FormatError);
        }

        let header =
            crate::util::get_ref::<DnsHeader>(data, 0).ok_or(DnsResponseCode::FormatError)?;

        if !header.is_response() {
            return Err(DnsResponseCode::FormatError);
        }

        // Security: トランザクションIDを検証 (RFC 5452 キャッシュポイズニング防止)
        let response_id = header.id();
        let id_valid = match self.pending_ids.lock() {
            Ok(mut pending) => pending.remove(&response_id).is_some(),
            Err(_) => {
                log::error!("[NET] DNS pending_ids lock poisoned - dropping response for security");
                false // ロックが汚染されている場合はセキュリティのため拒否
            }
        };
        if !id_valid {
            log::warn!(
                "[NET] DNS: Response with unexpected transaction ID 0x{:04x}, dropping (possible cache poisoning attempt)",
                response_id
            );
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            return Err(DnsResponseCode::FormatError);
        }

        let rcode = header.rcode();
        if rcode as u8 != DnsResponseCode::NoError as u8 {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            return Err(rcode);
        }

        let qcount = header.question_count() as usize;
        let acount = header.answer_count() as usize;
        let nscount = u16::from_be_bytes(header.nscount) as usize;
        let arcount = u16::from_be_bytes(header.arcount) as usize;

        // Security: Overall record count limit to prevent CPU exhaustion DoS (RFC 1035 doesn't specify, but 512-1024 is reasonable)
        if qcount > 64 || acount > 1024 || nscount > 1024 || arcount > 1024 {
            log::warn!(
                "[NET] DNS: Response with excessive record counts (Q: {}, A: {}, NS: {}, AR: {}), dropping",
                qcount,
                acount,
                nscount,
                arcount
            );
            return Err(DnsResponseCode::FormatError);
        }

        // 質問セクションを解析して検証 (RFC 5452 Section 3.1)
        let mut offset = DnsHeader::SIZE;
        let mut matched_question = false;
        for _ in 0..qcount {
            let (qname, next_off) = self.parse_name(data, offset)?;
            if next_off + 4 > data.len() {
                return Err(DnsResponseCode::FormatError);
            }
            let qtype = u16::from_be_bytes([data[next_off], data[next_off + 1]]);
            let _qclass = u16::from_be_bytes([data[next_off + 2], data[next_off + 3]]);

            // 期待される質問と一致するかチェック (Case-insensitive comparison for name)
            if qname.to_lowercase() == expected_name.to_lowercase() && qtype == expected_type as u16
            {
                matched_question = true;
            }

            offset = next_off + 4; // QTYPE + QCLASS
        }

        if !matched_question && qcount > 0 {
            log::warn!(
                "[NET] DNS: Response Question section does not match query ({:?} vs {}), dropping for security",
                expected_type,
                expected_name
            );
            return Err(DnsResponseCode::FormatError);
        }

        // 回答セクションを解析
        let records = self.parse_answer_section(data, &mut offset, acount)?;

        // 権威セクションをスキップ (キャッシュ対象外とする)
        for _ in 0..nscount {
            if offset >= data.len() {
                break;
            }
            offset = self.skip_name(data, offset)?;
            if offset + 10 > data.len() {
                break;
            }
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10 + rdlength;
        }

        // 追加セクションを解析 (解析は行うがキャッシュには慎重に扱う)
        let _additional_records = self.parse_answer_section(data, &mut offset, arcount)?;

        // ====================================================================
        // Security Fix: Cache Filtering (DNS Cache Poisoning Prevention)
        // ====================================================================
        // 1. 回答セクションのうち、クエリ名と一致するもの（またはCNAMEチェーン）のみキャッシュ
        // 2. 追加セクションは原則キャッシュしない（または非常に厳格なGlue検証が必要）
        // ここでは単純化のため、クエリ名と一致する回答のみをキャッシュ対象とする。

        let mut filter_cache_records = Vec::new();
        for rec in &records {
            if rec.name.to_lowercase() == expected_name.to_lowercase() {
                filter_cache_records.push(rec.clone());
            }
        }

        // CNAME チェーンの追跡などは複雑なため、現状は完全一致のみをサポート
        // (将来的に再帰リゾルバを実装する場合はここを拡張する)

        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);

        // フィルタリングされたレコードのみをキャッシュに追加
        if !filter_cache_records.is_empty() {
            self.cache_dns_records(&filter_cache_records, current_tick);
        }

        Ok(records)
    }

    pub fn parse_response_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Option<Result<Vec<DnsRecord>, DnsResponseCode>> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        match payload {
            kernel_api::resource::net::PacketPayload::Single(packet) => {
                if self.needs_tcp_fallback(packet.data()) {
                    None
                } else {
                    Some(self.parse_response(
                        packet.data(),
                        current_tick,
                        expected_name,
                        expected_type,
                    ))
                }
            }
            kernel_api::resource::net::PacketPayload::Chain(_) => {
                let total_len = view.total_len();
                let mut packet = crate::net::payload::alloc_packet_with_headroom(total_len, 0)?;
                if view.copy_all_into(&mut packet.data_mut()[..total_len]) != total_len {
                    return None;
                }
                if self.needs_tcp_fallback(packet.data()) {
                    None
                } else {
                    Some(self.parse_response(
                        packet.data(),
                        current_tick,
                        expected_name,
                        expected_type,
                    ))
                }
            }
        }
    }

    /// 回答セクションをパースする
    pub(super) fn parse_answer_section(
        &self,
        data: &[u8],
        offset: &mut usize,
        acount: usize,
    ) -> Result<Vec<DnsRecord>, DnsResponseCode> {
        let mut records = Vec::new();
        for _ in 0..acount {
            if *offset >= data.len() {
                break;
            }

            let (name, new_offset) = self.parse_name(data, *offset)?;
            *offset = new_offset;

            if *offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
            let rclass = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]) as usize;
            *offset += 10;

            if *offset + rdlength > data.len() {
                break;
            }

            let rdata = &data[*offset..*offset + rdlength];
            *offset += rdlength;

            if records.len() < DNS_MAX_ANSWER_COUNT {
                let record_data = self.parse_record_data(data, rdata, rtype, rdlength, *offset);

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
        }
        Ok(records)
    }

    /// レコードデータ（RDATA）をパースする
    pub(super) fn parse_record_data(
        &self,
        data: &[u8],
        rdata: &[u8],
        rtype: u16,
        rdlength: usize,
        offset_after_rdata: usize,
    ) -> DnsRecordData {
        match DnsQueryType::from_u16(rtype) {
            Some(DnsQueryType::A) if rdlength == 4 => {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(rdata);
                DnsRecordData::A(Ipv4Address::new(bytes))
            }
            Some(DnsQueryType::AAAA) if rdlength == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(rdata);
                DnsRecordData::AAAA(Ipv6Address::new(bytes))
            }
            Some(DnsQueryType::CNAME) | Some(DnsQueryType::NS) | Some(DnsQueryType::PTR) => {
                if let Ok((cname, _)) = self.parse_name(data, offset_after_rdata - rdlength) {
                    DnsRecordData::Name(cname)
                } else {
                    DnsRecordData::Raw(rdata.to_vec())
                }
            }
            Some(DnsQueryType::MX) if rdlength >= 3 => {
                let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                if let Ok((exchange, _)) = self.parse_name(data, offset_after_rdata - rdlength + 2)
                {
                    DnsRecordData::MX(preference, exchange)
                } else {
                    DnsRecordData::Raw(rdata.to_vec())
                }
            }
            Some(DnsQueryType::TXT) => self.parse_txt_record(rdata, rdlength),
            Some(DnsQueryType::SRV) if rdlength >= 7 => {
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                if let Ok((target, _)) = self.parse_name(data, offset_after_rdata - rdlength + 6) {
                    DnsRecordData::SRV {
                        priority,
                        weight,
                        port,
                        target,
                    }
                } else {
                    DnsRecordData::Raw(rdata.to_vec())
                }
            }
            _ => DnsRecordData::Raw(rdata.to_vec()),
        }
    }

    /// TXTレコードをパースする
    pub(super) fn parse_txt_record(&self, rdata: &[u8], rdlength: usize) -> DnsRecordData {
        if rdata.is_empty() {
            return DnsRecordData::Raw(rdata.to_vec());
        }

        // RFC 1035: TXT RDATA consists of one or more <character-string>s.
        // Each <character-string> has a 1-byte length followed by data.
        let mut txt_content = String::new();
        let mut offset = 0;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset < rdlength && offset < rdata.len() {
            let txt_len = rdata[offset] as usize;
            offset += 1;

            if offset + txt_len > rdata.len() || offset + txt_len > rdlength {
                // Malformed TXT record, but we've already started parsing.
                // If we have nothing yet, return Raw. Otherwise return what we have.
                if txt_content.is_empty() {
                    return DnsRecordData::Raw(rdata.to_vec());
                }
                break;
            }

            txt_content.push_str(&String::from_utf8_lossy(&rdata[offset..offset + txt_len]));
            offset += txt_len;
        }

        DnsRecordData::TXT(txt_content)
    }

    /// ドメイン名をスキップ
    pub(super) fn skip_name(
        &self,
        data: &[u8],
        mut offset: usize,
    ) -> Result<usize, DnsResponseCode> {
        let mut labels = 0;
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
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
                if offset + 2 > data.len() {
                    return Err(DnsResponseCode::FormatError);
                }
                return Ok(offset + 2);
            }

            // RFC 1035: Label length maximum is 63 bytes
            if len > 63 {
                return Err(DnsResponseCode::FormatError);
            }

            // Security: Limit number of labels to prevent CPU exhaustion
            labels += 1;
            if labels > 128 {
                return Err(DnsResponseCode::FormatError);
            }

            offset += 1 + len as usize;
        }
    }

    pub(super) fn follow_compression_pointer(
        &self,
        data: &[u8],
        offset: usize,
        len: u8,
        jump_count: &mut usize,
        jumped: &mut bool,
        final_offset: &mut usize,
    ) -> Result<usize, DnsResponseCode> {
        if offset + 1 >= data.len() {
            return Err(DnsResponseCode::FormatError);
        }
        if !*jumped {
            *final_offset = offset + 2;
        }
        let pointer = ((len as usize & 0x3F) << 8) | data[offset + 1] as usize;
        // Security: ポインタオフセットがデータ範囲内であることを検証
        if pointer >= data.len() {
            return Err(DnsResponseCode::FormatError);
        }
        *jump_count += 1;
        if *jump_count > 128 {
            return Err(DnsResponseCode::FormatError);
        }
        *jumped = true;
        Ok(pointer)
    }

    /// ドメイン名を解析 (圧縮対応)
    pub(super) fn parse_name(
        &self,
        data: &[u8],
        mut offset: usize,
    ) -> Result<(String, usize), DnsResponseCode> {
        let mut name = String::new();
        let mut jumped = false;
        let mut final_offset = offset;
        let mut jump_count = 0;

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
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
                offset = self.follow_compression_pointer(
                    data,
                    offset,
                    len,
                    &mut jump_count,
                    &mut jumped,
                    &mut final_offset,
                )?;
                continue;
            }

            // RFC 1035: Label length maximum is 63 bytes
            if len > 63 {
                return Err(DnsResponseCode::FormatError);
            }

            offset += 1;

            if offset + len as usize > data.len() {
                return Err(DnsResponseCode::FormatError);
            }

            if !name.is_empty() {
                name.push('.');
            }

            // RFC 1035: Total name length maximum is 255 bytes (including null)
            if name.len() + len as usize > 255 {
                return Err(DnsResponseCode::FormatError);
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

    // ========================================================================
    // DNS over TCP Support (RFC 7766)
    // ========================================================================

    /// Build a DNS query for TCP transport
    ///
    /// DNS over TCP requires a 2-byte length prefix before the message.
    /// RFC 7766 specifies that all DNS implementations should support TCP.
    ///
    /// # Arguments
    /// - `buffer`: Output buffer (must be at least message_len + 2)
    /// - `name`: Domain name to query
    /// - `qtype`: Query type (A, AAAA, etc.)
    ///
    /// # Returns
    /// Total length including the 2-byte length prefix
    pub fn build_tcp_query(
        &self,
        buffer: &mut [u8],
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<usize, &'static str> {
        if buffer.len() < 2 {
            return Err("Buffer too small for TCP length prefix");
        }

        // Build the DNS message after the length prefix
        let msg_len = self.build_query(&mut buffer[2..], name, qtype)?;

        // Prepend the 2-byte length prefix (network byte order)
        let len_bytes = (msg_len as u16).to_be_bytes();
        buffer[0] = len_bytes[0];
        buffer[1] = len_bytes[1];

        Ok(2 + msg_len)
    }

    /// Parse a DNS response received over TCP
    ///
    /// TCP responses include a 2-byte length prefix that specifies
    /// the length of the DNS message.
    ///
    /// # Arguments
    /// - `data`: Raw TCP data including length prefix
    /// - `current_tick`: Current time for cache TTL calculation
    ///
    /// # Returns
    /// Parsed DNS records or error code
    pub fn parse_tcp_response(
        &self,
        data: &[u8],
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Result<Vec<DnsRecord>, DnsResponseCode> {
        // TCP responses have a 2-byte length prefix
        if data.len() < 2 {
            return Err(DnsResponseCode::FormatError);
        }

        let msg_len = u16::from_be_bytes([data[0], data[1]]) as usize;

        if data.len() < 2 + msg_len {
            return Err(DnsResponseCode::FormatError);
        }

        // Parse the actual DNS message (skip length prefix)
        self.parse_response(
            &data[2..2 + msg_len],
            current_tick,
            expected_name,
            expected_type,
        )
    }

    /// Check if a UDP response requires TCP fallback
    ///
    /// According to RFC 7766, clients should retry with TCP when:
    /// 1. The TC (Truncated) bit is set in the response
    /// 2. The response size is exactly 512 bytes (traditional UDP limit)
    ///
    /// # Arguments
    /// - `data`: Raw UDP DNS response
    ///
    /// # Returns
    /// `true` if TCP fallback is recommended
    pub fn needs_tcp_fallback(&self, data: &[u8]) -> bool {
        if data.len() < DnsHeader::SIZE {
            return false;
        }

        let Some(header) = crate::util::get_ref::<DnsHeader>(data, 0) else {
            return false;
        };

        // Check TC (Truncated) bit
        if header.is_truncated() {
            return true;
        }

        // Also recommend TCP for responses at the traditional UDP limit
        // This suggests the response may have been truncated without setting TC
        if data.len() >= 512 {
            return true;
        }

        false
    }

    /// Calculate expected TCP message length from length prefix
    ///
    /// Used for reading TCP DNS messages which may be fragmented.
    ///
    /// # Arguments
    /// - `length_prefix`: First 2 bytes carried over the TCP connection payload sequence
    ///
    /// # Returns
    /// Expected total message length (excluding prefix)
    pub fn tcp_message_length(length_prefix: &[u8; 2]) -> u16 {
        u16::from_be_bytes(*length_prefix)
    }
}
