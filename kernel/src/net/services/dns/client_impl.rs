use super::*;
use crate::net::l4::udp::UdpAddr;
use crate::net::payload::PayloadSpan;
use crate::task::{self, TimeoutResult};

impl DnsClient {
    fn raw_record_span(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        offset: usize,
        len: usize,
    ) -> DnsRecordData {
        DnsRecordData::Raw(
            PayloadSpan::from_range(payload.clone(), offset, len).unwrap_or_else(|| {
                PayloadSpan::from_payload(kernel_api::resource::net::PacketPayload::default())
            }),
        )
    }

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
        let response = self.query_internal(name, DnsQueryType::A).await.ok()?;

        // Security: 結果を名前でフィルタリング (RFC 5452)
        for record in response.records {
            if record.name.eq_ignore_ascii_case(name) {
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
        let response = self.query_internal(name, DnsQueryType::AAAA).await.ok()?;

        // Security: 結果を名前でフィルタリング (RFC 5452)
        for record in response.records {
            if record.name.eq_ignore_ascii_case(name) {
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
    ) -> Result<DnsResponseView, &'static str> {
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
        let query_payload = self.build_query_payload(name, qtype)?;

        let dest = UdpAddr::new(server, DNS_PORT);
        if socket.send(query_payload.clone(), dest).await.is_err() {
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
                        let _ = socket.send(query_payload.clone(), dest).await;
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
    ) -> Result<DnsResponseView, &'static str> {
        async fn read_exact_payload(
            connection: &mut crate::net::l4::tcp::TcpConnection,
            stash: &mut kernel_api::resource::net::PacketPayload,
            len: usize,
        ) -> Result<Option<kernel_api::resource::net::PacketPayload>, &'static str> {
            while stash.total_len() < len {
                let Some(payload) = connection.recv_payload().await else {
                    break;
                };
                if payload.total_len() == 0 {
                    break;
                }
                crate::net::payload::append_payload(stash, payload);
            }
            if stash.total_len() < len {
                return Ok(None);
            }
            stash
                .take_prefix(len)
                .ok_or("TCP payload prefix split failed")
                .map(Some)
        }

        use crate::net::l4::endpoint::types::EndpointAddr;
        let dest = EndpointAddr::new(server.octets(), DNS_PORT);

        let mut connection = crate::net::l4::tcp::TcpConnection::dial_in(
            crate::net::runtime::default_runtime(),
            dest,
        )
        .await
        .map_err(|_| "TCP connection failed")?;

        let payload = self.build_tcp_query_payload(name, qtype)?;
        connection
            .send_payload(payload)
            .await
            .map_err(|_| "TCP write failed")?;
        connection
            .drain_tx()
            .await
            .map_err(|_| "TCP write drain failed")?;

        let mut stash = kernel_api::resource::net::PacketPayload::default();

        // Read 2-byte length prefix
        let len_payload = read_exact_payload(&mut connection, &mut stash, 2)
            .await?
            .ok_or("TCP read length prefix failed (connection closed or incomplete)")?;
        let len_buf = crate::net::payload::PacketPayloadView::new(&len_payload)
            .read_array::<2>(0)
            .ok_or("TCP length prefix parse failed")?;
        if len_buf == [0, 0] {
            return Err("TCP read length prefix failed (connection closed or incomplete)");
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > 65535 {
            return Err("TCP message too long");
        }

        let msg_data = read_exact_payload(&mut connection, &mut stash, msg_len)
            .await?
            .ok_or("TCP read incomplete message")?;

        let tick = crate::task::current_tick();
        self.parse_response_payload(&msg_data, tick, name, qtype)
            .ok_or("TCP fallback requested unexpectedly")?
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

    /// DNSクエリパケットを packet-backed payload として構築
    pub fn build_query_payload(
        &self,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        // トランザクションIDを生成 (RFC 5452: 予測困難なIDを使用)
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let id = u16::from_le_bytes([random_bytes[0], random_bytes[1]]);

        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&id.to_be_bytes())
            .ok_or("Failed to allocate DNS header")?;
        builder
            .push_bytes(&0x0100u16.to_be_bytes())
            .ok_or("Failed to allocate DNS header")?;
        builder
            .push_bytes(&1u16.to_be_bytes())
            .ok_or("Failed to allocate DNS header")?;
        builder
            .push_bytes(&0u16.to_be_bytes())
            .ok_or("Failed to allocate DNS header")?;
        builder
            .push_bytes(&0u16.to_be_bytes())
            .ok_or("Failed to allocate DNS header")?;
        builder
            .push_bytes(&1u16.to_be_bytes())
            .ok_or("Failed to allocate DNS header")?;

        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            let len = label.len();
            if len > 63 {
                return Err("Label too long");
            }
            builder
                .push_bytes(&[len as u8])
                .ok_or("Failed to allocate DNS label")?;
            builder
                .push_bytes(label.as_bytes())
                .ok_or("Failed to allocate DNS label")?;
        }

        builder
            .push_bytes(&[0])
            .ok_or("Failed to allocate DNS terminator")?;
        builder
            .push_bytes(&(qtype as u16).to_be_bytes())
            .ok_or("Failed to allocate DNS qtype")?;
        builder
            .push_bytes(&(DnsQueryClass::IN as u16).to_be_bytes())
            .ok_or("Failed to allocate DNS qclass")?;
        builder
            .push_bytes(&[0])
            .ok_or("Failed to allocate EDNS0 root name")?;
        builder
            .push_bytes(&(DnsQueryType::OPT as u16).to_be_bytes())
            .ok_or("Failed to allocate EDNS0 type")?;
        builder
            .push_bytes(&4096u16.to_be_bytes())
            .ok_or("Failed to allocate EDNS0 payload size")?;
        builder
            .push_bytes(&0u32.to_be_bytes())
            .ok_or("Failed to allocate EDNS0 flags")?;
        builder
            .push_bytes(&0u16.to_be_bytes())
            .ok_or("Failed to allocate EDNS0 rdlength")?;

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

        Ok(builder.build())
    }

    /// Check if a DNS query should be retried based on attempt count and elapsed time
    pub fn should_retry(&self, attempt: u8, elapsed_ms: u64) -> bool {
        attempt < DNS_MAX_RETRIES && elapsed_ms >= DNS_RETRY_TIMEOUT_MS
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

    pub fn parse_response_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Option<Result<DnsResponseView, DnsResponseCode>> {
        if self.needs_tcp_fallback_payload(payload) {
            None
        } else {
            Some(self.parse_response_payload_chained(
                payload,
                current_tick,
                expected_name,
                expected_type,
            ))
        }
    }

    fn needs_tcp_fallback_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> bool {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        if view.total_len() < DnsHeader::SIZE {
            return false;
        }
        let Some(flags) = view.read_array::<2>(2) else {
            return false;
        };
        let flags = u16::from_be_bytes(flags);
        ((flags >> 9) & 1 == 1) || view.total_len() >= 512
    }

    fn parse_response_payload_chained(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Result<DnsResponseView, DnsResponseCode> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        if view.total_len() < DnsHeader::SIZE {
            return Err(DnsResponseCode::FormatError);
        }

        let flags = view
            .read_array::<2>(2)
            .map(u16::from_be_bytes)
            .ok_or(DnsResponseCode::FormatError)?;
        if ((flags >> 15) & 1) != 1 {
            return Err(DnsResponseCode::FormatError);
        }

        let response_id = view
            .read_array::<2>(0)
            .map(u16::from_be_bytes)
            .ok_or(DnsResponseCode::FormatError)?;
        let id_valid = match self.pending_ids.lock() {
            Ok(mut pending) => pending.remove(&response_id).is_some(),
            Err(_) => {
                log::error!("[NET] DNS pending_ids lock poisoned - dropping response for security");
                false
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

        let rcode = DnsResponseCode::from_u8((flags & 0x0F) as u8);
        if rcode as u8 != DnsResponseCode::NoError as u8 {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            return Err(rcode);
        }

        let qcount = view
            .read_array::<2>(4)
            .map(u16::from_be_bytes)
            .ok_or(DnsResponseCode::FormatError)? as usize;
        let acount = view
            .read_array::<2>(6)
            .map(u16::from_be_bytes)
            .ok_or(DnsResponseCode::FormatError)? as usize;
        let nscount = view
            .read_array::<2>(8)
            .map(u16::from_be_bytes)
            .ok_or(DnsResponseCode::FormatError)? as usize;
        let arcount = view
            .read_array::<2>(10)
            .map(u16::from_be_bytes)
            .ok_or(DnsResponseCode::FormatError)? as usize;

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

        let mut offset = DnsHeader::SIZE;
        let mut matched_question = false;
        for _ in 0..qcount {
            let (qname, next_off) = self.parse_name_payload(payload, &view, offset)?;
            let qtype = view
                .read_array::<2>(next_off)
                .map(u16::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)?;
            if view.read_array::<2>(next_off + 2).is_none() {
                return Err(DnsResponseCode::FormatError);
            }
            if qname.eq_ignore_ascii_case(expected_name) && qtype == expected_type as u16 {
                matched_question = true;
            }
            offset = next_off + 4;
        }

        if !matched_question && qcount > 0 {
            log::warn!(
                "[NET] DNS: Response Question section does not match query ({:?} vs {}), dropping for security",
                expected_type,
                expected_name
            );
            return Err(DnsResponseCode::FormatError);
        }

        let records = self.parse_answer_section_payload(payload, &view, &mut offset, acount)?;

        for _ in 0..nscount {
            if offset >= view.total_len() {
                break;
            }
            offset = self.skip_name_payload(&view, offset)?;
            if offset + 10 > view.total_len() {
                break;
            }
            let rdlength = view
                .read_array::<2>(offset + 8)
                .map(u16::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)? as usize;
            offset += 10 + rdlength;
        }

        let _additional_records =
            self.parse_answer_section_payload(payload, &view, &mut offset, arcount)?;

        let mut filter_cache_records = Vec::new();
        for rec in &records {
            if rec.name.eq_ignore_ascii_case(expected_name) {
                filter_cache_records.push(rec.clone());
            }
        }

        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);
        if !filter_cache_records.is_empty() {
            self.cache_dns_response(
                expected_name,
                &DnsResponseView {
                    payload: payload.clone(),
                    records: filter_cache_records,
                },
                current_tick,
            );
        }
        Ok(DnsResponseView {
            payload: payload.clone(),
            records,
        })
    }

    fn parse_name_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        mut offset: usize,
    ) -> Result<(DnsNameView, usize), DnsResponseCode> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut final_offset = offset;
        let mut jump_count = 0usize;

        loop {
            let len = view
                .read_array::<1>(offset)
                .map(|bytes| bytes[0])
                .ok_or(DnsResponseCode::FormatError)?;
            if len == 0 {
                if !jumped {
                    final_offset = offset + 1;
                }
                break;
            }

            if len & 0xC0 == 0xC0 {
                let second = view
                    .read_array::<1>(offset + 1)
                    .map(|bytes| bytes[0])
                    .ok_or(DnsResponseCode::FormatError)?;
                if !jumped {
                    final_offset = offset + 2;
                }
                let pointer = ((len as usize & 0x3F) << 8) | second as usize;
                jump_count += 1;
                if jump_count > 128 || pointer >= view.total_len() {
                    return Err(DnsResponseCode::FormatError);
                }
                offset = pointer;
                jumped = true;
                continue;
            }

            if len > 63 {
                return Err(DnsResponseCode::FormatError);
            }

            let label = PayloadSpan::from_range(payload.clone(), offset + 1, len as usize)
                .ok_or(DnsResponseCode::FormatError)?;
            labels.push(label);
            offset += 1 + len as usize;
            if !jumped {
                final_offset = offset;
            }
        }

        Ok((DnsNameView::from_labels(labels), final_offset))
    }

    fn skip_name_payload(
        &self,
        view: &crate::net::payload::PacketPayloadView<'_>,
        mut offset: usize,
    ) -> Result<usize, DnsResponseCode> {
        let mut labels = 0usize;
        loop {
            let len = view
                .read_array::<1>(offset)
                .map(|bytes| bytes[0])
                .ok_or(DnsResponseCode::FormatError)?;
            if len == 0 {
                return Ok(offset + 1);
            }
            if len & 0xC0 == 0xC0 {
                if view.read_array::<1>(offset + 1).is_none() {
                    return Err(DnsResponseCode::FormatError);
                }
                return Ok(offset + 2);
            }
            if len > 63 {
                return Err(DnsResponseCode::FormatError);
            }
            labels += 1;
            if labels > 128 {
                return Err(DnsResponseCode::FormatError);
            }
            offset += 1 + len as usize;
        }
    }

    fn parse_answer_section_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: &mut usize,
        acount: usize,
    ) -> Result<Vec<DnsRecordMeta>, DnsResponseCode> {
        let mut records = Vec::new();
        for _ in 0..acount {
            if *offset >= view.total_len() {
                break;
            }

            let (name, new_offset) = self.parse_name_payload(payload, view, *offset)?;
            *offset = new_offset;
            if *offset + 10 > view.total_len() {
                break;
            }

            let rtype = view
                .read_array::<2>(*offset)
                .map(u16::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)?;
            let rclass = view
                .read_array::<2>(*offset + 2)
                .map(u16::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)?;
            let ttl = view
                .read_array::<4>(*offset + 4)
                .map(u32::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)?;
            let rdlength = view
                .read_array::<2>(*offset + 8)
                .map(u16::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)? as usize;
            *offset += 10;
            if *offset + rdlength > view.total_len() {
                break;
            }

            if records.len() < DNS_MAX_ANSWER_COUNT {
                let record_data =
                    self.parse_record_data_payload(payload, view, rtype, rdlength, *offset);
                records.push(DnsRecordMeta {
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
            *offset += rdlength;
        }
        Ok(records)
    }

    fn parse_record_data_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        rtype: u16,
        rdlength: usize,
        rdata_offset: usize,
    ) -> DnsRecordData {
        let raw_span = || self.raw_record_span(payload, rdata_offset, rdlength);

        match DnsQueryType::from_u16(rtype) {
            Some(DnsQueryType::A) if rdlength == 4 => view
                .read_array::<4>(rdata_offset)
                .map(Ipv4Address::new)
                .map(DnsRecordData::A)
                .unwrap_or_else(raw_span),
            Some(DnsQueryType::AAAA) if rdlength == 16 => view
                .read_array::<16>(rdata_offset)
                .map(Ipv6Address::new)
                .map(DnsRecordData::AAAA)
                .unwrap_or_else(raw_span),
            Some(DnsQueryType::CNAME) | Some(DnsQueryType::NS) | Some(DnsQueryType::PTR) => self
                .parse_name_payload(payload, view, rdata_offset)
                .map(|(name, _)| DnsRecordData::Name(name))
                .unwrap_or_else(|_| raw_span()),
            Some(DnsQueryType::MX) if rdlength >= 3 => {
                let Some(preference) = view.read_array::<2>(rdata_offset).map(u16::from_be_bytes)
                else {
                    return raw_span();
                };
                self.parse_name_payload(payload, view, rdata_offset + 2)
                    .map(|(exchange, _)| DnsRecordData::MX(preference, exchange))
                    .unwrap_or_else(|_| raw_span())
            }
            Some(DnsQueryType::TXT) => {
                self.parse_txt_record_payload(payload, view, rdata_offset, rdlength)
            }
            Some(DnsQueryType::SRV) if rdlength >= 7 => {
                let Some(priority) = view.read_array::<2>(rdata_offset).map(u16::from_be_bytes)
                else {
                    return raw_span();
                };
                let Some(weight) = view
                    .read_array::<2>(rdata_offset + 2)
                    .map(u16::from_be_bytes)
                else {
                    return raw_span();
                };
                let Some(port) = view
                    .read_array::<2>(rdata_offset + 4)
                    .map(u16::from_be_bytes)
                else {
                    return raw_span();
                };
                self.parse_name_payload(payload, view, rdata_offset + 6)
                    .map(|(target, _)| DnsRecordData::SRV {
                        priority,
                        weight,
                        port,
                        target,
                    })
                    .unwrap_or_else(|_| raw_span())
            }
            _ => raw_span(),
        }
    }

    fn parse_txt_record_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        rdata_offset: usize,
        rdlength: usize,
    ) -> DnsRecordData {
        if rdlength == 0 {
            return DnsRecordData::TXT(DnsTxtView::from_spans(Vec::new()));
        }

        let mut spans = Vec::new();
        let mut offset = 0usize;
        while offset < rdlength {
            let Some(txt_len) = view
                .read_array::<1>(rdata_offset + offset)
                .map(|bytes| bytes[0] as usize)
            else {
                return self.raw_record_span(payload, rdata_offset, rdlength);
            };
            offset += 1;
            if offset + txt_len > rdlength {
                return self.raw_record_span(payload, rdata_offset, rdlength);
            }
            let Some(label) =
                PayloadSpan::from_range(payload.clone(), rdata_offset + offset, txt_len)
            else {
                return self.raw_record_span(payload, rdata_offset, rdlength);
            };
            spans.push(label);
            offset += txt_len;
        }
        DnsRecordData::TXT(DnsTxtView::from_spans(spans))
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

    /// Build a DNS query for TCP transport as a packet-backed payload.
    pub fn build_tcp_query_payload(
        &self,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let message = self.build_query_payload(name, qtype)?;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&(message.total_len() as u16).to_be_bytes())
            .ok_or("Buffer too small for TCP length prefix")?;
        builder.push_payload(message);
        Ok(builder.build())
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
    pub fn parse_tcp_response_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Result<DnsResponseView, DnsResponseCode> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        if view.total_len() < 2 {
            return Err(DnsResponseCode::FormatError);
        }

        let len = view
            .read_array::<2>(0)
            .ok_or(DnsResponseCode::FormatError)?;
        let msg_len = u16::from_be_bytes(len) as usize;

        if view.total_len() < 2 + msg_len {
            return Err(DnsResponseCode::FormatError);
        }

        let message = crate::net::payload::payload_range(payload, 2, msg_len)
            .ok_or(DnsResponseCode::FormatError)?;
        self.parse_response_payload(&message, current_tick, expected_name, expected_type)
            .ok_or(DnsResponseCode::FormatError)?
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
