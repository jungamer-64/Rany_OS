use super::*;


impl DnsClient {
    /// 新しいDNSクライアントを作成
    pub fn new(tick_rate: u64) -> Self {
        Self {
            servers: PoisonLock::new(Vec::new()),
            cache: PoisonLock::new(DnsCache::new(tick_rate)),
            next_id: AtomicU16::new(1),
            stats: DnsStats::new(),
        }
    }

    /// DNSサーバーを設定
    pub fn set_servers(&self, servers: Vec<Ipv4Address>) {
        match self.servers.lock() {
            Ok(mut guard) => *guard = servers,
            Err(_) => log::error!("[NET] DNS Servers lock poisoned (set_servers) - operation skipped"),
        }
    }

    /// DNSサーバーを追加
    pub fn add_server(&self, server: Ipv4Address) {
        match self.servers.lock() {
            Ok(mut servers) => {
                if !servers.contains(&server) && servers.len() < 3 {
                    servers.push(server);
                }
            }
            Err(_) => log::error!("[NET] DNS Servers lock poisoned (add_server) - operation skipped"),
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
                log::error!("[NET] DNS Cache lock poisoned (resolve_cached) - treating as cache miss");
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// 期限切れキャッシュエントリをクリーンアップ
    pub fn cleanup_cache(&self, current_tick: u64) {
        match self.cache.lock() {
            Ok(mut cache) => cache.cleanup(current_tick),
            Err(_) => log::error!("[NET] DNS Cache lock poisoned (cleanup_cache) - operation skipped"),
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
            buffer[offset] = len as u8;
            offset += 1;
            buffer[offset..offset + len].copy_from_slice(label.as_bytes());
            offset += len;
        }

        buffer[offset] = 0;
        offset += 1;
        buffer[offset..offset + 2].copy_from_slice(&(qtype as u16).to_be_bytes());
        offset += 2;
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
                log::error!("[NET] DNS Cache lock poisoned (cache_dns_records) - skipping cache insert")
            }
        }
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

        let header =
            crate::util::get_ref::<DnsHeader>(data, 0).expect("DNS header slice out of bounds");

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
            offset = self.skip_name(data, offset)?;
            offset += 4; // QTYPE + QCLASS
        }

        // 回答セクションを解析
        let records = self.parse_answer_section(data, &mut offset, acount)?;

        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);

        // キャッシュに追加
        self.cache_dns_records(&records, current_tick);

        Ok(records)
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
            Some(DnsQueryType::CNAME) | Some(DnsQueryType::NS) | Some(DnsQueryType::PTR) => {
                if let Ok((cname, _)) = self.parse_name(data, offset_after_rdata - rdlength) {
                    DnsRecordData::Name(cname)
                } else {
                    DnsRecordData::Raw(rdata.to_vec())
                }
            }
            Some(DnsQueryType::MX) if rdlength >= 3 => {
                let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                if let Ok((exchange, _)) = self.parse_name(data, offset_after_rdata - rdlength + 2) {
                    DnsRecordData::MX(preference, exchange)
                } else {
                    DnsRecordData::Raw(rdata.to_vec())
                }
            }
            Some(DnsQueryType::TXT) => {
                self.parse_txt_record(rdata, rdlength)
            }
            Some(DnsQueryType::SRV) if rdlength >= 7 => {
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                if let Ok((target, _)) = self.parse_name(data, offset_after_rdata - rdlength + 6) {
                    DnsRecordData::SRV { priority, weight, port, target }
                } else {
                    DnsRecordData::Raw(rdata.to_vec())
                }
            }
            _ => DnsRecordData::Raw(rdata.to_vec()),
        }
    }

    /// TXTレコードをパースする
    pub(super) fn parse_txt_record(&self, rdata: &[u8], rdlength: usize) -> DnsRecordData {
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

    /// ドメイン名をスキップ
    pub(super) fn skip_name(&self, data: &[u8], mut offset: usize) -> Result<usize, DnsResponseCode> {
        let mut labels = 0;
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
                    data, offset, len, &mut jump_count, &mut jumped, &mut final_offset,
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

    /// プライマリDNSサーバーを取得
    pub fn primary_server(&self) -> Option<Ipv4Address> {
        match self.servers.lock() {
            Ok(servers) => servers.first().copied(),
            Err(_) => {
                log::error!("[NET] DNS Servers lock poisoned - returning None");
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
        self.parse_response(&data[2..2 + msg_len], current_tick)
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
    /// - `length_prefix`: First 2 bytes of TCP stream
    /// 
    /// # Returns
    /// Expected total message length (excluding prefix)
    pub fn tcp_message_length(length_prefix: &[u8; 2]) -> u16 {
        u16::from_be_bytes(*length_prefix)
    }
}
