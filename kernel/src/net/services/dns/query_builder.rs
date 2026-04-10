use super::*;

impl DnsClient {
    fn push_dns_name_payload(
        builder: &mut crate::net::payload::PacketPayloadBuilder,
        name: &DnsNameView,
    ) -> Result<(), &'static str> {
        for label in name.labels() {
            let len = label.total_len();
            if len > 63 {
                return Err("Label too long");
            }
            builder
                .push_bytes(&[len as u8])
                .ok_or("Failed to allocate DNS label")?;
            builder.push_payload(
                label
                    .to_payload()
                    .ok_or("Failed to allocate DNS label payload")?,
            );
        }
        builder
            .push_bytes(&[0])
            .ok_or("Failed to allocate DNS terminator")?;
        Ok(())
    }

    /// DNSクエリパケットを packet-backed payload として構築
    pub fn build_query_payload_for_name(
        &self,
        name: &DnsNameView,
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

        Self::push_dns_name_payload(&mut builder, name)?;
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

        self.cleanup_stale_pending_ids(crate::task::current_tick());
        if let Ok(mut pending) = self.pending_ids.lock() {
            while pending.len() >= 256 {
                let oldest_id = pending
                    .iter()
                    .min_by_key(|(_, created_at)| *created_at)
                    .map(|(pending_id, _)| *pending_id);
                if let Some(oldest_id) = oldest_id {
                    pending.remove(&oldest_id);
                } else {
                    break;
                }
            }
            pending.insert(id, crate::task::current_tick());
        }

        Ok(builder.build())
    }

    /// DNSクエリパケットを packet-backed payload として構築
    pub fn build_query_payload(
        &self,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let owned = DnsNameOwned::from_ascii_name(name).ok_or("Invalid DNS name")?;
        self.build_query_payload_for_name(&owned.as_view(), qtype)
    }

    /// Build a DNS query for TCP transport as a packet-backed payload.
    pub fn build_tcp_query_payload_for_name(
        &self,
        name: &DnsNameView,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let message = self.build_query_payload_for_name(name, qtype)?;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&(message.total_len() as u16).to_be_bytes())
            .ok_or("Buffer too small for TCP length prefix")?;
        builder.push_payload(message);
        Ok(builder.build())
    }

    /// Build a DNS query for TCP transport as a packet-backed payload.
    pub fn build_tcp_query_payload(
        &self,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let owned = DnsNameOwned::from_ascii_name(name).ok_or("Invalid DNS name")?;
        self.build_tcp_query_payload_for_name(&owned.as_view(), qtype)
    }

    /// Check if a DNS query should be retried based on attempt count and elapsed time
    pub fn should_retry(&self, attempt: u8, elapsed_ms: u64) -> bool {
        attempt < DNS_MAX_RETRIES && elapsed_ms >= DNS_RETRY_TIMEOUT_MS
    }

    pub(super) fn cleanup_stale_pending_ids(&self, now_tick: u64) {
        if let Ok(mut pending) = self.pending_ids.lock() {
            pending.retain(|_, created_at| {
                now_tick.saturating_sub(*created_at) <= DNS_PENDING_ID_TTL_TICKS
            });
        }
    }

    pub(super) fn retire_pending_query_id(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        let Some(id) = view.read_array::<2>(0).map(u16::from_be_bytes) else {
            return;
        };

        if let Ok(mut pending) = self.pending_ids.lock() {
            pending.remove(&id);
        }
    }
}
