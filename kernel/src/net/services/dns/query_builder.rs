// ============================================================================
// kernel/src/net/services/dns/query_builder.rs - サービス / DNS / query builder
// ============================================================================

use super::*;

impl DnsClient {
    pub(super) fn next_query_id(&self) -> u16 {
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        u16::from_le_bytes([random_bytes[0], random_bytes[1]])
    }

    pub(super) fn register_pending_query_id(&self, id: u16) {
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
    }

    fn dns_name_wire_len(name: &DnsNameOwned) -> Option<usize> {
        let mut len = 1usize;
        for label in name.labels() {
            if label.total_len() > 63 {
                return None;
            }
            len = len.checked_add(1)?.checked_add(label.total_len())?;
        }
        Some(len)
    }

    fn write_dns_name_payload(
        writer: &mut GeneratedPacketWriter,
        name: &DnsNameOwned,
    ) -> Result<(), &'static str> {
        for label in name.labels() {
            let len = label.total_len();
            if len > 63 {
                return Err("Label too long");
            }
            writer
                .write_u8(len as u8)
                .ok_or("Failed to allocate DNS label")?;
            let span = label
                .span(name.payload())
                .ok_or("Invalid DNS label payload range")?;
            let mut pushed = true;
            span.for_each_chunk(|chunk| {
                if pushed && writer.write_bytes(chunk).is_none() {
                    pushed = false;
                }
            });
            if !pushed {
                return Err("Failed to allocate DNS label payload");
            }
        }
        writer
            .write_u8(0)
            .ok_or("Failed to allocate DNS terminator")?;
        Ok(())
    }

    /// DNSクエリパケットを packet-backed payload として構築
    pub fn build_query_payload(
        &self,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let name = DnsNameOwned::parse_ascii(name).map_err(|_| "Invalid DNS name")?;
        self.build_query_payload_for_name(&name, qtype)
    }

    pub fn build_query_payload_for_name(
        &self,
        name: &DnsNameOwned,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let id = self.next_query_id();
        self.register_pending_query_id(id);
        self.build_query_payload_for_name_with_id(name, qtype, id)
    }

    pub fn build_query_payload_for_name_with_id(
        &self,
        name: &DnsNameOwned,
        qtype: DnsQueryType,
        id: u16,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let name_len = Self::dns_name_wire_len(name).ok_or("Invalid DNS name")?;
        let packet_len = DnsHeader::SIZE
            .checked_add(name_len)
            .and_then(|len| len.checked_add(4))
            .and_then(|len| len.checked_add(11))
            .ok_or("DNS query too large")?;
        let mut writer = GeneratedPacketWriter::new(packet_len, DEFAULT_PACKET_HEADROOM)
            .ok_or("Failed to allocate DNS query")?;
        writer
            .write_u16_be(id)
            .ok_or("Failed to write DNS header")?;
        writer
            .write_u16_be(0x0100)
            .ok_or("Failed to write DNS header")?;
        writer.write_u16_be(1).ok_or("Failed to write DNS header")?;
        writer.write_u16_be(0).ok_or("Failed to write DNS header")?;
        writer.write_u16_be(0).ok_or("Failed to write DNS header")?;
        writer.write_u16_be(1).ok_or("Failed to write DNS header")?;

        Self::write_dns_name_payload(&mut writer, name)?;
        writer
            .write_u16_be(qtype as u16)
            .ok_or("Failed to write DNS qtype")?;
        writer
            .write_u16_be(DnsQueryClass::IN as u16)
            .ok_or("Failed to write DNS qclass")?;
        writer
            .write_u8(0)
            .ok_or("Failed to write EDNS0 root name")?;
        writer
            .write_u16_be(DnsQueryType::OPT as u16)
            .ok_or("Failed to write EDNS0 type")?;
        writer
            .write_u16_be(4096)
            .ok_or("Failed to write EDNS0 payload size")?;
        writer
            .write_u32_be(0)
            .ok_or("Failed to write EDNS0 flags")?;
        writer
            .write_u16_be(0)
            .ok_or("Failed to write EDNS0 rdlength")?;

        self.stats.queries_sent.fetch_add(1, Ordering::Relaxed);

        writer.finish().ok_or("Incomplete DNS query")
    }

    /// Build a DNS query for TCP transport as a packet-backed payload.
    pub fn build_tcp_query_payload(
        &self,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let name = DnsNameOwned::parse_ascii(name).map_err(|_| "Invalid DNS name")?;
        self.build_tcp_query_payload_for_name(&name, qtype)
    }

    pub fn build_tcp_query_payload_for_name(
        &self,
        name: &DnsNameOwned,
        qtype: DnsQueryType,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let id = self.next_query_id();
        self.register_pending_query_id(id);
        self.build_tcp_query_payload_for_name_with_id(name, qtype, id)
    }

    pub fn build_tcp_query_payload_for_name_with_id(
        &self,
        name: &DnsNameOwned,
        qtype: DnsQueryType,
        id: u16,
    ) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
        let message = self.build_query_payload_for_name_with_id(name, qtype, id)?;
        let mut prefix = GeneratedPacketWriter::new(2, DEFAULT_PACKET_HEADROOM)
            .ok_or("Buffer too small for TCP length prefix")?;
        prefix
            .write_u16_be(message.total_len() as u16)
            .ok_or("Buffer too small for TCP length prefix")?;
        let mut payload = prefix.finish().ok_or("Incomplete DNS TCP prefix")?;
        crate::net::payload::append_payload(&mut payload, message);
        Ok(payload)
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

    pub(super) fn retire_pending_query_id_value(&self, id: u16) {
        if let Ok(mut pending) = self.pending_ids.lock() {
            pending.remove(&id);
        }
    }
}
