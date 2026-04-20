// ============================================================================
// kernel/src/net/services/dns/parser.rs - サービス / DNS / パーサ
// ============================================================================

use super::*;
use crate::net::payload::{OwnedPayloadRange, PacketPayloadBuilder, PayloadSpanRef};

struct DnsSectionCounts {
    qcount: usize,
    acount: usize,
    nscount: usize,
    arcount: usize,
}

pub(crate) struct ParsedDnsName {
    pub(crate) name: DnsNameView,
    pub(crate) next_offset: usize,
}

struct DnsNamePointerInfo {
    pointer: usize,
    pointer_end: usize,
    jump_count: usize,
}

struct DnsRecordHeader {
    name: DnsNameView,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlength: usize,
    rdata_offset: usize,
}

impl DnsClient {
    fn copied_owned_range(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        offset: usize,
        len: usize,
    ) -> Option<OwnedPayloadRange> {
        let span = PayloadSpanRef::from_range(payload, offset, len)?;
        let mut builder = PacketPayloadBuilder::new();
        builder.push_span_ref(span)?;
        Some(OwnedPayloadRange::from_payload(builder.build()))
    }

    pub(crate) fn raw_record_span(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        offset: usize,
        len: usize,
    ) -> DnsRecordData {
        DnsRecordData::Raw(
            self.copied_owned_range(payload, offset, len).unwrap_or_else(|| {
                OwnedPayloadRange::from_payload(kernel_api::resource::net::PacketPayload::default())
            }),
        )
    }

    pub fn parse_response_payload_for_name(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &DnsNameOwned,
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

    fn parse_and_validate_response_header_payload(
        &self,
        view: &crate::net::payload::PacketPayloadView<'_>,
    ) -> Result<u16, DnsResponseCode> {
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

        Ok(flags)
    }

    fn consume_pending_response_id_payload(
        &self,
        view: &crate::net::payload::PacketPayloadView<'_>,
    ) -> Result<(), DnsResponseCode> {
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
        if id_valid {
            return Ok(());
        }

        log::warn!(
            "[NET] DNS: Response with unexpected transaction ID 0x{:04x}, dropping (possible cache poisoning attempt)",
            response_id
        );
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
        Err(DnsResponseCode::FormatError)
    }

    fn handle_response_code_payload(
        &self,
        flags: u16,
        expected_name: &DnsNameOwned,
        current_tick: u64,
    ) -> Result<(), DnsResponseCode> {
        let rcode = DnsResponseCode::from_u8((flags & 0x0F) as u8);
        if rcode as u8 == DnsResponseCode::NoError as u8 {
            return Ok(());
        }

        self.stats.errors.fetch_add(1, Ordering::Relaxed);
        self.cache_negative_response_for_name(expected_name, rcode, current_tick);
        Err(rcode)
    }

    fn parse_section_counts_payload(
        &self,
        view: &crate::net::payload::PacketPayloadView<'_>,
    ) -> Result<DnsSectionCounts, DnsResponseCode> {
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

        Ok(DnsSectionCounts {
            qcount,
            acount,
            nscount,
            arcount,
        })
    }

    fn validate_question_section_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: &mut usize,
        qcount: usize,
        expected_name: &DnsNameOwned,
        expected_type: DnsQueryType,
    ) -> Result<(), DnsResponseCode> {
        let mut matched_question = false;
        for _ in 0..qcount {
            let parsed_name = self.parse_name_payload(payload, view, *offset)?;
            let qtype = view
                .read_array::<2>(parsed_name.next_offset)
                .map(u16::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)?;
            if view.read_array::<2>(parsed_name.next_offset + 2).is_none() {
                return Err(DnsResponseCode::FormatError);
            }

            if compare_dns_name_labels(parsed_name.name.labels(), expected_name.labels())
                == core::cmp::Ordering::Equal
                && qtype == expected_type as u16
            {
                matched_question = true;
            }
            *offset = parsed_name.next_offset + 4;
        }

        if matched_question || qcount == 0 {
            return Ok(());
        }

        log::warn!(
            "[NET] DNS: Response Question section does not match query ({:?}), dropping for security",
            expected_type
        );
        Err(DnsResponseCode::FormatError)
    }

    fn skip_authority_section_payload(
        &self,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: &mut usize,
        nscount: usize,
    ) -> Result<(), DnsResponseCode> {
        for _ in 0..nscount {
            if *offset >= view.total_len() {
                break;
            }

            *offset = self.skip_name_payload(view, *offset)?;
            if *offset + 10 > view.total_len() {
                break;
            }

            let rdlength = view
                .read_array::<2>(*offset + 8)
                .map(u16::from_be_bytes)
                .ok_or(DnsResponseCode::FormatError)? as usize;
            *offset += 10 + rdlength;
        }
        Ok(())
    }

    fn parse_response_payload_chained(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &DnsNameOwned,
        expected_type: DnsQueryType,
    ) -> Result<DnsResponseView, DnsResponseCode> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        let flags = self.parse_and_validate_response_header_payload(&view)?;
        self.consume_pending_response_id_payload(&view)?;
        self.handle_response_code_payload(flags, expected_name, current_tick)?;

        let counts = self.parse_section_counts_payload(&view)?;
        let mut offset = DnsHeader::SIZE;
        self.validate_question_section_payload(
            payload,
            &view,
            &mut offset,
            counts.qcount,
            expected_name,
            expected_type,
        )?;

        let records =
            self.parse_answer_section_payload(payload, &view, &mut offset, counts.acount)?;
        self.skip_authority_section_payload(&view, &mut offset, counts.nscount)?;
        let _ = self.parse_answer_section_payload(payload, &view, &mut offset, counts.arcount)?;

        Ok(self.finalize_response_payload(payload, expected_name, current_tick, records))
    }

    pub fn parse_response_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Option<Result<DnsResponseView, DnsResponseCode>> {
        let expected_name = DnsNameOwned::parse_ascii(expected_name).ok()?;
        self.parse_response_payload_for_name(payload, current_tick, &expected_name, expected_type)
    }

    fn parse_name_pointer_payload(
        &self,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: usize,
        len: u8,
        jump_count: usize,
    ) -> Result<DnsNamePointerInfo, DnsResponseCode> {
        let second = view
            .read_array::<1>(offset + 1)
            .map(|bytes| bytes[0])
            .ok_or(DnsResponseCode::FormatError)?;
        let pointer = ((len as usize & 0x3F) << 8) | second as usize;
        let new_jump_count = jump_count + 1;
        if new_jump_count > 128 || pointer >= view.total_len() {
            return Err(DnsResponseCode::FormatError);
        }

        Ok(DnsNamePointerInfo {
            pointer,
            pointer_end: offset + 2,
            jump_count: new_jump_count,
        })
    }

    fn parse_name_label_span_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        offset: usize,
        len: u8,
    ) -> Result<OwnedPayloadRange, DnsResponseCode> {
        if len > 63 {
            return Err(DnsResponseCode::FormatError);
        }

        self.copied_owned_range(payload, offset + 1, len as usize)
            .ok_or(DnsResponseCode::FormatError)
    }

    pub(crate) fn parse_name_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: usize,
    ) -> Result<ParsedDnsName, DnsResponseCode> {
        let mut labels = Vec::new();
        let mut text_len = 0usize;
        let mut current = offset;
        let mut pointer_end = None;
        let mut jump_count = 0usize;

        loop {
            let len = view
                .read_array::<1>(current)
                .map(|bytes| bytes[0])
                .ok_or(DnsResponseCode::FormatError)?;
            if len == 0 {
                let next_offset = pointer_end.unwrap_or(current + 1);
                return Ok(ParsedDnsName {
                    name: DnsNameView { labels, text_len },
                    next_offset,
                });
            }

            if len & 0xC0 == 0xC0 {
                let info = self.parse_name_pointer_payload(view, current, len, jump_count)?;
                if pointer_end.is_none() {
                    pointer_end = Some(info.pointer_end);
                }
                current = info.pointer;
                jump_count = info.jump_count;
                continue;
            }

            let span = self.parse_name_label_span_payload(payload, current, len)?;
            if !labels.is_empty() {
                text_len = text_len.saturating_add(1);
            }
            text_len = text_len.saturating_add(span.total_len());
            labels.push(span);
            current = current.saturating_add(1 + len as usize);
            if labels.len() > 128 {
                return Err(DnsResponseCode::FormatError);
            }
        }
    }

    pub(crate) fn parse_txt_record_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        rdata_offset: usize,
        rdlength: usize,
    ) -> DnsRecordData {
        let mut spans = Vec::new();
        let mut offset = rdata_offset;
        let end = rdata_offset.saturating_add(rdlength);
        let mut text_len = 0usize;

        while offset < end {
            let Some(len) = view.read_u8(offset).map(usize::from) else {
                return self.raw_record_span(payload, rdata_offset, rdlength);
            };
            offset = offset.saturating_add(1);
            if offset.saturating_add(len) > end {
                return self.raw_record_span(payload, rdata_offset, rdlength);
            }
            let Some(span) = self.copied_owned_range(payload, offset, len) else {
                return self.raw_record_span(payload, rdata_offset, rdlength);
            };
            text_len = text_len.saturating_add(span.total_len());
            spans.push(span);
            offset = offset.saturating_add(len);
        }

        DnsRecordData::TXT(DnsTxtView { spans, text_len })
    }

    fn finalize_response_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        _expected_name: &DnsNameOwned,
        _current_tick: u64,
        records: Vec<DnsRecordMeta>,
    ) -> DnsResponseView {
        self.stats.responses_received.fetch_add(1, Ordering::Relaxed);
        let response_payload = self
            .copied_owned_range(payload, 0, payload.total_len())
            .and_then(OwnedPayloadRange::into_payload)
            .unwrap_or_default();
        DnsResponseView {
            payload: response_payload,
            records,
        }
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

    fn parse_record_header_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: &mut usize,
    ) -> Result<Option<DnsRecordHeader>, DnsResponseCode> {
        if *offset >= view.total_len() {
            return Ok(None);
        }

        let parsed_name = self.parse_name_payload(payload, view, *offset)?;
        *offset = parsed_name.next_offset;
        if *offset + 10 > view.total_len() {
            return Ok(None);
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
            return Ok(None);
        }

        Ok(Some(DnsRecordHeader {
            name: parsed_name.name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata_offset: *offset,
        }))
    }

    fn record_class_from_u16(&self, rclass: u16) -> DnsQueryClass {
        if rclass == DnsQueryClass::IN as u16 {
            DnsQueryClass::IN
        } else {
            DnsQueryClass::IN
        }
    }

    fn build_record_meta_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        header: DnsRecordHeader,
    ) -> DnsRecordMeta {
        let record_data = self.parse_record_data_payload(
            payload,
            view,
            header.rtype,
            header.rdlength,
            header.rdata_offset,
        );

        DnsRecordMeta {
            name: header.name,
            rtype: DnsRecordType::from_u16(header.rtype),
            rclass: self.record_class_from_u16(header.rclass),
            ttl: header.ttl,
            data: record_data,
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
            let Some(header) = self.parse_record_header_payload(payload, view, offset)? else {
                break;
            };

            let next_offset = header.rdata_offset + header.rdlength;
            if records.len() < DNS_MAX_ANSWER_COUNT {
                records.push(self.build_record_meta_payload(payload, view, header));
            }
            *offset = next_offset;
        }

        Ok(records)
    }
}
