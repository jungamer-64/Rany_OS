// ============================================================================
// kernel/src/net/services/dns/parser.rs - サービス / DNS / パーサ
// ============================================================================

use super::*;
use crate::net::payload::{PacketPayloadView, PayloadRange};
use kernel_api::resource::net::PacketPayload;

struct DnsSectionCounts {
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

pub(super) struct DnsQuestion<'a> {
    pub(super) id: u16,
    pub(super) name: &'a DnsNameOwned,
    pub(super) kind: DnsQueryType,
}

pub(super) enum DnsReply {
    Unrelated,
    Truncated,
    Answer(Result<DnsResponseView, DnsResponseCode>),
}

struct MatchedReply {
    flags: u16,
    answer_offset: usize,
}

impl MatchedReply {
    fn matches(payload: &PacketPayload, question: &DnsQuestion<'_>) -> Option<Self> {
        let view = PacketPayloadView::new(payload);
        let flags = view.read_array::<2>(2).map(u16::from_be_bytes)?;
        // QR must indicate a response and OPCODE must match standard QUERY.
        if flags & 0xf800 != 0x8000 || view.read_array::<2>(0) != Some(question.id.to_be_bytes()) {
            return None;
        }
        let answer_offset = DnsClient::match_question(payload, &view, question).ok()?;
        Some(Self {
            flags,
            answer_offset,
        })
    }

    fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }
}

impl DnsClient {
    pub(super) fn parse_reply(
        &self,
        payload: PacketPayload,
        question: &DnsQuestion<'_>,
    ) -> DnsReply {
        let Some(reply) = MatchedReply::matches(&payload, question) else {
            return DnsReply::Unrelated;
        };
        if reply.is_truncated() {
            return DnsReply::Truncated;
        }
        DnsReply::Answer(self.parse_matched_response(
            payload,
            crate::task::current_tick(),
            question.name,
            reply.flags,
            reply.answer_offset,
        ))
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

        if acount > 1024 || nscount > 1024 || arcount > 1024 {
            log::warn!(
                "[NET] DNS: Response with excessive record counts (A: {}, NS: {}, AR: {}), dropping",
                acount,
                nscount,
                arcount
            );
            return Err(DnsResponseCode::FormatError);
        }

        Ok(DnsSectionCounts {
            acount,
            nscount,
            arcount,
        })
    }

    fn match_question(
        payload: &PacketPayload,
        view: &PacketPayloadView<'_>,
        expected: &DnsQuestion<'_>,
    ) -> Result<usize, DnsResponseCode> {
        if view.read_array::<2>(4) != Some(1u16.to_be_bytes()) {
            return Err(DnsResponseCode::FormatError);
        }
        let parsed = Self::parse_name_payload(payload, view, DnsHeader::SIZE)?;
        let kind = view
            .read_array::<2>(parsed.next_offset)
            .map(u16::from_be_bytes);
        let class = view
            .read_array::<2>(parsed.next_offset + 2)
            .map(u16::from_be_bytes);
        if compare_dns_name_view_to_owned(payload, &parsed.name, expected.name).is_ne()
            || kind != Some(expected.kind as u16)
            || class != Some(DnsQueryClass::IN as u16)
        {
            return Err(DnsResponseCode::FormatError);
        }
        Ok(parsed.next_offset + 4)
    }

    fn parse_matched_response(
        &self,
        payload: PacketPayload,
        current_tick: u64,
        expected_name: &DnsNameOwned,
        flags: u16,
        mut offset: usize,
    ) -> Result<DnsResponseView, DnsResponseCode> {
        let view = PacketPayloadView::new(&payload);
        let counts = self.parse_section_counts_payload(&view)?;
        let mut records = Vec::new();
        for _ in 0..counts.acount {
            let header = self.parse_record_header_payload(&payload, &view, &mut offset)?;
            if records.len() < DNS_MAX_ANSWER_COUNT {
                records.push(self.build_record_meta_payload(&payload, &view, header));
            }
        }
        for _ in 0..counts.nscount + counts.arcount {
            self.parse_record_header_payload(&payload, &view, &mut offset)?;
        }
        self.handle_response_code_payload(flags, expected_name, current_tick)?;
        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);
        Ok(DnsResponseView { payload, records })
    }

    fn parse_name_pointer_payload(
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
        payload: &kernel_api::resource::net::PacketPayload,
        offset: usize,
        len: u8,
    ) -> Result<PayloadRange, DnsResponseCode> {
        if len > 63 {
            return Err(DnsResponseCode::FormatError);
        }

        PayloadRange::checked(payload, offset + 1, len as usize).ok_or(DnsResponseCode::FormatError)
    }

    pub(crate) fn parse_name_payload(
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: usize,
    ) -> Result<ParsedDnsName, DnsResponseCode> {
        let mut labels = Vec::new();
        let mut text_len = 0usize;
        let mut current = offset;
        let mut pointer_end = None;
        let mut jump_count = 0usize;

        // LOOP_PROOF: mode=event; reason=Each label advances the packet cursor and label count, each pointer consumes the independent 128-jump budget, and end or budget or malformed input returns.;
        loop {
            let len = view
                .read_array::<1>(current)
                .map(|bytes| bytes[0])
                .ok_or(DnsResponseCode::FormatError)?;
            if len == 0 {
                let next_offset = pointer_end.unwrap_or(current + 1);
                return Ok(ParsedDnsName {
                    name: DnsNameView::from_parsed_labels(labels, text_len),
                    next_offset,
                });
            }

            if len & 0xC0 == 0xC0 {
                let info = Self::parse_name_pointer_payload(view, current, len, jump_count)?;
                if pointer_end.is_none() {
                    pointer_end = Some(info.pointer_end);
                }
                current = info.pointer;
                jump_count = info.jump_count;
                continue;
            }

            let span = Self::parse_name_label_span_payload(payload, current, len)?;
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

        // LOOP_PROOF: mode=bounded; reason=Each TXT string consumes its length byte and checked value within the finite RDATA range, while malformed input returns the raw owner.;
        while offset < end {
            let Some(len) = view.read_u8(offset).map(usize::from) else {
                return DnsRecordData::Raw;
            };
            offset = offset.saturating_add(1);
            if offset.saturating_add(len) > end {
                return DnsRecordData::Raw;
            }
            let Some(span) = PayloadRange::checked(payload, offset, len) else {
                return DnsRecordData::Raw;
            };
            text_len = text_len.saturating_add(len);
            spans.push(span);
            offset = offset.saturating_add(len);
        }

        DnsRecordData::TXT(DnsTxtView::from_ranges(spans, text_len))
    }

    fn parse_record_header_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        offset: &mut usize,
    ) -> Result<DnsRecordHeader, DnsResponseCode> {
        let parsed_name = Self::parse_name_payload(payload, view, *offset)?;
        *offset = parsed_name.next_offset;
        if *offset + 10 > view.total_len() {
            return Err(DnsResponseCode::FormatError);
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
            return Err(DnsResponseCode::FormatError);
        }

        let header = DnsRecordHeader {
            name: parsed_name.name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata_offset: *offset,
        };
        *offset += rdlength;
        Ok(header)
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
            rclass: DnsRecordClass::from_u16(header.rclass),
            ttl: header.ttl,
            data: record_data,
        }
    }
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod tests {
    use super::*;
    use crate::net::l4::test_support::packet_fixture_with_data;

    fn payload(bytes: &[u8]) -> PacketPayload {
        PacketPayload::try_single(packet_fixture_with_data(bytes)).expect("fixture payload")
    }

    #[test]
    fn dns_reply_requires_complete_declared_sections_before_cache_admission() {
        let client = DnsClient::new(crate::net::runtime::default_runtime(), 1000);
        let name_data = payload(b"host");
        let name = DnsNameOwned {
            labels: alloc::vec![PayloadRange::checked(&name_data, 0, 4).expect("label")],
            payload: name_data,
        };
        let question = DnsQuestion {
            id: 0x0123,
            name: &name,
            kind: DnsQueryType::A,
        };
        let base = &[
            1, 0x23, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'h', b'o', b's', b't', 0, 0, 1, 0, 1,
        ];
        let record = &[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1];

        for count_offset in [7, 9, 11] {
            for length in [0, 4, 15] {
                let mut message = base.to_vec();
                message[count_offset] = 1;
                message.extend_from_slice(&record[..length]);
                assert!(matches!(
                    client.parse_reply(payload(&message), &question),
                    DnsReply::Answer(Err(DnsResponseCode::FormatError))
                ));
                message[3] |= 3;
                assert!(matches!(
                    client.parse_reply(payload(&message), &question),
                    DnsReply::Answer(Err(DnsResponseCode::FormatError))
                ));
                assert_eq!(client.cache_len(), (0, 0));
            }

            let mut message = base.to_vec();
            message[count_offset] = 1;
            message.extend_from_slice(record);
            let DnsReply::Answer(Ok(response)) = client.parse_reply(payload(&message), &question)
            else {
                panic!("complete response");
            };
            assert_eq!(response.records.len(), usize::from(count_offset == 7));
        }
        let DnsReply::Answer(Ok(nodata)) = client.parse_reply(payload(base), &question) else {
            panic!("complete response with no records");
        };
        assert!(nodata.records.is_empty());
    }

    #[test]
    fn dns_reply_requires_matching_transaction_and_question() {
        let name_data = payload(b"host");
        let labels = alloc::vec![PayloadRange::checked(&name_data, 0, 4).expect("label")];
        let name = DnsNameOwned {
            payload: name_data,
            labels,
        };
        let question = DnsQuestion {
            id: 0x0123,
            name: &name,
            kind: DnsQueryType::A,
        };

        let response =
            b"\x01\x23\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x00\x00\x01\x00\x01";
        let mut unrelated = *response;
        unrelated[1] = 0x24;
        assert!(MatchedReply::matches(&payload(&unrelated), &question).is_none());
        unrelated = *response;
        unrelated[13] = b'p';
        assert!(MatchedReply::matches(&payload(&unrelated), &question).is_none());
        unrelated = *response;
        unrelated[21] = 3;
        unrelated[2] |= 2;
        assert!(MatchedReply::matches(&payload(&unrelated), &question).is_none());

        let mut truncated = *response;
        truncated[2] |= 2;
        let matched =
            MatchedReply::matches(&payload(&truncated), &question).expect("matching partial reply");
        assert!(matched.is_truncated());
        let matched =
            MatchedReply::matches(&payload(response), &question).expect("matching negative reply");
        assert!(!matched.is_truncated());
        assert_eq!(matched.flags & 0xf, 3);
    }
}
