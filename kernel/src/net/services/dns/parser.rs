use super::*;
use crate::net::payload::PayloadSpan;

impl DnsClient {
    fn raw_record_span(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        offset: usize,
        len: usize,
    ) -> DnsRecordData {
        DnsRecordData::Raw(
            PayloadSpan::from_range(payload, offset, len).unwrap_or_else(|| {
                PayloadSpan::from_payload(kernel_api::resource::net::PacketPayload::default())
            }),
        )
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
            self.cache_negative_response(expected_name, rcode, current_tick);
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

        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);
        if !records.is_empty() {
            self.cache_dns_response(
                expected_name,
                &DnsResponseView {
                    payload: payload.clone(),
                    records: records.clone(),
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

            let label = PayloadSpan::from_range(payload, offset + 1, len as usize)
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
            let Some(label) = PayloadSpan::from_range(payload, rdata_offset + offset, txt_len)
            else {
                return self.raw_record_span(payload, rdata_offset, rdlength);
            };
            spans.push(label);
            offset += txt_len;
        }
        DnsRecordData::TXT(DnsTxtView::from_spans(spans))
    }
}
