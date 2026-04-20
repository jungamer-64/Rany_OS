// ============================================================================
// kernel/src/net/services/dns/parser_records.rs - サービス / DNS / レコードパーサ
// ============================================================================

use super::*;

impl DnsClient {
    fn parse_named_rdata_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        rdata_offset: usize,
    ) -> Option<DnsRecordData> {
        self.parse_name_payload(payload, view, rdata_offset)
            .ok()
            .map(|parsed_name| DnsRecordData::Name(parsed_name.name))
    }

    fn parse_mx_rdata_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        rdata_offset: usize,
    ) -> Option<DnsRecordData> {
        let preference = view.read_array::<2>(rdata_offset).map(u16::from_be_bytes)?;
        self.parse_name_payload(payload, view, rdata_offset + 2)
            .ok()
            .map(|parsed_name| DnsRecordData::MX(preference, parsed_name.name))
    }

    pub(crate) fn parse_record_data_payload(
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
                .parse_named_rdata_payload(payload, view, rdata_offset)
                .unwrap_or_else(raw_span),
            Some(DnsQueryType::MX) if rdlength >= 3 => self
                .parse_mx_rdata_payload(payload, view, rdata_offset)
                .unwrap_or_else(raw_span),
            Some(DnsQueryType::TXT) => {
                self.parse_txt_record_payload(payload, view, rdata_offset, rdlength)
            }
            Some(DnsQueryType::SRV) if rdlength >= 7 => self
                .parse_srv_rdata_payload(payload, view, rdata_offset)
                .unwrap_or_else(raw_span),
            _ => raw_span(),
        }
    }
}
