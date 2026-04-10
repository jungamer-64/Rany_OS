use super::*;
use crate::net::payload::PayloadSpan;

impl DnsClient {
    pub(crate) fn parse_txt_record_payload(
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

    pub(crate) fn parse_srv_rdata_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        view: &crate::net::payload::PacketPayloadView<'_>,
        rdata_offset: usize,
    ) -> Option<DnsRecordData> {
        let priority = view.read_array::<2>(rdata_offset).map(u16::from_be_bytes)?;
        let weight = view
            .read_array::<2>(rdata_offset + 2)
            .map(u16::from_be_bytes)?;
        let port = view
            .read_array::<2>(rdata_offset + 4)
            .map(u16::from_be_bytes)?;
        self.parse_name_payload(payload, view, rdata_offset + 6)
            .ok()
            .map(|parsed_name| DnsRecordData::SRV {
                priority,
                weight,
                port,
                target: parsed_name.name,
            })
    }
}
