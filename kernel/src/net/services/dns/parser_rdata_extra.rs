use super::*;

impl DnsClient {
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
