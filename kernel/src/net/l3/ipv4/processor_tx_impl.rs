// ============================================================================
// kernel/src/net/l3/ipv4/processor_tx_impl.rs - L3 / IPv4 / 送信処理
// ============================================================================

use super::*;

impl Ipv4Processor {
    /// Build an IP packet for transmission
    pub fn build_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
        dst: Ipv4Address,
        protocol: IpProtocol,
    ) -> Option<Ipv4PacketMut<'a>> {
        let mut packet = Ipv4PacketMut::new(buffer)?;
        packet
            .init_header()
            .set_source(self.config.address)
            .set_destination(dst)
            .set_protocol(protocol)
            .set_identification(self.next_id(dst));
        Some(packet)
    }
}
