// ============================================================================
// kernel/src/net/l3/ipv4/config_impl.rs - L3 / IPv4 / 設定実装
// ============================================================================

use super::*;

impl Default for Ipv4Config {
    fn default() -> Self {
        Ipv4Config {
            address: Ipv4Address::ANY,
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        }
    }
}

impl Ipv4Config {
    /// Check if an address is on the local subnet
    pub fn is_local(&self, addr: &Ipv4Address) -> bool {
        self.address.same_subnet(addr, self.subnet_mask)
    }

    /// Get broadcast address for the subnet
    pub fn broadcast_address(&self) -> Ipv4Address {
        let net = self.address.apply_mask(self.subnet_mask);
        let inv_mask = Ipv4Address::new([
            !self.subnet_mask.as_bytes()[0],
            !self.subnet_mask.as_bytes()[1],
            !self.subnet_mask.as_bytes()[2],
            !self.subnet_mask.as_bytes()[3],
        ]);
        Ipv4Address::new([
            net.as_bytes()[0] | inv_mask.as_bytes()[0],
            net.as_bytes()[1] | inv_mask.as_bytes()[1],
            net.as_bytes()[2] | inv_mask.as_bytes()[2],
            net.as_bytes()[3] | inv_mask.as_bytes()[3],
        ])
    }
}
