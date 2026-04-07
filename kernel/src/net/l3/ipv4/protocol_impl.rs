use super::*;

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            2 => IpProtocol::Igmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            47 => IpProtocol::Gre,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Icmp => 1,
            IpProtocol::Igmp => 2,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Gre => 47,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::Unknown(v) => v,
        }
    }
}
