pub mod stack;
pub mod manager;
pub mod bridge;
pub mod timeouts;
pub(crate) mod host_http_service;

// Compatibility re-exports for moved modules.
pub use crate::net::NetworkError;
pub use crate::net::datapath::{mempool, optimization};
pub use crate::net::l2::{arp, ethernet, igmp};
pub use crate::net::l3::{icmp, icmpv6, ipv4, ipv6, ndp};
pub use crate::net::l4::{tcp, udp};

pub use self::manager::NetIfId;
pub use self::stack::NetworkConfig;
pub use crate::net::l3::ipv4::Ipv4Address;
pub use crate::net::l3::ipv6::Ipv6Address;
