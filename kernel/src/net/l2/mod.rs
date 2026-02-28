pub mod ethernet;
pub mod arp;
pub mod igmp;

// Compatibility for modules that import `super::ipv4` from L2 children.
pub use crate::net::l3::ipv4;
