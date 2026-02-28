pub mod dhcp;
pub mod dns;
pub mod mdns;

// Compatibility for service modules that used old sibling imports.
pub use crate::net::l2::ethernet;
pub use crate::net::l3::ipv4;
