// ============================================================================
// kernel/src/net/l3/mod.rs - L3 — ネットワーク層
// ============================================================================
//! # L3 — ネットワーク層
//!
//! IPv4/IPv6プロトコル処理、ICMP/ICMPv6、IGMP、NDP。

pub mod icmp;
pub mod icmpv6;
pub mod igmp;
pub mod ipv4;
pub mod ipv6;
pub mod ndp;
