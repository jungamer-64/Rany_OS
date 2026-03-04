// ============================================================================
// src/net/mod.rs - Network Subsystem
// ============================================================================
//! # ExoRust ネットワークサブシステム
//!
//! OSI参照モデルに沿ったレイヤ構成でゼロコピーネットワークスタックを提供する。
//!
//! ## モジュール構成
//! - [`l2`] — データリンク層 (Ethernet, ARP)
//! - [`l3`] — ネットワーク層 (IPv4, IPv6, ICMP, ICMPv6, IGMP, NDP)
//! - [`l4`] — トランスポート層 (TCP, UDP, Endpoint管理)
//! - [`services`] — アプリケーション層サービス (DHCP, DNS, mDNS, NTP, HTTP)
//! - [`security`] — セキュリティ (TLS, X.509, RSA, ECDH)
//! - [`datapath`] — データパス最適化 (ゼロコピー, メモリプール, 適応的ポーリング等)
//! - [`runtime`] — ランタイム統合 (スタック, ブリッジ, タイムアウト管理)
//! - [`api`] — 外部向けAPI (設定, 診断, 接続管理)
//! - [`obs`] — オブザーバビリティ (カウンタ, トレース, スナップショット)
//! - [`drivers`] — ドライバ登録
//!
//! ## dead_code について
//!
//! ネットワークスタックは段階的に構築されており、各レイヤのビルディングブロック
//! （ヘルパー関数、定数、内部フィールド等）が即座に全て使用されるわけではない。
//! runtime統合が進むにつれて順次使用されるため、モジュール全体で抑制する。

#![allow(dead_code)]

pub mod api;
pub mod defaults;
pub mod obs;
pub mod types;

pub mod l2;
pub mod l3;
pub mod l4;
pub mod services;
pub mod security;
pub mod datapath;
pub mod runtime;
pub mod drivers;
pub mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    pub use crate::net::tests::qemu::*;
}
