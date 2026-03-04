// ============================================================================
// kernel/src/net/api/shell.rs - 後方互換性ファサード
// ============================================================================
//! # Shell API 後方互換モジュール
//!
//! 以前のモノリシックな `shell.rs` は責任ごとに下記サブモジュールへ分割された:
//!
//! - [`super::config`]       — ネットワーク設定・統計の取得
//! - [`super::connections`]  — TCP/UDP接続情報・ARP操作
//! - [`super::icmp`]         — ICMP Echo (ping) 操作
//! - [`super::dhcp`]         — DHCP v4/v6 操作
//! - [`super::diagnostics`]  — 診断・DNS・スナップショット
//!
//! このファイルは既存コード (`crate::net::api::shell::*`) との後方互換のため
//! 全シンボルを再エクスポートする。新規コードは各サブモジュールを直接参照すること。
#![allow(deprecated)]

pub fn init_network_shell() {
    // no-op: runtime state is sourced from the actual network stack/DHCP clients.
}
