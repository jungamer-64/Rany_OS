// ============================================================================
// kernel/src/net/api/icmp.rs - ICMP Echo (ping) 操作
// ============================================================================
//! ICMP Echoリクエストの送信（同期・非同期）。

use alloc::string::String;

extern crate alloc;

pub fn send_icmp_echo(target: [u8; 4], seq: u16) -> Result<f32, String> {
    crate::net::runtime::bridge::send_real_icmp_echo(target, seq)
        .map(|rtt| rtt as f32)
        .map_err(String::from)
}

/// 非同期ICMP Echo送信
///
/// ICMP Echoリクエストをイベントキュー経由で送信する。
/// エグゼキュータが起動しているasyncコンテキストから呼び出す。
/// 応答を待機するには別途ICMP応答のリスニング機構が必要。
pub fn send_icmp_echo_async(target: [u8; 4], seq: u16) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::IcmpEchoRequest {
            target,
            sequence: seq,
        },
    );
    true
}
