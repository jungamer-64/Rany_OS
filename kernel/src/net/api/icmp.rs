// ============================================================================
// kernel/src/net/api/icmp.rs - ICMP Echo (ping) 操作
// ============================================================================
//! ICMP Echoリクエストの送信（同期・非同期）。

use alloc::string::String;

extern crate alloc;

/// ICMP Echo送信（イベントキュー経由の非同期フォールバック）
///
/// 内部的に `send_icmp_echo_async()` に委任する。
/// RTTを取得するには `ping_async()` または `IcmpEchoFuture` を使用すること。
pub fn send_icmp_echo(target: [u8; 4], seq: u16) -> Result<f32, String> {
    // イベントキュー経由でfire-and-forget送信
    send_icmp_echo_async(target, seq);
    // 同期的にRTTを返すことはできないため、0を返す
    // 実際のRTTを取得するには ping_async().await を使用
    Ok(0.0)
}

/// 非同期ICMP Echo送信（fire-and-forget）
///
/// ICMP Echoリクエストをイベントキュー経由で送信する。
/// エグゼキュータが起動しているasyncコンテキストから呼び出す。
/// 応答を待機するには `ping_async()` または `IcmpEchoFuture` を使用すること。
pub fn send_icmp_echo_async(target: [u8; 4], seq: u16) -> bool {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::IcmpEchoRequest {
            target,
            sequence: seq,
        },
    );
    true
}

/// 非同期ICMP Echo（推奨API）
///
/// ICMP Echo Requestを送信し、応答をFutureで待機する。
/// 完全にイベントキュー経由で動作し、同期ロックを一切取得しない。
///
/// # 使用例
/// ```ignore
/// let result = ping_async([8, 8, 8, 8], 1).await;
/// match result {
///     Ok(echo) => log::info!("RTT: {} us", echo.rtt_us),
///     Err(e) => log::warn!("ping failed: {:?}", e),
/// }
/// ```
pub fn ping_async(
    target: [u8; 4],
    seq: u16,
) -> crate::net::l4::endpoint::futures::IcmpEchoFuture {
    crate::net::l4::endpoint::futures::IcmpEchoFuture::new(target, seq)
}

/// カスタムタイムアウト付き非同期ICMP Echo
pub fn ping_async_with_timeout(
    target: [u8; 4],
    seq: u16,
    timeout_us: u64,
) -> crate::net::l4::endpoint::futures::IcmpEchoFuture {
    crate::net::l4::endpoint::futures::IcmpEchoFuture::with_timeout(target, seq, timeout_us)
}
