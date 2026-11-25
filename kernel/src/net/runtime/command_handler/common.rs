// ============================================================================
// kernel/src/net/runtime/command_handler/common.rs - ランタイム / コマンドハンドラ / 共通処理
// ============================================================================
//! RuntimeCommandHandler 共通型/ヘルパー

use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::runtime::command::{CommandReplyPayload, CommandReplyTicket};

/// イベント処理の結果
#[derive(Debug)]
pub enum EventHandleResult {
    /// 処理成功
    Success,
    /// ソケットが見つからない
    SocketNotFound(SocketId),
    /// プロトコルエラー
    ProtocolError(EndpointError),
}

#[inline]
pub(super) fn endpoint_ipv4_pair(
    local: EndpointAddr,
    remote: EndpointAddr,
) -> Option<([u8; 4], [u8; 4])> {
    Some((local.as_ipv4()?, remote.as_ipv4()?))
}

#[inline]
pub(super) fn endpoint_is_native_v6_pair(local: EndpointAddr, remote: EndpointAddr) -> bool {
    local.is_ipv6() && remote.is_ipv6() && local.as_ipv4().is_none() && remote.as_ipv4().is_none()
}

#[inline]
pub(super) fn endpoint_error_from_network(error: crate::net::types::NetworkError) -> EndpointError {
    match error {
        crate::net::types::NetworkError::Timer(cause) => EndpointError::Timer(cause),
        crate::net::types::NetworkError::InvalidAddress => EndpointError::InvalidArgument,
        crate::net::types::NetworkError::NetworkUnreachable => EndpointError::NetworkUnreachable,
        _ => EndpointError::Internal,
    }
}

#[inline]
pub(super) fn finish_command<T: CommandReplyPayload>(
    reply: CommandReplyTicket<T>,
    value: T,
) -> EventHandleResult {
    crate::net::runtime::command::complete_command(reply, value);
    EventHandleResult::Success
}
