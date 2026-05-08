// ============================================================================
// kernel/src/net/runtime/command_handler/common.rs - ランタイム / コマンドハンドラ / 共通処理
// ============================================================================
//! RuntimeCommandHandler 共通型/ヘルパー

use crate::net::datapath::mempool::PacketRef;
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{CommandReplyPayload, CommandReplyTicket, RuntimeCommand};
use crate::net::runtime::manager::NetIfId;
use kernel_api::resource::net::PacketPayload;

/// イベント処理の結果
#[derive(Debug)]
pub enum EventHandleResult {
    /// 処理成功
    Success,
    /// 着信パケット - プロトコルスタックへのオフロード
    IngressPacket {
        if_id: Option<NetIfId>,
        packet: PacketRef,
    },
    /// ソケットが見つからない
    SocketNotFound(SocketId),
    /// プロトコルエラー
    ProtocolError(EndpointError),
    /// 再試行が必要
    Retry(RuntimeCommand),
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
pub(super) fn resolve_ingress_if_id_in(
    runtime: NetRuntimeHandle,
    if_id: Option<NetIfId>,
) -> NetIfId {
    if let Some(if_id) = if_id {
        return if_id;
    }
    crate::net::runtime::device::primary_if_in(runtime)
        .or_else(|| {
            crate::net::runtime::manager::list_interfaces_in(runtime)
                .ok()
                .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
        })
        .unwrap_or_default()
}

#[inline]
pub(super) fn subslice_offset(container: &[u8], subslice: &[u8]) -> Option<usize> {
    let base = container.as_ptr() as usize;
    let sub = subslice.as_ptr() as usize;
    let end = base.checked_add(container.len())?;
    let sub_end = sub.checked_add(subslice.len())?;
    (sub >= base && sub_end <= end).then_some(sub - base)
}

#[inline]
pub(super) fn deliver_raw_payload_if_registered(if_id: NetIfId, payload: PacketPayload) -> bool {
    let Some(endpoint) = crate::net::l4::socket::find_raw_by_scope(if_id) else {
        return false;
    };
    endpoint.deliver_raw_payload(if_id, payload).is_ok()
}

#[inline]
pub(super) fn endpoint_error_from_network(error: crate::net::types::NetworkError) -> EndpointError {
    match error {
        crate::net::types::NetworkError::InvalidAddress => EndpointError::InvalidArgument,
        crate::net::types::NetworkError::NetworkUnreachable => EndpointError::NetworkUnreachable,
        _ => EndpointError::Internal,
    }
}

#[inline]
pub(super) fn tcp_error_from_endpoint_error(error: EndpointError) -> crate::net::l4::tcp::TcpError {
    match error {
        EndpointError::NotConnected => crate::net::l4::tcp::TcpError::ConnectionClosed,
        EndpointError::ConnectionRefused => crate::net::l4::tcp::TcpError::ConnectionRefused,
        EndpointError::Timeout => crate::net::l4::tcp::TcpError::Timeout,
        EndpointError::AddressInUse | EndpointError::PortInUse => {
            crate::net::l4::tcp::TcpError::AddressInUse
        }
        EndpointError::BufferFull => crate::net::l4::tcp::TcpError::BufferFull,
        EndpointError::NetworkUnreachable => crate::net::l4::tcp::TcpError::NetworkUnreachable,
        EndpointError::PermissionDenied => crate::net::l4::tcp::TcpError::PermissionDenied,
        _ => crate::net::l4::tcp::TcpError::InvalidState,
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

#[inline]
pub(super) fn stackless_dhcp_state_unavailable() -> crate::net::api::dhcp::DhcpRuntimeState {
    crate::net::api::dhcp::DhcpRuntimeState {
        v4_state: alloc::string::String::from("Unavailable"),
        v4_assigned_ip: None,
        v4_lease_remaining: None,
        v4_last_declined: None,
        v4_last_released: None,
        v6_state: alloc::string::String::from("Unavailable"),
        v6_assigned_ip: None,
        v6_preferred_remaining: None,
        v6_valid_remaining: None,
    }
}

/// IPv4 ペイロードからトランスポート層の送信元/宛先ポートを抽出する。
///
/// TCP (proto=6) / UDP (proto=17) の場合、ヘッダ先頭 4 バイトに
/// src_port(2) + dst_port(2) が格納されている。
/// ICMP やその他のプロトコルではポート 0 を返す。
#[inline]
pub(super) fn extract_ports(ipv4_data: &[u8], ihl: usize, protocol: u8) -> (u16, u16) {
    // TCP=6, UDP=17 のみポートを持つ
    if (protocol == 6 || protocol == 17) && ipv4_data.len() >= ihl + 4 {
        let src_port = u16::from_be_bytes([ipv4_data[ihl], ipv4_data[ihl + 1]]);
        let dst_port = u16::from_be_bytes([ipv4_data[ihl + 2], ipv4_data[ihl + 3]]);
        (src_port, dst_port)
    } else if protocol == 1 && ipv4_data.len() >= ihl + 2 {
        // ICMP: src_port = type, dst_port = code
        (ipv4_data[ihl] as u16, ipv4_data[ihl + 1] as u16)
    } else {
        (0, 0)
    }
}
