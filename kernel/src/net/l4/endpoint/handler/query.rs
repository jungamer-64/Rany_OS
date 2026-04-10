// ============================================================================
// kernel/src/net/l4/endpoint/handler/query.rs
// ============================================================================
//! NetworkEventHandler DHCP/TCPクエリ系メソッド

use crate::net::l4::endpoint::event::NetworkEvent;
use crate::net::l4::endpoint::handler::common::finish_command;
use crate::net::l4::endpoint::handler::{EventHandleResult, NetworkEventHandler};
use crate::net::l4::endpoint::tcb::{TcpConnectionState, tcb_table};
use crate::net::l4::endpoint::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;

impl NetworkEventHandler {
    pub(super) fn handle_query_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
    ) -> EventHandleResult {
        match event {
            NetworkEvent::GetDhcpState {
                if_id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                if let Some(if_id) = if_id {
                    crate::net::api::dhcp::get_dhcp_state_snapshot_in(runtime, NetIfId(if_id))
                } else {
                    crate::net::api::dhcp::dhcp_state_snapshot_in(runtime)
                },
            ),
            NetworkEvent::ListDhcpStates { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::dhcp::list_dhcp_states_snapshot_in(runtime),
            ),
            NetworkEvent::DhcpRenew { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let mut touched = false;
                let mut err_msg: Option<alloc::string::String> = None;

                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    client.force_renew_or_restart(now);
                    touched = true;
                }

                if err_msg.is_none() {
                    match dhcp::primary_v6_client_lock_in(runtime).lock() {
                        Ok(guard6) => {
                            if let Some(ref client6) = *guard6 {
                                if let Err(e) = client6.force_renew_or_restart(now) {
                                    err_msg = Some(alloc::string::String::from(e));
                                } else {
                                    touched = true;
                                }
                            }
                        }
                        Err(_) => {
                            err_msg = Some(alloc::string::String::from(
                                "DHCPv6 global client lock poisoned",
                            ))
                        }
                    }
                }

                let result = if let Some(error) = err_msg {
                    Err(error)
                } else if !touched {
                    Err(alloc::string::String::from(
                        "DHCP runtime is not initialized",
                    ))
                } else {
                    Ok(())
                };

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpRelease { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut released = false;
                // DHCPv4 Release
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    client.release();
                    released = true;
                }
                // DHCPv6 Release (RFC 8415 Section 18.2.6)
                if let Ok(guard) = dhcp::primary_v6_client_lock_in(runtime).lock() {
                    if let Some(ref client) = *guard {
                        client.release();
                        released = true;
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(released);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpDiscover { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let mut offer = None;

                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    let _ = client.drive(now, 1000);
                    if let Some(lease_offer) = client.offered_lease() {
                        offer = Some(crate::net::api::dhcp::DhcpOfferInfo {
                            server_ip: *lease_offer.server_ip.as_bytes(),
                            offered_ip: *lease_offer.ip_address.as_bytes(),
                        });
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(offer);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpInform { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let result = if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    match client.inform(now) {
                        Ok(true) => Ok(()),
                        Ok(false) => {
                            Err(alloc::string::String::from("failed to enqueue DHCPINFORM"))
                        }
                        Err(e) => Err(alloc::string::String::from(e)),
                    }
                } else {
                    Err(alloc::string::String::from(
                        "DHCPv4 runtime is not initialized",
                    ))
                };

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpLastDeclined { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    ip = client.last_declined_ip().map(|address| *address.as_bytes());
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(ip);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpLastReleased { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    ip = client.last_released_ip().map(|address| *address.as_bytes());
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(ip);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::GetTcpConnections { result_slot, waker } => {
                let snapshots = tcb_table().list_connections();
                let connections: alloc::vec::Vec<_> = snapshots
                    .into_iter()
                    .map(|snapshot| {
                        let state = match snapshot.state {
                            TcpConnectionState::Closed => "CLOSED",
                            TcpConnectionState::Listen => "LISTEN",
                            TcpConnectionState::SynSent => "SYN_SENT",
                            TcpConnectionState::SynReceived => "SYN_RCVD",
                            TcpConnectionState::Established => "ESTABLISHED",
                            TcpConnectionState::FinWait1 => "FIN_WAIT1",
                            TcpConnectionState::FinWait2 => "FIN_WAIT2",
                            TcpConnectionState::CloseWait => "CLOSE_WAIT",
                            TcpConnectionState::Closing => "CLOSING",
                            TcpConnectionState::LastAck => "LAST_ACK",
                            TcpConnectionState::TimeWait => "TIME_WAIT",
                        };
                        crate::net::api::connections::TcpConnectionInfo {
                            local_addr: alloc::format!("{}", snapshot.local),
                            remote_addr: alloc::format!("{}", snapshot.remote),
                            state: alloc::string::String::from(state),
                        }
                    })
                    .collect();

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(connections);
                }
                waker.wake();
                EventHandleResult::Success
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
