// ============================================================================
// kernel/src/net/l4/endpoint/handler/query.rs
// ============================================================================
//! RuntimeCommandHandler DHCP/TCPクエリ系メソッド

use crate::net::runtime::command::RuntimeCommand;
use crate::net::runtime::command_handler::common::finish_command;
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};
use crate::net::l4::tcp::tcb::{TcpConnectionState, tcb_table};
use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;

impl RuntimeCommandHandler {
    pub(super) fn handle_query_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::GetDhcpState {
                if_id,
                result_slot,
                waker,
            }) => finish_command(
                result_slot,
                waker,
                if let Some(if_id) = if_id {
                    crate::net::api::dhcp::get_dhcp_state_snapshot_in(runtime, NetIfId(if_id))
                } else {
                    crate::net::api::dhcp::dhcp_state_snapshot_in(runtime)
                },
            ),
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ListDhcpStates { result_slot, waker }) => finish_command(
                result_slot,
                waker,
                crate::net::api::dhcp::list_dhcp_states_snapshot_in(runtime),
            ),
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpRenew { result_slot, waker }) => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let mut touched = false;
                let mut err_msg: Option<alloc::string::String> = None;

                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    client.force_renew_or_restart(now);
                    touched = true;
                }

                if err_msg.is_none() {
                    if let Some(client6) = dhcp::primary_v6_client_in(runtime) {
                        if let Err(e) = client6.force_renew_or_restart(now) {
                            err_msg = Some(alloc::string::String::from(e));
                        } else {
                            touched = true;
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
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpRelease { result_slot, waker }) => {
                use crate::net::services::dhcp;

                let mut released = false;
                // DHCPv4 Release
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    client.release();
                    released = true;
                }
                // DHCPv6 Release (RFC 8415 Section 18.2.6)
                if let Some(client6) = dhcp::primary_v6_client_in(runtime) {
                    client6.release();
                    released = true;
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(released);
                }
                waker.wake();
                EventHandleResult::Success
            }
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpDiscover { result_slot, waker }) => {
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
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpInform { result_slot, waker }) => {
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
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpLastDeclined { result_slot, waker }) => {
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
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpLastReleased { result_slot, waker }) => {
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
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::GetTcpConnections { result_slot, waker }) => {
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
