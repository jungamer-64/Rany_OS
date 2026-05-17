// ============================================================================
// kernel/src/net/runtime/command_handler/query.rs - ランタイム / コマンドハンドラ / 問い合わせ処理
// ============================================================================
//! RuntimeCommandHandler DHCP/TCPクエリ系メソッド

use crate::net::l4::tcp::tcb::TcpConnectionState;
use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{RuntimeCommand, complete_command};
use crate::net::runtime::command_handler::common::finish_command;
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;

impl RuntimeCommandHandler {
    pub(super) fn handle_query_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetDhcpState { if_id, reply },
            ) => finish_command(
                reply,
                if let Some(if_id) = if_id {
                    crate::net::api::dhcp::get_dhcp_state_snapshot_in(runtime, NetIfId(if_id))
                } else {
                    crate::net::api::dhcp::dhcp_state_snapshot_in(runtime)
                },
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListDhcpStates { reply },
            ) => finish_command(
                reply,
                crate::net::api::dhcp::list_dhcp_states_snapshot_in(runtime),
            ),
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpRenew {
                reply,
            }) => {
                use crate::net::services::dhcp;

                let now = tcp_table_in(runtime).get_current_tick();
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

                complete_command(reply, result);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpRelease { reply },
            ) => {
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

                complete_command(reply, released);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpDiscover { reply },
            ) => {
                use crate::net::services::dhcp;

                let now = tcp_table_in(runtime).get_current_tick();
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

                complete_command(reply, offer);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpInform {
                reply,
            }) => {
                use crate::net::services::dhcp;

                let now = tcp_table_in(runtime).get_current_tick();
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

                complete_command(reply, result);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastDeclined { reply },
            ) => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    ip = client.last_declined_ip().map(|address| *address.as_bytes());
                }

                complete_command(reply, ip);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastReleased { reply },
            ) => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    ip = client.last_released_ip().map(|address| *address.as_bytes());
                }

                complete_command(reply, ip);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetTcpConnections { reply },
            ) => {
                let snapshots = tcp_table_in(runtime).list_connections();
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

                complete_command(reply, connections);
                EventHandleResult::Success
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
