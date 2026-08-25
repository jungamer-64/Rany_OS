// ============================================================================
// kernel/src/net/api/mod.rs - ネットワークAPI
// ============================================================================
//! # ネットワークAPI
//!
//! 外部向けの設定・診断・接続管理・ファイアウォールインターフェース。

pub mod config;
pub mod connections;
pub mod dhcp;
pub mod diagnostics;
pub mod firewall;
pub mod icmp;

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::task::{Context, Poll};

    use crate::net::runtime::{
        NetRuntimeHandle, create_runtime, default_runtime, manager,
        reset_runtime_registry_for_tests,
    };

    fn run_command_future<F>(runtime: NetRuntimeHandle, future: F) -> F::Output
    where
        F: Future,
    {
        let current = crate::cpu::CurrentCpu::acquire().expect("test CPU-local state");
        let resources =
            crate::net::runtime::command::command_resources_for_cpu_in(runtime, current.id())
                .expect("test command resources");
        let handler = crate::net::runtime::command_handler::RuntimeCommandHandler::new();
        let waker = crate::net::l4::test_support::noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);

        for _ in 0..100_000 {
            if let Poll::Ready(output) = Future::poll(future.as_mut(), &mut context) {
                return output;
            }
            while let Some(command) = resources.command_queue.recv() {
                let _ = handler.handle_event_in(runtime, command);
            }
        }

        panic!("network API command future timed out")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn query_apis_complete_through_cpu_local_command_resources() {
        let runtime = default_runtime();
        assert!(run_command_future(runtime, super::config::list_interfaces_in(runtime)).is_empty());
        assert!(
            run_command_future(runtime, super::connections::get_tcp_connections_in(runtime))
                .is_empty()
        );
        assert!(
            run_command_future(runtime, super::connections::get_udp_endpoints_in(runtime))
                .is_empty()
        );
        assert!(
            run_command_future(runtime, super::connections::get_arp_cache_in(runtime)).is_empty()
        );
        assert!(
            run_command_future(
                runtime,
                super::diagnostics::network_recent_events_in(runtime, 1)
            )
            .len()
                <= 1
        );
        assert!(
            run_command_future(runtime, super::firewall::firewall_status_in(runtime))
                .contains("Firewall:")
        );
        assert!(
            !run_command_future(runtime, super::dhcp::dhcp_state_in(runtime))
                .v4_state
                .is_empty()
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn query_apis_preserve_runtime_ownership() {
        reset_runtime_registry_for_tests();
        let runtime_a = default_runtime();
        let runtime_b = create_runtime().expect("runtime b allocation");
        manager::init_network_manager_in(runtime_a);
        manager::init_network_manager_in(runtime_b);

        manager::register_interface_in(runtime_a, "rt-a0", manager::PrimaryPreference::Auto)
            .expect("runtime a interface");
        let if_b0 =
            manager::register_interface_in(runtime_b, "rt-b0", manager::PrimaryPreference::Auto)
                .expect("runtime b interface");
        manager::register_interface_in(runtime_b, "rt-b1", manager::PrimaryPreference::Auto)
            .expect("runtime b interface");

        let interfaces =
            run_command_future(runtime_b, super::config::list_interfaces_in(runtime_b));
        let names: alloc::vec::Vec<_> = interfaces.into_iter().map(|iface| iface.name).collect();
        assert_eq!(
            names,
            alloc::vec![
                alloc::string::String::from("rt-b0"),
                alloc::string::String::from("rt-b1")
            ]
        );

        let states = run_command_future(runtime_b, super::dhcp::list_dhcp_states_in(runtime_b));
        assert_eq!(states.len(), 2);
        assert!(states.iter().any(|state| state.if_id == if_b0.0));
    }
}
