use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;

use crate::net::api::{config, connections, dhcp, diagnostics, firewall};
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::runtime::context::NetCpuResources;
use crate::net::runtime::{NetRuntimeHandle, create_runtime, manager};
use crate::net::services::mdns;
use crate::task::{TimeoutResult, with_timeout};

// The service host retains the consumer receipts. The fixture closes admission
// and observes their completion before returning to the next network case.
struct CommandRuntime {
    runtime: NetRuntimeHandle,
    resources: Vec<Arc<NetCpuResources>>,
}

impl CommandRuntime {
    fn new() -> Self {
        let runtime = create_runtime().expect("command API runtime");
        let resources = crate::cpu::snapshot()
            .online()
            .iter()
            .map(|cpu| {
                crate::services::start_network_commands(runtime, cpu)
                    .expect("service host command admission");
                runtime.context().cpu_resources(cpu).expect("CPU resources")
            })
            .collect();
        Self { runtime, resources }
    }

    async fn drain(self) {
        for resources in &self.resources {
            resources.command_queue.begin_drain();
        }
        complete(async {
            // LOOP_PROOF: mode=condition; reason=The condition ends when every queue is quiescent and its service receipt is returned, with timer waits and an owning deadline bounding observation.;
            while self.resources.iter().any(|resources| {
                !resources.command_queue.is_quiescent()
                    || crate::services::network_consumer_active(self.runtime.id(), resources.cpu_id)
            }) {
                crate::task::sleep_ms(1)
                    .await
                    .expect("consumer drain timer");
            }
        })
        .await;
    }
}

async fn complete<F: Future>(future: F) -> F::Output {
    match with_timeout(future, 1000).await {
        TimeoutResult::Completed(output) => output,
        TimeoutResult::TimedOut => panic!("service-owned network command did not complete"),
        TimeoutResult::TimerFailed(cause) => panic!("network command deadline: {cause:?}"),
    }
}

pub async fn api_queries_complete_through_service_consumers_smoke() -> bool {
    let owner = CommandRuntime::new();
    let runtime = owner.runtime;
    assert!(
        complete(config::list_interfaces_in(runtime))
            .await
            .is_empty()
    );
    assert!(
        complete(connections::get_tcp_connections_in(runtime))
            .await
            .is_empty()
    );
    assert!(
        complete(connections::get_udp_endpoints_in(runtime))
            .await
            .is_empty()
    );
    assert!(
        complete(connections::get_arp_cache_in(runtime))
            .await
            .is_empty()
    );
    assert!(
        complete(diagnostics::network_recent_events_in(runtime, 1))
            .await
            .len()
            <= 1
    );
    assert_eq!(
        complete(firewall::firewall_status_in(runtime)).await,
        "Stack unavailable"
    );
    assert_eq!(
        complete(firewall::firewall_enable_in(runtime)).await,
        Err("Stack unavailable")
    );
    crate::net::runtime::stack::init_in(runtime).expect("runtime stack admission");
    complete(firewall::firewall_enable_in(runtime))
        .await
        .expect("enable firewall");
    assert!(
        complete(firewall::firewall_status_in(runtime))
            .await
            .starts_with("Firewall: ENABLED\n")
    );
    complete(firewall::firewall_disable_in(runtime))
        .await
        .expect("disable firewall");
    assert!(
        complete(firewall::firewall_status_in(runtime))
            .await
            .starts_with("Firewall: DISABLED\n")
    );
    assert!(
        !complete(dhcp::dhcp_state_in(runtime))
            .await
            .v4_state
            .is_empty()
    );
    owner.drain().await;
    true
}

pub async fn api_queries_preserve_runtime_ownership_smoke() -> bool {
    let first = CommandRuntime::new();
    let second = CommandRuntime::new();
    manager::init_network_manager_in(first.runtime);
    manager::init_network_manager_in(second.runtime);
    let first_id =
        manager::register_interface_in(first.runtime, "query-a0", manager::PrimaryPreference::Auto)
            .expect("first interface");
    let second_id = manager::register_interface_in(
        second.runtime,
        "query-b0",
        manager::PrimaryPreference::Auto,
    )
    .expect("second interface");
    let second_next_id = manager::register_interface_in(
        second.runtime,
        "query-b1",
        manager::PrimaryPreference::Auto,
    )
    .expect("second next interface");

    let names: Vec<_> = complete(config::list_interfaces_in(second.runtime))
        .await
        .into_iter()
        .map(|interface| interface.name)
        .collect();
    assert_eq!(names, alloc::vec!["query-b0", "query-b1"]);
    let first_names: Vec<_> = complete(config::list_interfaces_in(first.runtime))
        .await
        .into_iter()
        .map(|interface| interface.name)
        .collect();
    assert_eq!(first_names, alloc::vec!["query-a0"]);
    let states = complete(dhcp::list_dhcp_states_in(second.runtime)).await;
    assert_eq!(states.len(), 2);
    assert!(states.iter().any(|state| state.if_id == second_id.0));
    assert!(states.iter().any(|state| state.if_id == second_next_id.0));
    let first_states = complete(dhcp::list_dhcp_states_in(first.runtime)).await;
    assert_eq!(first_states.len(), 1);
    assert_eq!(first_states[0].if_id, first_id.0);
    first.drain().await;
    second.drain().await;
    true
}

pub async fn mdns_configuration_commands_preserve_service_ownership_smoke() -> bool {
    let first = CommandRuntime::new();
    let second = CommandRuntime::new();
    mdns::init_in(first.runtime, "query-a".into(), Ipv4Address::ANY);
    mdns::init_in(second.runtime, "query-b".into(), Ipv4Address::ANY);
    let mut service = mdns::take_service_for_task_in(first.runtime).expect("mDNS owner");
    assert!(mdns::take_service_for_task_in(first.runtime).is_none());
    assert_eq!(service.local_ip(), Ipv4Address::ANY);
    let assigned = Ipv4Address::new([10, 0, 0, 42]);
    mdns::set_local_ip_in(first.runtime, assigned);
    assert_eq!(service.local_ip(), Ipv4Address::ANY);

    // Normal run drains configuration before binding/joining. This fixture has
    // no initialized IP stack: joining completes with a service failure,
    // or the normal deadline cancels the future at its Pending boundary.
    match with_timeout(service.run(), 100).await {
        TimeoutResult::Completed(Err(_)) | TimeoutResult::TimedOut => {}
        TimeoutResult::Completed(Ok(())) => {
            panic!("mDNS responder unexpectedly exited successfully")
        }
        TimeoutResult::TimerFailed(cause) => panic!("mDNS deadline: {cause:?}"),
    }
    assert_eq!(service.local_ip(), assigned);
    let other = mdns::take_service_for_task_in(second.runtime).expect("second mDNS owner");
    assert_eq!(other.local_ip(), Ipv4Address::ANY);
    first.drain().await;
    second.drain().await;
    true
}
