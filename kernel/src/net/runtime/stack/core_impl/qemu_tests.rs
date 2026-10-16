use super::*;

fn register_operational_interface(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &'static str,
    preference: crate::net::runtime::manager::PrimaryPreference,
    config: NetworkConfig,
) -> NetIfId {
    let if_id = crate::net::runtime::manager::register_interface_in(runtime, name, preference)
        .expect("register interface");
    crate::net::runtime::manager::set_interface_config_in(runtime, if_id, config)
        .expect("configure interface");
    crate::net::runtime::manager::set_interface_link_state_in(
        runtime,
        if_id,
        crate::net::runtime::manager::LinkState::Up,
    )
    .expect("raise interface link");
    if_id
}

fn production_stacks_converge_on_primary_and_remove_stopped_interfaces() {
    let runtime = crate::net::runtime::create_runtime().expect("isolated network runtime");
    crate::net::runtime::manager::init_network_manager_in(runtime);
    let if_a = register_operational_interface(
        runtime,
        "if-a",
        crate::net::runtime::manager::PrimaryPreference::Auto,
        NetworkConfig::default(),
    );
    let mut config_b = NetworkConfig::default();
    config_b.mac = crate::net::l2::ethernet::MacAddress::from_octets(2, 0, 0, 0, 0, 2);
    let if_b = register_operational_interface(
        runtime,
        "if-b",
        crate::net::runtime::manager::PrimaryPreference::Prefer,
        config_b,
    );

    let revision = crate::net::runtime::manager::current_interface_topology_revision_in(runtime);
    let mut stacks = core::array::from_fn::<_, 4, _>(|_| NetworkStack::new_in(runtime));
    assert!(
        stacks
            .iter()
            .all(|stack| stack.needs_interface_topology_revision(revision))
    );

    let manager_guard = runtime.context().manager.lock().expect("lock manager");
    assert!(crate::net::runtime::manager::try_interface_topology_in(runtime).is_none());
    drop(manager_guard);

    for stack in &mut stacks {
        let topology = crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("topology snapshot");
        stack.reconcile_interface_topology(topology);
        assert!(!stack.needs_interface_topology_revision(revision));
        assert_eq!(stack.default_interface_id(), Some(if_b));
        assert!(stack.interfaces.contains_key(&if_a));
        assert!(stack.interfaces.contains_key(&if_b));
    }

    crate::net::runtime::manager::set_interface_link_state_in(
        runtime,
        if_b,
        crate::net::runtime::manager::LinkState::Down,
    )
    .expect("drop primary link");
    let failover_revision =
        crate::net::runtime::manager::current_interface_topology_revision_in(runtime);
    assert_eq!(
        crate::net::runtime::manager::primary_interface_in(runtime),
        Some(if_a)
    );

    for stack in &mut stacks {
        let topology = crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("failover topology snapshot");
        stack.reconcile_interface_topology(topology);
        assert!(!stack.needs_interface_topology_revision(failover_revision));
        assert_eq!(stack.default_interface_id(), Some(if_a));
        assert!(stack.interfaces.contains_key(&if_a));
        assert!(!stack.interfaces.contains_key(&if_b));
    }
}

fn identical_topology_snapshot_preserves_interface_protocol_state() {
    let runtime = crate::net::runtime::create_runtime().expect("isolated network runtime");
    crate::net::runtime::manager::init_network_manager_in(runtime);
    let mut config = NetworkConfig::default();
    config.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::from_mac(
        config.mac.as_bytes(),
    ));
    let if_id = register_operational_interface(
        runtime,
        "if-state",
        crate::net::runtime::manager::PrimaryPreference::Auto,
        config,
    );
    let mut stack = NetworkStack::new_in(runtime);
    stack.reconcile_interface_topology(
        crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("initial topology snapshot"),
    );

    let neighbor = crate::net::l3::ipv6::Ipv6Address::new([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
    ]);
    stack.ndp_cache_insert_on(if_id, &neighbor, [1, 2, 3, 4, 5, 6], 42);
    assert!(
        stack.interfaces[&if_id]
            .ndp
            .as_ref()
            .expect("NDP processor")
            .cache()
            .lookup(&neighbor)
            .is_some()
    );

    stack.reconcile_interface_topology(
        crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("identical topology snapshot"),
    );
    assert!(
        stack.interfaces[&if_id]
            .ndp
            .as_ref()
            .expect("preserved NDP processor")
            .cache()
            .lookup(&neighbor)
            .is_some()
    );
}

fn timeout_retries_after_queue_loss_and_manager_contention() {
    use crate::net::runtime::command::{ControlCommand, RuntimeCommand};

    let runtime = crate::net::runtime::create_runtime().expect("isolated network runtime");
    crate::net::runtime::manager::init_network_manager_in(runtime);
    let if_id = register_operational_interface(
        runtime,
        "if-retry",
        crate::net::runtime::manager::PrimaryPreference::Auto,
        NetworkConfig::default(),
    );
    let mut stack = NetworkStack::new_in(runtime);
    stack.reconcile_interface_topology(
        crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("initial topology snapshot"),
    );

    let mut changed = NetworkConfig::default();
    changed.icmp_echo_enabled = false;
    crate::net::runtime::manager::set_interface_config_in(runtime, if_id, changed)
        .expect("change interface configuration");
    let changed_revision =
        crate::net::runtime::manager::current_interface_topology_revision_in(runtime);
    assert!(stack.needs_interface_topology_revision(changed_revision));

    let queue = crate::net::runtime::command::command_resources_for_cpu_in(
        runtime,
        crate::cpu::CurrentCpu::acquire()
            .expect("topology retry CPU")
            .id(),
    )
    .expect("current CPU command resources")
    .command_queue
    .clone();
    // LOOP_PROOF: mode=condition; reason=This isolated fixture has no producers and each recv removes one command from the bounded queue until empty.;
    while queue.recv().is_some() {}
    for _ in 0..crate::net::runtime::command::RuntimeCommandQueue::CAPACITY {
        assert!(queue.send(RuntimeCommand::Control(
            ControlCommand::ProcessGlobalTimeouts,
        )));
    }
    stack.process_timeouts();
    assert!(stack.needs_interface_topology_revision(changed_revision));
    // LOOP_PROOF: mode=condition; reason=The fixture has stopped producing commands and recv drains at most the queue capacity before returning None.;
    while queue.recv().is_some() {}

    stack.process_timeouts();
    let dirty = queue.recv().expect("timeout retry command");
    let manager_guard = runtime.context().manager.lock().expect("lock manager");
    assert!(matches!(
        crate::net::runtime::command_handler::RuntimeCommandHandler::new()
            .handle_event_with_stack_in(runtime, dirty, &mut stack),
        crate::net::runtime::command_handler::EventHandleResult::Success
    ));
    assert!(stack.needs_interface_topology_revision(changed_revision));
    drop(manager_guard);

    stack.process_timeouts();
    let dirty = queue.recv().expect("contention retry command");
    assert!(matches!(
        crate::net::runtime::command_handler::RuntimeCommandHandler::new()
            .handle_event_with_stack_in(runtime, dirty, &mut stack),
        crate::net::runtime::command_handler::EventHandleResult::Success
    ));
    assert!(!stack.needs_interface_topology_revision(changed_revision));
    assert_eq!(stack.interface_config(if_id), Some(changed));
}

pub(crate) fn interface_topology() -> bool {
    production_stacks_converge_on_primary_and_remove_stopped_interfaces();
    identical_topology_snapshot_preserves_interface_protocol_state();
    timeout_retries_after_queue_loss_and_manager_contention();
    true
}
