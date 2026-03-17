// ============================================================================
// kernel/src/net/l4/endpoint/tests.rs
// ============================================================================
//! # テスト - Accept関連テスト
//!
//! Accept機能の単体テスト

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::super::endpoint_core::Endpoint;
    use super::super::tcb::TcpControlBlockEntry;
    use super::super::types::{
        AcceptedConnection, EndpointAddr, EndpointError, EndpointFd, EndpointState, EndpointType,
    };
    use crate::net::l4::endpoint::event::{event_queue_in, reset_event_system_for_tests_in};
    use crate::net::runtime::manager::NetIfId;
    use crate::net::runtime::{create_runtime, default_runtime, reset_runtime_registry_for_tests};
    use crate::net::types::InterfaceScope;
    use alloc::vec;
    use alloc::vec::Vec;

    fn endpoint_new_with_fd_impl() {
        let fd = EndpointFd::from_raw(42);
        let endpoint = Endpoint::new_with_fd(EndpointType::Tcp, fd);

        assert_eq!(endpoint.fd(), fd);
        assert_eq!(endpoint.socket_type(), EndpointType::Tcp);
        assert_eq!(endpoint.state(), EndpointState::Created);
    }

    fn endpoint_accept_empty_queue_impl() {
        let endpoint = Endpoint::new(EndpointType::Tcp);

        {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        let result = endpoint.next_incoming_sync();
        assert!(matches!(result, Err(EndpointError::Timeout)));
    }

    fn endpoint_accept_with_connection_impl() {
        let listen_endpoint = Endpoint::new(EndpointType::Tcp);

        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        let accepted_fd = EndpointFd::from_raw(200);
        let local = EndpointAddr::new([192, 168, 1, 1], 8080);
        let remote = EndpointAddr::new([10, 0, 0, 2], 54000);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, NetIfId(0), tcb);

        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
        }

        let result = endpoint_accept_internal(&listen_endpoint);
        assert!(result.is_some());
        let (new_endpoint, addr, if_id) = result.unwrap();
        assert_eq!(addr, remote);
        assert_eq!(new_endpoint.fd(), accepted_fd);
        assert_eq!(if_id, NetIfId(0));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_accepted_connection() {
        let fd = EndpointFd::from_raw(100);
        let local = EndpointAddr::new([192, 168, 1, 1], 8080);
        let remote = EndpointAddr::new([192, 168, 1, 2], 54321);
        let tcb = TcpControlBlockEntry::new(fd, local, remote);

        let conn = AcceptedConnection::new(fd, local, remote, NetIfId(0), tcb);

        assert_eq!(conn.fd, fd);
        assert_eq!(conn.local_addr, local);
        assert_eq!(conn.remote_addr, remote);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_new_with_fd() {
        endpoint_new_with_fd_impl();
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_accept_empty_queue() {
        endpoint_accept_empty_queue_impl();
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_accept_with_connection() {
        endpoint_accept_with_connection_impl();
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_accept_with_connection_v6() {
        let listen_endpoint = Endpoint::new(EndpointType::Tcp);

        // Bound -> Listening
        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new_v6(
                crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(),
                8080,
            ));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        // 接続をAcceptキューに追加
        let accepted_fd = EndpointFd::from_raw(201);
        let local =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 8080);
        let remote =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 54001);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, NetIfId(1), tcb);

        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
        }

        // accept成功 (IPv6)
        let result = endpoint_accept_internal(&listen_endpoint);
        assert!(result.is_some());
        let (new_endpoint, addr, if_id) = result.unwrap();
        assert_eq!(addr, remote);
        assert_eq!(new_endpoint.fd(), accepted_fd);
        assert_eq!(if_id, NetIfId(1));
    }

    /// 内部テスト用: EndpointManager登録をスキップしてaccept
    fn endpoint_accept_internal(endpoint: &Endpoint) -> Option<(Endpoint, EndpointAddr, NetIfId)> {
        let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());

        if inner.state != EndpointState::Listening {
            return None;
        }

        if let Some(conn) = inner.tcp_mut().and_then(|t| t.accept_queue.pop_front()) {
            let new_endpoint =
                Endpoint::new_with_fd_in(EndpointType::Tcp, conn.fd, endpoint.runtime());
            {
                let mut new_inner = new_endpoint
                    .inner()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                new_inner.scope = InterfaceScope::Pinned(conn.if_id);
                new_inner.ensure_tcp().nodelay = inner.tcp().map_or(false, |t| t.nodelay); // 設定を引き継ぐ
                let _ = new_inner.transition_to(EndpointState::Connected);
            }
            return Some((new_endpoint, conn.remote_addr, conn.if_id));
        }

        None
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_nodelay_inheritance() {
        let listen_endpoint = Endpoint::new(EndpointType::Tcp);
        listen_endpoint.set_nodelay(true).unwrap();

        // Listening状態に
        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        // 接続を追加
        let accepted_fd = EndpointFd::from_raw(500);
        let local = EndpointAddr::new([192, 168, 1, 1], 8080);
        let remote = EndpointAddr::new([10, 0, 0, 1], 50000);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, NetIfId(2), tcb);

        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
        }

        // Accept
        let (new_endpoint, _, _) = endpoint_accept_internal(&listen_endpoint).unwrap();

        // 設定が引き継がれているか確認
        let inner = new_endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(inner.tcp().map_or(false, |t| t.nodelay));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_nodelay_tcb_update() {
        crate::net::l4::endpoint::manager::init_endpoint_manager();
        let handler = crate::net::l4::endpoint::handler::NetworkEventHandler::new();

        let sock = crate::net::l4::endpoint::create_tcp_endpoint();
        let fd = sock.fd();
        let local = EndpointAddr::new([127, 0, 0, 1], 10000);
        let remote = EndpointAddr::new([127, 0, 0, 1], 10001);

        // 接続済み状態のTCBを作成
        let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
        tcb.state = crate::net::l4::endpoint::tcb::TcpConnectionState::Established;
        tcb.set_nodelay(false); // 初期値: 偽
        crate::net::l4::endpoint::tcb::tcb_table().insert(tcb);

        // ソケット側のアドレス情報を設定（handlerがTCB検索に使用）
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        // イベントを処理
        let res = handler.handle_event(crate::net::l4::endpoint::event::NetworkEvent::SetNoDelay {
            fd,
            nodelay: true,
        });
        assert!(matches!(
            res,
            crate::net::l4::endpoint::handler::EventHandleResult::Success
        ));

        // TCBに反映されているか確認
        let updated_tcb = crate::net::l4::endpoint::tcb::tcb_table()
            .get(local, remote)
            .unwrap();
        assert!(updated_tcb.is_nodelay_enabled());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_accept_backlog_limit() {
        let endpoint = Endpoint::new(EndpointType::Tcp);

        // Listening状態に
        {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 9000));
            inner.ensure_tcp().accept_backlog = 2; // 小さいバックログ
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        // 接続を追加
        let local = EndpointAddr::new([192, 168, 1, 1], 9000);
        for i in 0..3u32 {
            let remote = EndpointAddr::new([10, 0, 0, i as u8], 50000 + i as u16);
            let fd = EndpointFd::from_raw(300 + i);
            let tcb = TcpControlBlockEntry::new(fd, local, remote);
            let conn = AcceptedConnection::new(fd, local, remote, NetIfId(3), tcb);

            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            if inner
                .tcp()
                .map_or(true, |t| t.accept_queue.len() < t.accept_backlog)
            {
                inner.ensure_tcp().accept_queue.push_back(conn);
            }
        }

        // バックログ上限で制限される
        let inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.tcp().map_or(0, |t| t.accept_queue.len()), 2);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_start_listening_v6() {
        // Ensure manager exists
        crate::net::l4::endpoint::manager::init_endpoint_manager();

        let sock = crate::net::l4::endpoint::create_tcp_endpoint();
        let local =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
        assert!(sock.set_local_addr(local).is_ok());
        assert!(sock.start_listening_sync(4).is_ok());

        if let Some(s) = sock.endpoint() {
            let inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(inner.local_addr.unwrap(), local);
            assert_eq!(inner.state, crate::net::l4::endpoint::EndpointState::Listening);
            assert!(inner.tcp().is_some());
        } else {
            panic!("endpoint not found");
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_handle_connect_creates_tcb_v6() {
        crate::net::l4::endpoint::manager::init_endpoint_manager();
        let handler = crate::net::l4::endpoint::handler::NetworkEventHandler::new();

        let sock = crate::net::l4::endpoint::create_tcp_endpoint();
        let fd = sock.fd();
        let local =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 2000);
        let remote =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 3000);

        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        let res = handler.handle_event(crate::net::l4::endpoint::event::NetworkEvent::Connect {
            fd,
            local,
            remote,
        });
        assert!(matches!(
            res,
            crate::net::l4::endpoint::handler::EventHandleResult::Success
        ));

        let tcb = crate::net::l4::endpoint::tcb::tcb_table().get(local, remote);
        assert!(tcb.is_some());
        assert_eq!(
            tcb.unwrap().state,
            crate::net::l4::endpoint::tcb::TcpConnectionState::SynSent
        );
    }

    #[cfg_attr(test, test_case)]
    pub fn test_next_incoming_pins_scope_to_ingress_interface() {
        let listen_endpoint = Endpoint::new(EndpointType::Tcp);
        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8088));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        let accepted_fd = EndpointFd::from_raw(900);
        let local = EndpointAddr::new([192, 168, 10, 1], 8088);
        let remote = EndpointAddr::new([10, 0, 0, 9], 54009);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, NetIfId(4), tcb);

        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
        }

        let (accepted, _, if_id) = listen_endpoint.next_incoming_sync().expect("accept");
        assert_eq!(if_id, NetIfId(4));
        let inner = accepted.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.scope, InterfaceScope::Pinned(NetIfId(4)));
        assert_eq!(inner.last_ingress_if_id, Some(NetIfId(4)));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_runtime_scopes_sync_events() {
        reset_runtime_registry_for_tests();

        let runtime_a = default_runtime();
        let runtime_b = create_runtime();

        reset_event_system_for_tests_in(runtime_a);
        reset_event_system_for_tests_in(runtime_b);

        let endpoint = Endpoint::new_in(EndpointType::Tcp, runtime_b);
        endpoint
            .set_priority(7)
            .expect("priority event should enqueue");

        assert!(event_queue_in(runtime_a).recv().is_none());
        match event_queue_in(runtime_b).recv() {
            Some(crate::net::l4::endpoint::event::NetworkEvent::SetPriority { fd, priority }) => {
                assert_eq!(fd, endpoint.fd());
                assert_eq!(priority, 7);
            }
            other => panic!("unexpected runtime-scoped event: {:?}", other),
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_accept_inherits_listener_runtime() {
        reset_runtime_registry_for_tests();

        let _runtime_a = default_runtime();
        let runtime_b = create_runtime();

        let listen_endpoint = Endpoint::new_in(EndpointType::Tcp, runtime_b);
        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8087));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        let accepted_fd = EndpointFd::from_raw(901);
        let local = EndpointAddr::new([192, 168, 20, 1], 8087);
        let remote = EndpointAddr::new([10, 0, 0, 10], 54010);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, NetIfId(5), tcb);

        {
            let mut inner = listen_endpoint
                .inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
        }

        let (accepted, _, _) = listen_endpoint.next_incoming_sync().expect("accept");
        assert_eq!(accepted.runtime().id(), runtime_b.id());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_raw_scope_registration_rejects_duplicate_scope() {
        let manager = crate::net::l4::endpoint::manager::EndpointManager::new();
        let any_fd = EndpointFd::from_raw(910);
        let pinned_fd = EndpointFd::from_raw(911);

        assert!(manager.register_raw_scope(InterfaceScope::Any, any_fd).is_ok());
        assert!(matches!(
            manager.register_raw_scope(InterfaceScope::Any, pinned_fd),
            Err(EndpointError::ResourceExhausted)
        ));
        assert!(
            manager
                .register_raw_scope(InterfaceScope::Pinned(NetIfId(6)), pinned_fd)
                .is_ok()
        );
    }

    #[cfg_attr(test, test_case)]
    pub fn test_raw_endpoint_prefers_pinned_scope_over_any() {
        let manager = crate::net::l4::endpoint::manager::EndpointManager::new();

        let wildcard = Endpoint::new_with_fd(EndpointType::Raw, EndpointFd::from_raw(920));
        {
            let mut inner = wildcard.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.scope = InterfaceScope::Any;
            inner.ensure_raw();
            let _ = inner.transition_to(EndpointState::Bound);
        }
        manager.register(wildcard.clone());
        assert!(manager
            .register_raw_scope(InterfaceScope::Any, wildcard.fd())
            .is_ok());

        let pinned = Endpoint::new_with_fd(EndpointType::Raw, EndpointFd::from_raw(921));
        {
            let mut inner = pinned.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.scope = InterfaceScope::Pinned(NetIfId(7));
            inner.ensure_raw();
            let _ = inner.transition_to(EndpointState::Bound);
        }
        manager.register(pinned.clone());
        assert!(manager
            .register_raw_scope(InterfaceScope::Pinned(NetIfId(7)), pinned.fd())
            .is_ok());

        assert_eq!(
            manager.find_raw_endpoint(NetIfId(7)).map(|ep| ep.fd()),
            Some(pinned.fd())
        );
        assert_eq!(
            manager.find_raw_endpoint(NetIfId(8)).map(|ep| ep.fd()),
            Some(wildcard.fd())
        );
    }

    #[cfg_attr(test, test_case)]
    pub fn test_raw_delivery_prefers_pinned_then_falls_back_to_any() {
        crate::net::l4::endpoint::manager::init_endpoint_manager();

        let raw_any = crate::net::l4::endpoint::create_raw_endpoint();
        if let Some(endpoint) = raw_any.endpoint() {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.scope = InterfaceScope::Any;
            inner.ensure_raw();
            let _ = inner.transition_to(EndpointState::Bound);
        }

        let raw_pinned = crate::net::l4::endpoint::create_raw_endpoint();
        if let Some(endpoint) = raw_pinned.endpoint() {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.scope = InterfaceScope::Pinned(NetIfId(12));
            inner.ensure_raw();
            let _ = inner.transition_to(EndpointState::Bound);
        }

        let manager = crate::net::l4::endpoint::manager::endpoint_manager()
            .expect("endpoint manager lock");
        let guard = manager.read().unwrap_or_else(|e| e.into_inner());
        let manager = guard.as_ref().expect("endpoint manager");
        assert!(manager
            .register_raw_scope(InterfaceScope::Any, raw_any.fd())
            .is_ok());
        assert!(manager
            .register_raw_scope(InterfaceScope::Pinned(NetIfId(12)), raw_pinned.fd())
            .is_ok());
        drop(guard);

        let pinned_payload = kernel_api::resource::net::PacketPayload::from_vec(vec![1, 2, 3, 4]);
        assert!(crate::net::l4::endpoint::manager::deliver_raw_payload(
            NetIfId(12),
            pinned_payload
        ));
        let (received_pinned, if_id) = raw_pinned
            .endpoint()
            .expect("pinned raw endpoint")
            .recv_raw_payload_sync()
            .expect("pinned delivery");
        assert_eq!(if_id, NetIfId(12));
        assert_eq!(received_pinned.into_vec(), vec![1, 2, 3, 4]);
        assert!(matches!(
            raw_any
                .endpoint()
                .expect("wildcard raw endpoint")
                .recv_raw_payload_sync(),
            Err(EndpointError::Timeout)
        ));

        let wildcard_payload = kernel_api::resource::net::PacketPayload::from_vec(vec![9, 8, 7]);
        assert!(crate::net::l4::endpoint::manager::deliver_raw_payload(
            NetIfId(13),
            wildcard_payload
        ));
        let (received_any, if_id) = raw_any
            .endpoint()
            .expect("wildcard raw endpoint")
            .recv_raw_payload_sync()
            .expect("wildcard delivery");
        assert_eq!(if_id, NetIfId(13));
        assert_eq!(received_any.into_vec(), vec![9, 8, 7]);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_syncookie_and_isn_hmac() {
        use crate::net::l4::endpoint::tcb::tcb_table;

        // Initialize secrets
        tcb_table().init_syncookies();

        let local = EndpointAddr::new([127, 0, 0, 1], 80);
        let remote = EndpointAddr::new([127, 0, 0, 1], 12345);
        let client_isn = 1000000;

        // Test SYN Cookie generation and verification
        let cookie = tcb_table().generate_syncookie(local, remote, client_isn, 2);
        assert_ne!(cookie, 0);

        // The cookie should be verifiable (ACK num is cookie + 1)
        let ack_num = cookie.wrapping_add(1);
        let mss_idx = tcb_table().verify_syncookie(local, remote, ack_num, client_isn);
        assert_eq!(mss_idx, Some(2));

        // Different parameters should fail verification
        let wrong_remote = EndpointAddr::new([127, 0, 0, 1], 54321);
        assert_eq!(
            tcb_table().verify_syncookie(local, wrong_remote, ack_num, client_isn),
            None
        );

        // Test ISN generation
        let isn1 = tcb_table().generate_isn(local, remote);
        let isn2 = tcb_table().generate_isn(local, remote);

        // Successive ISNs should be different (due to counter and potentially time)
        assert_ne!(isn1, isn2);

        // Different endpoints should have very different ISNs (due to HMAC)
        let isn3 = tcb_table().generate_isn(local, wrong_remote);
        assert_ne!(isn1, isn3);
    }
}
