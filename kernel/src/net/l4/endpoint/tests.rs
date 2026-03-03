// ============================================================================
// kernel/src/net/endpoint/tests.rs
// ============================================================================
//! # テスト - Accept関連テスト
//!
//! Accept機能の単体テスト

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::super::endpoint_core::Endpoint;
    use super::super::tcb::TcpControlBlockEntry;
    use super::super::types::{AcceptedConnection, EndpointAddr, EndpointError, EndpointFd, EndpointState};
    use crate::net::l4::endpoint::EndpointType;
    use alloc::vec::Vec;

    #[cfg_attr(test, test_case)]
    pub fn test_accepted_connection() {
        let fd = EndpointFd::from_raw(100);
        let local = EndpointAddr::new([192, 168, 1, 1], 8080);
        let remote = EndpointAddr::new([192, 168, 1, 2], 54321);
        let tcb = TcpControlBlockEntry::new(fd, local, remote);

        let conn = AcceptedConnection::new(fd, local, remote, tcb);

        assert_eq!(conn.fd, fd);
        assert_eq!(conn.local_addr, local);
        assert_eq!(conn.remote_addr, remote);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_new_with_fd() {
        let fd = EndpointFd::from_raw(42);
        let endpoint = Endpoint::new_with_fd(EndpointType::Tcp, fd);

        assert_eq!(endpoint.fd(), fd);
        assert_eq!(endpoint.endpoint_type(), EndpointType::Tcp);
        assert_eq!(endpoint.state(), EndpointState::Created);
    }

    // Legacy compatibility wrappers referenced by qemu test exports.
    pub fn test_socket_new_with_fd() {
        test_endpoint_new_with_fd();
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_accept_empty_queue() {
        let endpoint = Endpoint::new(EndpointType::Tcp);

        // Bound -> Listening
        {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        // 空のキューからnext_incomingするとTimeout
        let result = endpoint.next_incoming();
        assert!(matches!(result, Err(EndpointError::Timeout)));
    }

    pub fn test_socket_accept_empty_queue() {
        test_endpoint_accept_empty_queue();
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_accept_with_connection() {
        let listen_endpoint = Endpoint::new(EndpointType::Tcp);

        // Bound -> Listening
        {
            let mut inner = listen_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        // 接続をAcceptキューに追加
        let accepted_fd = EndpointFd::from_raw(200);
        let local = EndpointAddr::new([192, 168, 1, 1], 8080);
        let remote = EndpointAddr::new([10, 0, 0, 2], 54000);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, tcb);

        {
            let mut inner = listen_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
        }

        // accept成功
        // 注: EndpointManagerが初期化されていないため登録は失敗するが、
        // 接続情報は正しく返される
        let result = endpoint_accept_internal(&listen_endpoint);
        assert!(result.is_some());
        let (new_endpoint, addr) = result.unwrap();
        assert_eq!(addr, remote);
        assert_eq!(new_endpoint.fd(), accepted_fd);
    }

    pub fn test_socket_accept_with_connection() {
        test_endpoint_accept_with_connection();
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_accept_with_connection_v6() {
        let listen_endpoint = Endpoint::new(EndpointType::Tcp);

        // Bound -> Listening
        {
            let mut inner = listen_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 8080));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
        }

        // 接続をAcceptキューに追加
        let accepted_fd = EndpointFd::from_raw(201);
        let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 8080);
        let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 54001);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, tcb);

        {
            let mut inner = listen_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
        }

        // accept成功 (IPv6)
        let result = endpoint_accept_internal(&listen_endpoint);
        assert!(result.is_some());
        let (new_endpoint, addr) = result.unwrap();
        assert_eq!(addr, remote);
        assert_eq!(new_endpoint.fd(), accepted_fd);
    }

    /// 内部テスト用: EndpointManager登録をスキップしてaccept
    fn endpoint_accept_internal(endpoint: &Endpoint) -> Option<(Endpoint, EndpointAddr)> {
        let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());

        if inner.state != EndpointState::Listening {
            return None;
        }

        if let Some(conn) = inner.tcp_mut().and_then(|t| t.accept_queue.pop_front()) {
            let new_endpoint = Endpoint::new_with_fd(EndpointType::Tcp, conn.fd);
            {
                let mut new_inner = new_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                new_inner.ensure_tcp().nodelay = inner.tcp().map_or(false, |t| t.nodelay); // 設定を引き継ぐ
                let _ = new_inner.transition_to(EndpointState::Connected);
            }
            return Some((new_endpoint, conn.remote_addr));
            }

            None
            }

            #[cfg_attr(test, test_case)]
            pub fn test_tcp_nodelay_inheritance() {
            let listen_endpoint = Endpoint::new(EndpointType::Tcp);
            listen_endpoint.set_nodelay(true).unwrap();

            // Listening状態に
            {
            let mut inner = listen_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(EndpointAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Listening);
            }

            // 接続を追加
            let accepted_fd = EndpointFd::from_raw(500);
            let local = EndpointAddr::new([192, 168, 1, 1], 8080);
            let remote = EndpointAddr::new([10, 0, 0, 1], 50000);
            let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
            let conn = AcceptedConnection::new(accepted_fd, local, remote, tcb);

            {
            let mut inner = listen_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().accept_queue.push_back(conn);
            }

            // Accept
            let (new_endpoint, _) = endpoint_accept_internal(&listen_endpoint).unwrap();

            // 設定が引き継がれているか確認
            let inner = new_endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
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
            let res = handler.handle_event(crate::net::l4::endpoint::event::NetworkEvent::SetNoDelay { fd, nodelay: true });
            assert!(matches!(res, crate::net::l4::endpoint::handler::EventHandleResult::Success));

            // TCBに反映されているか確認
            let updated_tcb = crate::net::l4::endpoint::tcb::tcb_table().get(local, remote).unwrap();
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
            let conn = AcceptedConnection::new(fd, local, remote, tcb);

            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            if inner.tcp().map_or(true, |t| t.accept_queue.len() < t.accept_backlog) {
                inner.ensure_tcp().accept_queue.push_back(conn);
            }
        }

        // バックログ上限で制限される
        let inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.tcp().map_or(0, |t| t.accept_queue.len()), 2);
    }

    #[cfg_attr(test, test_case)]
    #[allow(deprecated)]
    pub fn test_start_listening_v6() {
        // Ensure manager exists
        crate::net::l4::endpoint::manager::init_endpoint_manager();

        let sock = crate::net::l4::endpoint::create_tcp_endpoint();
        let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
        assert!(sock.set_local_addr(local).is_ok());
        assert!(sock.start_listening(4).is_ok());

        if let Some(s) = sock.endpoint() {
            let inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(inner.local_addr.unwrap(), local);
            assert!(inner.tcp().map_or(false, |t| t.listener.is_some()));
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
        let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 2000);
        let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 3000);

        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        let res = handler.handle_event(crate::net::l4::endpoint::event::NetworkEvent::Connect { fd, local, remote });
        assert!(matches!(res, crate::net::l4::endpoint::handler::EventHandleResult::Success));

        let tcb = crate::net::l4::endpoint::tcb::tcb_table().get(local, remote);
        assert!(tcb.is_some());
        assert_eq!(tcb.unwrap().state, crate::net::l4::endpoint::tcb::TcpConnectionState::SynSent);
    }
}
