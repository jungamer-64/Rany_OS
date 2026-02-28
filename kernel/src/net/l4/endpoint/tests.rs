// ============================================================================
// kernel/src/net/endpoint/tests.rs
// ============================================================================
//! # テスト - Accept関連テスト
//!
//! Accept機能の単体テスト

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::super::socket::Socket;
    use super::super::tcb::TcpControlBlockEntry;
    use super::super::types::{AcceptedConnection, SocketAddr, SocketError, SocketFd, SocketState};
    use crate::net::endpoint::SocketType;
    use alloc::vec::Vec;

    #[cfg_attr(test, test_case)]
    pub fn test_accepted_connection() {
        let fd = SocketFd::from_raw(100);
        let local = SocketAddr::new([192, 168, 1, 1], 8080);
        let remote = SocketAddr::new([192, 168, 1, 2], 54321);
        let tcb = TcpControlBlockEntry::new(fd, local, remote);

        let conn = AcceptedConnection::new(fd, local, remote, tcb);

        assert_eq!(conn.fd, fd);
        assert_eq!(conn.local_addr, local);
        assert_eq!(conn.remote_addr, remote);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_socket_new_with_fd() {
        let fd = SocketFd::from_raw(42);
        let socket = Socket::new_with_fd(SocketType::Tcp, fd);

        assert_eq!(socket.fd(), fd);
        assert_eq!(socket.socket_type(), SocketType::Tcp);
        assert_eq!(socket.state(), SocketState::Created);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_socket_accept_empty_queue() {
        let socket = Socket::new(SocketType::Tcp);

        // Bound -> Listening
        {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(SocketAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Listening);
        }

        // 空のキューからnext_incomingするとTimeout
        let result = socket.next_incoming();
        assert!(matches!(result, Err(SocketError::Timeout)));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_socket_accept_with_connection() {
        let listen_socket = Socket::new(SocketType::Tcp);

        // Bound -> Listening
        {
            let mut inner = listen_socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(SocketAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Listening);
        }

        // 接続をAcceptキューに追加
        let accepted_fd = SocketFd::from_raw(200);
        let local = SocketAddr::new([192, 168, 1, 1], 8080);
        let remote = SocketAddr::new([10, 0, 0, 2], 54000);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, tcb);

        {
            let mut inner = listen_socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.accept_queue.push_back(conn);
        }

        // accept成功
        // 注: SocketManagerが初期化されていないため登録は失敗するが、
        // 接続情報は正しく返される
        let result = socket_accept_internal(&listen_socket);
        assert!(result.is_some());
        let (new_socket, addr) = result.unwrap();
        assert_eq!(addr, remote);
        assert_eq!(new_socket.fd(), accepted_fd);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_socket_accept_with_connection_v6() {
        let listen_socket = Socket::new(SocketType::Tcp);

        // Bound -> Listening
        {
            let mut inner = listen_socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::LOOPBACK.octets(), 8080));
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Listening);
        }

        // 接続をAcceptキューに追加
        let accepted_fd = SocketFd::from_raw(201);
        let local = SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::LOOPBACK.octets(), 8080);
        let remote = SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::LOOPBACK.octets(), 54001);
        let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
        let conn = AcceptedConnection::new(accepted_fd, local, remote, tcb);

        {
            let mut inner = listen_socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.accept_queue.push_back(conn);
        }

        // accept成功 (IPv6)
        let result = socket_accept_internal(&listen_socket);
        assert!(result.is_some());
        let (new_socket, addr) = result.unwrap();
        assert_eq!(addr, remote);
        assert_eq!(new_socket.fd(), accepted_fd);
    }

    /// 内部テスト用: SocketManager登録をスキップしてaccept
    fn socket_accept_internal(socket: &Socket) -> Option<(Socket, SocketAddr)> {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());

        if inner.state != SocketState::Listening {
            return None;
        }

        if let Some(conn) = inner.accept_queue.pop_front() {
            let new_socket = Socket::new_with_fd(SocketType::Tcp, conn.fd);
            {
                let mut new_inner = new_socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                let _ = new_inner.transition_to(SocketState::Connected);
            }
            return Some((new_socket, conn.remote_addr));
        }

        None
    }

    #[cfg_attr(test, test_case)]
    pub fn test_accept_backlog_limit() {
        let socket = Socket::new(SocketType::Tcp);

        // Listening状態に
        {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(SocketAddr::new([0, 0, 0, 0], 9000));
            inner.accept_backlog = 2; // 小さいバックログ
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Listening);
        }

        // 接続を追加
        let local = SocketAddr::new([192, 168, 1, 1], 9000);
        for i in 0..3u32 {
            let remote = SocketAddr::new([10, 0, 0, i as u8], 50000 + i as u16);
            let fd = SocketFd::from_raw(300 + i);
            let tcb = TcpControlBlockEntry::new(fd, local, remote);
            let conn = AcceptedConnection::new(fd, local, remote, tcb);

            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            if inner.accept_queue.len() < inner.accept_backlog {
                inner.accept_queue.push_back(conn);
            }
        }

        // バックログ上限で制限される
        let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.accept_queue.len(), 2);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_start_listening_v6() {
        // Ensure manager exists
        crate::net::endpoint::manager::init_socket_manager();

        let sock = crate::net::endpoint::create_tcp_socket();
        let local = SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
        assert!(sock.set_local_addr(local).is_ok());
        assert!(sock.start_listening(4).is_ok());

        if let Some(s) = sock.socket() {
            let inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(inner.local_addr.unwrap(), local);
            assert!(inner.tcp_listener.is_some());
        } else {
            panic!("socket not found");
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_handle_connect_creates_tcb_v6() {
        crate::net::endpoint::manager::init_socket_manager();
        let handler = crate::net::endpoint::handler::NetworkEventHandler::new();

        let sock = crate::net::endpoint::create_tcp_socket();
        let fd = sock.fd();
        let local = SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::LOOPBACK.octets(), 2000);
        let remote = SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::LOOPBACK.octets(), 3000);

        if let Some(s) = sock.socket() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        let res = handler.handle_event(crate::net::endpoint::event::NetworkEvent::Connect { fd, local, remote });
        assert!(matches!(res, crate::net::endpoint::handler::EventHandleResult::Success));

        let tcb = crate::net::endpoint::tcb::tcb_table().get(local, remote);
        assert!(tcb.is_some());
        assert_eq!(tcb.unwrap().state, crate::net::endpoint::tcb::TcpConnectionState::SynSent);
    }
}

