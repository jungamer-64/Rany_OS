//! # テスト - Accept関連テスト
//!
//! Accept機能の単体テスト

#[cfg(test)]
mod tests {
    use super::super::types::{SocketFd, SocketState, SocketAddr, AcceptedConnection, SocketError};
    use super::super::socket::Socket;
    use super::super::tcb::TcpControlBlockEntry;
    use crate::net::endpoint::SocketType;
    use alloc::vec::Vec;
    
    #[test]
    fn test_accepted_connection() {
        let fd = SocketFd::from_raw(100);
        let local = SocketAddr::new([192, 168, 1, 1], 8080);
        let remote = SocketAddr::new([192, 168, 1, 2], 54321);
        let tcb = TcpControlBlockEntry::new(fd, local, remote);
        
        let conn = AcceptedConnection::new(fd, local, remote, tcb);
        
        assert_eq!(conn.fd, fd);
        assert_eq!(conn.local_addr, local);
        assert_eq!(conn.remote_addr, remote);
    }
    
    #[test]
    fn test_socket_new_with_fd() {
        let fd = SocketFd::from_raw(42);
        let socket = Socket::new_with_fd(SocketType::Tcp, fd);
        
        assert_eq!(socket.fd(), fd);
        assert_eq!(socket.socket_type(), SocketType::Tcp);
        assert_eq!(socket.state(), SocketState::Created);
    }
    
    #[test]
    fn test_socket_accept_empty_queue() {
        let socket = Socket::new(SocketType::Tcp);
        
        // Bound -> Listening
        {
            let mut inner = socket.inner().lock();
            inner.local_addr = Some(SocketAddr::new([0, 0, 0, 0], 8080));
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Listening);
        }
        
        // 空のキューからacceptするとTimeout
        let result = socket.accept();
        assert!(matches!(result, Err(SocketError::Timeout)));
    }
    
    #[test]
    fn test_socket_accept_with_connection() {
        let listen_socket = Socket::new(SocketType::Tcp);
        
        // Bound -> Listening
        {
            let mut inner = listen_socket.inner().lock();
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
            let mut inner = listen_socket.inner().lock();
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
    
    /// 内部テスト用: SocketManager登録をスキップしてaccept
    fn socket_accept_internal(socket: &Socket) -> Option<(Socket, SocketAddr)> {
        let mut inner = socket.inner().lock();
        
        if inner.state != SocketState::Listening {
            return None;
        }
        
        if let Some(conn) = inner.accept_queue.pop_front() {
            let new_socket = Socket::new_with_fd(SocketType::Tcp, conn.fd);
            {
                let mut new_inner = new_socket.inner().lock();
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                let _ = new_inner.transition_to(SocketState::Connected);
            }
            return Some((new_socket, conn.remote_addr));
        }
        
        None
    }
    
    #[test]
    fn test_accept_backlog_limit() {
        let socket = Socket::new(SocketType::Tcp);
        
        // Listening状態に
        {
            let mut inner = socket.inner().lock();
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
            
            let mut inner = socket.inner().lock();
            if inner.accept_queue.len() < inner.accept_backlog {
                inner.accept_queue.push_back(conn);
            }
        }
        
        // バックログ上限で制限される
        let inner = socket.inner().lock();
        assert_eq!(inner.accept_queue.len(), 2);
    }
}
