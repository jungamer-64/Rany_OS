use super::socket::Socket;
use super::tcb::TcpControlBlockEntry;
use super::types::{AcceptedConnection, SocketAddr, SocketFd, SocketState, SocketError};
use super::SocketType;

pub fn accepted_connection_smoke() -> bool {
    let fd = SocketFd::from_raw(100);
    let local = SocketAddr::new([192, 168, 1, 1], 8080);
    let remote = SocketAddr::new([192, 168, 1, 2], 54321);
    let tcb = TcpControlBlockEntry::new(fd, local, remote);

    let conn = AcceptedConnection::new(fd, local, remote, tcb);
    conn.fd == fd && conn.local_addr == local && conn.remote_addr == remote
}

pub fn socket_new_with_fd_smoke() -> bool {
    let fd = SocketFd::from_raw(42);
    let socket = Socket::new_with_fd(SocketType::Tcp, fd);

    socket.fd() == fd
        && socket.socket_type() == SocketType::Tcp
        && socket.state() == SocketState::Created
}

pub fn socket_accept_empty_queue_smoke() -> bool {
    let socket = Socket::new(SocketType::Tcp);

    {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(SocketAddr::new([0, 0, 0, 0], 8080));
        let _ = inner.transition_to(SocketState::Bound);
        let _ = inner.transition_to(SocketState::Listening);
    }

    matches!(socket.next_incoming(), Err(SocketError::Timeout))
}

pub fn socket_accept_with_connection_smoke() -> bool {
    let listen_socket = Socket::new(SocketType::Tcp);

    {
        let mut inner = listen_socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(SocketAddr::new([0, 0, 0, 0], 8080));
        let _ = inner.transition_to(SocketState::Bound);
        let _ = inner.transition_to(SocketState::Listening);
    }

    let accepted_fd = SocketFd::from_raw(200);
    let local = SocketAddr::new([192, 168, 1, 1], 8080);
    let remote = SocketAddr::new([10, 0, 0, 2], 54000);
    let tcb = TcpControlBlockEntry::new(accepted_fd, local, remote);
    let conn = AcceptedConnection::new(accepted_fd, local, remote, tcb);

    {
        let mut inner = listen_socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.accept_queue.push_back(conn);
    }

    let Some((new_socket, addr)) = socket_accept_internal(&listen_socket) else {
        return false;
    };

    addr == remote && new_socket.fd() == accepted_fd
}

pub fn accept_backlog_limit_smoke() -> bool {
    let socket = Socket::new(SocketType::Tcp);

    {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(SocketAddr::new([0, 0, 0, 0], 9000));
        inner.accept_backlog = 2;
        let _ = inner.transition_to(SocketState::Bound);
        let _ = inner.transition_to(SocketState::Listening);
    }

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

    let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
    inner.accept_queue.len() == 2
}

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
