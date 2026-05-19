use kernel_api::error::KapiError;

pub(crate) fn stack_scope(
    scope: kernel_api::resource::net::InterfaceScope,
) -> crate::net::types::InterfaceScope {
    match scope {
        kernel_api::resource::net::InterfaceScope::Any => crate::net::types::InterfaceScope::Any,
        kernel_api::resource::net::InterfaceScope::Pinned(if_id) => {
            crate::net::types::InterfaceScope::Pinned(crate::net::runtime::manager::NetIfId(if_id))
        }
    }
}

pub(crate) fn endpoint_addr_from_kapi(
    addr: kernel_api::resource::net::NetSocketAddr,
) -> crate::net::l4::EndpointAddr {
    match addr {
        kernel_api::resource::net::NetSocketAddr::V4 { ip, port } => {
            crate::net::l4::EndpointAddr::new(ip, port)
        }
        kernel_api::resource::net::NetSocketAddr::V6 { ip, port } => {
            crate::net::l4::EndpointAddr::new_v6(ip, port)
        }
    }
}

pub(crate) fn endpoint_error_to_kapi(error: crate::net::l4::EndpointError) -> KapiError {
    match error {
        crate::net::l4::EndpointError::Timeout => KapiError::Timeout,
        crate::net::l4::EndpointError::PortInUse | crate::net::l4::EndpointError::AddressInUse => {
            KapiError::ResourceExhausted
        }
        crate::net::l4::EndpointError::PermissionDenied => KapiError::PermissionDenied,
        crate::net::l4::EndpointError::NotFound => KapiError::InvalidHandle,
        _ => KapiError::IoError,
    }
}

pub(crate) fn tcp_error_to_kapi(error: crate::net::l4::tcp::TcpError) -> KapiError {
    match error {
        crate::net::l4::tcp::TcpError::Timeout => KapiError::Timeout,
        crate::net::l4::tcp::TcpError::AddressInUse | crate::net::l4::tcp::TcpError::BufferFull => {
            KapiError::ResourceExhausted
        }
        crate::net::l4::tcp::TcpError::PermissionDenied => KapiError::PermissionDenied,
        crate::net::l4::tcp::TcpError::NetworkUnreachable => KapiError::NotFound,
        _ => KapiError::IoError,
    }
}

pub(crate) fn lookup_socket(
    fd: crate::net::l4::types::SocketId,
) -> Result<crate::net::l4::socket::Socket, KapiError> {
    crate::net::l4::socket::lookup_socket_in(crate::net::runtime::default_runtime(), fd)
        .ok_or(KapiError::InvalidHandle)
}

pub(crate) fn close_socket_handle(fd: crate::net::l4::types::SocketId) -> Result<(), KapiError> {
    let socket = lookup_socket(fd)?;
    socket.close_immediate().map_err(endpoint_error_to_kapi)?;
    let _ = crate::net::l4::socket::unregister_socket_in(socket.runtime(), fd);

    Ok(())
}
