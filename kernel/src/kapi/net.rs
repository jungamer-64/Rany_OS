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

pub(crate) fn apply_endpoint_scope(
    endpoint: &crate::net::l4::endpoint::endpoint_core::Endpoint,
    scope: kernel_api::resource::net::InterfaceScope,
) {
    let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
    inner.scope = stack_scope(scope);
}

pub(crate) fn endpoint_addr_from_kapi(
    addr: kernel_api::resource::net::NetSocketAddr,
) -> crate::net::l4::endpoint::EndpointAddr {
    match addr {
        kernel_api::resource::net::NetSocketAddr::V4 { ip, port } => {
            crate::net::l4::endpoint::EndpointAddr::new(ip, port)
        }
        kernel_api::resource::net::NetSocketAddr::V6 { ip, port } => {
            crate::net::l4::endpoint::EndpointAddr::new_v6(ip, port)
        }
    }
}

pub(crate) fn endpoint_error_to_kapi(error: crate::net::l4::endpoint::EndpointError) -> KapiError {
    match error {
        crate::net::l4::endpoint::EndpointError::Timeout => KapiError::Timeout,
        crate::net::l4::endpoint::EndpointError::PortInUse
        | crate::net::l4::endpoint::EndpointError::AddressInUse => KapiError::ResourceExhausted,
        crate::net::l4::endpoint::EndpointError::PermissionDenied => KapiError::PermissionDenied,
        crate::net::l4::endpoint::EndpointError::NotFound => KapiError::InvalidHandle,
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

pub(crate) fn network_error_to_kapi(error: crate::net::types::NetworkError) -> KapiError {
    match error {
        crate::net::types::NetworkError::PermissionDenied => KapiError::PermissionDenied,
        crate::net::types::NetworkError::PortInUse => KapiError::ResourceExhausted,
        crate::net::types::NetworkError::Timeout => KapiError::Timeout,
        crate::net::types::NetworkError::NetworkUnreachable => KapiError::NotFound,
        crate::net::types::NetworkError::BufferTooSmall
        | crate::net::types::NetworkError::ArpResolutionPending
        | crate::net::types::NetworkError::TransmitFailed => KapiError::ResourceExhausted,
        _ => KapiError::IoError,
    }
}

pub(crate) fn lookup_endpoint(
    fd: crate::net::l4::endpoint::EndpointFd,
) -> Result<crate::net::l4::endpoint::endpoint_core::Endpoint, KapiError> {
    let Some(mgr_lock) = crate::net::l4::endpoint::endpoint_manager() else {
        return Err(KapiError::NotFound);
    };
    let guard = mgr_lock.read().unwrap_or_else(|e| e.into_inner());
    let Some(mgr) = guard.as_ref() else {
        return Err(KapiError::NotFound);
    };
    mgr.get(fd).ok_or(KapiError::InvalidHandle)
}

pub(crate) fn close_endpoint_handle(
    fd: crate::net::l4::endpoint::EndpointFd,
) -> Result<(), KapiError> {
    let socket = lookup_endpoint(fd)?;
    socket.close_sync().map_err(endpoint_error_to_kapi)?;

    if let Some(mgr_lock) = crate::net::l4::endpoint::endpoint_manager() {
        let guard = mgr_lock.read().unwrap_or_else(|e| e.into_inner());
        if let Some(mgr) = guard.as_ref() {
            let _ = mgr.unregister(fd);
        }
    }

    Ok(())
}
