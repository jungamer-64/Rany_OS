// ============================================================================
// kernel/src/net/runtime/command_handler/control.rs - ランタイム / コマンドハンドラ / 制御処理
// ============================================================================
//! RuntimeCommandHandler 制御系メソッド
use crate::net::l4::types::SocketId;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command_handler::RuntimeCommandHandler;

impl RuntimeCommandHandler {
    pub(super) fn unregister_socket_in(&self, runtime: NetRuntimeHandle, socket_id: SocketId) {
        let _ = crate::net::l4::socket::unregister_socket_in(runtime, socket_id);
    }

    pub(super) fn close_socket_now_in(&self, runtime: NetRuntimeHandle, socket_id: SocketId) {
        let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, socket_id) else {
            return;
        };

        let _ = socket.with_inner_mut(|inner| {
            inner.mark_closed();
            inner.recv_waker.wake();
            inner.send_waker.wake();
            inner.connect_waker.wake();
            inner.accept_waker.wake();
        });

        let _ = crate::net::l4::socket::unregister_socket_in(runtime, socket_id);
    }
}
