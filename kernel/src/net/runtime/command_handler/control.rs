// ============================================================================
// kernel/src/net/l4/endpoint/handler/control.rs
// ============================================================================
//! RuntimeCommandHandler 制御系メソッド
use crate::net::l4::tcp::tcb_table;
use crate::net::l4::types::SocketId;
use crate::net::runtime::command_handler::EventHandleResult;
use crate::net::runtime::command_handler::RuntimeCommandHandler;

impl RuntimeCommandHandler {
    /// SetPriorityイベント処理
    pub(super) fn handle_set_priority(
        &self,
        socket_id: SocketId,
        priority: u8,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket(socket_id) else {
            return EventHandleResult::SocketNotFound(socket_id);
        };

        let (local, remote) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = match inner.local_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success,
            };
            let remote = match inner.remote_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success,
            };
            (local, remote)
        };

        // TCBに反映
        tcb_table().lookup_mut(local, remote, |tcb| {
            tcb.set_priority(priority);
        });

        EventHandleResult::Success
    }

    /// SetNoDelayイベント処理
    pub(super) fn handle_set_nodelay(
        &self,
        socket_id: SocketId,
        nodelay: bool,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket(socket_id) else {
            return EventHandleResult::SocketNotFound(socket_id);
        };

        let (local, remote) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = match inner.local_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success, // 未接続なら何もしない
            };
            let remote = match inner.remote_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success, // リモートなしなら何もしない
            };
            (local, remote)
        };

        // TCBに反映
        tcb_table().lookup_mut(local, remote, |tcb| {
            tcb.set_nodelay(nodelay);
        });

        EventHandleResult::Success
    }

    /// TX 資源解放通知処理
    pub(super) fn handle_tx_available(&self) -> EventHandleResult {
        // 送信待ちのソケットに DataReady イベントを再送して再試行を促す（TCP）
        // また、イベントキュー満杯で待機していた UDP ソケットの send_waker も起床させる
        crate::net::l4::socket::for_each_socket(|socket| {
            let pending = {
                let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                inner.has_send_data()
            };
            if pending && socket.is_tcp() {
                crate::net::runtime::command::enqueue_command_ignore_in(
                    socket.runtime(),
                    crate::net::runtime::command::RuntimeCommand::Transport(
                        crate::net::runtime::command::TransportCommand::TcpDataReady {
                            socket_id: socket.socket_id(),
                        },
                    ),
                );
            } else {
                // TCPバッファが空でも send_waker が設定されている場合（UDP の ResourceExhausted 待ち）
                // はここで直接起床させる。TCP の write/poll_write 境界も安全に再ポーリング可能。
                let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(w) = inner.send_waker.take() {
                    drop(inner); // ロック解放後に wake（デッドロック回避）
                    w.wake();
                }
            }
        });

        EventHandleResult::Success
    }

    pub(super) fn unregister_socket(&self, socket_id: SocketId) {
        let _ = crate::net::l4::socket::unregister_socket(socket_id);
    }

    pub(super) fn close_socket_now(&self, socket_id: SocketId) {
        let Some(socket) = crate::net::l4::socket::lookup_socket(socket_id) else {
            return;
        };

        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.mark_closed();
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
        if let Some(waker) = inner.send_waker.take() {
            waker.wake();
        }
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
        if let Some(waker) = inner.accept_waker.take() {
            waker.wake();
        }
        drop(inner);

        let _ = crate::net::l4::socket::unregister_socket(socket_id);
    }

    /// ICMP Echo Requestイベント処理（イベントキュー経由で非同期処理）
    ///
    /// `IcmpEcho` イベントとしてイベントキューに再送出し、
    /// スタックロック保持中のハンドラ（handle_event_with_stack）で処理させる。
    /// `send_real_icmp_echo` の同期ロック取得＋IRQ無効化を回避する。
    pub(super) fn handle_icmp_echo_request(
        &self,
        target: [u8; 4],
        sequence: u16,
    ) -> EventHandleResult {
        // fire-and-forget: スタックロック保持中のコンテキスト（IcmpEchoRequest）で
        // 直接処理されるため、ここでは no-op で Success を返す。
        // 実際のICMP送信は handle_event_with_stack の IcmpEchoRequest 分岐で処理済み。
        let _ = (target, sequence);
        EventHandleResult::Success
    }
}
