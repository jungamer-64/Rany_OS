// ============================================================================
// kernel/src/net/l4/endpoint/handler/control.rs
// ============================================================================
//! NetworkEventHandler 制御系メソッド
use crate::net::l4::endpoint::EndpointFd;
use crate::net::l4::endpoint::handler::ENDPOINT_MANAGER;
use crate::net::l4::endpoint::handler::EventHandleResult;
use crate::net::l4::endpoint::handler::NetworkEventHandler;
use crate::net::l4::endpoint::tcb_table;
use crate::net::l4::endpoint::types::EndpointState;

impl NetworkEventHandler {
    /// SetPriorityイベント処理
    pub(super) fn handle_set_priority(&self, fd: EndpointFd, priority: u8) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
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
    pub(super) fn handle_set_nodelay(&self, fd: EndpointFd, nodelay: bool) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
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
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            mgr.for_each(|socket| {
                let pending = {
                    let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                    inner.has_send_data()
                };
                if pending {
                    crate::net::l4::endpoint::event::enqueue_event_ignore_in(
                        socket.runtime(),
                        crate::net::l4::endpoint::event::NetworkEvent::DataReady {
                            fd: socket.fd(),
                            endpoint_type: socket.socket_type(),
                        },
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
        }

        EventHandleResult::Success
    }

    pub(super) fn unregister_endpoint(&self, fd: EndpointFd) {
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            let _ = mgr.unregister(fd);
        }
    }

    pub(super) fn close_endpoint_for_unbind(&self, fd: EndpointFd) {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return;
        };
        let Some(socket) = mgr.get(fd) else {
            return;
        };

        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.clear_protocol();
        inner.clear_tcp_payload_queues();
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
        let _ = inner.transition_to(EndpointState::Closed);
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
