use core::sync::atomic::Ordering;

use crate::net::l4::tcp::TcpConnection;
use crate::task::{self, TimeoutResult};
use kernel_api::resource::net::PacketPayload;

use super::router::{self, RequestResponse};

struct ResponsePlan {
    payload: PacketPayload,
    keep_alive: bool,
}

enum ReadOutcome {
    Send(ResponsePlan),
    NeedTimeoutFallback,
    CloseConnection,
}

enum ReceiveLoopControl {
    Continue,
    Break,
    Return(ReadOutcome),
}

const fn connection_deadline_tick(start_tick_ms: u64) -> u64 {
    start_tick_ms.saturating_add(super::HOST_HTTP_CONNECTION_TIMEOUT_MS)
}

const fn connection_deadline_reached_at(now_tick_ms: u64, deadline_tick_ms: u64) -> bool {
    now_tick_ms >= deadline_tick_ms
}

fn lifetime_exceeded() -> Option<ResponsePlan> {
    log::warn!(
        "[HOST-HTTP] connection lifetime exceeded {}ms, closing",
        super::HOST_HTTP_CONNECTION_TIMEOUT_MS
    );
    router::build_timeout_response_or_log().map(|payload| ResponsePlan {
        payload,
        keep_alive: false,
    })
}

fn request_response_to_plan(response: RequestResponse) -> Option<ResponsePlan> {
    match response {
        RequestResponse::Respond {
            payload,
            keep_alive,
        } => Some(ResponsePlan {
            payload,
            keep_alive,
        }),
        RequestResponse::Close => None,
    }
}

fn bad_request_plan() -> Option<ResponsePlan> {
    log::warn!("[HOST-HTTP] parse error while processing request");
    router::build_bad_request_response_or_log().map(|payload| ResponsePlan {
        payload,
        keep_alive: false,
    })
}

fn plan_from_buffered_payload(
    parser: &mut crate::net::services::http::parser::HttpParser,
) -> Option<Option<ResponsePlan>> {
    match parser.try_parse_request() {
        Ok(Some(request)) => Some(request_response_to_plan(
            router::build_request_response_or_fallback(&request),
        )),
        Ok(None) => None,
        Err(err) => {
            log::warn!("[HOST-HTTP] parse error: {:?}", err);
            Some(bad_request_plan())
        }
    }
}

fn read_deadline_exceeded(attempt: usize, deadline_tick_ms: u64) -> Option<Option<ResponsePlan>> {
    if attempt % super::HOST_HTTP_READ_DEADLINE_CHECK_STRIDE != 0 {
        return None;
    }

    let read_now_tick_ms = crate::task::current_tick();
    if connection_deadline_reached_at(read_now_tick_ms, deadline_tick_ms) {
        log::warn!(
            "[HOST-HTTP] request read deadline exceeded {}ms, closing",
            super::HOST_HTTP_CONNECTION_TIMEOUT_MS
        );
        return Some(lifetime_exceeded());
    }

    None
}

async fn handle_receive_timeout(
    client: &mut TcpConnection,
    parser: &mut crate::net::services::http::parser::HttpParser,
    deadline_tick_ms: u64,
) -> ReadOutcome {
    let mut saw_payload = false;

    for attempt in 0..super::HOST_HTTP_READ_TRIES {
        if let Some(plan) = read_deadline_exceeded(attempt, deadline_tick_ms) {
            return match plan {
                Some(plan) => ReadOutcome::Send(plan),
                None => ReadOutcome::CloseConnection,
            };
        }

        let receive_result =
            task::with_timeout(client.recv_payload(), super::HOST_HTTP_READ_TIMEOUT_MS).await;

        match process_receive_result(receive_result, parser, &mut saw_payload).await {
            ReceiveLoopControl::Continue => {}
            ReceiveLoopControl::Break => break,
            ReceiveLoopControl::Return(outcome) => return outcome,
        }
    }

    if saw_payload {
        ReadOutcome::NeedTimeoutFallback
    } else {
        ReadOutcome::CloseConnection
    }
}

async fn process_receive_result(
    receive_result: TimeoutResult<Option<PacketPayload>>,
    parser: &mut crate::net::services::http::parser::HttpParser,
    saw_payload: &mut bool,
) -> ReceiveLoopControl {
    match receive_result {
        TimeoutResult::TimedOut => {
            task::yield_now().await;
            ReceiveLoopControl::Continue
        }
        TimeoutResult::Completed(None) => ReceiveLoopControl::Break,
        TimeoutResult::Completed(Some(payload)) => {
            process_received_payload(payload, parser, saw_payload)
        }
    }
}

fn process_received_payload(
    payload: PacketPayload,
    parser: &mut crate::net::services::http::parser::HttpParser,
    saw_payload: &mut bool,
) -> ReceiveLoopControl {
    let len = payload.total_len();
    if len == 0 {
        return ReceiveLoopControl::Break;
    }

    *saw_payload = true;
    super::BYTES_RX.fetch_add(len as u64, Ordering::Relaxed);
    parser.push_payload(payload);

    if let Some(plan) = plan_from_buffered_payload(parser) {
        return ReceiveLoopControl::Return(match plan {
            Some(plan) => ReadOutcome::Send(plan),
            None => ReadOutcome::CloseConnection,
        });
    }

    ReceiveLoopControl::Continue
}

fn timeout_fallback_plan() -> Option<ResponsePlan> {
    log::warn!("[HOST-HTTP] request read timeout or client closed connection early");
    router::build_timeout_response_or_log().map(|payload| ResponsePlan {
        payload,
        keep_alive: false,
    })
}

async fn determine_response_plan(
    client: &mut TcpConnection,
    parser: &mut crate::net::services::http::parser::HttpParser,
    deadline_tick_ms: u64,
) -> Option<ResponsePlan> {
    let now_tick_ms = crate::task::current_tick();
    if connection_deadline_reached_at(now_tick_ms, deadline_tick_ms) {
        return lifetime_exceeded();
    }

    if let Some(plan) = plan_from_buffered_payload(parser) {
        return plan;
    }

    match handle_receive_timeout(client, parser, deadline_tick_ms).await {
        ReadOutcome::Send(plan) => Some(plan),
        ReadOutcome::NeedTimeoutFallback => timeout_fallback_plan(),
        ReadOutcome::CloseConnection => None,
    }
}

pub(super) async fn handle_client(mut client: TcpConnection) {
    let mut parser = crate::net::services::http::parser::HttpParser::new();
    let connection_started_tick_ms = crate::task::current_tick();
    let connection_deadline_tick_ms = connection_deadline_tick(connection_started_tick_ms);

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        let Some(plan) =
            determine_response_plan(&mut client, &mut parser, connection_deadline_tick_ms).await
        else {
            break;
        };

        log::info!(
            "[HOST-HTTP] preparing response: {} bytes",
            plan.payload.total_len()
        );

        if let Err(err) = write_response(&mut client, plan.payload).await {
            log::warn!("[HOST-HTTP] send error: {}", err);
            break;
        }

        if !plan.keep_alive {
            break;
        }
    }

    let _ = client.close();
}

async fn write_response(
    client: &mut TcpConnection,
    response: PacketPayload,
) -> Result<(), &'static str> {
    let total_len = response.total_len();
    client
        .send_payload(response)
        .await
        .map_err(|_| "socket write error")?;
    client.drain_tx().await.map_err(|_| "socket drain error")?;
    super::BYTES_TX.fetch_add(total_len as u64, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{connection_deadline_reached_at, connection_deadline_tick};

    #[test]
    fn connection_deadline_tick_uses_saturating_add() {
        let start = u64::MAX - 1;
        let deadline = connection_deadline_tick(start);
        assert_eq!(deadline, u64::MAX);
    }

    #[test]
    fn connection_deadline_reached_uses_monotonic_comparison() {
        assert!(!connection_deadline_reached_at(999, 1_000));
        assert!(connection_deadline_reached_at(1_000, 1_000));
        assert!(connection_deadline_reached_at(1_001, 1_000));
    }
}
