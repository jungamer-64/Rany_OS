use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum YieldState {
    Initial,
    Rescheduled,
}

pub struct YieldNow {
    state: YieldState,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match self.state {
            YieldState::Initial => {
                self.state = YieldState::Rescheduled;
                context.waker().wake_by_ref();
                Poll::Pending
            }
            YieldState::Rescheduled => Poll::Ready(()),
        }
    }
}

pub fn yield_now() -> YieldNow {
    YieldNow {
        state: YieldState::Initial,
    }
}

pub async fn yield_point() {
    yield_now().await;
}

pub async fn yield_point_with_quota_check() {
    yield_now().await;
}
