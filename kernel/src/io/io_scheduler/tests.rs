use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_io_priority_ordering() {
    assert!(IoPriority::Realtime > IoPriority::High);
    assert!(IoPriority::High > IoPriority::Normal);
    assert!(IoPriority::Normal > IoPriority::Idle);
    assert!(IoPriority::Idle > IoPriority::Background);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_io_mode_stats() {
    let stats = IoModeStats::new();
    stats.record_io(100);
    stats.record_io(200);
    stats.record_io(50);

    assert_eq!(stats.total_count(), 3);
    assert_eq!(stats.avg_latency_us(), 116); // (100+200+50)/3
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_scheduler_submit() {
    let scheduler = Arc::new(IoScheduler::new());
    let device = DeviceId::Nvme {
        controller: 0,
        namespace: 1,
    };

    let mut future = scheduler.submit_command(device, IoCommand::Flush, IoPriority::Normal);
    let id = future.request_id();
    assert_eq!(scheduler.get_state(id), Some(IoState::Pending));
    let (route, command) = scheduler.take_submission(id).unwrap().into_parts();
    assert!(matches!(command, IoCommand::Flush));
    assert!(!future.cancel());
    scheduler.complete_request(route.finish(IoCompletion::control(Ok(0))));
    assert_eq!(scheduler.get_state(id), Some(IoState::Completed));
    assert_eq!(ready_result(&mut future), IoResult::Success(0));
    assert_eq!(scheduler.get_state(id), None);
}

fn ready_result(future: &mut IoFuture) -> IoResult {
    let mut context = Context::from_waker(Waker::noop());
    match Pin::new(future).poll(&mut context) {
        Poll::Ready(completion) => completion.result(),
        Poll::Pending => panic!("expected a terminal control result"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn queued_cancellation_preserves_one_terminal_result() {
    let scheduler = Arc::new(IoScheduler::new());
    let mut future =
        scheduler.submit_command(DeviceId::Custom(1), IoCommand::Flush, IoPriority::Normal);
    let id = future.request_id();
    assert!(future.cancel());
    assert!(!future.cancel());
    assert!(scheduler.take_submission(id).is_none());
    assert_eq!(
        ready_result(&mut future),
        IoResult::Error(IoError::Cancelled)
    );
    assert_eq!(scheduler.stats.total_completed.load(Ordering::Relaxed), 1);
    assert_eq!(
        scheduler.stats.current_queue_depth.load(Ordering::Relaxed),
        0
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn abandoned_in_flight_request_remains_owned_until_completion() {
    let scheduler = Arc::new(IoScheduler::new());
    let future =
        scheduler.submit_command(DeviceId::Custom(1), IoCommand::Flush, IoPriority::Normal);
    let id = future.request_id();
    let (route, _) = scheduler.take_submission(id).unwrap().into_parts();
    drop(future);
    assert_eq!(scheduler.get_state(id), Some(IoState::InProgress));
    scheduler.complete_request(route.finish(IoCompletion::outcome_unknown(
        IoOperationType::Flush,
        IoError::Timeout,
    )));
    assert_eq!(scheduler.get_state(id), None);
    assert_eq!(scheduler.stats.total_completed.load(Ordering::Relaxed), 1);
    let retained = scheduler
        .abandoned_completions
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert_eq!(retained.len(), 1);
    assert_eq!(
        retained[0].result(),
        IoResult::OutcomeUnknown(IoError::Timeout)
    );
    drop(retained);
    scheduler.reap_abandoned();
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn shutdown_cancels_only_queued_commands() {
    let scheduler = Arc::new(IoScheduler::new());
    let device = DeviceId::Custom(1);
    let mut active = scheduler.submit_command(device, IoCommand::Flush, IoPriority::Normal);
    let (route, _) = scheduler
        .take_submission(active.request_id())
        .unwrap()
        .into_parts();
    let mut queued = scheduler.submit_command(device, IoCommand::Flush, IoPriority::Normal);
    scheduler.shutdown();
    let mut rejected = scheduler.submit_command(device, IoCommand::Flush, IoPriority::Normal);
    assert_eq!(
        ready_result(&mut queued),
        IoResult::Error(IoError::Cancelled)
    );
    assert_eq!(
        ready_result(&mut rejected),
        IoResult::Error(IoError::Cancelled)
    );
    assert!(!active.cancel());
    scheduler.complete_request(route.finish(IoCompletion::control(Ok(0))));
    assert_eq!(ready_result(&mut active), IoResult::Success(0));
    assert_eq!(
        scheduler.stats.current_queue_depth.load(Ordering::Relaxed),
        0
    );
    assert_eq!(scheduler.stats.total_completed.load(Ordering::Relaxed), 3);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn completion_hook_can_reenter_scheduler() {
    let scheduler = Arc::new(IoScheduler::new());
    let mut future =
        scheduler.submit_command(DeviceId::Custom(1), IoCommand::Flush, IoPriority::Normal);
    let id = future.request_id();
    let observed = Arc::new(AtomicBool::new(false));
    let hook_scheduler = scheduler.clone();
    let hook_observed = observed.clone();
    assert!(
        scheduler
            .register_completion_hook(
                id,
                Box::new(move |status| {
                    assert_eq!(hook_scheduler.get_state(id), Some(IoState::Completed));
                    assert_eq!(status, IoResult::Success(0));
                    hook_observed.store(true, Ordering::Release);
                })
            )
            .is_ok()
    );
    let (route, _) = scheduler.take_submission(id).unwrap().into_parts();
    scheduler.complete_request(route.finish(IoCompletion::control(Ok(0))));
    assert!(observed.load(Ordering::Acquire));
    assert_eq!(ready_result(&mut future), IoResult::Success(0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn replacing_waker_drops_its_owner_outside_scheduler_lock() {
    struct ReentrantWake {
        scheduler: alloc::sync::Weak<IoScheduler>,
        request: IoRequestId,
        dropped: Arc<AtomicBool>,
    }
    #[expect(
        clippy::manual_noop_waker,
        reason = "the custom last-owner destructor is the reentrancy contract under test"
    )]
    impl alloc::task::Wake for ReentrantWake {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for ReentrantWake {
        fn drop(&mut self) {
            let scheduler = self.scheduler.upgrade().unwrap();
            assert_eq!(scheduler.get_state(self.request), Some(IoState::Pending));
            self.dropped.store(true, Ordering::Release);
        }
    }
    let scheduler = Arc::new(IoScheduler::new());
    let mut future =
        scheduler.submit_command(DeviceId::Custom(1), IoCommand::Flush, IoPriority::Normal);
    let dropped = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(ReentrantWake {
        scheduler: Arc::downgrade(&scheduler),
        request: future.request_id(),
        dropped: dropped.clone(),
    }));
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(waker);
    assert!(!dropped.load(Ordering::Acquire));
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(dropped.load(Ordering::Acquire));
    assert!(future.cancel());
    assert_eq!(
        ready_result(&mut future),
        IoResult::Error(IoError::Cancelled)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn completion_wakes_only_the_current_observer() {
    struct CountWake(AtomicU64);
    impl alloc::task::Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let scheduler = Arc::new(IoScheduler::new());
    let mut future =
        scheduler.submit_command(DeviceId::Custom(1), IoCommand::Flush, IoPriority::Normal);
    let first = Arc::new(CountWake(AtomicU64::new(0)));
    let current = Arc::new(CountWake(AtomicU64::new(0)));
    for counter in [&first, &current] {
        let waker = Waker::from(counter.clone());
        assert!(
            Pin::new(&mut future)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }
    let (route, _) = scheduler
        .take_submission(future.request_id())
        .unwrap()
        .into_parts();
    scheduler.complete_request(route.finish(IoCompletion::control(Ok(0))));
    assert_eq!(first.0.load(Ordering::Relaxed), 0);
    assert_eq!(current.0.load(Ordering::Relaxed), 1);
    assert_eq!(ready_result(&mut future), IoResult::Success(0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn poll_callback_can_unregister_without_losing_completion() {
    struct RetiringPoller {
        executor: alloc::sync::Weak<PollingExecutor>,
        completion: PoisonLock<Option<DeviceCompletion>>,
        device: DeviceId,
    }
    impl PollHandler for RetiringPoller {
        fn is_ready(&self) -> bool {
            true
        }
        fn poll_completions(&self) -> Vec<DeviceCompletion> {
            assert!(
                self.executor
                    .upgrade()
                    .unwrap()
                    .unregister_handler(self.device)
            );
            self.completion
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .into_iter()
                .collect()
        }
    }
    let scheduler = Arc::new(IoScheduler::new());
    let executor = Arc::new(PollingExecutor::new(scheduler.clone()));
    let device = DeviceId::Custom(1);
    let mut future = scheduler.submit_command(device, IoCommand::Flush, IoPriority::Normal);
    let (route, _) = scheduler
        .take_submission(future.request_id())
        .unwrap()
        .into_parts();
    executor.register_handler(
        device,
        Arc::new(RetiringPoller {
            executor: Arc::downgrade(&executor),
            completion: PoisonLock::new(Some(route.finish(IoCompletion::control(Ok(0))))),
            device,
        }),
    );
    executor.start();
    assert_eq!(executor.poll_once(), 1);
    assert_eq!(executor.poll_once(), 0);
    assert_eq!(ready_result(&mut future), IoResult::Success(0));
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
#[test]
fn cancelling_and_dispatching_on_different_threads_has_one_winner() {
    use std::sync::Barrier;
    for _ in 0..128 {
        let scheduler = Arc::new(IoScheduler::new());
        let future =
            scheduler.submit_command(DeviceId::Custom(1), IoCommand::Flush, IoPriority::Normal);
        let id = future.request_id();
        let start = Barrier::new(2);
        std::thread::scope(|scope| {
            let cancel = scope.spawn(|| {
                start.wait();
                let cancelled = future.cancel();
                (cancelled, future)
            });
            start.wait();
            let submitted = scheduler.take_submission(id);
            let (cancelled, mut future) = cancel.join().unwrap();
            match submitted {
                Some(submission) => {
                    assert!(!cancelled);
                    let (route, _) = submission.into_parts();
                    scheduler.complete_request(route.finish(IoCompletion::control(Ok(0))));
                    assert_eq!(ready_result(&mut future), IoResult::Success(0));
                }
                None => {
                    assert!(cancelled);
                    assert_eq!(
                        ready_result(&mut future),
                        IoResult::Error(IoError::Cancelled)
                    );
                }
            }
        });
        assert_eq!(scheduler.stats.total_completed.load(Ordering::Relaxed), 1);
        assert_eq!(
            scheduler.stats.current_queue_depth.load(Ordering::Relaxed),
            0
        );
    }
}
