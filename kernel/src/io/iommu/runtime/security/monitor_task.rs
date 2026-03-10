// ============================================================================
// kernel/src/io/iommu/runtime/security/monitor_task.rs
// ============================================================================

use spin::Once;

use crate::security::audit::{AuditEvent, AuditEventType};

use super::{
    EventAggregator, IsolationReason, SecurityEvent, SecurityNotifier, default_security_monitor,
    emergency_isolate_device, emergency_isolation_registry, fault_rate_limiter,
    log_aggregated_event_summary, security_event_to_audit,
};

pub(crate) const SECURITY_MONITOR_INTERVAL_MS: u64 = 100;
pub(crate) const SECURITY_MONITOR_BATCH: usize = 128;

/// GC (Garbage Collection) interval for zombie DMA handles.
pub(crate) const ZOMBIE_GC_INTERVAL_MS: u64 = 5000;

/// Interval for flushing aggregated events (milliseconds).
pub(crate) const EVENT_AGGREGATE_FLUSH_MS: u64 = 1000;

/// Future that waits for the security monitor waker to be notified.
struct SecurityMonitorWaitFuture;

impl core::future::Future for SecurityMonitorWaitFuture {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if super::notifier::is_security_monitor_wake_pending() {
            return core::task::Poll::Ready(());
        }
        super::notifier::register_security_monitor_waker(cx.waker());
        if super::notifier::is_security_monitor_wake_pending() {
            core::task::Poll::Ready(())
        } else {
            core::task::Poll::Pending
        }
    }
}

/// Drain IOMMU security events and forward them to the audit pipeline.
pub async fn security_monitor_task() {
    let monitor = default_security_monitor();
    let mut gc_counter: u64 = 0;
    let mut aggregate_counter: u64 = 0;
    let mut aggregator = EventAggregator::new();

    loop {
        let _ = monitor.drain_events(SECURITY_MONITOR_BATCH, |event| {
            if let SecurityEvent::DmaViolation { source_id, .. } = event {
                let current_time = super::fault_storm::current_time_ms_approx();
                if let Some(_reason) = fault_rate_limiter().record_fault(source_id, current_time) {
                    let _ = emergency_isolate_device(source_id);
                    monitor.notify(SecurityEvent::DeviceIsolated {
                        source_id,
                        reason: IsolationReason::FaultStorm,
                    });
                }
            }

            let is_first = aggregator.record(event);
            if is_first {
                crate::security::audit::log_event(security_event_to_audit(event));
            }
        });

        let dropped = monitor.take_dropped_events();
        if dropped > 0 {
            crate::security::audit::log_event(
                AuditEvent::new(AuditEventType::IommuEvent, 0)
                    .success(false)
                    .message("monitor_events_dropped")
                    .field("count", alloc::format!("{}", dropped)),
            );
        }

        aggregate_counter += SECURITY_MONITOR_INTERVAL_MS;
        if aggregate_counter >= EVENT_AGGREGATE_FLUSH_MS {
            aggregate_counter = 0;
            aggregator.drain(|key, aggregate| {
                if aggregate.count <= 1 {
                    return;
                }
                log_aggregated_event_summary(key, aggregate);
            });
        }

        let isolated_count = emergency_isolation_registry().process_pending_isolations();
        if isolated_count > 0 {
            log::info!(
                "[IOMMU][Security] Processed {} pending device isolations",
                isolated_count
            );
        }

        gc_counter += SECURITY_MONITOR_INTERVAL_MS;
        if gc_counter >= ZOMBIE_GC_INTERVAL_MS {
            gc_counter = 0;
            run_zombie_dma_gc();
        }

        #[cfg(test)]
        crate::task::sleep_ms(SECURITY_MONITOR_INTERVAL_MS).await;
        #[cfg(not(test))]
        let _ = crate::task::with_timeout(SecurityMonitorWaitFuture, SECURITY_MONITOR_INTERVAL_MS)
            .await;
    }
}

/// Run garbage collection for zombie DMA handles.
pub(crate) fn run_zombie_dma_gc() {
    use crate::io::iommu::runtime::zombie;

    let pending = zombie::has_pending_zombies();
    let memory_pressure = crate::mm::phys::unified_alloc::memory_pressure_level();

    let max_process = if memory_pressure >= 80 {
        256
    } else if memory_pressure >= 50 || pending {
        64
    } else {
        0
    };

    if max_process == 0 {
        return;
    }

    let processed = zombie::run_zombie_gc(max_process);

    if processed > 0 {
        let stats = zombie::zombie_stats();
        log::debug!(
            "[IOMMU][GC] Processed {} zombies (total: enqueued={}, processed={}, dropped={})",
            processed,
            stats.total_enqueued,
            stats.total_processed,
            stats.total_dropped
        );
    }

    if memory_pressure >= 50 {
        let stats = emergency_isolation_registry().stats();
        log::debug!(
            "[IOMMU][GC] Memory pressure {} - emergency registry: total={} pending={} active={}",
            memory_pressure,
            stats.total_isolations,
            stats.pending_count,
            stats.active_count
        );
    }
}

static SECURITY_MONITOR_TASK: Once<()> = Once::new();

/// Spawn the default IOMMU security monitor task (idempotent).
pub fn spawn_security_monitor_task() {
    SECURITY_MONITOR_TASK.call_once(|| {
        let _ = crate::task::spawn_detached(security_monitor_task());
    });
}
