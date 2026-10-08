//! Synchronous ABI borrows enter retained, per-queue owners. No callback polls
//! a Future, allocates descriptor scratch, or copies a TX packet payload.
#![deny(unsafe_code)]

use super::bootstrap::*;
use super::*;
use crate::core::QueueSubmitOutcome;
use crate::defs::status;
use crate::net::{NetRxPollError, NetTxPollError};
use kernel_api::abi::driver::{
    AbiNetPortInfo, AbiNetPortOps, AbiNetPortRegistration, AbiNetPortStats, AbiNetTxMeta,
    AbiNetTxSubmission, CpuRxLease,
};

const POLL_BATCH: usize = 32;

pub(super) fn registration(runtime: &Arc<Runtime>) -> KapiResult<AbiNetPortRegistration> {
    let phase = runtime.phase.read();
    let Phase::Configured(network) = &*phase else {
        return Err(KapiError::Busy);
    };
    let max_tx_segments = network
        .tx
        .iter()
        .map(|slot| slot.lock().layout.ring().size() - 1)
        .min()
        .ok_or(KapiError::NotInitialized)?;
    let opaque = u64::try_from(Arc::as_ptr(runtime).expose_provenance())
        .map_err(|_| KapiError::InvalidAddress)?;
    Ok(AbiNetPortRegistration::new(
        AbiNetPortInfo {
            port_id: runtime.device.raw(),
            queue_pairs: network.enabled_pairs()?,
            max_tx_segments,
            mtu: u32::from(network.configuration.mtu()),
            mac: network.configuration.mac(),
            name_ptr: b"virtio-net".as_ptr(),
            name_len: b"virtio-net".len(),
            ..AbiNetPortInfo::default()
        },
        opaque,
        AbiNetPortOps {
            start,
            bind,
            submit_tx_chain,
            poll,
            handle_event,
            stats,
            stop,
            set_interrupts_enabled,
        },
    ))
}

/// # Safety
/// The registered host retains this opaque instance, code and callback gate for
/// the returned synchronous borrow. Scalar validation cannot prove provenance.
#[expect(
    unsafe_code,
    reason = "the host lends its retained instance through the ABI callback gate"
)]
unsafe fn runtime<'call>(opaque: u64) -> Option<&'call Runtime> {
    let address = usize::try_from(opaque).ok()?;
    if address == 0 || !address.is_multiple_of(core::mem::align_of::<Runtime>()) {
        return None;
    }
    // SAFETY: the caller retains the Arc whose exposed provenance produced this
    // registration value, and its code for the entire callback.
    Some(unsafe { &*core::ptr::with_exposed_provenance::<Runtime>(address) })
}

fn healthy(runtime: &Runtime) -> bool {
    let value = runtime.transport.status();
    value & status::VIRTIO_STATUS_DRIVER_OK != 0
        && value & (status::VIRTIO_STATUS_FAILED | status::VIRTIO_STATUS_DEVICE_NEEDS_RESET) == 0
}

#[expect(
    unsafe_code,
    reason = "startup copies the host's initialized runtime table and retains its cookie through acknowledged stop"
)]
unsafe extern "C" fn start(opaque: u64, table: *const AbiNetPortRuntime) -> i32 {
    // SAFETY: the host owns this registration and retains its instance and code.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    if table.is_null()
        || !table
            .addr()
            .is_multiple_of(core::mem::align_of::<AbiNetPortRuntime>())
    {
        return AbiError::InvalidParam as i32;
    }
    // SAFETY: the start ABI lends an initialized, aligned table synchronously;
    // its cookie and callbacks remain live until this port acknowledges stop.
    let binding = unsafe { *table };
    if binding.abi_size < core::mem::size_of::<AbiNetPortRuntime>() as u64 {
        return AbiError::InvalidParam as i32;
    }
    {
        let mut phase = runtime.phase.write();
        if !matches!(*phase, Phase::Configured(_)) {
            return AbiError::DeviceBusy as i32;
        }
        let current = core::mem::replace(&mut *phase, Phase::Transitioning);
        if let Phase::Configured(network) = current {
            *phase = Phase::Live { network, binding };
        }
    }
    // Publication precedes RX acquisition. Failed startup therefore preserves
    // the binding and every posted packet for the host's unregister retry.
    poll_runtime(runtime) as i32
}

#[expect(
    unsafe_code,
    reason = "the host retains the registered instance throughout interface binding"
)]
unsafe extern "C" fn bind(opaque: u64, _if_id: u16) -> i32 {
    // SAFETY: this is a host-guarded call on the retained registration.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    if matches!(
        *runtime.phase.read(),
        Phase::Configured(_) | Phase::Live { .. }
    ) {
        AbiError::Success as i32
    } else {
        AbiError::DeviceBusy as i32
    }
}

#[expect(
    unsafe_code,
    reason = "the host retains immutable TX descriptors synchronously and packet backing through completion"
)]
unsafe extern "C" fn submit_tx_chain(
    opaque: u64,
    input: *const AbiNetTxSubmission,
    meta: AbiNetTxMeta,
) -> i32 {
    // SAFETY: callback admission retains the exact opaque instance and code.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    if input.is_null()
        || !input
            .addr()
            .is_multiple_of(core::mem::align_of::<AbiNetTxSubmission>())
    {
        return AbiError::InvalidParam as i32;
    }
    let phase = runtime.phase.read();
    let Phase::Live { network, binding } = &*phase else {
        return AbiError::DeviceBusy as i32;
    };
    if !healthy(runtime) {
        return AbiError::IoError as i32;
    }
    let pairs = match network.enabled_pairs() {
        Ok(pairs) => pairs,
        Err(cause) => return AbiError::from(cause) as i32,
    };
    let pair = if meta.has_queue_index {
        meta.queue_index
    } else {
        (network.next_tx.fetch_add(1, Ordering::Relaxed) % u32::from(pairs)) as u16
    };
    let Some(slot) = network.tx.get(usize::from(pair)) else {
        return AbiError::InvalidParam as i32;
    };
    let mut slot = slot.lock();
    let CommandStage::Ready(queue) = &mut slot.stage else {
        return AbiError::DeviceBusy as i32;
    };
    // SAFETY: the submission ABI lends initialized descriptors for this call;
    // Live retains the issuing runtime and admitted immutable packet DMA until
    // notification. Configured implies successful DRIVER_OK and MQ ACK.
    let outcome = unsafe { queue.submit(&*input, meta) };
    match outcome {
        Ok(QueueSubmitOutcome::Published { .. }) => AbiError::Success as i32,
        Ok(QueueSubmitOutcome::PublicationUncertain { .. }) => {
            // Accepted publication keeps the host packet lease. Rejecting here
            // would permit reuse while hardware might still read the payload.
            runtime.transport.add_status(status::VIRTIO_STATUS_FAILED);
            request_poll(runtime, *binding);
            AbiError::Success as i32
        }
        Err(cause) => {
            runtime.counters.tx_errors.fetch_add(1, Ordering::Relaxed);
            cause as i32
        }
    }
}

#[expect(
    unsafe_code,
    reason = "ordinary host polling retains the instance and foreign runtime across synchronous lease callbacks"
)]
unsafe extern "C" fn poll(opaque: u64, _if_id: u16) -> i32 {
    // SAFETY: the host retains this instance and code through this callback.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    poll_runtime(runtime) as i32
}

#[expect(
    unsafe_code,
    reason = "the normal event task retains the same callback admission and instance as poll"
)]
unsafe extern "C" fn handle_event(opaque: u64, _if_id: u16, event: AbiNetDriverEvent) -> i32 {
    if !matches!(event.kind, 1..=3) {
        return AbiError::InvalidParam as i32;
    }
    // SAFETY: event delivery is under the host's retained callback gate.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    poll_runtime(runtime) as i32
}

#[expect(
    unsafe_code,
    reason = "Live retains every packet runtime callback through this bounded normal-task queue batch"
)]
fn poll_runtime(runtime: &Runtime) -> AbiError {
    let phase = runtime.phase.read();
    let Phase::Live { network, binding } = &*phase else {
        return AbiError::DeviceBusy;
    };
    if !healthy(runtime) {
        return AbiError::IoError;
    }
    runtime.pending_irq.swap(0, Ordering::AcqRel);
    let mut more = false;
    for slot in &network.tx {
        let mut slot = slot.lock();
        let CommandStage::Ready(queue) = &mut slot.stage else {
            return AbiError::DeviceBusy;
        };
        for index in 0..POLL_BATCH {
            // SAFETY: Live retains the issuing cookie/code and accepted packet
            // owners; used heads independently prove device completion.
            match unsafe { queue.poll(*binding) } {
                Ok(true) => {
                    runtime.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                    more |= index + 1 == POLL_BATCH;
                }
                Ok(false) => break,
                Err(NetTxPollError::Notification(cause)) => {
                    request_poll(runtime, *binding);
                    return cause;
                }
                Err(NetTxPollError::Ring(cause)) => {
                    log::error!("VirtIO TX ring retained after fault: {cause:?}");
                    runtime.transport.add_status(status::VIRTIO_STATUS_FAILED);
                    runtime.counters.tx_errors.fetch_add(1, Ordering::Relaxed);
                    return AbiError::IoError;
                }
            }
        }
    }
    for slot in &network.rx {
        let mut slot = slot.lock();
        let RxStage::Ready(queue) = &mut slot.stage else {
            return AbiError::DeviceBusy;
        };
        for index in 0..POLL_BATCH {
            match queue.poll() {
                Ok(Some(frame)) => {
                    let status = frame.submit();
                    if status.is_success() {
                        runtime.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
                    } else {
                        runtime.counters.rx_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    more |= index + 1 == POLL_BATCH;
                }
                Ok(None) => break,
                Err(NetRxPollError::Frame(_)) => {
                    runtime.counters.rx_errors.fetch_add(1, Ordering::Relaxed);
                    more |= index + 1 == POLL_BATCH;
                }
                Err(cause) => {
                    log::error!("VirtIO RX owner retained after fault: {cause:?}");
                    runtime.transport.add_status(status::VIRTIO_STATUS_FAILED);
                    runtime.counters.rx_errors.fetch_add(1, Ordering::Relaxed);
                    return AbiError::IoError;
                }
            }
        }
        // Bound refill by pre-admitted descriptors; never allocate queue metadata
        // while polling. The framework supplies packet pool leases separately.
        for _ in queue.pending_count()..usize::from(queue.capacity()) {
            // SAFETY: the live port retains this binding/code and owns writable
            // backing until hardware completion or this cell's observed stop.
            let packet = match unsafe { CpuRxLease::acquire(*binding) } {
                Ok(packet) => packet,
                Err(cause) => {
                    request_poll(runtime, *binding);
                    return cause;
                }
            };
            // SAFETY: this packet belongs to the retained port, DRIVER_OK and
            // MQ ACK preceded Live, and the queue retains accepted DMA owners.
            match unsafe { queue.post(packet) } {
                Ok(QueueSubmitOutcome::Published { .. }) => {}
                Ok(QueueSubmitOutcome::PublicationUncertain { .. }) => {
                    runtime.transport.add_status(status::VIRTIO_STATUS_FAILED);
                    return AbiError::IoError;
                }
                Err(failure) => {
                    let cause = failure.cause;
                    // Pre-publication CPU ownership returns this unused lease;
                    // the framework retains any failed automatic return.
                    drop(failure.lease);
                    return cause;
                }
            }
        }
    }
    if let Ok(link) = network.configuration.link_up(&runtime.transport) {
        let mut reported = network.reported_link.lock();
        if *reported != Some(link) {
            // SAFETY: the Live read guard retains the runtime cookie and code.
            let result =
                AbiError::from_raw(unsafe { (binding.update_link)(binding.runtime_cookie, link) });
            if result.is_success() {
                *reported = Some(link);
            } else {
                request_poll(runtime, *binding);
                return result;
            }
        }
    } else {
        request_poll(runtime, *binding);
        return AbiError::IoError;
    }
    if more || runtime.pending_irq.load(Ordering::Acquire) != 0 {
        request_poll(runtime, *binding);
    }
    AbiError::Success
}

#[expect(
    unsafe_code,
    reason = "the caller holds the Live read guard retaining the foreign notification binding"
)]
fn request_poll(runtime: &Runtime, binding: AbiNetPortRuntime) {
    runtime.pending_irq.fetch_or(1, Ordering::Release);
    // SAFETY: all callers retain Live and this binding/code across admission.
    let result = AbiError::from_raw(unsafe {
        (binding.schedule_event)(
            binding.runtime_cookie,
            AbiNetDriverEvent {
                kind: AbiNetDriverEventKind::Poll as u32,
                queue_index: 0,
                _padding: 0,
            },
        )
    });
    if !result.is_success() {
        log::warn!("VirtIO poll notification retained after admission failure: {result:?}");
    }
}

#[expect(
    unsafe_code,
    reason = "the host lends an aligned mutable stats slot for one synchronous observation"
)]
unsafe extern "C" fn stats(opaque: u64, output: *mut AbiNetPortStats) -> i32 {
    // SAFETY: the retained callback gate owns the opaque instance.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    if output.is_null()
        || !output
            .addr()
            .is_multiple_of(core::mem::align_of::<AbiNetPortStats>())
    {
        return AbiError::InvalidParam as i32;
    }
    let value = AbiNetPortStats {
        tx_packets: runtime.counters.tx_packets.load(Ordering::Relaxed),
        rx_packets: runtime.counters.rx_packets.load(Ordering::Relaxed),
        tx_errors: runtime.counters.tx_errors.load(Ordering::Relaxed),
        rx_errors: runtime.counters.rx_errors.load(Ordering::Relaxed),
        initialized: matches!(*runtime.phase.read(), Phase::Live { .. }) && healthy(runtime),
        reserved: [0; 7],
    };
    // SAFETY: this callback lends exclusive initialized output storage.
    unsafe {
        output.write(value);
    }
    AbiError::Success as i32
}

#[expect(
    unsafe_code,
    reason = "the host retains this instance until resource-preserving stop reports completion"
)]
unsafe extern "C" fn stop(opaque: u64) -> i32 {
    // SAFETY: unregister keeps callback admission, opaque owner and code live.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    let timer = match timer() {
        Ok(timer) => timer,
        Err(cause) => return AbiError::from(cause) as i32,
    };
    match runtime.advance_stop(timer.current_tick_ms()) {
        Ok(()) => AbiError::Success as i32,
        Err(cause) => AbiError::from(cause) as i32,
    }
}

#[expect(
    unsafe_code,
    reason = "the host retains the instance through interrupt policy updates and completion recheck"
)]
unsafe extern "C" fn set_interrupts_enabled(opaque: u64, enabled: bool) -> i32 {
    // SAFETY: adaptive polling holds the retained registration callback gate.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    {
        let phase = runtime.phase.read();
        let Phase::Live { network, .. } = &*phase else {
            return AbiError::DeviceBusy as i32;
        };
        for slot in &network.rx {
            let mut slot = slot.lock();
            let RxStage::Ready(queue) = &mut slot.stage else {
                return AbiError::DeviceBusy as i32;
            };
            if queue.set_interrupts_enabled(enabled).is_err() {
                return AbiError::IoError as i32;
            }
        }
        for slot in &network.tx {
            let mut slot = slot.lock();
            let CommandStage::Ready(queue) = &mut slot.stage else {
                return AbiError::DeviceBusy as i32;
            };
            if queue.set_interrupts_enabled(enabled).is_err() {
                return AbiError::IoError as i32;
            }
        }
    }
    // A used entry could precede the flag update without raising an interrupt.
    // Rechecking after enable consumes that work before the host goes idle.
    if enabled {
        poll_runtime(runtime) as i32
    } else {
        AbiError::Success as i32
    }
}
