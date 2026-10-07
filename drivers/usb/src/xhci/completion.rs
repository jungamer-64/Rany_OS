//! Hardware evidence construction is confined to the controller event consumer.
//! The caller has acquired the event cycle, checked the ring address, and removed
//! the unique matching input lease before invoking this transition.

#![deny(unsafe_code)]

use kernel_api::dma::{
    CompletedDmaLease, CpuDmaLease, DmaCompletionWitness, DmaQueueIdentity, DmaQuiesceWitness,
    DmaTransitionError, InFlightDmaLease, SharedDmaLease,
};

#[expect(
    unsafe_code,
    reason = "validated command completion proves the controller has finished reading this unique input context"
)]
pub(super) fn finish_command_input(
    memory: SharedDmaLease,
    queue: DmaQueueIdentity,
) -> Result<CpuDmaLease, DmaTransitionError<SharedDmaLease>> {
    // SAFETY: the sole caller consumes a cycle-acquired command completion,
    // validates its current command-ring address, and takes the exact input
    // context associated with that command. Input contexts are read only by
    // that command, never installed as output/device/endpoint context RAM.
    let witness = unsafe { DmaQuiesceWitness::after_queue_quiesced(queue, memory.lease_id()) };
    memory.quiesce(witness)
}

#[expect(
    unsafe_code,
    reason = "the event consumer bound this final transfer event to the unique active request and its queue generation"
)]
pub(super) fn finish_transfer(
    memory: InFlightDmaLease,
    queue: DmaQueueIdentity,
) -> Result<CompletedDmaLease, DmaTransitionError<InFlightDmaLease>> {
    // SAFETY: the sole caller validates a cycle-acquired Transfer Event against
    // the active request's slot, endpoint, final TRB, and remaining byte count.
    // Taking the request consumes its only association, preventing replay.
    let witness =
        unsafe { DmaCompletionWitness::from_validated_queue_entry(queue, memory.lease_id()) };
    memory.complete(witness)
}
