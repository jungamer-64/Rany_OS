//! Device-shared xHCI ring RAM with separate producer and event ownership.
//!
//! xHCI 1.2 sections 4.9 and 6.5 define cycle ownership, 64-byte alignment,
//! 64-KiB segment boundaries, and event segments without Link TRBs. Preparation
//! initializes CPU-owned RAM; activation removes CPU references before any
//! hardware publication. Failure returns the retained lease in its actual state.

#![forbid(unsafe_code)]

use kernel_api::dma::{
    CpuDmaLease, DmaDeviceAddress, DmaDirection, DmaLeaseError, DmaLeaseId, DmaQueueIdentity,
    DmaQuiesceWitness, PreparedSharedDmaLease, SharedDmaLease,
};

use super::trb::{Trb, TrbType};

const TRB_BYTES: usize = 16;
const SEGMENT_ALIGNMENT: u64 = 64;
const SEGMENT_BOUNDARY: u64 = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingBuildCause {
    InvalidGeometry,
    InvalidDirection,
    InvalidDeviceAddress,
    Dma(DmaLeaseError),
}

/// No failure discards ownership or treats activation as successful release.
#[derive(Debug)]
pub enum RingBuildError {
    Cpu {
        cause: RingBuildCause,
        memory: CpuDmaLease,
    },
    Prepared {
        cause: RingBuildCause,
        memory: PreparedSharedDmaLease,
    },
    Active {
        cause: RingBuildCause,
        memory: SharedDmaLease,
    },
}

/// Runtime access failures poison publication until hardware quiescence. The
/// ring retains its active lease; a failed descriptor write is never retried
/// blindly, and no credit is reclaimed from an unvalidated completion address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    Full,
    InvalidTrb,
    InvalidCompletion,
    Access(DmaLeaseError),
    Faulted(DmaLeaseError),
}

#[derive(Debug)]
pub struct RingQuiesceError<Ring> {
    pub cause: DmaLeaseError,
    pub ring: Ring,
}

#[derive(Debug)]
struct PreparedStorage {
    memory: PreparedSharedDmaLease,
    identity: DmaQueueIdentity,
    base: DmaDeviceAddress,
    entries: u16,
}

impl PreparedStorage {
    fn prepare(
        mut memory: CpuDmaLease,
        identity: DmaQueueIdentity,
        entries: u16,
        direction: DmaDirection,
    ) -> Result<Self, RingBuildError> {
        let bytes = usize::from(entries) * TRB_BYTES;
        if !(16..=4096).contains(&entries) || memory.byte_count().get() < bytes.next_multiple_of(64)
        {
            return Err(RingBuildError::Cpu {
                cause: RingBuildCause::InvalidGeometry,
                memory,
            });
        }
        if !matches!(memory.direction(), DmaDirection::Bidirectional)
            && memory.direction() != direction
        {
            return Err(RingBuildError::Cpu {
                cause: RingBuildCause::InvalidDirection,
                memory,
            });
        }
        if let Err(cause) = memory.write(|bytes| bytes.fill(0)) {
            return Err(RingBuildError::Cpu {
                cause: RingBuildCause::Dma(cause),
                memory,
            });
        }
        let memory = match memory.prepare_shared(identity) {
            Ok(memory) => memory,
            Err(error) => {
                let (cause, memory) = error.into_parts();
                return Err(RingBuildError::Cpu {
                    cause: RingBuildCause::Dma(cause),
                    memory,
                });
            }
        };
        let base = match memory.descriptor() {
            Ok(descriptor) => descriptor.device_address(),
            Err(cause) => {
                return Err(RingBuildError::Prepared {
                    cause: RingBuildCause::Dma(cause),
                    memory,
                });
            }
        };
        let last = base.checked_add(bytes.next_multiple_of(64) - 1);
        if !base.get().is_multiple_of(SEGMENT_ALIGNMENT)
            || last
                .is_none_or(|last| base.get() / SEGMENT_BOUNDARY != last.get() / SEGMENT_BOUNDARY)
        {
            return Err(RingBuildError::Prepared {
                cause: RingBuildCause::InvalidDeviceAddress,
                memory,
            });
        }
        Ok(Self {
            memory,
            identity,
            base,
            entries,
        })
    }

    fn activate(self) -> Result<ActiveStorage, RingBuildError> {
        let memory = match self.memory.activate() {
            Ok(memory) => memory,
            Err(error) => {
                let (cause, memory) = error.into_parts();
                return Err(RingBuildError::Prepared {
                    cause: RingBuildCause::Dma(cause),
                    memory,
                });
            }
        };
        Ok(ActiveStorage {
            memory,
            identity: self.identity,
            base: self.base,
            entries: self.entries,
            fault: None,
        })
    }
}

#[derive(Debug)]
struct ActiveStorage {
    memory: SharedDmaLease,
    identity: DmaQueueIdentity,
    base: DmaDeviceAddress,
    entries: u16,
    fault: Option<DmaLeaseError>,
}

impl ActiveStorage {
    fn healthy(&self) -> Result<(), RingError> {
        self.fault
            .map_or(Ok(()), |cause| Err(RingError::Faulted(cause)))
    }

    fn address(&self, index: usize) -> DmaDeviceAddress {
        // Segment validation established the complete span before activation.
        self.base
            .checked_add(index * TRB_BYTES)
            .expect("validated ring index cannot overflow its device address")
    }

    fn publish(&mut self, index: usize, trb: Trb) -> Result<(), RingError> {
        let result = (|| {
            let mut entry = self.memory.window(index * TRB_BYTES, TRB_BYTES)?;
            entry.write_u64(0, trb.parameter)?;
            entry.write_u32(8, trb.status)?;
            // DMA release ordering precedes this last scalar publication of
            // the cycle bit. No reference to active descriptor RAM is formed.
            entry.write_u32(12, trb.control)
        })();
        if let Err(cause) = result {
            self.fault = Some(cause);
            return Err(RingError::Access(cause));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PreparedProducerRing(PreparedStorage);

impl PreparedProducerRing {
    /// Initializes unpublished command/transfer RAM and validates its full span.
    ///
    /// # Errors
    /// Geometry, direction, registry, and address failures return the owner.
    pub fn prepare(
        memory: CpuDmaLease,
        identity: DmaQueueIdentity,
        entries: u16,
    ) -> Result<Self, RingBuildError> {
        PreparedStorage::prepare(memory, identity, entries, DmaDirection::ToDevice).map(Self)
    }

    pub const fn device_address(&self) -> DmaDeviceAddress {
        self.0.base
    }

    /// Excludes CPU slices, then initializes the invalid tail Link TRB before
    /// the controller can see the ring address.
    ///
    /// # Errors
    /// Returns prepared or active ownership; no MMIO publication occurs here.
    pub fn activate(self) -> Result<ProducerRing, RingBuildError> {
        let mut storage = self.0.activate()?;
        if let Err(RingError::Access(cause)) = storage.publish(
            usize::from(storage.entries - 1),
            Trb::link(storage.base.get(), true, false),
        ) {
            return Err(RingBuildError::Active {
                cause: RingBuildCause::Dma(cause),
                memory: storage.memory,
            });
        }
        Ok(ProducerRing {
            storage,
            enqueue: 0,
            retire: 0,
            outstanding: 0,
            cycle: true,
        })
    }
}

/// One tail Link TRB is reserved; outstanding entries cannot be overwritten.
#[derive(Debug)]
pub struct ProducerRing {
    storage: ActiveStorage,
    enqueue: usize,
    retire: usize,
    outstanding: usize,
    cycle: bool,
}

impl ProducerRing {
    pub const fn device_address(&self) -> DmaDeviceAddress {
        self.storage.base
    }

    pub const fn identity(&self) -> DmaQueueIdentity {
        self.storage.identity
    }

    pub fn lease_id(&self) -> DmaLeaseId {
        self.storage.memory.lease_id()
    }

    pub const fn cycle_bit(&self) -> bool {
        self.cycle
    }

    /// Publishes one TRB, assigning its cycle from the authoritative cursor.
    ///
    /// # Errors
    /// Full/invalid input performs no write. DMA failure retains and faults the
    /// ring; the failing entry is not counted as a successful publication.
    pub fn enqueue(&mut self, mut trb: Trb) -> Result<DmaDeviceAddress, RingError> {
        self.storage.healthy()?;
        if trb.trb_type() == TrbType::Link as u8 {
            return Err(RingError::InvalidTrb);
        }
        let capacity = usize::from(self.storage.entries - 1);
        if self.outstanding == capacity {
            return Err(RingError::Full);
        }
        if self.enqueue == capacity {
            self.storage.publish(
                capacity,
                Trb::link(self.storage.base.get(), true, self.cycle),
            )?;
            self.enqueue = 0;
            self.cycle = !self.cycle;
        }
        trb.set_cycle_bit(self.cycle);
        self.storage.publish(self.enqueue, trb)?;
        let address = self.storage.address(self.enqueue);
        self.enqueue += 1;
        self.outstanding += 1;
        Ok(address)
    }

    /// Publishes a complete transfer descriptor with its head cycle written
    /// last. The controller cannot consume an incomplete setup/data/status
    /// chain even while another transfer on this ring is already running.
    ///
    /// # Errors
    /// Checks all credits and types before writing. A failed write faults and
    /// retains the ring; callers retain associated DMA until hardware stop.
    pub(crate) fn enqueue_transfer(
        &mut self,
        entries: &[Trb],
    ) -> Result<DmaDeviceAddress, RingError> {
        self.storage.healthy()?;
        let capacity = usize::from(self.storage.entries - 1);
        if entries.is_empty()
            || entries
                .iter()
                .any(|entry| entry.trb_type() == TrbType::Link as u8)
        {
            return Err(RingError::InvalidTrb);
        }
        if entries.len() > capacity - self.outstanding {
            return Err(RingError::Full);
        }
        let head = self.enqueue % capacity;
        let initial_cycle = if self.enqueue == capacity {
            !self.cycle
        } else {
            self.cycle
        };
        for (offset, entry) in entries.iter().enumerate() {
            let logical_index = head + offset;
            let index = logical_index % capacity;
            let cycle = initial_cycle ^ (logical_index >= capacity);
            let mut invalid = *entry;
            invalid.set_cycle_bit(!cycle);
            self.storage.publish(index, invalid)?;
        }
        // A tail Link is visible before the head is committed. Its phase is
        // that of the segment being left, including a previously deferred wrap.
        if self.enqueue == capacity || head + entries.len() > capacity {
            let cycle = if self.enqueue == capacity {
                self.cycle
            } else {
                initial_cycle
            };
            self.storage
                .publish(capacity, Trb::link(self.storage.base.get(), true, cycle))?;
        }
        for offset in (0..entries.len()).rev() {
            let logical_index = head + offset;
            let index = logical_index % capacity;
            let cycle = initial_cycle ^ (logical_index >= capacity);
            let control = (entries[offset].control & !1) | u32::from(cycle);
            if let Err(cause) = self
                .storage
                .memory
                .window(index * TRB_BYTES, TRB_BYTES)
                .and_then(|mut window| window.write_u32(12, control))
            {
                self.storage.fault = Some(cause);
                return Err(RingError::Access(cause));
            }
        }
        let tail = head + entries.len();
        self.enqueue = if tail > capacity {
            tail - capacity
        } else {
            tail
        };
        self.cycle = initial_cycle ^ (tail > capacity);
        self.outstanding += entries.len();
        Ok(self.storage.address((tail - 1) % capacity))
    }

    /// Records a completion from this ring's hardware event consumer. Earlier
    /// entries are included because the controller consumes this ring in order.
    ///
    /// # Errors
    /// Rejects foreign, misaligned, tail-Link, or non-outstanding addresses.
    pub(crate) fn complete_through(&mut self, address: DmaDeviceAddress) -> Result<(), RingError> {
        let offset = address
            .get()
            .checked_sub(self.storage.base.get())
            .ok_or(RingError::InvalidCompletion)?;
        let capacity = usize::from(self.storage.entries - 1);
        if !offset.is_multiple_of(TRB_BYTES as u64) || offset / TRB_BYTES as u64 >= capacity as u64
        {
            return Err(RingError::InvalidCompletion);
        }
        let index = (offset / TRB_BYTES as u64) as usize;
        let count = (index + capacity - self.retire) % capacity + 1;
        if count > self.outstanding {
            return Err(RingError::InvalidCompletion);
        }
        self.outstanding -= count;
        self.retire = (index + 1) % capacity;
        Ok(())
    }

    /// # Errors
    /// A rejected stop witness returns this same ring and its active lease.
    pub fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<CpuDmaLease, RingQuiesceError<Self>> {
        match self.storage.memory.quiesce(witness) {
            Ok(memory) => Ok(memory),
            Err(error) => {
                let (cause, memory) = error.into_parts();
                Err(RingQuiesceError {
                    cause,
                    ring: Self {
                        storage: ActiveStorage {
                            memory,
                            ..self.storage
                        },
                        ..self
                    },
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct PreparedEventRing(PreparedStorage);

impl PreparedEventRing {
    /// Event segments contain zeroed TRBs and no tail Link TRB.
    ///
    /// # Errors
    /// Returns the owner on geometry, direction, address, or registry failure.
    pub fn prepare(
        memory: CpuDmaLease,
        identity: DmaQueueIdentity,
        entries: u16,
    ) -> Result<Self, RingBuildError> {
        PreparedStorage::prepare(memory, identity, entries, DmaDirection::FromDevice).map(Self)
    }

    pub const fn device_address(&self) -> DmaDeviceAddress {
        self.0.base
    }

    /// # Errors
    /// Activation failure returns the prepared owner before any MMIO write.
    pub fn activate(self) -> Result<EventRing, RingBuildError> {
        Ok(EventRing {
            storage: self.0.activate()?,
            dequeue: 0,
            cycle: true,
        })
    }
}

#[derive(Debug)]
pub struct EventRing {
    storage: ActiveStorage,
    dequeue: usize,
    cycle: bool,
}

impl EventRing {
    pub const fn device_address(&self) -> DmaDeviceAddress {
        self.storage.base
    }

    pub const fn identity(&self) -> DmaQueueIdentity {
        self.storage.identity
    }

    pub fn lease_id(&self) -> DmaLeaseId {
        self.storage.memory.lease_id()
    }

    /// Reads the cycle bit with acquire-side DMA ordering before payload. Wrap
    /// changes the expected cycle for the very next entry, never a cached batch.
    ///
    /// # Errors
    /// A DMA access failure faults and retains the active ring.
    /// ERDP is written only after the cursor advances, while the consumer owns
    /// both the ring and this narrow register. An empty poll performs no write.
    pub(crate) fn consume(
        &mut self,
        dequeue_register: &mut hal::mmio::OwnedMmioRegister<u64, hal::WriteOnly>,
    ) -> Result<Option<Trb>, RingError> {
        self.storage.healthy()?;
        let result = (|| {
            let entry = self
                .storage
                .memory
                .window(self.dequeue * TRB_BYTES, TRB_BYTES)?;
            let control = entry.read_u32(12)?;
            if (control & 1 != 0) != self.cycle {
                return Ok(None);
            }
            Ok(Some(Trb {
                parameter: entry.read_u64(0)?,
                status: entry.read_u32(8)?,
                control,
            }))
        })();
        let trb = match result {
            Ok(Some(trb)) => trb,
            Ok(None) => return Ok(None),
            Err(cause) => {
                self.storage.fault = Some(cause);
                return Err(RingError::Access(cause));
            }
        };
        self.dequeue += 1;
        if self.dequeue == usize::from(self.storage.entries) {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }
        dequeue_register.write(self.storage.address(self.dequeue).get() | 8);
        Ok(Some(trb))
    }

    /// # Errors
    /// A rejected stop witness returns the ring without restoring CPU access.
    pub fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<CpuDmaLease, RingQuiesceError<Self>> {
        match self.storage.memory.quiesce(witness) {
            Ok(memory) => Ok(memory),
            Err(error) => {
                let (cause, memory) = error.into_parts();
                Err(RingQuiesceError {
                    cause,
                    ring: Self {
                        storage: ActiveStorage {
                            memory,
                            ..self.storage
                        },
                        ..self
                    },
                })
            }
        }
    }
}
