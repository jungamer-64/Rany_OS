use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::aml::AmlPath;
use crate::{AcpiError, AcpiErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GpeNumber(u16);

impl GpeNumber {
    /// Constructs a GPE number supported by AML `_Lxx`/`_Exx` naming.
    ///
    /// # Errors
    ///
    /// Returns an error for GPE numbers above 255.
    pub fn new(number: u16) -> Result<Self, AcpiError> {
        if number > u16::from(u8::MAX) {
            return Err(AcpiError::new(
                AcpiErrorKind::CapacityExceeded,
                "GPE number exceeds AML event-method naming range",
            ));
        }
        Ok(Self(number))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpeTrigger {
    Edge,
    Level,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpeEvent {
    pub number: GpeNumber,
    pub trigger: GpeTrigger,
}

impl GpeEvent {
    /// Resolves the event method below `\_GPE`.
    ///
    /// # Errors
    ///
    /// Returns an error only if the internally generated ACPI path violates
    /// namespace path rules.
    pub fn method_path(self) -> Result<AmlPath, crate::AmlError> {
        let prefix = match self.trigger {
            GpeTrigger::Edge => 'E',
            GpeTrigger::Level => 'L',
        };
        let name = alloc::format!("\\_GPE._{prefix}{:02X}", self.number.get());
        AmlPath::new(alloc::sync::Arc::<str>::from(name))
    }
}

pub trait GpeController: Sync {
    fn mask(&self, number: GpeNumber);
    fn acknowledge(&self, event: GpeEvent);
    fn unmask(&self, number: GpeNumber);
}

pub struct GpeQueue<const N: usize> {
    slots: [UnsafeCell<MaybeUninit<GpeEvent>>; N],
    head: AtomicUsize,
    tail: AtomicUsize,
}

// SAFETY: the queue is single-producer/single-consumer. The producer writes a
// slot before publishing `tail`; the consumer reads it only after Acquire.
unsafe impl<const N: usize> Sync for GpeQueue<N> {}

impl<const N: usize> GpeQueue<N> {
    pub const fn new() -> Self {
        Self {
            slots: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Masks, acknowledges, and enqueues an asserted GPE from the SCI ISR.
    ///
    /// # Errors
    ///
    /// Returns an event-delivery error if the bounded queue is full. The GPE
    /// remains masked in that case so an overflowing interrupt cannot storm.
    pub fn capture(
        &self,
        controller: &impl GpeController,
        event: GpeEvent,
    ) -> Result<(), AcpiError> {
        controller.mask(event.number);
        controller.acknowledge(event);

        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if N == 0 || tail.wrapping_sub(head) >= N {
            return Err(AcpiError::new(
                AcpiErrorKind::CapacityExceeded,
                "bounded GPE work queue is full",
            ));
        }
        let index = tail % N;
        // SAFETY: this is the producer-owned slot until tail is published.
        unsafe { (*self.slots[index].get()).write(event) };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    pub fn pop(&self) -> Option<GpeEvent> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail || N == 0 {
            return None;
        }
        let index = head % N;
        // SAFETY: tail publication proves the producer initialized this slot.
        let event = unsafe { (*self.slots[index].get()).assume_init_read() };
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(event)
    }

    pub fn complete(&self, controller: &impl GpeController, event: GpeEvent) {
        controller.unmask(event.number);
    }
}

impl<const N: usize> Default for GpeQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyCode {
    BusCheck,
    DeviceCheck,
    EjectRequest,
    DeviceCheckLight,
    Other(u64),
}

impl From<u64> for NotifyCode {
    fn from(value: u64) -> Self {
        match value {
            0x00 => Self::BusCheck,
            0x01 => Self::DeviceCheck,
            0x03 => Self::EjectRequest,
            0x05 => Self::DeviceCheckLight,
            value => Self::Other(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuFirmwareEvent {
    RescanContainer { object: AmlPath },
    CheckDevice { object: AmlPath },
    EjectRequest { object: AmlPath },
}

impl CpuFirmwareEvent {
    pub(crate) fn from_notify(object: AmlPath, value: u64) -> Option<Self> {
        match NotifyCode::from(value) {
            NotifyCode::BusCheck => Some(Self::RescanContainer { object }),
            NotifyCode::DeviceCheck | NotifyCode::DeviceCheckLight => {
                Some(Self::CheckDevice { object })
            }
            NotifyCode::EjectRequest => Some(Self::EjectRequest { object }),
            NotifyCode::Other(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct Controller {
        masked: AtomicU32,
        acknowledged: AtomicU32,
        unmasked: AtomicU32,
    }

    impl GpeController for Controller {
        fn mask(&self, number: GpeNumber) {
            self.masked.fetch_or(1 << number.get(), Ordering::Relaxed);
        }

        fn acknowledge(&self, event: GpeEvent) {
            self.acknowledged
                .fetch_or(1 << event.number.get(), Ordering::Relaxed);
        }

        fn unmask(&self, number: GpeNumber) {
            self.unmasked.fetch_or(1 << number.get(), Ordering::Relaxed);
        }
    }

    #[test]
    fn level_and_edge_gpes_are_masked_before_worker_dispatch() {
        let queue = GpeQueue::<4>::new();
        let controller = Controller::default();
        let level = GpeEvent {
            number: GpeNumber::new(2).unwrap(),
            trigger: GpeTrigger::Level,
        };
        let edge = GpeEvent {
            number: GpeNumber::new(3).unwrap(),
            trigger: GpeTrigger::Edge,
        };
        queue.capture(&controller, level).unwrap();
        queue.capture(&controller, edge).unwrap();
        assert_eq!(queue.pop(), Some(level));
        assert_eq!(queue.pop(), Some(edge));
        assert_eq!(controller.masked.load(Ordering::Relaxed), 0b1100);
        assert_eq!(controller.acknowledged.load(Ordering::Relaxed), 0b1100);
        queue.complete(&controller, level);
        assert_eq!(controller.unmasked.load(Ordering::Relaxed), 0b0100);
    }
}
