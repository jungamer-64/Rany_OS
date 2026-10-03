//! Synchronous one-time initialization protected from local task switches.

use hal::preemption::PreemptionGuard;

pub struct InitOnce<T>(spin::Once<T>);

impl<T: core::fmt::Debug> core::fmt::Debug for InitOnce<T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("InitOnce")
            .field(&self.get())
            .finish()
    }
}

impl<T> InitOnce<T> {
    pub const fn new() -> Self {
        Self(spin::Once::new())
    }

    pub fn get(&self) -> Option<&T> {
        self.0.get()
    }

    /// The guard begins before claiming the initializer state. A second task
    /// on this CPU therefore cannot spin on an initializer it interrupted.
    pub fn call_once(&self, initialize: impl FnOnce() -> T) -> &T {
        let _preemption = PreemptionGuard::enter();
        self.0.call_once(initialize)
    }

    /// A failed initializer releases the claim and retains no value. Another
    /// caller may retry after the failure has been observed.
    ///
    /// # Errors
    /// Returns the initializer's error without marking initialization complete.
    pub fn try_call_once<E>(&self, initialize: impl FnOnce() -> Result<T, E>) -> Result<&T, E> {
        let _preemption = PreemptionGuard::enter();
        self.0.try_call_once(initialize)
    }
}

impl<T> Default for InitOnce<T> {
    fn default() -> Self {
        Self::new()
    }
}
