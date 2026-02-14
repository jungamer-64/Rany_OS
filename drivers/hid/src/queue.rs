// ============================================================================
// drivers/hid/src/queue.rs - Lock-free SPSC Scancode Queue
// ============================================================================
//!
//! Lock-free Single Producer Single Consumer (SPSC) queue for scancodes.
//!
//! This queue is designed for keyboard interrupt handling where:
//! - Producer: ISR (Interrupt Service Routine) - single thread only
//! - Consumer: Async poll - single thread only
//!
//! ## Data Format (u16)
//! ```text
//! ┌─────────────────────────────────────────┐
//! │ bit 15-9: Reserved (0)                  │
//! │ bit 8:    Extended Flag (0xE0 prefix)   │
//! │ bit 7-0:  Raw Scancode                  │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Memory Ordering Contract
//!
//! Uses Release-Acquire synchronization to ensure proper visibility:
//! - Producer uses Release ordering when writing data and updating tail
//! - Consumer uses Acquire ordering when reading tail and data
//!
//! ## Platform Considerations
//!
//! - **x86-64 (TSO)**: Release-Acquire is automatically guaranteed
//! - **ARM64**: Theoretically safe, but real-device testing recommended
//! - **RISC-V**: Compiler inserts fence instructions as needed

use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

/// Default queue size (must be power of 2)
pub const DEFAULT_QUEUE_SIZE: usize = 128;

/// Queue size mask for fast modulo operation
const QUEUE_MASK: usize = DEFAULT_QUEUE_SIZE - 1;

// Static assertion: size must be power of 2
const _: () = assert!(
    DEFAULT_QUEUE_SIZE.is_power_of_two(),
    "DEFAULT_QUEUE_SIZE must be a power of two"
);

/// Lock-free SPSC scancode queue
///
/// # Safety
///
/// This queue is safe only under strict SPSC conditions:
/// - Only ONE producer (ISR) may call `push`
/// - Only ONE consumer may call `pop`
///
/// Violating these conditions leads to undefined behavior.
pub struct ScancodeQueue {
    buffer: [AtomicU16; DEFAULT_QUEUE_SIZE],
    tail: AtomicUsize,
    head: AtomicUsize,
}

impl ScancodeQueue {
    /// Create a new empty queue
    pub const fn new() -> Self {
        const ZERO: AtomicU16 = AtomicU16::new(0);
        Self {
            buffer: [ZERO; DEFAULT_QUEUE_SIZE],
            tail: AtomicUsize::new(0),
            head: AtomicUsize::new(0),
        }
    }

    /// Push data to the queue (Producer side: called from ISR)
    ///
    /// # Memory Ordering
    /// - `buffer[tail].store(Release)`: Ensures data is written before tail update
    /// - `tail.store(Release)`: Consumer sees data when it sees new tail
    ///
    /// # Returns
    /// - `true`: Successfully pushed
    /// - `false`: Queue is full, data was not added
    #[inline]
    pub fn push(&self, data: u16) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        let next_tail = (tail + 1) & QUEUE_MASK;
        if next_tail == head {
            return false; // Queue full
        }

        // Release: Consumer sees data when it reads the new tail
        self.buffer[tail].store(data, Ordering::Release);
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    /// Pop data from the queue (Consumer side: called from poll)
    ///
    /// # Memory Ordering
    /// - `head.load(Acquire)`: Sees all writes after previous head update
    /// - `tail.load(Acquire)`: Sees producer's buffer writes
    /// - `buffer[head].load(Acquire)`: Ensures data read completes before head update
    ///
    /// # Returns
    /// - `Some(data)`: Next scancode in queue
    /// - `None`: Queue is empty
    #[inline]
    pub fn pop(&self) -> Option<u16> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None; // Queue empty
        }

        // Acquire: Producer's write is guaranteed to be visible
        let data = self.buffer[head].load(Ordering::Acquire);
        self.head.store((head + 1) & QUEUE_MASK, Ordering::Release);
        Some(data)
    }

    /// Check if queue is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    /// Get current queue length (approximate, may change during call)
    #[inline]
    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        (tail.wrapping_sub(head)) & QUEUE_MASK
    }
}

impl Default for ScancodeQueue {
    fn default() -> Self {
        Self::new()
    }
}
