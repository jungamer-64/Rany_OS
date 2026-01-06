// ============================================================================
// src/mm/magazine.rs - Generic Magazine Cache for Lock-Free Allocation
// IOVA_MM_MIGRATION_PLAN Phase 1.1: Magazine<T,N> Generalization
//
// Magazine caching pattern for O(1) allocation/deallocation with minimal
// contention. Used by both physical frame allocator and IOVA allocator.
//
// Design principles:
// - Cache line aligned to prevent false sharing
// - Stack-based (LIFO) for cache locality
// - Generic over element type T and capacity N
// - No heap allocation (fixed-size array)
// ============================================================================
#![allow(dead_code)]

use core::mem::MaybeUninit;

// ============================================================================
// Magazine<T, N> - Generic Per-CPU Cache
// ============================================================================

/// Generic magazine cache for O(1) push/pop operations
///
/// A magazine is a fixed-size stack that can hold up to N elements of type T.
/// It's designed for per-CPU caching where each CPU has its own magazine,
/// eliminating contention during allocation/deallocation.
///
/// # Type Parameters
/// - `T`: Element type (must be Copy for safe extraction)
/// - `N`: Maximum capacity (const generic)
///
/// # Usage
/// ```ignore
/// // For IOVA addresses (u64)
/// type IovaMagazine = Magazine<u64, 64>;
///
/// // For physical frame indices
/// type FrameMagazine = Magazine<FrameIndex, 64>;
/// ```
///
/// # Cache Line Alignment
/// The structure is aligned to 64 bytes (typical cache line size) to prevent
/// false sharing when multiple CPUs access their respective magazines.
#[repr(C, align(64))]
pub struct Magazine<T: Copy, const N: usize> {
    /// Storage for cached elements (stack-like, top at count-1)
    /// Using MaybeUninit to avoid requiring Default trait
    entries: [MaybeUninit<T>; N],
    /// Number of valid entries (0..=N)
    count: usize,
}

impl<T: Copy, const N: usize> Magazine<T, N> {
    /// Create an empty magazine
    ///
    /// # Const
    /// This is a const fn, allowing static initialization of per-CPU magazines.
    #[inline]
    pub const fn new() -> Self {
        Self {
            // SAFETY: MaybeUninit does not require initialization
            entries: unsafe { MaybeUninit::uninit().assume_init() },
            count: 0,
        }
    }

    /// Create a magazine initialized with zeros (for numeric types)
    ///
    /// This is useful when you want deterministic memory contents.
    #[inline]
    pub const fn zeroed() -> Self
    where
        T: Copy,
    {
        Self {
            // SAFETY: Zero-initialized MaybeUninit array
            entries: unsafe { MaybeUninit::zeroed().assume_init() },
            count: 0,
        }
    }

    /// Try to pop an element from the magazine (O(1))
    ///
    /// Returns `Some(element)` if magazine is not empty, `None` otherwise.
    ///
    /// # Performance
    /// - Single decrement + array access
    /// - No branching on hot path (branch prediction friendly)
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        // SAFETY: count was > 0, so entries[count] is initialized
        Some(unsafe { self.entries[self.count].assume_init() })
    }

    /// Try to push an element to the magazine (O(1))
    ///
    /// Returns `true` if element was pushed, `false` if magazine is full.
    ///
    /// # Performance
    /// - Single comparison + array access + increment
    /// - Predictable branch (usually not full)
    #[inline]
    pub fn push(&mut self, value: T) -> bool {
        if self.count >= N {
            return false; // Magazine full
        }
        self.entries[self.count] = MaybeUninit::new(value);
        self.count += 1;
        true
    }

    /// Get current number of elements
    #[inline]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Check if magazine is empty
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if magazine is full
    #[inline]
    pub const fn is_full(&self) -> bool {
        self.count >= N
    }

    /// Get the capacity of this magazine
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Get remaining space in the magazine
    #[inline]
    pub const fn remaining(&self) -> usize {
        N - self.count
    }

    /// Peek at the top element without removing it
    #[inline]
    pub fn peek(&self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        // SAFETY: count > 0, so entries[count-1] is initialized
        Some(unsafe { self.entries[self.count - 1].assume_init() })
    }

    /// Clear all elements from the magazine
    #[inline]
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Drain all elements from the magazine, calling the provided closure for each
    ///
    /// # Example
    /// ```ignore
    /// magazine.drain(|iova| {
    ///     bitmap.free(iova);
    /// });
    /// ```
    #[inline]
    pub fn drain<F>(&mut self, mut f: F)
    where
        F: FnMut(T),
    {
        while let Some(value) = self.pop() {
            f(value);
        }
    }

    /// Fill the magazine from an iterator, stopping when full
    ///
    /// Returns the number of elements added.
    #[inline]
    pub fn fill_from<I>(&mut self, iter: I) -> usize
    where
        I: IntoIterator<Item = T>,
    {
        let mut added = 0;
        for value in iter {
            if !self.push(value) {
                break;
            }
            added += 1;
        }
        added
    }

    /// Try to transfer elements to another magazine
    ///
    /// Transfers up to `count` elements from self to `other`.
    /// Returns the number of elements actually transferred.
    #[inline]
    pub fn transfer_to(&mut self, other: &mut Self, count: usize) -> usize {
        let mut transferred = 0;
        for _ in 0..count {
            if let Some(value) = self.pop() {
                if other.push(value) {
                    transferred += 1;
                } else {
                    // Other magazine is full, push back to self
                    self.push(value);
                    break;
                }
            } else {
                break;
            }
        }
        transferred
    }
}

impl<T: Copy, const N: usize> Default for Magazine<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MagazineSet<T, N, C> - Multi-Class Magazine Array
// ============================================================================

/// A set of magazines for multiple size classes
///
/// This is useful when you need separate magazines for different allocation
/// sizes (e.g., 4KB, 2MB, 1GB pages).
///
/// # Type Parameters
/// - `T`: Element type
/// - `N`: Capacity per magazine
/// - `C`: Number of size classes
#[repr(C, align(64))]
pub struct MagazineSet<T: Copy, const N: usize, const C: usize> {
    /// Array of magazines, one per size class
    magazines: [Magazine<T, N>; C],
}

impl<T: Copy, const N: usize, const C: usize> MagazineSet<T, N, C> {
    /// Create a new magazine set with all empty magazines
    #[inline]
    pub const fn new() -> Self {
        // SAFETY: Magazine<T, N>::new() is const and returns valid empty magazine
        Self {
            magazines: [const { Magazine::new() }; C],
        }
    }

    /// Get a reference to the magazine for a specific size class
    #[inline]
    pub fn get(&self, class: usize) -> Option<&Magazine<T, N>> {
        self.magazines.get(class)
    }

    /// Get a mutable reference to the magazine for a specific size class
    #[inline]
    pub fn get_mut(&mut self, class: usize) -> Option<&mut Magazine<T, N>> {
        self.magazines.get_mut(class)
    }

    /// Pop from a specific size class
    #[inline]
    pub fn pop(&mut self, class: usize) -> Option<T> {
        self.magazines.get_mut(class)?.pop()
    }

    /// Push to a specific size class
    #[inline]
    pub fn push(&mut self, class: usize, value: T) -> bool {
        self.magazines
            .get_mut(class)
            .map(|m| m.push(value))
            .unwrap_or(false)
    }

    /// Clear all magazines
    #[inline]
    pub fn clear_all(&mut self) {
        for magazine in &mut self.magazines {
            magazine.clear();
        }
    }

    /// Get total count across all magazines
    #[inline]
    pub fn total_count(&self) -> usize {
        self.magazines.iter().map(|m| m.len()).sum()
    }
}

impl<T: Copy, const N: usize, const C: usize> Default for MagazineSet<T, N, C> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Type Aliases for Common Use Cases
// ============================================================================

/// Default magazine capacity (matches original MAGAZINE_CAPACITY)
pub const DEFAULT_MAGAZINE_CAPACITY: usize = 64;

/// Number of size classes for frame/IOVA allocation (4KB, 2MB, 1GB)
pub const FRAME_SIZE_CLASSES: usize = 3;

/// Magazine for IOVA addresses
pub type IovaMagazine = Magazine<u64, DEFAULT_MAGAZINE_CAPACITY>;

/// Magazine set for IOVA addresses with 3 size classes
pub type IovaMagazineSet = MagazineSet<u64, DEFAULT_MAGAZINE_CAPACITY, FRAME_SIZE_CLASSES>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magazine_basic() {
        let mut mag: Magazine<u64, 4> = Magazine::new();

        assert!(mag.is_empty());
        assert!(!mag.is_full());
        assert_eq!(mag.len(), 0);
        assert_eq!(mag.capacity(), 4);

        // Push elements
        assert!(mag.push(1));
        assert!(mag.push(2));
        assert!(mag.push(3));
        assert!(mag.push(4));
        assert!(!mag.push(5)); // Full

        assert!(mag.is_full());
        assert_eq!(mag.len(), 4);

        // Pop elements (LIFO order)
        assert_eq!(mag.pop(), Some(4));
        assert_eq!(mag.pop(), Some(3));
        assert_eq!(mag.pop(), Some(2));
        assert_eq!(mag.pop(), Some(1));
        assert_eq!(mag.pop(), None); // Empty

        assert!(mag.is_empty());
    }

    #[test]
    fn test_magazine_peek() {
        let mut mag: Magazine<u64, 4> = Magazine::new();

        assert_eq!(mag.peek(), None);

        mag.push(42);
        assert_eq!(mag.peek(), Some(42));
        assert_eq!(mag.len(), 1); // Still there

        mag.push(43);
        assert_eq!(mag.peek(), Some(43)); // Top changed
    }

    #[test]
    fn test_magazine_drain() {
        let mut mag: Magazine<u64, 4> = Magazine::new();
        mag.push(1);
        mag.push(2);
        mag.push(3);

        let mut drained = Vec::new();
        mag.drain(|v| drained.push(v));

        assert_eq!(drained, vec![3, 2, 1]); // LIFO order
        assert!(mag.is_empty());
    }

    #[test]
    fn test_magazine_transfer() {
        let mut src: Magazine<u64, 4> = Magazine::new();
        let mut dst: Magazine<u64, 4> = Magazine::new();

        src.push(1);
        src.push(2);
        src.push(3);

        let transferred = src.transfer_to(&mut dst, 2);
        assert_eq!(transferred, 2);
        assert_eq!(src.len(), 1);
        assert_eq!(dst.len(), 2);
    }

    #[test]
    fn test_magazine_set() {
        let mut set: MagazineSet<u64, 4, 3> = MagazineSet::new();

        assert!(set.push(0, 100));
        assert!(set.push(1, 200));
        assert!(set.push(2, 300));

        assert_eq!(set.pop(0), Some(100));
        assert_eq!(set.pop(1), Some(200));
        assert_eq!(set.pop(2), Some(300));
        assert_eq!(set.pop(3), None); // Invalid class
    }
}
