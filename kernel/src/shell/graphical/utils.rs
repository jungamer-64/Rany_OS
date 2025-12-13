// ============================================================================
// src/shell/graphical/utils.rs - Graphical Shell Utilities
// ============================================================================

use crate::graphics::Rect;

// ============================================================================
// RectList - Fixed-capacity list of rectangles
// ============================================================================

/// A fixed-capacity list of Rects, used for avoiding heap allocations
/// during rendering pass calculations.
///
/// # Design Notes
///
/// - `Copy` trait is intentionally NOT implemented to prevent accidental
///   large stack copies (N=64 would be 1KB).
/// - Zero-size rectangles are silently filtered out during push operations.
/// - Uses `try_push` for fallible insertion, `push` panics if full.
#[derive(Debug, Clone)]
pub struct RectList<const N: usize> {
    rects: [Rect; N],
    count: usize,
}

impl<const N: usize> RectList<N> {
    pub const fn new() -> Self {
        Self {
            rects: [Rect::new(0, 0, 0, 0); N],
            count: 0,
        }
    }

    pub const fn capacity() -> usize {
        N
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn is_full(&self) -> bool {
        self.count >= N
    }

    /// Returns a slice of the active rectangles
    pub fn as_slice(&self) -> &[Rect] {
        &self.rects[..self.count]
    }

    #[cfg(debug_assertions)]
    fn validate(&self) {
        assert!(self.count <= N, "RectList count exceeds capacity");
        for (i, r) in self.as_slice().iter().enumerate() {
            assert!(r.is_valid(), "Invalid rect at index {}: {:?}", i, r);
        }
    }

    /// Attempts to push a rectangle into the list.
    ///
    /// Returns `Ok(())` if successful, `Err(())` if the list is full.
    /// Zero-size rectangles are silently ignored and return `Ok(())`.
    ///
    /// # Example
    /// ```ignore
    /// let mut list = RectList::<4>::new();
    /// if list.try_push(some_rect).is_err() {
    ///     // Fallback: full screen redraw
    ///     list = RectList::from_element(full_screen_rect);
    /// }
    /// ```
    pub fn try_push(&mut self, r: Rect) -> Result<(), ()> {
        if !r.is_valid() {
            return Ok(()); // Zero-size rectangles are silently ignored
        }

        if self.is_full() {
            return Err(());
        }

        self.rects[self.count] = r;
        self.count += 1;

        #[cfg(debug_assertions)]
        self.validate();

        Ok(())
    }

    /// Pushes a rectangle into the list.
    ///
    /// # Panics
    /// Panics if the list is full.
    ///
    /// For fallback-capable code, use `try_push` instead.
    ///
    /// Zero-size rectangles are silently ignored (intentional filtering).
    #[track_caller]
    pub fn push(&mut self, r: Rect) {
        if let Err(()) = self.try_push(r) {
            panic!(
                "RectList overflow: attempted to push into full RectList<{N}>. \
                 Consider increasing capacity or using try_push with fallback logic."
            );
        }
    }

    /// Attempts to push a rectangle, merging with any existing overlapping rectangle.
    ///
    /// Returns `Err(())` if the list is full and no merge is possible.
    ///
    /// If the new rectangle overlaps with an existing one, they are merged
    /// into a single bounding rectangle. This reduces overdraw at the cost
    /// of potentially drawing some pixels that weren't strictly dirty.
    pub fn try_push_or_merge(&mut self, r: Rect) -> Result<(), ()> {
        if !r.is_valid() {
            return Ok(()); // Zero-size rectangles are silently ignored
        }

        // Check if this rect overlaps with any existing rect
        for i in 0..self.count {
            if self.rects[i].intersects(&r) {
                // Merge: replace existing with union
                self.rects[i] = self.rects[i].union(&r);
                return Ok(());
            }
        }

        // No overlap - push as new entry
        self.try_push(r)
    }

    /// Pushes a rectangle, merging with any existing overlapping rectangle.
    ///
    /// Zero-size rectangles are silently ignored.
    ///
    /// # Panics
    /// Panics if the list is full and no merge is possible.
    #[track_caller]
    pub fn push_or_merge(&mut self, r: Rect) {
        if let Err(()) = self.try_push_or_merge(r) {
            panic!(
                "RectList overflow: attempted to push into full RectList<{N}>. \
                 Consider increasing capacity or using try_push_or_merge with fallback logic."
            );
        }
    }

    /// Creates a RectList containing a single element.
    pub const fn from_element(r: Rect) -> Self {
        let mut list = Self::new();
        // const fn では push() 等を呼べないため直接代入
        list.rects[0] = r;
        list.count = if r.width > 0 && r.height > 0 { 1 } else { 0 };
        list
    }

    /// Extends this list with rectangles from an iterator.
    ///
    /// # Panics
    /// Panics if appending would exceed capacity.
    pub fn extend(&mut self, iter: impl IntoIterator<Item = Rect>) {
        for rect in iter {
            self.push(rect);
        }
    }

    /// Extends this list with rectangles from an iterator, with fallback.
    ///
    /// Returns `Err(())` if any push would exceed capacity.
    pub fn try_extend(&mut self, iter: impl IntoIterator<Item = Rect>) -> Result<(), ()> {
        for rect in iter {
            self.try_push(rect)?;
        }
        Ok(())
    }
}

// Default trait implementation
impl<const N: usize> Default for RectList<N> {
    fn default() -> Self {
        Self::new()
    }
}

// Deref to slice for convenient access (e.g., .iter(), .len() from slice)
impl<const N: usize> core::ops::Deref for RectList<N> {
    type Target = [Rect];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

// Allows iterating over references: `for r in &regions { ... }`
impl<'a, const N: usize> IntoIterator for &'a RectList<N> {
    type Item = &'a Rect;
    type IntoIter = core::slice::Iter<'a, Rect>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

// Iterator for value consumption (copy): `for r in regions { ... }`
impl<const N: usize> IntoIterator for RectList<N> {
    type Item = Rect;
    type IntoIter = RectListIntoIter<N>;

    fn into_iter(self) -> Self::IntoIter {
        RectListIntoIter {
            list: self,
            index: 0,
        }
    }
}

pub struct RectListIntoIter<const N: usize> {
    list: RectList<N>,
    index: usize,
}

impl<const N: usize> Iterator for RectListIntoIter<N> {
    type Item = Rect;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.list.count {
            let r = self.list.rects[self.index];
            self.index += 1;
            Some(r)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.list.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<const N: usize> ExactSizeIterator for RectListIntoIter<N> {}
