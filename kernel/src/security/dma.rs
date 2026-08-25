// ============================================================================
// kernel/src/security/dma.rs - DMA Security & Physical Page Protection
// ============================================================================

//! DMA Security Monitor
//!
//! Provides the authoritative registry of physical ranges that devices must
//! never be allowed to access through DMA. Protection is page-granular because
//! IOMMU mappings cannot safely expose only part of a protected page.

use alloc::collections::BTreeMap;
use core::mem;
use spin::RwLock;

const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProtectionSpan {
    end: u64,
    registrations: u32,
}

/// A sorted set of non-overlapping, page-aligned spans.
///
/// `registrations` preserves independently owned protection claims: releasing
/// one allocation cannot expose a page that is still protected by another
/// overlapping allocation.
#[derive(Debug)]
struct ProtectionRegistry {
    spans: BTreeMap<u64, ProtectionSpan>,
}

impl ProtectionRegistry {
    const fn new() -> Self {
        Self {
            spans: BTreeMap::new(),
        }
    }

    fn register(&mut self, start: u64, end: u64) {
        self.split_at(start);
        self.split_at(end);

        let mut cursor = start;
        while cursor < end {
            if let Some(span) = self.spans.get_mut(&cursor) {
                span.registrations = span
                    .registrations
                    .checked_add(1)
                    .expect("DMA protection registration count overflowed");
                cursor = span.end;
                continue;
            }

            let next_start = self
                .spans
                .range(cursor..end)
                .next()
                .map_or(end, |(&next_start, _)| next_start);
            self.spans.insert(
                cursor,
                ProtectionSpan {
                    end: next_start,
                    registrations: 1,
                },
            );
            cursor = next_start;
        }

        self.coalesce();
    }

    fn unregister(&mut self, start: u64, end: u64) {
        self.split_at(start);
        self.split_at(end);

        let mut cursor = start;
        while cursor < end {
            let Some((&span_start, &span)) = self.spans.range(cursor..end).next() else {
                break;
            };

            cursor = span.end;
            if span.registrations == 1 {
                self.spans.remove(&span_start);
            } else if let Some(stored) = self.spans.get_mut(&span_start) {
                stored.registrations -= 1;
            }
        }

        self.coalesce();
    }

    fn contains(&self, phys: u64) -> bool {
        self.spans
            .range(..=phys)
            .next_back()
            .is_some_and(|(_, span)| phys < span.end)
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.spans
            .range(..end)
            .next_back()
            .is_some_and(|(_, span)| span.end > start)
    }

    fn split_at(&mut self, point: u64) {
        let Some((&span_start, &span)) = self.spans.range(..point).next_back() else {
            return;
        };
        if span.end <= point {
            return;
        }

        self.spans
            .get_mut(&span_start)
            .expect("predecessor span disappeared while write-locked")
            .end = point;
        self.spans.insert(
            point,
            ProtectionSpan {
                end: span.end,
                registrations: span.registrations,
            },
        );
    }

    fn coalesce(&mut self) {
        let old_spans = mem::take(&mut self.spans);
        for (start, span) in old_spans {
            if let Some(previous) = self.spans.last_entry()
                && previous.get().end == start
                && previous.get().registrations == span.registrations
            {
                previous.into_mut().end = span.end;
            } else {
                self.spans.insert(start, span);
            }
        }
    }
}

static PROTECTED_REGISTRY: RwLock<ProtectionRegistry> = RwLock::new(ProtectionRegistry::new());

fn page_aligned_range(start: u64, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }

    let raw_end = start
        .checked_add(size)
        .expect("DMA protection range must not overflow the physical address space");
    let end = raw_end
        .checked_add(PAGE_MASK)
        .expect("DMA protection range must leave room for page alignment")
        & !PAGE_MASK;
    Some((start & !PAGE_MASK, end))
}

/// Register the containing physical page as protected from DMA.
pub fn register_protected_page(phys: u64) {
    register_protected_range(phys, 1);
}

/// Release one protection claim for the containing physical page.
pub fn unregister_protected_page(phys: u64) {
    unregister_protected_range(phys, 1);
}

/// Check whether the physical address belongs to a protected page.
pub fn is_page_protected(phys: u64) -> bool {
    PROTECTED_REGISTRY.read().contains(phys)
}

/// Register every physical page touched by a range as protected from DMA.
pub fn register_protected_range(start: u64, size: u64) {
    let Some((start, end)) = page_aligned_range(start, size) else {
        return;
    };
    PROTECTED_REGISTRY.write().register(start, end);
}

/// Release one protection claim from every page touched by a range.
pub fn unregister_protected_range(start: u64, size: u64) {
    let Some((start, end)) = page_aligned_range(start, size) else {
        return;
    };
    PROTECTED_REGISTRY.write().unregister(start, end);
}

/// Check whether a physical range overlaps any protected page.
///
/// Overflowing ranges are rejected conservatively because they cannot describe
/// a valid DMA mapping.
pub fn range_overlaps_protected(start: u64, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = start.checked_add(size) else {
        return true;
    };
    PROTECTED_REGISTRY.read().overlaps(start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ProtectionRegistry {
        ProtectionRegistry::new()
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn sparse_ranges_have_no_fixed_address_boundary() {
        let mut registry = registry();
        let low = 0x2000;
        let high = (1_u64 << 40) + 0x4000;

        registry.register(low, low + PAGE_SIZE);
        registry.register(high, high + PAGE_SIZE);

        assert!(registry.contains(low));
        assert!(!registry.contains(low + PAGE_SIZE));
        assert!(registry.contains(high));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn overlapping_registrations_retain_independent_claims() {
        let mut registry = registry();
        registry.register(0x1000, 0x4000);
        registry.register(0x2000, 0x3000);

        registry.unregister(0x1000, 0x4000);

        assert!(!registry.contains(0x1000));
        assert!(registry.contains(0x2000));
        assert!(!registry.contains(0x3000));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn overlap_query_observes_only_intersecting_spans() {
        let mut registry = registry();
        registry.register(0x4000, 0x6000);

        assert!(!registry.overlaps(0x2000, 0x4000));
        assert!(registry.overlaps(0x3000, 0x5000));
        assert!(registry.overlaps(0x5000, 0x7000));
        assert!(!registry.overlaps(0x6000, 0x8000));
    }
}
