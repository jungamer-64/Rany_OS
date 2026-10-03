//! Shared address-space occupancy for RAM and IOVA pools. CPU caches belong
//! to the RAM owner; IOVA reuse is subject to IOTLB completion in its owner.
//! Detail page bits are the sole allocation authority for every page size.

use crate::loader::type_id::{SemVer, TypeHash, TypeIdHash, const_hash};
use crate::mm::bitmap::{BitmapError, HierarchicalBitmap};

pub const PAGE_SIZE_4K: u64 = 4096;
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageGranularity {
    Page4K,
    Page2M,
    Page1G,
}

impl PageGranularity {
    pub const fn size_bytes(self) -> u64 {
        match self {
            Self::Page4K => PAGE_SIZE_4K,
            Self::Page2M => PAGE_SIZE_2M,
            Self::Page1G => PAGE_SIZE_1G,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressPoolError {
    InvalidRange,
    Alignment,
    MetadataAllocation,
    Exhausted,
}

#[derive(Debug)]
pub struct FastBitmapAllocator {
    base: u64,
    size: u64,
    bitmap: HierarchicalBitmap,
}

impl FastBitmapAllocator {
    pub fn try_new(base: u64, size: u64) -> Result<Self, AddressPoolError> {
        if size == 0 || base.checked_add(size).is_none() {
            return Err(AddressPoolError::InvalidRange);
        }
        if base % PAGE_SIZE_4K != 0 || size % PAGE_SIZE_4K != 0 {
            return Err(AddressPoolError::Alignment);
        }
        let pages =
            usize::try_from(size / PAGE_SIZE_4K).map_err(|_| AddressPoolError::InvalidRange)?;
        let bitmap = HierarchicalBitmap::try_new(pages).map_err(|error| match error {
            BitmapError::MetadataAllocation => AddressPoolError::MetadataAllocation,
            _ => AddressPoolError::InvalidRange,
        })?;
        Ok(Self { base, size, bitmap })
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn free_count(&self) -> usize {
        self.bitmap.free_count()
    }
    pub fn total_pages(&self) -> usize {
        self.bitmap.total_units()
    }
    pub fn pmm_stats(&self) -> (u64, usize) {
        (self.free_count() as u64, self.total_pages())
    }

    pub fn allocate_4k(&self) -> Option<u64> {
        self.bitmap
            .allocate_one()
            .map(|page| self.base + page as u64 * PAGE_SIZE_4K)
    }
    pub fn allocate_2m(&self) -> Option<u64> {
        self.allocate_contiguous(PAGE_SIZE_2M, PAGE_SIZE_2M)
    }
    pub fn allocate_1g(&self) -> Option<u64> {
        self.allocate_contiguous(PAGE_SIZE_1G, PAGE_SIZE_1G)
    }
    pub fn allocate_4k_below(&self, limit: u64) -> Option<u64> {
        let pages = usize::try_from(
            limit.min(self.base + self.size).checked_sub(self.base)? / PAGE_SIZE_4K,
        )
        .ok()?;
        self.bitmap
            .allocate_one_below(pages)
            .map(|page| self.base + page as u64 * PAGE_SIZE_4K)
    }
    pub fn allocate_2m_below(&self, limit: u64) -> Option<u64> {
        self.allocate_contiguous_below(PAGE_SIZE_2M, PAGE_SIZE_2M, limit)
            .ok()
    }
    pub fn allocate_1g_below(&self, limit: u64) -> Option<u64> {
        self.allocate_contiguous_below(PAGE_SIZE_1G, PAGE_SIZE_1G, limit)
            .ok()
    }
    pub fn allocate_contiguous(&self, size: u64, align: u64) -> Option<u64> {
        self.allocate_contiguous_below(size, align, self.base + self.size)
            .ok()
    }

    /// Alignment uses the actual address, never the pool origin. A claim is
    /// unpublished until every word has been reserved exclusively.
    pub fn allocate_contiguous_below(
        &self,
        size: u64,
        align: u64,
        limit: u64,
    ) -> Result<u64, AddressPoolError> {
        if size == 0 {
            return Err(AddressPoolError::InvalidRange);
        }
        if !align.is_power_of_two() {
            return Err(AddressPoolError::Alignment);
        }
        let align = align.max(PAGE_SIZE_4K);
        let rounded_size = size
            .checked_add(PAGE_SIZE_4K - 1)
            .ok_or(AddressPoolError::InvalidRange)?
            & !(PAGE_SIZE_4K - 1);
        let count = usize::try_from(rounded_size / PAGE_SIZE_4K)
            .map_err(|_| AddressPoolError::InvalidRange)?;
        let end = limit.min(self.base + self.size);
        let mut candidate = self
            .base
            .checked_add(align - 1)
            .ok_or(AddressPoolError::InvalidRange)?
            & !(align - 1);
        // LOOP_PROOF: mode=condition; reason=Candidate advances by a positive aligned span bounded by end.;
        while candidate
            .checked_add(rounded_size)
            .is_some_and(|last| last <= end)
        {
            let page = ((candidate - self.base) / PAGE_SIZE_4K) as usize;
            match self.bitmap.claim_range(page, count) {
                Ok(claim) => {
                    claim.commit();
                    return Ok(candidate);
                }
                Err(BitmapError::Occupied { index }) => {
                    // Every candidate overlapping this occupied page is invalid.
                    // Skip its entire prefix instead of rescanning every page.
                    let after = self.base + (index as u64 + 1) * PAGE_SIZE_4K;
                    candidate = match after.checked_add(align - 1) {
                        Some(next) => next & !(align - 1),
                        None => break,
                    };
                }
                Err(_) => return Err(AddressPoolError::InvalidRange),
            }
        }
        Err(AddressPoolError::Exhausted)
    }

    fn page_range(&self, start: u64, size: u64) -> Result<(usize, usize), AddressPoolError> {
        if size == 0
            || start < self.base
            || start
                .checked_add(size)
                .is_none_or(|end| end > self.base + self.size)
        {
            return Err(AddressPoolError::InvalidRange);
        }
        if start % PAGE_SIZE_4K != 0 || size % PAGE_SIZE_4K != 0 {
            return Err(AddressPoolError::Alignment);
        }
        Ok((
            ((start - self.base) / PAGE_SIZE_4K) as usize,
            (size / PAGE_SIZE_4K) as usize,
        ))
    }

    /// Admission excludes reserved holes before pool publication.
    pub fn reserve(&self, start: u64, size: u64) -> Result<(), AddressPoolError> {
        let (page, count) = self.page_range(start, size)?;
        self.bitmap
            .reserve_range(page, count)
            .map_err(|_| AddressPoolError::InvalidRange)
    }

    /// The caller retains unique ownership until required TLB/IOTLB completion.
    /// This operation publishes the pages for reuse.
    pub fn free_range_immediate(&self, start: u64, size: u64) -> Result<(), AddressPoolError> {
        let (page, count) = self.page_range(start, size)?;
        self.bitmap.release_range(page, count);
        Ok(())
    }
    pub fn free_immediate(
        &self,
        addr: u64,
        granularity: PageGranularity,
    ) -> Result<(), AddressPoolError> {
        if addr % granularity.size_bytes() != 0 {
            return Err(AddressPoolError::Alignment);
        }
        self.free_range_immediate(addr, granularity.size_bytes())
    }
}

impl TypeIdHash for FastBitmapAllocator {
    fn type_id_hash() -> TypeHash {
        const_hash(b"FastBitmapAllocator:v3:base,size,page_occupancy")
    }
    fn type_name() -> &'static str {
        "FastBitmapAllocator"
    }
    fn type_version() -> SemVer {
        SemVer::new(3, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absolute_alignment_holes_limits_and_edges() {
        let pool = FastBitmapAllocator::try_new(PAGE_SIZE_4K, PAGE_SIZE_2M * 4).unwrap();
        pool.reserve(PAGE_SIZE_2M + PAGE_SIZE_4K, PAGE_SIZE_4K)
            .unwrap();
        assert_eq!(pool.allocate_2m(), Some(PAGE_SIZE_2M * 2));
        assert_eq!(pool.allocate_2m(), Some(PAGE_SIZE_2M * 3));
        assert_eq!(pool.allocate_2m(), None);
        assert_eq!(pool.allocate_1g(), None);
        assert_eq!(
            pool.allocate_contiguous_below(PAGE_SIZE_2M, PAGE_SIZE_2M, PAGE_SIZE_2M * 2),
            Err(AddressPoolError::Exhausted)
        );
        let edge = FastBitmapAllocator::try_new(PAGE_SIZE_4K * 63, PAGE_SIZE_4K * 65).unwrap();
        assert_eq!(
            edge.allocate_contiguous(PAGE_SIZE_4K * 65, PAGE_SIZE_4K),
            Some(PAGE_SIZE_4K * 63)
        );
        assert_eq!(edge.allocate_4k(), None);
        edge.free_range_immediate(PAGE_SIZE_4K * 63, PAGE_SIZE_4K * 65)
            .unwrap();
        assert_eq!(edge.free_count(), 65);
        assert_eq!(edge.allocate_4k_below(PAGE_SIZE_4K * 64 - 1), None);
        assert_eq!(
            edge.allocate_4k_below(PAGE_SIZE_4K * 64),
            Some(PAGE_SIZE_4K * 63)
        );
    }
    #[test]
    fn invalid_ranges_and_alignment_do_not_claim_pages() {
        assert!(matches!(
            FastBitmapAllocator::try_new(u64::MAX - 4095, 8192),
            Err(AddressPoolError::InvalidRange)
        ));
        assert!(matches!(
            FastBitmapAllocator::try_new(1, 4096),
            Err(AddressPoolError::Alignment)
        ));
        let pool = FastBitmapAllocator::try_new(4096, 8192).unwrap();
        assert_eq!(
            pool.allocate_contiguous_below(0, 4096, 12288),
            Err(AddressPoolError::InvalidRange)
        );
        assert_eq!(
            pool.allocate_contiguous_below(1, 3, 12288),
            Err(AddressPoolError::Alignment)
        );
        assert_eq!(
            pool.allocate_contiguous_below(u64::MAX, 4096, 12288),
            Err(AddressPoolError::InvalidRange)
        );
        assert_eq!(pool.free_count(), 2);
    }
    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn concurrent_mixed_claims_have_exclusive_occupancy() {
        use alloc::sync::Arc;
        let pool = Arc::new(FastBitmapAllocator::try_new(4096, PAGE_SIZE_2M * 8).unwrap());
        let active = Arc::new(std::sync::Mutex::new(
            alloc::vec![false; pool.total_pages()],
        ));
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let pool = Arc::clone(&pool);
                let active = Arc::clone(&active);
                scope.spawn(move || {
                    for i in 0..2000 {
                        let size = if (worker + i) % 5 == 0 {
                            PAGE_SIZE_2M
                        } else {
                            PAGE_SIZE_4K * ((i % 65 + 1) as u64)
                        };
                        let align = if size == PAGE_SIZE_2M {
                            PAGE_SIZE_2M
                        } else {
                            PAGE_SIZE_4K
                        };
                        let Some(start) = pool.allocate_contiguous(size, align) else {
                            continue;
                        };
                        let first = ((start - pool.base()) / PAGE_SIZE_4K) as usize;
                        let count = (size / PAGE_SIZE_4K) as usize;
                        {
                            let mut model = active.lock().unwrap();
                            assert!(model[first..first + count].iter().all(|bit| !bit));
                            model[first..first + count].fill(true);
                        }
                        std::thread::yield_now();
                        {
                            let mut model = active.lock().unwrap();
                            model[first..first + count].fill(false);
                            pool.free_range_immediate(start, size).unwrap();
                        }
                    }
                });
            }
        });
        assert_eq!(pool.free_count(), pool.total_pages());
        for _ in 0..pool.total_pages() {
            assert!(pool.allocate_4k().is_some());
        }
        assert_eq!(pool.allocate_4k(), None);
    }
}
